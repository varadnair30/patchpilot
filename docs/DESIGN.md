# PatchPilot — Design Document (v1, pre-code)

Human-gated dependency-vulnerability triage and remediation, built as a LangGraph state machine with durable interrupts, a LangSmith-gated regression suite, and guardrails enforced in code.

Decisions locked for v1: **Python target repos only**, **CLI approval queue first**, web queue built afterwards for the public demo.

![Architecture](architecture.svg)

---

## 1. Repository structure

Two repositories. The agent lives in `patchpilot`; the deterministic demo target lives in `patchpilot-demo-app` so that scans, tests and the recorded video always run against known inputs.

```
patchpilot/
├── README.md                      # leads with the GIF, the diagram, and the 60-second story
├── pyproject.toml                 # uv-managed; python 3.12
├── docker-compose.yml             # postgres, the agent, (later) the web queue
├── .env.example
├── docs/
│   ├── DESIGN.md                  # this file
│   ├── architecture.svg
│   ├── DEMO_SHOTLIST.md           # what to record, in what order
│   └── adr/                       # short architecture decision records (why no CrewAI, why policy is deterministic, …)
├── src/patchpilot/
│   ├── graph/
│   │   ├── state.py               # ScanState / AdvisoryState (TypedDict + reducers)
│   │   ├── build.py               # StateGraph wiring, conditional edges, checkpointer
│   │   ├── nodes/
│   │   │   ├── ingest.py
│   │   │   ├── reachability.py
│   │   │   ├── risk_policy.py
│   │   │   ├── plan_remediation.py
│   │   │   ├── human_gate.py      # the interrupt() node
│   │   │   ├── execute_pr.py
│   │   │   └── record_outcome.py
│   │   └── routing.py             # pure functions that decide the next edge
│   ├── policy/
│   │   ├── rules.py               # deterministic scoring + gate triggers (no LLM here)
│   │   ├── tiers.yaml             # package tiers: auth/crypto/serialization/… 
│   │   └── thresholds.yaml        # EPSS cutoff, confidence cutoff, budgets
│   ├── tools/                     # each tool = Pydantic input model + Pydantic output model + impl
│   │   ├── lockfile.py            # parse requirements/pyproject/uv.lock
│   │   ├── osv.py                 # batched OSV queries, cache-aware
│   │   ├── gh_advisory.py
│   │   ├── epss.py                # daily CSV loader + lookup
│   │   ├── reach_ast.py           # import + symbol call analysis
│   │   ├── pypi_resolver.py       # min safe version satisfying constraints
│   │   ├── changelog_rag.py       # fetch, chunk, embed, retrieve by imported symbols
│   │   ├── sandbox.py             # docker baseline/bump/diff runner
│   │   └── github_pr.py           # branch, commit, open PR — allowlisted actions only
│   ├── guardrails/
│   │   ├── contracts.py           # validate-or-halt wrapper applied to every tool call
│   │   ├── allowlist.py           # what the agent may do to a repo
│   │   ├── injection.py           # classifier for untrusted advisory/changelog text
│   │   ├── secrets.py             # output scan before any GitHub write
│   │   ├── budget.py              # per-run token/$ meter with hard stop
│   │   └── veto.py                # policy veto over LLM recommendations
│   ├── llm/
│   │   ├── client.py              # primary (Claude/GPT-4o) with Ollama fallback
│   │   └── prompts/               # pulled from LangSmith Prompt Hub by pinned version; local copies for offline
│   ├── recorded/                  # recorded-response mode: JSON fixtures keyed by request hash
│   ├── storage/
│   │   ├── db.py                  # postgres: cache, epss table, decision ledger
│   │   └── migrations/
│   ├── cli/
│   │   ├── scan.py                # `patchpilot scan <repo>`
│   │   ├── queue.py               # `patchpilot queue list|show|approve|reject|modify`
│   │   └── replay.py              # `patchpilot replay <thread_id>` time-travel through checkpoints
│   └── api/                       # v2: FastAPI approval queue + React UI
├── evals/
│   ├── golden/                    # ~60 seeded cases as YAML (inputs + expected decision + rationale)
│   ├── evaluators.py              # decision_match, tier_match, evidence_faithfulness, cost_latency
│   ├── run_evals.py               # `langsmith evaluate` driver; writes summary.json for CI
│   └── baseline.json              # pinned scores; CI compares against this
├── tests/
│   ├── unit/                      # tools, policy, guardrails, routing
│   ├── graph/                     # end-to-end graph runs in recorded mode; interrupt/resume tests
│   └── fixtures/
└── .github/workflows/
    ├── ci.yml                     # pytest → evals → gate
    └── golden-update.yml          # enforces 2-approver rule on evals/golden changes

patchpilot-demo-app/               # separate public repo, branch-protected
├── app/                           # small FastAPI service (~30 files)
├── requirements.txt               # ~10 deliberately pinned vulnerable versions
├── tests/
└── README.md                      # "this repo is intentionally vulnerable; it is PatchPilot's demo target"
```

---

## 2. Graph state

Two levels of state: one for the scan as a whole, one per advisory. Each advisory is processed by its own run of a per-advisory **subgraph** (`reachability → risk_policy → justify → …`), dispatched with `Send()`, so that a human decision on one advisory never blocks the others and each branch gets its own interrupt. The parent graph merges only `advisories` (by id) and `budget` (summed) back from a branch.

**ScanState** (thread = `repo_url + scan_id`)

| field | type | set by | notes |
|---|---|---|---|
| `scan_id` | str | cli | UUID |
| `repo` | RepoRef {url, default_branch, commit_sha} | cli | |
| `mode` | "recorded" \| "live" | cli | recorded is default |
| `dependencies` | list[Dependency {name, version, is_dev, source_file}] | ingest | |
| `advisories` | list[AdvisoryState] | ingest → fan-out | reducer: merge by advisory_id |
| `budget` | Budget {tokens_used, usd_used, tokens_cap, usd_cap} | every LLM call | hard-stop at cap |
| `data_freshness` | {osv_at, gh_at, epss_at} | ingest | printed in every PR |
| `summary` | ScanSummary | record_outcome | counts per decision class |

**AdvisoryState** (one per advisory; carried inside each Send branch)

| field | type | set by |
|---|---|---|
| `advisory_id` | str (GHSA-… / PYSEC-…) | ingest |
| `package`, `installed_version`, `fixed_versions` | str, str, list[str] | ingest |
| `cvss`, `epss`, `epss_percentile` | float | ingest |
| `vulnerable_symbols` | list[str] | ingest (from GH advisory, may be empty) |
| `untrusted_text` | {advisory_body, changelog_excerpt} | ingest / plan |
| `injection_flag` | bool + reason | guardrails.injection |
| `reachability` | {imported: bool, symbol_called: bool, call_sites: list[str], is_runtime_dep: bool, confidence: float} | reachability |
| `risk` | {score: float, tier: "critical"\|"high"\|"medium"\|"low", triggers: list[str]} | risk_policy |
| `justification` | str (LLM-written, cites evidence ids) | risk_policy |
| `plan` | {target_version, bump_kind: "patch"\|"minor"\|"major", changelog_hits: list[Chunk], breaking_changes: list[str]} | plan_remediation |
| `sandbox` | {supported: bool, baseline_failed: list[str], after_bump_failed: list[str], newly_failing: list[str], flaky_rerun: list[str]} | plan_remediation |
| `decision` | "auto_fix" \| "needs_human" \| "accept_risk" \| "not_applicable" \| "halted" | risk_policy / routing |
| `human` | {reviewer, verdict: "approve"\|"reject"\|"modify", modified_plan?, note, decided_at} | human_gate (on resume) |
| `pr` | {url, branch, number} | execute_pr |
| `trace_url` | str | record_outcome |
| `halt_reason` | str | any guardrail |

Every field written by an LLM is validated against a Pydantic model before it enters state. A validation failure sets `decision = halted` and routes straight to `record_outcome`.

---

## 3. Nodes, one by one

**ingest**
Parse the lockfile(s) into `dependencies`. Query OSV in one batched call for all (name, version) pairs; enrich each hit from the GitHub Advisory DB (CVSS, affected symbols, fixed versions); join EPSS from the local daily table. Advisory responses are cached in Postgres for 24 hours keyed by (package, version). The fetch step has a LangGraph retry policy (exponential backoff, max 4 attempts) and is the only node that talks to the outside world in live mode. Ends by fanning out one `Send("reachability", advisory)` per advisory. Untrusted text (advisory body) is run through the injection classifier here and flagged, never dropped, so the reviewer can still read it.

**reachability**
Static analysis only, no LLM. Walk the target repo's AST: is the package imported at all; if the advisory names vulnerable symbols, are any of them referenced; is the dependency a runtime or dev dependency (extras, `[dev]` groups, test-only imports). Produces call sites with file:line and a confidence score. Confidence is low when the advisory names no symbols (so we can only say "imported", not "vulnerable path reached") or when imports are dynamic.

**risk_policy**
Deterministic. `rules.py` computes a score from CVSS, EPSS, reachability, runtime-vs-dev, and package tier (from `tiers.yaml`; auth, crypto, serialization and network packages are "sensitive"). It sets `decision` to `not_applicable` (not reachable, high confidence), `accept_risk` (reachable but negligible EPSS and low CVSS, dev-only, etc.), or "continue" for everything else. It also emits the list of gate triggers. Only after the decision is fixed does the LLM run, and it is asked for one thing: a justification paragraph that cites evidence by id. The LLM cannot change the score or the decision. This separation is the single most important design choice for making the regression suite meaningful: the thing being tested is a policy plus a bounded LLM task, not a free-form agent.

**plan_remediation**
Resolve the minimum version that clears the advisory and still satisfies the repo's constraints. Classify the bump as patch/minor/major. Fetch the changelog for the version range, chunk it, embed it into a throwaway index, and retrieve against the symbols the repo actually imports; the LLM summarises breaking changes *from those chunks only* and must cite chunk ids. Then the sandbox: build (or reuse) the per-repo Docker layer, run the test suite unchanged (baseline), apply the bump, run again, compute `newly_failing` = failed-after minus failed-before, rerun those once to drop flakes. If the repo can't be installed or has no recognised test runner, `sandbox.supported = false`.

**routing (after plan_remediation)**
Pure function. `auto_fix` if and only if: bump is patch, `newly_failing` is empty, package is not in a sensitive tier, reachability confidence ≥ 0.7, no injection flag, budget under 80%. Otherwise `needs_human`.

**human_gate**
Calls `interrupt(payload)` where the payload is the one-screen evidence bundle (advisory summary, reachability proof, risk tier and triggers, plan, sandbox diff, changelog citations, justification, data freshness, injection flag if any). The checkpointer persists the whole branch state; the process can exit. Resume happens through `Command(resume={verdict, note, modified_plan?})` from the CLI (v1) or the web queue (v2). `modify` lets the reviewer change the target version; the graph then re-runs plan_remediation's sandbox step on the new version before proceeding.

**execute_pr**
Only reachable with `decision == auto_fix` or `human.verdict == approve`. Creates a branch `patchpilot/<advisory_id>`, applies the bump, runs the secret scanner over the diff and the PR body, and opens a PR whose body is the evidence bundle plus the LangSmith trace URL. The GitHub tool exposes exactly three operations (create branch, commit file, open PR); merge, force-push, and writes to protected branches or `.github/` do not exist as tools.

**record_outcome**
Writes the ledger row (decision, reviewer, verdict, timestamps, trace URL, PR URL), aggregates the scan summary, and marks the branch done. Ratification (see §5) is a separate nightly job, not part of the run.

---

## 4. Guardrails as code

| guardrail | where | behaviour on violation |
|---|---|---|
| Pydantic contracts on tool inputs and outputs | `guardrails/contracts.py` wraps every tool | halt branch, `halt_reason` set, trace tagged |
| Action allowlist | `tools/github_pr.py` only implements allowed ops; `allowlist.py` re-checks target branch and paths | halt |
| Injection classifier on advisory bodies and changelog text | ingest, plan_remediation | flag; forces `needs_human`; flagged text is shown to the reviewer inside a clearly marked quote block and never placed in a system prompt |
| Secret scan | execute_pr, before any write | halt |
| Budget meter | every LLM call | hard stop at cap; `needs_human` at 80% |
| Policy veto | risk_policy, routing | LLM output can never raise or lower a decision |
| Trace linkage | record_outcome | every PR and ledger row carries the trace URL |

---

## 5. Regression suite and gating

**Seeded golden set (~60 cases, built before launch).** Each case is a YAML file: a recorded advisory + a fixture repo snapshot (or a pointer into `patchpilot-demo-app` at a tagged commit) + the expected `decision`, expected `risk.tier`, expected gate triggers, and a short human rationale. Distribution: ~15 `not_applicable`, ~15 `auto_fix`, ~15 `needs_human` spread across each trigger, ~10 `accept_risk`, ~5 adversarial (injection text in advisory or changelog; misleading changelog that claims "no breaking changes" while tests fail).

**Evaluators (LangSmith).**
`decision_match` — exact match on `decision`; the blocking one.
`tier_match` — exact match on `risk.tier`.
`trigger_match` — set equality on gate triggers.
`evidence_faithfulness` — LLM-as-judge with the retrieved chunks and advisory as ground truth; checks every claim in `justification` and `breaking_changes` is supported by a cited id. Scored 0–1, threshold 0.9.
`cost_latency` — p95 tokens and seconds per advisory against `baseline.json`.

**Ratification of live decisions.** A nightly job promotes ledger rows to golden cases when either one reviewer decided and no one contested within 7 days, or two reviewers agreed. Contested rows go to `evals/disputed/`, are reported in CI, and never block.

**Flip handling.** A golden decision that changes blocks merge. The CI summary lists each flipped case with old vs new decision and both justifications. To accept the new behaviour, a developer opens a PR that edits the golden YAML; `golden-update.yml` requires two approvals for any change under `evals/golden/`. The golden dataset in LangSmith is versioned, and every eval run records the dataset version it was scored against.

---

## 6. CI workflow (`.github/workflows/ci.yml`)

Triggered on every PR to `patchpilot` and on pushes to `main`.

1. Set up Python 3.12 with `uv`; start Postgres as a service container; run migrations.
2. `ruff` and `mypy`.
3. `pytest tests/unit tests/graph` in recorded mode — no network, no LLM calls for unit tests; graph tests use a small deterministic fake model for control-flow (interrupt, resume, halt paths).
4. `python evals/run_evals.py --dataset patchpilot-golden@<pinned-version> --mode recorded` — real LLM calls for the justification and changelog steps (this is the part being regression-tested), using the repository's `LANGSMITH_API_KEY` and model key secrets. Cached advisory/changelog fixtures keep this to a few minutes.
5. Gate step reads `summary.json`: fail if any `decision_match` is false; fail if aggregate `evidence_faithfulness` < 0.9; fail if any score is below `baseline.json` by more than 0.02; fail if p95 cost > budget.
6. Post the summary as a PR comment with links to the LangSmith experiment and every flipped case.

`golden-update.yml` runs only when `evals/golden/**` changes and uses CODEOWNERS plus a required-reviewers check to enforce the second approval.

Prompts are pinned by Prompt Hub commit hash in `llm/prompts/manifest.yaml`; changing the hash is a code change and goes through the same gate.

---

## 7. Demo plan

**Fixture repo `patchpilot-demo-app`.** A small FastAPI service with about ten pinned dependencies chosen so every decision class appears at least once: two unreachable (e.g. an image library used only for formats the bug doesn't touch), two safe patch bumps, one sensitive-tier package with high EPSS (auth token library), one major bump that breaks tests, one dev-only dependency, one with no named symbols (low confidence), one whose changelog contains an injection attempt, one that resolves to `accept_risk`. Exact packages and versions are chosen from real historical advisories when the golden set is built, so results are reproducible forever.

**Recorded mode.** All OSV, GitHub Advisory, EPSS and changelog responses for the fixture are stored under `src/patchpilot/recorded/`. The demo, CI and the video all run with zero outbound calls except to the LLM and to GitHub for opening the PR.

**Shot list (target 2:00, real screen recording; AI tools only for storyboard, voiceover, title card, and editing).**

| time | screen | what happens |
|---|---|---|
| 0:00–0:10 | title card + architecture.svg | one sentence: what problem, what the agent does |
| 0:10–0:25 | terminal | `patchpilot scan https://github.com/<you>/patchpilot-demo-app` — output shows 10 advisories, then counts: 2 not_applicable, 2 auto_fix, 5 needs_human, 1 accept_risk |
| 0:25–0:40 | LangGraph Studio | the graph with five branches paused at `human_gate`; hover a paused branch to show checkpointed state |
| 0:40–1:05 | terminal (v1) or web queue (v2) | `patchpilot queue show <id>` on the auth-package case: evidence bundle on one screen; reviewer reads reachability proof and test diff; `patchpilot queue approve <id> --note "…"` |
| 1:05–1:20 | GitHub | the PR appears on the demo repo; scroll the evidence bundle; note branch protection, no auto-merge |
| 1:20–1:40 | LangSmith | open the trace linked from the PR; step through risk_policy → plan_remediation → interrupt → resume; show the golden dataset and the last CI experiment |
| 1:40–1:55 | GitHub Actions | a PR to PatchPilot that changes a prompt: CI fails with "1 golden decision flipped", with the diff shown |
| 1:55–2:00 | end card | links: repo, live queue, trace |

The GIF for the portfolio card is 0:40–1:20 trimmed to ~15 seconds.

**Live demo hosting (v2).** Web queue on Render/Fly free tier, Postgres on Neon/Supabase free tier, preloaded with the fixture's five pending cases. A nightly job closes demo PRs, resets the ledger, and re-runs the scan so the queue is always populated.

---

## 8. Build order

1. `policy/`, `tools/lockfile.py`, `tools/reach_ast.py`, unit tests — everything deterministic first.
2. `tools/osv.py`, `gh_advisory.py`, `epss.py` with recorded mode and the Postgres cache.
3. `graph/` with `ingest → reachability → risk_policy → record_outcome`; graph tests with a fake model.
4. `human_gate` + CLI queue; interrupt/resume tests including process restart.
5. `plan_remediation`: resolver, changelog retrieval, sandbox with baseline diff.
6. `execute_pr` + allowlist + secret scan against the demo repo.
7. Guardrails wrappers, budget meter, injection classifier.
8. Golden set (~60), evaluators, `run_evals.py`, `ci.yml`, `baseline.json`.
9. `patchpilot-demo-app` finalised and tagged; recorded fixtures frozen.
10. Web queue, hosting, video, README.
