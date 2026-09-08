# CLAUDE.md — working agreement for PatchPilot

You are continuing a partially built project. Read this file, then `docs/DESIGN.md` and
`docs/adr/*.md`, before writing code. The design is settled; your job is to implement the next
step faithfully, tests first, without adding components that were not agreed.

## What this is

Human-gated dependency-vulnerability triage and remediation. A LangGraph state machine scans a
Python repo, decides per advisory with a *deterministic policy*, plans and sandbox-tests the
minimal fix, pauses at a durable `interrupt()` for a human when the policy says so, and opens
evidence-backed PRs. Every ratified human decision becomes a golden test; CI blocks any change
that flips one. Read the architecture diagram: `docs/architecture.svg`.

## Non-negotiable rules

1. **The LLM never decides.** Decision class, score, tier and gate triggers come from
   `policy/rules.py` + `policy/*.yaml`. The model only writes justifications and summarises
   retrieved changelog chunks, through Pydantic schemas, with citation checks (ADR-0002).
2. **Recorded mode is the default.** Tests and CI must run with `PATCHPILOT_MODE=recorded` and
   zero network. `tests/conftest.py` monkeypatches httpx to fail on any call. New external
   calls go through `recorded/store.py` (`RecordedStore.fetch`) with browsable JSON fixtures.
3. **Every tool is a contract.** A tool is a function with a Pydantic input model and output
   model, wrapped in `@contract` (`guardrails/contracts.py`). Violations halt the branch
   (`decision="halted"`, `halt_reason` set); they never propagate as bare exceptions.
4. **Untrusted text is data.** Advisory bodies and changelogs live in
   `AdvisoryState.untrusted_text`, go only into user messages inside a delimited DATA block,
   never into system prompts, and never influence routing.
5. **Golden expectations change only deliberately.** `tests/graph/test_ingest_reachability.py`
   `EXPECTED` and `EXPECTED_SUMMARY` pin the fixture repo's decisions. If your change flips one,
   stop, explain why in the PR description, and update the expectation in a separate commit.
6. **No new components without cutting one.** Do not add queues, caches, frameworks, agents,
   vector DBs or services that are not in DESIGN.md. CrewAI is explicitly excluded.
7. **System shape vs demo deployment (ADR-0001).** The worker is a long-running service; GitHub
   Actions is only the demo deployment of that worker. Keep the language straight in code
   comments, README and docstrings.
8. **Python-only for v1.** Sandbox supports Python 3.9+ projects with requirements/pyproject/uv
   and pytest/unittest. Anything else is `sandbox.supported=false` and routes to a human.

## Repo map (what exists, what is next)

```
src/patchpilot/
  graph/state.py          ScanState (parent) + AdvisoryBranch (per-advisory subgraph) + reducers
  graph/build.py          START→ingest→Send(advisory×N)→collect ; subgraph reachability→risk_policy→justify
  graph/nodes/            ingest, reachability, risk_policy, justify   [next: plan_remediation, human_gate, execute_pr, record_outcome]
  graph/routing.py        pure routing functions
  policy/rules.py         deterministic score/tier/decision/triggers; thresholds.yaml, tiers.yaml, symbols.yaml
  tools/                  lockfile, osv, epss, cvss, reach_ast          [next: pypi_resolver, changelog_rag, sandbox, github_pr]
  guardrails/contracts.py validate-or-halt decorator                    [next: allowlist, injection, secrets, budget hard-stop, veto]
  llm/client.py           OpenAI via langchain-openai, pricing table, llm_enabled()
  llm/justify.py          evidence bundle with ids, citation validation, template fallback
  recorded/               RecordedStore + fixtures/{osv,epss}
  cli/main.py             `patchpilot scan <repo> [-v] [--json]`, `patchpilot record <repo>`
fixtures/patchpilot-demo-app   deterministic demo target (10 pinned vulnerable deps)
tests/unit, tests/graph        62 tests, all offline, <2s
```

## Commands

```bash
pip install -e ".[dev]"                   # add ".[llm,postgres]" from step 5 on
pytest                                    # must stay green and offline
ruff check src tests && ruff format --check src tests
patchpilot scan fixtures/patchpilot-demo-app -v
docker compose up -d postgres             # step 5+
```

Env: copy `.env.example` to `.env`. `OPENAI_API_KEY` enables the justifier (else template
fallback); `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY` enables tracing with no code changes.
`PATCHPILOT_LLM=off` forces the template path even with a key.

## Conventions

- Pydantic v2 models for every state field an LLM or tool writes; `TypedDict` only for graph state.
- Per-advisory work happens inside the `advisory` subgraph; the parent merges only
  `advisories` (by id) and `budget` (summed). Never return `repo` from a branch.
- Pure functions in `policy/` and `graph/routing.py`; side effects only in `tools/` and nodes.
- Thresholds and lists live in YAML, not code. Changing YAML is a decision change → golden gate.
- Tests: one file per module under `tests/unit`, graph behaviour under `tests/graph`. Use the
  `tmp_repo` fixture for synthetic repos and `demo_app` for the fixture app. Fake the LLM by
  passing `justifier=` (a callable) to `build_graph`; never call OpenAI in tests.
- Line length 100, ruff rules E/F/I/B/UP, Python ≥3.11.
- Commit per step on a branch `step-N-<name>`; PR description lists any golden changes.

## Build order with acceptance criteria

Step 4 is done. Each step below is one PR.

**Step 5 — human_gate + Postgres checkpointer + CLI queue**
- Add `human_gate` node to the subgraph after `justify` (before plan_remediation exists, gate on
  `risk.triggers` non-empty; later move it after plan_remediation). Use
  `langgraph.types.interrupt(payload)` where payload is the evidence bundle
  (`llm/justify.build_evidence`) plus decision, triggers, justification.
- Resume with `Command(resume={"verdict": "approve"|"reject", "reviewer": str, "note": str})`
  (`modify` with `target_version` arrives in step 6). Write `HumanDecision` into state.
- `storage/db.py`: PostgresSaver from `langgraph-checkpoint-postgres` behind `DATABASE_URL`;
  `build_graph(checkpointer=...)` unchanged. Ledger table `decisions(scan_id, advisory_id,
  reviewer, verdict, note, decided_at, trace_url)`.
- CLI: `patchpilot queue list|show <id>|approve <id>|reject <id>` reading pending interrupts from
  the checkpointer (`graph.get_state(config).tasks[*].interrupts`), resuming the right branch.
- Tests: (a) graph pauses with N interrupts for the fixture (expect 3 needs_human); (b) resume
  one branch does not affect the others; (c) **process-restart test**: run to interrupt with a
  SQLite/Postgres saver, build a *new* graph instance on the same thread, resume, assert the
  branch completes. Postgres tests skip when `DATABASE_URL` is unset; SQLite saver
  (`langgraph-checkpoint-sqlite`) covers restart in CI.
- Acceptance: `pytest` green; `patchpilot scan` then `patchpilot queue list` shows 3 pending;
  approve one; scan state shows `human.verdict` for that advisory only.

**Step 6 — plan_remediation**
- `tools/pypi_resolver.py`: minimal safe version satisfying repo constraints (recorded PyPI JSON).
- `tools/changelog_rag.py`: fetch release notes for the version range (recorded), chunk, embed
  (OpenAI embeddings, recorded), retrieve by the repo's imported symbols; LLM summarises breaking
  changes citing chunk ids (same citation check pattern as justify).
- `tools/sandbox.py`: Docker run; baseline test run → bump → rerun; `newly_failing` = after −
  before; rerun flakes once; `supported=false` when install/test runner detection fails.
- Routing after plan: `auto_fix` iff bump=patch, no newly failing tests, no triggers, confidence
  ≥0.7; else human_gate. Move human_gate after plan_remediation; `modify` verdict re-runs the
  sandbox for the chosen version.
- Acceptance: fixture yields starlette → needs_human (major, tests fail), python-multipart ×2
  and requests ×2 → auto_fix (if sandbox clean), pyjwt/cryptography → needs_human (tier).

**Step 7 — execute_pr + guardrails**
- `tools/github_pr.py` exposes exactly: create_branch, commit_file, open_pull_request. Token is a
  fine-grained PAT scoped to `patchpilot-demo-app`. `guardrails/allowlist.py` re-checks branch
  name prefix `patchpilot/`, protected-branch denial, and path denial for `.github/**`.
- `guardrails/secrets.py` scans diff + PR body before any write; `guardrails/injection.py`
  flags advisory/changelog text (LLM Guard or a small classifier) → sets `injection_flag`;
  `guardrails/budget.py` hard-stops at cap (halted) and triggers at 80%.
- Evidence bundle in PR body includes data freshness and the LangSmith trace URL.
- Acceptance: contract tests prove merge/force-push/protected-branch/CI-path writes are
  impossible by construction (no such tool exists; allowlist rejects).

**Step 8 — golden set, evaluators, CI gate**
- `evals/golden/*.yaml` (~60 cases; start from the 11 fixture cases + synthetic tmp_repo cases
  per rule + 5 adversarial injection cases). `evals/evaluators.py`: decision_match (exact),
  tier_match, trigger_match, evidence_faithfulness (gpt-4o judge over cited evidence),
  cost_latency. `evals/run_evals.py` writes `summary.json`; `evals/baseline.json` pinned.
- CI: pytest → evals → fail on any decision flip, faithfulness <0.9, score drop >0.02, p95 cost >
  budget; comment summary on PR. `golden-update.yml` requires 2 approvals on `evals/golden/**`.

**Step 9 — demo repo + recorded fixtures frozen.** Move `fixtures/patchpilot-demo-app` to its
own public repo, branch-protect `main`, tag, point recorded fixtures at the tag.

**Step 10 — worker entrypoint, approval API + React queue, hosting, video.**
`patchpilot worker --once|--loop` (consumes queue table, resumes threads); FastAPI queue API
(no LLM key, approve/reject only for anonymous, rate limit, `repository_dispatch` on approve);
GitHub Actions workflows for nightly reset and dispatch-resume; static React on GitHub Pages;
API on Render free + keep-alive; Postgres on Neon. Record the 2-minute video per
`docs/DESIGN.md` §7.

## When something is unclear

Prefer the smaller interpretation that keeps rules 1–8 intact, write the test that encodes
your interpretation, and note the assumption in the PR description. Do not silently widen
scope.
