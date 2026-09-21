# PatchPilot

Human-gated dependency-vulnerability triage and remediation. A LangGraph state machine scans a
Python repository, works out which advisories are actually reachable in the code, scores them with
a **deterministic policy**, plans and sandbox-tests the minimal fix, and pauses at a durable
`interrupt()` whenever the policy will not decide alone. Every ratified decision becomes a golden
test case, and CI blocks any change that flips one.

**The model never decides.** It writes the justification and summarises changelogs — both checked
against cited evidence — and nothing else. Decision class, risk score, tier and gate triggers all
come from rules in YAML ([ADR-0002](docs/adr/0002-deterministic-policy-llm-writes-justification-only.md)).
That is what makes a regression suite over agent decisions meaningful: the thing under test is a
policy plus a bounded LLM task, not a free-running agent.

![Architecture](docs/architecture.svg)

**[Live approval queue](https://varadnair30.github.io/patchpilot/queue/)** ·
[design](docs/DESIGN.md) · [decisions](docs/adr) · [demo target](https://github.com/varadnair30/patchpilot-demo-app)

---

## What it does on the demo app

Ten pinned dependencies carrying real historical advisories produce eleven findings, and the
policy settles six of them without asking anyone:

| decision | count | why |
|---|---|---|
| `not_applicable` | 3 | package imported, but the advisory's symbols are never reached |
| `accept_risk` | 1 | dev-only tooling, negligible exploitation probability |
| `auto_fix` | 2 | patch bump, no gate triggers, and a real Docker run shows no new test failures |
| `needs_human` | 5 | sensitive tier, a bump above the ceiling, or a fix that cannot be installed |

Two of those are worth reading closely, because they are the cases a simpler tool gets wrong:

**requests** resolves to **2.32.2**, not the 2.32.0 the advisory names — PyPI yanked 2.32.0 and
2.32.1 ("conflicts with CVE-2024-35195 mitigation"), so the minimum *installable* safe version is
higher than the minimum safe version.

**starlette** cannot be fixed on its own. `fastapi 0.100.0` requires `starlette<0.28.0`, so pip
refuses the bump outright. The sandbox reports that as **unproven**, not as a clean run — an
install that fails prints no failing tests, and reading that as "green" is exactly how a broken
bump would earn `auto_fix`.

## Try it

```bash
pip install -e ".[dev]"

patchpilot scan fixtures/patchpilot-demo-app     # recorded mode: zero network
patchpilot queue list                            # the 5 advisories the policy gated
patchpilot queue show GHSA-75c5-xw7c-p5pm        # the evidence bundle, on one screen
patchpilot queue approve GHSA-75c5-xw7c-p5pm --note "reachable in app/auth.py"

pytest                                           # 621 tests, offline, no model, no Docker
```

The scan pauses at a durable `interrupt()` for every gated advisory, and each advisory is its own
`Send()` branch — so approving one never touches the others, and the process can exit between the
scan and the approval. Checkpoints and the decision ledger go to Postgres when `DATABASE_URL` is
set, and to a local SQLite file otherwise.

Set `OPENAI_API_KEY` to have `gpt-4o-mini` write the justifications (cents per scan); without it
the graph uses a deterministic template and costs nothing. **The decisions are identical either
way** — that is the point. `PATCHPILOT_LLM=off` forces the free path even with a key set.

## How a decision gets made

```
ingest → reachability → risk_policy → plan_remediation → justify → ⏸ human_gate → execute_pr
```

- **reachability** walks the AST: is the package imported, are the advisory's named symbols
  actually referenced, is it a runtime or dev dependency. A dynamic import (`importlib`,
  `__import__`) drops confidence to 0.40, because the AST cannot follow it and a confident
  "never imported" would be a lie.
- **risk_policy** scores CVSS, EPSS, exposure, scope and package tier against
  [`thresholds.yaml`](src/patchpilot/policy/thresholds.yaml). Auth, crypto, serialization and
  web-framework packages can never be dismissed by static analysis alone.
- **plan_remediation** resolves the minimum installable version, retrieves the release notes that
  mention the symbols this repo imports, and runs the test suite in Docker before and after the
  bump. `newly_failing` is the difference; anything that passes on a rerun is recorded as flaky.
- **human_gate** calls `interrupt()` with the evidence bundle. A reviewer can take days.
- **execute_pr** exposes exactly three operations: create branch, commit file, open pull request.
  Merge and force-push do not exist as tools, and `guardrails/allowlist.py` refuses protected
  branches and any path under `.github/`.

## Shape of the system

Three components around one database ([ADR-0001](docs/adr/0001-system-shape-vs-demo-deployment.md)):

- **worker** — owns the graph, the Docker sandbox and GitHub write access.
  `patchpilot worker --once|--loop`.
- **approval API** — lists what is waiting, shows one evidence bundle, records a verdict. It holds
  no model key and **cannot** start a scan or open a pull request; there is no such route, and the
  image does not contain the code to do either.
- **Postgres** — checkpoints, decision ledger, work queue. The only thing the other two share.

A verdict from the web queue becomes a queue row; the worker applies it and writes the ledger. The
API never moves the graph.

## Two repositories, and why

`patchpilot` is the agent. The scan target is a **separate** repository, and that separation is
load-bearing: `execute_pr` writes to the target, so PatchPilot must never hold write access to its
own policy, golden expectations or CI workflows. `tools/checkout.py` reads `.git` only at the path
being scanned and never searches upwards — precisely so a target that lives inside another
repository cannot inherit its remote.

`fixtures/patchpilot-demo-app` is the vendored copy of the demo target, kept so the suite runs
offline. It cannot drift from the recordings: every sandbox fixture is a claim about that exact
tree, so `tests/unit/test_demo_app_frozen.py` recomputes a digest and fails if the app changes
without the fixtures being re-recorded.

## The regression gate

38 golden cases — the eleven demo advisories end to end, 22 synthetic cases pinning one policy rule
each, and 5 adversarial cases carrying prompt injections. Each records the reasoning a reviewer
would give, because whoever reviews a flip was not there when it was decided.

```bash
python evals/run_evals.py             # deterministic evaluators, free, offline
python evals/run_evals.py --judge     # adds the gpt-4o faithfulness judge (~$0.09)
```

`decision_match` is the blocking check and needs no model, so it runs on every pull request
including forks, where secrets are unavailable. A missing key reports `graded: false` rather than
quietly turning the gate green. Changing a case under `evals/golden/**` requires two approvals.

Raising `auto_fix.max_bump` from `patch` to `minor` flips two decisions, and CI names both — which
is the gate doing its job rather than a hypothetical.

## Status

All ten steps of the build order are complete. What is deployed, and what is not:

| | |
|---|---|
| Graph, policy, sandbox, guardrails, golden gate | done, 621 tests |
| Worker, approval API, static queue page | done; verified end to end locally |
| Queue page on GitHub Pages | **live** |
| Demo app published and frozen to a tag | **live** |
| Hosted API (Render) and Postgres (Neon) | not deployed — the queue page talks to a local API |
| `execute_pr` against real GitHub | **tested against recorded fixtures; never run live** |

That last row is the honest caveat. The GitHub tool, the allowlist, the secret scan and the branch
naming are covered by contract tests that prove merge and force-push are impossible by
construction — but no pull request has yet been opened against the demo repository by a real
scan.

## Stack

Python 3.12 · LangGraph · LangSmith · FastAPI · Postgres / SQLite · Docker · Pydantic v2 ·
OpenAI (justification and changelog summary only) · pytest · ruff · GitHub Actions
