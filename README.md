# PatchPilot

Human-gated dependency-vulnerability triage and remediation. A LangGraph state machine scans a
Python repository, works out which advisories are actually reachable, scores them with a
deterministic policy, plans and sandbox-tests the minimal fix, and pauses at a durable
`interrupt()` for a human whenever the policy says so. Every ratified human decision becomes a golden
test case; a LangSmith-driven regression suite blocks any change that flips one.

![Architecture](docs/architecture.svg)

Full design: [docs/DESIGN.md](docs/DESIGN.md) · decisions: [docs/adr](docs/adr)

## Status — week 1

| step | what | state |
|---|---|---|
| 1 | state schema, lockfile parser, AST reachability, CVSS calculator, recorded-response store | done |
| 2 | OSV + EPSS clients with recorded/live modes, curated symbol overlay | done |
| 3 | graph: `ingest → Send(advisory subgraph) × N → collect`, CLI `patchpilot scan` | done |
| 4 | `risk_policy` (deterministic rules, YAML thresholds/tiers) + `justify` (OpenAI, citation-checked, template fallback, budget meter) | done |
| 5 | `human_gate` with `interrupt()` + PostgresSaver + CLI approval queue | next |
| 6 | `plan_remediation`: resolver, changelog retrieval, Docker sandbox baseline diff | |
| 7 | `execute_pr`, allowlist, secret scan | |
| 8 | golden set, evaluators, CI gate | |

## Try it

```bash
pip install -e ".[dev]"
patchpilot scan fixtures/patchpilot-demo-app        # recorded mode: zero network
pytest                                              # 62 tests, all offline, LLM off
```

Set `OPENAI_API_KEY` to have `gpt-4o-mini` write the justifications (a few cents per scan);
without it the graph uses a deterministic template and costs nothing. Decisions are identical
either way, by design (ADR-0002). `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY` traces every
node and model call.

Live mode (`PATCHPILOT_MODE=live`) calls OSV.dev and FIRST EPSS; add `PATCHPILOT_RECORD=1` (or run
`patchpilot record <repo>`) to refresh the fixtures under `src/patchpilot/recorded/fixtures`.

`fixtures/patchpilot-demo-app` is the deterministic demo target: a small FastAPI service with ten
pinned dependencies carrying real historical advisories, chosen so every decision class appears.
It will move to its own public repository once `execute_pr` exists.
