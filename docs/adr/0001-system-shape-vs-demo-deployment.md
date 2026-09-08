# ADR-0001: System shape vs. demo deployment

**Status:** accepted · **Date:** 2026-09-08

## Context

PatchPilot has two audiences: engineering teams who would run it against their repositories, and reviewers of the project (portfolio visitors, interviewers) who need a deterministic public demo at zero hosting cost. Free-tier constraints must not be allowed to define the architecture.

## Decision

The **system** is described and built as three services around one database:

1. **Worker** — a long-running process that owns the LangGraph graph, the Docker sandbox, and GitHub write access. It consumes scan requests and resume events from a queue table, and resumes interrupted threads as soon as a verdict lands. In production this runs as a container (ECS/Kubernetes/a VM), not a cron job.
2. **Approval queue API** — a thin, stateless FastAPI service: list pending interrupts, show one evidence bundle, record a verdict. It holds no LLM key and cannot start scans.
3. **Postgres** — checkpoints, decision ledger, advisory cache, EPSS table. The only stateful component and the only integration point between the other two.

The **demo deployment** of the worker is GitHub Actions: a nightly workflow resets the fixture repo and a `repository_dispatch`-triggered workflow performs resumes. This gives a 1–2 minute approve-to-PR latency, unlimited free minutes on a public repo, Docker availability, and secret storage. The API runs on a free container host behind a keep-alive ping; the React frontend is static. The API is packaged both as a Dockerfile and as a plain ASGI app so it can move between container hosts and serverless hosts with a URL change.

## Consequences

- The worker code has exactly one entry point (`patchpilot worker --once` / `--loop`); the Actions workflow calls `--once`. Nothing in the worker knows it is running in CI.
- Documentation, the README, and interview answers describe the *system* shape first and label GitHub Actions as the demo deployment of the worker.
- When cost is no object, the demo deployment is replaced by running the same worker container on any host with Docker; no code changes.
