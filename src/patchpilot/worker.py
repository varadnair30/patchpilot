"""The worker: a long-running process that owns the graph, the sandbox and GitHub access.

ADR-0001 calls this a service, and GitHub Actions only the *demo deployment* of it. Nothing here
knows which it is. `--once` drains the queue and exits, which is what the Actions workflow calls;
`--loop` keeps polling, which is what a container does. Same code, same behaviour.

The worker is the only component that can start a scan or open a pull request. The approval API
cannot: it writes a row to the queue and this process notices. That separation is what lets the API
run with no LLM key, no Docker socket and no GitHub token.

Failures are per item. A repository whose sandbox will not build fails that one item and the drain
continues, because one poisoned repo must not stall every other job.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Protocol

from pydantic import BaseModel

from patchpilot.storage.queue import QueueItem, WorkQueue, open_work_queue

POLL_SECONDS = 5.0


class WorkerResult(BaseModel):
    processed: int = 0
    failed: int = 0


class Runner(Protocol):
    """What the worker needs from the graph. A Protocol so tests can stand in for it."""

    def scan(
        self, repo_path: str, repo_url: str | None = None, thread_id: str | None = None
    ) -> dict[str, Any]: ...

    def resume(
        self, thread_id: str, interrupt_id: str, verdict: str, reviewer: str, note: str
    ) -> dict[str, Any]: ...


class GraphRunner:
    """The real runner. Builds the graph against the durable checkpointer for each unit of work."""

    def scan(
        self, repo_path: str, repo_url: str | None = None, thread_id: str | None = None
    ) -> dict[str, Any]:
        from pathlib import Path

        from patchpilot.cli.main import build_repo_ref
        from patchpilot.graph.build import build_graph
        from patchpilot.graph.queue import pending_gates
        from patchpilot.storage.db import open_checkpointer

        scan_id = thread_id or str(uuid.uuid4())
        with open_checkpointer() as saver:
            graph = build_graph(saver)
            state = graph.invoke(
                {"scan_id": scan_id, "repo": build_repo_ref(Path(repo_path), repo_url)},
                config={"configurable": {"thread_id": scan_id}},
            )
            gates = pending_gates(graph, scan_id)
        # A branch parked at its gate has published nothing back to the parent, so the parent's
        # `advisories` still holds that advisory as ingest left it. Adding the two lists together
        # counts every gated advisory twice; count distinct ids instead.
        advisory_ids = {a.advisory_id for a in state.get("advisories", [])}
        advisory_ids |= {gate.payload.advisory_id for gate in gates}
        return {
            "scan_id": scan_id,
            "advisories": len(advisory_ids),
            "gates": len(gates),
        }

    def resume(
        self, thread_id: str, interrupt_id: str, verdict: str, reviewer: str, note: str
    ) -> dict[str, Any]:
        from patchpilot.graph.build import build_graph
        from patchpilot.graph.nodes.human_gate import ResumeCommand
        from patchpilot.graph.queue import pending_gates, resume_gate
        from patchpilot.storage.db import open_checkpointer

        with open_checkpointer() as saver:
            graph = build_graph(saver)
            resume_gate(
                graph,
                thread_id,
                interrupt_id,
                ResumeCommand(verdict=verdict, reviewer=reviewer, note=note),
            )
            remaining = len(pending_gates(graph, thread_id))
        return {"thread_id": thread_id, "remaining": remaining}


def process_item(item: QueueItem, runner: Runner) -> str:
    """Do one unit of work and return the note to record. Raises on failure."""
    if item.kind == "scan":
        outcome = runner.scan(
            repo_path=item.repo_path or "",
            repo_url=item.repo_url,
            thread_id=item.thread_id,
        )
        return (
            f"scanned {item.repo_path}: {outcome.get('advisories', 0)} advisories, "
            f"{outcome.get('gates', 0)} awaiting a human"
        )
    if item.kind == "resume":
        outcome = runner.resume(
            thread_id=item.thread_id or "",
            interrupt_id=item.interrupt_id or "",
            verdict=item.verdict or "",
            reviewer=item.reviewer or "unknown",
            note=item.note,
        )
        return (
            f"{item.verdict}d {item.thread_id}/{item.interrupt_id}; "
            f"{outcome.get('remaining', 0)} still awaiting a human"
        )
    raise ValueError(f"unknown work kind {item.kind!r}")


def drain(queue: WorkQueue, runner: Runner, worker: str, stale_seconds: int) -> WorkerResult:
    result = WorkerResult()
    while (item := queue.claim(worker, stale_seconds=stale_seconds)) is not None:
        try:
            note = process_item(item, runner)
        except Exception as e:
            # One bad item fails alone. The type and message go in the queue row; the traceback
            # belongs in the process log, not in a column a web page renders.
            queue.fail(item.id, note=f"{e.__class__.__name__}: {e}"[:500])
            result.failed += 1
            print(f"[worker {worker}] item {item.id} failed: {e.__class__.__name__}: {e}")
            continue
        queue.complete(item.id, note=note[:500])
        result.processed += 1
        print(f"[worker {worker}] item {item.id} done: {note}")
    return result


def run_once(
    url: str | None = None,
    runner: Runner | None = None,
    worker: str | None = None,
    stale_seconds: int = 1800,
) -> WorkerResult:
    """Drain whatever is queued, then return. This is what the Actions workflow calls."""
    worker = worker or f"worker-{uuid.uuid4().hex[:8]}"
    runner = runner or GraphRunner()
    with open_work_queue(url) as queue:
        return drain(queue, runner, worker, stale_seconds)


def run_loop(
    url: str | None = None,
    runner: Runner | None = None,
    worker: str | None = None,
    stale_seconds: int = 1800,
    poll_seconds: float = POLL_SECONDS,
    max_cycles: int | None = None,
) -> WorkerResult:
    """Keep draining. This is what a container does. `max_cycles` exists so tests can bound it."""
    worker = worker or f"worker-{uuid.uuid4().hex[:8]}"
    runner = runner or GraphRunner()
    total = WorkerResult()
    cycles = 0
    with open_work_queue(url) as queue:
        while max_cycles is None or cycles < max_cycles:
            batch = drain(queue, runner, worker, stale_seconds)
            total.processed += batch.processed
            total.failed += batch.failed
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            time.sleep(poll_seconds)
    return total
