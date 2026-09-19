"""The real GraphRunner against the fixture repo, in recorded mode.

The fake runner in tests/unit/test_worker.py proves the worker's dispatch and bookkeeping. This
proves the part the fake cannot: that driving the actual graph reports what really happened.
"""

from test_ingest_reachability import EXPECTED, GATED

from patchpilot.storage.queue import open_work_queue
from patchpilot.worker import GraphRunner, run_once


def test_the_runner_reports_the_advisories_it_actually_found(demo_app):
    """Gated branches publish nothing to the parent, so the parent still holds the advisory as
    ingest left it. Adding the parent's list to the gate list counted those twice — the demo app
    has 11 advisories and was reported as 16."""
    outcome = GraphRunner().scan(repo_path=str(demo_app), thread_id="worker-count")

    assert outcome["advisories"] == len(EXPECTED) == 11
    assert outcome["gates"] == len(GATED) == 5
    assert outcome["scan_id"] == "worker-count"


def test_a_queued_scan_runs_through_the_worker_and_records_what_it_found(demo_app, tmp_path):
    url = f"sqlite:///{tmp_path / 'q.sqlite'}"
    with open_work_queue(url) as queue:
        item = queue.enqueue(kind="scan", repo_path=str(demo_app))

    result = run_once(url, worker="w1")

    assert (result.processed, result.failed) == (1, 0)
    with open_work_queue(url) as queue:
        done = queue.get(item.id)
    assert done.status == "done"
    assert "11 advisories" in done.note
    assert "5 awaiting a human" in done.note


def test_the_worker_resumes_a_gate_a_reviewer_decided(demo_app, tmp_path):
    """The API records a verdict; the worker is what actually moves the graph."""
    from patchpilot.graph.build import build_graph
    from patchpilot.graph.queue import pending_gates
    from patchpilot.storage.db import open_checkpointer

    url = f"sqlite:///{tmp_path / 'q.sqlite'}"
    with open_work_queue(url) as queue:
        queue.enqueue(kind="scan", repo_path=str(demo_app), thread_id="t-resume")
    run_once(url, worker="w1")

    with open_checkpointer() as saver:
        gate = pending_gates(build_graph(saver), "t-resume")[0]

    with open_work_queue(url) as queue:
        queue.enqueue(
            kind="resume",
            thread_id="t-resume",
            interrupt_id=gate.interrupt_id,
            verdict="approve",
            reviewer="alice",
            note="checked",
        )
    result = run_once(url, worker="w1")
    assert (result.processed, result.failed) == (1, 0)

    with open_checkpointer() as saver:
        graph = build_graph(saver)
        assert len(pending_gates(graph, "t-resume")) == len(GATED) - 1
        advisories = {
            a.advisory_id: a
            for a in graph.get_state({"configurable": {"thread_id": "t-resume"}}).values[
                "advisories"
            ]
        }
    decided = advisories[gate.payload.advisory_id]
    assert decided.human.verdict == "approve" and decided.human.reviewer == "alice"
