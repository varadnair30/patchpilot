"""`patchpilot worker` — the long-running process that owns the graph.

ADR-0001 is explicit that this is a service, not a cron job, and that GitHub Actions is only the
demo deployment of it. So the worker must not know where it is running: `--once` drains what is
there and exits, `--loop` keeps going. The Actions workflow calls `--once` and nothing in here
can tell.
"""

from datetime import UTC, datetime, timedelta

import pytest

from patchpilot.storage.queue import open_work_queue
from patchpilot.worker import WorkerResult, process_item, run_once


@pytest.fixture
def queue_url(tmp_path):
    return f"sqlite:///{tmp_path / 'q.sqlite'}"


@pytest.fixture
def queue(queue_url):
    with open_work_queue(queue_url) as q:
        yield q


class FakeRunner:
    """Stands in for the graph. The worker's job is dispatch and bookkeeping, not triage."""

    def __init__(self, fail_on=()):
        self.scans: list[tuple] = []
        self.resumes: list[tuple] = []
        self.fail_on = set(fail_on)

    def scan(self, repo_path, repo_url=None, thread_id=None):
        if "scan" in self.fail_on:
            raise RuntimeError("docker engine unreachable")
        self.scans.append((repo_path, repo_url, thread_id))
        return {"gates": 2, "advisories": 11}

    def resume(self, thread_id, interrupt_id, verdict, reviewer, note):
        if "resume" in self.fail_on:
            raise RuntimeError("thread vanished")
        self.resumes.append((thread_id, interrupt_id, verdict, reviewer, note))
        return {"remaining": 1}


# ==================================================================== dispatch


def test_a_scan_item_runs_a_scan(queue, queue_url):
    queue.enqueue(kind="scan", repo_path="/repos/demo", repo_url="https://x/y")
    runner = FakeRunner()

    result = run_once(queue_url, runner=runner, worker="w1")

    assert result.processed == 1 and result.failed == 0
    assert runner.scans == [("/repos/demo", "https://x/y", None)]
    assert runner.resumes == []


def test_a_resume_item_resumes_that_branch(queue, queue_url):
    queue.enqueue(
        kind="resume",
        thread_id="scan-1",
        interrupt_id="int-9",
        verdict="approve",
        reviewer="alice",
        note="looks right",
    )
    runner = FakeRunner()

    run_once(queue_url, runner=runner, worker="w1")

    assert runner.resumes == [("scan-1", "int-9", "approve", "alice", "looks right")]
    assert runner.scans == []


def test_run_once_drains_everything_then_stops(queue, queue_url):
    for i in range(3):
        queue.enqueue(kind="scan", repo_path=f"/repo-{i}")
    runner = FakeRunner()

    result = run_once(queue_url, runner=runner, worker="w1")

    assert result.processed == 3
    assert len(runner.scans) == 3
    assert queue.pending() == []


def test_an_empty_queue_is_not_an_error(queue, queue_url):
    result = run_once(queue_url, runner=FakeRunner(), worker="w1")
    assert result == WorkerResult(processed=0, failed=0)


# ==================================================================== bookkeeping


def test_a_finished_item_is_marked_done_with_what_happened(queue, queue_url):
    item = queue.enqueue(kind="scan", repo_path="/a")
    run_once(queue_url, runner=FakeRunner(), worker="w1")

    done = queue.get(item.id)
    assert done.status == "done"
    assert "11" in done.note, "the note should say what the scan found"


def test_a_failing_item_is_marked_failed_and_does_not_stop_the_drain(queue, queue_url):
    """One poisoned repo must not stall every other job in the queue."""
    bad = queue.enqueue(kind="scan", repo_path="/bad")
    good = queue.enqueue(kind="resume", thread_id="t", interrupt_id="i", verdict="approve")
    runner = FakeRunner(fail_on={"scan"})

    result = run_once(queue_url, runner=runner, worker="w1")

    assert result.processed == 1 and result.failed == 1
    assert queue.get(bad.id).status == "failed"
    assert "docker" in queue.get(bad.id).note
    assert queue.get(good.id).status == "done", "the healthy item still ran"


def test_a_failure_records_the_exception_type_not_a_traceback(queue, queue_url):
    item = queue.enqueue(kind="scan", repo_path="/bad")
    run_once(queue_url, runner=FakeRunner(fail_on={"scan"}), worker="w1")
    note = queue.get(item.id).note
    assert "RuntimeError" in note
    assert "Traceback" not in note, "the note is a summary, the log has the detail"


def test_the_worker_claims_under_its_own_name(queue, queue_url):
    item = queue.enqueue(kind="scan", repo_path="/a")
    run_once(queue_url, runner=FakeRunner(), worker="worker-42")
    assert queue.get(item.id).claimed_by == "worker-42"


# ==================================================================== crash recovery


def test_an_item_abandoned_by_a_dead_worker_is_picked_up(queue, queue_url):
    item = queue.enqueue(kind="scan", repo_path="/a")
    queue.claim("worker-that-died")
    queue.force_claimed_at(item.id, datetime.now(UTC) - timedelta(hours=2))

    runner = FakeRunner()
    result = run_once(queue_url, runner=runner, worker="w2", stale_seconds=3600)

    assert result.processed == 1
    assert runner.scans == [("/a", None, None)]


def test_a_recently_claimed_item_is_left_alone(queue, queue_url):
    queue.enqueue(kind="scan", repo_path="/a")
    queue.claim("worker-still-working")

    result = run_once(queue_url, runner=FakeRunner(), worker="w2", stale_seconds=3600)
    assert result.processed == 0


# ==================================================================== one item at a time


def test_process_item_dispatches_on_kind():
    runner = FakeRunner()
    from patchpilot.storage.queue import QueueItem

    scan = QueueItem(id=1, kind="scan", repo_path="/a", enqueued_at=datetime.now(UTC))
    note = process_item(scan, runner)
    assert runner.scans and "11" in note

    resume = QueueItem(
        id=2,
        kind="resume",
        thread_id="t",
        interrupt_id="i",
        verdict="reject",
        reviewer="bob",
        enqueued_at=datetime.now(UTC),
    )
    process_item(resume, runner)
    assert runner.resumes[0][2] == "reject"


def test_an_unknown_kind_is_a_failure_not_a_crash():
    from patchpilot.storage.queue import QueueItem

    item = QueueItem.model_construct(
        id=1, kind="something-new", status="running", enqueued_at=datetime.now(UTC)
    )
    with pytest.raises(ValueError, match="unknown work kind"):
        process_item(item, FakeRunner())
