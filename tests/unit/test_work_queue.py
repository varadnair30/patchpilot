"""The queue table the worker consumes.

ADR-0001: the worker and the approval API share nothing but Postgres. The API records that someone
approved something; the worker notices and resumes the thread. Neither calls the other, so the API
needs no LLM key, no Docker and no GitHub token — it cannot start a scan or open a pull request
even if it wanted to.

That means the queue's guarantees carry real weight, and the two that matter most are: an item is
claimed by exactly one worker, and a crashed worker's item comes back rather than vanishing.
"""

from datetime import UTC, datetime, timedelta

import pytest

from patchpilot.storage.queue import (
    QueueItem,
    WorkKind,
    open_work_queue,
)


@pytest.fixture
def queue(tmp_path):
    with open_work_queue(f"sqlite:///{tmp_path / 'q.sqlite'}") as q:
        yield q


# ==================================================================== enqueue and claim


def test_an_enqueued_scan_comes_back_as_pending(queue):
    item = queue.enqueue(kind="scan", repo_path="/repos/demo", repo_url="https://x/y")
    assert item.id > 0
    assert item.kind == "scan"
    assert item.status == "pending"

    pending = queue.pending()
    assert [p.id for p in pending] == [item.id]


def test_claiming_returns_the_oldest_item_first(queue):
    first = queue.enqueue(kind="scan", repo_path="/a")
    second = queue.enqueue(kind="scan", repo_path="/b")
    assert queue.claim("worker-1").id == first.id
    assert queue.claim("worker-1").id == second.id


def test_an_item_is_claimed_by_exactly_one_worker(queue):
    """Two workers polling the same table must not both run the same scan."""
    queue.enqueue(kind="scan", repo_path="/a")
    first = queue.claim("worker-1")
    second = queue.claim("worker-2")
    assert first is not None
    assert second is None, "a claimed item must not be handed out again"


def test_claiming_an_empty_queue_returns_none(queue):
    assert queue.claim("worker-1") is None


def test_a_claim_records_which_worker_took_it(queue):
    queue.enqueue(kind="scan", repo_path="/a")
    item = queue.claim("worker-7")
    assert item.status == "running"
    assert item.claimed_by == "worker-7"
    assert item.claimed_at is not None


# ==================================================================== finishing


def test_completing_an_item_takes_it_out_of_the_queue(queue):
    queue.enqueue(kind="scan", repo_path="/a")
    item = queue.claim("w1")
    queue.complete(item.id, note="2 advisories awaiting a human")

    assert queue.pending() == []
    assert queue.claim("w1") is None
    done = queue.get(item.id)
    assert done.status == "done" and "awaiting" in done.note


def test_a_failed_item_records_why(queue):
    queue.enqueue(kind="scan", repo_path="/a")
    item = queue.claim("w1")
    queue.fail(item.id, note="docker engine unreachable")
    failed = queue.get(item.id)
    assert failed.status == "failed"
    assert "docker" in failed.note


def test_a_failed_item_is_not_retried_automatically(queue):
    """A failure is a thing a human should look at, not something to spin on."""
    queue.enqueue(kind="scan", repo_path="/a")
    item = queue.claim("w1")
    queue.fail(item.id, note="boom")
    assert queue.claim("w1") is None


# ==================================================================== crash recovery


def test_an_item_abandoned_by_a_dead_worker_is_reclaimed(queue):
    """The worker is a long-running process that can be killed mid-scan. Its item must come back."""
    queue.enqueue(kind="scan", repo_path="/a")
    taken = queue.claim("worker-that-dies")

    stale = datetime.now(UTC) - timedelta(hours=2)
    queue.force_claimed_at(taken.id, stale)

    recovered = queue.reclaim_stale(older_than_seconds=3600)
    assert recovered == [taken.id]
    again = queue.claim("worker-2")
    assert again is not None and again.id == taken.id
    assert again.attempts == 2, "the retry is visible, so a poison item can be spotted"


def test_a_healthy_worker_keeps_its_item(queue):
    queue.enqueue(kind="scan", repo_path="/a")
    taken = queue.claim("worker-1")
    assert queue.reclaim_stale(older_than_seconds=3600) == []
    assert queue.get(taken.id).status == "running"


def test_an_item_that_keeps_dying_is_given_up_on(queue):
    """Otherwise one bad repo occupies the worker forever."""
    queue.enqueue(kind="scan", repo_path="/a", max_attempts=2)
    stale = datetime.now(UTC) - timedelta(hours=2)

    first = queue.claim("w1")
    queue.force_claimed_at(first.id, stale)
    queue.reclaim_stale(older_than_seconds=3600)

    second = queue.claim("w2")
    queue.force_claimed_at(second.id, stale)
    queue.reclaim_stale(older_than_seconds=3600)

    assert queue.claim("w3") is None
    dead = queue.get(first.id)
    assert dead.status == "failed"
    assert "attempts" in dead.note


# ==================================================================== resume items


def test_a_resume_item_carries_the_verdict_the_api_recorded(queue):
    """The API cannot resume a thread itself — it has no graph. It records the verdict here."""
    item = queue.enqueue(
        kind="resume",
        thread_id="scan-123",
        interrupt_id="int-abc",
        verdict="approve",
        reviewer="alice",
        note="evidence checked",
    )
    claimed = queue.claim("w1")
    assert claimed.kind == "resume"
    assert claimed.thread_id == "scan-123"
    assert claimed.interrupt_id == "int-abc"
    assert (claimed.verdict, claimed.reviewer, claimed.note) == (
        "approve",
        "alice",
        "evidence checked",
    )
    assert claimed.id == item.id


@pytest.mark.parametrize("kind", ["scan", "resume"])
def test_both_kinds_share_one_queue_in_arrival_order(queue, kind: WorkKind):
    queue.enqueue(kind="resume", thread_id="t1", interrupt_id="i1", verdict="approve")
    queue.enqueue(kind="scan", repo_path="/a")
    assert [i.kind for i in queue.pending()] == ["resume", "scan"]


def test_a_resume_without_a_verdict_is_rejected(queue):
    with pytest.raises(ValueError, match="verdict"):
        queue.enqueue(kind="resume", thread_id="t1", interrupt_id="i1")


def test_a_scan_without_a_repo_is_rejected(queue):
    with pytest.raises(ValueError, match="repo_path"):
        queue.enqueue(kind="scan")


def test_the_same_verdict_cannot_be_queued_twice(queue):
    """A double-click in the web queue must not resume the same branch twice."""
    queue.enqueue(kind="resume", thread_id="t1", interrupt_id="i1", verdict="approve")
    with pytest.raises(ValueError, match="already queued"):
        queue.enqueue(kind="resume", thread_id="t1", interrupt_id="i1", verdict="reject")


def test_a_second_verdict_is_allowed_once_the_first_is_done(queue):
    queue.enqueue(kind="resume", thread_id="t1", interrupt_id="i1", verdict="approve")
    item = queue.claim("w1")
    queue.complete(item.id)
    again = queue.enqueue(kind="resume", thread_id="t1", interrupt_id="i2", verdict="approve")
    assert again.id != item.id


# ==================================================================== durability


def test_the_queue_survives_reopening_the_database(tmp_path):
    url = f"sqlite:///{tmp_path / 'q.sqlite'}"
    with open_work_queue(url) as q:
        q.enqueue(kind="scan", repo_path="/a")
    with open_work_queue(url) as q:
        assert [i.repo_path for i in q.pending()] == ["/a"]


def test_queue_items_round_trip_their_timestamps(queue):
    item = queue.enqueue(kind="scan", repo_path="/a")
    stored = queue.get(item.id)
    assert isinstance(stored.enqueued_at, datetime)
    assert stored.enqueued_at.tzinfo is not None
    assert abs((datetime.now(UTC) - stored.enqueued_at).total_seconds()) < 60


def test_an_unknown_id_is_none(queue):
    assert queue.get(9999) is None


def test_a_queue_item_is_serialisable(queue):
    item = queue.enqueue(kind="scan", repo_path="/a", repo_url="https://x/y")
    assert QueueItem.model_validate_json(item.model_dump_json()) == item
