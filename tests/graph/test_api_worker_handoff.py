"""API records a verdict, worker applies it — the whole point of the two-service split.

ADR-0001 says the worker and the approval API share nothing but the database. These tests drive
both halves against one store and check the handoff really works, and really is one-directional.
"""

import pytest
from fastapi.testclient import TestClient
from test_ingest_reachability import GATED

from patchpilot.api.app import create_app
from patchpilot.graph.build import build_graph
from patchpilot.graph.queue import pending_gates
from patchpilot.graph.state import RepoRef
from patchpilot.storage.db import open_checkpointer
from patchpilot.worker import run_once


@pytest.fixture
def system(tmp_path, monkeypatch, demo_app):
    """One SQLite file playing the part of Postgres, with a scan parked at its gates."""
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(tmp_path / "state.sqlite"))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    with open_checkpointer() as saver:
        build_graph(saver, justifier=None, summariser=None).invoke(
            {"scan_id": "demo", "repo": RepoRef(path=str(demo_app))},
            config={"configurable": {"thread_id": "demo"}},
        )
    with TestClient(create_app(rate_limit_per_minute=1000)) as client:
        yield client
    get_settings.cache_clear()


def open_gates() -> list:
    with open_checkpointer() as saver:
        return pending_gates(build_graph(saver, justifier=None, summariser=None), "demo")


def test_a_verdict_recorded_by_the_api_is_applied_by_the_worker(system):
    assert len(open_gates()) == len(GATED)
    target = system.get("/api/queue").json()["items"][0]

    posted = system.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "approve", "reviewer": "alice", "note": "evidence checked"},
    )
    assert posted.status_code == 200

    # Nothing has moved yet: the API only wrote a row.
    assert len(open_gates()) == len(GATED)

    result = run_once(worker="w1")
    assert (result.processed, result.failed) == (1, 0)

    remaining = open_gates()
    assert len(remaining) == len(GATED) - 1
    assert target["interrupt_id"] not in {g.interrupt_id for g in remaining}

    with open_checkpointer() as saver:
        graph = build_graph(saver, justifier=None, summariser=None)
        values = graph.get_state({"configurable": {"thread_id": "demo"}}).values
    decided = next(a for a in values["advisories"] if a.advisory_id == target["advisory_id"])
    assert decided.human.verdict == "approve"
    assert decided.human.reviewer == "alice"
    assert decided.human.note == "evidence checked"


def test_the_queue_shrinks_as_verdicts_are_applied(system):
    for expected_remaining in range(len(GATED) - 1, -1, -1):
        listing = system.get("/api/queue").json()
        target = listing["items"][0]
        system.post(
            f"/api/queue/{target['interrupt_id']}/verdict",
            json={"verdict": "approve", "reviewer": "alice"},
        )
        run_once(worker="w1")
        assert system.get("/api/queue").json()["count"] == expected_remaining

    assert system.get("/api/queue").json()["count"] == 0


def test_a_rejection_is_applied_without_opening_anything(system):
    target = system.get("/api/queue").json()["items"][0]
    system.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "reject", "reviewer": "bob", "note": "wait for the next release"},
    )
    run_once(worker="w1")

    with open_checkpointer() as saver:
        values = (
            build_graph(saver, justifier=None, summariser=None)
            .get_state({"configurable": {"thread_id": "demo"}})
            .values
        )
    decided = next(a for a in values["advisories"] if a.advisory_id == target["advisory_id"])
    assert decided.human.verdict == "reject"
    assert decided.pr is None, "a rejected advisory must never have a pull request"
