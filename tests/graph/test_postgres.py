"""The Postgres half of step 5. Skipped unless DATABASE_URL points at a real database.

CI covers the same code paths with SQLite (see test_human_gate.py and test_storage_db.py); these
tests exist so that `docker compose up -d postgres && pytest` proves the production saver too.
"""

import os
import uuid

import pytest
from test_human_gate import GATED
from test_ingest_reachability import EXPECTED_SUMMARY

from patchpilot.graph.build import build_graph
from patchpilot.graph.nodes.human_gate import ResumeCommand
from patchpilot.graph.queue import pending_gates, resume_gate
from patchpilot.graph.state import RepoRef
from patchpilot.storage.db import open_checkpointer, open_ledger

# Captured at import time: conftest strips DATABASE_URL from the environment so that the rest of
# the suite can never accidentally reach a database.
PG_URL = os.environ.get("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not PG_URL.startswith(("postgres://", "postgresql://")),
    reason="DATABASE_URL is not set to a Postgres database",
)


def test_postgres_checkpointer_holds_a_gate_across_a_restart(demo_app):
    thread = f"pg-{uuid.uuid4()}"
    config = {"configurable": {"thread_id": thread}}

    with open_checkpointer(PG_URL) as saver:
        graph = build_graph(saver, justifier=None)
        graph.invoke({"scan_id": thread, "repo": RepoRef(path=str(demo_app))}, config=config)
        assert {g.payload.advisory_id for g in pending_gates(graph, thread)} == GATED

    with open_checkpointer(PG_URL) as saver:
        graph = build_graph(saver, justifier=None)
        for _ in range(len(GATED)):
            gate = pending_gates(graph, thread)[0]
            resume_gate(
                graph, thread, gate.interrupt_id, ResumeCommand(verdict="approve", reviewer="pg")
            )
        snapshot = graph.get_state(config)

    assert snapshot.next == ()
    assert snapshot.values["summary"].counts == EXPECTED_SUMMARY


def test_postgres_ledger_round_trips_a_verdict():
    scan_id = f"pg-{uuid.uuid4()}"
    with open_ledger(PG_URL) as ledger:
        ledger.record(
            scan_id=scan_id,
            advisory_id="GHSA-75c5-xw7c-p5pm",
            reviewer="alice",
            verdict="approve",
            note="postgres round trip",
        )
        rows = ledger.list(scan_id=scan_id)
    assert [(r.reviewer, r.verdict, r.note) for r in rows] == [
        ("alice", "approve", "postgres round trip")
    ]
