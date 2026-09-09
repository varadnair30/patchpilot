"""Durable storage: the checkpointer factory and the decision ledger.

Postgres is the production target; SQLite is the same SQL and the same code path, so CI exercises
the ledger and the restart story offline. Postgres-only assertions live in
tests/graph/test_postgres.py and skip when DATABASE_URL is unset.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.sqlite import SqliteSaver

from patchpilot.storage.db import (
    DecisionRow,
    UnsupportedDatabase,
    checkpoint_url,
    open_checkpointer,
    open_ledger,
)


def test_checkpoint_url_prefers_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost:5432/patchpilot")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    assert checkpoint_url() == "postgresql://u:p@localhost:5432/patchpilot"


def test_checkpoint_url_falls_back_to_a_local_sqlite_file(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(tmp_path / "cp.sqlite"))
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    url = checkpoint_url()
    assert url.startswith("sqlite:///")
    assert Path(url.removeprefix("sqlite:///")) == tmp_path / "cp.sqlite"


def test_open_checkpointer_dispatches_on_scheme(tmp_path):
    with open_checkpointer("memory") as saver:
        assert isinstance(saver, InMemorySaver)
    with open_checkpointer(f"sqlite:///{tmp_path / 'cp.sqlite'}") as saver:
        assert isinstance(saver, SqliteSaver)
    assert (tmp_path / "cp.sqlite").exists()


def test_open_checkpointer_creates_the_parent_directory(tmp_path):
    target = tmp_path / "nested" / "dir" / "cp.sqlite"
    with open_checkpointer(f"sqlite:///{target}"):
        pass
    assert target.exists()


def test_open_checkpointer_rejects_an_unknown_scheme():
    with pytest.raises(UnsupportedDatabase):
        with open_checkpointer("mysql://localhost/patchpilot"):
            pass


# ------------------------------------------------------------------ ledger


def test_ledger_records_and_reads_back_a_decision(tmp_path):
    url = f"sqlite:///{tmp_path / 'led.sqlite'}"
    decided = datetime(2026, 9, 8, 12, 30, tzinfo=UTC)
    with open_ledger(url) as ledger:
        ledger.record(
            scan_id="scan-1",
            advisory_id="GHSA-75c5-xw7c-p5pm",
            reviewer="alice",
            verdict="approve",
            note="patch bump, symbol reachable",
            decided_at=decided,
            trace_url="https://smith.langchain.com/o/x/r/y",
        )
        rows = ledger.list()

    assert len(rows) == 1
    row = rows[0]
    assert isinstance(row, DecisionRow)
    assert (row.scan_id, row.advisory_id) == ("scan-1", "GHSA-75c5-xw7c-p5pm")
    assert row.reviewer == "alice"
    assert (row.verdict, row.note) == ("approve", "patch bump, symbol reachable")
    assert row.decided_at == decided
    assert row.trace_url == "https://smith.langchain.com/o/x/r/y"


def test_ledger_survives_reopening_the_same_database(tmp_path):
    url = f"sqlite:///{tmp_path / 'led.sqlite'}"
    with open_ledger(url) as ledger:
        ledger.record(scan_id="s", advisory_id="a", reviewer="alice", verdict="reject")
    with open_ledger(url) as ledger:
        assert [r.advisory_id for r in ledger.list()] == ["a"]


def test_ledger_filters_by_scan(tmp_path):
    url = f"sqlite:///{tmp_path / 'led.sqlite'}"
    with open_ledger(url) as ledger:
        ledger.record(scan_id="s1", advisory_id="a1", reviewer="alice", verdict="approve")
        ledger.record(scan_id="s2", advisory_id="a2", reviewer="bob", verdict="reject")
        assert {r.advisory_id for r in ledger.list()} == {"a1", "a2"}
        assert [r.advisory_id for r in ledger.list(scan_id="s1")] == ["a1"]


def test_a_second_verdict_on_the_same_advisory_supersedes_the_first(tmp_path):
    """One row per (scan, advisory): the ledger records the decision that stands."""
    url = f"sqlite:///{tmp_path / 'led.sqlite'}"
    with open_ledger(url) as ledger:
        ledger.record(scan_id="s", advisory_id="a", reviewer="alice", verdict="reject")
        ledger.record(scan_id="s", advisory_id="a", reviewer="bob", verdict="approve", note="ok")
        rows = ledger.list()
    assert len(rows) == 1
    assert (rows[0].reviewer, rows[0].verdict, rows[0].note) == ("bob", "approve", "ok")


def test_ledger_defaults_the_timestamp_to_now_in_utc(tmp_path):
    url = f"sqlite:///{tmp_path / 'led.sqlite'}"
    with open_ledger(url) as ledger:
        ledger.record(scan_id="s", advisory_id="a", reviewer="alice", verdict="approve")
        row = ledger.list()[0]
    assert row.decided_at.tzinfo is not None
    assert abs((datetime.now(UTC) - row.decided_at).total_seconds()) < 60


def test_the_checkpointer_declares_patchpilot_state_types(tmp_path, caplog):
    """LangGraph will refuse unregistered types in a future version; ours must all be declared."""
    import logging

    from langgraph.graph import END, START, StateGraph

    from patchpilot.graph.state import RepoRef, ScanState
    from patchpilot.storage.db import STATE_MODELS

    assert RepoRef in STATE_MODELS

    graph = StateGraph(ScanState)
    graph.add_node("n", lambda s: {"repo": RepoRef(path="x")})
    graph.add_edge(START, "n")
    graph.add_edge("n", END)

    url = f"sqlite:///{tmp_path / 'cp.sqlite'}"
    config = {"configurable": {"thread_id": "serde"}}
    with open_checkpointer(url) as saver:
        graph.compile(checkpointer=saver).invoke({"scan_id": "serde"}, config=config)

    with caplog.at_level(logging.WARNING):
        with open_checkpointer(url) as saver:
            assert graph.compile(checkpointer=saver).get_state(config).values["repo"].path == "x"
    assert "unregistered type" not in caplog.text
