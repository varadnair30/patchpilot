"""Durable storage: LangGraph checkpoints and the decision ledger.

Postgres is the system's only stateful component (ADR-0001): the worker writes checkpoints there,
the approval queue reads them, and the ledger records what a human decided. SQLite is the same
SQL through the same code path, so CI — and anyone who just cloned the repo — gets durable
interrupts across process restarts without running a database.

`DATABASE_URL` selects Postgres. With it unset, checkpoints and the ledger live in the SQLite file
at `PATCHPILOT_CHECKPOINT_DB` (`.patchpilot/checkpoints.sqlite` by default). The literal url
`"memory"` gives an in-process saver, for callers that do not want durability at all.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from pydantic import BaseModel

from patchpilot.config import Settings, get_settings
from patchpilot.graph import state as graph_state

SQLITE_PREFIX = "sqlite:///"
POSTGRES_PREFIXES = ("postgres://", "postgresql://")
MEMORY_URL = "memory"


class UnsupportedDatabase(ValueError):
    """The url does not name a database PatchPilot knows how to open."""


# Everything PatchPilot puts in a checkpoint is a Pydantic model from `graph/state.py`. LangGraph's
# serialiser warns on any type it was not told about, and a future version will refuse to load it,
# so declare them rather than relying on the permissive default.
STATE_MODELS: tuple[type, ...] = tuple(
    obj
    for obj in vars(graph_state).values()
    if isinstance(obj, type) and issubclass(obj, BaseModel)
)


def patchpilot_serde() -> JsonPlusSerializer:
    return JsonPlusSerializer(allowed_msgpack_modules=STATE_MODELS)


def checkpoint_url(settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    if settings.database_url:
        return settings.database_url
    return SQLITE_PREFIX + str(Path(settings.checkpoint_db).expanduser().resolve())


def _sqlite_path(url: str) -> str:
    path = Path(url[len(SQLITE_PREFIX) :])
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


@contextmanager
def open_checkpointer(url: str | None = None) -> Iterator[BaseCheckpointSaver]:
    """Open the saver named by `url` (defaulting to `checkpoint_url()`) for the duration of a call.

    `build_graph(checkpointer=...)` is unchanged: this only decides which saver it gets.
    """
    url = url or checkpoint_url()
    if url == MEMORY_URL:
        yield InMemorySaver()
        return
    if url.startswith(SQLITE_PREFIX):
        from langgraph.checkpoint.sqlite import SqliteSaver

        with SqliteSaver.from_conn_string(_sqlite_path(url)) as saver:
            saver.serde = patchpilot_serde()
            saver.setup()
            yield saver
        return
    if url.startswith(POSTGRES_PREFIXES):
        try:
            from langgraph.checkpoint.postgres import PostgresSaver
        except ImportError as e:  # pragma: no cover - depends on the installed extras
            raise UnsupportedDatabase(
                "DATABASE_URL points at Postgres; install the extra: pip install -e '.[postgres]'"
            ) from e

        with PostgresSaver.from_conn_string(url) as saver:
            saver.serde = patchpilot_serde()
            saver.setup()
            yield saver
        return
    raise UnsupportedDatabase(f"unsupported database url: {url!r}")


# --------------------------------------------------------------------------------------------
# Decision ledger
# --------------------------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS decisions (
    scan_id     TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    reviewer    TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    decided_at  TEXT NOT NULL,
    trace_url   TEXT,
    PRIMARY KEY (scan_id, advisory_id)
)
"""

# One row per (scan, advisory): the ledger records the decision that stands, and a second look at
# the same advisory supersedes the first. `excluded` is spelled the same in SQLite and Postgres.
_INSERT = """
INSERT INTO decisions (scan_id, advisory_id, reviewer, verdict, note, decided_at, trace_url)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_id, advisory_id) DO UPDATE SET
    reviewer   = excluded.reviewer,
    verdict    = excluded.verdict,
    note       = excluded.note,
    decided_at = excluded.decided_at,
    trace_url  = excluded.trace_url
"""

_SELECT = """
SELECT scan_id, advisory_id, reviewer, verdict, note, decided_at, trace_url
FROM decisions
"""


class DecisionRow(BaseModel):
    scan_id: str
    advisory_id: str
    reviewer: str
    verdict: str
    note: str = ""
    decided_at: datetime
    trace_url: str | None = None


class Ledger:
    """The `decisions` table. Step 8's nightly ratification job promotes these rows to golden
    cases; step 7 puts the trace url on them."""

    def __init__(self, connection: Any, placeholder: str) -> None:
        self._connection = connection
        self._placeholder = placeholder
        with self._cursor() as cur:
            cur.execute(_DDL)

    @contextmanager
    def _cursor(self) -> Iterator[Any]:
        cur = self._connection.cursor()
        try:
            yield cur
            self._connection.commit()
        finally:
            cur.close()

    def _sql(self, sql: str) -> str:
        return sql.replace("?", self._placeholder)

    def record(
        self,
        *,
        scan_id: str,
        advisory_id: str,
        reviewer: str,
        verdict: str,
        note: str = "",
        decided_at: datetime | None = None,
        trace_url: str | None = None,
    ) -> DecisionRow:
        row = DecisionRow(
            scan_id=scan_id,
            advisory_id=advisory_id,
            reviewer=reviewer,
            verdict=verdict,
            note=note,
            decided_at=decided_at or datetime.now(UTC),
            trace_url=trace_url,
        )
        with self._cursor() as cur:
            cur.execute(
                self._sql(_INSERT),
                (
                    row.scan_id,
                    row.advisory_id,
                    row.reviewer,
                    row.verdict,
                    row.note,
                    row.decided_at.isoformat(),
                    row.trace_url,
                ),
            )
        return row

    def list(self, scan_id: str | None = None) -> list[DecisionRow]:
        where = "WHERE scan_id = ? " if scan_id else ""
        sql = _SELECT + where + "ORDER BY decided_at, advisory_id"
        with self._cursor() as cur:
            cur.execute(self._sql(sql), (scan_id,) if scan_id else ())
            rows = cur.fetchall()
        return [
            DecisionRow(
                scan_id=r[0],
                advisory_id=r[1],
                reviewer=r[2],
                verdict=r[3],
                note=r[4],
                decided_at=datetime.fromisoformat(r[5]) if isinstance(r[5], str) else r[5],
                trace_url=r[6],
            )
            for r in rows
        ]


@contextmanager
def sqlite_connection(url: str) -> Iterator[sqlite3.Connection]:
    """A SQLite connection for `memory` or `sqlite:///`. Shared by the ledger and the queue."""
    path = ":memory:" if url == MEMORY_URL else _sqlite_path(url)
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


@contextmanager
def open_ledger(url: str | None = None) -> Iterator[Ledger]:
    url = url or checkpoint_url()
    if url == MEMORY_URL or url.startswith(SQLITE_PREFIX):
        with sqlite_connection(url) as connection:
            yield Ledger(connection, "?")
        return
    if url.startswith(POSTGRES_PREFIXES):
        try:
            import psycopg
        except ImportError as e:  # pragma: no cover - depends on the installed extras
            raise UnsupportedDatabase(
                "DATABASE_URL points at Postgres; install the extra: pip install -e '.[postgres]'"
            ) from e

        with psycopg.connect(url) as connection:
            yield Ledger(connection, "%s")
        return
    raise UnsupportedDatabase(f"unsupported database url: {url!r}")
