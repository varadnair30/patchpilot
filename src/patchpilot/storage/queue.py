"""The work queue the worker consumes and the approval API writes to.

This table is the only thing connecting the two services (ADR-0001). The API records "someone
approved this"; the worker notices and resumes the thread. Neither calls the other, which is what
lets the API hold no LLM key, no Docker socket and no GitHub token: it *cannot* start a scan or
open a pull request, because the only verb it has is "write a row".

Two properties carry the weight:

* **An item is claimed by exactly one worker.** The claim is a conditional UPDATE — the row moves
  from pending to running in the same statement that selects it — so two workers polling the same
  table cannot both take the same scan.
* **A crashed worker's item comes back.** The worker is a long-running process that can be killed
  mid-scan; `reclaim_stale` returns anything left running too long. Attempts are counted, so an
  item that keeps killing its worker is failed rather than retried forever.

The SQL is the same on SQLite and Postgres, as with the decision ledger.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel

from patchpilot.storage.db import (
    MEMORY_URL,
    POSTGRES_PREFIXES,
    SQLITE_PREFIX,
    UnsupportedDatabase,
    checkpoint_url,
    sqlite_connection,
)

WorkKind = Literal["scan", "resume"]
WorkStatus = Literal["pending", "running", "done", "failed"]

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_STALE_SECONDS = 1800

_DDL = """
CREATE TABLE IF NOT EXISTS work_queue (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    repo_path    TEXT,
    repo_url     TEXT,
    thread_id    TEXT,
    interrupt_id TEXT,
    verdict      TEXT,
    reviewer     TEXT,
    note         TEXT NOT NULL DEFAULT '',
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    enqueued_at  TEXT NOT NULL,
    claimed_at   TEXT,
    claimed_by   TEXT
)
"""

# Postgres has no AUTOINCREMENT; the rest of the statement is identical.
_DDL_POSTGRES = _DDL.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")

_COLUMNS = (
    "id, kind, status, repo_path, repo_url, thread_id, interrupt_id, verdict, reviewer, "
    "note, attempts, max_attempts, enqueued_at, claimed_at, claimed_by"
)


class QueueItem(BaseModel):
    id: int
    kind: WorkKind
    status: WorkStatus = "pending"

    # scan items
    repo_path: str | None = None
    repo_url: str | None = None

    # resume items
    thread_id: str | None = None
    interrupt_id: str | None = None
    verdict: str | None = None
    reviewer: str | None = None

    note: str = ""
    attempts: int = 0
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    enqueued_at: datetime
    claimed_at: datetime | None = None
    claimed_by: str | None = None


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value))


class WorkQueue:
    def __init__(self, connection: Any, placeholder: str) -> None:
        self._connection = connection
        self._placeholder = placeholder
        with self._cursor() as cur:
            cur.execute(_DDL if placeholder == "?" else _DDL_POSTGRES)

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

    def _row(self, row: Any) -> QueueItem:
        fields = _COLUMNS.split(", ")
        data = dict(zip(fields, row, strict=True))
        data["enqueued_at"] = _as_datetime(data["enqueued_at"])
        data["claimed_at"] = _as_datetime(data["claimed_at"])
        return QueueItem.model_validate(data)

    # ---------------------------------------------------------------- writing

    def enqueue(
        self,
        *,
        kind: WorkKind,
        repo_path: str | None = None,
        repo_url: str | None = None,
        thread_id: str | None = None,
        interrupt_id: str | None = None,
        verdict: str | None = None,
        reviewer: str | None = None,
        note: str = "",
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> QueueItem:
        if kind == "scan" and not repo_path:
            raise ValueError("a scan item needs a repo_path")
        if kind == "resume":
            if not (thread_id and interrupt_id):
                raise ValueError("a resume item needs thread_id and interrupt_id")
            if not verdict:
                raise ValueError("a resume item needs a verdict")
            # A double-click in the web queue must not resume the same branch twice.
            with self._cursor() as cur:
                cur.execute(
                    self._sql(
                        "SELECT id FROM work_queue WHERE thread_id = ? AND interrupt_id = ? "
                        "AND status IN ('pending','running')"
                    ),
                    (thread_id, interrupt_id),
                )
                if cur.fetchone():
                    raise ValueError(f"a verdict for {thread_id}/{interrupt_id} is already queued")

        now = datetime.now(UTC).isoformat()
        with self._cursor() as cur:
            cur.execute(
                self._sql(
                    "INSERT INTO work_queue (kind, status, repo_path, repo_url, thread_id, "
                    "interrupt_id, verdict, reviewer, note, attempts, max_attempts, enqueued_at) "
                    "VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)"
                ),
                (
                    kind,
                    repo_path,
                    repo_url,
                    thread_id,
                    interrupt_id,
                    verdict,
                    reviewer,
                    note,
                    max_attempts,
                    now,
                ),
            )
            new_id = self._last_id(cur)
        return self.get(new_id)  # type: ignore[return-value]

    def _last_id(self, cur: Any) -> int:
        if self._placeholder == "?":
            return int(cur.lastrowid)
        cur.execute("SELECT lastval()")
        return int(cur.fetchone()[0])

    def claim(self, worker: str, stale_seconds: int = DEFAULT_STALE_SECONDS) -> QueueItem | None:
        """Take the oldest pending item, atomically. Returns None when there is nothing to do."""
        self.reclaim_stale(older_than_seconds=stale_seconds)
        now = datetime.now(UTC).isoformat()
        with self._cursor() as cur:
            # One statement moves the row out of `pending`, so a concurrent worker sees nothing.
            cur.execute(
                self._sql(
                    "UPDATE work_queue SET status = 'running', claimed_by = ?, claimed_at = ?, "
                    "attempts = attempts + 1 WHERE id = ("
                    "  SELECT id FROM work_queue WHERE status = 'pending' "
                    "  ORDER BY id LIMIT 1) AND status = 'pending'"
                ),
                (worker, now),
            )
            if not cur.rowcount:
                return None
            cur.execute(
                self._sql(
                    f"SELECT {_COLUMNS} FROM work_queue WHERE claimed_by = ? AND "
                    "status = 'running' ORDER BY claimed_at DESC, id DESC LIMIT 1"
                ),
                (worker,),
            )
            row = cur.fetchone()
        return self._row(row) if row else None

    def complete(self, item_id: int, note: str = "") -> None:
        self._finish(item_id, "done", note)

    def fail(self, item_id: int, note: str = "") -> None:
        self._finish(item_id, "failed", note)

    def _finish(self, item_id: int, status: WorkStatus, note: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                self._sql("UPDATE work_queue SET status = ?, note = ? WHERE id = ?"),
                (status, note, item_id),
            )

    def reclaim_stale(self, older_than_seconds: int = DEFAULT_STALE_SECONDS) -> list[int]:
        """Return items whose worker died. Ones that have used up their attempts are failed."""
        cutoff = (datetime.now(UTC) - timedelta(seconds=older_than_seconds)).isoformat()
        with self._cursor() as cur:
            cur.execute(
                self._sql(
                    f"SELECT {_COLUMNS} FROM work_queue WHERE status = 'running' "
                    "AND claimed_at IS NOT NULL AND claimed_at < ?"
                ),
                (cutoff,),
            )
            stale = [self._row(row) for row in cur.fetchall()]

        reclaimed: list[int] = []
        for item in stale:
            if item.attempts >= item.max_attempts:
                self._finish(
                    item.id,
                    "failed",
                    f"gave up after {item.attempts} attempts; the worker did not finish it",
                )
                continue
            with self._cursor() as cur:
                cur.execute(
                    self._sql(
                        "UPDATE work_queue SET status = 'pending', claimed_by = NULL, "
                        "claimed_at = NULL WHERE id = ?"
                    ),
                    (item.id,),
                )
            reclaimed.append(item.id)
        return reclaimed

    # ---------------------------------------------------------------- reading

    def get(self, item_id: int) -> QueueItem | None:
        with self._cursor() as cur:
            cur.execute(self._sql(f"SELECT {_COLUMNS} FROM work_queue WHERE id = ?"), (item_id,))
            row = cur.fetchone()
        return self._row(row) if row else None

    def pending(self, limit: int = 100) -> list[QueueItem]:
        with self._cursor() as cur:
            cur.execute(
                self._sql(
                    f"SELECT {_COLUMNS} FROM work_queue WHERE status = 'pending' "
                    "ORDER BY id LIMIT ?"
                ),
                (limit,),
            )
            return [self._row(row) for row in cur.fetchall()]

    def force_claimed_at(self, item_id: int, when: datetime) -> None:
        """Test seam: pretend a worker took this item a while ago."""
        with self._cursor() as cur:
            cur.execute(
                self._sql("UPDATE work_queue SET claimed_at = ? WHERE id = ?"),
                (when.isoformat(), item_id),
            )


@contextmanager
def open_work_queue(url: str | None = None) -> Iterator[WorkQueue]:
    url = url or checkpoint_url()
    if url == MEMORY_URL or url.startswith(SQLITE_PREFIX):
        with sqlite_connection(url) as connection:
            yield WorkQueue(connection, "?")
        return
    if url.startswith(POSTGRES_PREFIXES):
        try:
            import psycopg
        except ImportError as e:  # pragma: no cover - depends on the installed extras
            raise UnsupportedDatabase(
                "DATABASE_URL points at Postgres; install the extra: pip install -e '.[postgres]'"
            ) from e

        with psycopg.connect(url) as connection:
            yield WorkQueue(connection, "%s")
        return
    raise UnsupportedDatabase(f"unsupported database url: {url!r}")
