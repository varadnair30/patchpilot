"""The approval queue API.

ADR-0001: a thin, stateless service with exactly three jobs — list what is waiting, show one
evidence bundle, record a verdict. It does not own the graph and it never resumes anything. A
verdict becomes a row in the work queue; the worker is what moves the graph.

That is a security boundary, not a layering preference. This service is the only part of PatchPilot
exposed to the internet, and anonymous visitors can approve or reject on the public demo. So it is
built to be uninteresting to attack:

* **It cannot start a scan.** Not "returns 403" — there is no such route, and no code path here
  constructs a graph, a sandbox or a container.
* **It cannot open a pull request.** It holds no GitHub write token.
* **It holds no model key.** Nothing here imports the LLM client, so a key in the environment is
  simply never read.
* **It cannot spend money.** Following from the three above.

The strongest version of each of those is enforced by absence rather than by a check, which is why
the tests assert on the route table as well as on responses.

`repository_dispatch` is a latency optimisation and nothing more. The queue is the source of truth;
if no dispatch token is configured, the worker picks the verdict up on its next poll. That keeps
the default deployment credential-free.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from patchpilot.graph.nodes.human_gate import GatePayload
from patchpilot.graph.queue import gates_from_tasks, list_threads
from patchpilot.storage.db import open_checkpointer
from patchpilot.storage.queue import open_work_queue

DEFAULT_RATE_LIMIT = 30
UNLIMITED_PATHS = frozenset({"/health", "/", "/docs", "/openapi.json"})


class VerdictRequest(BaseModel):
    """What an anonymous reviewer may say. `modify` is not offered here: it needs a target version
    and a sandbox re-run, which only the worker can do."""

    verdict: Literal["approve", "reject"]
    reviewer: str = Field(min_length=1, max_length=64)
    note: str = Field(default="", max_length=2000)


class QueueRow(BaseModel):
    """One line in the queue listing. Enough to decide what to open, not the whole bundle."""

    thread_id: str
    interrupt_id: str
    advisory_id: str
    package: str
    installed_version: str
    target_version: str | None = None
    bump_kind: str | None = None
    risk_score: float
    risk_tier: str
    triggers: list[str] = Field(default_factory=list)
    sandbox_supported: bool | None = None


class RateLimiter:
    """A fixed-window counter per client address.

    Deliberately in-process: the demo runs one container, and a shared limiter would mean another
    dependency for the one service that is supposed to have almost none. Behind more than one
    replica this becomes per-replica, which is documented rather than pretended away.
    """

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        window = self._hits[client]
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= self.per_minute:
            return False
        window.append(now)
        return True


def _read_gates() -> list[tuple[str, str, GatePayload]]:
    """Every branch parked at a human gate, read straight out of the checkpointer."""
    found: list[tuple[str, str, GatePayload]] = []
    with open_checkpointer() as saver:
        from patchpilot.graph.build import build_graph

        graph = build_graph(saver, justifier=None, summariser=None)
        for thread_id in list_threads(saver):
            snapshot = graph.get_state({"configurable": {"thread_id": thread_id}})
            for gate in gates_from_tasks(thread_id, snapshot.tasks):
                found.append((gate.thread_id, gate.interrupt_id, gate.payload))
    return found


def _dispatch(thread_id: str) -> bool:
    """Nudge the demo worker. Optional: without a token the worker polls and still gets there."""
    token = os.environ.get("PATCHPILOT_DISPATCH_TOKEN")
    repo = os.environ.get("PATCHPILOT_DISPATCH_REPO")
    if not (token and repo):
        return False
    try:
        response = httpx.post(
            f"https://api.github.com/repos/{repo}/dispatches",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"event_type": "patchpilot-resume", "client_payload": {"thread_id": thread_id}},
            timeout=10.0,
        )
        return response.status_code in (200, 204)
    except httpx.HTTPError:
        # The verdict is already durable in the queue. A failed nudge costs latency, not work.
        return False


def create_app(rate_limit_per_minute: int = DEFAULT_RATE_LIMIT) -> FastAPI:
    app = FastAPI(
        title="PatchPilot approval queue",
        description=(
            "Read what PatchPilot paused, and record a verdict. This service cannot start a scan "
            "or open a pull request; it writes to a queue that the worker consumes."
        ),
        version="1.0.0",
    )
    limiter = RateLimiter(rate_limit_per_minute)

    # The React queue is served from GitHub Pages, a different origin. Reads and verdicts only.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("PATCHPILOT_CORS_ORIGINS", "*").split(","),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def rate_limit(request: Request, call_next):
        if request.url.path not in UNLIMITED_PATHS:
            client = request.client.host if request.client else "unknown"
            if not limiter.allow(client):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "too many requests; this is a public demo"},
                )
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Also the keep-alive target on free hosting, so it is never rate limited."""
        return {"status": "ok", "service": "patchpilot-approval-queue"}

    @app.get("/api/queue")
    def list_queue() -> dict[str, Any]:
        rows = [
            QueueRow(
                thread_id=thread_id,
                interrupt_id=interrupt_id,
                advisory_id=payload.advisory_id,
                package=payload.package,
                installed_version=payload.installed_version,
                target_version=payload.plan.target_version if payload.plan else None,
                bump_kind=payload.plan.bump_kind if payload.plan else payload.bump_kind,
                risk_score=payload.risk_score,
                risk_tier=payload.risk_tier,
                triggers=payload.triggers,
                sandbox_supported=payload.sandbox.supported if payload.sandbox else None,
            )
            for thread_id, interrupt_id, payload in _read_gates()
        ]
        rows.sort(key=lambda r: (r.thread_id, r.advisory_id))
        return {"count": len(rows), "items": [r.model_dump() for r in rows]}

    @app.get("/api/queue/{interrupt_id}")
    def show_item(interrupt_id: str) -> dict[str, Any]:
        for _thread_id, found_id, payload in _read_gates():
            if found_id == interrupt_id:
                # The bundle carries advisory and changelog text copied from the internet. It
                # goes out as JSON so the client renders it as text; the API never marks it safe.
                return payload.model_dump(mode="json")
        raise HTTPException(status_code=404, detail="no pending approval with that id")

    @app.post("/api/queue/{interrupt_id}/verdict")
    def record_verdict(interrupt_id: str, body: VerdictRequest) -> dict[str, Any]:
        thread_id = next(
            (t for t, found, _ in _read_gates() if found == interrupt_id),
            None,
        )
        if thread_id is None:
            raise HTTPException(status_code=404, detail="no pending approval with that id")

        with open_work_queue() as queue:
            try:
                item = queue.enqueue(
                    kind="resume",
                    thread_id=thread_id,
                    interrupt_id=interrupt_id,
                    verdict=body.verdict,
                    reviewer=body.reviewer,
                    note=body.note,
                )
            except ValueError as e:
                # Already queued: a double-click, not an error worth a 500.
                raise HTTPException(status_code=409, detail=str(e)) from e

        return {
            "queued": True,
            "item_id": item.id,
            "verdict": body.verdict,
            "dispatched": _dispatch(thread_id),
            "detail": "recorded; the worker applies it",
        }

    return app


# `uvicorn patchpilot.api.app:app`
app = create_app()


def main() -> None:  # pragma: no cover - thin entry point
    import uvicorn

    uvicorn.run(
        "patchpilot.api.app:app",
        host=os.environ.get("HOST", "0.0.0.0"),  # noqa: S104 - a container binds all interfaces
        port=int(os.environ.get("PORT", "8000")),
    )
