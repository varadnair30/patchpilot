"""The approval API.

ADR-0001 makes this a thin, stateless service that can do exactly three things: list what is
waiting, show one evidence bundle, and record a verdict. It does not own the graph. It cannot
start a scan or open a pull request — not because it checks a permission, but because no such
endpoint exists and it holds no credential that would allow it.

Most of these tests are about what the API *cannot* do. That is the point of it.
"""

import pytest
from fastapi.testclient import TestClient

from patchpilot.api.app import create_app
from patchpilot.storage.queue import open_work_queue


@pytest.fixture
def api(tmp_path, monkeypatch, demo_app):
    """A real scan parked at its gates, then the API pointed at the same database."""
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(db))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    from patchpilot.graph.build import build_graph
    from patchpilot.graph.state import RepoRef
    from patchpilot.storage.db import open_checkpointer

    with open_checkpointer() as saver:
        graph = build_graph(saver, justifier=None, summariser=None)
        graph.invoke(
            {"scan_id": "demo", "repo": RepoRef(path=str(demo_app))},
            config={"configurable": {"thread_id": "demo"}},
        )

    with TestClient(create_app(rate_limit_per_minute=1000)) as client:
        yield client
    get_settings.cache_clear()


# ==================================================================== what it can do


def test_health_needs_nothing(api):
    assert api.get("/health").status_code == 200


def test_the_queue_lists_what_is_waiting_for_a_human(api):
    body = api.get("/api/queue").json()
    assert body["count"] == 5
    ids = {item["advisory_id"] for item in body["items"]}
    assert "GHSA-75c5-xw7c-p5pm" in ids
    row = next(i for i in body["items"] if i["advisory_id"] == "GHSA-75c5-xw7c-p5pm")
    assert row["package"] == "pyjwt"
    assert row["triggers"] == ["sensitive_tier:auth"]
    assert row["thread_id"] == "demo"


def test_one_item_returns_the_evidence_bundle(api):
    listing = api.get("/api/queue").json()["items"]
    target = next(i for i in listing if i["advisory_id"] == "GHSA-f96h-pmfr-66vw")

    bundle = api.get(f"/api/queue/{target['interrupt_id']}").json()

    assert bundle["advisory_id"] == "GHSA-f96h-pmfr-66vw"
    assert bundle["plan"]["target_version"] == "0.40.0"
    assert bundle["sandbox"]["supported"] is False
    assert bundle["evidence"], "the reviewer sees what the justifier saw"
    assert "dependency_conflict" in bundle["triggers"]


def test_an_unknown_item_is_a_clean_404(api):
    r = api.get("/api/queue/does-not-exist")
    assert r.status_code == 404
    assert "no pending approval" in r.json()["detail"].lower()


def test_a_verdict_is_queued_for_the_worker_not_applied_here(api, tmp_path):
    """The API records the decision. Only the worker can move the graph."""
    target = api.get("/api/queue").json()["items"][0]

    r = api.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "approve", "reviewer": "alice", "note": "checked"},
    )
    assert r.status_code == 200
    assert r.json()["queued"] is True

    with open_work_queue() as queue:
        pending = queue.pending()
    assert len(pending) == 1
    item = pending[0]
    assert item.kind == "resume"
    assert (item.thread_id, item.interrupt_id) == (target["thread_id"], target["interrupt_id"])
    assert (item.verdict, item.reviewer) == ("approve", "alice")

    # And the gate is still open, because nothing has resumed it yet.
    assert api.get("/api/queue").json()["count"] == 5


def test_a_rejection_is_recorded_the_same_way(api):
    target = api.get("/api/queue").json()["items"][0]
    r = api.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "reject", "reviewer": "bob", "note": "too risky"},
    )
    assert r.status_code == 200
    with open_work_queue() as queue:
        assert queue.pending()[0].verdict == "reject"


# ==================================================================== what it cannot do


def test_there_is_no_endpoint_that_starts_a_scan(api):
    """Not "returns 403" — the route does not exist. The API cannot spend money or run Docker."""
    routes = {r.path for r in api.app.routes}
    assert not any("scan" in path for path in routes), routes
    for attempt in ("/api/scan", "/api/queue/scan", "/scan"):
        assert api.post(attempt, json={"repo_path": "/etc"}).status_code in (404, 405)


def test_the_api_cannot_enqueue_work_of_any_kind_but_a_verdict(api):
    target = api.get("/api/queue").json()["items"][0]
    api.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "approve", "reviewer": "alice"},
    )
    with open_work_queue() as queue:
        assert {item.kind for item in queue.pending()} == {"resume"}


@pytest.mark.parametrize("verdict", ["modify", "merge", "delete", "", "APPROVE ", "approve;drop"])
def test_only_approve_and_reject_are_accepted(api, verdict):
    target = api.get("/api/queue").json()["items"][0]
    r = api.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": verdict, "reviewer": "alice"},
    )
    assert r.status_code == 422


def test_the_same_verdict_cannot_be_submitted_twice(api):
    """A double-click must not queue two resumes for one branch."""
    target = api.get("/api/queue").json()["items"][0]
    payload = {"verdict": "approve", "reviewer": "alice"}
    first = api.post(f"/api/queue/{target['interrupt_id']}/verdict", json=payload)
    second = api.post(f"/api/queue/{target['interrupt_id']}/verdict", json=payload)

    assert first.status_code == 200
    assert second.status_code == 409
    with open_work_queue() as queue:
        assert len(queue.pending()) == 1


def test_a_reviewer_name_is_bounded(api):
    target = api.get("/api/queue").json()["items"][0]
    r = api.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "approve", "reviewer": "x" * 200},
    )
    assert r.status_code == 422


def test_a_note_is_bounded(api):
    target = api.get("/api/queue").json()["items"][0]
    r = api.post(
        f"/api/queue/{target['interrupt_id']}/verdict",
        json={"verdict": "approve", "reviewer": "alice", "note": "x" * 5000},
    )
    assert r.status_code == 422


def test_untrusted_advisory_text_is_returned_as_data(api):
    """The bundle carries text copied from the internet. It must arrive as JSON for the client to
    render as text — never as markup the API has blessed."""
    listing = api.get("/api/queue").json()["items"]
    bundle = api.get(f"/api/queue/{listing[0]['interrupt_id']}").json()
    assert isinstance(bundle["untrusted_text"], dict)
    assert (
        api.get(f"/api/queue/{listing[0]['interrupt_id']}")
        .headers["content-type"]
        .startswith("application/json")
    )


# ==================================================================== rate limiting


def test_an_anonymous_flood_is_refused(tmp_path, monkeypatch, demo_app):
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(tmp_path / "s.sqlite"))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    with TestClient(create_app(rate_limit_per_minute=3)) as client:
        codes = [client.get("/api/queue").status_code for _ in range(6)]
    assert codes.count(429) >= 2, codes
    assert codes[0] == 200


def test_health_is_never_rate_limited(tmp_path, monkeypatch):
    """The keep-alive ping must not be what exhausts the budget."""
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(tmp_path / "s.sqlite"))
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    with TestClient(create_app(rate_limit_per_minute=2)) as client:
        assert all(client.get("/health").status_code == 200 for _ in range(10))


# ==================================================================== credentials


def test_the_api_never_reads_a_model_key(monkeypatch, tmp_path):
    """ADR-0001: the API holds no LLM key. If it ever tried, this would fail loudly."""
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(tmp_path / "s.sqlite"))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-never-be-read")
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    import patchpilot.llm.client as client_module

    def explode(*args, **kwargs):
        raise AssertionError("the approval API must never construct a model")

    monkeypatch.setattr(client_module, "get_chat_model", explode)
    monkeypatch.setattr(client_module, "get_embeddings_model", explode)

    with TestClient(create_app(rate_limit_per_minute=100)) as client:
        assert client.get("/api/queue").status_code == 200
        assert client.get("/health").status_code == 200
