"""execute_pr inside the real graph, against the fixture repo in recorded mode.

The point of these is the *route*: which advisories reach a pull request, which are stopped, and
what a human's verdict changes. The tool-level guardrails live in tests/unit/test_github_pr.py.
"""

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from test_ingest_reachability import EXPECTED, GATED

from patchpilot.graph.build import build_graph
from patchpilot.graph.nodes.human_gate import ResumeCommand
from patchpilot.graph.queue import pending_gates, resume_gate
from patchpilot.graph.state import RepoRef
from patchpilot.recorded.store import RecordedStore

SLUG = "varadnair30/patchpilot-demo-app"
AUTO_FIX = {aid for aid, expected in EXPECTED.items() if expected[4] == "auto_fix"}
AUTH_ADVISORY = "GHSA-75c5-xw7c-p5pm"


@pytest.fixture
def github_recorded(monkeypatch, tmp_path, demo_app):
    """Copy the real fixtures, then add recorded GitHub responses for every branch we might open."""
    import shutil

    from patchpilot.config import get_settings

    source = get_settings().fixtures_dir
    fixtures = tmp_path / "fixtures"
    shutil.copytree(source, fixtures)
    monkeypatch.setenv("PATCHPILOT_FIXTURES_DIR", str(fixtures))
    get_settings.cache_clear()

    store = RecordedStore()
    for number, advisory_id in enumerate(sorted(EXPECTED), start=1):
        branch = f"patchpilot/{advisory_id}"
        store.write("github/branch", f"{SLUG}/{branch}", {"sha": "abc123", "created": True})
        store.write(
            "github/commit", f"{SLUG}/{branch}/requirements.txt", {"commit_sha": f"sha{number}"}
        )
        store.write(
            "github/pr",
            f"{SLUG}/{branch}",
            {"number": number, "url": f"https://github.com/{SLUG}/pull/{number}"},
        )
    yield
    get_settings.cache_clear()


def scan(demo_app, thread, url=None):
    graph = build_graph(InMemorySaver(), justifier=None, summariser=None)
    result = graph.invoke(
        {
            "scan_id": thread,
            "repo": RepoRef(path=str(demo_app), url=url, default_branch="main"),
        },
        config={"configurable": {"thread_id": thread}},
    )
    return graph, {a.advisory_id: a for a in result["advisories"]}


# ==================================================================== who reaches a pull request


def test_auto_fixes_open_pull_requests_without_asking_anyone(github_recorded, demo_app):
    _, advisories = scan(demo_app, "pr-1", url=f"https://github.com/{SLUG}")
    assert AUTO_FIX, "the fixture must keep exercising the auto_fix path"
    for advisory_id in AUTO_FIX:
        adv = advisories[advisory_id]
        assert adv.decision == "auto_fix"
        assert adv.pr is not None, advisory_id
        assert adv.pr.branch == f"patchpilot/{advisory_id}"
        assert adv.pr.url.startswith(f"https://github.com/{SLUG}/pull/")


def test_terminal_advisories_never_open_a_pull_request(github_recorded, demo_app):
    _, advisories = scan(demo_app, "pr-2", url=f"https://github.com/{SLUG}")
    for advisory_id, expected in EXPECTED.items():
        if expected[4] in {"not_applicable", "accept_risk"}:
            assert advisories[advisory_id].pr is None, advisory_id


def test_a_gated_advisory_opens_nothing_until_a_human_says_so(github_recorded, demo_app):
    graph, advisories = scan(demo_app, "pr-3", url=f"https://github.com/{SLUG}")

    assert {g.payload.advisory_id for g in pending_gates(graph, "pr-3")} == GATED
    for advisory_id in GATED:
        # A parked branch has published nothing of its own; what the parent holds is still the
        # untouched copy ingest wrote, with no decision, no plan and certainly no pull request.
        parked = advisories[advisory_id]
        assert parked.decision is None, advisory_id
        assert parked.plan is None and parked.pr is None, advisory_id


def test_approving_at_the_gate_opens_the_pull_request(github_recorded, demo_app):
    graph, _ = scan(demo_app, "pr-4", url=f"https://github.com/{SLUG}")
    gate = next(g for g in pending_gates(graph, "pr-4") if g.payload.advisory_id == AUTH_ADVISORY)

    resume_gate(
        graph,
        "pr-4",
        gate.interrupt_id,
        ResumeCommand(verdict="approve", reviewer="alice", note="evidence checked"),
    )

    values = graph.get_state({"configurable": {"thread_id": "pr-4"}}).values
    adv = next(a for a in values["advisories"] if a.advisory_id == AUTH_ADVISORY)
    assert adv.pr is not None
    assert adv.pr.branch == f"patchpilot/{AUTH_ADVISORY}"
    assert adv.human.reviewer == "alice"


def test_rejecting_at_the_gate_opens_nothing(github_recorded, demo_app):
    graph, _ = scan(demo_app, "pr-5", url=f"https://github.com/{SLUG}")
    gate = next(g for g in pending_gates(graph, "pr-5") if g.payload.advisory_id == AUTH_ADVISORY)

    resume_gate(
        graph,
        "pr-5",
        gate.interrupt_id,
        ResumeCommand(verdict="reject", reviewer="bob", note="wait for the next release"),
    )

    values = graph.get_state({"configurable": {"thread_id": "pr-5"}}).values
    adv = next(a for a in values["advisories"] if a.advisory_id == AUTH_ADVISORY)
    assert adv.pr is None
    assert adv.human.verdict == "reject"
    assert adv.decision == "needs_human", "the policy's decision class is untouched"


# ==================================================================== no target configured


def test_without_a_github_url_the_scan_still_completes_and_says_why(github_recorded, demo_app):
    """Today's real state: the demo target has no GitHub home until step 9."""
    _, advisories = scan(demo_app, "pr-6", url=None)
    for advisory_id in AUTO_FIX:
        adv = advisories[advisory_id]
        assert adv.decision == "auto_fix", "the decision is unaffected"
        assert adv.pr is None
        assert "no GitHub URL" in adv.pr_note
        assert adv.halt_reason is None, "a missing target is configuration, not a failure"


# ==================================================================== the PR body, end to end


def test_the_pull_request_body_is_built_from_real_scan_evidence(
    github_recorded, demo_app, monkeypatch
):
    import patchpilot.graph.nodes.execute_pr as node

    bodies = {}
    real = node.open_pull_request

    def spy(inp):
        bodies[inp.head] = inp.body
        return real(inp)

    monkeypatch.setattr(node, "open_pull_request", spy)
    scan(demo_app, "pr-7", url=f"https://github.com/{SLUG}")

    advisory_id = sorted(AUTO_FIX)[0]
    body = bodies[f"patchpilot/{advisory_id}"]
    assert "python-multipart" in body
    assert "No new test failures" in body, "the real recorded Docker run"
    assert "Data freshness" in body
    assert "cannot merge" in body.lower()

    from patchpilot.guardrails.secrets import scan_text

    assert scan_text(body) == [], "nothing credential-shaped reaches GitHub"
