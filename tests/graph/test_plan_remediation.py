"""plan_remediation end to end against the fixture repo, in recorded mode.

The PyPI metadata, the release notes and the sandbox results replayed here were all recorded from
the real thing (`patchpilot record`); the sandbox fixtures came out of actual Docker runs of the
demo app's test suite. So these assertions are about real package behaviour, not invented data.
"""

from langgraph.checkpoint.memory import InMemorySaver
from test_ingest_reachability import EXPECTED, GATED

from patchpilot.graph.build import build_graph
from patchpilot.graph.nodes.human_gate import GatePayload
from patchpilot.graph.queue import pending_gates
from patchpilot.graph.state import Budget, RepoRef
from patchpilot.llm.changelog import BreakingChanges

MULTIPART_PATCH = "GHSA-2jv5-9r88-3w3p"  # python-multipart 0.0.6 -> 0.0.7, the clean auto_fix
REQUESTS_YANKED = "GHSA-9wx4-h78v-vm56"  # advisory says 2.32.0, but 2.32.0/2.32.1 were yanked
STARLETTE_MAJOR = "GHSA-f96h-pmfr-66vw"  # fastapi pins starlette<0.28.0, so the bump cannot install
URLLIB3_NA = "GHSA-34jh-p97f-mpxf"  # not_applicable: terminal before any planning happens


def run(demo_app, thread, summariser=None):
    """Scan and return every advisory, including the ones parked at their gate."""
    graph = build_graph(InMemorySaver(), justifier=None, summariser=summariser)
    result = graph.invoke(
        {"scan_id": thread, "repo": RepoRef(path=str(demo_app))},
        config={"configurable": {"thread_id": thread}},
    )
    by_id = {a.advisory_id: a for a in result["advisories"]}
    gates = {g.payload.advisory_id: g for g in pending_gates(graph, thread)}
    return by_id, gates


# ------------------------------------------------------------------ the resolver in the graph


def test_the_target_version_is_the_minimal_installable_one_not_the_advisory_s(demo_app):
    """requests 2.32.0 and 2.32.1 are yanked on PyPI ("conflicts with CVE-2024-35195 mitigation"),
    so the smallest version that clears the advisory *and* installs is 2.32.2."""
    _, gates = run(demo_app, "plan-1")
    plan = gates[REQUESTS_YANKED].payload.plan
    assert EXPECTED[REQUESTS_YANKED][3] == "2.32.0", "the advisory's own fixed version"
    assert plan.target_version == "2.32.2", "but the resolver skips the yanked releases"
    assert plan.bump_kind == "minor"


def test_a_pin_that_forbids_the_target_is_reported_as_a_conflict(demo_app):
    _, gates = run(demo_app, "plan-2")
    plan = gates[STARLETTE_MAJOR].payload.plan
    assert plan.target_version == "0.40.0" and plan.bump_kind == "major"
    assert plan.dependency_conflicts == ["fastapi 0.100.0 requires starlette<0.28.0,>=0.27.0"]


# ------------------------------------------------------------------ the sandbox in the graph


def test_a_clean_patch_bump_is_auto_fixed(demo_app):
    by_id, gates = run(demo_app, "plan-3")
    adv = by_id[MULTIPART_PATCH]
    assert adv.decision == "auto_fix"
    assert MULTIPART_PATCH not in gates, "an auto_fix never asks a human"
    assert adv.sandbox.supported and adv.sandbox.newly_failing == []
    assert adv.gate_triggers == []
    assert adv.plan.target_version == "0.0.7"


def test_a_bump_that_cannot_be_installed_never_reads_as_clean(demo_app):
    """The sandbox distinguishes "the suite passed" from "the suite never ran"."""
    _, gates = run(demo_app, "plan-4")
    payload = gates[STARLETTE_MAJOR].payload
    assert payload.sandbox.supported is False
    assert payload.sandbox.newly_failing == []
    assert "cannot be installed" in payload.sandbox.reason
    assert "sandbox_unsupported" in payload.triggers


def test_terminal_advisories_are_never_planned_or_sandboxed(demo_app):
    """not_applicable is settled before a remediation exists; running Docker for it is waste."""
    by_id, _ = run(demo_app, "plan-5")
    adv = by_id[URLLIB3_NA]
    assert adv.decision == "not_applicable"
    assert adv.plan is None and adv.sandbox is None


# ------------------------------------------------------------------ the changelog in the graph


def test_the_plan_carries_cited_breaking_changes(demo_app):
    """Every citation must resolve to a chunk that was actually retrieved (ADR-0002)."""
    _, gates = run(demo_app, "plan-6")
    plan = gates["GHSA-9hjg-9r4m-mvj7"].payload.plan
    assert plan.changelog_hits, "release notes were retrieved for the range"
    assert plan.breaking_changes
    retrieved = {c.chunk_id for c in plan.changelog_hits}
    assert set(plan.breaking_change_citations) <= retrieved
    assert all(c.version.startswith("2.32") for c in plan.changelog_hits)


def test_an_invented_citation_is_rejected_and_the_template_used_instead(demo_app):
    def liar(package, from_version, to_version, chunks):
        return BreakingChanges(items=["everything broke"], chunk_ids=["9.9.9#0"]), Budget()

    _, gates = run(demo_app, "plan-7", summariser=liar)
    plan = gates["GHSA-9hjg-9r4m-mvj7"].payload.plan
    assert "everything broke" not in plan.breaking_changes
    assert any("cited unknown chunk ids" in n for n in plan.notes)


def test_the_summariser_is_charged_to_the_budget(demo_app):
    def summariser(package, from_version, to_version, chunks):
        return (
            BreakingChanges(items=["a real one"], chunk_ids=[chunks[0].chunk_id]),
            Budget(tokens_used=50, usd_used=0.0002),
        )

    graph = build_graph(InMemorySaver(), justifier=None, summariser=summariser)
    graph.invoke(
        {"scan_id": "plan-8", "repo": RepoRef(path=str(demo_app))},
        config={"configurable": {"thread_id": "plan-8"}},
    )
    budget = graph.get_state({"configurable": {"thread_id": "plan-8"}}).values["budget"]
    # Only advisories that reach plan_remediation and retrieve chunks are charged.
    assert budget.tokens_used > 0 and budget.tokens_used % 50 == 0


# ------------------------------------------------------------------ what the reviewer sees


def test_the_gate_bundle_shows_the_version_and_the_test_result(demo_app):
    _, gates = run(demo_app, "plan-9")
    assert set(gates) == GATED
    for gate in gates.values():
        payload = gate.payload
        assert isinstance(payload, GatePayload)
        assert payload.plan is not None, "a reviewer approves a specific version"
        assert payload.plan.target_version
        assert payload.sandbox is not None, "and sees whether it was test-proven"
        assert payload.triggers, "and why they were asked at all"
