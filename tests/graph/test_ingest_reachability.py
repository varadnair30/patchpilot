"""End-to-end graph run against the fixture repo in recorded mode, LLM off.

These expectations are the seed of the golden set: if any of them changes, a decision upstream of
the human gate has moved, and that must be a deliberate, reviewed change.

Since step 5 the scan no longer runs straight through: three advisories park at `human_gate`. The
helpers below approve them so the run reaches `collect`. A verdict is recorded in
`AdvisoryState.human` and never in `decision` (ADR-0002), so every expectation here is unchanged
by the gate — which is exactly what these tests are for.
"""

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from patchpilot.graph.build import build_graph
from patchpilot.graph.nodes.human_gate import ResumeCommand
from patchpilot.graph.queue import pending_gates, resume_gate
from patchpilot.graph.state import Budget, RepoRef
from patchpilot.llm.justify import Justification

# advisory_id: (imported, symbol_called, is_runtime_dep, min_fixed_version,
#               decision-or-None, bump_kind, triggers)
EXPECTED = {
    "GHSA-75c5-xw7c-p5pm": (True, True, True, "2.10.1", None, "patch", ["sensitive_tier:auth"]),
    "GHSA-9wx4-h78v-vm56": (True, True, True, "2.32.0", None, "minor", []),
    "GHSA-9hjg-9r4m-mvj7": (True, True, True, "2.32.4", None, "minor", []),
    "GHSA-34jh-p97f-mpxf": (True, False, True, "2.2.2", "not_applicable", "patch", []),
    "GHSA-h75v-3vvj-5mfj": (True, False, True, "3.1.4", "not_applicable", "patch", []),
    "GHSA-44wm-f244-xhp3": (True, False, True, "10.3.0", "not_applicable", "minor", []),
    "GHSA-2jv5-9r88-3w3p": (False, True, True, "0.0.7", None, "patch", []),
    "GHSA-59g5-xgcq-4qw3": (False, True, True, "0.0.18", None, "patch", []),
    "GHSA-f96h-pmfr-66vw": (
        False,
        True,
        True,
        "0.40.0",
        None,
        "major",
        ["sensitive_tier:web-framework", "major_bump"],
    ),
    "GHSA-6vqw-3v5j-54x4": (True, False, True, "42.0.4", None, "patch", ["sensitive_tier:crypto"]),
    "GHSA-fj7x-q9j7-g6q6": (False, False, False, "24.3.0", "accept_risk", "major", []),
}

# The advisories the policy raised gate triggers for; they park at human_gate until approved.
GATED = {aid for aid, expected in EXPECTED.items() if expected[6]}

EXPECTED_SUMMARY = {
    "pending:needs_human": 3,
    "pending:auto_fix_candidate": 4,
    "not_applicable": 3,
    "accept_risk": 1,
}


def _approve_pending(graph, thread):
    """Clear the human gates so the scan reaches `collect`. One resume per parked branch."""
    while gates := pending_gates(graph, thread):
        resume_gate(
            graph,
            thread,
            gates[0].interrupt_id,
            ResumeCommand(verdict="approve", reviewer="golden-test"),
        )


def _run(demo_app, justifier=None, thread="t1"):
    graph = build_graph(InMemorySaver(), justifier=justifier)
    config = {"configurable": {"thread_id": thread}}
    graph.invoke({"scan_id": thread, "repo": RepoRef(path=str(demo_app))}, config=config)
    _approve_pending(graph, thread)
    return graph.get_state(config).values


def test_scan_demo_app_matches_golden_expectations(demo_app):
    result = _run(demo_app)
    advisories = {a.advisory_id: a for a in result["advisories"]}
    assert set(advisories) == set(EXPECTED), "advisory set drifted from fixtures"
    for aid, (imported, called, runtime, fix, decision, bump, triggers) in EXPECTED.items():
        a = advisories[aid]
        r = a.reachability
        assert r is not None, aid
        assert (r.imported, r.symbol_called, r.is_runtime_dep) == (imported, called, runtime), (
            aid,
            r,
        )
        assert a.min_fixed_version == fix, aid
        assert a.decision == decision, (aid, a.decision, a.policy_reasons)
        assert a.bump_kind == bump, aid
        assert a.risk is not None and a.risk.triggers == triggers, (aid, a.risk)
        assert a.justification and a.justification_evidence, aid
    assert result["summary"].total_advisories == 11
    assert result["summary"].counts == EXPECTED_SUMMARY


def test_every_advisory_has_scores_and_untrusted_text(demo_app):
    result = _run(demo_app)
    for a in result["advisories"]:
        assert a.cvss is not None and a.epss is not None, a.advisory_id
        assert a.untrusted_text.advisory_summary
        assert a.justification_notes == ["llm off: template justification"]
    assert result["data_freshness"].mode == "recorded"
    assert result["errors"] == []
    assert result["budget"].tokens_used == 0


def test_fake_justifier_runs_once_per_advisory_and_budget_is_summed(demo_app):
    seen = []

    def fake(adv, evidence, decision):
        seen.append((adv.advisory_id, decision))
        return (
            Justification(
                text=f"Fake justification for {adv.advisory_id} citing the advisory.",
                evidence_ids=["advisory"],
            ),
            Budget(tokens_used=100, usd_used=0.001),
        )

    result = _run(demo_app, justifier=fake, thread="t2")
    assert len(seen) == 11 and len({s[0] for s in seen}) == 11
    assert {d for _, d in seen} == {
        "not_applicable",
        "accept_risk",
        "needs_human (pending plan)",
        "auto_fix candidate (pending sandbox)",
    }
    assert result["budget"].tokens_used == 1100
    assert abs(result["budget"].usd_used - 0.011) < 1e-9
    assert result["budget"].tokens_cap == 200_000, "caps survive the reducer"


def test_fan_out_runs_one_subgraph_per_advisory(demo_app):
    """Each advisory is processed on its own Send() branch, so a human gate on one advisory never
    blocks the others: eight branches finish while three sit at their interrupt."""
    graph = build_graph(InMemorySaver(), justifier=None)
    config = {"configurable": {"thread_id": "t3"}}
    finished: list[str] = []

    def drain(payload):
        for event in graph.stream(payload, config=config, stream_mode="updates"):
            if "advisory" in event:
                finished.extend(a.advisory_id for a in event["advisory"]["advisories"])

    drain({"scan_id": "t3", "repo": RepoRef(path=str(demo_app))})
    assert set(finished) == set(EXPECTED) - GATED, "the gated branches are parked, not finished"

    while gates := pending_gates(graph, "t3"):
        drain(
            Command(
                resume={gates[0].interrupt_id: {"verdict": "approve", "reviewer": "golden-test"}}
            )
        )
    assert set(finished) == set(EXPECTED)


def test_repo_without_advisories_short_circuits(tmp_repo):
    repo = tmp_repo({"requirements.txt": "fastapi==0.100.0\n", "app.py": "x=1\n"})
    graph = build_graph(InMemorySaver(), justifier=None)
    result = graph.invoke(
        {"scan_id": "t4", "repo": RepoRef(path=str(repo))},
        config={"configurable": {"thread_id": "t4"}},
    )
    assert result["advisories"] == []
    assert result["summary"].total_advisories == 0


def test_checkpoint_persists_state(demo_app):
    saver = InMemorySaver()
    graph = build_graph(saver, justifier=None)
    cfg = {"configurable": {"thread_id": "t5"}}
    graph.invoke({"scan_id": "t5", "repo": RepoRef(path=str(demo_app))}, config=cfg)
    assert graph.get_state(cfg).next == ("advisory",) * 3, "three branches wait for a human"

    _approve_pending(graph, "t5")
    snapshot = graph.get_state(cfg)
    assert len(snapshot.values["advisories"]) == 11
    assert snapshot.next == ()
