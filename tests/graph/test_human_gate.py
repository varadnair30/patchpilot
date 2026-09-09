"""Interrupt / resume behaviour of the human gate, end to end against the fixture repo.

The golden expectations live in test_ingest_reachability.py and are imported here on purpose: the
point of these tests is that adding a human in the loop moves *nothing* upstream of the gate.
"""

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from test_ingest_reachability import EXPECTED, EXPECTED_SUMMARY, GATED

from patchpilot.graph.build import build_graph
from patchpilot.graph.nodes.human_gate import GatePayload, ResumeCommand
from patchpilot.graph.queue import list_threads, pending_gates, resume_gate
from patchpilot.graph.state import Budget, RepoRef
from patchpilot.llm.justify import Justification
from patchpilot.storage.db import open_checkpointer

# GATED is imported from the golden file so it can never silently drift from it. Since step 6 it
# is every advisory the deterministic policy landed on `needs_human` — which now includes requests,
# gated by its minor bump, a trigger risk_policy never saw.
UNGATED = set(EXPECTED) - GATED


def start_scan(graph, demo_app, thread: str) -> dict:
    return graph.invoke(
        {"scan_id": thread, "repo": RepoRef(path=str(demo_app))},
        config={"configurable": {"thread_id": thread}},
    )


def advisories_of(graph, thread: str) -> dict:
    values = graph.get_state({"configurable": {"thread_id": thread}}).values
    return {a.advisory_id: a for a in values.get("advisories", [])}


def approve(graph, thread, gate, reviewer="alice", note=""):
    return resume_gate(
        graph,
        thread,
        gate.interrupt_id,
        ResumeCommand(verdict="approve", reviewer=reviewer, note=note),
    )


# ------------------------------------------------------------------ pausing


def test_every_needs_human_advisory_pauses_at_the_gate(demo_app):
    assert len(GATED) == 5, "the fixture must keep exercising the gate"
    graph = build_graph(InMemorySaver(), justifier=None)
    result = start_scan(graph, demo_app, "gate-1")

    interrupts = result["__interrupt__"]
    assert len(interrupts) == len(GATED)
    payloads = [GatePayload.model_validate(i.value) for i in interrupts]
    assert {p.advisory_id for p in payloads} == GATED
    for p in payloads:
        assert p.scan_id == "gate-1"
        assert p.decision == "needs_human"
        # `risk_triggers` is what risk_policy produced; `triggers` adds plan_remediation's, so
        # requests appears here with `minor_bump` and no risk trigger at all.
        assert p.risk_triggers == EXPECTED[p.advisory_id][6]
        assert set(p.triggers) >= set(p.risk_triggers) and p.triggers
        assert p.justification and p.justification_evidence
        assert p.evidence, "the reviewer gets the same evidence bundle the justifier saw"


def test_pending_gates_reads_the_queue_back_out_of_the_checkpointer(demo_app):
    graph = build_graph(InMemorySaver(), justifier=None)
    start_scan(graph, demo_app, "gate-2")

    gates = pending_gates(graph, "gate-2")
    assert {g.payload.advisory_id for g in gates} == GATED
    assert all(g.thread_id == "gate-2" for g in gates)
    assert len({g.interrupt_id for g in gates}) == len(GATED), "one interrupt id per branch"
    assert len({g.task_id for g in gates}) == len(GATED)


def test_ungated_advisories_finish_while_the_others_wait(demo_app):
    """A human decision on one advisory must never block the rest of the scan."""
    graph = build_graph(InMemorySaver(), justifier=None)
    result = start_scan(graph, demo_app, "gate-3")

    assert {g.payload.advisory_id for g in pending_gates(graph, "gate-3")} == GATED

    by_id = {a.advisory_id: a for a in result["advisories"]}
    for aid in UNGATED:
        assert by_id[aid].risk is not None and by_id[aid].justification, aid
    for aid in GATED:
        # A parked branch has published nothing back to the parent; the parent still holds the
        # advisory as `ingest` left it. That is what makes the pause safe to walk away from.
        assert by_id[aid].risk is None, aid
    assert all(a.human is None for a in result["advisories"]), "nobody has decided anything yet"
    assert result.get("summary") is None, "the scan is not finished while a gate is open"


# ------------------------------------------------------------------ resuming one branch


def test_resuming_one_branch_leaves_the_others_pending(demo_app):
    graph = build_graph(InMemorySaver(), justifier=None)
    start_scan(graph, demo_app, "gate-4")
    target = sorted(pending_gates(graph, "gate-4"), key=lambda g: g.payload.advisory_id)[0]

    approve(graph, "gate-4", target, reviewer="alice", note="patch bump, evidence checked")

    still_open = {g.payload.advisory_id for g in pending_gates(graph, "gate-4")}
    assert still_open == GATED - {target.payload.advisory_id}

    advisories = advisories_of(graph, "gate-4")
    decided = advisories[target.payload.advisory_id]
    assert decided.human.verdict == "approve"
    assert decided.human.reviewer == "alice"
    assert decided.human.note == "patch bump, evidence checked"
    for aid in still_open:
        assert advisories[aid].risk is None, "a branch still at its gate has published nothing"
    for aid in still_open | UNGATED:
        assert advisories[aid].human is None, "only the resumed branch carries a verdict"


def test_a_verdict_does_not_change_the_policy_decision_class(demo_app):
    """ADR-0002: the reviewer records a verdict; the decision class stays the policy's."""
    graph = build_graph(InMemorySaver(), justifier=None)
    start_scan(graph, demo_app, "gate-5")
    gates = sorted(pending_gates(graph, "gate-5"), key=lambda g: g.payload.advisory_id)

    resume_gate(
        graph,
        "gate-5",
        gates[0].interrupt_id,
        ResumeCommand(verdict="reject", reviewer="bob", note="wait for the next release"),
    )

    a = advisories_of(graph, "gate-5")[gates[0].payload.advisory_id]
    assert a.human.verdict == "reject"
    assert a.decision == EXPECTED[a.advisory_id][4]
    assert a.risk.triggers == EXPECTED[a.advisory_id][6]
    assert a.risk.score == gates[0].payload.risk_score


def test_a_malformed_resume_halts_only_that_branch(demo_app):
    graph = build_graph(InMemorySaver(), justifier=None)
    start_scan(graph, demo_app, "gate-6")
    gates = sorted(pending_gates(graph, "gate-6"), key=lambda g: g.payload.advisory_id)

    graph.invoke(
        Command(resume={gates[0].interrupt_id: {"verdict": "looks fine to me"}}),
        config={"configurable": {"thread_id": "gate-6"}},
    )

    advisories = advisories_of(graph, "gate-6")
    halted = advisories[gates[0].payload.advisory_id]
    assert halted.decision == "halted"
    assert "human_gate" in halted.halt_reason
    assert halted.human is None
    assert {g.payload.advisory_id for g in pending_gates(graph, "gate-6")} == GATED - {
        gates[0].payload.advisory_id
    }


# ------------------------------------------------------------------ finishing the scan


def test_resuming_every_branch_completes_the_scan_without_moving_a_decision(demo_app):
    graph = build_graph(InMemorySaver(), justifier=None)
    start_scan(graph, demo_app, "gate-7")
    for _ in range(len(GATED)):
        gate = pending_gates(graph, "gate-7")[0]
        approve(graph, "gate-7", gate, reviewer="alice")

    snapshot = graph.get_state({"configurable": {"thread_id": "gate-7"}})
    assert snapshot.next == ()
    assert pending_gates(graph, "gate-7") == []

    advisories = {a.advisory_id: a for a in snapshot.values["advisories"]}
    assert set(advisories) == set(EXPECTED)
    for aid, (imported, called, runtime, fix, decision, bump, triggers) in EXPECTED.items():
        a = advisories[aid]
        r = a.reachability
        assert (r.imported, r.symbol_called, r.is_runtime_dep) == (imported, called, runtime), aid
        assert a.min_fixed_version == fix, aid
        assert a.decision == decision, (aid, a.decision)
        assert a.bump_kind == bump, aid
        assert a.risk.triggers == triggers, aid
    assert snapshot.values["summary"].counts == EXPECTED_SUMMARY
    assert snapshot.values["summary"].total_advisories == 11
    assert {aid for aid, a in advisories.items() if a.human} == GATED


def test_upstream_nodes_are_replayed_from_the_checkpoint_not_recomputed(demo_app):
    """Resuming must not re-run justify: it would double-charge the budget and re-ask the model."""
    calls: list[str] = []

    def fake(adv, evidence, decision):
        calls.append(adv.advisory_id)
        return (
            Justification(
                text=f"Fake justification for {adv.advisory_id}.", evidence_ids=["advisory"]
            ),
            Budget(tokens_used=100, usd_used=0.001),
        )

    graph = build_graph(InMemorySaver(), justifier=fake)
    start_scan(graph, demo_app, "gate-8")
    assert len(calls) == 11 and len(set(calls)) == 11

    for _ in range(len(GATED)):
        approve(graph, "gate-8", pending_gates(graph, "gate-8")[0])

    assert len(calls) == 11, "justify ran again on resume"
    budget = graph.get_state({"configurable": {"thread_id": "gate-8"}}).values["budget"]
    assert budget.tokens_used == 1100
    assert abs(budget.usd_used - 0.011) < 1e-9


# ------------------------------------------------------------------ durability


def test_a_new_graph_instance_on_a_new_connection_can_resume_a_gate(demo_app, tmp_path):
    """The acceptance test for durability: the worker process may exit while a human thinks."""
    url = f"sqlite:///{tmp_path / 'checkpoints.sqlite'}"
    thread = "restart-1"

    with open_checkpointer(url) as saver:
        graph = build_graph(saver, justifier=None)
        start_scan(graph, demo_app, thread)
        gates = sorted(pending_gates(graph, thread), key=lambda g: g.payload.advisory_id)
        assert len(gates) == len(GATED)
        target_id = gates[0].interrupt_id
        target_advisory = gates[0].payload.advisory_id

    # a brand-new process: new connection, new saver, new compiled graph, same thread
    with open_checkpointer(url) as saver:
        graph = build_graph(saver, justifier=None)
        assert list_threads(saver) == [thread]
        reopened = pending_gates(graph, thread)
        assert {g.payload.advisory_id for g in reopened} == GATED
        assert target_id in {g.interrupt_id for g in reopened}, "interrupt ids must be stable"

        resume_gate(
            graph,
            thread,
            target_id,
            ResumeCommand(verdict="approve", reviewer="carol", note="resumed after restart"),
        )

        advisories = advisories_of(graph, thread)
        resumed = advisories[target_advisory]
        assert resumed.human.verdict == "approve"
        assert resumed.human.reviewer == "carol"
        assert resumed.justification, "state before the gate was restored, not recomputed"
        assert resumed.risk.triggers == EXPECTED[target_advisory][6]
        assert {g.payload.advisory_id for g in pending_gates(graph, thread)} == GATED - {
            target_advisory
        }


def test_a_scan_finished_across_three_restarts_matches_the_golden_summary(demo_app, tmp_path):
    url = f"sqlite:///{tmp_path / 'checkpoints.sqlite'}"
    thread = "restart-2"

    with open_checkpointer(url) as saver:
        start_scan(build_graph(saver, justifier=None), demo_app, thread)

    for _ in range(len(GATED)):
        with open_checkpointer(url) as saver:
            graph = build_graph(saver, justifier=None)
            approve(graph, thread, pending_gates(graph, thread)[0], reviewer="dana")

    with open_checkpointer(url) as saver:
        graph = build_graph(saver, justifier=None)
        snapshot = graph.get_state({"configurable": {"thread_id": thread}})
        assert snapshot.next == ()
        assert snapshot.values["summary"].counts == EXPECTED_SUMMARY
        assert all(
            a.human.reviewer == "dana"
            for a in snapshot.values["advisories"]
            if a.advisory_id in GATED
        )
