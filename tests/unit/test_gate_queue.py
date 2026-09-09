"""Pure parts of the approval queue: turning checkpointer tasks into queue rows, and resolving
the id a reviewer typed."""

import pytest
from langgraph.types import Interrupt, PregelTask

from patchpilot.graph.nodes.human_gate import GatePayload
from patchpilot.graph.queue import (
    AmbiguousGate,
    GateNotFound,
    PendingGate,
    find_gate,
    gates_from_tasks,
)


def payload(advisory_id: str, scan_id: str = "s1") -> dict:
    return GatePayload(
        scan_id=scan_id,
        advisory_id=advisory_id,
        package="pyjwt",
        installed_version="2.4.0",
        min_fixed_version="2.10.1",
        bump_kind="patch",
        decision="needs_human",
        risk_score=6.2,
        risk_tier="high",
        package_tier="auth",
        triggers=["sensitive_tier:auth"],
        justification="because",
        justification_evidence=["advisory"],
        evidence=[{"id": "advisory", "fact": "f"}],
    ).model_dump(mode="json")


def task(name="advisory", interrupts=(), result=None, task_id="task-1"):
    return PregelTask(
        id=task_id,
        name=name,
        path=("__pregel_push", 0, False),
        interrupts=interrupts,
        result=result,
    )


def gate(advisory_id, thread="s1", interrupt_id="i1"):
    return PendingGate(
        thread_id=thread,
        task_id="t",
        interrupt_id=interrupt_id,
        payload=GatePayload.model_validate(payload(advisory_id, thread)),
    )


# ------------------------------------------------------------------ reading the queue


def test_a_task_waiting_at_an_interrupt_becomes_a_queue_row():
    tasks = [task(interrupts=(Interrupt(value=payload("GHSA-a"), id="int-1"),))]
    rows = gates_from_tasks("s1", tasks)
    assert len(rows) == 1
    assert (rows[0].thread_id, rows[0].interrupt_id) == ("s1", "int-1")
    assert rows[0].payload.advisory_id == "GHSA-a"


def test_a_task_that_already_produced_a_result_is_no_longer_pending():
    """After a resume the interrupt write stays in the checkpoint; `result` marks it done."""
    tasks = [
        task(
            interrupts=(Interrupt(value=payload("GHSA-a"), id="int-1"),),
            result={"advisories": []},
        )
    ]
    assert gates_from_tasks("s1", tasks) == []


def test_tasks_without_interrupts_are_ignored():
    assert gates_from_tasks("s1", [task(), task(result={"advisories": []})]) == []


def test_interrupts_that_are_not_human_gates_are_ignored():
    """Future interrupt kinds must not break `patchpilot queue list`."""
    tasks = [task(interrupts=(Interrupt(value={"kind": "something_else"}, id="int-9"),))]
    assert gates_from_tasks("s1", tasks) == []


def test_several_interrupts_on_one_task_all_become_rows():
    tasks = [
        task(
            interrupts=(
                Interrupt(value=payload("GHSA-a"), id="int-1"),
                Interrupt(value=payload("GHSA-b"), id="int-2"),
            )
        )
    ]
    assert [r.payload.advisory_id for r in gates_from_tasks("s1", tasks)] == ["GHSA-a", "GHSA-b"]


# ------------------------------------------------------------------ resolving an id


def test_find_gate_matches_the_advisory_id_case_insensitively():
    gates = [gate("GHSA-a"), gate("GHSA-b", interrupt_id="i2")]
    assert find_gate(gates, "ghsa-b").payload.advisory_id == "GHSA-b"


def test_find_gate_matches_an_interrupt_id_prefix():
    gates = [gate("GHSA-a", interrupt_id="abc123"), gate("GHSA-b", interrupt_id="def456")]
    assert find_gate(gates, "def").payload.advisory_id == "GHSA-b"


def test_find_gate_raises_when_nothing_matches():
    with pytest.raises(GateNotFound):
        find_gate([gate("GHSA-a")], "GHSA-z")
    with pytest.raises(GateNotFound):
        find_gate([], "GHSA-a")


def test_find_gate_refuses_to_guess_between_two_scans():
    gates = [
        gate("GHSA-a", thread="s1", interrupt_id="i1"),
        gate("GHSA-a", thread="s2", interrupt_id="i2"),
    ]
    with pytest.raises(AmbiguousGate) as excinfo:
        find_gate(gates, "GHSA-a")
    assert "s1" in str(excinfo.value) and "s2" in str(excinfo.value)
