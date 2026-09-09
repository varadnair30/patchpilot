"""The approval queue, read straight out of the checkpointer.

There is no queue table and no broker: a pending approval *is* a LangGraph task sitting at an
`interrupt()`, and `graph.get_state(config).tasks[*].interrupts` is the whole listing API. The CLI
(and later the FastAPI queue) are thin renderers over these functions.

A task keeps its interrupt write in the checkpoint even after it has been resumed, so `result` is
what distinguishes "still waiting for a human" from "already decided".
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.types import Command, PregelTask

from patchpilot.graph.nodes.human_gate import GATE_KIND, GatePayload, ResumeCommand


class GateNotFound(LookupError):
    """Nothing in the queue matches the id the reviewer typed."""


class AmbiguousGate(LookupError):
    """The id is pending in more than one scan; the reviewer must say which."""


@dataclass(frozen=True)
class PendingGate:
    thread_id: str
    task_id: str
    interrupt_id: str
    payload: GatePayload


def thread_config(thread_id: str) -> dict:
    return {"configurable": {"thread_id": thread_id}}


def gates_from_tasks(thread_id: str, tasks: Iterable[PregelTask]) -> list[PendingGate]:
    gates: list[PendingGate] = []
    for task in tasks:
        if task.result is not None:
            continue  # resumed already; the interrupt write is just history now
        for item in task.interrupts:
            value = item.value
            if not isinstance(value, dict) or value.get("kind") != GATE_KIND:
                continue  # a future interrupt kind is not this queue's business
            gates.append(
                PendingGate(
                    thread_id=thread_id,
                    task_id=task.id,
                    interrupt_id=item.id,
                    payload=GatePayload.model_validate(value),
                )
            )
    return gates


def pending_gates(graph, thread_id: str) -> list[PendingGate]:
    return gates_from_tasks(thread_id, graph.get_state(thread_config(thread_id)).tasks)


def list_threads(checkpointer: BaseCheckpointSaver, limit: int = 500) -> list[str]:
    """Distinct thread ids known to the checkpointer, most recently written first."""
    seen: list[str] = []
    for checkpoint in checkpointer.list(None, limit=limit):
        thread_id = (checkpoint.config or {}).get("configurable", {}).get("thread_id")
        if thread_id and thread_id not in seen:
            seen.append(thread_id)
    return seen


def all_pending_gates(
    graph, checkpointer: BaseCheckpointSaver, limit: int = 500
) -> list[PendingGate]:
    gates: list[PendingGate] = []
    for thread_id in list_threads(checkpointer, limit):
        gates.extend(pending_gates(graph, thread_id))
    return gates


def find_gate(gates: Sequence[PendingGate], wanted: str) -> PendingGate:
    """Resolve what a reviewer typed: an advisory id, or a prefix of an interrupt id."""
    needle = wanted.strip().lower()
    matches = [g for g in gates if g.payload.advisory_id.lower() == needle]
    if not matches:
        matches = [g for g in gates if g.interrupt_id.lower().startswith(needle)]
    if not matches:
        raise GateNotFound(f"no pending approval matches {wanted!r}")
    if len(matches) > 1:
        threads = ", ".join(sorted({g.thread_id for g in matches}))
        raise AmbiguousGate(
            f"{wanted!r} is pending in more than one scan ({threads}); pass --thread to choose"
        )
    return matches[0]


def resume_gate(graph, thread_id: str, interrupt_id: str, resume: ResumeCommand) -> dict:
    """Resume exactly one branch. Every other branch of the scan stays where it is."""
    return graph.invoke(
        Command(resume={interrupt_id: resume.model_dump(mode="json")}),
        config=thread_config(thread_id),
    )
