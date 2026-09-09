"""Graph wiring.

Step 6 shape:

    START -> ingest -> [Send: advisory x N] -> collect -> END

    advisory (subgraph, one run per advisory, own AdvisoryBranch state):
        reachability -> risk_policy -> plan_remediation -> justify -> (human_gate | END)

`justify` sits after `plan_remediation` because the LLM only ever runs once the decision is
already fixed (ADR-0002): it explains the terminal decision and the plan behind it, rather than
guessing at one that has not been made yet.

`human_gate` calls `interrupt()`, so a branch can sit paused for days while the other branches of
the same scan finish. That only works because each advisory is its own `Send()` branch: the
interrupt belongs to one task, and `Command(resume={interrupt_id: ...})` wakes exactly that one.

The subgraph is where execute_pr and record_outcome are added next. The checkpointer and both LLM
tasks are injectable: tests use InMemorySaver with fake callables; the worker uses PostgresSaver
(see storage/db.py) and OpenAI.
"""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from patchpilot.graph.nodes.human_gate import human_gate
from patchpilot.graph.nodes.ingest import ingest
from patchpilot.graph.nodes.justify import make_justify_node
from patchpilot.graph.nodes.plan_remediation import make_plan_remediation_node
from patchpilot.graph.nodes.reachability import reachability
from patchpilot.graph.nodes.risk_policy import risk_policy
from patchpilot.graph.routing import fan_out_advisories, route_to_human_gate
from patchpilot.graph.state import AdvisoryBranch, ScanState, ScanSummary
from patchpilot.llm.changelog import SummariserFn, openai_summariser
from patchpilot.llm.justify import JustifierFn, openai_justifier


def collect(state: ScanState) -> dict:
    advisories = state.get("advisories") or []
    counts: dict[str, int] = {}
    for a in advisories:
        if a.decision:
            key = a.decision
        elif a.risk and a.risk.triggers:
            key = "pending:needs_human"
        elif a.risk:
            key = "pending:auto_fix_candidate"
        else:
            key = "unscored"
        counts[key] = counts.get(key, 0) + 1
    return {"summary": ScanSummary(counts=counts, total_advisories=len(advisories))}


def build_advisory_subgraph(justifier: JustifierFn | None, summariser: SummariserFn | None):
    sg = StateGraph(AdvisoryBranch)
    sg.add_node("reachability", reachability)
    sg.add_node("risk_policy", risk_policy)
    sg.add_node("plan_remediation", make_plan_remediation_node(summariser))
    sg.add_node("justify", make_justify_node(justifier))
    sg.add_node("human_gate", human_gate)
    sg.add_edge(START, "reachability")
    sg.add_edge("reachability", "risk_policy")
    sg.add_edge("risk_policy", "plan_remediation")
    sg.add_edge("plan_remediation", "justify")
    sg.add_conditional_edges("justify", route_to_human_gate, ["human_gate", END])
    sg.add_edge("human_gate", END)
    return sg.compile()


def build_graph(
    checkpointer: BaseCheckpointSaver | None = None,
    justifier: JustifierFn | None | str = "auto",
    summariser: SummariserFn | None | str = "auto",
):
    """`"auto"`: OpenAI when OPENAI_API_KEY is set, else the deterministic template fallback.

    Both LLM tasks are injectable so tests can pass a callable and never reach OpenAI.
    """
    if justifier == "auto":
        justifier = openai_justifier()
    if summariser == "auto":
        summariser = openai_summariser()

    subgraph = build_advisory_subgraph(justifier, summariser)

    def advisory(branch: AdvisoryBranch) -> dict:
        """Run the per-advisory subgraph and publish only the keys the parent merges.
        (Returning the whole subgraph state would write `repo` N times in one step.)"""
        out = subgraph.invoke(branch)
        return {"advisories": out.get("advisories", []), "budget": out.get("budget")}

    g = StateGraph(ScanState)
    g.add_node("ingest", ingest)
    g.add_node("advisory", advisory)
    g.add_node("collect", collect)

    g.add_edge(START, "ingest")
    g.add_conditional_edges("ingest", fan_out_advisories, ["advisory", "collect"])
    g.add_edge("advisory", "collect")
    g.add_edge("collect", END)

    return g.compile(checkpointer=checkpointer or InMemorySaver())


# LangGraph Studio / `langgraph dev` entry point
graph = build_graph()
