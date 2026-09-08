"""Graph wiring.

Step 4 shape:

    START -> ingest -> [Send: advisory x N] -> collect -> END

    advisory (subgraph, one run per advisory, own AdvisoryBranch state):
        reachability -> risk_policy -> justify

The subgraph is where plan_remediation, human_gate and execute_pr are added next, so a human
decision on one advisory never blocks the others. The checkpointer and the justifier are
injectable: tests use InMemorySaver and a fake justifier; the worker uses PostgresSaver and OpenAI.
"""

from __future__ import annotations

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from patchpilot.graph.nodes.ingest import ingest
from patchpilot.graph.nodes.justify import make_justify_node
from patchpilot.graph.nodes.reachability import reachability
from patchpilot.graph.nodes.risk_policy import risk_policy
from patchpilot.graph.routing import fan_out_advisories
from patchpilot.graph.state import AdvisoryBranch, ScanState, ScanSummary
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


def build_advisory_subgraph(justifier: JustifierFn | None):
    sg = StateGraph(AdvisoryBranch)
    sg.add_node("reachability", reachability)
    sg.add_node("risk_policy", risk_policy)
    sg.add_node("justify", make_justify_node(justifier))
    sg.add_edge(START, "reachability")
    sg.add_edge("reachability", "risk_policy")
    sg.add_edge("risk_policy", "justify")
    sg.add_edge("justify", END)
    return sg.compile()


def build_graph(
    checkpointer: BaseCheckpointSaver | None = None,
    justifier: JustifierFn | None | str = "auto",
):
    """`justifier="auto"`: OpenAI when OPENAI_API_KEY is set, else the template fallback."""
    if justifier == "auto":
        justifier = openai_justifier()

    subgraph = build_advisory_subgraph(justifier)

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
