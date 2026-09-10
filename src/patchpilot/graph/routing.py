"""Pure routing functions. No side effects, no LLM; unit-tested directly."""

from __future__ import annotations

from langgraph.graph import END
from langgraph.types import Send

from patchpilot.graph.state import AdvisoryBranch, ScanState


def fan_out_advisories(state: ScanState) -> list[Send] | str:
    """After ingest: one per-advisory subgraph run per advisory, or straight to collect."""
    advisories = state.get("advisories") or []
    if not advisories:
        return "collect"
    repo = state["repo"]
    budget = state.get("budget")
    fraction = budget.fraction_used if budget else 0.0
    return [
        Send(
            "advisory",
            {
                "scan_id": state.get("scan_id"),
                "data_freshness": state.get("data_freshness"),
                "repo": repo,
                "dependencies": state.get("dependencies") or [],
                "advisory": adv,
                "budget_fraction": fraction,
            },
        )
        for adv in advisories
    ]


def route_to_human_gate(branch: AdvisoryBranch) -> str:
    """After justify: a human, a pull request, or nothing.

    The decision was settled by `policy.rules.decide_after_plan`; this only reads it. `auto_fix`
    goes straight to execute_pr because the policy cleared it and the sandbox proved it.
    """
    adv = branch["advisory"]
    if adv.decision == "needs_human":
        return "human_gate"
    if adv.decision == "auto_fix":
        return "execute_pr"
    return END


def route_after_gate(branch: AdvisoryBranch) -> str:
    """After the human gate: only an explicit approval opens a pull request.

    A reject, a halt from a malformed resume, or anything else ends the branch. `execute_pr`
    re-checks this itself rather than trusting the edge.
    """
    adv = branch["advisory"]
    if adv.decision == "halted":
        return END
    if adv.human is not None and adv.human.verdict == "approve":
        return "execute_pr"
    return END
