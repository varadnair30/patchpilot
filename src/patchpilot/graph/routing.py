"""Pure routing functions. No side effects, no LLM; unit-tested directly."""

from __future__ import annotations

from langgraph.types import Send

from patchpilot.graph.state import ScanState


def fan_out_advisories(state: ScanState) -> list[Send] | str:
    """After ingest: one per-advisory subgraph run per advisory, or straight to collect."""
    advisories = state.get("advisories") or []
    if not advisories:
        return "collect"
    repo = state["repo"]
    budget = state.get("budget")
    fraction = budget.fraction_used if budget else 0.0
    return [
        Send("advisory", {"repo": repo, "advisory": adv, "budget_fraction": fraction})
        for adv in advisories
    ]
