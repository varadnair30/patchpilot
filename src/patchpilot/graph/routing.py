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
                "repo": repo,
                "advisory": adv,
                "budget_fraction": fraction,
            },
        )
        for adv in advisories
    ]


def route_after_justify(branch: AdvisoryBranch) -> str:
    """Whether this advisory needs a human before anything else happens to it.

    Step 5 gates on the deterministic triggers `policy/rules.py` produced. A terminal decision is
    the policy's final word — there is nothing for a reviewer to approve — so those go straight to
    END. Step 6 moves this decision after `plan_remediation`, where a clean sandbox diff on a patch
    bump is what earns `auto_fix`.
    """
    adv = branch["advisory"]
    if adv.decision in ("halted", "not_applicable", "accept_risk"):
        return END
    if adv.risk and adv.risk.triggers:
        return "human_gate"
    return END
