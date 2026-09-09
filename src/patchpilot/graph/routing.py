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
                "dependencies": state.get("dependencies") or [],
                "advisory": adv,
                "budget_fraction": fraction,
            },
        )
        for adv in advisories
    ]


def route_to_human_gate(branch: AdvisoryBranch) -> str:
    """Whether this advisory needs a human before anything else happens to it.

    Since step 6 the answer is simply the decision `plan_remediation` recorded: `policy/rules.py`
    grants `auto_fix` only when the bump is within the YAML ceiling, the sandbox diff is clean and
    no trigger fired. Everything else, terminal classes aside, is a reviewer's call.
    """
    return "human_gate" if branch["advisory"].decision == "needs_human" else END
