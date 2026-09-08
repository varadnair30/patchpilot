"""justify: the only LLM call so far. Writes the justification, never touches the decision.

Last node of the per-advisory subgraph in step 4, so it also publishes the finished advisory and
the budget delta to the parent graph.
"""

from __future__ import annotations

from patchpilot.graph.state import AdvisoryBranch, Budget
from patchpilot.llm.justify import JustifierFn, justify


def make_justify_node(justifier: JustifierFn | None):
    def justify_node(branch: AdvisoryBranch) -> dict:
        adv = branch["advisory"].model_copy(deep=True)
        if adv.decision == "halted":
            return {"advisory": adv, "advisories": [adv], "budget": Budget()}
        # Provisional label for the writer: terminal decisions are final; everything else is
        # "pending remediation plan" until plan_remediation and the human gate exist.
        decision_label = adv.decision or (
            "needs_human (pending plan)"
            if adv.risk and adv.risk.triggers
            else "auto_fix candidate (pending sandbox)"
        )
        j, delta, notes = justify(adv, adv.policy_reasons, decision_label, justifier)
        adv.justification = j.text
        adv.justification_evidence = j.evidence_ids
        adv.justification_notes = notes
        return {"advisory": adv, "advisories": [adv], "budget": delta}

    return justify_node
