"""justify: writes the justification, never touches the decision.

Runs after `plan_remediation`, so the decision it explains is the final one (ADR-0002: the model
only ever describes a decision the policy already made). It is the last node before the human gate,
so it also publishes the finished advisory and the budget delta to the parent graph.
"""

from __future__ import annotations

from patchpilot.graph.state import AdvisoryBranch, Budget
from patchpilot.guardrails.budget import BUDGET_EXHAUSTED_FRACTION
from patchpilot.llm.justify import JustifierFn, justify


def make_justify_node(justifier: JustifierFn | None):
    def justify_node(branch: AdvisoryBranch) -> dict:
        adv = branch["advisory"].model_copy(deep=True)
        if adv.decision == "halted":
            return {"advisory": adv, "advisories": [adv], "budget": Budget()}
        # Hard stop: an agent that can exceed its own budget has no budget.
        if branch.get("budget_fraction", 0.0) >= BUDGET_EXHAUSTED_FRACTION:
            adv.decision = "halted"
            adv.halt_reason = "budget: run cap reached before this advisory could be justified"
            return {"advisory": adv, "advisories": [adv], "budget": Budget()}
        j, delta, notes = justify(adv, adv.policy_reasons, adv.decision or "undecided", justifier)
        adv.justification = j.text
        adv.justification_evidence = j.evidence_ids
        adv.justification_notes = notes
        return {"advisory": adv, "advisories": [adv], "budget": delta}

    return justify_node
