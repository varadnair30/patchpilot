"""risk_policy: deterministic decision + triggers (ADR-0002). No LLM here."""

from __future__ import annotations

from patchpilot.graph.state import AdvisoryBranch
from patchpilot.policy.rules import evaluate


def risk_policy(branch: AdvisoryBranch) -> dict:
    adv = branch["advisory"].model_copy(deep=True)
    if adv.decision == "halted":
        return {"advisory": adv}
    outcome = evaluate(adv, budget_fraction=branch.get("budget_fraction", 0.0))
    adv.risk = outcome.risk
    adv.bump_kind = outcome.bump
    adv.policy_reasons = outcome.reasons
    if outcome.decision:
        adv.decision = outcome.decision  # type: ignore[assignment]
    return {"advisory": adv}
