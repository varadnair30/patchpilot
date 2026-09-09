"""human_gate: the durable pause.

The node hands the reviewer a one-screen evidence bundle through `interrupt()` and stops. The
checkpointer persists the whole branch, so the worker process may exit while a human thinks; a
later process resumes the same thread with
`Command(resume={"verdict": ..., "reviewer": ..., "note": ...})`.

Two things this node deliberately does *not* do:

* It does not decide. The decision class and the gate triggers come from `policy/rules.py`
  (ADR-0002); the verdict is recorded beside them in `AdvisoryState.human`, never inside
  `decision`. `execute_pr` (step 7) is what reads `human.verdict == "approve"`.
* It does not trust the resume payload. Anything that is not a valid `ResumeCommand` halts the
  branch the same way a tool contract violation does (rule 3), rather than being written to state.

In step 5 the gate sits directly after `justify` and fires on non-empty `risk.triggers`. Step 6
moves it after `plan_remediation`, where the sandbox diff joins the bundle and `modify` becomes a
third verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from langgraph.types import interrupt
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from patchpilot.graph.state import (
    AdvisoryBranch,
    AdvisoryState,
    BumpKind,
    HumanDecision,
    InjectionFlag,
    Reachability,
    RiskTier,
    UntrustedText,
)
from patchpilot.llm.justify import EvidenceItem, build_evidence

GATE_KIND = "human_gate"


class GatePayload(BaseModel):
    """What the reviewer sees. Serialised to plain JSON before it enters the checkpointer, so it
    survives any saver and can be rendered by a CLI, an API or the web queue unchanged."""

    kind: Literal["human_gate"] = GATE_KIND
    scan_id: str | None = None

    advisory_id: str
    package: str
    installed_version: str
    min_fixed_version: str | None = None
    bump_kind: BumpKind | None = None
    is_dev: bool = False
    cvss: float | None = None
    severity_label: str | None = None
    epss: float | None = None

    decision: str = Field(description="Decision class the reviewer is being asked to confirm")
    risk_score: float
    risk_tier: RiskTier
    package_tier: str = "default"
    triggers: list[str] = Field(default_factory=list)

    reachability: Reachability | None = None
    justification: str | None = None
    justification_evidence: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)

    # Rule 4: the reviewer must be able to read the advisory text, so it travels with the bundle
    # as clearly labelled data. It is never merged into a prompt or used for routing.
    untrusted_text: UntrustedText = Field(default_factory=UntrustedText)
    injection_flag: InjectionFlag = Field(default_factory=InjectionFlag)


class ResumeCommand(BaseModel):
    """The reviewer's verdict, as it arrives in `Command(resume=...)`.

    `modify` (with a target version) needs `plan_remediation` to re-run the sandbox on the chosen
    version, so it is rejected until step 6 rather than silently recorded and ignored.
    """

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["approve", "reject"]
    reviewer: str = Field(min_length=1)
    note: str = ""


def build_gate_payload(adv: AdvisoryState, scan_id: str | None) -> GatePayload:
    """The evidence bundle the justifier saw, plus the decision, the triggers and the paragraph."""
    risk = adv.risk
    return GatePayload(
        scan_id=scan_id,
        advisory_id=adv.advisory_id,
        package=adv.package,
        installed_version=adv.installed_version,
        min_fixed_version=adv.min_fixed_version,
        bump_kind=adv.bump_kind,
        is_dev=adv.is_dev,
        cvss=adv.cvss,
        severity_label=adv.severity_label,
        epss=adv.epss,
        decision=adv.decision or "needs_human",
        risk_score=risk.score if risk else 0.0,
        risk_tier=risk.tier if risk else "low",
        package_tier=risk.package_tier if risk else "default",
        triggers=list(risk.triggers) if risk else [],
        reachability=adv.reachability,
        justification=adv.justification,
        justification_evidence=list(adv.justification_evidence),
        evidence=build_evidence(adv, adv.policy_reasons),
        untrusted_text=adv.untrusted_text,
        injection_flag=adv.injection_flag,
    )


def human_gate(branch: AdvisoryBranch) -> dict:
    adv = branch["advisory"].model_copy(deep=True)
    if adv.decision == "halted":
        return {"advisory": adv, "advisories": [adv]}

    payload = build_gate_payload(adv, branch.get("scan_id"))
    # Everything above this line re-runs on every resume attempt, so it must stay side-effect free.
    raw = interrupt(payload.model_dump(mode="json"))

    try:
        resume = ResumeCommand.model_validate(raw)
    except ValidationError as e:
        adv.decision = "halted"
        adv.halt_reason = f"human_gate: resume payload contract violated: {e}"
        return {"advisory": adv, "advisories": [adv]}

    adv.human = HumanDecision(
        reviewer=resume.reviewer,
        verdict=resume.verdict,
        note=resume.note,
        decided_at=datetime.now(UTC),
    )
    return {"advisory": adv, "advisories": [adv]}
