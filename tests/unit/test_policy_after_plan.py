"""`decide_after_plan`: the deterministic rule that grants or withholds auto_fix.

ADR-0002 lives or dies here. No LLM output is an input to any of this, and every number it reads
comes from thresholds.yaml, so widening the policy is a reviewable YAML change.
"""

import pytest

from patchpilot.graph.state import AdvisoryState, Plan, Reachability, Risk, SandboxResult
from patchpilot.policy.rules import Policy, decide_after_plan, load_policy


def advisory(**overrides) -> AdvisoryState:
    base = dict(
        advisory_id="GHSA-x",
        package="requests",
        installed_version="2.31.0",
        min_fixed_version="2.31.1",
        reachability=Reachability(imported=True, symbol_called=True, confidence=0.9),
        risk=Risk(score=4.0, tier="medium", triggers=[]),
        plan=Plan(target_version="2.31.1", bump_kind="patch"),
        sandbox=SandboxResult(supported=True),
    )
    base.update(overrides)
    return AdvisoryState(**base)


def policy_with(**auto_fix) -> Policy:
    base = load_policy()
    thresholds = {**base.thresholds, "auto_fix": {**base.thresholds["auto_fix"], **auto_fix}}
    return Policy(thresholds=thresholds, tiers=base.tiers)


# ------------------------------------------------------------------ the happy path


def test_a_clean_patch_bump_earns_auto_fix():
    outcome = decide_after_plan(advisory())
    assert outcome.decision == "auto_fix"
    assert outcome.triggers == []
    assert any("no human needed" in r for r in outcome.reasons)


# ------------------------------------------------------------------ each condition, one at a time


def test_a_minor_bump_is_above_the_default_ceiling():
    outcome = decide_after_plan(advisory(plan=Plan(target_version="2.32.0", bump_kind="minor")))
    assert outcome.decision == "needs_human"
    assert "minor_bump" in outcome.triggers


def test_a_major_bump_is_above_the_ceiling():
    outcome = decide_after_plan(advisory(plan=Plan(target_version="3.0.0", bump_kind="major")))
    assert outcome.decision == "needs_human"
    assert "major_bump" in outcome.triggers


def test_the_ceiling_is_a_yaml_threshold_not_a_hardcoded_rule():
    """Raising max_bump to `minor` is how you widen the policy; it is not a code change."""
    plan = Plan(target_version="2.32.0", bump_kind="minor")
    assert decide_after_plan(advisory(plan=plan)).decision == "needs_human"
    assert (
        decide_after_plan(advisory(plan=plan), policy=policy_with(max_bump="minor")).decision
        == "auto_fix"
    )


def test_a_newly_failing_test_blocks_auto_fix():
    outcome = decide_after_plan(
        advisory(sandbox=SandboxResult(supported=True, newly_failing=["tests/test_a.py::test_x"]))
    )
    assert outcome.decision == "needs_human"
    assert "tests_newly_failing:1" in outcome.triggers
    assert any("test_x" in r for r in outcome.reasons), "the reviewer is told which test"


def test_a_test_that_was_already_red_does_not_block():
    """The baseline is what makes the sandbox trustworthy."""
    outcome = decide_after_plan(
        advisory(
            sandbox=SandboxResult(
                supported=True,
                baseline_failed=["tests/test_a.py::test_x"],
                after_bump_failed=["tests/test_a.py::test_x"],
                newly_failing=[],
            )
        )
    )
    assert outcome.decision == "auto_fix"


def test_an_unprovable_bump_is_never_auto_fixed():
    outcome = decide_after_plan(
        advisory(sandbox=SandboxResult(supported=False, reason="no test runner found"))
    )
    assert outcome.decision == "needs_human"
    assert "sandbox_unsupported" in outcome.triggers
    assert any("no test runner found" in r for r in outcome.reasons)


def test_a_missing_sandbox_result_is_treated_as_unproven():
    outcome = decide_after_plan(advisory(sandbox=None))
    assert outcome.decision == "needs_human" and "sandbox_unsupported" in outcome.triggers


def test_low_reachability_confidence_blocks_auto_fix():
    outcome = decide_after_plan(
        advisory(reachability=Reachability(imported=True, symbol_called=True, confidence=0.4))
    )
    assert outcome.decision == "needs_human"
    assert any(t.startswith("low_confidence") for t in outcome.triggers)


def test_a_policy_trigger_from_risk_policy_still_forces_a_human():
    """A sensitive-tier package cannot buy its way out with a clean sandbox."""
    outcome = decide_after_plan(
        advisory(risk=Risk(score=4.0, tier="medium", triggers=["sensitive_tier:auth"]))
    )
    assert outcome.decision == "needs_human"
    assert outcome.triggers == ["sensitive_tier:auth"]


def test_a_dependency_conflict_forces_a_human():
    outcome = decide_after_plan(
        advisory(
            plan=Plan(
                target_version="0.40.0",
                bump_kind="patch",
                dependency_conflicts=["fastapi 0.100.0 requires starlette<0.28.0"],
            )
        )
    )
    assert outcome.decision == "needs_human"
    assert "dependency_conflict" in outcome.triggers
    assert any("not self-contained" in r for r in outcome.reasons)


def test_being_near_the_budget_cap_forces_a_human():
    outcome = decide_after_plan(advisory(), budget_fraction=0.9)
    assert outcome.decision == "needs_human" and "budget_near_limit" in outcome.triggers


def test_no_plan_at_all_forces_a_human():
    outcome = decide_after_plan(advisory(plan=None))
    assert outcome.decision == "needs_human"
    assert "no_fix_available" in outcome.triggers
    assert any("nothing to apply" in r for r in outcome.reasons)


# ------------------------------------------------------------------ trigger hygiene


def test_triggers_are_never_duplicated():
    outcome = decide_after_plan(
        advisory(
            risk=Risk(score=4.0, tier="medium", triggers=["major_bump", "low_confidence:0.40"]),
            plan=Plan(target_version="3.0.0", bump_kind="major"),
            reachability=Reachability(imported=True, symbol_called=True, confidence=0.4),
        )
    )
    assert outcome.triggers.count("major_bump") == 1
    assert outcome.triggers.count("low_confidence:0.40") == 1


def test_the_decision_is_a_pure_function_of_its_inputs():
    adv = advisory()
    assert decide_after_plan(adv).decision == decide_after_plan(adv).decision
    assert adv.decision is None, "deciding must not mutate the advisory"


@pytest.mark.parametrize("verdict", ["approve", "reject"])
def test_a_human_verdict_is_not_an_input(verdict):
    """The reviewer's verdict lives beside the decision, never inside the rule that makes it."""
    from datetime import UTC, datetime

    from patchpilot.graph.state import HumanDecision

    adv = advisory(
        human=HumanDecision(reviewer="alice", verdict=verdict, decided_at=datetime.now(UTC))
    )
    assert decide_after_plan(adv).decision == "auto_fix"
