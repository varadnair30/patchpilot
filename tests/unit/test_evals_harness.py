"""The golden harness has to be trustworthy before the golden set means anything.

Two failure modes matter more than the rest, and both actually happened while it was being built:
a case that silently contaminates another case's inputs, and a gate that reports success when it
could not really check. Each has a test here.
"""

import json
from pathlib import Path

import pytest
import yaml

from evals.cases import GOLDEN_DIR, CaseResult, GoldenCase, load_cases, prepare_workspace, run_case
from evals.evaluators import (
    FAITHFULNESS_THRESHOLD,
    CaseReport,
    CheckOutcome,
    decision_match,
    evidence_faithfulness,
    grade,
    percentile,
    trigger_match,
)
from evals.run_evals import gate, render, summarise
from patchpilot.llm.justify import EvidenceItem


def case(**overrides) -> GoldenCase:
    base = dict(
        id="c1",
        description="d",
        rationale="r",
        source="fixture",
        repo="fixtures/patchpilot-demo-app",
        advisory_id="GHSA-75c5-xw7c-p5pm",
        expect={"decision": "needs_human"},
    )
    base.update(overrides)
    return GoldenCase.model_validate(base)


# ==================================================================== the golden files


def test_every_shipped_case_loads_and_is_uniquely_named():
    cases = load_cases()
    assert len(cases) >= 30, "the golden set should not shrink by accident"
    assert len({c.id for c in cases}) == len(cases)


def test_every_case_explains_itself():
    """A flip is reviewed by someone who was not there. The rationale is what they read."""
    for c in load_cases():
        assert len(c.rationale.strip()) > 40, f"{c.id} needs a real rationale"
        assert c.description.strip(), c.id


def test_the_golden_set_covers_every_decision_class():
    decisions = {c.expect.decision for c in load_cases()}
    assert {"auto_fix", "needs_human", "not_applicable", "accept_risk"} <= decisions


def test_the_golden_set_covers_the_named_policy_rules():
    rules = {c.rule for c in load_cases() if c.rule}
    for required in (
        "auto_fix",
        "not_applicable",
        "accept_risk",
        "sensitive_tier",
        "max_bump",
        "require_clean_sandbox",
        "dependency_conflict",
        "low_confidence",
        "injection_flagged",
        "no_fix_available",
    ):
        assert required in rules, f"no golden case pins the {required} rule"


def test_adversarial_cases_exist_and_all_expect_a_human():
    adversarial = [c for c in load_cases() if c.id.startswith("adv-")]
    assert len(adversarial) >= 5
    assert all(c.expect.decision == "needs_human" for c in adversarial)


def test_a_duplicate_id_is_rejected(tmp_path):
    payload = {
        "cases": [
            {
                "id": "same",
                "description": "d",
                "rationale": "r" * 50,
                "source": "synthetic",
                "files": {"requirements.txt": "a==1\n"},
                "advisory": {"advisory_id": "X", "package": "a", "installed_version": "1"},
                "expect": {"decision": "needs_human"},
            }
        ]
        * 2
    }
    (tmp_path / "dupes.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_cases(tmp_path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"source": "fixture", "repo": None},
        {"source": "fixture", "advisory_id": None},
        {"source": "synthetic", "repo": None, "advisory_id": None},
    ],
)
def test_a_case_missing_what_its_source_needs_is_rejected(overrides):
    with pytest.raises(ValueError):
        case(**overrides)


# ==================================================================== case isolation


def test_one_case_cannot_rewrite_another_cases_inputs(tmp_path):
    """The bug this guards against: every synthetic `widget` case wants the same fixture key, so a
    shared directory let an adversarial case's poisoned changelog become the changelog for eight
    other cases and flip them."""
    shared_key = "widget/1.0.0..1.0.1"
    poisoned = case(
        id="poisoner",
        source="synthetic",
        repo=None,
        advisory_id=None,
        files={"requirements.txt": "widget==1.0.0\n", "app.py": "import widget\n"},
        advisory={
            "advisory_id": "X1",
            "package": "widget",
            "installed_version": "1.0.0",
            "min_fixed_version": "1.0.1",
        },
        recorded={
            "changelog": {shared_key: {"releases": [{"version": "1.0.1", "notes": "POISON"}]}}
        },
    )
    innocent = case(
        id="innocent",
        source="synthetic",
        repo=None,
        advisory_id=None,
        files={"requirements.txt": "widget==1.0.0\n", "app.py": "import widget\n"},
        advisory={
            "advisory_id": "X2",
            "package": "widget",
            "installed_version": "1.0.0",
            "min_fixed_version": "1.0.1",
        },
        recorded={
            "changelog": {shared_key: {"releases": [{"version": "1.0.1", "notes": "CLEAN"}]}}
        },
    )

    prepare_workspace(tmp_path)
    run_case(poisoned, tmp_path)
    run_case(innocent, tmp_path)

    from patchpilot.recorded.store import RecordedStore

    # After running both, the innocent case's own fixture tree still holds its own data.
    store = RecordedStore()
    notes = store.read("changelog", shared_key)["releases"][0]["notes"]
    assert notes == "CLEAN", "a case must not inherit another case's recorded data"


def test_running_cases_never_writes_into_the_repository_fixture_tree(tmp_path):
    from patchpilot.config import get_settings

    repo_fixtures = Path(get_settings().fixtures_dir)
    before = sorted(p.name for p in repo_fixtures.rglob("*.json"))
    prepare_workspace(tmp_path)
    for c in load_cases()[:5]:
        run_case(c, tmp_path)
    assert sorted(p.name for p in repo_fixtures.rglob("*.json")) == before


# ==================================================================== evaluators


def test_decision_match_is_exact():
    result = CaseResult(case_id="c1", decision="auto_fix")
    assert decision_match(case(expect={"decision": "auto_fix"}), result).passed
    assert not decision_match(case(expect={"decision": "needs_human"}), result).passed


def test_trigger_match_is_set_equality_not_order():
    result = CaseResult(case_id="c1", triggers=["b", "a"])
    check = trigger_match(case(expect={"decision": "needs_human", "triggers": ["a", "b"]}), result)
    assert check.passed


def test_trigger_match_reports_what_is_missing_and_what_is_extra():
    result = CaseResult(case_id="c1", triggers=["a", "c"])
    check = trigger_match(case(expect={"decision": "needs_human", "triggers": ["a", "b"]}), result)
    assert not check.passed
    assert "missing ['b']" in check.detail and "unexpected ['c']" in check.detail


def test_omitting_triggers_means_they_are_not_asserted():
    assert trigger_match(case(), CaseResult(case_id="c1", triggers=["anything"])) is None


def test_a_case_that_errored_fails_rather_than_crashing_the_run():
    report, _ = grade(case(), CaseResult(case_id="c1", error="BoomError: nope"))
    assert not report.passed
    assert report.checks[0].name == "ran"


# ==================================================================== faithfulness


def test_an_invented_citation_scores_zero_without_calling_the_judge():
    """The deterministic check runs first, so a judge outage cannot hide a fabricated citation."""

    def judge(_result):  # pragma: no cover - must not be reached
        raise AssertionError("the judge should not be consulted")

    result = CaseResult(
        case_id="c1",
        justification="Because reasons.",
        cited_evidence=["does-not-exist"],
        evidence=[EvidenceItem(id="advisory", fact="f")],
    )
    score, unsupported, _ = evidence_faithfulness(result, judge)
    assert score == 0.0
    assert "do not exist" in unsupported[0]


def test_without_a_judge_faithfulness_is_unscored_rather_than_perfect():
    result = CaseResult(case_id="c1", justification="x", evidence=[EvidenceItem(id="a", fact="f")])
    score, _, _ = evidence_faithfulness(result, None)
    assert score is None, "an ungraded case must never read as a passing one"


# ==================================================================== the gate


def passing_report(case_id="c1", **kw) -> CaseReport:
    defaults = dict(checks=[CheckOutcome(name="decision_match", passed=True)])
    defaults.update(kw)
    return CaseReport(case_id=case_id, **defaults)


def test_the_gate_passes_a_clean_run():
    summary = summarise([passing_report()], graded=False)
    assert gate(summary, None) == []


def test_a_decision_flip_blocks_the_merge():
    flipped = CaseReport(
        case_id="c9",
        checks=[
            CheckOutcome(
                name="decision_match", passed=False, expected="needs_human", actual="auto_fix"
            )
        ],
    )
    summary = summarise([flipped], graded=False)
    failures = gate(summary, None)
    assert any("decision flipped: c9" in f for f in failures)


def test_a_score_drop_beyond_the_limit_blocks_the_merge():
    summary = summarise([passing_report(), passing_report("c2")], graded=False)
    summary["score"] = 0.90
    assert any("score dropped" in f for f in gate(summary, {"score": 1.0}))


def test_a_score_drop_within_the_limit_is_allowed():
    summary = summarise([passing_report()], graded=False)
    summary["score"] = 0.99
    assert gate(summary, {"score": 1.0}) == []


def test_a_missing_key_does_not_turn_faithfulness_into_a_pass():
    """Ungraded must be visible, not silently green."""
    summary = summarise([passing_report(faithfulness=None)], graded=False)
    assert summary["faithfulness"]["graded"] is False
    assert gate(summary, None) == []
    assert "not graded" in render(summary, [])


def test_a_low_faithfulness_score_blocks_when_it_was_graded():
    low = passing_report(faithfulness=0.4)
    summary = summarise([low], graded=True)
    failures = gate(summary, None)
    assert any("unfaithful justification" in f for f in failures)
    assert any(str(FAITHFULNESS_THRESHOLD) in f for f in failures)


def test_an_errored_case_blocks_the_merge():
    summary = summarise([CaseReport(case_id="c3", error="boom")], graded=False)
    assert any("case errored: c3" in f for f in gate(summary, None))


def test_the_comment_names_every_flipped_case():
    flipped = CaseReport(
        case_id="demo-x",
        checks=[
            CheckOutcome(
                name="decision_match", passed=False, expected="needs_human", actual="auto_fix"
            )
        ],
    )
    summary = summarise([flipped], graded=False)
    comment = render(summary, gate(summary, None))
    assert "demo-x" in comment
    assert "needs_human" in comment and "auto_fix" in comment
    assert "two approvals" in comment


def test_the_summary_is_json_serialisable():
    summary = summarise([passing_report()], graded=False)
    json.dumps(summary)


def test_percentile_handles_small_samples():
    assert percentile([]) == 0.0
    assert percentile([5.0]) == 5.0
    assert percentile([1.0, 2.0, 3.0]) >= 2.0


# ==================================================================== the baseline


def test_the_pinned_baseline_matches_the_shipped_set():
    baseline = json.loads((GOLDEN_DIR.parent / "baseline.json").read_text(encoding="utf-8"))
    assert baseline["total"] == len(load_cases()), (
        "baseline.json is stale; re-pin it with "
        "`python evals/run_evals.py --update-baseline` and say why in the PR"
    )
    assert baseline["score"] == 1.0, "the golden set ships green"
