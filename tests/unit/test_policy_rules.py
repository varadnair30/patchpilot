import pytest

from patchpilot.graph.state import AdvisoryState, InjectionFlag, Reachability
from patchpilot.policy.rules import (
    bump_kind,
    compute_score,
    epss_factor,
    evaluate,
    load_policy,
    tier_for,
)

P = load_policy()


def _adv(**kw) -> AdvisoryState:
    base = dict(
        advisory_id="GHSA-x",
        package="somepkg",
        installed_version="1.2.3",
        min_fixed_version="1.2.4",
        cvss=7.5,
        epss=0.005,
    )
    base.update(kw)
    return AdvisoryState(**base)


def _reach(imported=True, called=True, confidence=0.85, runtime=True, test_only=False):
    return Reachability(
        imported=imported,
        symbol_called=called,
        is_runtime_dep=runtime,
        imported_from_test_only=test_only,
        confidence=confidence,
    )


@pytest.mark.parametrize(
    "a,b,kind",
    [
        ("1.2.3", "1.2.4", "patch"),
        ("2.31.0", "2.32.4", "minor"),
        ("1.9.0", "2.0.0", "major"),
        ("0.27.0", "0.40.0", "major"),  # 0.x minor counts as major
        ("0.0.6", "0.0.18", "patch"),
        ("42.0.0", "42.0.4", "patch"),
        ("garbage", "1.0", "major"),
    ],
)
def test_bump_kind(a, b, kind):
    assert bump_kind(a, b) == kind


def test_epss_factor_range():
    assert epss_factor(None, P) == pytest.approx(0.70)
    assert epss_factor(0.05, P) == pytest.approx(1.00)
    assert epss_factor(0.5, P) == pytest.approx(1.30)  # saturates


def test_tiers():
    assert tier_for(9.0, P) == "critical"
    assert tier_for(7.0, P) == "high"
    assert tier_for(4.0, P) == "medium"
    assert tier_for(3.99, P) == "low"


def test_score_uses_label_fallback_without_cvss():
    adv = _adv(cvss=None, severity_label="HIGH", reachability=_reach(), epss=0.0)
    score, kind = compute_score(adv, P)
    assert kind == "symbol_called"
    assert score == pytest.approx(8.0 * 1.0 * 0.70, abs=0.01)


def test_not_applicable_when_symbol_not_called():
    adv = _adv(reachability=_reach(called=False))
    out = evaluate(adv)
    assert out.decision == "not_applicable"
    assert out.risk.triggers == []
    assert out.bump == "patch"


def test_not_applicable_when_not_imported():
    adv = _adv(reachability=_reach(imported=False, called=False, confidence=0.9))
    assert evaluate(adv).decision == "not_applicable"


def test_sensitive_tier_is_never_dismissed_statically():
    adv = _adv(package="cryptography", reachability=_reach(called=False))
    out = evaluate(adv)
    assert out.decision is None
    assert "sensitive_tier:crypto" in out.risk.triggers
    assert out.risk.package_tier == "crypto"


def test_dev_only_low_epss_is_accept_risk_even_when_never_imported():
    """Dev tools are executed, not imported: the dev rule outranks static dismissal."""
    adv = _adv(package="black", is_dev=True, reachability=_reach(imported=False, called=False))
    out = evaluate(adv)
    assert out.decision == "accept_risk"
    assert any("dev-only" in r for r in out.reasons)


def test_dev_only_high_epss_is_not_dismissed():
    adv = _adv(
        package="black", is_dev=True, epss=0.2, reachability=_reach(imported=False, called=False)
    )
    assert evaluate(adv).decision == "not_applicable"  # falls through to the static rule


def test_import_only_low_score_is_accept_risk():
    adv = _adv(cvss=3.0, epss=0.001, reachability=_reach(called=None, confidence=0.5))
    assert evaluate(adv).decision == "accept_risk"


def test_import_only_high_score_continues_with_low_confidence_trigger():
    adv = _adv(cvss=9.8, epss=0.001, reachability=_reach(called=None, confidence=0.5))
    out = evaluate(adv)
    assert out.decision is None
    assert any(t.startswith("low_confidence") for t in out.risk.triggers)


def test_reachable_patch_bump_has_no_triggers():
    adv = _adv(reachability=_reach())
    out = evaluate(adv)
    assert out.decision is None and out.risk.triggers == [] and out.bump == "patch"


def test_major_bump_and_high_epss_and_injection_trigger():
    adv = _adv(
        installed_version="1.0.0",
        min_fixed_version="2.0.0",
        epss=0.3,
        reachability=_reach(),
        injection_flag=InjectionFlag(flagged=True, reason="x"),
    )
    t = evaluate(adv, budget_fraction=0.9).risk.triggers
    assert "major_bump" in t
    assert any(x.startswith("epss_high") for x in t)
    assert "injection_flagged" in t
    assert "budget_near_limit" in t


def test_no_fix_available_trigger():
    adv = _adv(min_fixed_version=None, reachability=_reach())
    out = evaluate(adv)
    assert out.bump is None and "no_fix_available" in out.risk.triggers


def test_score_capped_at_ten():
    adv = _adv(cvss=10.0, epss=0.9, reachability=_reach())
    assert compute_score(adv, P)[0] == 10.0
