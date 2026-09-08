"""Deterministic risk policy (ADR-0002).

Inputs are the typed facts ingest and reachability already produced. Outputs are a score, a tier,
a terminal decision when one can be made without a remediation plan (`not_applicable`,
`accept_risk`), and the list of gate triggers that will force a human on the way through
plan_remediation. No LLM is involved anywhere in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from patchpilot.graph.state import AdvisoryState, BumpKind, Reachability, Risk, RiskTier

POLICY_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Policy:
    thresholds: dict[str, Any]
    tiers: dict[str, dict[str, list[str]]]

    def package_tier(self, package: str) -> tuple[str, bool]:
        """Return (tier_name, is_sensitive) for a canonical package name."""
        canon = canonicalize_name(package)
        for tier, pkgs in self.tiers.get("sensitive", {}).items():
            if canon in {canonicalize_name(p) for p in pkgs}:
                return tier, True
        for tier, pkgs in self.tiers.get("informational", {}).items():
            if canon in {canonicalize_name(p) for p in pkgs}:
                return tier, False
        return "default", False


@lru_cache
def load_policy(
    thresholds_path: Path = POLICY_DIR / "thresholds.yaml",
    tiers_path: Path = POLICY_DIR / "tiers.yaml",
) -> Policy:
    return Policy(
        thresholds=yaml.safe_load(thresholds_path.read_text(encoding="utf-8")),
        tiers=yaml.safe_load(tiers_path.read_text(encoding="utf-8")),
    )


# --------------------------------------------------------------------------------------------
# Building blocks (each independently unit-tested)
# --------------------------------------------------------------------------------------------


def bump_kind(installed: str, target: str) -> BumpKind:
    """Semantic distance of a version bump. For 0.x packages a minor change counts as major,
    following the semver convention that 0.x minors may break."""
    try:
        a, b = Version(installed), Version(target)
    except InvalidVersion:
        return "major"
    if a.major != b.major:
        return "major"
    if a.minor != b.minor:
        return "major" if a.major == 0 else "minor"
    return "patch"


def base_score(cvss: float | None, severity_label: str | None, policy: Policy) -> float:
    if cvss is not None:
        return float(cvss)
    table = policy.thresholds["score"]["label_fallback"]
    return float(table.get((severity_label or "UNKNOWN").upper(), table["UNKNOWN"]))


def exposure_factor(reach: Reachability | None, policy: Policy) -> tuple[float, str]:
    ex = policy.thresholds["score"]["exposure"]
    if reach is None:
        return ex["import_only"], "unknown"
    if reach.symbol_called:
        return ex["symbol_called"], "symbol_called"
    if not reach.imported:
        return ex["not_imported"], "not_imported"
    if reach.symbol_called is None:
        return ex["import_only"], "import_only"
    return ex["imported_not_called"], "imported_not_called"


def epss_factor(epss: float | None, policy: Policy) -> float:
    s = policy.thresholds["score"]
    e = 0.0 if epss is None else float(epss)
    return s["epss_floor"] + s["epss_span"] * min(e / s["epss_saturation"], 1.0)


def tier_for(score: float, policy: Policy) -> RiskTier:
    t = policy.thresholds["tiers"]
    if score >= t["critical"]:
        return "critical"
    if score >= t["high"]:
        return "high"
    if score >= t["medium"]:
        return "medium"
    return "low"


def compute_score(adv: AdvisoryState, policy: Policy) -> tuple[float, str]:
    base = base_score(adv.cvss, adv.severity_label, policy)
    exposure, exposure_kind = exposure_factor(adv.reachability, policy)
    dev = policy.thresholds["score"]["dev_only_multiplier"] if adv.is_dev else 1.0
    score = base * exposure * dev * epss_factor(adv.epss, policy)
    return round(min(score, 10.0), 2), exposure_kind


# --------------------------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyOutcome:
    risk: Risk
    decision: str | None  # "not_applicable" | "accept_risk" | None (= continue to remediation)
    bump: BumpKind | None
    reasons: list[str]  # human-readable, deterministic, cited by the justification


def evaluate(
    adv: AdvisoryState, budget_fraction: float = 0.0, policy: Policy | None = None
) -> PolicyOutcome:
    policy = policy or load_policy()
    th = policy.thresholds
    reach = adv.reachability
    tier_name, sensitive = policy.package_tier(adv.package)
    score, exposure_kind = compute_score(adv, policy)
    tier = tier_for(score, policy)
    reasons: list[str] = [f"score {score} -> tier {tier} (exposure={exposure_kind})"]
    triggers: list[str] = []

    confidence = reach.confidence if reach else 0.0
    epss = adv.epss if adv.epss is not None else 0.0
    bump = (
        bump_kind(adv.installed_version, adv.min_fixed_version) if adv.min_fixed_version else None
    )

    # ---- terminal decisions (no remediation plan needed) --------------------------------
    d = th["decisions"]
    if sensitive:
        reasons.append(f"package is in sensitive tier '{tier_name}': no static-only dismissal")
    else:
        # Dev-only tooling is executed, not imported, so "never imported" proves nothing there;
        # the dev rule therefore runs before the static-dismissal rule.
        if adv.is_dev and epss < d["accept_risk_max_epss"]:
            reasons.append(
                f"dev-only dependency with EPSS {epss:.3f} < {d['accept_risk_max_epss']}"
            )
            return PolicyOutcome(
                Risk(score=score, tier=tier, triggers=[], package_tier=tier_name),
                "accept_risk",
                bump,
                reasons,
            )
        if (
            reach
            and reach.symbol_called is False
            and confidence >= d["not_applicable_min_confidence"]
        ):
            reasons.append(
                "vulnerable symbol(s) not referenced"
                if reach.imported
                else "package never imported"
            )
            return PolicyOutcome(
                Risk(score=score, tier=tier, triggers=[], package_tier=tier_name),
                "not_applicable",
                bump,
                reasons,
            )
        if (
            reach
            and reach.symbol_called is None
            and score < d["accept_risk_max_score"]
            and epss < d["accept_risk_max_epss"]
        ):
            reasons.append("import-only evidence, low score and low EPSS")
            return PolicyOutcome(
                Risk(score=score, tier=tier, triggers=[], package_tier=tier_name),
                "accept_risk",
                bump,
                reasons,
            )

    # ---- gate triggers for advisories that continue to plan_remediation -----------------
    g = th["gate"]
    if sensitive:
        triggers.append(f"sensitive_tier:{tier_name}")
    if bump == "major":
        triggers.append("major_bump")
    if bump is None:
        triggers.append("no_fix_available")
    if epss >= g["epss_human"]:
        triggers.append(f"epss_high:{epss:.3f}")
    if confidence < g["low_confidence"]:
        triggers.append(f"low_confidence:{confidence:.2f}")
    if adv.injection_flag.flagged:
        triggers.append("injection_flagged")
    if budget_fraction >= g["budget_warn_fraction"]:
        triggers.append("budget_near_limit")
    if reach and reach.imported_from_test_only:
        triggers.append("test_only_usage")

    if triggers:
        reasons.append("human gate required: " + ", ".join(triggers))
    else:
        reasons.append("no gate triggers; eligible for auto_fix if the sandbox diff is clean")

    return PolicyOutcome(
        Risk(score=score, tier=tier, triggers=triggers, package_tier=tier_name), None, bump, reasons
    )
