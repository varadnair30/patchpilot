from patchpilot.graph.state import AdvisoryState, Budget, CallSite, Reachability, Risk
from patchpilot.llm.client import usage_cost
from patchpilot.llm.justify import Justification, build_evidence, justify


def _adv() -> AdvisoryState:
    return AdvisoryState(
        advisory_id="GHSA-75c5-xw7c-p5pm",
        package="pyjwt",
        installed_version="2.10.0",
        min_fixed_version="2.10.1",
        cvss=2.2,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N",
        epss=0.0083,
        epss_percentile=0.55,
        vulnerable_symbols=["jwt.decode"],
        reachability=Reachability(
            imported=True,
            symbol_called=True,
            call_sites=[CallSite(file="app/auth.py", line=16, symbol="jwt.decode", snippet="x")],
            confidence=0.85,
        ),
        risk=Risk(score=1.65, tier="low", triggers=["sensitive_tier:auth"], package_tier="auth"),
    )


REASONS = ["score 1.65 -> tier low", "human gate required: sensitive_tier:auth"]


def test_evidence_ids_are_stable_and_complete():
    ids = [e.id for e in build_evidence(_adv(), REASONS)]
    assert ids[:3] == ["advisory", "cvss", "epss"]
    assert "call:0" in ids and "policy" in ids and "reason:1" in ids


def test_llm_off_uses_template_and_costs_nothing():
    j, budget, notes = justify(_adv(), REASONS, "needs_human", justifier=None)
    assert "template" in j.text and budget.tokens_used == 0
    assert notes == ["llm off: template justification"]
    assert set(j.evidence_ids) <= {e.id for e in build_evidence(_adv(), REASONS)}


def test_valid_model_output_is_accepted_and_budget_recorded():
    calls = []

    def fake(adv, evidence, decision):
        calls.append(decision)
        return (
            Justification(
                text="jwt.decode is called with a string issuer; auth tier forces review.",
                evidence_ids=["call:0", "policy"],
            ),
            Budget(tokens_used=500, usd_used=0.0002),
        )

    j, budget, notes = justify(_adv(), REASONS, "needs_human", fake)
    assert calls == ["needs_human"]
    assert j.evidence_ids == ["call:0", "policy"]
    assert budget.tokens_used == 500 and notes == []


def test_hallucinated_citation_is_rejected_then_retried():
    attempts = iter(
        [
            Justification(
                text="This cites something that does not exist in the bundle.",
                evidence_ids=["exploit-db:1"],
            ),
            Justification(
                text="Second attempt cites only real evidence ids from the bundle.",
                evidence_ids=["advisory", "epss"],
            ),
        ]
    )

    def fake(adv, evidence, decision):
        return next(attempts), Budget(tokens_used=100, usd_used=0.0001)

    j, budget, notes = justify(_adv(), REASONS, "needs_human", fake)
    assert j.evidence_ids == ["advisory", "epss"]
    assert budget.tokens_used == 200, "both attempts are paid for and accounted"
    assert notes and "unknown evidence ids ['exploit-db:1']" in notes[0]


def test_two_bad_attempts_fall_back_to_template():
    def fake(adv, evidence, decision):
        return Justification(
            text="Always cites a fabricated id, twice in a row here.", evidence_ids=["nope"]
        ), Budget()

    j, budget, notes = justify(_adv(), REASONS, "needs_human", fake)
    assert "template" in j.text
    assert notes[-1].startswith("fell back")


def test_model_that_raises_is_handled():
    def fake(adv, evidence, decision):
        raise ValueError("boom")

    j, _, notes = justify(_adv(), REASONS, "needs_human", fake)
    assert "template" in j.text and len(notes) == 3


def test_usage_cost_pricing():
    b = usage_cost("gpt-4o-mini", {"input_tokens": 1_000_000, "output_tokens": 0})
    assert b.usd_used == 0.15 and b.tokens_used == 1_000_000
    assert usage_cost("unknown-model", {"input_tokens": 1_000_000}).usd_used == 2.50
    assert usage_cost("gpt-4o", None).tokens_used == 0
