import pytest
from pydantic import BaseModel

from patchpilot.graph.state import Dependency
from patchpilot.guardrails.contracts import ContractViolation, contract
from patchpilot.recorded.store import MissingFixture
from patchpilot.tools.cvss import cvss3_base_score, severity_label_from_score
from patchpilot.tools.epss import EpssInput, lookup_epss
from patchpilot.tools.osv import OsvInput, lookup_advisories, parse_osv_record


@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N", 2.2),
        ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", 6.7),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_known_scores(vector, score):
    assert cvss3_base_score(vector) == score


def test_cvss_rejects_garbage():
    assert cvss3_base_score("CVSS:4.0/AV:N") is None
    assert cvss3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert severity_label_from_score(7.5) == "HIGH"


def test_parse_osv_record_ranges_and_min_fix():
    record = {
        "id": "GHSA-test",
        "aliases": ["CVE-2024-1"],
        "summary": "s",
        "details": "d",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "urllib3"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.19"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.2.2"}]},
                ],
            }
        ],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"}],
        "database_specific": {"severity": "MODERATE"},
    }
    adv = parse_osv_record(
        record,
        Dependency(name="urllib3", version="2.2.1", source_file="r.txt"),
        ["urllib3.ProxyManager"],
    )
    assert adv.fixed_versions == ["1.26.19", "2.2.2"]
    assert adv.min_fixed_version == "2.2.2", (
        "minimal safe bump is the smallest fixed version above installed"
    )
    assert adv.cvss == 4.4 and adv.severity_label == "MODERATE"
    assert adv.vulnerable_symbols == ["urllib3.ProxyManager"]
    assert adv.untrusted_text.advisory_summary == "s"


def test_lookup_advisories_recorded_demo_set():
    deps = [
        Dependency(name="requests", version="2.31.0", source_file="requirements.txt"),
        Dependency(name="fastapi", version="0.100.0", source_file="requirements.txt"),
    ]
    out = lookup_advisories(
        OsvInput(dependencies=deps, symbol_overlay={"GHSA-9wx4-h78v-vm56": ["requests.Session"]})
    )
    ids = [a.advisory_id for a in out.advisories]
    assert ids == ["GHSA-9wx4-h78v-vm56", "GHSA-9hjg-9r4m-mvj7"]
    assert out.advisories[0].vulnerable_symbols == ["requests.Session"]
    assert out.advisories[1].vulnerable_symbols == []


def test_lookup_advisories_missing_fixture_is_loud():
    deps = [Dependency(name="nonexistent-pkg", version="0.0.1", source_file="r.txt")]
    with pytest.raises(MissingFixture):
        lookup_advisories(OsvInput(dependencies=deps))


def test_epss_recorded_and_missing():
    out = lookup_epss(EpssInput(cve_ids=["CVE-2024-24762", "CVE-1999-0000", "GHSA-not-a-cve"]))
    assert out.scores["CVE-2024-24762"].epss == pytest.approx(0.0151)
    assert out.missing == ["CVE-1999-0000"]


def test_contract_halts_on_bad_output():
    class In(BaseModel):
        x: int

    class Out(BaseModel):
        y: int

    @contract(In, Out)
    def bad(inp: In):
        return {"y": "not-an-int"}

    with pytest.raises(ContractViolation) as e:
        bad({"x": 1})
    assert e.value.side == "output"
    with pytest.raises(ContractViolation) as e:
        bad({"x": "nope"})
    assert e.value.side == "input"
