"""OSV.dev client with recorded/live modes.

Live mode: one batched POST /v1/querybatch for all (package, version) pairs, then GET /v1/vulns/{id}
for each advisory (cached per id). Recorded mode: fixtures/osv/query/<pkg>==<ver>.json holds the id
list, fixtures/osv/vulns/<ID>.json holds the record. The parsing below is the same in both modes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from patchpilot.config import get_settings
from patchpilot.graph.state import AdvisoryState, Dependency, UntrustedText
from patchpilot.guardrails.contracts import contract
from patchpilot.recorded.store import RecordedStore
from patchpilot.tools.cvss import cvss3_base_score


class OsvInput(BaseModel):
    dependencies: list[Dependency]
    symbol_overlay: dict[str, list[str]] = Field(
        default_factory=dict,
        description="advisory_id -> vulnerable symbols (curated; OSV rarely names them for PyPI)",
    )


class OsvOutput(BaseModel):
    advisories: list[AdvisoryState] = Field(default_factory=list)
    fetched_at: datetime
    lookups: int = 0


def _dep_key(d: Dependency) -> str:
    return f"{d.name}=={d.version}"


def _live_query_batch(deps: list[Dependency]) -> list[list[str]]:
    s = get_settings()
    body = {
        "queries": [
            {"package": {"name": d.name, "ecosystem": "PyPI"}, "version": d.version} for d in deps
        ]
    }
    with httpx.Client(timeout=s.http_timeout_seconds) as client:
        r = client.post(f"{s.osv_base_url}/querybatch", json=body)
        r.raise_for_status()
        results = r.json().get("results", [])
    return [[v["id"] for v in res.get("vulns", [])] for res in results]


def _live_vuln(vuln_id: str) -> dict[str, Any]:
    s = get_settings()
    with httpx.Client(timeout=s.http_timeout_seconds) as client:
        r = client.get(f"{s.osv_base_url}/vulns/{vuln_id}")
        r.raise_for_status()
        return r.json()


def _parse_version(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _affected_ranges_for(record: dict[str, Any], package: str) -> list[dict[str, Any]]:
    out = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if (
            pkg.get("ecosystem") == "PyPI"
            and pkg.get("name", "").lower().replace("_", "-") == package
        ):
            out.extend(aff.get("ranges", []))
    return out


def _fixed_versions(ranges: list[dict[str, Any]]) -> list[str]:
    fixed = []
    for rng in ranges:
        for ev in rng.get("events", []):
            if "fixed" in ev:
                fixed.append(ev["fixed"])
    return fixed


def _min_fixed_above(installed: str, fixed: list[str]) -> str | None:
    """Smallest fixed version greater than the installed one (the minimal safe bump)."""
    inst = _parse_version(installed)
    candidates = [v for v in (_parse_version(f) for f in fixed) if v is not None]
    if inst is not None:
        candidates = [v for v in candidates if v > inst]
    return str(min(candidates)) if candidates else None


def _severity(record: dict[str, Any]) -> tuple[str | None, float | None, str | None]:
    vector = None
    for sev in record.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            vector = sev.get("score")
            break
    score = cvss3_base_score(vector) if vector else None
    label = record.get("database_specific", {}).get("severity")
    return vector, score, label


def parse_osv_record(
    record: dict[str, Any], dep: Dependency, symbols: list[str] | None = None
) -> AdvisoryState:
    ranges = _affected_ranges_for(record, dep.name)
    fixed = _fixed_versions(ranges)
    vector, score, label = _severity(record)
    return AdvisoryState(
        advisory_id=record["id"],
        aliases=list(record.get("aliases", [])),
        package=dep.name,
        installed_version=dep.version,
        is_dev=dep.is_dev,
        fixed_versions=fixed,
        min_fixed_version=_min_fixed_above(dep.version, fixed),
        cvss_vector=vector,
        cvss=score,
        severity_label=label,
        vulnerable_symbols=list(symbols or []),
        untrusted_text=UntrustedText(
            advisory_summary=record.get("summary", "") or "",
            advisory_details=(record.get("details", "") or "")[:4000],
        ),
    )


@contract(OsvInput, OsvOutput)
def lookup_advisories(inp: OsvInput) -> OsvOutput:
    store = RecordedStore()
    deps = inp.dependencies
    lookups = 0

    # 1) ids per dependency
    if store.settings.mode == "live":
        id_lists = _live_query_batch(deps)
        lookups += 1
        if store.settings.record:
            for d, ids in zip(deps, id_lists, strict=True):
                store.write("osv/query", _dep_key(d), {"ids": ids})
    else:
        id_lists = [store.read("osv/query", _dep_key(d))["ids"] for d in deps]

    # 2) full records (cached per id within this call)
    advisories: list[AdvisoryState] = []
    cache: dict[str, dict[str, Any]] = {}
    for d, ids in zip(deps, id_lists, strict=True):
        for vid in ids:
            if vid not in cache:
                cache[vid] = store.fetch("osv/vulns", vid, lambda vid=vid: _live_vuln(vid))
                lookups += 1
            advisories.append(parse_osv_record(cache[vid], d, inp.symbol_overlay.get(vid)))

    return OsvOutput(advisories=advisories, fetched_at=datetime.now(UTC), lookups=lookups)
