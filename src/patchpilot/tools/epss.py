"""EPSS lookup (FIRST.org) with recorded/live modes.

Live: GET /epss?cve=A,B,C in one call (the API accepts comma lists). Recorded: one fixture per CVE
under fixtures/epss/<CVE>.json. Production replaces the live call with the daily CSV loaded into
Postgres (DESIGN.md §6); the interface here is the same either way.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from patchpilot.config import get_settings
from patchpilot.guardrails.contracts import contract
from patchpilot.recorded.store import MissingFixture, RecordedStore


class EpssInput(BaseModel):
    cve_ids: list[str]


class EpssScore(BaseModel):
    cve: str
    epss: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    date: str


class EpssOutput(BaseModel):
    scores: dict[str, EpssScore] = Field(default_factory=dict)
    missing: list[str] = Field(default_factory=list)
    fetched_at: datetime


def _live_lookup(cves: list[str]) -> dict[str, dict[str, Any]]:
    s = get_settings()
    out: dict[str, dict[str, Any]] = {}
    for i in range(0, len(cves), 100):  # API limit per request
        chunk = cves[i : i + 100]
        with httpx.Client(timeout=s.http_timeout_seconds) as client:
            r = client.get(s.epss_base_url, params={"cve": ",".join(chunk)})
            r.raise_for_status()
        for row in r.json().get("data", []):
            out[row["cve"]] = row
    return out


@contract(EpssInput, EpssOutput)
def lookup_epss(inp: EpssInput) -> EpssOutput:
    store = RecordedStore()
    cves = sorted({c for c in inp.cve_ids if c.upper().startswith("CVE-")})
    rows: dict[str, dict[str, Any]] = {}
    missing: list[str] = []

    if store.settings.mode == "live":
        rows = _live_lookup(cves)
        if store.settings.record:
            for cve, row in rows.items():
                store.write("epss", cve, row)
        missing = [c for c in cves if c not in rows]
    else:
        for cve in cves:
            try:
                rows[cve] = store.read("epss", cve)
            except MissingFixture:
                missing.append(cve)

    scores = {
        cve: EpssScore(
            cve=cve,
            epss=float(row["epss"]),
            percentile=float(row["percentile"]),
            date=str(row["date"]),
        )
        for cve, row in rows.items()
    }
    return EpssOutput(scores=scores, missing=missing, fetched_at=datetime.now(UTC))
