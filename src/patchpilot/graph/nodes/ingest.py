"""ingest: lockfiles -> advisories (OSV) -> EPSS join.

Only node that talks to the outside world (in live mode). Everything it produces is typed; the
untrusted advisory text is kept in `AdvisoryState.untrusted_text` and never used as instructions.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from patchpilot.config import PACKAGE_ROOT, get_settings
from patchpilot.graph.state import Budget, DataFreshness, ScanState
from patchpilot.guardrails.contracts import ContractViolation
from patchpilot.tools.epss import EpssInput, lookup_epss
from patchpilot.tools.lockfile import LockfileInput, parse_lockfiles
from patchpilot.tools.osv import OsvInput, lookup_advisories

SYMBOLS_FILE = PACKAGE_ROOT / "policy" / "symbols.yaml"


def load_symbol_overlay(path: Path = SYMBOLS_FILE) -> dict[str, list[str]]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): [str(s) for s in (v or [])] for k, v in data.items()}


def ingest(state: ScanState) -> dict:
    settings = get_settings()
    repo = state["repo"]
    errors: list[str] = []

    try:
        lock = parse_lockfiles(LockfileInput(repo_path=repo.path))
    except ContractViolation as e:
        return {"errors": [f"ingest/lockfile: {e}"], "dependencies": [], "advisories": []}
    if lock.unpinned:
        errors.append(
            f"ingest: {len(lock.unpinned)} unpinned requirement(s) skipped: {lock.unpinned[:5]}"
        )

    try:
        osv = lookup_advisories(
            OsvInput(dependencies=lock.dependencies, symbol_overlay=load_symbol_overlay())
        )
    except ContractViolation as e:
        return {
            "errors": errors + [f"ingest/osv: {e}"],
            "dependencies": lock.dependencies,
            "advisories": [],
        }

    cves = [a for adv in osv.advisories for a in adv.aliases if a.startswith("CVE-")]
    epss = lookup_epss(EpssInput(cve_ids=cves))
    for adv in osv.advisories:
        for alias in adv.aliases:
            if alias in epss.scores:
                adv.epss = epss.scores[alias].epss
                adv.epss_percentile = epss.scores[alias].percentile
                break
    if epss.missing:
        errors.append(f"ingest/epss: no score for {epss.missing}")

    return {
        "dependencies": lock.dependencies,
        "advisories": osv.advisories,
        "data_freshness": DataFreshness(
            osv_at=osv.fetched_at, epss_at=epss.fetched_at, mode=settings.mode
        ),
        "budget": Budget(tokens_cap=settings.budget_tokens, usd_cap=settings.budget_usd),
        "errors": errors,
    }
