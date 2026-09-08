"""CVSS v3.x base-score calculator (FIRST specification, section 7.1).

OSV returns the vector string, not the numeric score, so we compute it. Deterministic, no network.
CVSS v4 vectors are not scored here (v3 is present on every advisory we care about); callers fall
back to the database severity label when no v3 vector exists.
"""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(.+)$")


def _roundup(x: float) -> float:
    """CVSS 3.1 'Roundup': smallest number, to one decimal, >= x (with float-safety)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    m = _VECTOR_RE.match(vector.strip())
    if not m:
        return None
    parts = dict(p.split(":", 1) for p in m.group(1).split("/") if ":" in p)
    try:
        scope_changed = parts["S"] == "C"
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        exploitability = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * pr * _UI[parts["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_label_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MODERATE"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
