"""Scan anything PatchPilot is about to publish for credentials.

A PR body carries an evidence bundle assembled from advisory text, changelog text, file paths and
test output. A diff carries whatever was in the file. Neither is a place a token should appear, and
GitHub is a one-way door: once a secret is pushed, rotating it is the only remedy.

So this runs immediately before any write, over both the diff and the PR body. A hit halts the
branch (rule 3) rather than redacting and continuing — a redaction that misses one occurrence is
worse than not writing at all, and a human can look at what tripped it.

Findings never contain the secret. They carry a masked fragment, enough to locate it in the file
and no more, because findings end up in `halt_reason`, in the ledger, and in logs.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from pydantic import BaseModel, Field


class SecretsFound(RuntimeError):
    """Something that looks like a credential was found in content bound for GitHub."""

    def __init__(self, where: str, findings: list[SecretFinding]) -> None:
        self.where = where
        self.findings = findings
        summary = ", ".join(f"{f.kind} at line {f.line}" for f in findings)
        super().__init__(f"secret scan blocked the write to {where}: {summary}")


class SecretFinding(BaseModel):
    kind: str = Field(description="What the pattern recognised, e.g. 'github-pat'")
    line: int = Field(description="1-indexed line number within the scanned text")
    masked: str = Field(description="A masked fragment; never the credential itself")


# Ordered most specific first, so a GitHub PAT is reported as such and not as generic entropy.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("langsmith-key", re.compile(r"\blsv2_(?:pt|sk)_[A-Za-z0-9]{16,}")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("postgres-url", re.compile(r"\bpostgres(?:ql)?://[^\s:/@]+:[^\s:/@]+@")),
    (
        "assigned-credential",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*"
            r"[\"']?([A-Za-z0-9_\-+/]{16,})[\"']?"
        ),
    ),
)

# Words that make a long random-looking string obviously not a credential.
_PLACEHOLDERS = re.compile(
    r"(?i)(example|placeholder|redacted|your[_-]?key|xxxx|<[^>]+>|\bnone\b|\bnull\b|changeme|"
    r"dummy|sample|test[_-]?key|fake|\.\.\.)"
)


def _mask(value: str) -> str:
    """Show enough to find it, never enough to use it."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * 8}{value[-2:]}"


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def scan_text(text: str) -> list[SecretFinding]:
    """Every credential-shaped thing in `text`, deduplicated by (kind, line)."""
    findings: list[SecretFinding] = []
    seen: set[tuple[str, int]] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1) if match.groups() else match.group(0)
                if _PLACEHOLDERS.search(value):
                    continue
                # A generic `token = ...` assignment needs to look random to count; real prose
                # like `api_key: see the documentation for how to obtain one` must not trip it.
                if kind == "assigned-credential" and _shannon_entropy(value) < 3.0:
                    continue
                key = (kind, line_number)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(SecretFinding(kind=kind, line=line_number, masked=_mask(value)))
    return findings


def assert_clean(text: str, where: str) -> None:
    """Raise unless `text` is safe to publish. Called before every GitHub write."""
    findings = scan_text(text)
    if findings:
        raise SecretsFound(where, findings)


def assert_all_clean(documents: Iterable[tuple[str, str]]) -> None:
    """`documents` is (where, text). Scans everything and reports all of it, not just the first."""
    problems: list[SecretFinding] = []
    wheres: list[str] = []
    for where, text in documents:
        found = scan_text(text)
        if found:
            problems.extend(found)
            wheres.append(where)
    if problems:
        raise SecretsFound(" and ".join(wheres), problems)
