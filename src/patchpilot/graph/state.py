"""Graph state for PatchPilot.

Two levels:

* `ScanState`     — one per (repo, scan_id) thread. Holds the dependency list, the advisories, the
                    budget meter and data-freshness stamps.
* `AdvisoryState` — one per advisory. Each advisory is processed on its own `Send()` branch so a
                    human decision on one advisory never blocks the others.

Every field an LLM will ever write is a Pydantic model, validated before it enters state
(see guardrails/contracts.py). The reducers below make the fan-out/fan-in deterministic.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field
from typing_extensions import TypedDict

DecisionClass = Literal["auto_fix", "needs_human", "accept_risk", "not_applicable", "halted"]
RiskTier = Literal["critical", "high", "medium", "low"]
BumpKind = Literal["patch", "minor", "major"]
Verdict = Literal["approve", "reject", "modify"]


# --------------------------------------------------------------------------------------------
# Input side
# --------------------------------------------------------------------------------------------


class RepoRef(BaseModel):
    path: str = Field(description="Local checkout path the tools operate on")
    url: str | None = None
    default_branch: str = "main"
    commit_sha: str | None = None


class Dependency(BaseModel):
    name: str = Field(description="Normalised distribution name, e.g. 'python-multipart'")
    version: str
    is_dev: bool = False
    source_file: str


class DataFreshness(BaseModel):
    osv_at: datetime | None = None
    epss_at: datetime | None = None
    mode: Literal["recorded", "live"] = "recorded"


class Budget(BaseModel):
    tokens_used: int = 0
    usd_used: float = 0.0
    tokens_cap: int = 200_000
    usd_cap: float = 1.0

    @property
    def fraction_used(self) -> float:
        return max(
            self.tokens_used / self.tokens_cap if self.tokens_cap else 0.0,
            self.usd_used / self.usd_cap if self.usd_cap else 0.0,
        )


# --------------------------------------------------------------------------------------------
# Per-advisory
# --------------------------------------------------------------------------------------------


class UntrustedText(BaseModel):
    """Text from outside (advisory bodies, changelogs). Never placed in a system prompt."""

    advisory_summary: str = ""
    advisory_details: str = ""
    changelog_excerpt: str = ""


class InjectionFlag(BaseModel):
    flagged: bool = False
    reason: str = ""


class CallSite(BaseModel):
    file: str
    line: int
    symbol: str
    snippet: str = ""


class Reachability(BaseModel):
    imported: bool = False
    import_sites: list[str] = Field(
        default_factory=list, description="file:line of import statements"
    )
    symbol_called: bool | None = Field(
        default=None, description="None when the advisory names no symbols to search for"
    )
    call_sites: list[CallSite] = Field(default_factory=list)
    is_runtime_dep: bool = True
    imported_from_test_only: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    notes: list[str] = Field(default_factory=list)


class Risk(BaseModel):
    score: float = Field(ge=0.0, le=10.0)
    tier: RiskTier
    triggers: list[str] = Field(default_factory=list, description="Reasons that force a human gate")
    package_tier: str = "default"


class ChangelogChunk(BaseModel):
    chunk_id: str
    version: str
    text: str


class Plan(BaseModel):
    target_version: str
    bump_kind: BumpKind
    changelog_hits: list[ChangelogChunk] = Field(default_factory=list)
    breaking_changes: list[str] = Field(default_factory=list)


class SandboxResult(BaseModel):
    supported: bool
    reason: str = ""
    baseline_failed: list[str] = Field(default_factory=list)
    after_bump_failed: list[str] = Field(default_factory=list)
    newly_failing: list[str] = Field(default_factory=list)
    flaky_rerun: list[str] = Field(default_factory=list)


class HumanDecision(BaseModel):
    reviewer: str
    verdict: Verdict
    note: str = ""
    modified_target_version: str | None = None
    decided_at: datetime


class PullRequestRef(BaseModel):
    url: str
    branch: str
    number: int


class AdvisoryState(BaseModel):
    """Everything known about one advisory against one repo."""

    advisory_id: str = Field(description="GHSA-… / PYSEC-… id as returned by OSV")
    aliases: list[str] = Field(default_factory=list)
    package: str
    installed_version: str
    is_dev: bool = False
    fixed_versions: list[str] = Field(default_factory=list)
    min_fixed_version: str | None = None
    cvss_vector: str | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    severity_label: str | None = Field(
        default=None, description="Database severity label, e.g. HIGH"
    )
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    vulnerable_symbols: list[str] = Field(
        default_factory=list,
        description="Dotted symbols whose use makes the vulnerable path reachable; may be empty",
    )
    untrusted_text: UntrustedText = Field(default_factory=UntrustedText)
    injection_flag: InjectionFlag = Field(default_factory=InjectionFlag)

    reachability: Reachability | None = None
    risk: Risk | None = None
    bump_kind: BumpKind | None = None
    policy_reasons: list[str] = Field(default_factory=list)
    justification: str | None = None
    justification_evidence: list[str] = Field(default_factory=list)
    justification_notes: list[str] = Field(default_factory=list)
    plan: Plan | None = None
    sandbox: SandboxResult | None = None
    decision: DecisionClass | None = None
    human: HumanDecision | None = None
    pr: PullRequestRef | None = None
    trace_url: str | None = None
    halt_reason: str | None = None


# --------------------------------------------------------------------------------------------
# Reducers
# --------------------------------------------------------------------------------------------


def merge_advisories(left: list[AdvisoryState], right: list[AdvisoryState]) -> list[AdvisoryState]:
    """Fan-in reducer: merge by advisory_id, newer entry wins, original order preserved."""
    by_id: dict[str, AdvisoryState] = {a.advisory_id: a for a in left or []}
    order = [a.advisory_id for a in left or []]
    for a in right or []:
        if a.advisory_id not in by_id:
            order.append(a.advisory_id)
        by_id[a.advisory_id] = a
    return [by_id[i] for i in order]


def add_budget(left: Budget, right: Budget) -> Budget:
    if left is None:
        return right
    if right is None:
        return left
    return Budget(
        tokens_used=left.tokens_used + right.tokens_used,
        usd_used=left.usd_used + right.usd_used,
        tokens_cap=left.tokens_cap,
        usd_cap=left.usd_cap,
    )


# --------------------------------------------------------------------------------------------
# Graph-level state
# --------------------------------------------------------------------------------------------


class ScanSummary(BaseModel):
    counts: dict[str, int] = Field(default_factory=dict)
    total_advisories: int = 0


class ScanState(TypedDict, total=False):
    scan_id: str
    repo: RepoRef
    dependencies: list[Dependency]
    advisories: Annotated[list[AdvisoryState], merge_advisories]
    budget: Annotated[Budget, add_budget]
    data_freshness: DataFreshness
    summary: ScanSummary
    errors: Annotated[list[str], lambda a, b: (a or []) + (b or [])]


class AdvisoryBranch(TypedDict, total=False):
    """State of the per-advisory subgraph (one Send() branch per advisory).

    `advisory` is branch-local working state. The last node of the subgraph writes `advisories`
    and `budget`, which the parent graph merges through its reducers.
    """

    repo: RepoRef
    advisory: AdvisoryState
    budget_fraction: float
    advisories: Annotated[list[AdvisoryState], merge_advisories]
    budget: Annotated[Budget, add_budget]
