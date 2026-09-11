"""Golden cases: what one is, and how to run it.

A golden case is a repository plus one advisory plus the decision a human ratified. Running it
replays the deterministic pipeline — `reachability -> risk_policy -> plan_remediation` — and reads
off the decision, the tier and the gate triggers. That stops short of `human_gate` on purpose: the
decision is already fixed by then (ADR-0002), so the eval never interrupts, never asks for a
verdict and never touches GitHub.

Two kinds of case:

* `fixture`   — an advisory from `fixtures/patchpilot-demo-app`, resolved through the real recorded
                OSV/EPSS/PyPI/changelog/sandbox data. These are the end-to-end cases.
* `synthetic` — a tiny repo written to a temp directory plus an inline advisory, targeting one rule
                in `policy/rules.py`. Recorded data for the planner can be supplied inline so a case
                can reach `auto_fix` without needing the demo app.

Everything runs in recorded mode with no network, so a golden case is reproducible forever.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from patchpilot.graph.nodes.ingest import ingest
from patchpilot.graph.nodes.justify import make_justify_node
from patchpilot.graph.nodes.plan_remediation import make_plan_remediation_node
from patchpilot.graph.nodes.reachability import reachability
from patchpilot.graph.nodes.risk_policy import risk_policy
from patchpilot.graph.state import AdvisoryState, Budget, RepoRef
from patchpilot.llm.justify import EvidenceItem, build_evidence
from patchpilot.recorded.store import RecordedStore

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
REPO_ROOT = Path(__file__).resolve().parent.parent


class Expectation(BaseModel):
    """What a reviewer ratified. `decision` is the blocking one; the others are checked when set."""

    decision: Literal["auto_fix", "needs_human", "accept_risk", "not_applicable", "halted"]
    tier: Literal["critical", "high", "medium", "low"] | None = None
    triggers: list[str] | None = Field(
        default=None, description="Set equality when given; omit to not assert on triggers"
    )


class GoldenCase(BaseModel):
    id: str
    description: str
    rationale: str = Field(description="Why a human decided this; read by whoever reviews a flip")
    rule: str = Field(default="", description="The policy rule this case pins, for coverage")
    source: Literal["fixture", "synthetic"]
    expect: Expectation

    # fixture cases
    repo: str | None = None
    advisory_id: str | None = None

    # synthetic cases
    files: dict[str, str] = Field(default_factory=dict)
    advisory: dict[str, Any] | None = None
    recorded: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Inline recorded data as {namespace: {key: payload}}. Namespaces can contain "
        "a slash ('pypi/project'), so they are given separately from the key rather than joined.",
    )

    @model_validator(mode="after")
    def _shape_matches_source(self) -> GoldenCase:
        if self.source == "fixture" and not (self.repo and self.advisory_id):
            raise ValueError("a fixture case needs `repo` and `advisory_id`")
        if self.source == "synthetic" and not (self.files and self.advisory):
            raise ValueError("a synthetic case needs `files` and `advisory`")
        return self


class CaseResult(BaseModel):
    """What the pipeline actually produced for one case."""

    case_id: str
    decision: str | None = None
    tier: str | None = None
    triggers: list[str] = Field(default_factory=list)
    justification: str | None = None
    cited_evidence: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    tokens: int = 0
    usd: float = 0.0
    seconds: float = 0.0
    error: str | None = None


def load_cases(directory: Path = GOLDEN_DIR) -> list[GoldenCase]:
    """Every case in the golden directory, sorted by id so runs are comparable."""
    cases: list[GoldenCase] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in payload.get("cases", []):
            case = GoldenCase.model_validate(raw)
            if case.id in seen:
                raise ValueError(f"duplicate golden case id {case.id!r} in {path.name}")
            seen.add(case.id)
            cases.append(case)
    return sorted(cases, key=lambda c: c.id)


# --------------------------------------------------------------------------------------------
# Materialising a case
# --------------------------------------------------------------------------------------------


_INGEST_CACHE: dict[str, dict[str, Any]] = {}


def _fixture_advisory(repo: str, advisory_id: str) -> tuple[AdvisoryState, list, RepoRef]:
    """Resolve one advisory out of a real repo, running ingest once per repo and caching it.

    Keyed on the fixtures directory as well as the repo: the same repository read against different
    recorded data is a different question, and answering it from cache would be wrong.
    """
    from patchpilot.config import get_settings

    path = (REPO_ROOT / repo).resolve() if not Path(repo).is_absolute() else Path(repo)
    key = f"{get_settings().fixtures_dir}|{path}"
    if key not in _INGEST_CACHE:
        _INGEST_CACHE[key] = ingest({"repo": RepoRef(path=str(path))})
    state = _INGEST_CACHE[key]
    for advisory in state.get("advisories", []):
        if advisory.advisory_id == advisory_id:
            return (
                advisory.model_copy(deep=True),
                list(state.get("dependencies") or []),
                RepoRef(path=str(path)),
            )
    raise LookupError(f"{advisory_id} is not among the advisories ingest found in {repo}")


def _synthetic_repo(case: GoldenCase, workdir: Path) -> tuple[AdvisoryState, list, RepoRef]:
    from patchpilot.tools.lockfile import LockfileInput, parse_lockfiles

    root = workdir / case.id
    for relative, content in case.files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    advisory = AdvisoryState.model_validate(case.advisory)
    # Mirror ingest: untrusted advisory text goes through the injection classifier on the way in.
    # Without this an adversarial case would be testing the policy's handling of a flag the case
    # set by hand, rather than whether the classifier raises it at all.
    if not advisory.injection_flag.flagged:
        from patchpilot.guardrails.injection import classify

        advisory.injection_flag = classify(
            advisory.untrusted_text.advisory_summary, advisory.untrusted_text.advisory_details
        )
    dependencies = parse_lockfiles(LockfileInput(repo_path=str(root))).dependencies
    return advisory, dependencies, RepoRef(path=str(root))


def _point_at(fixtures_dir: Path) -> None:
    import os

    from patchpilot.config import get_settings

    os.environ["PATCHPILOT_FIXTURES_DIR"] = str(fixtures_dir)
    get_settings.cache_clear()


def prepare_workspace(workdir: Path) -> Path:
    """Copy the recorded fixtures into the workspace and point PatchPilot at the copy.

    Synthetic cases write their own inline fixtures, and those must never land in the repository's
    fixture tree — a golden case that silently edits the recorded data it is scored against would
    make the whole suite meaningless. Working on a copy removes the possibility.
    """
    import shutil

    from patchpilot.config import get_settings

    source = Path(get_settings().fixtures_dir)
    base = workdir / "fixtures-base"
    if source.is_dir() and not base.exists():
        shutil.copytree(source, base)
    base.mkdir(parents=True, exist_ok=True)
    _point_at(base)
    _INGEST_CACHE.clear()
    return base


def _case_fixtures(case: GoldenCase, workdir: Path) -> Path:
    """Give a case with inline data its own fixture tree, and point PatchPilot at it.

    Cases share key spaces: every synthetic `widget` case wants `widget/1.0.0..1.0.1`, so writing
    inline data into one shared directory lets one case decide another's outcome. That is not a
    tidiness problem — an adversarial case's poisoned changelog silently became the changelog for
    every other case using the same version range, and eight of them flipped.
    """
    import shutil

    base = workdir / "fixtures-base"
    if not case.recorded:
        _point_at(base)
        return base

    private = workdir / "fx" / case.id
    if not private.exists():
        shutil.copytree(base, private)
    _point_at(private)

    store = RecordedStore()
    for namespace, entries in case.recorded.items():
        for key, payload in entries.items():
            store.write(namespace, key, payload)
    return private


def run_case(
    case: GoldenCase,
    workdir: Path,
    justifier=None,
    summariser=None,
) -> CaseResult:
    """Replay the deterministic pipeline for one case. Never interrupts, never writes to GitHub."""
    started = time.perf_counter()
    try:
        _case_fixtures(case, workdir)
        if case.source == "fixture":
            advisory, dependencies, repo = _fixture_advisory(
                case.repo or "", case.advisory_id or ""
            )
        else:
            advisory, dependencies, repo = _synthetic_repo(case, workdir)

        branch: dict[str, Any] = {
            "scan_id": f"eval:{case.id}",
            "repo": repo,
            "advisory": advisory,
            "dependencies": dependencies,
            "budget_fraction": 0.0,
        }
        branch.update(reachability(branch))
        branch.update(risk_policy(branch))
        branch.update(make_plan_remediation_node(summariser)(branch))

        budget: Budget = branch.get("budget") or Budget()
        adv: AdvisoryState = branch["advisory"]

        # justify runs last and only matters for faithfulness; it cannot move the decision.
        justified = make_justify_node(justifier)({**branch, "advisory": adv})
        adv = justified["advisory"]
        justify_budget: Budget = justified.get("budget") or Budget()

        return CaseResult(
            case_id=case.id,
            decision=adv.decision,
            tier=adv.risk.tier if adv.risk else None,
            triggers=list(adv.gate_triggers or (adv.risk.triggers if adv.risk else [])),
            justification=adv.justification,
            cited_evidence=list(adv.justification_evidence),
            evidence=build_evidence(adv, adv.policy_reasons),
            tokens=budget.tokens_used + justify_budget.tokens_used,
            usd=budget.usd_used + justify_budget.usd_used,
            seconds=time.perf_counter() - started,
        )
    except Exception as e:  # a case that explodes is a failure, not a crashed run
        return CaseResult(
            case_id=case.id,
            error=f"{e.__class__.__name__}: {e}",
            seconds=time.perf_counter() - started,
        )
