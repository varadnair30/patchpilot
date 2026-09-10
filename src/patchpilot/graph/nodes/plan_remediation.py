"""plan_remediation: what would we actually change, and does it break anything?

Three tools and one bounded LLM task, in order:

1. `pypi_resolver` — the minimal safe version, and whether the repo's other pins allow it.
2. `changelog_rag` — the release-note paragraphs that mention the symbols this repo imports.
3. `llm/changelog` — a breaking-change summary of *those paragraphs*, citing their ids.
4. `sandbox`      — the test suite before the bump and after it; `newly_failing` is the difference.

Then `policy.rules.decide_after_plan` turns that evidence into the terminal decision. The node
itself decides nothing (rule 1): it gathers, the policy rules.

Every tool failure degrades the plan instead of propagating: a package with no recorded PyPI data,
no changelog, or no runnable test suite ends up with less evidence, which the policy reads as
"a human should look at this". Only a contract violation halts the branch (rule 3).
"""

from __future__ import annotations

import httpx

from patchpilot.graph.state import AdvisoryBranch, Budget, Plan, SandboxResult
from patchpilot.guardrails.contracts import ContractViolation
from patchpilot.guardrails.injection import classify
from patchpilot.llm.changelog import BreakingChanges, SummariserFn, summarise_breaking_changes
from patchpilot.policy.rules import decide_after_plan
from patchpilot.recorded.store import MissingFixture
from patchpilot.tools.changelog_rag import ChangelogInput, ChangelogOutput, retrieve_changelog
from patchpilot.tools.pypi_resolver import ResolverInput, resolve_target_version
from patchpilot.tools.sandbox import SandboxInput, SandboxOutput, run_sandbox

TERMINAL = ("halted", "not_applicable", "accept_risk")

# An external service being slow, rate-limited or down is a fact about today, not about this
# advisory. It must cost the plan its evidence — which the policy reads as "a human should look at
# this" — and never take the branch, or the other ten branches in the scan, down with it.
# `ContractViolation` is deliberately NOT in here: bad data is a halt (rule 3).
UNAVAILABLE = (MissingFixture, httpx.HTTPError, TimeoutError, ConnectionError)


def retrieval_symbols(adv) -> list[str]:
    """What to retrieve the changelog against: the advisory's symbols and the ones we saw called."""
    symbols = list(adv.vulnerable_symbols)
    if adv.reachability:
        symbols += [c.symbol for c in adv.reachability.call_sites]
    seen: list[str] = []
    for symbol in symbols:
        if symbol and symbol not in seen:
            seen.append(symbol)
    return seen


def make_plan_remediation_node(summariser: SummariserFn | None):
    def plan_remediation(branch: AdvisoryBranch) -> dict:
        adv = branch["advisory"].model_copy(deep=True)
        if adv.decision in TERMINAL:
            return {"advisory": adv}

        notes: list[str] = []
        budget = Budget()

        try:
            resolved = resolve_target_version(
                ResolverInput(
                    package=adv.package,
                    installed_version=adv.installed_version,
                    min_fixed_version=adv.min_fixed_version,
                    dependencies=list(branch.get("dependencies") or []),
                )
            )
        except ContractViolation as e:
            adv.decision = "halted"
            adv.halt_reason = f"plan_remediation/resolver: {e}"
            return {"advisory": adv}
        except UNAVAILABLE as e:
            resolved = None
            notes.append(f"resolver unavailable: {_describe(e)}")

        if resolved is None or not resolved.target_version:
            adv.plan = None
            adv.policy_reasons = adv.policy_reasons + [
                f"no target version: {resolved.reason if resolved else notes[-1]}"
            ]
            return _finish(adv, branch, budget, notes)

        target = resolved.target_version
        notes += resolved.notes

        try:
            changelog = retrieve_changelog(
                ChangelogInput(
                    package=adv.package,
                    from_version=adv.installed_version,
                    to_version=target,
                    symbols=retrieval_symbols(adv),
                )
            )
        except ContractViolation as e:
            adv.decision = "halted"
            adv.halt_reason = f"plan_remediation/changelog: {e}"
            return {"advisory": adv}
        except UNAVAILABLE as e:
            changelog = ChangelogOutput(package=adv.package)
            notes.append(f"changelog unavailable: {_describe(e)}")
        notes += changelog.notes

        # Release notes are untrusted too (rule 4), and they are about to be handed to a model.
        # ingest only saw the advisory body, so classify the retrieved chunks and fold the result
        # in before the policy decides — an injected changelog has to reach a human.
        changelog_flag = classify(*[chunk.text for chunk in changelog.chunks])
        if changelog_flag.flagged and not adv.injection_flag.flagged:
            adv.injection_flag = changelog_flag
            notes.append(f"changelog flagged: {changelog_flag.reason}")
        elif changelog_flag.flagged:
            notes.append(f"changelog also flagged: {changelog_flag.reason}")

        try:
            summary, delta, summary_notes = summarise_breaking_changes(
                adv.package, adv.installed_version, target, changelog.chunks, summariser
            )
        except Exception as e:  # noqa: BLE001 - see below
            # Deliberately broad. The breaking-change summary is explanatory: nothing routes on it,
            # and the model client can fail in as many ways as there are SDKs. Losing the summary
            # must never lose the plan.
            summary, delta, summary_notes = (
                BreakingChanges(),
                Budget(),
                [f"breaking-change summary unavailable: {_describe(e)}"],
            )
        budget = delta
        notes += summary_notes

        try:
            sandbox = run_sandbox(
                SandboxInput(
                    repo_path=branch["repo"].path,
                    package=adv.package,
                    installed_version=adv.installed_version,
                    target_version=target,
                )
            )
        except ContractViolation as e:
            adv.decision = "halted"
            adv.halt_reason = f"plan_remediation/sandbox: {e}"
            return {"advisory": adv}
        except UNAVAILABLE as e:
            sandbox = SandboxOutput(
                result=SandboxResult(
                    supported=False, reason=f"sandbox unavailable: {_describe(e)}"
                ),
                mode="skipped",
            )
            notes.append(sandbox.result.reason)
        notes += sandbox.notes

        adv.plan = Plan(
            target_version=target,
            bump_kind=resolved.bump_kind or "major",
            changelog_hits=changelog.chunks,
            breaking_changes=summary.items,
            breaking_change_citations=summary.chunk_ids,
            dependency_conflicts=resolved.conflicts,
            notes=notes,
        )
        adv.bump_kind = adv.plan.bump_kind
        adv.sandbox = sandbox.result
        return _finish(adv, branch, budget, notes)

    return plan_remediation


def _describe(exc: BaseException) -> str:
    """Short, safe rendering of a failure for the plan notes and the reviewer's screen."""
    return f"{exc.__class__.__name__}: {str(exc)[:200]}"


def _finish(adv, branch: AdvisoryBranch, budget: Budget, notes: list[str]) -> dict:
    """Hand the evidence to the deterministic policy and record what it decided."""
    outcome = decide_after_plan(adv, budget_fraction=branch.get("budget_fraction", 0.0))
    adv.decision = outcome.decision  # type: ignore[assignment]
    adv.gate_triggers = outcome.triggers
    adv.policy_reasons = adv.policy_reasons + outcome.reasons
    if adv.plan is not None and notes:
        adv.plan.notes = notes
    return {"advisory": adv, "budget": budget}
