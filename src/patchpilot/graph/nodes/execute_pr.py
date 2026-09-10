"""execute_pr: turn an approved remediation into a pull request, and nothing more.

Reachable only two ways, both decided before this node runs:

* `decision == "auto_fix"` — the policy cleared it and the sandbox proved it
* `human.verdict == "approve"` — a named reviewer cleared it at the gate

The node re-checks that anyway. Routing is a claim about what should happen; this is the thing
that actually happens, and defence in depth means it does not take routing's word for it.

The content committed is the *same* content the sandbox tested, because both come from
`tools/sandbox.planned_edits`. That is what makes "the tests passed on this change" a statement
about the change being proposed rather than about a different one.

Anything a guardrail refuses — allowlist, secret scan, contract, budget — halts the branch with
`halt_reason` set (rule 3). A refused write is never a silently skipped write.
"""

from __future__ import annotations

import re

from patchpilot.graph.state import AdvisoryBranch, AdvisoryState, DataFreshness, PullRequestRef
from patchpilot.guardrails.allowlist import AllowlistViolation, branch_for
from patchpilot.guardrails.budget import BUDGET_EXHAUSTED_FRACTION
from patchpilot.guardrails.contracts import ContractViolation
from patchpilot.guardrails.secrets import SecretsFound
from patchpilot.llm.client import current_trace_url
from patchpilot.recorded.store import MissingFixture
from patchpilot.tools.github_pr import (
    CommitFileInput,
    CreateBranchInput,
    GitHubError,
    OpenPullRequestInput,
    commit_file,
    create_branch,
    open_pull_request,
)
from patchpilot.tools.sandbox import planned_edits

# Anchored, and dots are legal in a repository name (`owner/my.repo`, `owner/foo.js`). The old
# pattern excluded dots and was unanchored, so `owner/foo.js` silently became `owner/foo` — a
# different repository, which the token might well have access to.
_GITHUB_SLUG = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9][A-Za-z0-9._-]*)/"
    r"(?P<repo>[A-Za-z0-9][A-Za-z0-9._-]*?)"
    r"(?:\.git)?/?$",
    re.IGNORECASE,
)


def github_slug(url: str | None) -> str | None:
    """`https://github.com/owner/repo.git` -> `owner/repo`. None when this is not a GitHub repo."""
    if not url:
        return None
    match = _GITHUB_SLUG.match(url.strip())
    return f"{match.group('owner')}/{match.group('repo')}" if match else None


def is_approved(adv: AdvisoryState) -> bool:
    """The only two states that may open a pull request."""
    if adv.decision == "auto_fix":
        return True
    return adv.human is not None and adv.human.verdict == "approve"


def render_pr_body(
    adv: AdvisoryState, freshness: DataFreshness | None = None, trace_url: str | None = None
) -> str:
    """The evidence bundle, as the reviewer on GitHub will read it.

    Everything here is already in state; nothing is recomputed and nothing is asserted that the
    scan did not establish. Untrusted advisory text is quoted, labelled, and never presented as
    PatchPilot's own words.
    """
    plan = adv.plan
    lines: list[str] = []

    if adv.decision == "auto_fix":
        opened_because = "Opened automatically: the policy cleared it and the sandbox agreed."
    else:
        who = adv.human.reviewer if adv.human else "a reviewer"
        note = f" — “{adv.human.note}”" if adv.human and adv.human.note else ""
        opened_because = f"Approved by **{who}** at PatchPilot's human gate{note}."

    lines.append(
        f"## {adv.package} {adv.installed_version} → {plan.target_version if plan else '?'}"
    )
    lines.append("")
    lines.append(opened_because)
    lines.append("")

    lines.append("### Advisory")
    lines.append("")
    lines.append(
        f"- **{adv.advisory_id}**" + (f" ({', '.join(adv.aliases)})" if adv.aliases else "")
    )
    if adv.cvss is not None:
        lines.append(f"- CVSS **{adv.cvss}** `{adv.cvss_vector or ''}`")
    elif adv.severity_label:
        lines.append(f"- Severity **{adv.severity_label}**")
    if adv.epss is not None:
        percentile = f" ({adv.epss_percentile:.0%} percentile)" if adv.epss_percentile else ""
        lines.append(f"- EPSS **{adv.epss:.4f}**{percentile}")
    if adv.risk:
        lines.append(
            f"- Policy score **{adv.risk.score}** → tier **{adv.risk.tier}** "
            f"(package tier `{adv.risk.package_tier}`)"
        )
    lines.append("")

    reach = adv.reachability
    if reach:
        lines.append("### Is it reachable here?")
        lines.append("")
        if reach.symbol_called:
            lines.append(f"Yes — confidence {reach.confidence:.2f}.")
            lines.append("")
            for site in reach.call_sites[:5]:
                lines.append(f"- `{site.file}:{site.line}` — `{site.symbol}`")
        elif reach.imported:
            lines.append(
                f"Imported, but no vulnerable symbol referenced (confidence "
                f"{reach.confidence:.2f})."
            )
        else:
            lines.append("The package is never imported by this repository.")
        lines.append("")

    if plan:
        lines.append("### The change")
        lines.append("")
        lines.append(
            f"- `{adv.package}` **{adv.installed_version} → {plan.target_version}** "
            f"({plan.bump_kind} bump)"
        )
        for conflict in plan.dependency_conflicts:
            lines.append(f"- ⚠️ {conflict}")
        if plan.breaking_changes:
            lines.append("")
            lines.append("**Breaking changes found in the release notes:**")
            lines.append("")
            for change in plan.breaking_changes:
                lines.append(f"- {change}")
            if plan.breaking_change_citations:
                lines.append("")
                lines.append(
                    f"<sub>cited from chunks: {', '.join(plan.breaking_change_citations)}</sub>"
                )
        lines.append("")

    box = adv.sandbox
    if box:
        lines.append("### Test evidence")
        lines.append("")
        if not box.supported:
            lines.append(f"⚠️ Not proven by the sandbox — {box.reason}")
        elif box.newly_failing:
            lines.append(f"❌ {len(box.newly_failing)} test(s) newly failing after the bump:")
            lines.append("")
            for test in box.newly_failing:
                lines.append(f"- `{test}`")
        else:
            lines.append(f"✅ No new test failures. ({box.reason})")
        if box.baseline_failed:
            lines.append("")
            lines.append(
                f"<sub>{len(box.baseline_failed)} test(s) were already failing before "
                f"the bump and are not attributed to it.</sub>"
            )
        if box.flaky_rerun:
            lines.append("")
            lines.append(
                f"<sub>{len(box.flaky_rerun)} test(s) passed on rerun, treated as flaky.</sub>"
            )
        lines.append("")

    if adv.justification:
        lines.append("### Why this decision")
        lines.append("")
        lines.append(adv.justification)
        if adv.justification_evidence:
            lines.append("")
            lines.append(f"<sub>cites: {', '.join(adv.justification_evidence)}</sub>")
        lines.append("")

    if adv.gate_triggers:
        lines.append(f"**Gate triggers:** {', '.join(f'`{t}`' for t in adv.gate_triggers)}")
        lines.append("")

    if adv.injection_flag.flagged:
        lines.append("### ⚠️ Untrusted text was flagged")
        lines.append("")
        lines.append(f"{adv.injection_flag.reason}")
        lines.append("")
        lines.append(
            "> The advisory or changelog text for this package contains what looks like "
            "an instruction aimed at an automated reader. It was treated as data only and "
            "could not affect the decision, which is computed deterministically."
        )
        lines.append("")

    lines.append("---")
    lines.append("")
    if freshness:
        stamps = []
        if freshness.osv_at:
            stamps.append(f"OSV {freshness.osv_at:%Y-%m-%d %H:%M UTC}")
        if freshness.epss_at:
            stamps.append(f"EPSS {freshness.epss_at:%Y-%m-%d %H:%M UTC}")
        stamps.append(f"mode `{freshness.mode}`")
        lines.append(f"<sub>Data freshness: {' · '.join(stamps)}</sub>")
    if trace_url:
        lines.append("")
        lines.append(f"<sub>[LangSmith trace]({trace_url})</sub>")
    lines.append("")
    lines.append(
        "<sub>Opened by [PatchPilot](https://github.com/varadnair30/patchpilot). "
        "PatchPilot cannot merge this PR, force-push, or edit CI configuration.</sub>"
    )
    return "\n".join(lines)


def pr_title(adv: AdvisoryState) -> str:
    target = adv.plan.target_version if adv.plan else "a fixed version"
    return f"Bump {adv.package} from {adv.installed_version} to {target} ({adv.advisory_id})"


def execute_pr(branch: AdvisoryBranch) -> dict:
    adv = branch["advisory"].model_copy(deep=True)

    def publish() -> dict:
        return {"advisory": adv, "advisories": [adv]}

    if adv.decision == "halted":
        return publish()

    # Routing should never send us anything else; check anyway.
    if not is_approved(adv):
        adv.pr_note = "no pull request: the change was not approved"
        return publish()
    if adv.plan is None or not adv.plan.target_version:
        adv.pr_note = "no pull request: there is no remediation plan to apply"
        return publish()
    if branch.get("budget_fraction", 0.0) >= BUDGET_EXHAUSTED_FRACTION:
        adv.decision = "halted"
        adv.halt_reason = "budget: run cap reached before the pull request could be opened"
        return publish()

    repo_ref = branch["repo"]
    slug = github_slug(repo_ref.url)
    if slug is None:
        # The demo target has no GitHub home until step 9. That is a configuration state, not a
        # failure, so the decision stands and the reason is recorded for the reviewer.
        adv.pr_note = (
            "no pull request: the scan target has no GitHub URL configured "
            "(RepoRef.url is unset), so there is nowhere to open one"
        )
        return publish()

    trace_url = current_trace_url()
    adv.trace_url = trace_url

    try:
        edits = planned_edits(repo_ref.path, adv.package, adv.plan.target_version)
        if not edits:
            adv.pr_note = (
                f"no pull request: {adv.package} is not pinned in any file PatchPilot can rewrite"
            )
            return publish()

        head = branch_for(adv.advisory_id)
        # Branch from the revision that was scanned, not from wherever the default branch has
        # moved to since. A human gate can be open for days, and the file content below is the
        # content of the local checkout at scan time: branching from a newer base would let this
        # PR silently revert whatever else changed in those files, and would make the test
        # evidence a claim about a base that is no longer the one being proposed.
        create_branch(
            CreateBranchInput(
                repo=slug,
                branch=head,
                base_branch=repo_ref.default_branch,
                base_sha=repo_ref.commit_sha,
            )
        )
        if not repo_ref.commit_sha:
            adv.pr_note = (
                "branched from the current default branch: the scan did not record a commit sha, "
                "so the base may have moved since the sandbox ran"
            )
        for path, content in sorted(edits.items()):
            commit_file(
                CommitFileInput(
                    repo=slug,
                    branch=head,
                    base_branch=repo_ref.default_branch,
                    path=path,
                    content=content,
                    message=f"{pr_title(adv)}\n\nSee the pull request body for the evidence.",
                )
            )
        opened = open_pull_request(
            OpenPullRequestInput(
                repo=slug,
                head=head,
                base=repo_ref.default_branch,
                title=pr_title(adv),
                body=render_pr_body(adv, branch.get("data_freshness"), trace_url),
            )
        )
        adv.pr = PullRequestRef(url=opened.url, branch=opened.branch, number=opened.number)
    except (
        AllowlistViolation,
        SecretsFound,
        ContractViolation,
        GitHubError,
        MissingFixture,
    ) as e:
        adv.decision = "halted"
        adv.halt_reason = f"execute_pr: {e}"

    return publish()
