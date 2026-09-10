"""execute_pr: the node, the PR body, and the preconditions it refuses to skip."""

from datetime import UTC, datetime

import pytest

from patchpilot.graph.nodes.execute_pr import (
    execute_pr,
    github_slug,
    is_approved,
    pr_title,
    render_pr_body,
)
from patchpilot.graph.state import (
    AdvisoryState,
    CallSite,
    DataFreshness,
    HumanDecision,
    InjectionFlag,
    Plan,
    Reachability,
    RepoRef,
    Risk,
    SandboxResult,
)
from patchpilot.recorded.store import RecordedStore

REPO_URL = "https://github.com/varadnair30/patchpilot-demo-app"
SLUG = "varadnair30/patchpilot-demo-app"
BRANCH = "patchpilot/GHSA-75c5-xw7c-p5pm"


def make_advisory(**overrides) -> AdvisoryState:
    base = dict(
        advisory_id="GHSA-75c5-xw7c-p5pm",
        package="pyjwt",
        installed_version="2.10.0",
        min_fixed_version="2.10.1",
        cvss=2.2,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        epss=0.008,
        epss_percentile=0.42,
        reachability=Reachability(
            imported=True,
            symbol_called=True,
            call_sites=[CallSite(file="app/auth.py", line=21, symbol="jwt.decode")],
            confidence=0.85,
        ),
        risk=Risk(score=1.6, tier="low", triggers=["sensitive_tier:auth"], package_tier="auth"),
        gate_triggers=["sensitive_tier:auth"],
        plan=Plan(target_version="2.10.1", bump_kind="patch"),
        sandbox=SandboxResult(supported=True, reason="pip install then pytest"),
        decision="needs_human",
        justification="Reachable auth advisory; the policy forces a human.",
        justification_evidence=["advisory", "policy"],
        human=HumanDecision(
            reviewer="alice",
            verdict="approve",
            note="evidence checked",
            decided_at=datetime(2026, 9, 9, tzinfo=UTC),
        ),
    )
    base.update(overrides)
    return AdvisoryState(**base)


@pytest.fixture
def demo_branch(monkeypatch, tmp_path, tmp_repo):
    """A repo to read pins from, plus recorded GitHub responses for the three writes."""
    monkeypatch.setenv("PATCHPILOT_FIXTURES_DIR", str(tmp_path / "fixtures"))
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    store = RecordedStore()
    store.write("github/branch", f"{SLUG}/{BRANCH}", {"sha": "abc123", "created": True})
    store.write("github/commit", f"{SLUG}/{BRANCH}/requirements.txt", {"commit_sha": "def456"})
    store.write(
        "github/pr", f"{SLUG}/{BRANCH}", {"number": 7, "url": f"https://github.com/{SLUG}/pull/7"}
    )

    repo = tmp_repo({"requirements.txt": "pyjwt==2.10.0\nrequests==2.31.0\n"})

    def build(advisory=None, url=REPO_URL, budget_fraction=0.0):
        return {
            "scan_id": "s1",
            "repo": RepoRef(path=str(repo), url=url, default_branch="main"),
            "advisory": advisory or make_advisory(),
            "budget_fraction": budget_fraction,
            "data_freshness": DataFreshness(mode="recorded"),
        }

    yield build
    get_settings.cache_clear()


# ==================================================================== who may open a PR


def test_an_auto_fix_may_open_a_pull_request():
    assert is_approved(make_advisory(decision="auto_fix", human=None))


def test_an_approved_gate_decision_may_open_a_pull_request():
    assert is_approved(make_advisory())


@pytest.mark.parametrize("verdict", ["reject", "modify"])
def test_anything_other_than_approve_may_not(verdict):
    adv = make_advisory(
        human=HumanDecision(reviewer="bob", verdict=verdict, decided_at=datetime.now(UTC))
    )
    assert not is_approved(adv)


@pytest.mark.parametrize("decision", ["needs_human", "not_applicable", "accept_risk", "halted"])
def test_an_undecided_or_terminal_advisory_may_not(decision):
    assert not is_approved(make_advisory(decision=decision, human=None))


def test_the_node_refuses_even_if_routing_sends_it_something_unapproved(demo_branch):
    """Defence in depth: routing is a claim, this is the thing that happens."""
    out = execute_pr(demo_branch(make_advisory(decision="needs_human", human=None)))
    assert out["advisory"].pr is None
    assert "not approved" in out["advisory"].pr_note


# ==================================================================== the happy path


def test_an_approved_advisory_opens_a_pull_request(demo_branch):
    out = execute_pr(demo_branch())
    pr = out["advisory"].pr
    assert pr is not None
    assert (pr.number, pr.branch) == (7, BRANCH)
    assert pr.url.endswith("/pull/7")
    assert out["advisory"].halt_reason is None


def test_the_commit_content_is_the_content_the_sandbox_tested(demo_branch, monkeypatch):
    """Both come from planned_edits, so 'the tests passed on this' is about this change."""
    seen = {}
    import patchpilot.graph.nodes.execute_pr as node

    real = node.commit_file

    def spy(inp):
        seen["path"], seen["content"] = inp.path, inp.content
        return real(inp)

    monkeypatch.setattr(node, "commit_file", spy)
    execute_pr(demo_branch())
    assert seen["path"] == "requirements.txt"
    assert "pyjwt==2.10.1" in seen["content"]
    assert "requests==2.31.0" in seen["content"], "unrelated pins are untouched"


def test_the_repo_on_disk_is_never_modified(demo_branch):
    branch = demo_branch()
    before = (__import__("pathlib").Path(branch["repo"].path) / "requirements.txt").read_text(
        encoding="utf-8"
    )
    execute_pr(branch)
    after = (__import__("pathlib").Path(branch["repo"].path) / "requirements.txt").read_text(
        encoding="utf-8"
    )
    assert before == after == "pyjwt==2.10.0\nrequests==2.31.0\n"


# ==================================================================== when there is nowhere to go


def test_a_target_without_a_github_url_records_why_and_does_not_halt(demo_branch):
    """The demo app has no GitHub home until step 9; that is configuration, not failure."""
    out = execute_pr(demo_branch(url=None))
    adv = out["advisory"]
    assert adv.pr is None
    assert adv.decision == "needs_human", "the decision stands"
    assert adv.halt_reason is None
    assert "no GitHub URL" in adv.pr_note


def test_a_package_that_is_not_pinned_produces_a_note_not_a_pr(demo_branch):
    out = execute_pr(
        demo_branch(
            make_advisory(package="pillow", plan=Plan(target_version="10.3.0", bump_kind="minor"))
        )
    )
    assert out["advisory"].pr is None
    assert "not pinned" in out["advisory"].pr_note


def test_an_advisory_with_no_plan_opens_nothing(demo_branch):
    out = execute_pr(demo_branch(make_advisory(plan=None)))
    assert out["advisory"].pr is None
    assert "no remediation plan" in out["advisory"].pr_note


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/owner/repo", "owner/repo"),
        ("https://github.com/owner/repo.git", "owner/repo"),
        ("http://www.github.com/owner/repo/", "owner/repo"),
        ("git@github.com:owner/repo.git", None),
        ("https://gitlab.com/owner/repo", None),
        (None, None),
        ("", None),
    ],
)
def test_only_github_urls_are_recognised(url, expected):
    assert github_slug(url) == expected


# ==================================================================== guardrails halt the branch


def test_a_budget_cap_halts_before_any_write(demo_branch):
    out = execute_pr(demo_branch(budget_fraction=1.0))
    assert out["advisory"].decision == "halted"
    assert "budget" in out["advisory"].halt_reason
    assert out["advisory"].pr is None


def test_a_secret_in_the_diff_halts_the_branch(demo_branch, tmp_repo, monkeypatch):
    branch = demo_branch()
    import pathlib

    pathlib.Path(branch["repo"].path, "requirements.txt").write_text(
        "pyjwt==2.10.0\n# ghp_abcdefghijklmnopqrstuvwxyz0123456789\n", encoding="utf-8"
    )
    out = execute_pr(branch)
    assert out["advisory"].decision == "halted"
    assert "execute_pr" in out["advisory"].halt_reason
    assert out["advisory"].pr is None


def test_an_already_halted_branch_is_left_alone(demo_branch):
    out = execute_pr(demo_branch(make_advisory(decision="halted", halt_reason="earlier failure")))
    assert out["advisory"].halt_reason == "earlier failure"
    assert out["advisory"].pr is None


def test_the_branch_publishes_itself_to_the_parent(demo_branch):
    out = execute_pr(demo_branch())
    assert out["advisories"] == [out["advisory"]]


# ==================================================================== the PR body


def test_the_body_carries_the_whole_evidence_bundle():
    body = render_pr_body(
        make_advisory(),
        DataFreshness(osv_at=datetime(2026, 9, 8, 12, tzinfo=UTC), mode="recorded"),
        "https://smith.langchain.com/o/x/r/y",
    )
    assert "pyjwt 2.10.0 → 2.10.1" in body
    assert "GHSA-75c5-xw7c-p5pm" in body
    assert "CVSS **2.2**" in body
    assert "EPSS **0.0080**" in body
    assert "app/auth.py:21" in body, "the reachability proof"
    assert "No new test failures" in body
    assert "Reachable auth advisory" in body, "the justification"
    assert "sensitive_tier:auth" in body
    assert "Data freshness" in body and "recorded" in body
    assert "smith.langchain.com" in body, "the trace url"


def test_the_body_names_the_reviewer_who_approved_it():
    body = render_pr_body(make_advisory())
    assert "alice" in body and "evidence checked" in body


def test_an_auto_fix_body_says_no_human_was_involved():
    body = render_pr_body(make_advisory(decision="auto_fix", human=None))
    assert "Opened automatically" in body
    assert "alice" not in body


def test_the_body_states_what_patchpilot_cannot_do():
    """The reviewer should not have to take the guardrails on trust."""
    body = render_pr_body(make_advisory())
    assert "cannot merge" in body.lower()


def test_failing_tests_are_shown_not_buried():
    body = render_pr_body(
        make_advisory(
            sandbox=SandboxResult(
                supported=True, reason="pytest", newly_failing=["tests/test_app.py::test_upload"]
            )
        )
    )
    assert "1 test(s) newly failing" in body
    assert "tests/test_app.py::test_upload" in body


def test_a_baseline_failure_is_not_blamed_on_the_bump():
    body = render_pr_body(
        make_advisory(
            sandbox=SandboxResult(
                supported=True, reason="pytest", baseline_failed=["tests/test_flaky.py::test_x"]
            )
        )
    )
    assert "already failing before" in body


def test_an_unproven_bump_says_so():
    body = render_pr_body(
        make_advisory(sandbox=SandboxResult(supported=False, reason="cannot be installed"))
    )
    assert "Not proven by the sandbox" in body
    assert "cannot be installed" in body


def test_a_flagged_injection_is_surfaced_with_its_context():
    body = render_pr_body(
        make_advisory(
            injection_flag=InjectionFlag(flagged=True, reason="instruction-override: 'ignore…'")
        )
    )
    assert "Untrusted text was flagged" in body
    assert "could not affect the decision" in body


def test_dependency_conflicts_and_breaking_changes_are_shown():
    body = render_pr_body(
        make_advisory(
            plan=Plan(
                target_version="0.40.0",
                bump_kind="major",
                dependency_conflicts=["fastapi 0.100.0 requires starlette<0.28.0"],
                breaking_changes=["`Session.request` no longer accepts `strict`."],
                breaking_change_citations=["2.32.0#1"],
            )
        )
    )
    assert "fastapi 0.100.0 requires starlette<0.28.0" in body
    assert "no longer accepts `strict`" in body
    assert "2.32.0#1" in body


def test_the_body_never_contains_a_credential():
    """The body is scanned before the write, but it should not need to be."""
    from patchpilot.guardrails.secrets import scan_text

    assert scan_text(render_pr_body(make_advisory())) == []


def test_the_title_names_the_package_and_both_versions():
    title = pr_title(make_advisory())
    assert "pyjwt" in title and "2.10.0" in title and "2.10.1" in title
    assert "GHSA-75c5-xw7c-p5pm" in title


# ==================================================================== repository names with dots


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/owner/my.repo", "owner/my.repo"),
        ("https://github.com/owner/foo.js", "owner/foo.js"),
        ("https://github.com/owner/a.b.c", "owner/a.b.c"),
        ("https://github.com/my.org/repo", "my.org/repo"),
        ("https://github.com/owner/repo.git", "owner/repo"),
        ("https://github.com/owner/my.repo.git", "owner/my.repo"),
    ],
)
def test_dots_are_legal_in_repository_names(url, expected):
    """`owner/foo.js` used to truncate to `owner/foo` — a different repository, which the token
    might well be able to write to."""
    assert github_slug(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo/pull/1",
        "https://github.com/owner",
        "https://github.com/",
        "https://gitlab.com/owner/repo",
        "https://notgithub.com/owner/repo",
    ],
)
def test_anything_that_is_not_a_repository_root_is_refused(url):
    assert github_slug(url) is None
