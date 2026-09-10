"""The GitHub tool, and the claim that dangerous writes are impossible by construction.

Two halves to that claim:

* the operations that would be dangerous are not implemented at all — asserted here by inspecting
  the module's public surface, so adding one later fails this test rather than shipping quietly;
* the three that are implemented refuse anything outside their remit, on every call.
"""

import inspect

import pytest

from patchpilot.guardrails.allowlist import AllowlistViolation
from patchpilot.guardrails.secrets import SecretsFound
from patchpilot.recorded.store import RecordedStore
from patchpilot.tools import github_pr
from patchpilot.tools.github_pr import (
    WRITE_OPERATIONS,
    CommitFileInput,
    CreateBranchInput,
    GitHubError,
    OpenPullRequestInput,
    commit_file,
    create_branch,
    github_token,
    open_pull_request,
)

REPO = "varadnair30/patchpilot-demo-app"
BRANCH = "patchpilot/GHSA-75c5-xw7c-p5pm"


@pytest.fixture
def recorded_github(monkeypatch, tmp_path):
    """Fixtures for the three operations, as `patchpilot record` would have written them."""
    monkeypatch.setenv("PATCHPILOT_FIXTURES_DIR", str(tmp_path))
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    store = RecordedStore()
    store.write("github/branch", f"{REPO}/{BRANCH}", {"sha": "abc123", "created": True})
    store.write("github/commit", f"{REPO}/{BRANCH}/requirements.txt", {"commit_sha": "def456"})
    store.write(
        "github/pr",
        f"{REPO}/{BRANCH}",
        {"number": 7, "url": f"https://github.com/{REPO}/pull/7"},
    )
    yield store
    get_settings.cache_clear()


# ==================================================================== impossible by construction


def test_the_module_exposes_exactly_three_write_operations():
    """The security argument is a list of three. If this fails, that argument changed."""
    assert WRITE_OPERATIONS == ("create_branch", "commit_file", "open_pull_request")


@pytest.mark.parametrize(
    "forbidden",
    [
        "merge",
        "merge_pull_request",
        "force_push",
        "push_force",
        "delete_branch",
        "delete_ref",
        "update_ref",
        "update_branch_protection",
        "dispatch_workflow",
        "create_workflow",
        "close_pull_request",
        "approve_pull_request",
        "add_collaborator",
        "delete_repo",
    ],
)
def test_dangerous_operations_do_not_exist(forbidden):
    """Not disabled, not flagged off — absent. There is no function to reach."""
    assert not hasattr(github_pr, forbidden), f"{forbidden} must not exist in the GitHub tool"


def test_no_public_function_writes_outside_the_three():
    """Catch a fourth write slipping in under a different name."""
    public = {
        name
        for name, obj in vars(github_pr).items()
        if not name.startswith("_")
        and inspect.isfunction(obj)
        and obj.__module__ == github_pr.__name__
    }
    helpers = {"github_token"}
    assert public - helpers == set(WRITE_OPERATIONS)


def test_the_tool_never_issues_a_delete_or_a_patch():
    """A PUT to contents and POSTs to refs/pulls are the whole vocabulary."""
    source = inspect.getsource(github_pr)
    for verb in ('"DELETE"', '"PATCH"'):
        assert verb not in source, f"{verb} must not appear in the GitHub tool"


# ==================================================================== the allowlist, on every call


@pytest.mark.parametrize("branch", ["main", "master", "develop", "release", "feature/x", "hotfix"])
def test_a_branch_outside_our_namespace_is_refused_by_every_operation(recorded_github, branch):
    with pytest.raises(AllowlistViolation):
        create_branch(CreateBranchInput(repo=REPO, branch=branch, base_branch="main"))
    with pytest.raises(AllowlistViolation):
        commit_file(
            CommitFileInput(
                repo=REPO,
                branch=branch,
                path="requirements.txt",
                content="requests==2.32.4\n",
                message="bump",
            )
        )
    with pytest.raises(AllowlistViolation):
        open_pull_request(
            OpenPullRequestInput(repo=REPO, head=branch, base="main", title="t", body="b")
        )


def test_the_default_branch_can_never_be_the_target(recorded_github):
    """Even named `patchpilot/…`, a branch that *is* the default is refused."""
    with pytest.raises(AllowlistViolation):
        create_branch(CreateBranchInput(repo=REPO, branch="shipping", base_branch="shipping"))


@pytest.mark.parametrize(
    "path",
    [".github/workflows/ci.yml", ".git/config", "../../etc/passwd", "/etc/passwd", ".gitmodules"],
)
def test_ci_paths_and_traversal_are_refused_at_commit_time(recorded_github, path):
    with pytest.raises(AllowlistViolation):
        commit_file(
            CommitFileInput(repo=REPO, branch=BRANCH, path=path, content="x: 1\n", message="bump")
        )


# ==================================================================== the secret scan


def test_a_credential_in_the_diff_blocks_the_commit(recorded_github):
    with pytest.raises(SecretsFound):
        commit_file(
            CommitFileInput(
                repo=REPO,
                branch=BRANCH,
                path="requirements.txt",
                content="requests==2.32.4\n# ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
                message="bump requests",
            )
        )


def test_a_credential_in_the_pr_body_blocks_the_pull_request(recorded_github):
    with pytest.raises(SecretsFound):
        open_pull_request(
            OpenPullRequestInput(
                repo=REPO,
                head=BRANCH,
                base="main",
                title="Bump requests",
                body="Evidence:\nAKIAIOSFODNN7EXAMPLX\n",
            )
        )


def test_a_clean_body_that_talks_about_tokens_is_still_allowed(recorded_github):
    """PR bodies discuss configuration constantly; the scanner must not block prose."""
    pr = open_pull_request(
        OpenPullRequestInput(
            repo=REPO,
            head=BRANCH,
            base="main",
            title="Bump pyjwt",
            body="Set GITHUB_TOKEN to a fine-grained token before running the worker.",
        )
    )
    assert pr.number == 7


# ==================================================================== the happy path


def test_the_three_operations_round_trip_in_recorded_mode(recorded_github):
    branch = create_branch(CreateBranchInput(repo=REPO, branch=BRANCH, base_branch="main"))
    assert (branch.branch, branch.sha, branch.created) == (BRANCH, "abc123", True)

    commit = commit_file(
        CommitFileInput(
            repo=REPO,
            branch=BRANCH,
            path="requirements.txt",
            content="pyjwt==2.10.1\n",
            message="Bump pyjwt to 2.10.1",
        )
    )
    assert commit.commit_sha == "def456"

    pr = open_pull_request(
        OpenPullRequestInput(
            repo=REPO, head=BRANCH, base="main", title="Bump pyjwt", body="Evidence bundle."
        )
    )
    assert pr.number == 7
    assert pr.url.endswith("/pull/7")
    assert pr.branch == BRANCH


def test_recorded_mode_needs_no_token(recorded_github, monkeypatch):
    """CI has no GITHUB_TOKEN and must still exercise every guardrail."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    branch = create_branch(CreateBranchInput(repo=REPO, branch=BRANCH, base_branch="main"))
    assert branch.sha == "abc123"


def test_live_mode_without_a_token_says_what_is_missing(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(GitHubError) as excinfo:
        github_token()
    assert "fine-grained" in str(excinfo.value)


def test_inputs_are_validated_by_contract(recorded_github):
    from patchpilot.guardrails.contracts import ContractViolation

    with pytest.raises(ContractViolation):
        create_branch({"repo": REPO})  # branch missing
