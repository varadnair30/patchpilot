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


# ==================================================================== branching from the scan


def test_the_branch_is_cut_from_the_revision_that_was_scanned(recorded_github, monkeypatch):
    """A human gate can be open for days. Branching from wherever the default branch has moved to
    would let the PR revert unrelated changes and would make the test evidence describe a base
    that is no longer the one being proposed."""
    calls = []
    monkeypatch.setenv("PATCHPILOT_MODE", "live")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    def fake_request(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        return {}

    monkeypatch.setattr(github_pr, "_request", fake_request)
    create_branch(
        CreateBranchInput(repo=REPO, branch=BRANCH, base_branch="main", base_sha="deadbeef")
    )

    assert not any(m == "GET" for m, _, _ in calls), "the moving head must not be consulted"
    post = next(body for m, p, body in calls if m == "POST" and "git/refs" in p)
    assert post["sha"] == "deadbeef"
    assert post["ref"] == f"refs/heads/{BRANCH}"


def test_without_a_scanned_revision_the_current_head_is_used(recorded_github, monkeypatch):
    calls = []
    monkeypatch.setenv("PATCHPILOT_MODE", "live")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    def fake_request(method, path, **kwargs):
        calls.append((method, path))
        if method == "GET":
            return {"object": {"sha": "headsha"}}
        return {}

    monkeypatch.setattr(github_pr, "_request", fake_request)
    create_branch(CreateBranchInput(repo=REPO, branch=BRANCH, base_branch="main"))
    assert ("GET", f"/repos/{REPO}/git/ref/heads/main") in calls


# ==================================================================== reruns are idempotent


def test_an_existing_pull_request_is_reused_rather_than_duplicated(recorded_github, monkeypatch):
    """GitHub answers a second POST for the same head/base with a 422. A rerun of a scan reuses
    the deterministic branch name, so it must find what is already open."""
    monkeypatch.setenv("PATCHPILOT_MODE", "live")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    posted = []

    def fake_request(method, path, **kwargs):
        if method == "GET" and path.endswith("/pulls"):
            return [{"number": 42, "html_url": f"https://github.com/{REPO}/pull/42"}]
        posted.append((method, path))
        return {"number": 99, "html_url": "https://example.invalid/99"}

    monkeypatch.setattr(github_pr, "_request", fake_request)
    pr = open_pull_request(
        OpenPullRequestInput(repo=REPO, head=BRANCH, base="main", title="t", body="b")
    )

    assert pr.number == 42, "the open PR was reused"
    assert posted == [], "no duplicate POST was attempted"


def test_a_first_run_still_opens_a_pull_request(recorded_github, monkeypatch):
    monkeypatch.setenv("PATCHPILOT_MODE", "live")
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    from patchpilot.config import get_settings

    get_settings.cache_clear()

    def fake_request(method, path, **kwargs):
        if method == "GET" and path.endswith("/pulls"):
            return []
        return {"number": 7, "html_url": f"https://github.com/{REPO}/pull/7"}

    monkeypatch.setattr(github_pr, "_request", fake_request)
    pr = open_pull_request(
        OpenPullRequestInput(repo=REPO, head=BRANCH, base="main", title="t", body="b")
    )
    assert pr.number == 7
