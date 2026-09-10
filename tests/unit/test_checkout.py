"""Reading the scan target's own git metadata — carefully.

The dangerous mistake this module exists to avoid: PatchPilot's demo target lives at
`fixtures/patchpilot-demo-app`, *inside* the PatchPilot repository. A parent-directory search for
`.git` would resolve the target's remote to PatchPilot itself, and the agent would open pull
requests against its own policy rules, golden expectations and CI workflows. Every guardrail in
step 7 assumes the agent cannot reach its own source, so this is load-bearing.
"""

import pytest

from patchpilot.cli.main import build_repo_ref
from patchpilot.tools.checkout import normalise_remote_url, read_checkout

SHA = "a" * 40


@pytest.fixture
def fake_checkout(tmp_path):
    """Write git plumbing files directly; no git binary is involved, here or in the code."""

    def make(url="https://github.com/owner/repo.git", branch="main", sha=SHA, packed=False):
        git = tmp_path / ".git"
        (git / "refs" / "heads").mkdir(parents=True)
        (git / "config").write_text(
            "[core]\n\trepositoryformatversion = 0\n"
            f'[remote "origin"]\n\turl = {url}\n\tfetch = +refs/heads/*\n'
            '[branch "main"]\n\tremote = origin\n',
            encoding="utf-8",
        )
        (git / "HEAD").write_text(f"ref: refs/heads/{branch}\n", encoding="utf-8")
        if packed:
            (git / "packed-refs").write_text(
                f"# pack-refs with: peeled fully-peeled sorted\n{sha} refs/heads/{branch}\n",
                encoding="utf-8",
            )
        else:
            (git / "refs" / "heads" / branch).write_text(f"{sha}\n", encoding="utf-8")
        return tmp_path

    return make


# ==================================================================== never walk up


def test_a_directory_inside_a_repository_reports_no_remote(fake_checkout):
    """The demo app's exact situation. Inheriting the parent's remote would point PatchPilot at
    its own source."""
    repo = fake_checkout()
    nested = repo / "fixtures" / "demo-app"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    info = read_checkout(nested)
    assert info.is_git_checkout is False
    assert info.url is None and info.commit_sha is None


def test_the_cli_never_gives_a_nested_target_its_parents_remote(fake_checkout):
    repo = fake_checkout(url="https://github.com/varadnair30/patchpilot.git")
    nested = repo / "fixtures" / "patchpilot-demo-app"
    nested.mkdir(parents=True)

    ref = build_repo_ref(nested)
    assert ref.url is None, "PatchPilot must never target its own repository"


def test_a_plain_directory_is_not_an_error(tmp_path):
    info = read_checkout(tmp_path)
    assert info == type(info)()


# ==================================================================== what it does read


def test_the_origin_remote_and_revision_are_read(fake_checkout):
    info = read_checkout(fake_checkout())
    assert info.is_git_checkout
    assert info.url == "https://github.com/owner/repo"
    assert info.commit_sha == SHA
    assert info.default_branch == "main"


def test_a_packed_ref_is_resolved(fake_checkout):
    """A freshly cloned repository has no loose ref file for its branch."""
    info = read_checkout(fake_checkout(packed=True))
    assert info.commit_sha == SHA


def test_a_detached_head_gives_a_revision_and_no_branch(fake_checkout):
    repo = fake_checkout()
    (repo / ".git" / "HEAD").write_text(f"{SHA}\n", encoding="utf-8")
    info = read_checkout(repo)
    assert info.commit_sha == SHA and info.default_branch is None


def test_a_non_default_branch_name_is_honoured(fake_checkout):
    info = read_checkout(fake_checkout(branch="shipping"))
    assert info.default_branch == "shipping"


def test_a_checkout_with_no_remote_still_yields_a_revision(fake_checkout):
    repo = fake_checkout()
    (repo / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    info = read_checkout(repo)
    assert info.url is None and info.commit_sha == SHA


# ==================================================================== remote url shapes


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("https://github.com/owner/repo", "https://github.com/owner/repo"),
        ("https://github.com/owner/my.repo", "https://github.com/owner/my.repo"),
        ("git@github.com:owner/repo.git", "https://github.com/owner/repo"),
        ("ssh://git@github.com/owner/repo.git", "https://github.com/owner/repo"),
        ("https://github.com/owner/repo/", "https://github.com/owner/repo"),
        ("", None),
        (None, None),
    ],
)
def test_remote_urls_are_normalised(raw, expected):
    assert normalise_remote_url(raw) == expected


# ==================================================================== the CLI wiring


def test_an_explicit_url_overrides_whatever_was_found(fake_checkout):
    repo = fake_checkout(url="git@github.com:owner/wrong.git")
    ref = build_repo_ref(repo, "https://github.com/owner/right")
    assert ref.url == "https://github.com/owner/right"


def test_the_scan_records_the_revision_it_scanned(fake_checkout):
    """execute_pr branches from this, so the PR's base is the revision the sandbox tested."""
    ref = build_repo_ref(fake_checkout())
    assert ref.commit_sha == SHA
    assert ref.url == "https://github.com/owner/repo"
    assert ref.default_branch == "main"


def test_a_target_with_no_git_metadata_still_scans(tmp_path):
    ref = build_repo_ref(tmp_path)
    assert ref.url is None and ref.commit_sha is None
    assert ref.default_branch == "main", "a sane default so the rest of the scan works"
