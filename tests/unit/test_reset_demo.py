"""The nightly reset — specifically, what it is allowed to delete.

A scheduled job holding a GitHub token is exactly the script that quietly grows into "delete every
branch". The filter is the whole safety story, so most of this file is about branches it must
refuse to touch.
"""

import httpx
import pytest

from scripts.reset_demo import BRANCH_PREFIX, close_pull_requests, is_patchpilot_branch

# ==================================================================== the branch filter


@pytest.mark.parametrize(
    "branch",
    [
        "patchpilot/GHSA-2jv5-9r88-3w3p",
        "patchpilot/GHSA-75c5-xw7c-p5pm",
        "patchpilot/anything",
    ],
)
def test_branches_patchpilot_created_are_in_scope(branch):
    assert is_patchpilot_branch(branch)


@pytest.mark.parametrize(
    "branch",
    [
        "main",
        "master",
        "develop",
        "",
        "feature/patchpilot/nested",
        "my-patchpilot/thing",
        "PATCHPILOT/upper",
        "patchpilot",
        "../patchpilot/escape",
        "patchpilot/../../main",
        "release/v1",
        "dependabot/pip/requests-2.32.4",
    ],
)
def test_everything_else_is_refused(branch):
    """The default branch, a human's branch, another bot's branch, and path traversal."""
    assert not is_patchpilot_branch(branch)


def test_the_prefix_is_the_one_the_allowlist_enforces():
    """If these ever drift, the reset would either miss PatchPilot's branches or reach beyond
    them. Both are bad, so they are pinned to the same constant."""
    from patchpilot.guardrails.allowlist import BRANCH_PREFIX as ALLOWLIST_PREFIX

    assert BRANCH_PREFIX == ALLOWLIST_PREFIX


# ==================================================================== closing pull requests


class FakeGitHub:
    """Records what the reset would do to the demo repo."""

    def __init__(self, pulls):
        self._pulls = pulls
        self.closed: list[int] = []
        self.deleted: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, params=None):
        return httpx.Response(200, json=self._pulls, request=httpx.Request("GET", url))

    def patch(self, url, json=None):
        self.closed.append(int(url.rstrip("/").split("/")[-1]))
        return httpx.Response(200, json={}, request=httpx.Request("PATCH", url))

    def delete(self, url):
        self.deleted.append(url.split("/heads/", 1)[1])
        return httpx.Response(204, request=httpx.Request("DELETE", url))


def pull(number: int, branch: str) -> dict:
    return {"number": number, "head": {"ref": branch}}


@pytest.fixture
def github(monkeypatch):
    def install(pulls):
        fake = FakeGitHub(pulls)
        monkeypatch.setattr(httpx, "Client", lambda *a, **k: fake)
        return fake

    return install


def test_only_patchpilots_pull_requests_are_closed(github):
    fake = github(
        [
            pull(1, "patchpilot/GHSA-2jv5-9r88-3w3p"),
            pull(2, "main"),
            pull(3, "someone-elses-work"),
            pull(4, "patchpilot/GHSA-59g5-xgcq-4qw3"),
            pull(5, "dependabot/pip/urllib3-2.2.2"),
        ]
    )
    touched = close_pull_requests("owner/demo", "token")

    assert fake.closed == [1, 4]
    assert fake.deleted == [
        "patchpilot/GHSA-2jv5-9r88-3w3p",
        "patchpilot/GHSA-59g5-xgcq-4qw3",
    ]
    assert len(touched) == 2


def test_a_branch_is_deleted_so_the_next_scan_can_reuse_the_name(github):
    """Branch names are deterministic per advisory; a leftover branch would collide."""
    fake = github([pull(7, "patchpilot/GHSA-x")])
    close_pull_requests("owner/demo", "token")
    assert fake.deleted == ["patchpilot/GHSA-x"]


def test_nothing_is_touched_when_no_patchpilot_pull_requests_are_open(github):
    fake = github([pull(1, "main"), pull(2, "chore/docs")])
    assert close_pull_requests("owner/demo", "token") == []
    assert fake.closed == [] and fake.deleted == []


def test_a_dry_run_changes_nothing(github):
    fake = github([pull(1, "patchpilot/GHSA-x")])
    touched = close_pull_requests("owner/demo", "token", dry_run=True)
    assert fake.closed == [] and fake.deleted == []
    assert "would close #1" in touched[0]


def test_an_empty_repository_is_not_an_error(github):
    github([])
    assert close_pull_requests("owner/demo", "token") == []
