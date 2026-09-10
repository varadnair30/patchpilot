"""The only three things PatchPilot can do to a GitHub repository.

    create_branch        branch off the default branch, under `patchpilot/`
    commit_file          write one file on that branch
    open_pull_request    open a PR from that branch, as a draft-able proposal

That list is the security argument, and it is enforced by absence. There is no `merge`, no
`force_push`, no `delete_branch`, no `update_protected_branch`, no `dispatch_workflow` — not
disabled, not behind a flag, not guarded by an `if`: simply not written. A jailbroken prompt, a
poisoned changelog and a bug in this file all have the same ceiling, because you cannot call a
function that does not exist.

What the three surviving operations *can* be pointed at is checked on every call by
`guardrails/allowlist.py` (branch prefix, protected refs, `.github/**` and traversal) and
`guardrails/secrets.py` (nothing credential-shaped reaches GitHub). Both raise; `execute_pr` turns
that into `decision="halted"` rather than a skipped write.

Recorded mode replays `github/<op>/<key>.json`, so the tests and CI prove the guardrails without a
token and without touching the network (rule 2).
"""

from __future__ import annotations

import base64
import os
from typing import Any

import httpx
from pydantic import BaseModel, Field

from patchpilot.config import get_settings
from patchpilot.guardrails.allowlist import WriteRequest, check_write
from patchpilot.guardrails.contracts import contract
from patchpilot.guardrails.secrets import assert_all_clean
from patchpilot.recorded.store import RecordedStore

GITHUB_API = "https://api.github.com"


class GitHubError(RuntimeError):
    """The GitHub API refused an operation."""


# --------------------------------------------------------------------------------------------
# Contracts
# --------------------------------------------------------------------------------------------


class CreateBranchInput(BaseModel):
    repo: str = Field(description="owner/name")
    branch: str
    base_branch: str = "main"
    base_sha: str | None = Field(
        default=None,
        description="Exact revision to branch from — the one the sandbox tested. When unset, the "
        "current head of base_branch is used, which may have moved since the scan.",
    )


class CreateBranchOutput(BaseModel):
    repo: str
    branch: str
    base_branch: str
    sha: str
    created: bool = Field(description="False when the branch already existed at this sha")


class CommitFileInput(BaseModel):
    repo: str
    branch: str
    base_branch: str = "main"
    path: str
    content: str
    message: str


class CommitFileOutput(BaseModel):
    repo: str
    branch: str
    path: str
    commit_sha: str


class OpenPullRequestInput(BaseModel):
    repo: str
    head: str = Field(description="The patchpilot/… branch the change is on")
    base: str = Field(default="main", description="The branch to merge into — never written to")
    title: str
    body: str


class OpenPullRequestOutput(BaseModel):
    repo: str
    number: int
    url: str
    branch: str


# --------------------------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------------------------


def github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise GitHubError(
            "GITHUB_TOKEN is not set. execute_pr needs a fine-grained token scoped to the target "
            "repository with Contents and Pull requests write access."
        )
    return token


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {github_token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    settings = get_settings()
    with httpx.Client(timeout=settings.http_timeout_seconds) as client:
        response = client.request(method, f"{GITHUB_API}{path}", headers=_headers(), **kwargs)
    if response.status_code >= 400:
        raise GitHubError(f"{method} {path} -> {response.status_code}: {response.text[:300]}")
    return response.json() if response.content else {}


def _recorded() -> bool:
    return get_settings().mode == "recorded"


# --------------------------------------------------------------------------------------------
# The three operations
# --------------------------------------------------------------------------------------------


@contract(CreateBranchInput, CreateBranchOutput)
def create_branch(inp: CreateBranchInput) -> CreateBranchOutput:
    """Create `branch` off `base_branch`. Never updates an existing ref — no force, no rewrite."""
    check_write(
        WriteRequest(repo=inp.repo, branch=inp.branch, base_branch=inp.base_branch, paths=[])
    )
    store = RecordedStore()
    key = f"{inp.repo}/{inp.branch}"

    def live() -> dict[str, Any]:
        if inp.base_sha:
            base_sha = inp.base_sha
        else:
            ref = _request("GET", f"/repos/{inp.repo}/git/ref/heads/{inp.base_branch}")
            base_sha = ref["object"]["sha"]
        created = True
        try:
            _request(
                "POST",
                f"/repos/{inp.repo}/git/refs",
                json={"ref": f"refs/heads/{inp.branch}", "sha": base_sha},
            )
        except GitHubError as e:
            # A branch left over from a previous run is reused as-is; it is never moved.
            if "already exists" not in str(e):
                raise
            created = False
        return {"sha": base_sha, "created": created}

    payload = store.fetch("github/branch", key, live)
    return CreateBranchOutput(
        repo=inp.repo,
        branch=inp.branch,
        base_branch=inp.base_branch,
        sha=payload["sha"],
        created=bool(payload.get("created", True)),
    )


@contract(CommitFileInput, CommitFileOutput)
def commit_file(inp: CommitFileInput) -> CommitFileOutput:
    """Write one file on a patchpilot/… branch. The path is re-checked against the allowlist."""
    check_write(
        WriteRequest(
            repo=inp.repo, branch=inp.branch, base_branch=inp.base_branch, paths=[inp.path]
        )
    )
    assert_all_clean([(f"{inp.path} contents", inp.content), ("commit message", inp.message)])

    store = RecordedStore()
    key = f"{inp.repo}/{inp.branch}/{inp.path}"

    def live() -> dict[str, Any]:
        existing_sha: str | None = None
        try:
            current = _request(
                "GET", f"/repos/{inp.repo}/contents/{inp.path}", params={"ref": inp.branch}
            )
            existing_sha = current.get("sha")
        except GitHubError:
            existing_sha = None  # a new file
        body: dict[str, Any] = {
            "message": inp.message,
            "content": base64.b64encode(inp.content.encode("utf-8")).decode("ascii"),
            "branch": inp.branch,
        }
        if existing_sha:
            body["sha"] = existing_sha
        result = _request("PUT", f"/repos/{inp.repo}/contents/{inp.path}", json=body)
        return {"commit_sha": result.get("commit", {}).get("sha", "")}

    payload = store.fetch("github/commit", key, live)
    return CommitFileOutput(
        repo=inp.repo, branch=inp.branch, path=inp.path, commit_sha=payload["commit_sha"]
    )


@contract(OpenPullRequestInput, OpenPullRequestOutput)
def open_pull_request(inp: OpenPullRequestInput) -> OpenPullRequestOutput:
    """Open a PR. It proposes a merge; it cannot perform one, and nothing here can."""
    check_write(WriteRequest(repo=inp.repo, branch=inp.head, base_branch=inp.base, paths=[]))
    assert_all_clean([("pr title", inp.title), ("pr body", inp.body)])

    store = RecordedStore()
    key = f"{inp.repo}/{inp.head}"

    def live() -> dict[str, Any]:
        # Opening a PR is not idempotent on GitHub: a second POST for the same head/base is a 422.
        # A rerun of a scan reuses the deterministic branch name, so look first and reuse what is
        # already open rather than halting the advisory on a duplicate.
        owner = inp.repo.split("/", 1)[0]
        existing = _request(
            "GET",
            f"/repos/{inp.repo}/pulls",
            params={"head": f"{owner}:{inp.head}", "base": inp.base, "state": "open"},
        )
        if isinstance(existing, list) and existing:
            return {"number": existing[0]["number"], "url": existing[0]["html_url"]}

        result = _request(
            "POST",
            f"/repos/{inp.repo}/pulls",
            json={"title": inp.title, "head": inp.head, "base": inp.base, "body": inp.body},
        )
        return {"number": result["number"], "url": result["html_url"]}

    payload = store.fetch("github/pr", key, live)
    return OpenPullRequestOutput(
        repo=inp.repo, number=int(payload["number"]), url=payload["url"], branch=inp.head
    )


# The public surface, asserted in tests. Adding to this list is a deliberate, reviewed act.
WRITE_OPERATIONS = ("create_branch", "commit_file", "open_pull_request")
