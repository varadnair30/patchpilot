"""What PatchPilot is allowed to do to a repository.

This is the second half of a belt-and-braces argument. The first half is in `tools/github_pr.py`,
which implements exactly three operations — create a branch, commit a file, open a pull request.
Merging, force-pushing, deleting branches and editing protected refs are not guarded here because
they do not exist: there is no function to call, so no prompt, bug or injected instruction can
reach them.

What *is* guarded here is the shape of the three operations that do exist. A branch name, a base
branch and a file path all arrive from state, and state is influenced by advisory text we did not
write. So every write re-checks, immediately before it happens:

* the branch we are pushing to starts with `patchpilot/`
* the branch we are pushing to is not the repository's default or a protected branch
* the path we are writing is not CI configuration, not inside `.git`, and not an escape upwards

A violation raises, and the node turns it into `decision="halted"` with `halt_reason` set (rule 3).
It never becomes a silently skipped write.
"""

from __future__ import annotations

import posixpath
import re

from pydantic import BaseModel, Field

BRANCH_PREFIX = "patchpilot/"

# Refs PatchPilot may never target, whatever the repository calls its default.
PROTECTED_BRANCHES = frozenset(
    {"main", "master", "trunk", "develop", "development", "release", "stable", "production", "prod"}
)

# Writing CI configuration would let a PR change the checks that judge it, so `.github/**` is
# refused even though the fine-grained token is not supposed to carry the workflow scope either.
DENIED_PATH_PREFIXES = (".github/", ".git/", ".gitea/", ".circleci/", ".gitlab/")
DENIED_PATH_NAMES = frozenset({".gitattributes", ".gitmodules"})

_VALID_BRANCH = re.compile(r"^[A-Za-z0-9._\-/]+$")


class AllowlistViolation(RuntimeError):
    """A write was attempted that PatchPilot is not permitted to make."""

    def __init__(self, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"allowlist [{rule}]: {detail}")


class WriteRequest(BaseModel):
    """One proposed write, checked as a whole so a caller cannot skip half the rules."""

    repo: str = Field(description="owner/name of the target repository")
    branch: str = Field(description="The branch being written to")
    base_branch: str = Field(description="The repository's default branch")
    paths: list[str] = Field(default_factory=list)


def check_branch_name(branch: str) -> None:
    if not branch or not branch.strip():
        raise AllowlistViolation("branch_name", "branch name is empty")
    if branch != branch.strip():
        raise AllowlistViolation(
            "branch_name", f"branch name has surrounding whitespace: {branch!r}"
        )
    if not branch.startswith(BRANCH_PREFIX):
        raise AllowlistViolation(
            "branch_prefix", f"{branch!r} does not start with {BRANCH_PREFIX!r}"
        )
    if not _VALID_BRANCH.match(branch):
        raise AllowlistViolation("branch_name", f"{branch!r} contains illegal characters")
    if ".." in branch or branch.endswith("/") or "//" in branch:
        raise AllowlistViolation("branch_name", f"{branch!r} is not a well-formed ref")


def check_not_protected(branch: str, base_branch: str) -> None:
    """The target branch must be neither a well-known protected name nor the repo's own default."""
    target = branch.strip().lower()
    if target in PROTECTED_BRANCHES:
        raise AllowlistViolation("protected_branch", f"{branch!r} is a protected branch")
    if base_branch and target == base_branch.strip().lower():
        raise AllowlistViolation(
            "protected_branch", f"{branch!r} is the repository's default branch"
        )


def check_path(path: str) -> None:
    """Reject CI configuration, git internals, absolute paths and anything escaping the repo."""
    if not path or not path.strip():
        raise AllowlistViolation("path", "empty path")
    normalised = path.replace("\\", "/").strip()

    if normalised.startswith("/") or re.match(r"^[A-Za-z]:/", normalised):
        raise AllowlistViolation("path_absolute", f"{path!r} is an absolute path")

    collapsed = posixpath.normpath(normalised)
    if collapsed.startswith("../") or collapsed == ".." or collapsed.startswith("/"):
        raise AllowlistViolation("path_traversal", f"{path!r} escapes the repository root")

    lowered = collapsed.lower()
    for prefix in DENIED_PATH_PREFIXES:
        if lowered == prefix.rstrip("/") or lowered.startswith(prefix):
            raise AllowlistViolation("path_denied", f"{path!r} is CI or git configuration")
    if lowered in DENIED_PATH_NAMES:
        raise AllowlistViolation("path_denied", f"{path!r} is git configuration")


def check_write(request: WriteRequest) -> None:
    """Every rule, in one call. `tools/github_pr.py` runs this before each of its three writes."""
    check_branch_name(request.branch)
    check_not_protected(request.branch, request.base_branch)
    for path in request.paths:
        check_path(path)


def branch_for(advisory_id: str) -> str:
    """The only branch name PatchPilot ever proposes, so it always satisfies the prefix rule."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", advisory_id)
    # `..` is illegal in a git ref, and it is exactly what a traversal attempt leaves behind.
    safe = re.sub(r"\.{2,}", ".", safe).strip("-./")
    if not safe:
        raise AllowlistViolation(
            "branch_name", f"advisory id {advisory_id!r} yields no branch name"
        )
    branch = f"{BRANCH_PREFIX}{safe}"
    check_branch_name(branch)  # never hand back a name our own rules would refuse
    return branch
