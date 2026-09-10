"""What the local checkout knows about itself: its remote, its revision, its default branch.

Two things depend on this, and both are safety-relevant.

`execute_pr` needs a repository to open the pull request against. Deriving it from the checkout is
the obvious answer, but it has to be done with one rule held firmly: **never walk up**. PatchPilot's
own demo target lives at `fixtures/patchpilot-demo-app` *inside* the PatchPilot repository, so a
parent-directory search would resolve the target's remote to PatchPilot itself — and the agent would
open pull requests against its own policy, its own golden expectations and its own CI. The whole
guardrail argument assumes the agent cannot reach its own source. So `.git` is read only when it
sits directly at the path being scanned, and a subdirectory of a repository is reported as having no
remote at all.

`execute_pr` also needs the revision the sandbox actually tested. Branching from whatever the
default branch happens to point at *now* is wrong: a human gate can be open for days, and the file
content committed comes from the local checkout as it was at scan time. Recording the scanned
commit lets the pull request be branched from exactly the revision the evidence describes.

Nothing here runs `git`. It reads the plumbing files directly, so it works in a container with no
git binary and never executes anything from a repository being scanned.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field

_REMOTE_URL = re.compile(
    r'\[remote\s+"origin"\](?P<body>.*?)(?=\n\[|\Z)', re.IGNORECASE | re.DOTALL
)
_URL_LINE = re.compile(r"^\s*url\s*=\s*(?P<url>\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_SSH_REMOTE = re.compile(r"^(?:ssh://)?git@([^:/]+)[:/](.+?)(?:\.git)?/?$", re.IGNORECASE)
_SCP_LIKE = re.compile(r"^[^/]+@[^:]+:")


class CheckoutInfo(BaseModel):
    """What we could learn locally. Every field is optional: a plain directory is not an error."""

    url: str | None = Field(default=None, description="origin remote, normalised to https://")
    commit_sha: str | None = Field(default=None, description="the revision that was scanned")
    default_branch: str | None = Field(default=None, description="the branch HEAD points at")
    is_git_checkout: bool = False


def normalise_remote_url(raw: str | None) -> str | None:
    """`git@github.com:owner/repo.git` and `https://…/repo.git` both become `https://…/repo`."""
    if not raw:
        return None
    url = raw.strip()
    if not url:
        return None
    ssh = _SSH_REMOTE.match(url)
    if ssh:
        return f"https://{ssh.group(1)}/{ssh.group(2)}"
    if _SCP_LIKE.match(url) and "://" not in url:
        return None  # some other scp-style remote we do not understand
    url = re.sub(r"/+$", "", url)
    return url.removesuffix(".git") if url.endswith(".git") else url


def _git_dir(repo_path: Path) -> Path | None:
    """`.git` directly at this path, or None. Deliberately does not search upwards."""
    candidate = repo_path / ".git"
    if candidate.is_dir():
        return candidate
    if candidate.is_file():
        # A worktree or submodule: `gitdir: <path>`
        try:
            pointer = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if pointer.startswith("gitdir:"):
            target = Path(pointer.split(":", 1)[1].strip())
            resolved = target if target.is_absolute() else (repo_path / target)
            return resolved if resolved.is_dir() else None
    return None


def _read_origin(git_dir: Path) -> str | None:
    config = git_dir / "config"
    if not config.is_file():
        return None
    try:
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    section = _REMOTE_URL.search(text)
    if not section:
        return None
    line = _URL_LINE.search(section.group("body"))
    return normalise_remote_url(line.group("url")) if line else None


def _read_head(git_dir: Path) -> tuple[str | None, str | None]:
    """(commit_sha, branch_name). A detached HEAD gives a sha and no branch."""
    head_file = git_dir / "HEAD"
    if not head_file.is_file():
        return None, None
    try:
        head = head_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None, None

    if not head.startswith("ref:"):
        return (head, None) if re.fullmatch(r"[0-9a-f]{40}", head) else (None, None)

    ref = head.split(":", 1)[1].strip()
    branch = ref.rsplit("/", 1)[-1] if ref.startswith("refs/heads/") else None

    loose = git_dir / ref
    if loose.is_file():
        try:
            sha = loose.read_text(encoding="utf-8", errors="replace").strip()
            if re.fullmatch(r"[0-9a-f]{40}", sha):
                return sha, branch
        except OSError:
            pass

    packed = git_dir / "packed-refs"
    if packed.is_file():
        try:
            for line in packed.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("#") or line.startswith("^"):
                    continue
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0], branch
        except OSError:
            pass
    return None, branch


def read_checkout(repo_path: str | Path) -> CheckoutInfo:
    """Read `<repo_path>/.git` only. A directory inside a repository reports nothing."""
    root = Path(repo_path)
    git_dir = _git_dir(root)
    if git_dir is None:
        return CheckoutInfo()
    commit_sha, branch = _read_head(git_dir)
    return CheckoutInfo(
        url=_read_origin(git_dir),
        commit_sha=commit_sha,
        default_branch=branch,
        is_git_checkout=True,
    )
