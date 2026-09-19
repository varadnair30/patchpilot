"""Pinning the recorded fixtures to a known revision of the demo app.

Every sandbox fixture is a claim about a specific tree: "installing this repository and running its
tests before and after bumping X produced exactly this". That claim is only true for the tree it
was recorded against. Edit a line of the demo app and the recordings quietly start describing an
application that no longer exists — and because recorded mode never runs Docker, nothing would
notice. The golden set would keep passing while measuring fiction.

So the demo app is frozen: `demo_app.json` records the published repository, its tag, and a digest
of the tree, and a test recomputes the digest. Changing the demo app is then a deliberate act —
re-record the fixtures, re-tag, re-freeze — rather than something that can happen by accident.

The digest covers paths and contents, and normalises line endings so a clone on Windows and a clone
on Linux agree.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field

from patchpilot.config import PACKAGE_ROOT

MANIFEST_PATH = PACKAGE_ROOT / "recorded" / "fixtures" / "demo_app.json"
REPO_ROOT = PACKAGE_ROOT.parent.parent
VENDORED_DEMO_APP = REPO_ROOT / "fixtures" / "patchpilot-demo-app"

# Never part of the application, and never stable across machines.
IGNORED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", ".ruff_cache"}


class DemoAppManifest(BaseModel):
    """What the recorded fixtures were recorded against."""

    repo_url: str | None = Field(default=None, description="Where the demo app is published")
    tag: str | None = Field(default=None, description="The tag the fixtures describe")
    commit: str | None = Field(default=None, description="The commit that tag points at")
    tree_digest: str = Field(description="sha256 over the vendored tree's paths and contents")
    file_count: int = 0
    note: str = ""


def iter_files(root: Path) -> list[Path]:
    """Files in an order that does not depend on the operating system.

    Sorting `Path` objects is a trap here: comparison is case-folded on Windows and case-sensitive
    on POSIX, so `README.md` sorts before `app/` on Linux and after it on Windows. That is enough
    to change the digest between a developer's machine and CI while every file is byte-identical.
    Sort on the relative POSIX string instead.
    """
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file() and not (set(path.relative_to(root).parts) & IGNORED_DIRS)
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def tree_digest(root: Path) -> tuple[str, int]:
    """A stable digest of a directory: (sha256, file count).

    Line endings are normalised because git checks the demo app out with CRLF on Windows and LF on
    Linux, and a digest that disagreed between the two would fail CI for no real reason.
    """
    digest = hashlib.sha256()
    files = iter_files(root)
    for path in files:
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes().replace(b"\r\n", b"\n")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).hexdigest().encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest(), len(files)


def load_manifest(path: Path = MANIFEST_PATH) -> DemoAppManifest | None:
    if not path.exists():
        return None
    return DemoAppManifest.model_validate_json(path.read_text(encoding="utf-8"))


def write_manifest(manifest: DemoAppManifest, path: Path = MANIFEST_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def freeze(
    root: Path = VENDORED_DEMO_APP,
    repo_url: str | None = None,
    tag: str | None = None,
    commit: str | None = None,
) -> DemoAppManifest:
    """Record the current state of the demo app as the one the fixtures describe."""
    digest, count = tree_digest(root)
    previous = load_manifest()
    return DemoAppManifest(
        repo_url=repo_url or (previous.repo_url if previous else None),
        tag=tag or (previous.tag if previous else None),
        commit=commit or (previous.commit if previous else None),
        tree_digest=digest,
        file_count=count,
        note="Recorded OSV, EPSS, PyPI, changelog and sandbox fixtures describe this exact tree.",
    )
