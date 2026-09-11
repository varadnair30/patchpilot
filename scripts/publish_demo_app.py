"""Build the demo app as a standalone repository, and freeze the fixtures against it.

    python scripts/publish_demo_app.py --build        # stage a tagged repo, print push commands
    python scripts/publish_demo_app.py --freeze       # re-pin the fixtures to the vendored tree

Why the demo app is published at all: `execute_pr` needs somewhere to open a pull request, and
PatchPilot must never have write access to its own source (see tools/checkout.py). A separate
repository is what keeps those two facts compatible.

Why the vendored copy stays: the whole suite runs offline in recorded mode (rule 2). Cloning the
demo app to run tests would trade that guarantee for tidiness. Instead the vendored tree is frozen
against the published tag, and tests/unit/test_demo_app_frozen.py fails if the two drift apart.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from patchpilot.recorded.freeze import (  # noqa: E402
    VENDORED_DEMO_APP,
    freeze,
    load_manifest,
    tree_digest,
    write_manifest,
)

DEFAULT_TAG = "v1.0.0"


# A fixed identity and timestamp make the commit sha a function of the tree alone, so rebuilding
# produces the same sha and the manifest can pin it before anything is pushed. Without this the sha
# changes every run and the manifest would name a commit that exists only in a temp directory.
FROZEN_DATE = "2026-01-01T00:00:00+00:00"
GIT_IDENTITY = [
    "-c",
    "user.name=PatchPilot",
    "-c",
    "user.email=noreply@example.invalid",
]


def run(args: list[str], cwd: Path) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_DATE": FROZEN_DATE,
        "GIT_COMMITTER_DATE": FROZEN_DATE,
    }
    done = subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env
    )
    if done.returncode != 0:
        raise SystemExit(f"{' '.join(args)} failed:\n{done.stdout}{done.stderr}")
    return done.stdout.strip()


def _force_remove(func, path, _exc):
    """git marks objects read-only, which stops rmtree on Windows."""
    import os
    import stat

    os.chmod(path, stat.S_IWRITE)
    func(path)


def build(destination: Path, repo_url: str, tag: str) -> str:
    """Stage the demo app as its own git repository and return the commit sha."""
    if destination.exists():
        shutil.rmtree(destination, onexc=_force_remove)
    # Copy verbatim and invent nothing: the published tree has to be byte-identical to the vendored
    # one, or the manifest would pin a digest that the tagged commit does not actually have.
    shutil.copytree(
        VENDORED_DEMO_APP,
        destination,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"),
    )

    run(["git", "init", "-q", "-b", "main"], destination)
    run(["git", "add", "-A"], destination)
    run(
        [
            "git",
            *GIT_IDENTITY,
            "commit",
            "-q",
            "-m",
            "patchpilot-demo-app: intentionally vulnerable demo target\n\n"
            "Ten pinned dependencies carrying real historical advisories, chosen so every "
            "PatchPilot decision class appears at least once. Do not deploy this.",
        ],
        destination,
    )
    run(
        ["git", *GIT_IDENTITY, "tag", "-a", tag, "-m", f"PatchPilot demo target {tag}"], destination
    )
    run(["git", "remote", "add", "origin", f"{repo_url}.git"], destination)
    return run(["git", "rev-parse", "HEAD"], destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", help="stage the standalone repository")
    parser.add_argument(
        "--freeze", action="store_true", help="re-pin fixtures to the vendored tree"
    )
    parser.add_argument(
        "--repo-url",
        default="https://github.com/varadnair30/patchpilot-demo-app",
        help="where the demo app is published",
    )
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(tempfile.gettempdir()) / "patchpilot-demo-app",
        help="where to stage the repository",
    )
    args = parser.parse_args()

    if not args.build and not args.freeze:
        parser.error("choose --build, --freeze, or both")

    commit = None
    if args.build:
        commit = build(args.out, args.repo_url, args.tag)
        print(f"staged {args.out}")
        print(f"  commit {commit}")
        print(f"  tag    {args.tag}")
        print(f"  remote {args.repo_url}.git")
        print()
        print("Create an EMPTY public repo with that name, then:")
        print(f"  cd {args.out}")
        print("  git push -u origin main")
        print(f"  git push origin {args.tag}")

    if args.freeze:
        manifest = freeze(repo_url=args.repo_url, tag=args.tag, commit=commit)
        path = write_manifest(manifest)
        print(f"\nfroze {manifest.file_count} files -> {path}")
        print(f"  digest {manifest.tree_digest}")
        if commit:
            print(f"  commit {commit}")
    else:
        digest, count = tree_digest(VENDORED_DEMO_APP)
        current = load_manifest()
        if current and current.tree_digest != digest:
            print(
                f"\nWARNING: the vendored tree ({count} files, {digest[:12]}) no longer matches "
                f"the manifest ({current.file_count} files, {current.tree_digest[:12]}). "
                "Re-record the fixtures, then re-run with --freeze."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
