"""Put the public demo back how it started.

Two jobs, both narrow on purpose:

* close the pull requests PatchPilot opened on the demo repo and delete their branches
* clear the durable state so the queue repopulates on the next scan

The branch filter is the thing to read carefully. It closes only pull requests whose head branch
starts with `patchpilot/` — the same prefix `guardrails/allowlist.py` enforces on the way in. A
reset job with a GitHub token is exactly the sort of script that quietly grows into "delete every
branch", so the filter is explicit, tested, and refuses anything it does not recognise.

Run by .github/workflows/nightly-reset.yml. Safe to run by hand.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Importing config is what loads .env into the environment. Actions sets these directly, so
# without this the script works in CI and silently finds no token when run by hand — which is
# exactly when you want the dry run to tell you something.
import patchpilot.config  # noqa: E402,F401

BRANCH_PREFIX = "patchpilot/"
DEFAULT_DEMO_REPO = "varadnair30/patchpilot-demo-app"
API = "https://api.github.com"


def is_patchpilot_branch(branch: str) -> bool:
    """Only branches PatchPilot created. Never a human's, never the default branch."""
    return bool(branch) and branch.startswith(BRANCH_PREFIX) and ".." not in branch


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def close_pull_requests(repo: str, token: str, dry_run: bool = False) -> list[str]:
    """Close PatchPilot's open pull requests and delete their branches. Returns what it touched."""
    touched: list[str] = []
    with httpx.Client(timeout=30.0, headers=_headers(token)) as client:
        response = client.get(
            f"{API}/repos/{repo}/pulls", params={"state": "open", "per_page": 100}
        )
        response.raise_for_status()
        for pull in response.json():
            branch = (pull.get("head") or {}).get("ref", "")
            if not is_patchpilot_branch(branch):
                continue
            number = pull["number"]
            if dry_run:
                touched.append(f"would close #{number} ({branch})")
                continue
            client.patch(f"{API}/repos/{repo}/pulls/{number}", json={"state": "closed"})
            # Deleting the branch is what lets the next scan reuse the deterministic name.
            client.delete(f"{API}/repos/{repo}/git/refs/heads/{branch}")
            touched.append(f"closed #{number} ({branch})")
    return touched


def clear_state(url: str | None = None) -> dict[str, Any]:
    """Drop the checkpoints, the ledger and the queue so the next scan starts clean."""
    from patchpilot.storage.db import (
        MEMORY_URL,
        POSTGRES_PREFIXES,
        SQLITE_PREFIX,
        checkpoint_url,
        sqlite_connection,
    )

    url = url or checkpoint_url()
    # Checkpoint tables are LangGraph's; the other two are ours. Dropping rather than deleting
    # rows keeps this correct if a schema changes underneath us.
    tables = [
        "checkpoints",
        "checkpoint_blobs",
        "checkpoint_writes",
        "checkpoint_migrations",
        "decisions",
        "work_queue",
    ]
    dropped: list[str] = []

    def _drop(connection: Any) -> None:
        cur = connection.cursor()
        try:
            for table in tables:
                try:
                    cur.execute(f"DROP TABLE IF EXISTS {table}")
                    dropped.append(table)
                except Exception as e:  # a table that never existed is not a failure
                    print(f"  skipped {table}: {e.__class__.__name__}")
            connection.commit()
        finally:
            cur.close()

    if url == MEMORY_URL or url.startswith(SQLITE_PREFIX):
        with sqlite_connection(url) as connection:
            _drop(connection)
    elif url.startswith(POSTGRES_PREFIXES):
        import psycopg

        with psycopg.connect(url) as connection:
            _drop(connection)
    else:
        raise SystemExit(f"unsupported database url: {url!r}")
    return {"dropped": dropped}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--close-prs", action="store_true", help="close PatchPilot's demo PRs")
    parser.add_argument("--clear-state", action="store_true", help="drop checkpoints/ledger/queue")
    parser.add_argument("--dry-run", action="store_true", help="say what would happen")
    parser.add_argument("--repo", default=os.environ.get("DEMO_REPO", DEFAULT_DEMO_REPO))
    args = parser.parse_args()

    if not (args.close_prs or args.clear_state):
        parser.error("choose --close-prs, --clear-state, or both")

    if args.close_prs:
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            print("GITHUB_TOKEN is not set; skipping pull requests")
        else:
            for line in close_pull_requests(args.repo, token, dry_run=args.dry_run) or [
                "no PatchPilot pull requests were open"
            ]:
                print(f"  {line}")

    if args.clear_state:
        if args.dry_run:
            print("  would drop checkpoints, decisions and work_queue")
        else:
            print(f"  dropped: {', '.join(clear_state()['dropped'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
