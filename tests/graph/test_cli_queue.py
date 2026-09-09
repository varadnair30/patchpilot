"""`patchpilot scan` then `patchpilot queue list|show|approve|reject`, across processes.

Each CliRunner invocation opens and closes its own checkpointer connection, so these tests are the
CLI-level version of the process-restart test: nothing is carried in memory between commands.
"""

import pytest
from test_ingest_reachability import EXPECTED
from typer.testing import CliRunner

from patchpilot.cli.main import app
from patchpilot.storage.db import open_ledger

GATED = {aid for aid, expected in EXPECTED.items() if expected[6]}
AUTH_ADVISORY = "GHSA-75c5-xw7c-p5pm"  # pyjwt: sensitive_tier:auth, the demo's showcase gate

runner = CliRunner()


@pytest.fixture
def cli_env(monkeypatch, tmp_path):
    """A private on-disk checkpoint store, so `scan` and `queue` really share durable state."""
    db = tmp_path / "checkpoints.sqlite"
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("PATCHPILOT_CHECKPOINT_DB", str(db))
    monkeypatch.setenv("PATCHPILOT_LLM", "off")
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    yield f"sqlite:///{db}"
    get_settings.cache_clear()


def run(*args):
    result = runner.invoke(app, list(args))
    if result.exception and not isinstance(result.exception, SystemExit):
        raise result.exception
    return result


def test_scan_reports_the_pending_gates_and_the_queue_lists_them(cli_env, demo_app):
    scan = run("scan", str(demo_app), "--thread", "cli-1")
    assert scan.exit_code == 0, scan.output
    assert "3" in scan.output and "awaiting" in scan.output.lower()
    for aid in GATED:
        assert aid in scan.output, "a paused advisory is still shown in the scan table"

    listing = run("queue", "list")
    assert listing.exit_code == 0, listing.output
    for aid in GATED:
        assert aid in listing.output
    assert "cli-1" in listing.output


def test_queue_show_prints_the_evidence_bundle(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-2")
    shown = run("queue", "show", AUTH_ADVISORY)
    assert shown.exit_code == 0, shown.output
    assert AUTH_ADVISORY in shown.output
    assert "sensitive_tier:auth" in shown.output
    assert "pyjwt" in shown.output
    assert "justification" in shown.output.lower()
    assert "evidence" in shown.output.lower()


def test_approve_resumes_only_that_branch_and_writes_the_ledger(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-3")

    approved = run(
        "queue", "approve", AUTH_ADVISORY, "--reviewer", "alice", "--note", "evidence checked"
    )
    assert approved.exit_code == 0, approved.output
    assert AUTH_ADVISORY in approved.output

    listing = run("queue", "list")
    assert AUTH_ADVISORY not in listing.output
    for aid in GATED - {AUTH_ADVISORY}:
        assert aid in listing.output, "the other gates are untouched"

    with open_ledger(cli_env) as ledger:
        rows = ledger.list()
    assert [(r.advisory_id, r.reviewer, r.verdict, r.note) for r in rows] == [
        (AUTH_ADVISORY, "alice", "approve", "evidence checked")
    ]
    assert rows[0].scan_id == "cli-3"


def test_reject_is_recorded_too(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-4")
    rejected = run("queue", "reject", AUTH_ADVISORY, "--reviewer", "bob", "--note", "too risky")
    assert rejected.exit_code == 0, rejected.output

    with open_ledger(cli_env) as ledger:
        rows = ledger.list()
    assert (rows[0].verdict, rows[0].reviewer) == ("reject", "bob")


def test_a_decided_advisory_leaves_the_queue(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-5")
    assert run("queue", "show", AUTH_ADVISORY).exit_code == 0
    run("queue", "approve", AUTH_ADVISORY, "--reviewer", "alice")

    gone = run("queue", "show", AUTH_ADVISORY)
    assert gone.exit_code == 1
    assert "no pending" in gone.output.lower()
    assert AUTH_ADVISORY not in run("queue", "list", "--thread", "cli-5").output


def test_an_unknown_id_fails_cleanly(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-6")
    missing = run("queue", "show", "GHSA-does-not-exist")
    assert missing.exit_code == 1
    assert "no pending" in missing.output.lower()


def test_an_id_pending_in_two_scans_must_be_disambiguated(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-7a")
    run("scan", str(demo_app), "--thread", "cli-7b")

    ambiguous = run("queue", "approve", AUTH_ADVISORY, "--reviewer", "alice")
    assert ambiguous.exit_code == 1
    assert "cli-7a" in ambiguous.output and "cli-7b" in ambiguous.output

    ok = run("queue", "approve", AUTH_ADVISORY, "--thread", "cli-7b", "--reviewer", "alice")
    assert ok.exit_code == 0
    with open_ledger(cli_env) as ledger:
        assert [r.scan_id for r in ledger.list()] == ["cli-7b"]


def test_an_empty_queue_says_so(cli_env):
    listing = run("queue", "list")
    assert listing.exit_code == 0
    assert "no pending" in listing.output.lower()


def test_approving_every_gate_finishes_the_scan(cli_env, demo_app):
    run("scan", str(demo_app), "--thread", "cli-8")
    for aid in sorted(GATED):
        assert run("queue", "approve", aid, "--reviewer", "alice").exit_code == 0

    listing = run("queue", "list")
    assert "no pending" in listing.output.lower()

    rescan = run("queue", "list", "--thread", "cli-8")
    assert "no pending" in rescan.output.lower()
    with open_ledger(cli_env) as ledger:
        assert {r.advisory_id for r in ledger.list()} == GATED
