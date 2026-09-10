"""PatchPilot command line.

patchpilot scan <repo_path>            scan a repo; advisories that need a human pause durably
patchpilot scan <repo_path> --json     machine-readable output
patchpilot record <repo_path>          live mode + record fixtures (needs network)
patchpilot queue …                     review what the scan paused (cli/queue.py)

A scan writes its checkpoints to the store `storage/db.py` resolves (Postgres via DATABASE_URL,
otherwise a local SQLite file), so the queue commands are separate processes reading the same
durable state — the same relationship the worker and the approval API have in production.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from patchpilot.cli.queue import queue_app

app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(queue_app, name="queue")
console = Console(width=max(150, Console().width))


def build_repo_ref(repo_path: Path, repo_url: str | None = None):
    """Describe the scan target: where it is, what revision, and where its pull requests go.

    The remote is read from `<repo_path>/.git` only — never from a parent directory. A target that
    lives inside another repository (which is exactly where the demo app sits) must not inherit
    that repository's remote, or PatchPilot would open pull requests against its own source.
    `--repo-url` overrides whatever was found.
    """
    from patchpilot.graph.state import RepoRef
    from patchpilot.tools.checkout import normalise_remote_url, read_checkout

    resolved = repo_path.resolve()
    checkout = read_checkout(resolved)
    return RepoRef(
        path=str(resolved),
        url=normalise_remote_url(repo_url) if repo_url else checkout.url,
        default_branch=checkout.default_branch or "main",
        commit_sha=checkout.commit_sha,
    )


def _run_scan(
    repo_path: Path, thread_id: str | None = None, repo_url: str | None = None
) -> tuple[str, dict, list]:
    """Run one scan to completion or to its first set of human gates.

    Returns (scan_id, final state, gates still awaiting a human).
    """
    from patchpilot.graph.build import build_graph
    from patchpilot.graph.queue import pending_gates
    from patchpilot.storage.db import open_checkpointer

    scan_id = thread_id or str(uuid.uuid4())
    with open_checkpointer() as saver:
        graph = build_graph(saver)
        result = graph.invoke(
            {"scan_id": scan_id, "repo": build_repo_ref(repo_path, repo_url)},
            config={"configurable": {"thread_id": scan_id}},
        )
        gates = pending_gates(graph, scan_id)
    return scan_id, result, gates


def _paused_row(payload) -> object:
    """Render a branch that is parked at its human gate as an advisory row.

    Its writes have not reached the parent state yet — that is what "paused" means — so the scan
    table reads them back out of the interrupt payload instead.
    """
    from patchpilot.graph.state import AdvisoryState, Risk

    return AdvisoryState(
        advisory_id=payload.advisory_id,
        package=payload.package,
        installed_version=payload.installed_version,
        min_fixed_version=payload.min_fixed_version,
        bump_kind=payload.bump_kind,
        is_dev=payload.is_dev,
        cvss=payload.cvss,
        severity_label=payload.severity_label,
        epss=payload.epss,
        reachability=payload.reachability,
        risk=Risk(
            score=payload.risk_score,
            tier=payload.risk_tier,
            triggers=payload.triggers,
            package_tier=payload.package_tier,
        ),
        justification=payload.justification,
        justification_evidence=payload.justification_evidence,
        plan=payload.plan,
        sandbox=payload.sandbox,
        gate_triggers=payload.triggers,
    )


def _decision_label(a) -> str:
    if a.human:
        colour = "green" if a.human.verdict == "approve" else "red"
        return f"[{colour}]{a.human.verdict}d by {a.human.reviewer}[/{colour}]"
    if a.decision:
        colors = {"halted": "red", "not_applicable": "green", "accept_risk": "green"}
        return f"[{colors.get(a.decision, 'white')}]{a.decision}[/]"
    if a.risk and a.risk.triggers:
        return "[yellow]pending → needs_human[/yellow]"
    if a.risk:
        return "[cyan]pending → auto_fix?[/cyan]"
    return "-"


def _reach_label(a) -> str:
    r = a.reachability
    if a.decision == "halted":
        return "[red]halted[/red]"
    if r is None:
        return "-"
    if r.symbol_called:
        return "[red]REACHABLE[/red]" + ("" if r.imported else " (via re-export)")
    if not r.imported:
        return "[green]not imported[/green]"
    if r.symbol_called is None:
        return "[yellow]imported (no symbols)[/yellow]"
    return "[green]imported, not reached[/green]"


@app.command()
def scan(
    repo_path: Path = typer.Argument(
        ..., exists=True, file_okay=False, help="Path to a Python repo"
    ),
    as_json: bool = typer.Option(False, "--json", help="Print the final state as JSON"),
    mode: str | None = typer.Option(None, help="recorded | live (overrides PATCHPILOT_MODE)"),
    thread: str | None = typer.Option(
        None, "--thread", help="Scan id / checkpointer thread (default: a fresh UUID)"
    ),
    repo_url: str | None = typer.Option(
        None,
        "--repo-url",
        help="Where pull requests go, e.g. https://github.com/owner/repo. Defaults to the "
        "checkout's own origin remote; without either, PatchPilot plans but opens nothing.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print reasons and justifications"),
) -> None:
    if mode:
        os.environ["PATCHPILOT_MODE"] = mode
    scan_id, result, gates = _run_scan(repo_path, thread, repo_url)
    # A branch parked at its gate has published nothing back to the parent, so `advisories` still
    # holds that advisory as `ingest` left it. Show the reviewer what the branch actually knows.
    paused = {g.payload.advisory_id: _paused_row(g.payload) for g in gates}
    finished = [a for a in result.get("advisories", []) if a.advisory_id not in paused]
    advisories = [paused.get(a.advisory_id, a) for a in result.get("advisories", [])]
    seen = {a.advisory_id for a in advisories}
    advisories += [row for aid, row in paused.items() if aid not in seen]

    if as_json:
        payload = {
            "scan_id": scan_id,
            "summary": result["summary"].model_dump() if result.get("summary") else None,
            "data_freshness": result["data_freshness"].model_dump(mode="json")
            if result.get("data_freshness")
            else None,
            "advisories": [a.model_dump(mode="json") for a in finished],
            "awaiting_human": [g.payload.model_dump(mode="json") for g in gates],
            "errors": result.get("errors", []),
        }
        console.print_json(json.dumps(payload))
        return

    fresh = result.get("data_freshness")
    console.print(
        f"[bold]PatchPilot scan[/bold]  scan_id={scan_id}  repo={repo_path}  "
        f"mode={fresh.mode if fresh else '?'}  "
        f"deps={len(result.get('dependencies', []))}  advisories={len(advisories)}"
    )
    table = Table(show_lines=False, header_style="bold")
    table.add_column("advisory", no_wrap=True, min_width=20)
    table.add_column("package", min_width=16)
    for col in (
        "installed → fix",
        "bump",
        "cvss",
        "epss",
        "scope",
        "reachability",
        "score/tier",
        "decision",
        "gate triggers",
    ):
        table.add_column(col)
    for a in advisories:
        r = a.reachability
        awaiting = a.advisory_id in paused
        table.add_row(
            a.advisory_id,
            a.package,
            f"{a.installed_version} → "
            f"{(a.plan.target_version if a.plan else None) or a.min_fixed_version or '-'}",
            a.bump_kind or "-",
            f"{a.cvss:.1f}" if a.cvss is not None else (a.severity_label or "-"),
            f"{a.epss:.3f}" if a.epss is not None else "-",
            "dev" if a.is_dev else ("runtime" if r is None or r.is_runtime_dep else "test-only"),
            _reach_label(a),
            f"{a.risk.score:.1f} {a.risk.tier}" if a.risk else "-",
            "[yellow]awaiting human[/yellow]" if awaiting else _decision_label(a),
            ", ".join(a.gate_triggers or (a.risk.triggers if a.risk else [])),
        )
    console.print(table)
    if verbose:
        for a in advisories:
            console.print(f"\n[bold]{a.advisory_id}[/bold] ({a.package}) — {_decision_label(a)}")
            for reason in a.policy_reasons:
                console.print(f"  · {reason}")
            console.print(f"  [dim]justification:[/dim] {a.justification}")
            console.print(f"  [dim]cites:[/dim] {', '.join(a.justification_evidence)}")
            if a.human:
                console.print(
                    f"  [dim]human:[/dim] {a.human.verdict} by {a.human.reviewer} "
                    f"at {a.human.decided_at:%Y-%m-%d %H:%M:%SZ} — {a.human.note or 'no note'}"
                )
    if gates:
        console.print(
            f"[yellow]{len(gates)} advisory(ies) awaiting human approval[/yellow] — "
            f"run [bold]patchpilot queue list[/bold], then "
            f"[bold]patchpilot queue approve <advisory-id>[/bold]"
        )
    if result.get("summary"):
        console.print("summary:", result["summary"].counts)
    if result.get("budget"):
        b = result["budget"]
        console.print(f"llm budget: {b.tokens_used} tokens, ${b.usd_used:.4f}")
    for e in result.get("errors", []):
        console.print(f"[yellow]note[/yellow] {e}")


@app.command()
def record(
    repo_path: Path = typer.Argument(..., exists=True, file_okay=False),
) -> None:
    """Run in live mode and write every external response to the fixtures directory."""
    os.environ["PATCHPILOT_MODE"] = "live"
    os.environ["PATCHPILOT_RECORD"] = "1"
    from patchpilot.config import get_settings

    get_settings.cache_clear()
    _, result, gates = _run_scan(repo_path)
    console.print(
        f"recorded fixtures for {len(result.get('advisories', [])) + len(gates)} advisories under "
        f"{get_settings().fixtures_dir}"
    )


if __name__ == "__main__":
    app()
