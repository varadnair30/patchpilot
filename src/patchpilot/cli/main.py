"""PatchPilot command line.

patchpilot scan <repo_path>            run ingest + reachability, print the table
patchpilot scan <repo_path> --json     machine-readable output
patchpilot record <repo_path>          live mode + record fixtures (needs network)
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console(width=max(150, Console().width))


def _run_scan(repo_path: Path, thread_id: str | None = None) -> dict:
    from patchpilot.graph.build import build_graph
    from patchpilot.graph.state import RepoRef

    graph = build_graph()
    scan_id = thread_id or str(uuid.uuid4())
    result = graph.invoke(
        {"scan_id": scan_id, "repo": RepoRef(path=str(repo_path.resolve()))},
        config={"configurable": {"thread_id": scan_id}},
    )
    return result


def _decision_label(a) -> str:
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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print reasons and justifications"),
) -> None:
    if mode:
        os.environ["PATCHPILOT_MODE"] = mode
    result = _run_scan(repo_path)
    advisories = result.get("advisories", [])

    if as_json:
        payload = {
            "scan_id": result.get("scan_id"),
            "summary": result["summary"].model_dump() if result.get("summary") else None,
            "data_freshness": result["data_freshness"].model_dump(mode="json")
            if result.get("data_freshness")
            else None,
            "advisories": [a.model_dump(mode="json") for a in advisories],
            "errors": result.get("errors", []),
        }
        console.print_json(json.dumps(payload))
        return

    fresh = result.get("data_freshness")
    console.print(
        f"[bold]PatchPilot scan[/bold]  repo={repo_path}  mode={fresh.mode if fresh else '?'}  "
        f"deps={len(result.get('dependencies', []))}  advisories={len(advisories)}"
    )
    table = Table(show_lines=False, header_style="bold")
    for col in (
        "advisory",
        "package",
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
        table.add_row(
            a.advisory_id,
            a.package,
            f"{a.installed_version} → {a.min_fixed_version or '-'}",
            a.bump_kind or "-",
            f"{a.cvss:.1f}" if a.cvss is not None else (a.severity_label or "-"),
            f"{a.epss:.3f}" if a.epss is not None else "-",
            "dev" if a.is_dev else ("runtime" if r is None or r.is_runtime_dep else "test-only"),
            _reach_label(a),
            f"{a.risk.score:.1f} {a.risk.tier}" if a.risk else "-",
            _decision_label(a),
            ", ".join(a.risk.triggers) if a.risk and a.risk.triggers else "",
        )
    console.print(table)
    if verbose:
        for a in advisories:
            console.print(f"\n[bold]{a.advisory_id}[/bold] ({a.package}) — {_decision_label(a)}")
            for reason in a.policy_reasons:
                console.print(f"  · {reason}")
            console.print(f"  [dim]justification:[/dim] {a.justification}")
            console.print(f"  [dim]cites:[/dim] {', '.join(a.justification_evidence)}")
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
    result = _run_scan(repo_path)
    console.print(
        f"recorded fixtures for {len(result.get('advisories', []))} advisories under "
        f"{get_settings().fixtures_dir}"
    )


if __name__ == "__main__":
    app()
