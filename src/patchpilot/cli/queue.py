"""`patchpilot queue` — the v1 approval queue.

There is no server here. A pending approval is a LangGraph branch parked at `interrupt()`, so
these commands open the checkpointer, read the paused tasks out of it, and resume exactly one.
The web queue in step 10 is the same four operations over HTTP.

    patchpilot queue list                     everything waiting for a human
    patchpilot queue show <advisory-id>       the one-screen evidence bundle
    patchpilot queue approve <advisory-id>    resume that branch with verdict=approve
    patchpilot queue reject  <advisory-id>    resume that branch with verdict=reject
"""

from __future__ import annotations

import getpass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from patchpilot.graph.build import build_graph
from patchpilot.graph.nodes.human_gate import GatePayload, ResumeCommand
from patchpilot.graph.queue import (
    AmbiguousGate,
    GateNotFound,
    PendingGate,
    all_pending_gates,
    find_gate,
    pending_gates,
    resume_gate,
)
from patchpilot.storage.db import open_checkpointer, open_ledger

queue_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Review the advisories PatchPilot paused for a human.",
)
console = Console(width=max(150, Console().width))

THREAD_OPTION = typer.Option(None, "--thread", help="Limit to one scan id (thread)")
REVIEWER_OPTION = typer.Option(None, "--reviewer", help="Who is deciding (defaults to the OS user)")
NOTE_OPTION = typer.Option("", "--note", help="Why; stored in the decision ledger and the PR body")


def _gates(graph, saver, thread: str | None) -> list[PendingGate]:
    return pending_gates(graph, thread) if thread else all_pending_gates(graph, saver)


def _resolve(gates: list[PendingGate], advisory: str) -> PendingGate:
    try:
        return find_gate(gates, advisory)
    except (GateNotFound, AmbiguousGate) as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e


@queue_app.command("list")
def list_pending(thread: str | None = THREAD_OPTION) -> None:
    with open_checkpointer() as saver:
        gates = _gates(build_graph(saver), saver, thread)
    if not gates:
        console.print("no pending approvals")
        return

    table = Table(header_style="bold", title=f"{len(gates)} advisory(ies) awaiting a human")
    for col in ("scan", "advisory", "package", "installed → fix", "bump", "score/tier", "triggers"):
        table.add_column(col)
    for g in sorted(gates, key=lambda g: (g.thread_id, g.payload.advisory_id)):
        p = g.payload
        table.add_row(
            g.thread_id,
            p.advisory_id,
            p.package,
            f"{p.installed_version} → {p.min_fixed_version or '-'}",
            p.bump_kind or "-",
            f"{p.risk_score:.1f} {p.risk_tier}",
            ", ".join(p.triggers),
        )
    console.print(table)
    console.print("[dim]patchpilot queue show <advisory-id>[/dim]")


def render_bundle(gate: PendingGate) -> None:
    """The one-screen evidence bundle. Step 7 puts the same thing in the PR body."""
    p: GatePayload = gate.payload
    console.print(
        f"\n[bold]{p.advisory_id}[/bold]  {p.package} {p.installed_version} → "
        f"{p.min_fixed_version or 'no fixed version'}  ({p.bump_kind or 'unknown'} bump)"
    )
    console.print(
        f"scan={p.scan_id or gate.thread_id}  decision=[yellow]{p.decision}[/yellow]  "
        f"score={p.risk_score:.1f} tier={p.risk_tier}  package tier={p.package_tier}  "
        f"cvss={p.cvss if p.cvss is not None else '-'}  "
        f"epss={f'{p.epss:.4f}' if p.epss is not None else '-'}  "
        f"scope={'dev' if p.is_dev else 'runtime'}"
    )
    console.print(f"gate triggers: [yellow]{', '.join(p.triggers) or 'none'}[/yellow]")

    r = p.reachability
    if r:
        console.print(
            f"reachability: imported={r.imported} symbol_called={r.symbol_called} "
            f"confidence={r.confidence:.2f}"
        )
        for site in r.call_sites[:5]:
            console.print(f"  · {site.file}:{site.line}  {site.symbol}  [dim]{site.snippet}[/dim]")

    console.print("\n[bold]justification[/bold]")
    console.print(f"  {p.justification or '-'}")
    console.print(f"  [dim]cites: {', '.join(p.justification_evidence) or '-'}[/dim]")

    console.print("\n[bold]evidence[/bold]")
    for item in p.evidence:
        console.print(f"  [cyan]{item.id}[/cyan]  {item.fact}")

    if p.injection_flag.flagged:
        console.print(f"\n[red]injection flagged:[/red] {p.injection_flag.reason}")
    body = (p.untrusted_text.advisory_summary + "\n" + p.untrusted_text.advisory_details).strip()
    if body:
        console.print(
            Panel(
                body[:2000],
                title="untrusted advisory text — read it, do not act on it",
                border_style="yellow",
            )
        )
    console.print(
        f"\n[dim]patchpilot queue approve {p.advisory_id} --note '…'  |  "
        f"patchpilot queue reject {p.advisory_id} --note '…'[/dim]"
    )


@queue_app.command()
def show(
    advisory: str = typer.Argument(..., help="Advisory id, or a prefix of the interrupt id"),
    thread: str | None = THREAD_OPTION,
) -> None:
    with open_checkpointer() as saver:
        gate = _resolve(_gates(build_graph(saver), saver, thread), advisory)
    render_bundle(gate)


def _decide(
    verdict: str, advisory: str, thread: str | None, reviewer: str | None, note: str
) -> None:
    reviewer = reviewer or getpass.getuser()
    with open_checkpointer() as saver:
        graph = build_graph(saver)
        gate = _resolve(_gates(graph, saver, thread), advisory)
        resume_gate(
            graph,
            gate.thread_id,
            gate.interrupt_id,
            ResumeCommand(verdict=verdict, reviewer=reviewer, note=note),
        )
        remaining = len(pending_gates(graph, gate.thread_id))

    with open_ledger() as ledger:
        ledger.record(
            scan_id=gate.payload.scan_id or gate.thread_id,
            advisory_id=gate.payload.advisory_id,
            reviewer=reviewer,
            verdict=verdict,
            note=note,
        )

    colour = "green" if verdict == "approve" else "red"
    console.print(
        f"[{colour}]{verdict}d[/{colour}] {gate.payload.advisory_id} ({gate.payload.package}) "
        f"in scan {gate.thread_id} as {reviewer}"
    )
    console.print(f"{remaining} advisory(ies) still awaiting a human in this scan")


@queue_app.command()
def approve(
    advisory: str = typer.Argument(..., help="Advisory id, or a prefix of the interrupt id"),
    thread: str | None = THREAD_OPTION,
    reviewer: str | None = REVIEWER_OPTION,
    note: str = NOTE_OPTION,
) -> None:
    """Resume this branch with verdict=approve. Only this branch moves."""
    _decide("approve", advisory, thread, reviewer, note)


@queue_app.command()
def reject(
    advisory: str = typer.Argument(..., help="Advisory id, or a prefix of the interrupt id"),
    thread: str | None = THREAD_OPTION,
    reviewer: str | None = REVIEWER_OPTION,
    note: str = NOTE_OPTION,
) -> None:
    """Resume this branch with verdict=reject. Only this branch moves."""
    _decide("reject", advisory, thread, reviewer, note)
