"""Terminal reporter — Rich when available, plain text otherwise.

Degrades cleanly when stdout isn't a TTY or `NO_COLOR` is set. Output is
copy-pasteable and asciinema-recordable — no spinners, no alt-screen buffer.
"""

from __future__ import annotations

import os
import sys
from typing import IO

from ..models import ScoreCard

try:
    from rich.console import Console
    from rich.table import Table

    _rich_available = True
except ImportError:  # pragma: no cover
    _rich_available = False


_NOT_EVALUATED = (
    "tool authorization, correctness, cost, latency, reliability,\n"
    "  tenant isolation, availability, data retention"
)


def _use_color(stream: IO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def render(scorecard: ScoreCard, stream: IO = sys.stdout) -> None:
    if _rich_available and _use_color(stream):
        _render_rich(scorecard, stream)
    else:
        _render_plain(scorecard, stream)


def _render_exposure_section_plain(sc: ScoreCard, stream: IO) -> None:
    if sc.mcp_exposure is None or not sc.mcp_exposure.servers:
        return
    p = lambda *args: print(*args, file=stream)
    p("MCP Exposure Evidence")
    for srv in sc.mcp_exposure.servers:
        if srv.error:
            p(f"  {srv.server_name}: ERROR — {srv.error}")
            continue
        p(f"  server: {srv.server_name}")
        p(f"    tools enumerated                            {srv.tools_enumerated}")
        p(f"    write-capable tools                         {len(srv.tools_write_capable):<3} {_names(srv.tools_write_capable)}")
        p(f"    network-capable tools                       {len(srv.tools_network_capable):<3} {_names(srv.tools_network_capable)}")
        p(f"    tools with untrusted-instruction patterns   {len(srv.tools_with_untrusted_instructions):<3} {_names(srv.tools_with_untrusted_instructions)}")
        p(f"    resources scanned                           {srv.resources_scanned}")
        p(f"    resources containing injection patterns     {len(srv.resources_with_injection):<3} {_names(srv.resources_with_injection)}")
    p()


def _render_exposure_section_rich(sc: ScoreCard, console) -> None:
    if sc.mcp_exposure is None or not sc.mcp_exposure.servers:
        return
    console.print("[bold]MCP Exposure Evidence[/bold]")
    for srv in sc.mcp_exposure.servers:
        if srv.error:
            console.print(f"  [red]{srv.server_name}[/red]: ERROR — {srv.error}")
            continue
        console.print(f"  server: [cyan]{srv.server_name}[/cyan]")
        console.print(f"    tools enumerated                            {srv.tools_enumerated}")
        console.print(
            f"    write-capable tools                         "
            f"[yellow]{len(srv.tools_write_capable)}[/yellow]  {_names(srv.tools_write_capable)}"
        )
        console.print(
            f"    network-capable tools                       "
            f"[yellow]{len(srv.tools_network_capable)}[/yellow]  {_names(srv.tools_network_capable)}"
        )
        console.print(
            f"    tools with untrusted-instruction patterns   "
            f"[red]{len(srv.tools_with_untrusted_instructions)}[/red]  {_names(srv.tools_with_untrusted_instructions)}"
        )
        console.print(f"    resources scanned                           {srv.resources_scanned}")
        console.print(
            f"    resources containing injection patterns     "
            f"[red]{len(srv.resources_with_injection)}[/red]  {_names(srv.resources_with_injection)}"
        )
    console.print()


def _names(items: list[str]) -> str:
    if not items:
        return ""
    return f"({', '.join(items[:6])}{'...' if len(items) > 6 else ''})"


def _render_rich(sc: ScoreCard, stream: IO) -> None:
    console = Console(file=stream, force_terminal=True, highlight=False)
    console.print(
        f"[bold]ContextWall Preflight[/bold]  — suite: {sc.assessment.suite}@{sc.assessment.suite_version}"
    )
    console.print(
        f"Adapter: {sc.assessment.adapter}    Assessment mode: "
        f"[magenta]{sc.assessment.mode.upper()}[/magenta]"
    )
    console.print("Assessment scope: SAFETY ONLY\n")

    _render_exposure_section_rich(sc, console)

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Dimension", style="cyan", no_wrap=True)
    table.add_column("Grade", style="yellow")
    table.add_column("Raw", style="dim")
    for name, dim in sc.dimensions.items():
        if dim.grade == "N/A":
            raw = "insufficient evidence (adapter cannot observe this dimension)"
        else:
            raw = f"{dim.passed}/{dim.total} cases passed in pinned suite"
            if dim.sample_size_warning:
                raw += "  (small-sample: one fixture flips grade)"
        table.add_row(_pretty(name), dim.grade, raw)
    console.print(table)
    console.print()

    gate_color = {
        "pass": "green",
        "blocked": "red",
        "insufficient_evidence": "yellow",
        "adapter_error": "red",
        "invalid_target": "red",
        "advisory": "blue",
    }.get(sc.gate.status.value, "white")
    console.print(f"Release gate: [{gate_color}]{sc.gate.status.value.upper()}[/{gate_color}]")
    if sc.gate.blocking_failures:
        console.print(f"  Policy: {sc.gate.policy} (min grade {sc.gate.minimum_grade})")
        for f in sc.gate.blocking_failures:
            console.print(f"  [red]x[/red] {f.id}: {f.reason.replace('_', ' ')}")

    console.print("\n[bold]Not evaluated:[/bold]")
    console.print(f"  {_NOT_EVALUATED}\n")

    console.print(f"[bold]Assessment boundary ({sc.assessment.adapter}):[/bold]")
    console.print(f"  Observed:     {', '.join(sc.evidence_boundary.observed)}")
    console.print(f"  Not observed: {', '.join(sc.evidence_boundary.not_observed)}")


def _render_plain(sc: ScoreCard, stream: IO) -> None:
    def p(*args) -> None:
        print(*args, file=stream)

    p(f"ContextWall Preflight — suite: {sc.assessment.suite}@{sc.assessment.suite_version}")
    p(f"Adapter: {sc.assessment.adapter}    Assessment mode: {sc.assessment.mode.upper()}")
    p("Assessment scope: SAFETY ONLY")
    p()
    _render_exposure_section_plain(sc, stream)
    for name, dim in sc.dimensions.items():
        if dim.grade == "N/A":
            raw = "insufficient evidence"
        else:
            raw = f"{dim.passed}/{dim.total} cases passed in pinned suite"
            if dim.sample_size_warning:
                raw += "  (small-sample: one fixture flips grade)"
        p(f"  {_pretty(name):30s} {dim.grade:5s}  {raw}")
    p()
    p(f"Release gate: {sc.gate.status.value.upper()}")
    if sc.gate.blocking_failures:
        p(f"  Policy: {sc.gate.policy} (min grade {sc.gate.minimum_grade})")
        for f in sc.gate.blocking_failures:
            p(f"  x {f.id}: {f.reason.replace('_', ' ')}")
    p()
    p("Not evaluated:")
    p(f"  {_NOT_EVALUATED}")
    p()
    p(f"Assessment boundary ({sc.assessment.adapter}):")
    p(f"  Observed:     {', '.join(sc.evidence_boundary.observed)}")
    p(f"  Not observed: {', '.join(sc.evidence_boundary.not_observed)}")


def _pretty(name: str) -> str:
    words = {
        "injection": "Injection Resistance",
        "grounding": "Grounding Under Attack",
        "exfiltration": "Data Exfiltration",
    }
    return words.get(name, name.replace("_", " ").title())
