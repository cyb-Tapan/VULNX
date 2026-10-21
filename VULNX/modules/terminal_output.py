"""
terminal_output.py

All user-facing terminal rendering lives here: banner, status lines,
findings, errors, and the final summary. VULNX never writes results to
disk — this module's only output surface is stdout via Rich.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from modules.models import Confidence, Finding, ScanStats, Severity

console = Console()

BANNER = r"""
__     ___   _ _     _   ___  __
\ \   / / | | | |   | \ | \ \/ /
 \ \ / /| | | | |   |  \| |\  /
  \ V / | |_| | |___| |\  |/  \
   \_/   \___/|_____|_| \_/_/\_\

          VULNX Web Security Assessment CLI
          Version 1.0.0  |  Author: cyb-Tapan
""".rstrip("\n")

AUTHORIZED_USE_NOTICE = (
    "Use only against systems you own or are explicitly, contractually "
    "authorized to test. --authorized is an acknowledgement of that fact, "
    "not proof of it. You are responsible for your own actions."
)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold magenta",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}


def print_banner() -> None:
    console.print(Text(BANNER, style="bold green"))
    console.print(f"[yellow]{AUTHORIZED_USE_NOTICE}[/yellow]\n")


def info(msg: str) -> None:
    console.print(f"[blue][INFO][/blue] {msg}")


def success(msg: str) -> None:
    console.print(f"[green][SUCCESS][/green] {msg}")


def open_port(msg: str) -> None:
    console.print(f"[green][OPEN][/green] {msg}")


def endpoint(msg: str) -> None:
    console.print(f"[cyan][ENDPOINT][/cyan] {msg}")


def found(msg: str) -> None:
    console.print(f"[yellow][FOUND][/yellow] {msg}")


def warning(msg: str) -> None:
    console.print(f"[yellow][WARNING][/yellow] {msg}")


def error(msg: str) -> None:
    console.print(f"[red][ERROR][/red] {msg}")


def skipped(msg: str) -> None:
    console.print(f"[dim][SKIPPED][/dim] {msg}")


def print_finding(f: Finding) -> None:
    style = _SEVERITY_STYLE.get(f.severity, "white")
    console.print(f"\n[{style}][FOUND][/{style}] {f.category}")
    console.print(f"  URL: {f.affected_url}")
    if f.parameter:
        console.print(f"  Parameter: {f.parameter}")
    if f.http_method:
        console.print(f"  Method: {f.http_method}")
    console.print(f"  Severity: [{style}]{f.severity.value}[/{style}]")
    console.print(f"  Confidence: {f.confidence.value}")
    console.print(f"  Status: {f.status.value}")
    if f.evidence:
        console.print(f"  Evidence: {f.evidence}")
    console.print(f"  Remediation: {f.remediation}")
    if f.note:
        console.print(f"  Note: {f.note}")


def print_summary(stats: ScanStats, target: str) -> None:
    console.print("\n[bold]\\[SUMMARY][/bold] Scan " + ("interrupted" if stats.interrupted else "finished"))
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_row("Target", target)
    table.add_row("Ports discovered", str(stats.ports_discovered))
    table.add_row("Pages inspected", str(stats.pages_inspected))
    table.add_row("Endpoints discovered", str(stats.endpoints_discovered))
    table.add_row("Requests sent", str(stats.requests_sent))
    table.add_row("Findings (total)", str(stats.findings_total))
    table.add_row("  Verified", str(stats.findings_verified))
    table.add_row("  Potential", str(stats.findings_potential))
    table.add_row("  Inconclusive", str(stats.findings_inconclusive))
    table.add_row("Modules run", ", ".join(stats.modules_run) or "none")
    table.add_row("Modules skipped", ", ".join(stats.modules_skipped) or "none")
    table.add_row("Modules failed", ", ".join(stats.modules_failed) or "none")
    console.print(table)
    if stats.interrupted:
        console.print(
            "[yellow]This scan was interrupted before completion. Counts above "
            "reflect only work actually performed.[/yellow]"
        )
