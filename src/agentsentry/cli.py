from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from agentsentry.graph import scan_project
from agentsentry.models import SEVERITY_ORDER, Severity

app = typer.Typer(
    name="agentsentry",
    help="Deterministic capability and taint reachability analyzer for AI agents and MCP servers.",
    no_args_is_help=True,
)
console = Console()


class FailLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


@app.callback()
def main() -> None:
    """AgentSentry CLI."""


@app.command()
def scan(
    target: Path = typer.Argument(..., exists=True, help="Path to the AI agent or MCP server directory/file."),
    json_output: bool = typer.Option(False, "--json", help="Print full scan results as JSON."),
    fail_on: FailLevel = typer.Option(
        FailLevel.none,
        "--fail-on",
        help="Exit with code 1 if any finding meets or exceeds this severity.",
    ),
) -> None:
    """Scan an AI agent or MCP server for reachable capabilities and toxic tool chains."""
    result = scan_project(target)

    if json_output:
        typer.echo(result.model_dump_json(indent=2))
    else:
        score = result.blast_radius_score
        score_color = "red" if score >= 60 else "yellow" if score >= 25 else "green"
        console.print(
            Panel.fit(
                f"[bold cyan]AgentSentry[/bold cyan] | Target: [white]{result.target}[/white]\n"
                f"Files: [bold]{result.files_scanned}[/bold] | "
                f"Functions: [bold]{result.functions_parsed}[/bold] | "
                f"Call Edges: [bold]{result.call_edges}[/bold] | "
                f"Tools: [bold]{len(result.tools)}[/bold] | "
                f"Time: [bold]{result.scan_ms}ms[/bold] | "
                f"Blast Radius: [{score_color} bold]{score}/100[/{score_color} bold]"
            )
        )

        if not result.tools:
            console.print("[yellow]No agent tools (@tool, @mcp.tool, StructuredTool) detected.[/yellow]")
        else:
            tool_table = Table(title="Discovered Agent Tools", show_lines=True)
            tool_table.add_column("Tool", style="bold cyan")
            tool_table.add_column("Framework", style="dim")
            tool_table.add_column("Reachable Sinks", style="white")

            for report in result.tools:
                sink_lines: list[str] = []
                for h in report.hits:
                    badges: list[str] = []
                    if not h.tainted:
                        badges.append("[green]HARDCODED[/green]")
                    if h.guarded:
                        badges.append(f"[green]GUARDED: {h.guard_reason}[/green]")
                    badge_str = f" {' '.join(badges)}" if badges else ""
                    sink_lines.append(f"[yellow]{h.capability.value}[/yellow]: {' -> '.join(h.call_path)}{badge_str}")
                tool_table.add_row(
                    f"{report.tool.name}\n[dim]{report.tool.file}:{report.tool.line}[/dim]",
                    report.tool.framework,
                    "\n".join(sink_lines) or "[dim]No dangerous sinks[/dim]",
                )
            console.print(tool_table)

        if result.findings:
            finding_table = Table(title="Security Findings", show_lines=True)
            finding_table.add_column("Rule", style="bold")
            finding_table.add_column("Severity")
            finding_table.add_column("Finding & Recommendation", style="white")
            finding_table.add_column("Tools", style="cyan")

            for f in result.findings:
                color = SEVERITY_COLORS[f.severity]
                finding_table.add_row(
                    f.rule_id,
                    f"[{color}]{f.severity.value}[/{color}]",
                    f"[bold]{f.title}[/bold]\n{f.description}\n[dim]Fix: {f.recommendation}[/dim]",
                    ", ".join(f.tools),
                )
            console.print(finding_table)

            tree = Tree("[bold]Witness Attack Paths[/bold]")
            for f in result.findings:
                color = SEVERITY_COLORS[f.severity]
                branch = tree.add(f"[{color}]{f.rule_id}[/{color}] {f.title}")
                for wp in f.witness_paths:
                    branch.add(wp)
            console.print(tree)
        elif result.tools:
            console.print("[bold green]No unguarded security findings detected.[/bold green]")

    if fail_on != FailLevel.none:
        threshold = SEVERITY_ORDER[Severity(fail_on.value.upper())]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in result.findings):
            raise typer.Exit(code=1)
