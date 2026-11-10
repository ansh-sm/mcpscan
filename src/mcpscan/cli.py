"""Command Line Interface for mcpscan."""

import asyncio
import sys
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpscan import __version__
from mcpscan.connector import MCPConnector, MCPConnectorError
from mcpscan.engine import SecurityEngine
from mcpscan.reporters.terminal import TerminalReporter
from mcpscan.reporters.sarif import SarifReporter
from mcpscan.reporters.json_reporter import JsonReporter
from mcpscan.reporters.html_reporter import HtmlReporter
from mcpscan.reporters.markdown_reporter import MarkdownReporter

app = typer.Typer(
    name="mcpscan",
    help="Industrial-grade security posture analyzer and vulnerability scanner for MCP servers.",
    add_completion=False,
)
console = Console()
reporter = TerminalReporter(console)
sarif_reporter = SarifReporter()
json_reporter = JsonReporter()
html_reporter = HtmlReporter()
markdown_reporter = MarkdownReporter()
engine = SecurityEngine()


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]mcpscan[/bold cyan] version [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show mcpscan version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """MCP Server Security Posture Scanner."""
    pass


@app.command()
def scan(
    command: Optional[str] = typer.Option(
        None,
        "--command",
        "-c",
        help="Command to spawn target MCP server over stdio (e.g. 'python server.py' or 'node build/index.js').",
    ),
    sse_url: Optional[str] = typer.Option(
        None,
        "--sse",
        help="Remote SSE endpoint URL of target MCP server (e.g. 'http://localhost:8000/sse').",
    ),
    sarif_output: Optional[str] = typer.Option(
        None,
        "--sarif",
        "-s",
        help="Path to export OASIS SARIF 2.1.0 security report.",
    ),
    json_output: Optional[str] = typer.Option(
        None,
        "--json",
        "-j",
        help="Path to export raw JSON security report.",
    ),
    html_output: Optional[str] = typer.Option(
        None,
        "--html",
        "-H",
        help="Path to export visual HTML security report dashboard.",
    ),
    markdown_output: Optional[str] = typer.Option(
        None,
        "--markdown",
        "-M",
        help="Path to export portable Markdown security report (PR comments, Slack sharing).",
    ),
    timeout: int = typer.Option(
        15,
        "--timeout",
        "-t",
        help="Connection and enumeration timeout in seconds.",
    ),
    fail_under: int = typer.Option(
        70,
        "--fail-under",
        help="Exit with non-zero exit code if score falls below this threshold (for CI/CD gates).",
    ),
    select_rules: Optional[str] = typer.Option(
        None,
        "--select",
        help="Comma-separated list of Rule IDs to execute (e.g. 'MCP-SEC-001,MCP-SEC-002').",
    ),
    ignore_rules: Optional[str] = typer.Option(
        None,
        "--ignore",
        help="Comma-separated list of Rule IDs to skip.",
    ),
):
    """Scan an MCP server over stdio or SSE and audit its security posture."""
    if not command and not sse_url:
        console.print(
            Panel(
                "[bold red]Error:[/bold red] You must specify a target server via [bold yellow]--command[/bold yellow] (stdio) "
                "or [bold yellow]--sse[/bold yellow] (HTTP/SSE).",
                title="[bold red]Missing Target[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    target_str = command if command else sse_url
    transport_type = "stdio" if command else "SSE"

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target_str}\n"
            f"[bold cyan]Transport:[/bold cyan] {transport_type}\n"
            f"[bold cyan]Timeout:[/bold cyan] {timeout}s",
            title="[bold green]mcpscan Security Audit[/bold green]",
            border_style="cyan",
        )
    )

    console.print("[dim]Connecting and negotiating capabilities...[/dim]")

    connector = MCPConnector(timeout=float(timeout))
    try:
        if command:
            manifest = asyncio.run(connector.connect_stdio(command))
        elif sse_url:
            manifest = asyncio.run(connector.connect_sse(sse_url))
        else:
            console.print("[bold red]Error: No valid transport specified.[/bold red]")
            raise typer.Exit(code=1)
    except MCPConnectorError as e:
        console.print(Panel(f"[bold red]Connection Error:[/bold red] {str(e)}", border_style="red"))
        raise typer.Exit(code=1)

    # Parse rule filters
    enabled_list = [r.strip() for r in select_rules.split(",") if r.strip()] if select_rules else None
    disabled_list = [r.strip() for r in ignore_rules.split(",") if r.strip()] if ignore_rules else None

    # Execute Security Audit
    report = engine.audit(
        manifest,
        enabled_rules=enabled_list,
        disabled_rules=disabled_list,
    )

    # Render Terminal Report
    reporter.render(report)

    # Export SARIF if requested
    if sarif_output:
        try:
            sarif_reporter.save(report, sarif_output)
            console.print(f"[bold green]✓[/bold green] SARIF 2.1.0 report exported to: [bold cyan]{sarif_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write SARIF report:[/bold red] {str(e)}")

    # Export JSON if requested
    if json_output:
        try:
            json_reporter.save(report, json_output)
            console.print(f"[bold green]✓[/bold green] JSON report exported to: [bold cyan]{json_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write JSON report:[/bold red] {str(e)}")

    # Export HTML if requested
    if html_output:
        try:
            html_reporter.save(report, html_output)
            console.print(f"[bold green]✓[/bold green] Visual HTML Dashboard exported to: [bold cyan]{html_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write HTML report:[/bold red] {str(e)}")

    # Export Markdown if requested
    if markdown_output:
        try:
            markdown_reporter.save(report, markdown_output)
            console.print(f"[bold green]✓[/bold green] Markdown report exported to: [bold cyan]{markdown_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write Markdown report:[/bold red] {str(e)}")

    # Check CI/CD Threshold
    if report.score < fail_under:
        console.print(
            f"[bold red]CI/CD Gate Failed:[/bold red] Score [bold]{report.score}[/bold] is below threshold of [bold]{fail_under}[/bold].\n"
        )
        raise typer.Exit(code=2)


@app.command("list-rules")
def list_rules():
    """Display all registered security rules with their IDs, severity, and descriptions."""
    from mcpscan.rules import registry

    table = Table(
        title="mcpscan Registered Security Rules",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold yellow", width=14)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Title", style="bold white", min_width=30)
    table.add_column("CWE", style="dim", width=18)
    table.add_column("OWASP LLM", style="dim", width=14)

    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }

    for rule in registry.registered_rules:
        sev_style = severity_styles.get(rule.severity.value, "white")
        table.add_row(
            rule.rule_id,
            f"[{sev_style}]{rule.severity.value}[/{sev_style}]",
            rule.title,
            rule.cwe.split(":")[0] if rule.cwe else "—",
            rule.owasp_llm.split(":")[0] if rule.owasp_llm else "—",
        )

    console.print()
    console.print(table)
    console.print(f"\n[dim]Total: {len(registry.registered_rules)} rules registered[/dim]\n")


if __name__ == "__main__":
    app()
