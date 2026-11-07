"""Command Line Interface for mcpscan."""

import asyncio
import sys
from typing import Optional
import typer
from rich.console import Console
from rich.panel import Panel

from mcpscan import __version__
from mcpscan.connector import MCPConnector, MCPConnectorError
from mcpscan.engine import SecurityEngine
from mcpscan.reporters.terminal import TerminalReporter
from mcpscan.reporters.sarif import SarifReporter

app = typer.Typer(
    name="mcpscan",
    help="Industrial-grade security posture analyzer and vulnerability scanner for MCP servers.",
    add_completion=False,
)
console = Console()
reporter = TerminalReporter(console)
sarif_reporter = SarifReporter()
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

    # Execute Security Audit
    report = engine.audit(manifest)

    # Render Terminal Report
    reporter.render(report)

    # Export SARIF if requested
    if sarif_output:
        try:
            sarif_reporter.save(report, sarif_output)
            console.print(f"[bold green]✓[/bold green] SARIF 2.1.0 report exported to: [bold cyan]{sarif_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write SARIF report:[/bold red] {str(e)}")

    # Check CI/CD Threshold
    if report.score < fail_under:
        console.print(
            f"[bold red]CI/CD Gate Failed:[/bold red] Score [bold]{report.score}[/bold] is below threshold of [bold]{fail_under}[/bold].\n"
        )
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
