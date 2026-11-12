"""Command Line Interface for mcpscan."""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcpscan import __version__
from mcpscan.config import compute_finding_fingerprint, load_config
from mcpscan.connector import MCPConnector, MCPConnectorError
from mcpscan.diff import compute_diff, load_report_from_file
from mcpscan.engine import SecurityEngine
from mcpscan.reporters.html_reporter import HtmlReporter
from mcpscan.reporters.json_reporter import JsonReporter
from mcpscan.reporters.markdown_diff import MarkdownDiffReporter
from mcpscan.reporters.markdown_reporter import MarkdownReporter
from mcpscan.reporters.sarif import SarifReporter
from mcpscan.reporters.terminal import TerminalReporter
from mcpscan.reporters.terminal_diff import TerminalDiffReporter

app = typer.Typer(
    name="mcpscan",
    help="Security posture analyzer and vulnerability scanner for MCP servers.",
    add_completion=False,
)
console = Console()
reporter = TerminalReporter(console)
terminal_diff_reporter = TerminalDiffReporter(console)
markdown_diff_reporter = MarkdownDiffReporter()
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
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show mcpscan version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
):
    """MCP Server Security Posture Scanner."""


@app.command()
def scan(
    command: str | None = typer.Option(
        None,
        "--command",
        "-c",
        help="Command to spawn target MCP server over stdio (e.g. 'python server.py' or 'node build/index.js').",
    ),
    sse_url: str | None = typer.Option(
        None,
        "--sse",
        help="Remote SSE endpoint URL of target MCP server (e.g. 'http://localhost:8000/sse').",
    ),
    sarif_output: str | None = typer.Option(
        None,
        "--sarif",
        "-s",
        help="Path to export OASIS SARIF 2.1.0 security report.",
    ),
    json_output: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="Path to export raw JSON security report.",
    ),
    html_output: str | None = typer.Option(
        None,
        "--html",
        "-H",
        help="Path to export visual HTML security report dashboard.",
    ),
    markdown_output: str | None = typer.Option(
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
    select_rules: str | None = typer.Option(
        None,
        "--select",
        help="Comma-separated list of Rule IDs to execute (e.g. 'MCP-SEC-001,MCP-SEC-002').",
    ),
    ignore_rules: str | None = typer.Option(
        None,
        "--ignore",
        help="Comma-separated list of Rule IDs to skip.",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-C",
        help="Path to .mcpscan.yml configuration file.",
    ),
):
    """Scan an MCP server over stdio or SSE and audit its security posture."""
    if command and sse_url:
        raise typer.BadParameter("Choose only one target: --command or --sse.")
    if not command and not sse_url:
        raise typer.BadParameter("Specify a target using --command or --sse.")
    if timeout <= 0:
        raise typer.BadParameter("--timeout must be greater than zero.")

    # Load configuration (.mcpscan.yml)
    try:
        cfg = load_config(explicit_path=config_file)
    except FileNotFoundError as e:
        console.print(f"[bold red]Config file error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        raise typer.Exit(code=1)

    # CLI flags override config defaults
    effective_timeout = timeout if timeout != 15 or not config_file else cfg.timeout
    effective_fail_under = fail_under if fail_under != 70 or not config_file else cfg.fail_under

    sarif_output = sarif_output or cfg.output.sarif
    json_output = json_output or cfg.output.json
    html_output = html_output or cfg.output.html
    markdown_output = markdown_output or cfg.output.markdown

    # Active finding suppressions
    suppressed_fps = {s.fingerprint for s in cfg.suppress if not s.is_expired}

    target_str = command if command else sse_url
    transport_type = "stdio" if command else "SSE"

    console.print(
        Panel(
            f"[bold cyan]Target:[/bold cyan] {target_str}\n"
            f"[bold cyan]Transport:[/bold cyan] {transport_type}\n"
            f"[bold cyan]Timeout:[/bold cyan] {effective_timeout}s",
            title="[bold green]mcpscan Security Audit[/bold green]",
            border_style="cyan",
        )
    )

    console.print("[dim]Connecting and negotiating capabilities...[/dim]")

    connector = MCPConnector(timeout=float(effective_timeout))
    try:
        if command:
            manifest = asyncio.run(connector.connect_stdio(command))
        elif sse_url:
            manifest = asyncio.run(connector.connect_sse(sse_url))
        else:
            console.print("[bold red]Error: No valid transport specified.[/bold red]")
            raise typer.Exit(code=1)
    except MCPConnectorError as e:
        console.print(Panel(f"[bold red]Connection Error:[/bold red] {e!s}", border_style="red"))
        raise typer.Exit(code=1)

    # Parse rule filters (CLI takes precedence over config)
    if select_rules:
        enabled_list = [r.strip() for r in select_rules.split(",") if r.strip()]
    elif cfg.select:
        enabled_list = cfg.select
    else:
        enabled_list = None

    if ignore_rules:
        disabled_list = [r.strip() for r in ignore_rules.split(",") if r.strip()]
    elif cfg.ignore:
        disabled_list = cfg.ignore
    else:
        disabled_list = None

    # Execute Security Audit
    report = engine.audit(
        manifest,
        enabled_rules=enabled_list,
        disabled_rules=disabled_list,
        suppressed_fingerprints=suppressed_fps,
    )

    # Render Terminal Report
    reporter.render(report)

    export_failed = False

    # Export SARIF if requested
    if sarif_output:
        try:
            sarif_reporter.save(report, sarif_output)
            console.print(f"[bold green]✓[/bold green] SARIF 2.1.0 report exported to: [bold cyan]{sarif_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write SARIF report:[/bold red] {e!s}")
            export_failed = True

    # Export JSON if requested
    if json_output:
        try:
            json_reporter.save(report, json_output)
            console.print(f"[bold green]✓[/bold green] JSON report exported to: [bold cyan]{json_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write JSON report:[/bold red] {e!s}")
            export_failed = True

    # Export HTML if requested
    if html_output:
        try:
            html_reporter.save(report, html_output)
            console.print(f"[bold green]✓[/bold green] Visual HTML Dashboard exported to: [bold cyan]{html_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write HTML report:[/bold red] {e!s}")
            export_failed = True

    # Export Markdown if requested
    if markdown_output:
        try:
            markdown_reporter.save(report, markdown_output)
            console.print(f"[bold green]✓[/bold green] Markdown report exported to: [bold cyan]{markdown_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write Markdown report:[/bold red] {e!s}")
            export_failed = True

    if export_failed:
        console.print("[bold red]One or more requested reports failed to export.[/bold red]")
        raise typer.Exit(code=1)

    # Warn if scan was incomplete
    if not report.scan_complete:
        console.print(
            "[bold red]Scan incomplete. Do not treat this result as a clean scan.[/bold red]"
        )
        for error in report.scan_errors:
            console.print(f"  - {error}")
        raise typer.Exit(code=3)

    # Check CI/CD Threshold
    if report.score < effective_fail_under:
        console.print(
            f"[bold red]CI/CD Gate Failed:[/bold red] Score [bold]{report.score}[/bold] is below threshold of [bold]{effective_fail_under}[/bold].\n"
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
    table.add_column("Confidence", justify="center", width=12)
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
    confidence_styles = {
        "HIGH": "bold green",
        "MEDIUM": "yellow",
        "LOW": "dim cyan",
    }

    for rule in registry.registered_rules:
        sev_style = severity_styles.get(rule.severity.value, "white")
        conf_val = getattr(rule, "default_confidence", None)
        conf_str = conf_val.value if conf_val else "MEDIUM"
        conf_style = confidence_styles.get(conf_str, "white")
        table.add_row(
            rule.rule_id,
            f"[{sev_style}]{rule.severity.value}[/{sev_style}]",
            f"[{conf_style}]{conf_str}[/{conf_style}]",
            rule.title,
            rule.cwe.split(":")[0] if rule.cwe else "—",
            rule.owasp_llm.split(":")[0] if rule.owasp_llm else "—",
        )

    console.print()
    console.print(table)
    console.print(f"\n[dim]Total: {len(registry.registered_rules)} rules registered[/dim]\n")


@app.command("fingerprint")
def fingerprint(
    rule_id: str = typer.Argument(..., help="Rule ID (e.g. MCP-SEC-002)"),
    target: str = typer.Argument(..., help="Target component name (e.g. tool_name.param)"),
    path: str | None = typer.Option(None, "--path", "-p", help="JSON path within the schema/manifest"),
):
    """Compute a suppression fingerprint for a finding to use in .mcpscan.yml."""
    fp = compute_finding_fingerprint(rule_id, target, path)
    console.print(f"\n[bold cyan]Finding Fingerprint:[/bold cyan] [bold green]{fp}[/bold green]")
    console.print("\n[dim]To suppress this finding in .mcpscan.yml:[/dim]")
    console.print("[dim]suppress:[/dim]")
    console.print(f'[dim]  - fingerprint: "{fp}"[/dim]')
    console.print('[dim]    reason: "Accepted risk / validated boundary"[/dim]\n')


@app.command("diff")
def diff_command(
    baseline_report: str = typer.Argument(..., help="Path to baseline scan report JSON."),
    current_report: str = typer.Argument(..., help="Path to current scan report JSON."),
    markdown_output: str | None = typer.Option(
        None,
        "--markdown",
        "-M",
        help="Path to export Markdown diff report (ideal for PR comments).",
    ),
    json_output: str | None = typer.Option(
        None,
        "--json",
        "-j",
        help="Path to export raw JSON diff report.",
    ),
    fail_on_regression: bool = typer.Option(
        False,
        "--fail-on-regression",
        help="Exit with code 2 if any new vulnerabilities are introduced or score degraded.",
    ),
    fail_under: int | None = typer.Option(
        None,
        "--fail-under",
        help="Exit with code 2 if current scan score falls below this threshold.",
    ),
):
    """Compare two mcpscan JSON reports and analyze posture regressions for CI/CD PR gates."""
    # 1. Load reports
    try:
        baseline = load_report_from_file(baseline_report)
    except Exception as e:
        console.print(f"[bold red]Failed to load baseline report:[/bold red] {e}")
        raise typer.Exit(code=1)

    try:
        current = load_report_from_file(current_report)
    except Exception as e:
        console.print(f"[bold red]Failed to load current report:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 2. Compute delta
    diff_res = compute_diff(baseline, current)

    # 3. Render terminal scorecard
    terminal_diff_reporter.render(diff_res)

    # 4. Export Markdown if requested
    export_failed = False
    if markdown_output:
        try:
            markdown_diff_reporter.save(diff_res, markdown_output)
            console.print(f"[bold green]✓[/bold green] Markdown diff exported to: [bold cyan]{markdown_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write Markdown diff report:[/bold red] {e}")
            export_failed = True

    # 5. Export JSON if requested
    if json_output:
        try:
            from pathlib import Path
            Path(json_output).write_text(diff_res.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[bold green]✓[/bold green] JSON diff exported to: [bold cyan]{json_output}[/bold cyan]\n")
        except Exception as e:
            console.print(f"[bold red]Failed to write JSON diff report:[/bold red] {e}")
            export_failed = True

    if export_failed:
        raise typer.Exit(code=1)

    # 6. CI/CD Gate evaluations
    if fail_on_regression and diff_res.has_regressions:
        console.print(
            f"[bold red]CI/CD Gate Failed:[/bold red] Posture regression detected "
            f"({len(diff_res.new_findings)} new finding(s), delta: {diff_res.score_delta} pts).\n"
        )
        raise typer.Exit(code=2)

    if fail_under is not None and diff_res.current_score < fail_under:
        console.print(
            f"[bold red]CI/CD Gate Failed:[/bold red] Current score [bold]{diff_res.current_score}[/bold] "
            f"is below threshold of [bold]{fail_under}[/bold].\n"
        )
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
