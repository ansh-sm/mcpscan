"""Rich terminal dashboard for presenting security assessment reports."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpscan.models import AssessmentReport, PostureGrade, Severity


class TerminalReporter:
    """Renders human-readable security scorecards to terminal."""

    GRADE_COLORS = {
        PostureGrade.A_PLUS: "bold bright_green",
        PostureGrade.A: "bold green",
        PostureGrade.B: "bold cyan",
        PostureGrade.C: "bold yellow",
        PostureGrade.D: "bold dark_orange",
        PostureGrade.F: "bold red",
    }

    SEVERITY_STYLES = {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold cyan",
        Severity.INFO: "dim white",
    }

    def __init__(self, console: Console = None):
        self.console = console or Console()

    def render(self, report: AssessmentReport) -> None:
        """Render complete scorecard, stats, and finding remediation details."""
        grade_style = self.GRADE_COLORS.get(report.grade, "bold white")

        # 1. Header Banner & Posture Scorecard
        score_text = Text()
        score_text.append("Security Posture Grade: ", style="bold")
        score_text.append(f" {report.grade.value} ", style=grade_style)
        score_text.append("  |  Score: ", style="bold")
        score_text.append(f"{report.score}/100\n", style="bold green" if report.score >= 75 else "bold red")

        score_text.append("Status: ", style="bold")
        if report.scan_complete:
            score_text.append("COMPLETE\n", style="bold green")
        else:
            score_text.append("INCOMPLETE\n", style="bold red")

        score_text.append("Server: ", style="dim")
        score_text.append(f"{report.server_name} (v{report.server_version})  |  ", style="bold cyan")
        score_text.append("Surface: ", style="dim")
        score_text.append(f"{report.tools_count} Tools, {report.resources_count} Resources, {report.prompts_count} Prompts", style="bold")

        self.console.print(
            Panel(
                score_text,
                title="[bold blue]MCP Security Posture Assessment[/bold blue]",
                border_style="blue",
                padding=(1, 2),
            )
        )

        # Incomplete scan warning
        if not report.scan_complete:
            err_text = Text()
            err_text.append("Warning: This scan was incomplete. Do not treat a lack of findings as proof of security.\n", style="bold yellow")
            err_text.append("Encountered errors:\n", style="dim")
            for err in report.scan_errors:
                err_text.append(f"  • {err}\n", style="red")
            self.console.print(
                Panel(
                    err_text,
                    title="[bold red]Incomplete Scan Warning[/bold red]",
                    border_style="red",
                    padding=(1, 2),
                )
            )

        # 2. Findings Table
        if not report.findings:
            if report.scan_complete:
                msg = "[bold green]No heuristic indicators detected in scanned metadata.[/bold green]\nNote: A clean scan does not guarantee complete security."
            else:
                msg = "[bold yellow]No findings detected, but the scan was incomplete.[/bold yellow]\nAbsence of findings does not establish safety."
            self.console.print(
                Panel(
                    msg,
                    border_style="green" if report.scan_complete else "yellow",
                )
            )
            return

        table = Table(
            title=f"Detected Findings ({len(report.findings)} issues flagged)",
            title_style="bold red",
            border_style="dim",
            header_style="bold cyan",
            expand=True,
        )

        table.add_column("Severity", width=12, justify="center")
        table.add_column("Rule ID", width=14)
        table.add_column("Component", width=22)
        table.add_column("Finding Summary & Remediation", ratio=1)

        for finding in report.findings:
            sev_style = self.SEVERITY_STYLES.get(finding.severity, "white")
            sev_badge = Text(f" {finding.severity.value} ", style=sev_style)

            location_str = f"{finding.location.target_name}\n[dim]{finding.location.path or ''}[/dim]"

            details = Text()
            details.append(f"{finding.title}\n", style="bold")
            details.append(f"{finding.description}\n\n", style="dim")
            if finding.evidence:
                details.append(f"Evidence: {finding.evidence}\n", style="yellow")
            details.append(f"Remediation: {finding.remediation}", style="green")

            table.add_row(
                sev_badge,
                finding.rule_id,
                location_str,
                details,
            )

        self.console.print(table)
        self.console.print()
