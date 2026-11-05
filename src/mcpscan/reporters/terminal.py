"""Rich terminal dashboard for presenting security assessment reports."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpscan.models import AssessmentReport, PostureGrade, Severity


class TerminalReporter:
    """Renders human-readable, executive-ready security scorecards to terminal."""

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
        score_text.append(f"Security Posture Grade: ", style="bold")
        score_text.append(f" {report.grade.value} ", style=grade_style)
        score_text.append(f"  |  Score: ", style="bold")
        score_text.append(f"{report.score}/100\n", style="bold green" if report.score >= 75 else "bold red")

        score_text.append(f"Server: ", style="dim")
        score_text.append(f"{report.server_name} (v{report.server_version})  |  ", style="bold cyan")
        score_text.append(f"Surface: ", style="dim")
        score_text.append(f"{report.tools_count} Tools, {report.resources_count} Resources, {report.prompts_count} Prompts", style="bold")

        self.console.print(
            Panel(
                score_text,
                title="[bold blue]MCP Security Posture Assessment[/bold blue]",
                border_style="blue",
                padding=(1, 2),
            )
        )

        # 2. Findings Table
        if not report.findings:
            self.console.print(
                Panel(
                    "[bold green]No security vulnerabilities or poisoning vectors detected.[/bold green]\n"
                    "Server posture adheres to least-privilege standards.",
                    border_style="green",
                )
            )
            return

        table = Table(
            title=f"Detected Vulnerabilities ({len(report.findings)} issues found)",
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
