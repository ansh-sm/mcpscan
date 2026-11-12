"""Rich terminal renderer for security posture diff reports."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpscan.diff import DiffReport
from mcpscan.models import Severity


class TerminalDiffReporter:
    """Renders visual diff scorecards and finding change tables in terminal."""

    SEVERITY_STYLES = {
        Severity.CRITICAL: "bold white on red",
        Severity.HIGH: "bold red",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold cyan",
        Severity.INFO: "dim white",
    }

    def __init__(self, console: Console = None):
        self.console = console or Console()

    def render(self, diff: DiffReport) -> None:
        """Render complete posture diff breakdown to console."""
        # 1. Delta Summary Panel
        delta_str = f"+{diff.score_delta}" if diff.score_delta > 0 else f"{diff.score_delta}"
        delta_color = "bold green" if diff.score_delta > 0 else ("bold red" if diff.score_delta < 0 else "bold yellow")

        summary_text = Text()
        summary_text.append("Posture Transition: ", style="bold")
        summary_text.append(f"{diff.baseline_grade.value} ", style="bold cyan")
        summary_text.append("→ ", style="bold")
        summary_text.append(f"{diff.current_grade.value}\n", style="bold green" if not diff.has_regressions else "bold red")

        summary_text.append("Security Score: ", style="bold")
        summary_text.append(f"{diff.baseline_score} ", style="bold")
        summary_text.append("→ ", style="bold")
        summary_text.append(f"{diff.current_score} ", style="bold")
        summary_text.append(f"({delta_str} pts)\n", style=delta_color)

        summary_text.append("Regressions (New): ", style="bold")
        summary_text.append(
            f"{len(diff.new_findings)}\n",
            style="bold red" if diff.new_findings else "bold green",
        )

        summary_text.append("Resolved (Fixed): ", style="bold")
        summary_text.append(
            f"{len(diff.resolved_findings)}\n",
            style="bold green" if diff.resolved_findings else "dim",
        )

        summary_text.append("Unresolved: ", style="bold")
        summary_text.append(f"{len(diff.unresolved_findings)}", style="dim")

        border_style = "red" if diff.has_regressions else ("green" if diff.is_improved else "cyan")
        title_text = (
            "[bold red]🚨 Security Posture Regression[/bold red]"
            if diff.has_regressions
            else (
                "[bold green]✨ Security Posture Improved[/bold green]"
                if diff.is_improved
                else "[bold cyan]mcpscan Posture Diff[/bold cyan]"
            )
        )

        self.console.print(
            Panel(
                summary_text,
                title=title_text,
                border_style=border_style,
                padding=(1, 2),
            )
        )

        # 2. New Findings (Regressions) Table
        if diff.new_findings:
            new_table = Table(
                title=f"🚨 New Findings Introduced ({len(diff.new_findings)} regressions)",
                title_style="bold red",
                border_style="red",
                header_style="bold cyan",
                expand=True,
            )
            new_table.add_column("Severity", width=12, justify="center")
            new_table.add_column("Rule ID", width=14)
            new_table.add_column("Component", width=24)
            new_table.add_column("Finding Summary", ratio=1)

            for f in diff.new_findings:
                sev_style = self.SEVERITY_STYLES.get(f.severity, "white")
                sev_badge = Text(f" {f.severity.value} ", style=sev_style)
                loc_str = f"{f.location.target_name}\n[dim]{f.location.path or ''}[/dim]"

                details = Text()
                details.append(f"{f.title}\n", style="bold")
                details.append(f"{f.description}\n", style="dim")
                if f.evidence:
                    details.append(f"Evidence: {f.evidence}", style="yellow")

                new_table.add_row(sev_badge, f.rule_id, loc_str, details)

            self.console.print(new_table)
            self.console.print()

        # 3. Resolved Findings Table
        if diff.resolved_findings:
            resolved_table = Table(
                title=f"✅ Resolved Vulnerabilities ({len(diff.resolved_findings)} fixed)",
                title_style="bold green",
                border_style="green",
                header_style="bold cyan",
                expand=True,
            )
            resolved_table.add_column("Severity", width=12, justify="center")
            resolved_table.add_column("Rule ID", width=14)
            resolved_table.add_column("Component", width=24)
            resolved_table.add_column("Remediated Issue", ratio=1)

            for f in diff.resolved_findings:
                sev_style = self.SEVERITY_STYLES.get(f.severity, "white")
                sev_badge = Text(f" {f.severity.value} ", style=sev_style)
                loc_str = f"{f.location.target_name}\n[dim]{f.location.path or ''}[/dim]"

                details = Text()
                details.append(f"{f.title}\n", style="bold")
                details.append(f"Remediated: {f.remediation}", style="green")

                resolved_table.add_row(sev_badge, f.rule_id, loc_str, details)

            self.console.print(resolved_table)
            self.console.print()
