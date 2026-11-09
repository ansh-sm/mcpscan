"""Markdown security audit report generator for PR comments, Slack, and documentation.

Generates clean, portable Markdown reports suitable for GitHub PR reviews,
Slack/Discord sharing, and static documentation embedding.
"""

from datetime import datetime
from typing import Dict, List
from mcpscan.models import AssessmentReport, Finding, PostureGrade, Severity


class MarkdownReporter:
    """Renders AssessmentReport as a self-contained Markdown document."""

    # Grade badge indicators
    GRADE_BADGES = {
        PostureGrade.A_PLUS: "🟢 A+",
        PostureGrade.A: "🟢 A",
        PostureGrade.B: "🟡 B",
        PostureGrade.C: "🟠 C",
        PostureGrade.D: "🔴 D",
        PostureGrade.F: "🔴 F",
    }

    SEVERITY_INDICATORS = {
        Severity.CRITICAL: "🔴 CRITICAL",
        Severity.HIGH: "🟠 HIGH",
        Severity.MEDIUM: "🟡 MEDIUM",
        Severity.LOW: "🔵 LOW",
        Severity.INFO: "⚪ INFO",
    }

    def generate(self, report: AssessmentReport) -> str:
        """Convert AssessmentReport into a Markdown-formatted string."""
        sections: List[str] = []

        # Header
        sections.append(self._render_header(report))
        sections.append(self._render_summary_table(report))
        sections.append(self._render_attack_surface(report))

        if report.findings:
            sections.append(self._render_severity_breakdown(report))
            sections.append(self._render_findings_table(report))
            sections.append(self._render_findings_detail(report))
        else:
            sections.append("\n## ✅ No Security Findings\n")
            sections.append(
                "No vulnerabilities detected. The server's declared attack surface "
                "passed all registered security rules.\n"
            )

        sections.append(self._render_footer(report))

        return "\n".join(sections)

    def save(self, report: AssessmentReport, output_path: str) -> None:
        """Write Markdown report to file."""
        content = self.generate(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    def _render_header(self, report: AssessmentReport) -> str:
        grade_badge = self.GRADE_BADGES.get(report.grade, report.grade.value)
        return (
            f"# 🛡️ mcpscan Security Assessment\n\n"
            f"**Server:** `{report.server_name}` v{report.server_version}  \n"
            f"**Grade:** {grade_badge}  \n"
            f"**Score:** {report.score}/100  \n"
            f"**Scan Time:** {report.scan_timestamp}  \n"
        )

    def _render_summary_table(self, report: AssessmentReport) -> str:
        finding_count = len(report.findings)
        severity_counts = self._count_by_severity(report.findings)

        lines = [
            "\n## 📊 Summary\n",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Posture Grade** | {self.GRADE_BADGES.get(report.grade, report.grade.value)} |",
            f"| **Score** | {report.score}/100 |",
            f"| **Total Findings** | {finding_count} |",
            f"| **Critical** | {severity_counts.get(Severity.CRITICAL, 0)} |",
            f"| **High** | {severity_counts.get(Severity.HIGH, 0)} |",
            f"| **Medium** | {severity_counts.get(Severity.MEDIUM, 0)} |",
            f"| **Low** | {severity_counts.get(Severity.LOW, 0)} |",
            f"| **Info** | {severity_counts.get(Severity.INFO, 0)} |",
        ]
        return "\n".join(lines) + "\n"

    def _render_attack_surface(self, report: AssessmentReport) -> str:
        lines = [
            "\n## 🎯 Attack Surface\n",
            "| Component | Count |",
            "| :--- | :---: |",
            f"| Tools | {report.tools_count} |",
            f"| Resources | {report.resources_count} |",
            f"| Prompts | {report.prompts_count} |",
        ]
        return "\n".join(lines) + "\n"

    def _render_severity_breakdown(self, report: AssessmentReport) -> str:
        severity_counts = self._count_by_severity(report.findings)
        bars: List[str] = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                indicator = self.SEVERITY_INDICATORS[sev]
                bar = "█" * count
                bars.append(f"  {indicator}: {bar} ({count})")

        if not bars:
            return ""

        return "\n## 📈 Severity Distribution\n\n```\n" + "\n".join(bars) + "\n```\n"

    def _render_findings_table(self, report: AssessmentReport) -> str:
        lines = [
            "\n## 🔍 Findings Overview\n",
            "| # | Rule ID | Severity | Title | Location |",
            "| :---: | :--- | :---: | :--- | :--- |",
        ]

        for i, finding in enumerate(report.findings, 1):
            sev = self.SEVERITY_INDICATORS.get(finding.severity, finding.severity.value)
            location = f"`{finding.location.target_name}`"
            lines.append(
                f"| {i} | `{finding.rule_id}` | {sev} | {finding.title} | {location} |"
            )

        return "\n".join(lines) + "\n"

    def _render_findings_detail(self, report: AssessmentReport) -> str:
        lines = ["\n## 📋 Detailed Findings\n"]

        for i, finding in enumerate(report.findings, 1):
            sev = self.SEVERITY_INDICATORS.get(finding.severity, finding.severity.value)
            lines.append(f"### {i}. {finding.title}\n")
            lines.append(f"- **Rule:** `{finding.rule_id}`")
            lines.append(f"- **Severity:** {sev}")
            lines.append(f"- **Location:** `{finding.location.target_type}` → `{finding.location.target_name}`")
            if finding.cwe:
                lines.append(f"- **CWE:** {finding.cwe}")
            if finding.owasp_llm:
                lines.append(f"- **OWASP LLM:** {finding.owasp_llm}")
            lines.append(f"\n**Description:** {finding.description}\n")
            lines.append(f"**Remediation:** {finding.remediation}\n")
            if finding.evidence:
                lines.append(f"**Evidence:**\n```\n{finding.evidence}\n```\n")
            lines.append("---\n")

        return "\n".join(lines)

    def _render_footer(self, report: AssessmentReport) -> str:
        return (
            "\n---\n\n"
            "*Generated by [mcpscan](https://github.com/ansh-sm/mcpscan) — "
            "Industrial-grade MCP Server Security Posture Scanner*\n"
        )

    @staticmethod
    def _count_by_severity(findings: List[Finding]) -> Dict[Severity, int]:
        counts: Dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
