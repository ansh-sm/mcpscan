"""Standalone HTML report generator for visual executive dashboards."""

import html
from typing import Dict, List
from mcpscan import __version__
from mcpscan.models import AssessmentReport, Finding, PostureGrade, Severity


class HtmlReporter:
    """Generates self-contained, responsive HTML visual security dashboards."""

    GRADE_THEMES = {
        PostureGrade.A_PLUS: ("#10b981", "#ecfdf5", "text-emerald-700"),
        PostureGrade.A: ("#059669", "#ecfdf5", "text-emerald-700"),
        PostureGrade.B: ("#0284c7", "#f0f9ff", "text-sky-700"),
        PostureGrade.C: ("#eab308", "#fefce8", "text-yellow-700"),
        PostureGrade.D: ("#f97316", "#fff7ed", "text-orange-700"),
        PostureGrade.F: ("#ef4444", "#fef2f2", "text-red-700"),
    }

    SEVERITY_BADGES = {
        Severity.CRITICAL: ("#dc2626", "#fee2e2"),
        Severity.HIGH: ("#ea580c", "#ffedd5"),
        Severity.MEDIUM: ("#ca8a04", "#fef9c3"),
        Severity.LOW: ("#0284c7", "#e0f2fe"),
        Severity.INFO: ("#4b5563", "#f3f4f6"),
    }

    def generate(self, report: AssessmentReport) -> str:
        """Render an AssessmentReport into a standalone HTML page."""
        grade_color, grade_bg, _ = self.GRADE_THEMES.get(
            report.grade, ("#6b7280", "#f9fafb", "text-gray-700")
        )

        rows_html: List[str] = []
        for f in report.findings:
            sev_fg, sev_bg = self.SEVERITY_BADGES.get(f.severity, ("#374151", "#e5e7eb"))
            evidence_snippet = (
                f'<div class="evidence"><strong>Evidence:</strong> <code>{html.escape(f.evidence)}</code></div>'
                if f.evidence
                else ""
            )
            cwe_badge = (
                f'<span class="tax-badge">{html.escape(f.cwe)}</span>'
                if f.cwe
                else ""
            )
            owasp_badge = (
                f'<span class="tax-badge">{html.escape(f.owasp_llm)}</span>'
                if f.owasp_llm
                else ""
            )

            rows_html.append(
                f"""
                <tr class="finding-row">
                    <td>
                        <span class="badge" style="background-color: {sev_bg}; color: {sev_fg};">
                            {html.escape(f.severity.value)}
                        </span>
                    </td>
                    <td><code>{html.escape(f.rule_id)}</code></td>
                    <td>
                        <strong>{html.escape(f.location.target_name)}</strong>
                        <div class="location-path">{html.escape(f.location.path or '')}</div>
                    </td>
                    <td>
                        <div class="finding-title">{html.escape(f.title)}</div>
                        <p class="finding-desc">{html.escape(f.description)}</p>
                        {evidence_snippet}
                        <div class="remediation">
                            <strong>Remediation:</strong> {html.escape(f.remediation)}
                        </div>
                        <div class="taxonomy-tags">
                            {cwe_badge}
                            {owasp_badge}
                        </div>
                    </td>
                </tr>
                """
            )

        findings_table_content = (
            "".join(rows_html)
            if rows_html
            else '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: #059669;"><strong>No security vulnerabilities detected. Server satisfies least-privilege standards!</strong></td></tr>'
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mcpscan Report - {html.escape(report.server_name)}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            padding: 2.5rem 1.5rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .header-title h1 {{ font-size: 1.8rem; font-weight: 700; }}
        .header-title p {{ color: var(--text-dim); font-size: 0.95rem; margin-top: 0.3rem; }}
        .scorecard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
        }}
        .card-label {{ font-size: 0.85rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }}
        .card-value {{ font-size: 2.2rem; font-weight: 800; margin-top: 0.5rem; }}
        .grade-pill {{
            display: inline-block;
            background-color: {grade_bg};
            color: {grade_color};
            border-radius: 8px;
            padding: 0.2rem 1rem;
            font-size: 2.2rem;
            font-weight: 900;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
        }}
        th, td {{ padding: 1.2rem; text-align: left; vertical-align: top; }}
        th {{
            background-color: #172033;
            color: var(--text-dim);
            font-size: 0.85rem;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border-color);
        }}
        tr:not(:last-child) td {{ border-bottom: 1px solid var(--border-color); }}
        .badge {{
            display: inline-block;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.35rem 0.7rem;
            border-radius: 6px;
            letter-spacing: 0.04em;
        }}
        .location-path {{ font-size: 0.8rem; color: var(--text-dim); font-family: monospace; margin-top: 0.2rem; }}
        .finding-title {{ font-weight: 700; font-size: 1.05rem; margin-bottom: 0.4rem; }}
        .finding-desc {{ color: var(--text-dim); font-size: 0.92rem; margin-bottom: 0.6rem; }}
        .evidence {{
            background-color: #0b1120;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.6rem 0.8rem;
            font-size: 0.85rem;
            margin-bottom: 0.6rem;
        }}
        .remediation {{
            background-color: #06241a;
            border-left: 4px solid #10b981;
            padding: 0.6rem 0.8rem;
            font-size: 0.88rem;
            border-radius: 0 6px 6px 0;
            margin-bottom: 0.6rem;
            color: #d1fae5;
        }}
        .taxonomy-tags {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }}
        .tax-badge {{
            font-size: 0.75rem;
            background-color: #334155;
            color: #cbd5e1;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
        }}
        .footer {{
            margin-top: 3rem;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-dim);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>mcpscan Security Assessment</h1>
                <p>Target Server: <strong>{html.escape(report.server_name)}</strong> (version {html.escape(report.server_version)})</p>
            </div>
            <div>
                <span style="color: var(--text-dim); font-size: 0.85rem;">Generated on: {html.escape(report.scan_timestamp)}</span>
            </div>
        </div>

        <div class="scorecard">
            <div class="card">
                <div class="card-label">Posture Grade</div>
                <div class="card-value"><span class="grade-pill">{report.grade.value}</span></div>
            </div>
            <div class="card">
                <div class="card-label">Security Score</div>
                <div class="card-value" style="color: {grade_color};">{report.score} / 100</div>
            </div>
            <div class="card">
                <div class="card-label">Surface Declared</div>
                <div class="card-value">{report.tools_count} <span style="font-size: 1rem; color: var(--text-dim);">Tools</span>, {report.resources_count} <span style="font-size: 1rem; color: var(--text-dim);">Res</span></div>
            </div>
            <div class="card">
                <div class="card-label">Total Findings</div>
                <div class="card-value" style="color: {'#ef4444' if report.findings else '#10b981'};">{len(report.findings)}</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 130px;">Severity</th>
                    <th style="width: 140px;">Rule ID</th>
                    <th style="width: 220px;">Component</th>
                    <th>Vulnerability Details & Remediation</th>
                </tr>
            </thead>
            <tbody>
                {findings_table_content}
            </tbody>
        </table>

        <div class="footer">
            Generated with <a href="https://github.com/ansh-sm/mcpscan" style="color: #38bdf8; text-decoration: none;">mcpscan v{__version__}</a> &bull; Industrial-grade MCP Security Analyzer
        </div>
    </div>
</body>
</html>
"""

    def save(self, report: AssessmentReport, output_path: str) -> None:
        """Render and save HTML report to disk."""
        content = self.generate(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
