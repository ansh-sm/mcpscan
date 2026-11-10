"""Standalone HTML executive dashboard generator with modern cyber UI, interactive filtering, and waiver export."""

import html
import json
from typing import Dict, List
from mcpscan import __version__
from mcpscan.config import compute_finding_fingerprint
from mcpscan.models import AssessmentReport, Finding, PostureGrade, Severity


class HtmlReporter:
    """Generates self-contained, responsive HTML visual security dashboards with zero external runtime dependencies."""

    GRADE_CONFIG = {
        PostureGrade.A_PLUS: {"color": "#10b981", "bg": "rgba(16, 185, 129, 0.12)", "border": "#059669", "label": "A+"},
        PostureGrade.A: {"color": "#10b981", "bg": "rgba(16, 185, 129, 0.12)", "border": "#059669", "label": "A"},
        PostureGrade.B: {"color": "#06b6d4", "bg": "rgba(6, 182, 212, 0.12)", "border": "#0891b2", "label": "B"},
        PostureGrade.C: {"color": "#eab308", "bg": "rgba(234, 179, 8, 0.12)", "border": "#ca8a04", "label": "C"},
        PostureGrade.D: {"color": "#f97316", "bg": "rgba(249, 115, 22, 0.12)", "border": "#ea580c", "label": "D"},
        PostureGrade.F: {"color": "#ef4444", "bg": "rgba(239, 68, 68, 0.14)", "border": "#dc2626", "label": "F"},
    }

    SEVERITY_STYLES = {
        Severity.CRITICAL: {"fg": "#f87171", "bg": "rgba(239, 68, 68, 0.15)", "border": "#ef4444", "dot": "#ef4444"},
        Severity.HIGH: {"fg": "#fb923c", "bg": "rgba(249, 115, 22, 0.15)", "border": "#f97316", "dot": "#f97316"},
        Severity.MEDIUM: {"fg": "#facc15", "bg": "rgba(234, 179, 8, 0.15)", "border": "#eab308", "dot": "#eab308"},
        Severity.LOW: {"fg": "#38bdf8", "bg": "rgba(56, 189, 248, 0.15)", "border": "#38bdf8", "dot": "#38bdf8"},
        Severity.INFO: {"fg": "#94a3b8", "bg": "rgba(148, 163, 184, 0.15)", "border": "#64748b", "dot": "#64748b"},
    }

    CONFIDENCE_STYLES = {
        "HIGH": {"fg": "#4ade80", "bg": "rgba(74, 222, 128, 0.1)", "border": "#22c55e"},
        "MEDIUM": {"fg": "#fde047", "bg": "rgba(253, 224, 71, 0.1)", "border": "#eab308"},
        "LOW": {"fg": "#67e8f9", "bg": "rgba(103, 232, 249, 0.1)", "border": "#06b6d4"},
    }

    def generate(self, report: AssessmentReport) -> str:
        """Render AssessmentReport into a high-grade standalone HTML application."""
        grade_info = self.GRADE_CONFIG.get(report.grade, self.GRADE_CONFIG[PostureGrade.F])
        score_circumference = 2 * 3.14159 * 52
        dash_offset = score_circumference - (report.score / 100.0) * score_circumference

        # Count severities
        sev_counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in report.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        # Incomplete banner
        incomplete_banner = ""
        if not report.scan_complete:
            err_items = "".join(f"<li><code>{html.escape(e)}</code></li>" for e in report.scan_errors)
            incomplete_banner = f"""
            <div class="alert-banner alert-warning">
                <div class="alert-icon">⚠️</div>
                <div class="alert-content">
                    <div class="alert-title">Incomplete Scan Warning</div>
                    <div class="alert-desc">This scan did not complete all advertised discovery stages. Absence of findings must not be interpreted as establishing safety.</div>
                    <ul class="alert-list">{err_items}</ul>
                </div>
            </div>
            """

        # Build cards
        cards_html: List[str] = []
        for i, f in enumerate(report.findings, 1):
            sev_style = self.SEVERITY_STYLES.get(f.severity, self.SEVERITY_STYLES[Severity.INFO])
            conf_val = f.confidence.value
            conf_style = self.CONFIDENCE_STYLES.get(conf_val, self.CONFIDENCE_STYLES["MEDIUM"])

            fp = compute_finding_fingerprint(
                f.rule_id,
                f.location.target_name,
                f.location.path,
            )

            evidence_block = ""
            if f.evidence:
                evidence_block = f"""
                <div class="detail-section">
                    <div class="section-label">DETECTED EVIDENCE</div>
                    <div class="code-box">
                        <pre><code>{html.escape(f.evidence)}</code></pre>
                        <button class="copy-btn" onclick="copyText('{html.escape(f.evidence, quote=True)}')">Copy Evidence</button>
                    </div>
                </div>
                """

            cwe_badge = f'<span class="pill-tag pill-cwe">{html.escape(f.cwe)}</span>' if f.cwe else ""
            owasp_badge = f'<span class="pill-tag pill-owasp">{html.escape(f.owasp_llm)}</span>' if f.owasp_llm else ""

            waiver_yaml = f'- fingerprint: "{fp}"\\n  reason: "Accepted risk for {html.escape(f.location.target_name)}"'

            cards_html.append(f"""
            <div class="finding-card" data-severity="{f.severity.value}" data-rule="{f.rule_id}" data-search="{html.escape((f.title + ' ' + f.rule_id + ' ' + f.location.target_name + ' ' + f.description).lower())}">
                <div class="finding-header">
                    <div class="header-left">
                        <span class="sev-badge" style="color: {sev_style['fg']}; background: {sev_style['bg']}; border-color: {sev_style['border']};">
                            <span class="sev-dot" style="background: {sev_style['dot']};"></span>
                            {f.severity.value}
                        </span>
                        <span class="conf-badge" style="color: {conf_style['fg']}; background: {conf_style['bg']}; border-color: {conf_style['border']};">
                            {conf_val} CONFIDENCE
                        </span>
                        <span class="rule-id-badge">{f.rule_id}</span>
                        <span class="location-badge"><code>{html.escape(f.location.target_type)}</code> → <strong>{html.escape(f.location.target_name)}</strong></span>
                    </div>
                    <div class="header-right">
                        <span class="fingerprint-tag" title="Finding Fingerprint for waivers">FP: {fp[:8]}...</span>
                    </div>
                </div>
                
                <div class="finding-body">
                    <h3 class="finding-title">{html.escape(f.title)}</h3>
                    <p class="finding-description">{html.escape(f.description)}</p>
                    
                    {evidence_block}

                    <div class="detail-section">
                        <div class="section-label">RECOMMENDED REMEDIATION</div>
                        <div class="remediation-box">
                            <span class="remediation-icon">💡</span>
                            <div>{html.escape(f.remediation)}</div>
                        </div>
                    </div>

                    <div class="finding-footer">
                        <div class="tag-group">
                            {cwe_badge}
                            {owasp_badge}
                        </div>
                        <button class="waiver-btn" onclick="copyWaiver('{fp}', '{html.escape(f.location.target_name, quote=True)}')">
                            📋 Copy Waiver Snippet
                        </button>
                    </div>
                </div>
            </div>
            """)

        cards_content = "\n".join(cards_html) if cards_html else (
            '<div class="clean-slate"><h3>✨ No Security Indicators Detected</h3><p>No heuristic risk signals found in declared component schemas. Note: static scans do not guarantee complete security.</p></div>'
            if report.scan_complete else
            '<div class="clean-slate warning"><h3>⚠️ Scan Incomplete</h3><p>No findings were registered, but discovery failed on some advertised interfaces.</p></div>'
        )

        # JSON data payload for dynamic in-browser export
        report_json_str = json.dumps(report.model_dump(), indent=2)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mcpscan Security Assessment — {html.escape(report.server_name)}</title>
    <style>
        :root {{
            --bg-base: #060911;
            --bg-surface: #0c121e;
            --bg-card: rgba(18, 26, 43, 0.75);
            --bg-card-hover: rgba(24, 35, 58, 0.9);
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-glow: rgba(56, 189, 248, 0.25);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #38bdf8;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-base);
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.08) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.06) 0px, transparent 50%),
                radial-gradient(at 50% 100%, rgba(244, 63, 94, 0.05) 0px, transparent 60%);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            min-height: 100vh;
            padding: 2.5rem 1.5rem 5rem;
            line-height: 1.55;
            -webkit-font-smoothing: antialiased;
        }}
        .app-container {{
            max-width: 1240px;
            margin: 0 auto;
        }}
        /* Top Navigation Bar */
        .top-navbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: 2.5rem;
            flex-wrap: wrap;
            gap: 1.2rem;
        }}
        .brand-section {{
            display: flex;
            align-items: center;
            gap: 0.9rem;
        }}
        .brand-logo {{
            width: 44px;
            height: 44px;
            background: linear-gradient(135deg, #0284c7, #10b981);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            box-shadow: 0 0 20px rgba(2, 132, 199, 0.4);
        }}
        .brand-text h1 {{
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            background: linear-gradient(to right, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand-text p {{
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
        .action-group {{
            display: flex;
            align-items: center;
            gap: 0.8rem;
        }}
        .btn {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-subtle);
            color: var(--text-primary);
            padding: 0.55rem 1.1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .btn:hover {{
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
            transform: translateY(-1px);
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #0284c7, #0369a1);
            border-color: #38bdf8;
            color: #fff;
        }}
        .btn-primary:hover {{
            background: linear-gradient(135deg, #0369a1, #075985);
            box-shadow: 0 0 15px rgba(56, 189, 248, 0.35);
        }}

        /* Hero Executive Scorecard */
        .hero-dashboard {{
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}
        @media (max-width: 860px) {{
            .hero-dashboard {{ grid-template-columns: 1fr; }}
        }}
        .grade-gauge-card {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 2rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }}
        .gauge-svg-container {{
            position: relative;
            width: 140px;
            height: 140px;
            margin-bottom: 1rem;
        }}
        .gauge-svg {{
            transform: rotate(-90deg);
        }}
        .gauge-bg {{
            fill: none;
            stroke: rgba(255, 255, 255, 0.06);
            stroke-width: 10;
        }}
        .gauge-fill {{
            fill: none;
            stroke: {grade_info['color']};
            stroke-width: 10;
            stroke-linecap: round;
            stroke-dasharray: {score_circumference:.1f};
            stroke-dashoffset: {dash_offset:.1f};
            transition: stroke-dashoffset 1s ease;
            filter: drop-shadow(0 0 8px {grade_info['color']});
        }}
        .gauge-center {{
            position: absolute;
            inset: 0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }}
        .gauge-grade {{
            font-size: 2.8rem;
            font-weight: 900;
            color: {grade_info['color']};
            line-height: 1;
        }}
        .gauge-score-label {{
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 600;
            margin-top: 0.2rem;
        }}
        .gauge-subtext {{
            font-size: 0.85rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 700;
        }}

        .stats-overview-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.2rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            padding: 1.4rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: border-color 0.2s ease;
        }}
        .stat-card:hover {{
            border-color: rgba(255, 255, 255, 0.15);
        }}
        .stat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
        }}
        .stat-value {{
            font-size: 2rem;
            font-weight: 800;
            color: var(--text-primary);
            margin: 0.5rem 0;
        }}
        .stat-footer {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        /* Severity Filter Toolbar */
        .filter-toolbar {{
            background: var(--bg-surface);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1rem 1.2rem;
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .filter-pills {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        .filter-pill {{
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: 0.4rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
        }}
        .filter-pill:hover {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
        }}
        .filter-pill.active {{
            background: rgba(56, 189, 248, 0.15);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }}
        .search-box {{
            display: flex;
            align-items: center;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-subtle);
            border-radius: 8px;
            padding: 0.4rem 0.8rem;
            width: 280px;
        }}
        .search-input {{
            background: transparent;
            border: none;
            outline: none;
            color: var(--text-primary);
            font-size: 0.85rem;
            width: 100%;
        }}
        .search-input::placeholder {{
            color: var(--text-muted);
        }}

        /* Findings List */
        .findings-stream {{
            display: flex;
            flex-direction: column;
            gap: 1.2rem;
        }}
        .finding-card {{
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-subtle);
            border-radius: 14px;
            overflow: hidden;
            transition: all 0.2s ease;
        }}
        .finding-card:hover {{
            border-color: rgba(255, 255, 255, 0.18);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        }}
        .finding-header {{
            padding: 1rem 1.4rem;
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border-subtle);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.8rem;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 0.7rem;
            flex-wrap: wrap;
        }}
        .sev-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.75rem;
            font-weight: 800;
            padding: 0.25rem 0.65rem;
            border-radius: 6px;
            border: 1px solid;
            letter-spacing: 0.04em;
        }}
        .sev-dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }}
        .conf-badge {{
            font-size: 0.72rem;
            font-weight: 700;
            padding: 0.22rem 0.55rem;
            border-radius: 6px;
            border: 1px solid;
            letter-spacing: 0.05em;
        }}
        .rule-id-badge {{
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 0.8rem;
            font-weight: 700;
            color: #cbd5e1;
            background: rgba(255, 255, 255, 0.06);
            padding: 0.2rem 0.5rem;
            border-radius: 5px;
        }}
        .location-badge {{
            font-size: 0.82rem;
            color: var(--text-secondary);
        }}
        .fingerprint-tag {{
            font-family: ui-monospace, monospace;
            font-size: 0.72rem;
            color: var(--text-muted);
            background: rgba(0, 0, 0, 0.3);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
        }}
        .finding-body {{
            padding: 1.4rem;
        }}
        .finding-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: #fff;
            margin-bottom: 0.6rem;
        }}
        .finding-description {{
            color: #cbd5e1;
            font-size: 0.92rem;
            line-height: 1.6;
            margin-bottom: 1.2rem;
        }}
        .detail-section {{
            margin-bottom: 1rem;
        }}
        .section-label {{
            font-size: 0.72rem;
            font-weight: 800;
            color: var(--text-muted);
            letter-spacing: 0.06em;
            margin-bottom: 0.4rem;
        }}
        .code-box {{
            background: #04070d;
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 8px;
            padding: 0.8rem 1rem;
            position: relative;
        }}
        .code-box pre {{
            margin: 0;
            font-family: ui-monospace, monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
            overflow-x: auto;
        }}
        .copy-btn {{
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            font-size: 0.7rem;
            padding: 0.25rem 0.6rem;
            border-radius: 4px;
            cursor: pointer;
        }}
        .copy-btn:hover {{
            background: rgba(255, 255, 255, 0.15);
            color: #fff;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid #10b981;
            border-radius: 0 8px 8px 0;
            padding: 0.8rem 1rem;
            display: flex;
            align-items: flex-start;
            gap: 0.8rem;
            font-size: 0.88rem;
            color: #d1fae5;
        }}
        .remediation-icon {{
            font-size: 1.1rem;
        }}
        .finding-footer {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 1.2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-subtle);
            flex-wrap: wrap;
            gap: 0.8rem;
        }}
        .tag-group {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}
        .pill-tag {{
            font-size: 0.72rem;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-weight: 600;
        }}
        .pill-cwe {{ background: rgba(59, 130, 246, 0.15); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }}
        .pill-owasp {{ background: rgba(168, 85, 247, 0.15); color: #d8b4fe; border: 1px solid rgba(168, 85, 247, 0.3); }}
        .waiver-btn {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 600;
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .waiver-btn:hover {{
            background: rgba(255, 255, 255, 0.1);
            color: var(--text-primary);
        }}

        /* Clean State */
        .clean-slate {{
            background: var(--bg-card);
            border: 1px solid rgba(16, 185, 129, 0.3);
            border-radius: 16px;
            padding: 3rem;
            text-align: center;
        }}
        .clean-slate h3 {{ color: #10b981; font-size: 1.4rem; margin-bottom: 0.5rem; }}
        .clean-slate p {{ color: var(--text-secondary); font-size: 0.95rem; }}
        .clean-slate.warning {{ border-color: rgba(234, 179, 8, 0.3); }}
        .clean-slate.warning h3 {{ color: #eab308; }}

        /* Incomplete Banner */
        .alert-banner {{
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            padding: 1.2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
        }}
        .alert-warning {{
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
        }}
        .alert-icon {{ font-size: 1.4rem; }}
        .alert-title {{ font-weight: 800; font-size: 1rem; color: #f87171; margin-bottom: 0.2rem; }}
        .alert-desc {{ font-size: 0.9rem; margin-bottom: 0.5rem; }}
        .alert-list {{ margin-left: 1.2rem; font-size: 0.85rem; }}

        /* Toast notification */
        .toast {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #0f172a;
            border: 1px solid var(--accent-cyan);
            color: #fff;
            padding: 0.8rem 1.4rem;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            display: none;
            z-index: 1000;
        }}
        footer {{
            text-align: center;
            margin-top: 4rem;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        footer a {{ color: var(--accent-cyan); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Top Navbar -->
        <header class="top-navbar">
            <div class="brand-section">
                <div class="brand-logo">🛡️</div>
                <div class="brand-text">
                    <h1>mcpscan Security Assessment</h1>
                    <p>Target: <strong>{html.escape(report.server_name)}</strong> (version {html.escape(report.server_version)}) &bull; Generated: {html.escape(report.scan_timestamp)}</p>
                </div>
            </div>
            <div class="action-group">
                <button class="btn" onclick="exportJSON()">💾 Export JSON</button>
                <button class="btn btn-primary" onclick="window.print()">🖨️ Print / PDF</button>
            </div>
        </header>

        {incomplete_banner}

        <!-- Hero Scorecard -->
        <section class="hero-dashboard">
            <div class="grade-gauge-card">
                <div class="gauge-svg-container">
                    <svg class="gauge-svg" width="140" height="140">
                        <circle class="gauge-bg" cx="70" cy="70" r="52"></circle>
                        <circle class="gauge-fill" cx="70" cy="70" r="52"></circle>
                    </svg>
                    <div class="gauge-center">
                        <div class="gauge-grade">{report.grade.value}</div>
                        <div class="gauge-score-label">{report.score}/100</div>
                    </div>
                </div>
                <div class="gauge-subtext">POSTURE GRADE</div>
            </div>

            <div class="stats-overview-grid">
                <div class="stat-card">
                    <div class="stat-header">
                        <span>ATTACK SURFACE</span>
                        <span>🎯</span>
                    </div>
                    <div class="stat-value">{report.tools_count + report.resources_count + report.prompts_count}</div>
                    <div class="stat-footer">{report.tools_count} Tools, {report.resources_count} Res, {report.prompts_count} Prompts</div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span>TOTAL FINDINGS</span>
                        <span>⚠️</span>
                    </div>
                    <div class="stat-value" style="color: {'#ef4444' if report.findings else '#10b981'};">{len(report.findings)}</div>
                    <div class="stat-footer">{sev_counts['CRITICAL']} Critical, {sev_counts['HIGH']} High</div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span>SCAN STATUS</span>
                        <span>{'✅' if report.scan_complete else '❌'}</span>
                    </div>
                    <div class="stat-value" style="font-size: 1.6rem; color: {'#10b981' if report.scan_complete else '#ef4444'};">
                        {'COMPLETE' if report.scan_complete else 'INCOMPLETE'}
                    </div>
                    <div class="stat-footer">{f'{report.suppressed_count} waived' if report.suppressed_count > 0 else 'All checks evaluated'}</div>
                </div>

                <div class="stat-card">
                    <div class="stat-header">
                        <span>SEVERITY PEAK</span>
                        <span>⚡</span>
                    </div>
                    <div class="stat-value" style="font-size: 1.6rem;">
                        {report.findings[0].severity.value if report.findings else 'NONE'}
                    </div>
                    <div class="stat-footer">Based on CWE & OWASP LLM</div>
                </div>
            </div>
        </section>

        <!-- Filter Toolbar -->
        <section class="filter-toolbar">
            <div class="filter-pills">
                <div class="filter-pill active" onclick="filterSeverity('ALL', this)">All ({len(report.findings)})</div>
                <div class="filter-pill" onclick="filterSeverity('CRITICAL', this)">Critical ({sev_counts['CRITICAL']})</div>
                <div class="filter-pill" onclick="filterSeverity('HIGH', this)">High ({sev_counts['HIGH']})</div>
                <div class="filter-pill" onclick="filterSeverity('MEDIUM', this)">Medium ({sev_counts['MEDIUM']})</div>
                <div class="filter-pill" onclick="filterSeverity('LOW', this)">Low ({sev_counts['LOW']})</div>
            </div>

            <div class="search-box">
                <input type="text" class="search-input" id="searchInput" placeholder="Search rules, components, titles..." oninput="handleSearch()">
            </div>
        </section>

        <!-- Findings Stream -->
        <main class="findings-stream" id="findingsContainer">
            {cards_content}
        </main>

        <footer>
            Generated by <a href="https://github.com/ansh-sm/mcpscan">mcpscan v{__version__}</a> &bull; MCP server metadata security scanner
        </footer>
    </div>

    <!-- Hidden Raw JSON Data for In-Browser Export -->
    <script id="report-data" type="application/json">{report_json_str}</script>

    <div class="toast" id="toastBox">Action completed</div>

    <script>
        let currentFilter = 'ALL';

        function filterSeverity(severity, element) {{
            currentFilter = severity;
            document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
            if (element) element.classList.add('active');
            applyFilters();
        }}

        function handleSearch() {{
            applyFilters();
        }}

        function applyFilters() {{
            const search = (document.getElementById('searchInput').value || '').toLowerCase().trim();
            const cards = document.querySelectorAll('.finding-card');

            cards.forEach(card => {{
                const cardSev = card.getAttribute('data-severity');
                const cardSearch = card.getAttribute('data-search') || '';

                const matchesSev = (currentFilter === 'ALL' || cardSev === currentFilter);
                const matchesSearch = !search || cardSearch.includes(search);

                if (matchesSev && matchesSearch) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function showToast(msg) {{
            const toast = document.getElementById('toastBox');
            toast.innerText = msg;
            toast.style.display = 'block';
            setTimeout(() => {{ toast.style.display = 'none'; }}, 2500);
        }}

        function copyText(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                showToast('✓ Copied to clipboard!');
            }});
        }}

        function copyWaiver(fp, target) {{
            const snippet = `suppress:\\n  - fingerprint: "${{fp}}"\\n    reason: "Waiver for ${{target}}"`;
            navigator.clipboard.writeText(snippet).then(() => {{
                showToast('✓ Copied .mcpscan.yml waiver snippet!');
            }});
        }}

        function exportJSON() {{
            const raw = document.getElementById('report-data').textContent;
            const blob = new Blob([raw], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `mcpscan-${{Date.now()}}.json`;
            a.click();
            URL.revokeObjectURL(url);
            showToast('✓ Exported JSON Report');
        }}
    </script>
</body>
</html>
"""

    def save(self, report: AssessmentReport, output_path: str) -> None:
        """Render and save HTML report to disk."""
        content = self.generate(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
