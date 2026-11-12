"""Unit tests for report diffing, posture regressions, and CI/CD PR gate integration."""

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.diff import compute_diff, load_report_from_file
from mcpscan.models import (
    AssessmentReport,
    Finding,
    FindingLocation,
    PostureGrade,
    Severity,
)
from mcpscan.reporters.markdown_diff import MarkdownDiffReporter
from mcpscan.reporters.terminal_diff import TerminalDiffReporter

runner = CliRunner()


@pytest.fixture
def clean_report() -> AssessmentReport:
    return AssessmentReport(
        server_name="TestServer",
        server_version="1.0.0",
        grade=PostureGrade.A_PLUS,
        score=100,
        findings=[],
        tools_count=2,
        resources_count=1,
        prompts_count=0,
        scan_timestamp="2026-11-12T00:00:00Z",
        scan_complete=True,
        scan_errors=[],
    )


@pytest.fixture
def vuln_report() -> AssessmentReport:
    return AssessmentReport(
        server_name="TestServer",
        server_version="1.1.0",
        grade=PostureGrade.B,
        score=75,
        findings=[
            Finding(
                rule_id="MCP-SEC-002",
                title="Unconstrained command parameter 'cmd'",
                severity=Severity.HIGH,
                description="Command execution risk",
                remediation="Constrain with enum",
                location=FindingLocation(
                    target_type="tool_param",
                    target_name="shell.cmd",
                    path="inputSchema.properties.cmd",
                ),
            )
        ],
        tools_count=2,
        resources_count=1,
        prompts_count=0,
        scan_timestamp="2026-11-12T01:00:00Z",
        scan_complete=True,
        scan_errors=[],
    )


def test_diff_detects_new_regression(clean_report, vuln_report):
    """Diffing clean baseline against vulnerable current must detect regression."""
    diff = compute_diff(baseline=clean_report, current=vuln_report)

    assert diff.has_regressions is True
    assert diff.is_improved is False
    assert diff.score_delta == -25
    assert diff.baseline_grade == PostureGrade.A_PLUS
    assert diff.current_grade == PostureGrade.B
    assert len(diff.new_findings) == 1
    assert diff.new_findings[0].rule_id == "MCP-SEC-002"
    assert len(diff.resolved_findings) == 0
    assert len(diff.unresolved_findings) == 0


def test_diff_detects_resolved_finding(clean_report, vuln_report):
    """Diffing vulnerable baseline against clean current must detect resolved findings."""
    diff = compute_diff(baseline=vuln_report, current=clean_report)

    assert diff.has_regressions is False
    assert diff.is_improved is True
    assert diff.score_delta == 25
    assert len(diff.resolved_findings) == 1
    assert diff.resolved_findings[0].rule_id == "MCP-SEC-002"
    assert len(diff.new_findings) == 0


def test_diff_unchanged_reports(vuln_report):
    """Identical reports produce zero delta and mark findings unresolved."""
    diff = compute_diff(baseline=vuln_report, current=vuln_report)

    assert diff.has_regressions is False
    assert diff.is_improved is False
    assert diff.score_delta == 0
    assert len(diff.new_findings) == 0
    assert len(diff.resolved_findings) == 0
    assert len(diff.unresolved_findings) == 1


def test_load_report_from_file_valid(tmp_path, clean_report):
    """Valid JSON file deserializes into AssessmentReport."""
    path = tmp_path / "report.json"
    path.write_text(clean_report.model_dump_json(), encoding="utf-8")

    loaded = load_report_from_file(str(path))
    assert loaded.server_name == clean_report.server_name
    assert loaded.score == 100


def test_load_report_from_file_missing():
    """Non-existent path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="Report file not found"):
        load_report_from_file("missing_report_file.json")


def test_load_report_from_file_malformed(tmp_path):
    """Corrupted JSON raises ValueError."""
    path = tmp_path / "bad.json"
    path.write_text("{ corrupt json ...", encoding="utf-8")

    with pytest.raises(ValueError, match="Failed to read report JSON"):
        load_report_from_file(str(path))


def test_markdown_diff_reporter(tmp_path, clean_report, vuln_report):
    """MarkdownDiffReporter generates valid PR comment markdown with alert banners."""
    diff = compute_diff(baseline=clean_report, current=vuln_report)
    reporter = MarkdownDiffReporter()

    md_content = reporter.generate(diff)
    assert "# 🛡️ mcpscan Posture Delta Review" in md_content
    assert "Security Regression Detected" in md_content
    assert "-25 pts" in md_content
    assert "MCP-SEC-002" in md_content

    out_file = tmp_path / "diff.md"
    reporter.save(diff, str(out_file))
    assert out_file.exists()


def test_terminal_diff_reporter(clean_report, vuln_report):
    """TerminalDiffReporter executes without raising exceptions."""
    diff = compute_diff(baseline=clean_report, current=vuln_report)
    reporter = TerminalDiffReporter()
    reporter.render(diff)


def test_cli_diff_regression_exit_code_2(tmp_path, clean_report, vuln_report):
    """CLI diff with --fail-on-regression must exit with code 2 on new findings."""
    base_file = tmp_path / "base.json"
    curr_file = tmp_path / "curr.json"
    base_file.write_text(clean_report.model_dump_json(), encoding="utf-8")
    curr_file.write_text(vuln_report.model_dump_json(), encoding="utf-8")

    # Without flag -> exit 0
    result_ok = runner.invoke(app, ["diff", str(base_file), str(curr_file)])
    assert result_ok.exit_code == 0

    # With --fail-on-regression -> exit 2
    result_fail = runner.invoke(app, ["diff", str(base_file), str(curr_file), "--fail-on-regression"])
    assert result_fail.exit_code == 2
    assert "CI/CD Gate Failed" in result_fail.output


def test_cli_diff_exports_markdown_and_json(tmp_path, clean_report, vuln_report):
    """CLI diff generates exported markdown and json files correctly."""
    base_file = tmp_path / "base.json"
    curr_file = tmp_path / "curr.json"
    md_out = tmp_path / "pr_diff.md"
    json_out = tmp_path / "diff_data.json"

    base_file.write_text(clean_report.model_dump_json(), encoding="utf-8")
    curr_file.write_text(vuln_report.model_dump_json(), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "diff",
            str(base_file),
            str(curr_file),
            "-M",
            str(md_out),
            "-j",
            str(json_out),
        ],
    )
    assert result.exit_code == 0
    assert md_out.exists()
    assert json_out.exists()

    diff_dict = json.loads(json_out.read_text(encoding="utf-8"))
    assert diff_dict["score_delta"] == -25
    assert len(diff_dict["new_findings"]) == 1
