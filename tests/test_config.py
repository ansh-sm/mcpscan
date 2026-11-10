"""Unit tests for project-level YAML configuration, finding fingerprinting, and suppressions."""

import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.config import (
    SuppressionEntry,
    compute_finding_fingerprint,
    load_config,
)
from mcpscan.engine import SecurityEngine
from mcpscan.models import ServerManifest

runner = CliRunner()


def test_fingerprint_deterministic():
    """Fingerprints must be stable SHA-256 hashes across identical calls."""
    fp1 = compute_finding_fingerprint("MCP-SEC-002", "shell_tool.command", "inputSchema.properties.command")
    fp2 = compute_finding_fingerprint("MCP-SEC-002", "shell_tool.command", "inputSchema.properties.command")
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex string


def test_fingerprint_differs_by_component():
    """Different components produce different fingerprints."""
    fp1 = compute_finding_fingerprint("MCP-SEC-002", "tool_a.cmd")
    fp2 = compute_finding_fingerprint("MCP-SEC-002", "tool_b.cmd")
    assert fp1 != fp2


def test_load_config_defaults_when_no_file(tmp_path):
    """When no .mcpscan.yml exists, default config is returned."""
    cfg = load_config(search_dir=str(tmp_path))
    assert cfg.fail_under == 70
    assert cfg.timeout == 15
    assert cfg.select == []
    assert cfg.ignore == []
    assert cfg.suppress == []


def test_load_config_missing_explicit_path():
    """Specifying a non-existent explicit path must raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_config(explicit_path="non_existent_config.yml")


def test_load_config_valid_yaml(tmp_path):
    """Parses a valid .mcpscan.yml correctly."""
    config_file = tmp_path / ".mcpscan.yml"
    config_file.write_text(
        """
fail_under: 85
timeout: 30
select:
  - MCP-SEC-001
  - MCP-SEC-002
ignore:
  - MCP-SEC-005
output:
  sarif: "reports/audit.sarif"
  markdown: "reports/audit.md"
suppress:
  - fingerprint: "abc123def456"
    reason: "Known acceptable risk"
    expires: "2099-01-01"
""",
        encoding="utf-8",
    )

    cfg = load_config(search_dir=str(tmp_path))
    assert cfg.fail_under == 85
    assert cfg.timeout == 30
    assert cfg.select == ["MCP-SEC-001", "MCP-SEC-002"]
    assert cfg.ignore == ["MCP-SEC-005"]
    assert cfg.output.sarif == "reports/audit.sarif"
    assert cfg.output.markdown == "reports/audit.md"
    assert len(cfg.suppress) == 1
    assert cfg.suppress[0].fingerprint == "abc123def456"
    assert not cfg.suppress[0].is_expired


def test_suppression_entry_expiry():
    """Expired suppressions return is_expired=True."""
    entry_expired = SuppressionEntry(
        fingerprint="123",
        expires="2020-01-01",
    )
    assert entry_expired.is_expired is True

    entry_future = SuppressionEntry(
        fingerprint="123",
        expires="2099-12-31",
    )
    assert entry_future.is_expired is False

    entry_no_expiry = SuppressionEntry(fingerprint="123")
    assert entry_no_expiry.is_expired is False


def test_engine_filters_suppressed_findings():
    """Engine must exclude suppressed findings and avoid score deduction."""
    manifest = ServerManifest(
        tools=[
            {
                "name": "shell_tool",
                "description": "Runs commands",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                    },
                },
            }
        ]
    )

    # Without suppression
    engine = SecurityEngine()
    unfiltered_report = engine.audit(manifest)
    assert len(unfiltered_report.findings) == 1
    assert unfiltered_report.score == 85  # 100 - 15 (HIGH penalty)
    assert unfiltered_report.suppressed_count == 0

    # Calculate fingerprint of the finding
    fp = compute_finding_fingerprint(
        "MCP-SEC-002",
        "shell_tool.command",
        "inputSchema.command",
    )

    # With suppression
    suppressed_report = engine.audit(manifest, suppressed_fingerprints={fp})
    assert len(suppressed_report.findings) == 0
    assert suppressed_report.score == 100
    assert suppressed_report.suppressed_count == 1


def test_cli_fingerprint_command():
    """CLI fingerprint command prints expected hash."""
    result = runner.invoke(app, ["fingerprint", "MCP-SEC-002", "shell.command", "-p", "inputSchema.command"])
    assert result.exit_code == 0
    assert "Finding Fingerprint:" in result.output
    expected_fp = compute_finding_fingerprint("MCP-SEC-002", "shell.command", "inputSchema.command")
    assert expected_fp in result.output
