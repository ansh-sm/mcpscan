"""Tests verifying scan integrity, honest reporting, error handling, and CLI exit codes."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from mcpscan.cli import app
from mcpscan.connector import MCPConnector
from mcpscan.engine import SecurityEngine
from mcpscan.models import (
    AssessmentReport,
    PostureGrade,
    ServerManifest,
    Severity,
)
from mcpscan.reporters.html_reporter import HtmlReporter
from mcpscan.reporters.sarif import SarifReporter
from mcpscan.rules.base import BaseRule, RuleRegistry

runner = CliRunner()


@pytest.mark.asyncio
async def test_advertised_enumeration_failure_marks_scan_incomplete():
    """An advertised feature whose listing fails must be recorded as an error and mark scan incomplete."""
    connector = MCPConnector(timeout=5.0)

    # Mock session advertising tools and prompts
    mock_session = MagicMock()
    mock_session.initialize = AsyncMock(
        return_value=MagicMock(
            server_info=MagicMock(name="TestServer", version="1.0"),
            capabilities={"tools": {}, "prompts": {}},
        )
    )
    # tools succeeds, prompts fails
    mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))
    mock_session.list_prompts = AsyncMock(side_effect=RuntimeError("remote RPC failed"))

    manifest = await connector._extract_manifest_from_session(mock_session)

    assert manifest.scan_complete is False
    assert len(manifest.scan_errors) == 1
    assert "prompts enumeration failed (RuntimeError)" in manifest.scan_errors[0]


@pytest.mark.asyncio
async def test_unsupported_capability_does_not_mark_incomplete():
    """An unadvertised MCP feature must be safely skipped and not mark the scan incomplete."""
    connector = MCPConnector(timeout=5.0)

    mock_session = MagicMock()
    # Server advertises ONLY tools (resources and prompts are not supported)
    mock_session.initialize = AsyncMock(
        return_value=MagicMock(
            server_info=MagicMock(name="ToolOnlyServer", version="1.0"),
            capabilities={"tools": {}},
        )
    )
    mock_session.list_tools = AsyncMock(return_value=MagicMock(tools=[]))
    mock_session.list_resources = AsyncMock()
    mock_session.list_prompts = AsyncMock()

    manifest = await connector._extract_manifest_from_session(mock_session)

    assert manifest.scan_complete is True
    assert manifest.scan_errors == []
    # Verify unadvertised capabilities were never called
    mock_session.list_resources.assert_not_called()
    mock_session.list_prompts.assert_not_called()


def test_rule_exception_marks_report_incomplete_and_sanitizes():
    """A crashed rule must mark report incomplete without leaking raw exception details."""

    class CrashingRule(BaseRule):
        rule_id = "MCP-CRASH-001"
        title = "Crashing rule"
        severity = Severity.HIGH
        description = "Test rule"
        remediation = "Fix"
        cwe = "CWE-000"
        owasp_llm = "LLM00"

        def evaluate(self, manifest: ServerManifest):
            raise RuntimeError("CRITICAL_INTERNAL_DB_PASSWORD_LEAKED_TEXT")

    custom_registry = RuleRegistry()
    custom_registry.register(CrashingRule)

    engine = SecurityEngine(rule_registry=custom_registry)
    clean_manifest = ServerManifest(server_info={"name": "Test", "version": "1.0"})

    report = engine.audit(clean_manifest)

    assert report.scan_complete is False
    assert len(report.scan_errors) == 1
    # Check that error is recorded with sanitized exception type
    assert "rule MCP-CRASH-001 failed (RuntimeError)" in report.scan_errors[0]
    # Check that raw exception text is not leaked
    assert "CRITICAL_INTERNAL_DB_PASSWORD_LEAKED_TEXT" not in str(report.scan_errors)


def test_duplicate_rule_id_rejected():
    """Registering a rule with an existing identifier must raise ValueError."""

    class DummyRule(BaseRule):
        rule_id = "MCP-DUP-001"
        title = "Dummy rule"
        severity = Severity.LOW
        description = "Test"
        remediation = "None"
        cwe = "CWE-0"
        owasp_llm = "LLM0"

        def evaluate(self, manifest: ServerManifest):
            return []

    custom_registry = RuleRegistry()
    custom_registry.register(DummyRule)
    with pytest.raises(ValueError, match="Duplicate rule identifier"):
        custom_registry.register(DummyRule)


def test_cli_exits_nonzero_for_incomplete_scans(monkeypatch):
    """CLI must return exit code 3 when scan_complete is False."""
    incomplete_manifest = ServerManifest(
        server_info={"name": "BrokenServer", "version": "1.0"},
        scan_complete=False,
        scan_errors=["tools enumeration failed (ConnectionResetError)"],
    )

    async def fake_connect(self, cmd):
        return incomplete_manifest

    monkeypatch.setattr(MCPConnector, "connect_stdio", fake_connect)

    result = runner.invoke(app, ["scan", "-c", "dummy_server.py"])

    assert result.exit_code == 3
    assert "Scan incomplete" in result.output
    assert "tools enumeration failed" in result.output


def test_cli_validates_mutual_exclusion():
    """CLI must reject specifying both --command and --sse."""
    result = runner.invoke(app, ["scan", "-c", "python server.py", "--sse", "http://localhost:8000/sse"])
    assert result.exit_code != 0
    assert "Choose only one target" in result.output


def test_sarif_and_html_show_incomplete_status():
    """SARIF and HTML reporters must explicitly surface incomplete status and notifications."""
    report = AssessmentReport(
        server_name="PartialServer",
        server_version="0.5",
        grade=PostureGrade.B,
        score=80,
        tools_count=2,
        resources_count=0,
        prompts_count=0,
        scan_timestamp="2026-11-10T00:00:00Z",
        scan_complete=False,
        scan_errors=["resources enumeration failed (TimeoutError)"],
    )

    # 1. SARIF check
    sarif_doc = SarifReporter().generate(report)
    invocation = sarif_doc["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert len(invocation["toolExecutionNotifications"]) == 1
    assert "resources enumeration failed" in invocation["toolExecutionNotifications"][0]["message"]["text"]

    # 2. HTML check
    html_doc = HtmlReporter().generate(report)
    assert "Incomplete Scan Warning" in html_doc
    assert "resources enumeration failed (TimeoutError)" in html_doc
    assert "MCP server metadata security scanner" in html_doc
