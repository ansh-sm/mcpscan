"""Integration tests for HTML reporting and rule filtering flags."""

import os
import sys

import pytest

from mcpscan.connector import MCPConnector
from mcpscan.engine import SecurityEngine
from mcpscan.reporters.html_reporter import HtmlReporter

CMD_VULN_SERVER = (
    r".\.venv\Scripts\python tests/fixtures/vulnerable_server.py"
    if os.path.exists(r".\.venv\Scripts\python.exe")
    else f"{sys.executable} tests/fixtures/vulnerable_server.py"
)


@pytest.mark.asyncio
async def test_html_dashboard_generation(tmp_path):
    connector = MCPConnector(timeout=10.0)
    manifest = await connector.connect_stdio(CMD_VULN_SERVER)
    
    engine = SecurityEngine()
    report = engine.audit(manifest)

    html_file = tmp_path / "dashboard.html"
    HtmlReporter().save(report, str(html_file))

    assert html_file.exists()
    content = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "mcpscan Security Assessment" in content
    assert "MCP-SEC-001" in content
    assert report.server_name in content


@pytest.mark.asyncio
async def test_rule_filtering_select_and_ignore():
    connector = MCPConnector(timeout=10.0)
    manifest = await connector.connect_stdio(CMD_VULN_SERVER)
    
    engine = SecurityEngine()

    # 1. Test selecting only MCP-SEC-001
    rep_selected = engine.audit(manifest, enabled_rules=["MCP-SEC-001"])
    rule_ids = {f.rule_id for f in rep_selected.findings}
    assert "MCP-SEC-001" in rule_ids
    assert "MCP-SEC-002" not in rule_ids

    # 2. Test ignoring MCP-SEC-001
    rep_ignored = engine.audit(manifest, disabled_rules=["MCP-SEC-001"])
    rule_ids_ignored = {f.rule_id for f in rep_ignored.findings}
    assert "MCP-SEC-001" not in rule_ids_ignored
    assert "MCP-SEC-002" in rule_ids_ignored
