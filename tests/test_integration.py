"""Integration tests for end-to-end scanner execution and SARIF generation."""

import json
import os
import sys

import pytest

from mcpscan.connector import MCPConnector
from mcpscan.engine import SecurityEngine
from mcpscan.models import PostureGrade
from mcpscan.reporters.sarif import SarifReporter

CMD_SMOKE_SERVER = (
    r".\.venv\Scripts\python tests/fixtures/smoke_server.py"
    if os.path.exists(r".\.venv\Scripts\python.exe")
    else f"{sys.executable} tests/fixtures/smoke_server.py"
)

CMD_VULN_SERVER = (
    r".\.venv\Scripts\python tests/fixtures/vulnerable_server.py"
    if os.path.exists(r".\.venv\Scripts\python.exe")
    else f"{sys.executable} tests/fixtures/vulnerable_server.py"
)


@pytest.mark.asyncio
async def test_e2e_clean_server(tmp_path):
    connector = MCPConnector(timeout=10.0)
    manifest = await connector.connect_stdio(CMD_SMOKE_SERVER)
    
    engine = SecurityEngine()
    report = engine.audit(manifest)

    assert report.score == 100
    assert report.grade == PostureGrade.A_PLUS
    assert len(report.findings) == 0

    # SARIF generation verification
    sarif_path = tmp_path / "clean.sarif"
    SarifReporter().save(report, str(sarif_path))
    assert sarif_path.exists()

    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 0


@pytest.mark.asyncio
async def test_e2e_vulnerable_server(tmp_path):
    connector = MCPConnector(timeout=10.0)
    manifest = await connector.connect_stdio(CMD_VULN_SERVER)
    
    engine = SecurityEngine()
    report = engine.audit(manifest)

    assert report.score < 40
    assert len(report.findings) >= 8

    rule_ids = {f.rule_id for f in report.findings}
    for i in range(1, 9):
        assert f"MCP-SEC-{i:03d}" in rule_ids, f"Expected MCP-SEC-{i:03d} to trigger"

    # SARIF generation verification
    sarif_path = tmp_path / "vuln.sarif"
    SarifReporter().save(report, str(sarif_path))
    assert sarif_path.exists()

    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 8
    # Verify SARIF contains partialFingerprints and confidence
    first_result = sarif_data["runs"][0]["results"][0]
    assert "partialFingerprints" in first_result
    assert "confidence" in first_result["properties"]
