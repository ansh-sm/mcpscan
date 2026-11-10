"""Shared test fixtures and cross-platform helpers for mcpscan test suite."""

import os
import sys

import pytest

from mcpscan.models import (
    AssessmentReport,
    Finding,
    FindingLocation,
    PostureGrade,
    ServerManifest,
    Severity,
)

PYTHON_EXE = (
    r".\.venv\Scripts\python"
    if os.path.exists(r".\.venv\Scripts\python.exe")
    else sys.executable
)


@pytest.fixture
def smoke_server_cmd() -> str:
    """Cross-platform command to spawn smoke test MCP server over stdio."""
    return f"{PYTHON_EXE} tests/fixtures/smoke_server.py"


@pytest.fixture
def vuln_server_cmd() -> str:
    """Cross-platform command to spawn deliberately vulnerable MCP server over stdio."""
    return f"{PYTHON_EXE} tests/fixtures/vulnerable_server.py"


@pytest.fixture
def clean_manifest() -> ServerManifest:
    """A clean server manifest with no security flaws."""
    return ServerManifest(
        server_info={"name": "CleanDemoServer", "version": "1.0.0"},
        capabilities={"tools": {}},
        tools=[
            {
                "name": "safe_calculator",
                "description": "Calculates simple addition of two integers.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer"},
                        "b": {"type": "integer"},
                    },
                    "required": ["a", "b"],
                },
            }
        ],
        resources=[],
        prompts=[],
        scan_complete=True,
        scan_errors=[],
    )


@pytest.fixture
def sample_report() -> AssessmentReport:
    """A sample assessment report with one finding."""
    return AssessmentReport(
        server_name="TestTargetServer",
        server_version="1.2.3",
        grade=PostureGrade.B,
        score=75,
        findings=[
            Finding(
                rule_id="MCP-SEC-002",
                title="Unconstrained command parameter 'command'",
                severity=Severity.HIGH,
                description="Command parameter lacks validation bounds.",
                remediation="Constrain with enum or regex pattern.",
                location=FindingLocation(
                    target_type="tool_param",
                    target_name="executor.command",
                    path="inputSchema.properties.command",
                ),
                cwe="CWE-78",
                owasp_llm="LLM06",
                evidence="type: string",
            )
        ],
        tools_count=1,
        resources_count=0,
        prompts_count=0,
        scan_timestamp="2026-11-11T00:00:00Z",
        scan_complete=True,
        scan_errors=[],
        suppressed_count=0,
    )
