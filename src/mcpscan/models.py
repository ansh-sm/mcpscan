"""Typed domain models for findings, manifests, and assessment reports."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized vulnerability severity levels aligned with CVSS 3.1."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingLocation(BaseModel):
    """Precise location of a detected security vulnerability."""
    target_type: str = Field(..., description="Type of target (e.g., 'tool', 'resource', 'prompt')")
    target_name: str = Field(..., description="Identifier name of the component")
    path: Optional[str] = Field(None, description="JSON path within the schema/manifest (e.g., 'inputSchema.properties.command')")


class Finding(BaseModel):
    """An individual security finding detected by a rule."""
    rule_id: str = Field(..., description="Unique rule identifier (e.g., 'MCP-SEC-001')")
    title: str = Field(..., description="Short summary of the vulnerability")
    severity: Severity = Field(..., description="Vulnerability severity level")
    description: str = Field(..., description="Detailed explanation of the risk vector")
    remediation: str = Field(..., description="Prescriptive guidance to remediate the vulnerability")
    location: FindingLocation = Field(..., description="Component and path location where detected")
    cwe: Optional[str] = Field(None, description="Common Weakness Enumeration ID (e.g., 'CWE-77')")
    owasp_llm: Optional[str] = Field(None, description="OWASP Top 10 for LLMs category (e.g., 'LLM01: Prompt Injection')")
    evidence: Optional[str] = Field(None, description="Snippet or value triggering the detection")


class ServerManifest(BaseModel):
    """Extracted snapshot of the MCP server's declared attack surface."""
    server_info: Dict[str, Any] = Field(default_factory=dict, description="Implementation info returned during initialize")
    capabilities: Dict[str, Any] = Field(default_factory=dict, description="Declared server capabilities")
    tools: List[Dict[str, Any]] = Field(default_factory=list, description="Enumerated tools and JSON schemas")
    resources: List[Dict[str, Any]] = Field(default_factory=list, description="Declared static and dynamic resources")
    prompts: List[Dict[str, Any]] = Field(default_factory=list, description="Declared system prompt templates")


class PostureGrade(str, Enum):
    """Human-readable posture health grade."""
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class AssessmentReport(BaseModel):
    """Unified security posture evaluation report."""
    server_name: str
    server_version: str
    grade: PostureGrade
    score: int = Field(..., ge=0, le=100, description="0-100 normalized security posture score")
    findings: List[Finding] = Field(default_factory=list)
    tools_count: int
    resources_count: int
    prompts_count: int
    scan_timestamp: str
