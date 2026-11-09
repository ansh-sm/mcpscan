"""Typed domain models for findings, manifests, and assessment reports."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingLocation(BaseModel):
    """Precise location of a detected security finding."""

    target_type: str = Field(..., description="Type of target, such as tool, resource, or prompt")
    target_name: str = Field(..., description="Identifier name of the component")
    path: Optional[str] = Field(None, description="JSON path within the schema or manifest")


class Finding(BaseModel):
    """An individual heuristic security finding."""

    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Short summary of the finding")
    severity: Severity = Field(..., description="Finding severity")
    description: str = Field(..., description="Explanation of the detected risk indicator")
    remediation: str = Field(..., description="Suggested remediation")
    location: FindingLocation = Field(..., description="Component and path where detected")
    cwe: Optional[str] = Field(None, description="Common Weakness Enumeration reference")
    owasp_llm: Optional[str] = Field(None, description="OWASP LLM Top 10 reference")
    evidence: Optional[str] = Field(None, description="Sanitized evidence that triggered the rule")


class ServerManifest(BaseModel):
    """Snapshot of an MCP server's declared attack surface."""

    server_info: Dict[str, Any] = Field(default_factory=dict)
    capabilities: Dict[str, Any] = Field(default_factory=dict)
    tools: List[Dict[str, Any]] = Field(default_factory=list)
    resources: List[Dict[str, Any]] = Field(default_factory=list)
    prompts: List[Dict[str, Any]] = Field(default_factory=list)
    scan_complete: bool = Field(True, description="Whether all advertised scan stages completed")
    scan_errors: List[str] = Field(default_factory=list, description="Sanitized scan-stage failures")


class PostureGrade(str, Enum):
    """Human-readable summary grade for the heuristic score."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class AssessmentReport(BaseModel):
    """Unified security assessment report; findings are heuristic, not a certification."""

    server_name: str
    server_version: str
    grade: PostureGrade
    score: int = Field(..., ge=0, le=100, description="Heuristic score from 0 to 100")
    findings: List[Finding] = Field(default_factory=list)
    tools_count: int
    resources_count: int
    prompts_count: int
    scan_timestamp: str
    scan_complete: bool = Field(True, description="False means results must not be interpreted as clean")
    scan_errors: List[str] = Field(default_factory=list, description="Sanitized scan-stage failures")
