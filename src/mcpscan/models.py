"""Typed domain models for findings, manifests, and assessment reports."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Detection confidence level distinguishing hard evidence from heuristic suspicion.

    HIGH   — deterministic match (regex hit on a known secret pattern, invisible Unicode found).
    MEDIUM — strong heuristic signal (dangerous param name + missing constraint).
    LOW    — speculative / name-based suspicion that warrants human review.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingLocation(BaseModel):
    """Precise location of a detected security finding."""

    target_type: str = Field(..., description="Type of target, such as tool, resource, or prompt")
    target_name: str = Field(..., description="Identifier name of the component")
    path: str | None = Field(None, description="JSON path within the schema or manifest")


class Finding(BaseModel):
    """An individual heuristic security finding."""

    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Short summary of the finding")
    severity: Severity = Field(..., description="Finding severity")
    confidence: Confidence = Field(
        Confidence.MEDIUM,
        description="Detection confidence: HIGH=deterministic, MEDIUM=strong heuristic, LOW=speculative",
    )
    description: str = Field(..., description="Explanation of the detected risk indicator")
    remediation: str = Field(..., description="Suggested remediation")
    location: FindingLocation = Field(..., description="Component and path where detected")
    cwe: str | None = Field(None, description="Common Weakness Enumeration reference")
    owasp_llm: str | None = Field(None, description="OWASP LLM Top 10 reference")
    evidence: str | None = Field(None, description="Sanitized evidence that triggered the rule")


class ServerManifest(BaseModel):
    """Snapshot of an MCP server's declared attack surface."""

    server_info: dict[str, Any] = Field(default_factory=dict)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    scan_complete: bool = Field(
        True,
        description="Whether all supported scan stages completed successfully",
    )
    scan_errors: list[str] = Field(
        default_factory=list,
        description="Sanitized scan-stage failures",
    )


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
    findings: list[Finding] = Field(default_factory=list)
    tools_count: int
    resources_count: int
    prompts_count: int
    scan_timestamp: str
    scan_complete: bool = Field(True, description="False means results must not be interpreted as clean")
    scan_errors: list[str] = Field(default_factory=list, description="Sanitized scan-stage failures")
    suppressed_count: int = Field(0, description="Count of findings suppressed via configuration")
