"""Security posture evaluation and scoring engine."""

from datetime import datetime, timezone
from typing import List, Optional
from mcpscan.models import AssessmentReport, Finding, PostureGrade, ServerManifest, Severity
from mcpscan.rules import registry


class SecurityEngine:
    """Orchestrates security rule analysis and computes standardized posture grades."""

    # Penalty weights aligned with risk severity
    SEVERITY_PENALTIES = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    def __init__(self, rule_registry=None):
        self.registry = rule_registry or registry

    def audit(
        self,
        manifest: ServerManifest,
        enabled_rules: Optional[List[str]] = None,
        disabled_rules: Optional[List[str]] = None,
    ) -> AssessmentReport:
        """Run registered rules against the manifest and generate an AssessmentReport."""
        scan_errors = list(manifest.scan_errors)

        findings: List[Finding] = self.registry.run_all(
            manifest,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            errors=scan_errors,
        )

        # Calculate composite score starting from 100
        score = 100
        for f in findings:
            penalty = self.SEVERITY_PENALTIES.get(f.severity, 0)
            score -= penalty

        score = max(0, min(100, score))

        # Assign Posture Grade
        if score >= 95:
            grade = PostureGrade.A_PLUS
        elif score >= 85:
            grade = PostureGrade.A
        elif score >= 75:
            grade = PostureGrade.B
        elif score >= 60:
            grade = PostureGrade.C
        elif score >= 40:
            grade = PostureGrade.D
        else:
            grade = PostureGrade.F

        server_info = manifest.server_info or {}
        server_name = server_info.get("name", "unknown")
        server_version = server_info.get("version", "unknown")

        return AssessmentReport(
            server_name=server_name,
            server_version=server_version,
            grade=grade,
            score=score,
            findings=findings,
            tools_count=len(manifest.tools),
            resources_count=len(manifest.resources),
            prompts_count=len(manifest.prompts),
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            scan_complete=manifest.scan_complete and not scan_errors,
            scan_errors=scan_errors,
        )
