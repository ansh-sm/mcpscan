"""Report diffing engine for comparing security posture between scan snapshots.

Enables CI/CD PR regression gates by calculating score deltas, identifying newly
introduced vulnerabilities, and tracking resolved security findings across scans.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from mcpscan.config import compute_finding_fingerprint
from mcpscan.models import AssessmentReport, Finding, PostureGrade


class DiffReport(BaseModel):
    """Structured delta between two security assessment reports."""

    baseline_server: str
    baseline_version: str
    current_server: str
    current_version: str

    baseline_score: int
    current_score: int
    score_delta: int = Field(..., description="current_score - baseline_score")

    baseline_grade: PostureGrade
    current_grade: PostureGrade

    new_findings: List[Finding] = Field(
        default_factory=list,
        description="Vulnerabilities present in current scan but absent in baseline (regressions)",
    )
    resolved_findings: List[Finding] = Field(
        default_factory=list,
        description="Vulnerabilities present in baseline that have been remediated in current scan",
    )
    unresolved_findings: List[Finding] = Field(
        default_factory=list,
        description="Vulnerabilities present in both baseline and current scans",
    )

    baseline_scan_complete: bool = True
    current_scan_complete: bool = True

    @property
    def has_regressions(self) -> bool:
        """True if any new findings were introduced or if score degraded."""
        return len(self.new_findings) > 0 or self.score_delta < 0

    @property
    def is_improved(self) -> bool:
        """True if score increased and no new findings were introduced."""
        return self.score_delta > 0 and len(self.new_findings) == 0


def _build_fingerprint_map(findings: List[Finding]) -> Dict[str, Finding]:
    """Map SHA-256 finding fingerprints to finding instances."""
    res: Dict[str, Finding] = {}
    for f in findings:
        fp = compute_finding_fingerprint(
            f.rule_id,
            f.location.target_name,
            f.location.path,
        )
        res[fp] = f
    return res


def compute_diff(
    baseline: AssessmentReport,
    current: AssessmentReport,
) -> DiffReport:
    """Compare baseline and current assessment reports to produce a DiffReport.

    Findings are matched across snapshots using their stable SHA-256 fingerprints.
    """
    baseline_map = _build_fingerprint_map(baseline.findings)
    current_map = _build_fingerprint_map(current.findings)

    baseline_fps = set(baseline_map.keys())
    current_fps = set(current_map.keys())

    new_fps = current_fps - baseline_fps
    resolved_fps = baseline_fps - current_fps
    common_fps = current_fps & baseline_fps

    new_findings = [current_map[fp] for fp in sorted(new_fps)]
    resolved_findings = [baseline_map[fp] for fp in sorted(resolved_fps)]
    unresolved_findings = [current_map[fp] for fp in sorted(common_fps)]

    score_delta = current.score - baseline.score

    return DiffReport(
        baseline_server=baseline.server_name,
        baseline_version=baseline.server_version,
        current_server=current.server_name,
        current_version=current.server_version,
        baseline_score=baseline.score,
        current_score=current.score,
        score_delta=score_delta,
        baseline_grade=baseline.grade,
        current_grade=current.grade,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unresolved_findings=unresolved_findings,
        baseline_scan_complete=baseline.scan_complete,
        current_scan_complete=current.scan_complete,
    )


def load_report_from_file(path_str: str) -> AssessmentReport:
    """Load and validate an AssessmentReport from a JSON file path.

    Raises FileNotFoundError if file is absent, or ValueError if JSON is malformed.
    """
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"Report file not found: {path_str}")

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except Exception as exc:
        raise ValueError(f"Failed to read report JSON from {path_str}: {exc}") from exc

    try:
        return AssessmentReport.model_validate(data)
    except Exception as exc:
        raise ValueError(f"File {path_str} does not match AssessmentReport schema: {exc}") from exc
