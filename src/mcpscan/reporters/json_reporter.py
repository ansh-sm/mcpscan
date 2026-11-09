"""JSON security audit report generator for pipeline automation and SIEM ingestion."""

import json
from typing import Any, Dict
from mcpscan.models import AssessmentReport


class JsonReporter:
    """Serializes complete AssessmentReport objects to standard JSON."""

    def generate(self, report: AssessmentReport) -> Dict[str, Any]:
        """Convert AssessmentReport into a dictionary."""
        return report.model_dump()

    def save(self, report: AssessmentReport, output_path: str) -> None:
        """Write AssessmentReport to a file formatted as JSON."""
        data = self.generate(report)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
