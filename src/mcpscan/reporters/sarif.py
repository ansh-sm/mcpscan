"""OASIS SARIF 2.1.0 document generator for CI/CD integrations."""

import json
from typing import Any, Dict, List
from mcpscan import __version__
from mcpscan.models import AssessmentReport, Severity


class SarifReporter:
    """Generates standard OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0 JSON reports."""

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"

    # Map mcpscan Severity to SARIF levels
    SEVERITY_TO_SARIF_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    def generate(self, report: AssessmentReport) -> Dict[str, Any]:
        """Convert an AssessmentReport into a valid SARIF 2.1.0 dictionary."""
        # 1. Build distinct rules list
        rules_map: Dict[str, Dict[str, Any]] = {}
        for finding in report.findings:
            if finding.rule_id not in rules_map:
                sarif_rule: Dict[str, Any] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {"text": f"Remediation: {finding.remediation}"},
                    "defaultConfiguration": {
                        "level": self.SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
                    },
                    "properties": {},
                }
                if finding.cwe:
                    sarif_rule["properties"]["cwe"] = finding.cwe
                if finding.owasp_llm:
                    sarif_rule["properties"]["owasp_llm"] = finding.owasp_llm

                rules_map[finding.rule_id] = sarif_rule

        # 2. Build results list
        results: List[Dict[str, Any]] = []
        for finding in report.findings:
            result_item: Dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": self.SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {
                    "text": (
                        f"{finding.title}: {finding.description} "
                        f"[Target: {finding.location.target_name} at {finding.location.path or 'manifest'}]"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"mcp://{report.server_name}/{finding.location.target_type}/{finding.location.target_name}",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        },
                        "logicalLocations": [
                            {
                                "name": finding.location.target_name,
                                "kind": finding.location.target_type,
                            }
                        ],
                    }
                ],
            }
            results.append(result_item)

        # 3. Build invocation with honest execution status
        invocation: Dict[str, Any] = {
            "executionSuccessful": report.scan_complete,
            "endTimeUtc": report.scan_timestamp,
        }
        if report.scan_errors:
            invocation["toolExecutionNotifications"] = [
                {
                    "level": "warning",
                    "message": {"text": err},
                    "descriptor": {"id": "SCAN-INCOMPLETE"},
                }
                for err in report.scan_errors
            ]

        # 4. Assemble complete SARIF 2.1.0 document
        sarif_doc: Dict[str, Any] = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcpscan",
                            "semanticVersion": __version__,
                            "informationUri": "https://github.com/ansh-sm/mcpscan",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "invocations": [invocation],
                    "results": results,
                }
            ],
        }

        return sarif_doc

    def save(self, report: AssessmentReport, output_path: str) -> None:
        """Serialize SARIF 2.1.0 document to a file."""
        sarif_data = self.generate(report)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
