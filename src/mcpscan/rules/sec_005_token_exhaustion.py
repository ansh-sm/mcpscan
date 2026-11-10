"""Rule MCP-SEC-005: Unbounded Collections & Token Denial of Service (DoS) Risk.

Detects unbounded string arrays, missing maxItems, or missing maxLength attributes in tool input schemas
which can be exploited by malicious actors to exhaust host context windows or cause ReDoS / resource starvation.

Uses recursive schema traversal to inspect collections inside nested structures.
"""


from mcpscan.models import (
    Confidence,
    Finding,
    FindingLocation,
    ServerManifest,
    Severity,
)
from mcpscan.rules.base import BaseRule
from mcpscan.schema_utils import walk_schema


class TokenExhaustionRule(BaseRule):
    rule_id = "MCP-SEC-005"
    title = "Unbounded Schema Input / Token Exhaustion Risk"
    severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    description = (
        "The tool parameter schema accepts unbounded arrays or strings without 'maxItems' or 'maxLength' boundaries. "
        "Adversaries can craft giant payloads exceeding LLM token context limits, leading to denial of service or context truncation."
    )
    remediation = (
        "Define explicit schema constraints: specify 'maxItems' on all array parameters and 'maxLength' "
        "on open-ended text inputs to enforce strict token limits."
    )
    cwe = "CWE-400: Uncontrolled Resource Consumption"
    owasp_llm = "LLM04: Model Denial of Service"

    def evaluate(self, manifest: ServerManifest) -> list[Finding]:
        findings: list[Finding] = []

        for tool in manifest.tools:
            tool_name = tool.get("name", "unnamed_tool")
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                continue

            for node in walk_schema(schema):
                prop_data = node.schema
                prop_type = prop_data.get("type")

                # Check 1: Array without maxItems
                if prop_type == "array" and "maxItems" not in prop_data:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Unbounded array parameter '{node.name}' in tool '{tool_name}'",
                            severity=self.severity,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Array parameter '{node.name}' at path '{node.json_path}' in tool '{tool_name}' lacks 'maxItems' constraint, "
                                "leaving it vulnerable to large-payload context window exhaustion."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="tool_param",
                                target_name=f"{tool_name}.{node.name}",
                                path=f"inputSchema.{node.json_path}",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence="type: array without maxItems",
                        )
                    )

                # Check 2: Raw string without maxLength when name implies multi-line or bulk input
                if prop_type == "string" and "maxLength" not in prop_data:
                    if any(term in node.name.lower() for term in ["content", "data", "body", "payload", "document", "text"]):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Unbounded bulk text parameter '{node.name}' in tool '{tool_name}'",
                                severity=Severity.LOW,
                                confidence=Confidence.MEDIUM,
                                description=(
                                    f"Bulk text parameter '{node.name}' at path '{node.json_path}' lacks 'maxLength' constraint. "
                                    "Consider setting a sensible upper bound to avoid excessive context consumption."
                                ),
                                remediation=self.remediation,
                                location=FindingLocation(
                                target_type="tool_param",
                                target_name=f"{tool_name}.{node.name}",
                                path=f"inputSchema.{node.json_path}",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence="type: string without maxLength",
                        )
                    )

        return findings
