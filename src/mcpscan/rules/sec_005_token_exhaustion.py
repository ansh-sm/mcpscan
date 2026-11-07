"""Rule MCP-SEC-005: Unbounded Collections & Token Denial of Service (DoS) Risk.

Detects unbounded string arrays, missing maxItems, or missing maxLength attributes in tool input schemas
which can be exploited by malicious actors to exhaust host context windows or cause ReDoS / resource starvation.
"""

from typing import Any, Dict, List
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class TokenExhaustionRule(BaseRule):
    rule_id = "MCP-SEC-005"
    title = "Unbounded Schema Input / Token Exhaustion Risk"
    severity = Severity.MEDIUM
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

    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        for tool in manifest.tools:
            tool_name = tool.get("name", "unnamed_tool")
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                continue

            properties = schema.get("properties", {})
            if not isinstance(properties, dict):
                continue

            for prop_name, prop_data in properties.items():
                if not isinstance(prop_data, dict):
                    continue

                prop_type = prop_data.get("type")

                # Check 1: Array without maxItems
                if prop_type == "array" and "maxItems" not in prop_data:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Unbounded array parameter '{prop_name}' in tool '{tool_name}'",
                            severity=self.severity,
                            description=(
                                f"Array parameter '{prop_name}' in tool '{tool_name}' lacks 'maxItems' constraint, "
                                "leaving it vulnerable to large-payload context window exhaustion."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="tool_param",
                                target_name=f"{tool_name}.{prop_name}",
                                path=f"inputSchema.properties.{prop_name}",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence="type: array without maxItems",
                        )
                    )

                # Check 2: Raw string without maxLength when name implies multi-line or bulk input
                if prop_type == "string" and "maxLength" not in prop_data:
                    if any(term in prop_name.lower() for term in ["content", "data", "body", "payload", "document", "text"]):
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Unbounded bulk text parameter '{prop_name}' in tool '{tool_name}'",
                                severity=Severity.LOW,
                                description=(
                                    f"Bulk text parameter '{prop_name}' lacks 'maxLength' constraint. "
                                    "Consider setting a sensible upper bound to avoid excessive context consumption."
                                ),
                                remediation=self.remediation,
                                location=FindingLocation(
                                    target_type="tool_param",
                                    target_name=f"{tool_name}.{prop_name}",
                                    path=f"inputSchema.properties.{prop_name}",
                                ),
                                cwe=self.cwe,
                                owasp_llm=self.owasp_llm,
                                evidence="type: string without maxLength",
                            )
                        )

        return findings
