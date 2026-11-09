"""Rule MCP-SEC-006: Server-Side Request Forgery (SSRF) & Arbitrary Network Egress Risk.

Audits tool parameter definitions and schemas for unconstrained network URL inputs,
webhook destinations, or host targets lacking protocol, domain whitelist, or private CIDR validation.
"""

from typing import Any, Dict, List
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class SSRFNetworkEgressRule(BaseRule):
    rule_id = "MCP-SEC-006"
    title = "Unconstrained Network Target / Server-Side Request Forgery (SSRF) Risk"
    severity = Severity.HIGH
    description = (
        "The tool defines a URL, webhook, or host address parameter without explicit protocol, "
        "domain whitelist, or private IP address restrictions, potentially allowing adversaries "
        "to trigger SSRF attacks against internal network endpoints (e.g. cloud metadata services, 169.254.169.254, localhost)."
    )
    remediation = (
        "Enforce strict URL schema validation using regex 'pattern' enforcing HTTPS schemes and explicit domain whitelists. "
        "Disallow internal IP addresses (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.169.254)."
    )
    cwe = "CWE-918: Server-Side Request Forgery (SSRF)"
    owasp_llm = "LLM06: Excessive Agency"

    URL_PARAM_NAMES = {
        "url", "endpoint", "target_url", "webhook", "webhook_url",
        "callback", "callback_url", "api_url", "host", "domain"
    }

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

                if prop_name.lower() in self.URL_PARAM_NAMES:
                    has_format = prop_data.get("format") == "uri"
                    has_pattern = "pattern" in prop_data
                    has_enum = "enum" in prop_data

                    # If the parameter accepts arbitrary URLs without pattern or enum restrictions
                    if not has_pattern and not has_enum:
                        evidence_msg = f"Parameter '{prop_name}' lacks pattern/domain constraints"
                        if not has_format:
                            evidence_msg += " and missing URI format validator"

                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Unconstrained URL parameter '{prop_name}' in tool '{tool_name}'",
                                severity=self.severity,
                                description=(
                                    f"Tool '{tool_name}' accepts external URL parameter '{prop_name}' "
                                    "without restricting target domains or enforcing private IP boundary protections."
                                ),
                                remediation=self.remediation,
                                location=FindingLocation(
                                    target_type="tool_param",
                                    target_name=f"{tool_name}.{prop_name}",
                                    path=f"inputSchema.properties.{prop_name}",
                                ),
                                cwe=self.cwe,
                                owasp_llm=self.owasp_llm,
                                evidence=evidence_msg,
                            )
                        )

        return findings
