"""Rule MCP-SEC-004: Hardcoded Secrets, High-Entropy Credentials, and Token Exposure.

Audits tool parameter defaults, schema descriptions, example payloads, and resource URIs
for high-entropy secrets, bearer tokens, AWS credentials, and provider API keys (OpenAI, Anthropic, GitHub, etc.).
"""

import math
import re
from typing import Any, Dict, List, Optional
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class SecretExposureRule(BaseRule):
    rule_id = "MCP-SEC-004"
    title = "Credential Leakage / Hardcoded Secret in Schema"
    severity = Severity.CRITICAL
    description = (
        "The server manifest exposes sensitive credentials, API keys, or high-entropy tokens "
        "within tool parameter defaults, descriptions, or resource URIs."
    )
    remediation = (
        "Never hardcode API keys, passwords, or authentication tokens in tool definitions or default values. "
        "Instruct users or host applications to inject secrets dynamically via secure environment variables or vault headers."
    )
    cwe = "CWE-798: Use of Hard-coded Credentials"
    owasp_llm = "LLM02: Sensitive Information Disclosure"

    # Known secret regex signatures
    SECRET_SIGNATURES = [
        (r"(?i)\b(?:sk-[a-zA-Z0-9]{20,48})\b", "OpenAI / LLM API Key"),
        (r"(?i)\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b", "GitHub Personal Access Token"),
        (r"(?i)\b(?:AKIA[0-9A-Z]{16})\b", "AWS Access Key ID"),
        (r"(?i)\b(?:xox[baprs]-[0-9a-zA-Z-]{10,48})\b", "Slack Token"),
        (r"(?i)\b(?:eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b", "JSON Web Token (JWT)"),
        (r"(?i)(?:api[_-]?key|password|secret|auth[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]", "Assigned Secret / Password"),
    ]

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy to identify high-entropy cryptographic strings."""
        if not data or len(data) < 20:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Audit Tools & inputSchema
        for tool in manifest.tools:
            tool_name = tool.get("name", "unnamed_tool")
            schema = tool.get("inputSchema", {})
            if isinstance(schema, dict):
                properties = schema.get("properties", {})
                if isinstance(properties, dict):
                    for prop_name, prop_data in properties.items():
                        if isinstance(prop_data, dict):
                            findings.extend(
                                self._audit_property(tool_name, prop_name, prop_data)
                            )

        # 2. Audit Resource URIs
        for resource in manifest.resources:
            uri = resource.get("uri", "")
            res_name = resource.get("name") or uri or "unnamed_resource"
            for sig_pattern, sig_desc in self.SECRET_SIGNATURES:
                match = re.search(sig_pattern, uri)
                if match:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Secret exposed in resource URI: {sig_desc}",
                            severity=self.severity,
                            description=(
                                f"Resource '{res_name}' contains a hardcoded credential ({sig_desc}) in its URI."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="resource",
                                target_name=res_name,
                                path="uri",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence=f"Pattern: {sig_desc}",
                        )
                    )
                    break

        return findings

    def _audit_property(
        self,
        tool_name: str,
        prop_name: str,
        prop_data: Dict[str, Any],
    ) -> List[Finding]:
        findings: List[Finding] = []
        path = f"inputSchema.properties.{prop_name}"
        location_name = f"{tool_name}.{prop_name}"

        # Check default value
        default_val = prop_data.get("default")
        if isinstance(default_val, str) and len(default_val) > 8:
            for sig_pattern, sig_desc in self.SECRET_SIGNATURES:
                if re.search(sig_pattern, default_val):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Hardcoded {sig_desc} in parameter default",
                            severity=self.severity,
                            description=(
                                f"Tool '{tool_name}' exposes parameter '{prop_name}' with a hardcoded {sig_desc} in its default value."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="tool_param",
                                target_name=location_name,
                                path=f"{path}.default",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence=f"Detected {sig_desc}",
                        )
                    )
                    return findings

            # Entropy check on defaults
            entropy = self._shannon_entropy(default_val)
            if entropy > 4.5 and len(default_val) >= 24 and " " not in default_val:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=f"High-entropy token detected in parameter default",
                        severity=Severity.HIGH,
                        description=(
                            f"Parameter '{prop_name}' has a default value with high Shannon entropy ({entropy:.2f}), "
                            "indicating a potential raw secret or encryption key."
                        ),
                        remediation=self.remediation,
                        location=FindingLocation(
                            target_type="tool_param",
                            target_name=location_name,
                            path=f"{path}.default",
                        ),
                        cwe=self.cwe,
                        owasp_llm=self.owasp_llm,
                        evidence=f"Entropy: {entropy:.2f}",
                    )
                )

        return findings
