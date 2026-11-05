"""Rule MCP-SEC-002: Excessive Execution & Unconstrained Parameters.

Detects dangerous parameter names (e.g., 'command', 'cmd', 'script', 'eval', 'exec')
that lack strict enum, pattern, or length bounds in their JSON schemas.
"""

from typing import List, Optional
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class ExcessiveExecutionRule(BaseRule):
    rule_id = "MCP-SEC-002"
    title = "Unconstrained Arbitrary Command / Shell Execution Parameter"
    severity = Severity.HIGH
    description = (
        "The tool defines an arbitrary code or command execution parameter (e.g. 'command', 'cmd', 'eval') "
        "without strict validation constraints such as an enum list, regex pattern, or maximum length restriction."
    )
    remediation = (
        "Constrain command parameters with strict allowed values using JSON Schema 'enum', "
        "or enforce a restrictive regex 'pattern'. Avoid exposing raw shell pass-through parameters."
    )
    cwe = "CWE-78: OS Command Injection"
    owasp_llm = "LLM06: Excessive Agency"

    DANGEROUS_PARAM_NAMES = {
        "command", "cmd", "exec", "execute", "shell", "script",
        "eval", "bash", "powershell", "code", "run_cmd"
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

                if prop_name.lower() in self.DANGEROUS_PARAM_NAMES:
                    # Check if constrained
                    has_enum = "enum" in prop_data
                    has_pattern = "pattern" in prop_data
                    has_max_length = "maxLength" in prop_data

                    if not has_enum and not has_pattern:
                        evidence_parts = [f"type: {prop_data.get('type', 'any')}"]
                        if not has_max_length:
                            evidence_parts.append("unbounded length")

                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"Unconstrained command parameter '{prop_name}' in tool '{tool_name}'",
                                severity=self.severity,
                                description=(
                                    f"Tool '{tool_name}' exposes parameter '{prop_name}' which indicates arbitrary code/command "
                                    "execution, but provides neither an 'enum' whitelist nor a validating 'pattern'."
                                ),
                                remediation=self.remediation,
                                location=FindingLocation(
                                    target_type="tool_param",
                                    target_name=f"{tool_name}.{prop_name}",
                                    path=f"inputSchema.properties.{prop_name}",
                                ),
                                cwe=self.cwe,
                                owasp_llm=self.owasp_llm,
                                evidence=", ".join(evidence_parts),
                            )
                        )

        return findings
