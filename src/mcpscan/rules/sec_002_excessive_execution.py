"""Rule MCP-SEC-002: Excessive Execution & Unconstrained Parameters.

Detects dangerous parameter names (e.g., 'command', 'cmd', 'script', 'eval', 'exec')
that lack strict enum, pattern, or length bounds in their JSON schemas.

Uses recursive schema traversal to detect dangerous params hidden inside
nested objects, arrays, or composition branches.
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


class ExcessiveExecutionRule(BaseRule):
    rule_id = "MCP-SEC-002"
    title = "Unconstrained Arbitrary Command / Shell Execution Parameter"
    severity = Severity.HIGH
    default_confidence = Confidence.MEDIUM
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
        "eval", "bash", "powershell", "code", "run_cmd",
    }

    def evaluate(self, manifest: ServerManifest) -> list[Finding]:
        findings: list[Finding] = []

        for tool in manifest.tools:
            tool_name = tool.get("name", "unnamed_tool")
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                continue

            for node in walk_schema(schema):
                if node.name.lower() not in self.DANGEROUS_PARAM_NAMES:
                    continue

                prop_data = node.schema
                has_enum = "enum" in prop_data
                has_pattern = "pattern" in prop_data
                has_max_length = "maxLength" in prop_data

                if not has_enum and not has_pattern:
                    evidence_parts = [f"type: {prop_data.get('type', 'any')}"]
                    if not has_max_length:
                        evidence_parts.append("unbounded length")

                    # Deeper nesting = lower confidence (might be legitimate nested config)
                    confidence = Confidence.HIGH if node.depth == 0 else Confidence.MEDIUM

                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Unconstrained command parameter '{node.name}' in tool '{tool_name}'",
                            severity=self.severity,
                            confidence=confidence,
                            description=(
                                f"Tool '{tool_name}' exposes parameter '{node.name}' at path "
                                f"'{node.json_path}' which indicates arbitrary code/command "
                                "execution, but provides neither an 'enum' whitelist nor a validating 'pattern'."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="tool_param",
                                target_name=f"{tool_name}.{node.name}",
                                path=f"inputSchema.{node.json_path}",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence=", ".join(evidence_parts),
                        )
                    )

        return findings
