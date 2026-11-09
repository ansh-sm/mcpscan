"""Rule MCP-SEC-007: Undeclared / Unsafe Dynamic Prompt Template Injection Risk.

Audits MCP prompts declarations to ensure prompt arguments declare safety constraints,
do not accept unescaped system role overrides, and are not vulnerable to indirect prompt injection.
"""

import re
from typing import List
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class DynamicPromptInjectionRule(BaseRule):
    rule_id = "MCP-SEC-007"
    title = "Prompt Template Injection / Insecure Prompt Argument Risk"
    severity = Severity.HIGH
    description = (
        "The server declares system prompt templates with unconstrained or role-sensitive arguments "
        "(e.g. 'role', 'system_prompt', 'instructions') without boundary constraints, allowing users or "
        "adversaries to inject arbitrary instructions into the host LLM prompt pipeline."
    )
    remediation = (
        "Avoid exposing prompt arguments that directly control system instructions or model roles. "
        "Constrain prompt template arguments with strict input filtering and boundary encapsulation."
    )
    cwe = "CWE-77: Command Injection"
    owasp_llm = "LLM01: Prompt Injection"

    DANGEROUS_ARG_NAMES = {
        "role", "system_prompt", "system", "instruction", "instructions", "directive", "prompt_override"
    }

    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        for prompt in manifest.prompts:
            prompt_name = prompt.get("name", "unnamed_prompt")
            arguments = prompt.get("arguments", [])
            if not isinstance(arguments, list):
                continue

            for arg in arguments:
                if not isinstance(arg, dict):
                    continue
                arg_name = arg.get("name", "")
                if arg_name.lower() in self.DANGEROUS_ARG_NAMES:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Insecure prompt argument '{arg_name}' in prompt template '{prompt_name}'",
                            severity=self.severity,
                            description=(
                                f"Prompt template '{prompt_name}' exposes argument '{arg_name}' which can override "
                                "system-level behavior or guardrails during prompt hydration."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="prompt_arg",
                                target_name=f"{prompt_name}.{arg_name}",
                                path=f"arguments.{arg_name}",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence=f"Argument: {arg_name}",
                        )
                    )

        return findings
