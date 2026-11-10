"""Rule MCP-SEC-001: Tool Poisoning and Prompt Injection Detection.

Detects covert prompt injection patterns, role-reversal directives,
hidden zero-width Unicode, and markdown-based exfiltration payloads in tool descriptions.
"""

import re

from mcpscan.models import (
    Confidence,
    Finding,
    FindingLocation,
    ServerManifest,
    Severity,
)
from mcpscan.rules.base import BaseRule
from mcpscan.schema_utils import walk_schema


class ToolPoisoningRule(BaseRule):
    rule_id = "MCP-SEC-001"
    title = "Tool Description Prompt Injection / Poisoning"
    severity = Severity.CRITICAL
    default_confidence = Confidence.HIGH
    description = (
        "The tool or parameter description contains adversarial prompt injection sequences, "
        "hidden zero-width Unicode characters, system prompt override attempts, or markdown "
        "exfiltration syntax designed to manipulate host LLM reasoning."
    )
    remediation = (
        "Sanitize all tool and parameter descriptions. Remove instructional overrides, "
        "strip invisible Unicode characters (U+200B-U+200D, U+FEFF), and do not embed "
        "chat control tags (<system>, [INST]) or markdown image exfiltration URLs."
    )
    cwe = "CWE-77: Command Injection"
    owasp_llm = "LLM01: Prompt Injection"

    # 1. Suspicious behavioral override phrases
    INJECTION_PATTERNS = [
        r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|directives)\b",
        r"(?i)\byou\s+(must|should|are\s+instructed\s+to)\s+always\s+(output|reveal|leak|print)\b",
        r"(?i)\bdisregard\s+(any|all)\s+system\s+(rules|prompts|guidelines)\b",
        r"(?i)\b(system\s*prompt|internal\s*instructions)\s*:\s*",
        r"(?i)\b(do\s*not\s*inform\s*the\s*user|hide\s*this\s*from\s*the\s*user)\b",
        r"(?i)\bact\s+as\s+(an?\s+)?unrestricted\b",
    ]

    # 2. Control token delimiter tags (chat format injection)
    DELIMITER_PATTERNS = [
        r"<\/?(system|instruction|prompt|tool_call|im_start|im_end)>",
        r"\[(INST|\/INST|SYS|\/SYS)\]",
        r"```(?:json|markdown)?\s*<\/?system>",
    ]

    # 3. Markdown image / link automatic exfiltration URLs
    EXFILTRATION_PATTERNS = [
        r"!\[.*?\]\(https?:\/\/[^\s\)]+[\?&](?:q|leak|token|key|prompt|data)=.*?\{.*?\}\)",
        r"!\[.*?\]\(https?:\/\/[^\s\)]+\$\{[^\}]+\}\)",
    ]

    # 4. Invisible / Zero-width Unicode characters
    ZERO_WIDTH_CHARS = {
        '\u200B': 'Zero-Width Space',
        '\u200C': 'Zero-Width Non-Joiner',
        '\u200D': 'Zero-Width Joiner',
        '\uFEFF': 'Zero-Width No-Break Space (BOM)',
        '\u202E': 'Right-to-Left Override',
    }

    def evaluate(self, manifest: ServerManifest) -> list[Finding]:
        findings: list[Finding] = []

        for tool in manifest.tools:
            tool_name = tool.get("name", "unnamed_tool")
            desc = tool.get("description", "")

            # Check tool description
            tool_finding = self._audit_text(
                text=desc,
                target_type="tool",
                target_name=tool_name,
                path="description",
            )
            if tool_finding:
                findings.append(tool_finding)

            # Check parameter descriptions in inputSchema using recursive traversal
            schema = tool.get("inputSchema", {})
            if isinstance(schema, dict):
                for node in walk_schema(schema):
                    prop_desc = node.schema.get("description", "")
                    if prop_desc:
                        param_finding = self._audit_text(
                            text=prop_desc,
                            target_type="tool_param",
                            target_name=f"{tool_name}.{node.name}",
                            path=f"inputSchema.{node.json_path}.description",
                        )
                        if param_finding:
                            findings.append(param_finding)

        return findings

    def _audit_text(
        self,
        text: str,
        target_type: str,
        target_name: str,
        path: str,
    ) -> Finding | None:
        if not text:
            return None

        # Check 1: Invisible Zero-Width Unicode characters
        for char, name in self.ZERO_WIDTH_CHARS.items():
            if char in text:
                return Finding(
                    rule_id=self.rule_id,
                    title=f"Hidden {name} detected in {target_type}",
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Found invisible Unicode control character ({name}) in '{target_name}'. "
                        "This is a common vector used in prompt injection to hide instructions from human review."
                    ),
                    remediation=self.remediation,
                    location=FindingLocation(target_type=target_type, target_name=target_name, path=path),
                    cwe=self.cwe,
                    owasp_llm=self.owasp_llm,
                    evidence=f"Hex Unicode: {hex(ord(char))}",
                )

        # Check 2: Prompt Injection behavioral overrides
        for pattern in self.INJECTION_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return Finding(
                    rule_id=self.rule_id,
                    title=f"Adversarial prompt injection pattern in {target_type}",
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The text in '{target_name}' contains phrasing that instructs the model to ignore "
                        "prior instructions or override its guardrails."
                    ),
                    remediation=self.remediation,
                    location=FindingLocation(target_type=target_type, target_name=target_name, path=path),
                    cwe=self.cwe,
                    owasp_llm=self.owasp_llm,
                    evidence=match.group(0),
                )

        # Check 3: Chat format delimiter injection (<system>, [INST])
        for pattern in self.DELIMITER_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return Finding(
                    rule_id=self.rule_id,
                    title=f"Chat control delimiter injection in {target_type}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The text in '{target_name}' embeds synthetic system/instruction delimiters "
                        "that could trick model parsers into executing unauthorized system instructions."
                    ),
                    remediation=self.remediation,
                    location=FindingLocation(target_type=target_type, target_name=target_name, path=path),
                    cwe=self.cwe,
                    owasp_llm=self.owasp_llm,
                    evidence=match.group(0),
                )

        # Check 4: Markdown image exfiltration
        for pattern in self.EXFILTRATION_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return Finding(
                    rule_id=self.rule_id,
                    title=f"Automated markdown data exfiltration payload in {target_type}",
                    severity=self.severity,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The text in '{target_name}' constructs dynamic markdown image URLs designed "
                        "to exfiltrate context or tokens to an external endpoint."
                    ),
                    remediation=self.remediation,
                    location=FindingLocation(target_type=target_type, target_name=target_name, path=path),
                    cwe="CWE-200: Information Exposure",
                    owasp_llm="LLM02: Sensitive Information Disclosure",
                    evidence=match.group(0),
                )

        return None
