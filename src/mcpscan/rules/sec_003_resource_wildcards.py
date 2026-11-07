"""Rule MCP-SEC-003: Overly Broad Resource URI Templates & Path Traversal Risks.

Detects resource URI patterns that allow unrestricted filesystem traversal (e.g. file:///**, file:///*)
or unconstrained sensitive root directories exposed without scoping restrictions.
"""

import re
from typing import List
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class BroadResourceURIRule(BaseRule):
    rule_id = "MCP-SEC-003"
    title = "Overly Broad Resource URI Template / Filesystem Traversal Risk"
    severity = Severity.HIGH
    description = (
        "The server declares resource URI templates with unrestricted wildcards (e.g. 'file:///**', 'file:///*') "
        "or scopes pointing directly to root/system paths without directory confinement, exposing sensitive host files."
    )
    remediation = (
        "Restrict resource URIs to specific application-scoped subdirectories. "
        "Avoid wildcard recursive URI roots like 'file:///**' and disallow directory traversal sequences ('../')."
    )
    cwe = "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
    owasp_llm = "LLM06: Excessive Agency"

    # Dangerous wildcard URI patterns
    DANGEROUS_URI_PATTERNS = [
        (r"^file:///\*{1,3}$", "Unrestricted filesystem root wildcard"),
        (r"^file:///\*{1,2}/.*", "Recursive unrestricted filesystem template"),
        (r"^file:///(?:[A-Za-z]:)?/$", "Direct root filesystem mount exposed"),
        (r"^file:///(?:etc|proc|sys|windows|system32)\b", "Direct access to sensitive operating system directory"),
        (r"\.\./", "Path traversal sequence in declared URI"),
    ]

    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        for resource in manifest.resources:
            uri = resource.get("uri", "")
            res_name = resource.get("name") or uri or "unnamed_resource"

            for pattern, reason in self.DANGEROUS_URI_PATTERNS:
                if re.search(pattern, uri, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Risky Resource URI: {reason}",
                            severity=self.severity,
                            description=(
                                f"Resource '{res_name}' exposes URI pattern '{uri}' which violates least-privilege "
                                f"isolation: {reason}."
                            ),
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="resource",
                                target_name=res_name,
                                path="uri",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence=uri,
                        )
                    )
                    break

        return findings
