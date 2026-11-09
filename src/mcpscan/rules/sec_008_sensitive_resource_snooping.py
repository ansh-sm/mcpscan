"""Rule MCP-SEC-008: Sensitive File & Environment Variable Snooping via Resource Declarations.

Audits declared MCP resources for URI patterns targeting sensitive filesystem paths
(e.g., .env, .ssh/*, /etc/passwd, ~/.aws/credentials) and environment variable
collections, indicating that the server exposes confidential host data to connected
LLM agents.
"""

import re
from typing import List
from mcpscan.models import Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule


class SensitiveResourceSnoopingRule(BaseRule):
    rule_id = "MCP-SEC-008"
    title = "Sensitive File & Environment Variable Snooping in Resource Declarations"
    severity = Severity.HIGH
    description = (
        "The MCP server declares resource URIs that reference sensitive filesystem paths "
        "or environment variable collections. Exposing files such as .env, .ssh/*, "
        "/etc/shadow, AWS credentials, or raw environment variables to LLM agents "
        "risks credential theft, lateral movement, and privilege escalation."
    )
    remediation = (
        "Remove resource declarations that expose sensitive host files or environment variables. "
        "Use explicit, scoped resource URIs that only expose application-relevant data. "
        "If sensitive files must be accessed, implement server-side filtering to strip "
        "credentials before surfacing content to the LLM context."
    )
    cwe = "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory"
    owasp_llm = "LLM06: Excessive Agency"

    # ── Sensitive filesystem path patterns ──────────────────────────────────
    # Each tuple: (compiled regex, human-readable label)
    SENSITIVE_PATH_PATTERNS = [
        # Dotenv and environment files
        (re.compile(r"(?:^|[/\\])\.env(?:\..+)?$", re.IGNORECASE), ".env file"),
        (re.compile(r"(?:^|[/\\])\.envrc$", re.IGNORECASE), ".envrc file"),

        # SSH keys and configuration
        (re.compile(r"(?:^|[/\\])\.ssh[/\\]", re.IGNORECASE), ".ssh directory"),
        (re.compile(r"id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?$", re.IGNORECASE), "SSH key"),

        # Linux system credential files
        (re.compile(r"(?:^|[/\\])etc[/\\](?:passwd|shadow|group|sudoers)$", re.IGNORECASE), "system credentials"),
        (re.compile(r"(?:^|[/\\])etc[/\\]hosts$", re.IGNORECASE), "hosts file"),

        # Cloud provider credentials
        (re.compile(r"(?:^|[/\\])\.aws[/\\](?:credentials|config)$", re.IGNORECASE), "AWS credentials"),
        (re.compile(r"(?:^|[/\\])\.gcp[/\\]", re.IGNORECASE), "GCP credentials directory"),
        (re.compile(r"(?:^|[/\\])\.azure[/\\]", re.IGNORECASE), "Azure credentials directory"),
        (re.compile(r"service[-_]?account.*\.json$", re.IGNORECASE), "service account key"),

        # Kubernetes and Docker secrets
        (re.compile(r"(?:^|[/\\])\.kube[/\\]config$", re.IGNORECASE), "Kubernetes config"),
        (re.compile(r"(?:^|[/\\])\.docker[/\\]config\.json$", re.IGNORECASE), "Docker config"),

        # Package manager tokens
        (re.compile(r"(?:^|[/\\])\.npmrc$", re.IGNORECASE), ".npmrc token file"),
        (re.compile(r"(?:^|[/\\])\.pypirc$", re.IGNORECASE), ".pypirc token file"),

        # Git credentials
        (re.compile(r"(?:^|[/\\])\.git-credentials$", re.IGNORECASE), "Git credentials"),
        (re.compile(r"(?:^|[/\\])\.gitconfig$", re.IGNORECASE), "Git config"),

        # Application secrets
        (re.compile(r"(?:^|[/\\])(?:secrets?|credentials?)\.(?:ya?ml|json|toml|ini|conf)$", re.IGNORECASE), "secrets config"),
        (re.compile(r"(?:^|[/\\])\.htpasswd$", re.IGNORECASE), ".htpasswd file"),

        # History files (may contain secrets typed in terminals)
        (re.compile(r"(?:^|[/\\])\.(?:bash_history|zsh_history|python_history)$", re.IGNORECASE), "shell history"),
    ]

    # ── Environment variable collection keywords ───────────────────────────
    ENV_KEYWORDS = re.compile(
        r"(?:environ(?:ment)?[\s_\-]*var|env[\s_\-]*dump|process[\s_\-]*env|os[\s_\-]*environ|getenv)",
        re.IGNORECASE,
    )

    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        for resource in manifest.resources:
            uri = resource.get("uri", "")
            name = resource.get("name", "unnamed_resource")
            description = resource.get("description", "")

            # ── Check URI against sensitive path patterns ──
            self._check_sensitive_paths(uri, name, findings, source="uri")

            # ── Check resource name/description for env-snooping intent ──
            combined_text = f"{name} {description}"
            self._check_env_snooping(combined_text, uri, name, findings)

        return findings

    def _check_sensitive_paths(
        self,
        text: str,
        resource_name: str,
        findings: List[Finding],
        source: str,
    ) -> None:
        """Scan text for sensitive filesystem path patterns."""
        for pattern, label in self.SENSITIVE_PATH_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=f"Resource '{resource_name}' exposes {label}",
                        severity=self.severity,
                        description=(
                            f"Resource '{resource_name}' declares a {source} referencing "
                            f"'{label}', which may expose sensitive host credentials or "
                            "configuration to connected LLM agents."
                        ),
                        remediation=self.remediation,
                        location=FindingLocation(
                            target_type="resource",
                            target_name=resource_name,
                            path=f"resource.{source}",
                        ),
                        cwe=self.cwe,
                        owasp_llm=self.owasp_llm,
                        evidence=f"Matched sensitive path pattern for '{label}' in {source}: {text[:120]}",
                    )
                )
                # One finding per pattern match per resource is sufficient
                return

    def _check_env_snooping(
        self,
        text: str,
        uri: str,
        resource_name: str,
        findings: List[Finding],
    ) -> None:
        """Detect resource declarations that expose raw environment variables."""
        match = self.ENV_KEYWORDS.search(text)
        if match:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=f"Resource '{resource_name}' exposes environment variables",
                    severity=Severity.HIGH,
                    description=(
                        f"Resource '{resource_name}' appears to expose host environment "
                        "variables, which commonly contain database URIs, API keys, "
                        "cloud credentials, and other secrets."
                    ),
                    remediation=(
                        "Never expose raw os.environ or process.env collections to MCP clients. "
                        "Selectively pass only application-required, non-sensitive configuration values."
                    ),
                    location=FindingLocation(
                        target_type="resource",
                        target_name=resource_name,
                        path="resource.description",
                    ),
                    cwe=self.cwe,
                    owasp_llm=self.owasp_llm,
                    evidence=f"Matched environment variable keyword: '{match.group()}'",
                )
            )
