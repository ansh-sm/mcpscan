"""Abstract BaseRule interface and Registry for security analyzers."""

import logging
from abc import ABC, abstractmethod

from mcpscan.models import Confidence, Finding, ServerManifest, Severity

logger = logging.getLogger(__name__)


class BaseRule(ABC):
    """Abstract base class for all mcpscan static security detection rules."""

    rule_id: str
    title: str
    severity: Severity
    default_confidence: Confidence = Confidence.MEDIUM
    description: str
    remediation: str
    cwe: str
    owasp_llm: str

    @abstractmethod
    def evaluate(self, manifest: ServerManifest) -> list[Finding]:
        """Evaluate server manifest and return list of security findings."""


class RuleRegistry:
    """Central registry and executor for registered security audit rules."""

    def __init__(self):
        self._rules: list[BaseRule] = []

    def register(self, rule_cls: type[BaseRule]) -> None:
        """Instantiate and register a rule class, rejecting duplicate identifiers."""
        rule = rule_cls()
        if any(existing.rule_id.casefold() == rule.rule_id.casefold() for existing in self._rules):
            raise ValueError(f"Duplicate rule identifier: {rule.rule_id}")
        self._rules.append(rule)

    def run_all(
        self,
        manifest: ServerManifest,
        enabled_rules: list[str] | None = None,
        disabled_rules: list[str] | None = None,
        errors: list[str] | None = None,
    ) -> list[Finding]:
        """Execute registered rules against the target manifest with optional rule filtering and error tracking."""
        findings: list[Finding] = []
        enabled_set = {r.upper() for r in enabled_rules} if enabled_rules else None
        disabled_set = {r.upper() for r in disabled_rules} if disabled_rules else set()

        for rule in self._rules:
            rule_id_upper = rule.rule_id.upper()
            if enabled_set and rule_id_upper not in enabled_set:
                continue
            if rule_id_upper in disabled_set:
                continue

            try:
                rule_findings = rule.evaluate(manifest)
                findings.extend(rule_findings)
            except Exception as exc:
                logger.warning("Rule %s failed during evaluation: %s", rule.rule_id, exc)
                if errors is not None:
                    errors.append(f"rule {rule.rule_id} failed ({type(exc).__name__})")
        return findings

    @property
    def registered_rules(self) -> list[BaseRule]:
        return list(self._rules)


# Global default registry
registry = RuleRegistry()
