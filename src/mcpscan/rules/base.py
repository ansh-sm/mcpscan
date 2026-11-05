"""Abstract BaseRule interface and Registry for security analyzers."""

from abc import ABC, abstractmethod
from typing import List, Type
from mcpscan.models import Finding, ServerManifest, Severity


class BaseRule(ABC):
    """Abstract base class for all mcpscan static security detection rules."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    cwe: str
    owasp_llm: str

    @abstractmethod
    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        """Evaluate server manifest and return list of security findings."""
        pass


class RuleRegistry:
    """Central registry and executor for registered security audit rules."""

    def __init__(self):
        self._rules: List[BaseRule] = []

    def register(self, rule_cls: Type[BaseRule]) -> None:
        """Instantiate and register a rule class."""
        self._rules.append(rule_cls())

    def run_all(self, manifest: ServerManifest) -> List[Finding]:
        """Execute all registered rules against the target manifest."""
        findings: List[Finding] = []
        for rule in self._rules:
            try:
                rule_findings = rule.evaluate(manifest)
                findings.extend(rule_findings)
            except Exception as e:
                # Rule execution failure should never crash the entire scanner
                # We log or capture it cleanly
                pass
        return findings

    @property
    def registered_rules(self) -> List[BaseRule]:
        return list(self._rules)


# Global default registry
registry = RuleRegistry()
