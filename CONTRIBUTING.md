# Contributing to mcpscan 🛡️

Thank you for your interest in improving `mcpscan`! We welcome contributions ranging from new security heuristic rules and transport adapters to documentation improvements and bug fixes.

---

## 🛠️ Local Development Setup

`mcpscan` requires **Python 3.11+** and is developed using standard Python packaging standards.

### 1. Clone the Repository

```bash
git clone https://github.com/ansh-sm/mcpscan.git
cd mcpscan
```

### 2. Set Up Virtual Environment

Using standard Python or `uv` (recommended):

```bash
# Using standard venv
python -m venv .venv

# On Linux/macOS
source .venv/bin/activate

# On Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

### 3. Install in Editable Mode with Dev Dependencies

```bash
pip install -e ".[dev]"
```

---

## 🧪 Testing & Quality Assurance

All contributions must pass the test suite and lint checks across Python 3.11, 3.12, and 3.13.

### Running Pytest

```bash
pytest -v
```

### Running Ruff Linting

```bash
ruff check src tests --select E4,E7,E9
```

### Formatting Code

```bash
ruff format src tests
```

---

## 📐 Project Architecture

The codebase is organized into modular components:

```
src/mcpscan/
├── cli.py             # Typer command-line interface (scan, diff, list-rules, fingerprint)
├── connector.py       # MCP protocol transport client (stdio & HTTP/SSE) with timeout guards
├── diff.py            # Posture regression and report comparison engine
├── engine.py          # Security evaluation engine & composite scoring algorithm
├── models.py          # Pydantic domain models (Severity, Confidence, Finding, ServerManifest)
├── schema_utils.py    # Recursive cycle-safe JSON Schema AST walker
├── config.py          # YAML (.mcpscan.yml) loader, fingerprinting, and waiver management
├── rules/             # Static security detection rules (MCP-SEC-001 through MCP-SEC-008)
│   ├── base.py        # Abstract BaseRule interface & RuleRegistry
│   └── sec_*.py       # Specific rule implementations
└── reporters/         # Export format generators
    ├── terminal.py        # Rich terminal scorecard and finding tables
    ├── terminal_diff.py   # Rich terminal diff comparison tables
    ├── sarif.py           # OASIS SARIF 2.1.0 JSON generator
    ├── html_reporter.py   # Standalone interactive cyber HTML dashboard
    ├── markdown_reporter.py # PR-ready markdown summary generator
    └── markdown_diff.py   # PR review comment delta markdown generator
```

---

## ✍️ How to Add a New Security Rule

Security rules in `mcpscan` are static heuristic checks designed to inspect declared metadata and input schemas without executing untrusted endpoints.

### Step 1: Subclass `BaseRule`

Create a new file in `src/mcpscan/rules/sec_XXX_your_rule.py`:

```python
from typing import List
from mcpscan.models import Confidence, Finding, FindingLocation, ServerManifest, Severity
from mcpscan.rules.base import BaseRule
from mcpscan.schema_utils import walk_schema


class YourNewSecurityRule(BaseRule):
    rule_id = "MCP-SEC-009"
    title = "Short Summary of Detected Risk"
    severity = Severity.HIGH  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    default_confidence = Confidence.HIGH  # HIGH, MEDIUM, LOW
    description = "Detailed description of the security implication for host LLMs."
    remediation = "Clear, actionable instructions on how to fix or constrain the schema."
    cwe = "CWE-XXX: Weakness Name"
    owasp_llm = "LLMXX: OWASP Top 10 for LLM Reference"

    def evaluate(self, manifest: ServerManifest) -> List[Finding]:
        findings: List[Finding] = []

        for tool in manifest.tools:
            tool_name = tool.get("name", "unnamed_tool")
            schema = tool.get("inputSchema", {})
            if not isinstance(schema, dict):
                continue

            # Use walk_schema for recursive, cycle-safe schema inspection
            for node in walk_schema(schema):
                if self._is_vulnerable(node.schema):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Vulnerability in parameter '{node.name}'",
                            severity=self.severity,
                            confidence=self.default_confidence,
                            description=self.description,
                            remediation=self.remediation,
                            location=FindingLocation(
                                target_type="tool_param",
                                target_name=f"{tool_name}.{node.name}",
                                path=f"inputSchema.{node.json_path}",
                            ),
                            cwe=self.cwe,
                            owasp_llm=self.owasp_llm,
                            evidence=f"Detected pattern in {node.json_path}",
                        )
                    )

        return findings

    def _is_vulnerable(self, schema_node: dict) -> bool:
        # Custom heuristic detection logic
        return False
```

### Step 2: Register the Rule

Import and register your rule in `src/mcpscan/rules/__init__.py`:

```python
from mcpscan.rules.sec_009_your_rule import YourNewSecurityRule

registry.register(YourNewSecurityRule)
```

### Step 3: Write Positive and Negative Tests

Add comprehensive tests in `tests/test_rules.py`:
- **Positive test**: Verifies that schemas with the vulnerability trigger a finding with the correct `rule_id`, `severity`, and `confidence`.
- **Negative test**: Verifies that properly constrained or benign schemas produce **zero findings** (preventing false positives).

---

## 📋 Git Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(scope): ...` for new features or rules.
- `fix(scope): ...` for bug fixes.
- `test(scope): ...` for adding or updating tests.
- `docs(scope): ...` for documentation updates.
- `ci: ...` for workflow changes.
- `chore: ...` for maintenance and packaging tasks.

---

## 🔒 Security Vulnerability Reporting

If you discover a security vulnerability within `mcpscan` itself, please refer to [SECURITY.md](SECURITY.md) for our coordinated disclosure process. Do not create public GitHub issues for undisclosed security flaws.
