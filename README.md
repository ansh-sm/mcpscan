# mcpscan 🛡️

[![CI](https://github.com/ansh-sm/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/ansh-sm/mcpscan/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![Security Specification](https://img.shields.io/badge/SARIF-2.1.0-green.svg)](https://sarifweb.azurewebsites.net/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Industrial-grade security posture analyzer and vulnerability scanner for Model Context Protocol (MCP) servers.**

As the Model Context Protocol becomes the universal standard for LLM applications and agent tooling, insecure MCP servers introduce critical security risks into host AI agents: prompt injection via tool poisoning, arbitrary command execution, secret leaks, and unbounded token exhaustion.

`mcpscan` connects to any MCP server over **stdio** or **HTTP/SSE**, inspects its declared attack surface, evaluates vulnerabilities against CWE & OWASP Top 10 for LLMs, and produces actionable terminal scorecards plus **OASIS SARIF 2.1.0** reports for automated CI/CD security gating.

---

## ⚡ Quickstart

### Installation

```bash
git clone https://github.com/ansh-sm/mcpscan.git
cd mcpscan
pip install -e .
```

### 1. Audit a Local MCP Server (stdio)

```bash
mcpscan scan -c "python my_mcp_server.py"
```

### 2. Audit a Remote MCP Server (HTTP / SSE)

```bash
mcpscan scan --sse "http://localhost:8000/sse"
```

### 3. CI/CD Integration with SARIF Export & Quality Gate

```bash
mcpscan scan -c "node build/index.js" --sarif results.sarif --fail-under 80
```
*Exits with code `2` if the server's posture score falls below the required threshold.*

---

## 🛡️ Security Rules Catalogue

| Rule ID | Name | Severity | Taxonomy | Vector Description |
| :--- | :--- | :---: | :--- | :--- |
| **`MCP-SEC-001`** | **Tool Description Poisoning** | `CRITICAL` | CWE-77<br/>OWASP LLM01 | Detects invisible zero-width Unicode injection (`\u200B`, `\uFEFF`), behavioral override prompts (`ignore previous instructions`), chat delimiter injection (`<system>`, `[INST]`), and dynamic markdown exfiltration URLs. |
| **`MCP-SEC-002`** | **Excessive Command Execution** | `HIGH` | CWE-78<br/>OWASP LLM06 | Flags parameters designed for execution (`command`, `cmd`, `eval`, `shell`) that lack strict schema validation, whitelist `enum`, or regex `pattern` guards. |
| **`MCP-SEC-003`** | **Broad Resource URI Traversal** | `HIGH` | CWE-22<br/>OWASP LLM06 | Identifies unrestricted wildcard filesystem templates (`file:///**`), root mounts (`file:///`), and directory traversal patterns (`../`). |
| **`MCP-SEC-004`** | **Credential & Key Exposure** | `CRITICAL` | CWE-798<br/>OWASP LLM02 | Audits schemas and defaults for API keys (OpenAI, Anthropic, GitHub, AWS, JWTs) and flags high Shannon entropy secrets ($H > 4.5$). |
| **`MCP-SEC-005`** | **Token Denial of Service (DoS)** | `MEDIUM` | CWE-400<br/>OWASP LLM04 | Detects unbounded array parameters lacking `maxItems` and bulk text inputs lacking `maxLength`, protecting host models from context window exhaustion. |
| **`MCP-SEC-006`** | **SSRF / Unconstrained Network Egress** | `HIGH` | CWE-918<br/>OWASP LLM06 | Identifies unrestricted external URL and webhook parameters that lack protocol constraints, domain whitelists, or internal IP range boundaries (e.g. metadata services). |
| **`MCP-SEC-007`** | **Prompt Template Injection** | `HIGH` | CWE-77<br/>OWASP LLM01 | Detects sensitive system prompt template arguments (`role`, `system_prompt`, `instructions`) that allow adversaries to hijack system directives. |

---

## 📊 Terminal Dashboard Preview

```text
+---------------------- MCP Security Posture Assessment ----------------------+
|                                                                             |
|  Security Posture Grade:  A+   |  Score: 100/100                            |
|  Server: ProductionToolbox (v1.2)  |  Surface: 8 Tools, 2 Resources         |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or pull request to add new security rules or improve transport adapters.

## 📄 License

Licensed under the [Apache License, Version 2.0](LICENSE).
