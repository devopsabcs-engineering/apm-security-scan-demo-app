---
description: "Scan agent configuration files for security violations — Unicode injection, semantic patterns, MCP misconfigs, supply chain risks"
agent: APMSecurityDetector
argument-hint: "[path=...] [engine=...]"
---

# APM Security Scan

## Inputs

* ${input:path}: (Optional) Path to scan. Defaults to workspace root.
* ${input:engine}: (Optional) Specific engine to run (unicode, lockfile, semantic, mcp). Runs all if omitted.

## Requirements

1. Scan agent configuration files at the provided path for security violations across four engines.
2. Use the 4-engine architecture (APM audit, lockfile integrity, semantic patterns, MCP validation).
3. Produce a report organized by attack category with severity classification.
4. Map findings to OWASP LLM Top 10 (2025) and CWE identifiers.
5. Generate SARIF output with `automationDetails.id` prefixed with `apm-security/`.
