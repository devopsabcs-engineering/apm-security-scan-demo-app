---
description: "Remediate agent configuration security violations — strip Unicode, fix MCP configs, remove secrets, harden supply chain"
agent: APMSecurityResolver
argument-hint: "[path=...] [finding=...]"
---

# APM Security Fix

## Inputs

* ${input:path}: (Optional) Path to the file or directory with violations.
* ${input:finding}: (Optional) Specific finding ID (e.g., APM-SEC-001) to remediate. Fixes all if omitted.

## Requirements

1. Read the APM Security scan findings for the specified path.
2. Apply automated remediation using the appropriate engine-specific fix strategy.
3. For Unicode issues, use `apm audit --strip` or manual character removal.
4. For semantic pattern issues, remove or replace the violating content.
5. For MCP issues, update configuration to use only allowlisted servers.
6. Generate unified diff patches showing all changes.
7. Re-scan to verify all fixes were applied correctly.
