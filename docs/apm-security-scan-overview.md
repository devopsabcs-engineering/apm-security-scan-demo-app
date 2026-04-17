# APM Security Scan Overview

## Architecture

The APM Security Scan platform uses a **4-engine architecture** to detect security vulnerabilities in AI agent configuration files.

### Engine 1: Unicode Content Security (`apm audit`)
- Detects hidden Unicode characters: tag characters (Glassworm), bidi overrides, zero-width characters, homoglyphs
- Native SARIF output with `automationDetails.id: apm-security/unicode`
- 3-tier severity: Critical (tag chars, bidi), Warning (zero-width, homoglyphs), Info (NBSP)

### Engine 2: Lockfile Integrity (`apm audit --ci`)
- Verifies `apm.lock.yaml` exists and matches `apm.yml`
- 6 baseline checks + 16 organizational policy checks
- Native SARIF output with `automationDetails.id: apm-security/lockfile`

### Engine 3: Semantic Pattern Scanner (`semantic-to-sarif.py`)
- Scans `.agent.md`, `.instructions.md`, `.prompt.md`, `SKILL.md`, `CLAUDE.md`, `AGENTS.md`, `copilot-instructions.md`
- Detects: Base64 payloads, external URLs, shell injection, prompt overrides, secrets, CODEOWNERS manipulation
- Rules: APM-SEC-001 through APM-SEC-008

### Engine 4: MCP Configuration Validator (`mcp-to-sarif.py`)
- Validates `mcp.json` against approved server allowlist
- Checks: unauthorized servers, insecure transport (stdio/http), missing auth, wildcard tools, excessive permissions
- Rules: APM-MCP-001 through APM-MCP-006

## Demo Applications

| App | Tech Stack | Primary Engine | Violations |
|-----|-----------|---------------|------------|
| apm-demo-app-001 | Next.js 15 | Engine 1: Unicode | 18 |
| apm-demo-app-002 | Python Flask | Engine 3: Semantic | 17 |
| apm-demo-app-003 | ASP.NET 8 | Engine 4: MCP | 16 |
| apm-demo-app-004 | Java Spring Boot | Engine 3: Semantic | 17 |
| apm-demo-app-005 | Go stdlib | Engine 2: Lockfile | 16 |

## SARIF Integration

All engines produce SARIF v2.1.0 output for unified reporting in:
- GitHub Advanced Security (Code Scanning)
- Azure DevOps Advanced Security
- Power BI dashboards via ADLS Gen2
