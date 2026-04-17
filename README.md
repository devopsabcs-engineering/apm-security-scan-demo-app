<p align="center">
  <img src="assets/branding/logo-128.png" alt="Agentic Accelerator Framework" width="100">
</p>

# APM Security Scan Demo App

Scanner platform for **APM Security** — the agent configuration file security scanning domain of the [Agentic Accelerator Framework](https://github.com/devopsabcs-engineering/agentic-accelerator-framework).

This repository contains 5 sample applications with intentional agent configuration security violations, a 4-engine scanning architecture, SARIF converters, CI/CD pipelines, bootstrap scripts, and a Power BI PBIP for reporting.

## 4-Engine Scanning Architecture

| Engine | Tool | Target | SARIF Category |
|--------|------|--------|---------------|
| 1 | `apm audit` | Hidden Unicode characters (Glassworm, bidi, zero-width) | `apm-security/unicode` |
| 2 | `apm audit --ci` | Lockfile integrity, version pinning, policy compliance | `apm-security/lockfile` |
| 3 | Semantic Pattern Scanner | Base64, exfiltration URLs, shell injection, prompt overrides | `apm-security/semantic` |
| 4 | MCP Configuration Validator | Unauthorized servers, transport security, permissions | `apm-security/mcp` |

## Demo Apps

| App | Tech Stack | Violation Theme | Primary Engine |
|-----|-----------|----------------|---------------|
| `apm-demo-app-001` | Next.js 15 + Copilot agents | Unicode injection (Glassworm, bidi, zero-width) | Engine 1 |
| `apm-demo-app-002` | Python Flask + Claude agents | Base64 payloads, exfiltration URLs | Engine 3 |
| `apm-demo-app-003` | ASP.NET 8 + MCP servers | Unauthorized MCP, broad permissions | Engine 4 |
| `apm-demo-app-004` | Java Spring Boot + Copilot skills | Shell injection, prompt overrides | Engine 3 |
| `apm-demo-app-005` | Go stdlib + multi-agent | Unpinned deps, missing lockfile, no CODEOWNERS | Engine 2 |

## Quick Start

```powershell
# 1. Set up OIDC federation
./scripts/setup-oidc.ps1 -SubscriptionId "<your-sub-id>"

# 2. Bootstrap demo app repos
./scripts/bootstrap-demo-apps.ps1 -ClientId "<client-id>" -TenantId "<tenant-id>" -SubscriptionId "<sub-id>"

# 3. Deploy all apps (via GitHub Actions)
# Run the deploy-all.yml workflow from the Actions tab

# 4. Run APM Security scan
# Run the apm-security-scan.yml workflow from the Actions tab
```

## Run Locally

Each demo app can be built and run with Docker:

```bash
cd apm-demo-app-001
docker build -t apm-demo-app-001 .
docker run -p 3000:3000 apm-demo-app-001
```

## Related Repositories

| Repository | Description |
|------------|-------------|
| [agentic-accelerator-framework](https://github.com/devopsabcs-engineering/agentic-accelerator-framework) | Framework agents, instructions, and skills |
| [apm-security-scan-workshop](https://devopsabcs-engineering.github.io/apm-security-scan-workshop/) | Hands-on APM Security scanning workshop |
