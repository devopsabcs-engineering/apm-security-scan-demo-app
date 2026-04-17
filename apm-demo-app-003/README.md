# APM Demo App 003 — ASP.NET 8 + MCP Servers

MCP configuration demo targeting **Engine 4: MCP Configuration Validator**.

This app contains 16 intentional violations focused on unauthorized MCP servers, overly broad tool permissions, and missing transport validation.

## Violations

| # | Type | File | Rule ID |
|---|------|------|---------|
| 1-4 | Unauthorized MCP servers | `mcp.json` | APM-SEC-005 |
| 5-6 | Insecure transport | `mcp.json` | MCP-TRANSPORT |
| 7-8 | Missing authentication | `mcp.json` | MCP-AUTH |
| 9-10 | Excessive tool permissions | `mcp.json` | APM-SEC-007 |
| 11-13 | Shell injection in agent config | `.github/copilot-instructions.md` | APM-SEC-003 |
| 14-15 | External URLs | `.github/copilot-instructions.md` | APM-SEC-002 |
| 16 | Missing CODEOWNERS | — | APM-SEC-008 |

## Run Locally

```bash
docker build -t apm-demo-app-003 .
docker run -p 8080:8080 apm-demo-app-003
```

Open http://localhost:8080 in your browser.
