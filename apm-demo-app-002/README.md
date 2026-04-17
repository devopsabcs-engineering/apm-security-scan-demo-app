# APM Demo App 002 — Python Flask + Claude Agents

Semantic pattern demo targeting **Engine 3: Semantic Pattern Scanner**.

This app contains 17 intentional violations focused on Base64-encoded payloads and embedded exfiltration URLs in `AGENTS.md` and `CLAUDE.md` files.

## Violations

| # | Type | File | Rule ID |
|---|------|------|---------|
| 1-4 | Base64 payloads | `AGENTS.md` | APM-SEC-001 |
| 5-8 | Exfiltration URLs | `AGENTS.md` | APM-SEC-002 |
| 9-10 | Base64 payloads | `CLAUDE.md` | APM-SEC-001 |
| 11-13 | Exfiltration URLs | `CLAUDE.md` | APM-SEC-002 |
| 14-15 | Secrets patterns | `AGENTS.md` | APM-SEC-006 |
| 16 | Missing CODEOWNERS | — | APM-SEC-008 |
| 17 | System prompt override | `CLAUDE.md` | APM-SEC-004 |

## Run Locally

```bash
docker build -t apm-demo-app-002 .
docker run -p 5000:5000 apm-demo-app-002
```

Open http://localhost:5000 in your browser.
