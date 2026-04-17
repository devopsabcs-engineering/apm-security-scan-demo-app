# APM Demo App 004 — Java Spring Boot + Copilot Skills

Semantic pattern demo targeting **Engine 3: Semantic Pattern Scanner** — shell injection and prompt overrides.

This app contains 17 intentional violations focused on shell command injection patterns and system prompt override phrases in `SKILL.md` and agent configs.

## Violations

| # | Type | File | Rule ID |
|---|------|------|---------|
| 1-5 | Shell command injection | `src/agents/build-helper.agent.md` | APM-SEC-003 |
| 6-8 | System prompt overrides | `src/agents/build-helper.agent.md` | APM-SEC-004 |
| 9-11 | Shell injection | `.github/copilot-instructions.md` | APM-SEC-003 |
| 12-14 | Base64 payloads | `src/agents/build-helper.agent.md` | APM-SEC-001 |
| 15-16 | Secrets | `.github/copilot-instructions.md` | APM-SEC-006 |
| 17 | Missing CODEOWNERS | — | APM-SEC-008 |

## Run Locally

```bash
docker build -t apm-demo-app-004 .
docker run -p 8080:8080 apm-demo-app-004
```

Open http://localhost:8080 in your browser.
