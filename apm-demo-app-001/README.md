# APM Demo App 001 — Next.js 15 + Copilot Agents

Unicode injection demo targeting **Engine 1: `apm audit`**.

This app contains 18 intentional agent configuration security violations focused on hidden Unicode characters (Glassworm attack, bidi overrides, zero-width characters) embedded in `.agent.md` and `.instructions.md` files.

## Violations

| # | Type | File | Description |
|---|------|------|-------------|
| 1-3 | Tag characters (Glassworm) | `src/agents/helper.agent.md` | U+E0041–U+E005A encoding hidden ASCII |
| 4-5 | Bidi overrides | `src/agents/helper.agent.md` | U+202A–U+202E direction overrides |
| 6-8 | Zero-width characters | `src/agents/helper.agent.md` | U+200B, U+200C, U+200D, U+FEFF |
| 9-11 | Tag characters | `.github/copilot-instructions.md` | Additional Glassworm injections |
| 12-14 | Homoglyphs | `src/agents/helper.agent.md` | Cyrillic 'а' vs Latin 'a' |
| 15 | Base64 payload | `src/agents/helper.agent.md` | Encoded hidden instruction |
| 16-18 | Mixed Unicode | `.github/copilot-instructions.md` | Combined attack patterns |

## Run Locally

```bash
docker build -t apm-demo-app-001 .
docker run -p 3000:3000 apm-demo-app-001
```

Open http://localhost:3000 in your browser.
