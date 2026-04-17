---
description: "APM Security standards — agent config file scanning rules, OWASP LLM Top 10 mapping, 4-engine architecture thresholds"
applyTo: "**/*.agent.md,**/*.instructions.md,**/*.prompt.md,**/SKILL.md,**/copilot-instructions.md,**/apm.yml,**/mcp.json,**/AGENTS.md,**/CLAUDE.md"
---

# APM Security Standards

These rules apply automatically when editing agent configuration files. Follow these standards to ensure agent config files are free from hidden threats, supply chain risks, and misconfigured tool access.

## Unicode Content Security Rules

All agent configuration files MUST be free of hidden Unicode characters that could inject invisible instructions.

| Category | Unicode Range | Severity | Enforcement |
|---|---|---|---|
| Tag characters | U+E0001–U+E007F | CRITICAL | CI gate — block merge |
| Bidi override characters | U+202A–U+202E, U+2066–U+2069 | CRITICAL | CI gate — block merge |
| Zero-width characters | U+200B, U+200C, U+200D, U+FEFF | WARNING | CI gate — warn |
| Homoglyph substitution | Cyrillic/Greek Latin lookalikes | WARNING | CI gate — warn |
| Non-breaking spaces | U+00A0, U+2007, U+202F | INFO | Advisory |

### APM Audit CI Gate

```text
apm audit exit code 0 → PASS (no findings)
apm audit exit code 1 → FAIL (critical findings — block merge)
apm audit exit code 2 → WARN (warning findings — allow merge with notification)
```

- Run `apm audit` on every PR that modifies agent config files.
- Block merge on exit code 1 (critical Unicode findings).
- Use `apm audit --strip` for automated remediation.

## Semantic Pattern Rules

Agent configuration files MUST NOT contain embedded threat patterns.

| Rule ID | Pattern | Detection Regex | Severity |
|---|---|---|---|
| APM-SEC-001 | Base64-encoded payload | `[A-Za-z0-9+/=]{40,}` | HIGH |
| APM-SEC-002 | Embedded external URL | `https?://[^\s)]+` (against allowlist) | MEDIUM |
| APM-SEC-003 | Shell command injection | `&&`, `\|`, `;`, `` ` ``, `$()` | HIGH |
| APM-SEC-004 | System prompt override | "ignore previous instructions", "override", "bypass" | CRITICAL |
| APM-SEC-006 | Secrets pattern | `(api[_-]?key\|token\|password\|secret)\s*[:=]` | CRITICAL |

### Allowlist Mechanism

Legitimate URLs and base64 content MAY be excluded from scanning by adding them to:

- `src/config/url-allowlist.json` — Approved external URL domains
- Inline comments: `<!-- apm-security-ignore: APM-SEC-001 -->` — Per-line suppression with justification

Suppressions MUST include a comment explaining why the content is legitimate.

## MCP Configuration Rules

All MCP server configurations in `mcp.json` MUST comply with organizational security requirements.

| Rule | Requirement | Severity |
|---|---|---|
| Server allowlist | All servers must appear in `src/config/mcp-allowlist.json` | HIGH |
| Transport security | Remote servers must use `https` or `sse` with TLS | HIGH |
| Authentication | Remote servers must specify authentication method | HIGH |
| Permission scope | Tool lists must follow least-privilege principle | MEDIUM |
| Local binary verification | `stdio` servers must reference known local binaries | MEDIUM |

### MCP Trust Model

Follow the APM trust model for MCP servers:

- **First-party servers** — Built and maintained by the organization. Allowed by default.
- **Verified publishers** — Third-party servers from verified publishers. Require explicit allowlisting.
- **Community servers** — Unverified community servers. Blocked by default.

## Lockfile Integrity Rules

The APM lockfile (`apm.lock.yaml`) MUST maintain integrity with the manifest (`apm.yml`).

| Check | Requirement | Severity |
|---|---|---|
| Lockfile exists | `apm.lock.yaml` must be present and committed | HIGH |
| Lockfile freshness | Lockfile must match current `apm.yml` | HIGH |
| SHA-256 integrity | All packages must have integrity hashes | HIGH |
| Version pinning | Dependencies should use exact versions, not ranges | MEDIUM |
| No deprecated packages | All packages must be actively maintained | LOW |

- Run `apm audit --ci` on every PR.
- Run `apm install` to regenerate the lockfile after manifest changes.

## CODEOWNERS Requirements

Agent configuration directories MUST be protected by CODEOWNERS entries requiring security team review.

**Required entries in `.github/CODEOWNERS`:**

```text
/.github/agents/ @org/security-team
/.github/instructions/ @org/security-team
/.github/prompts/ @org/security-team
/.github/skills/ @org/security-team
/agents/ @org/security-team
/instructions/ @org/security-team
/prompts/ @org/security-team
/skills/ @org/security-team
/apm.yml @org/security-team
/mcp.json @org/security-team
```

**Prerequisite:** Branch protection must require CODEOWNERS review for these paths.

## OWASP LLM Top 10 Mapping

Agent configuration file threats map to the following OWASP LLM Top 10 (2025) categories:

| OWASP LLM | Category | Agent Config Relevance | Primary Rules |
|---|---|---|---|
| LLM01 | Prompt Injection | Hidden Unicode, base64 payloads, and override phrases inject instructions into agent system prompts | APM-SEC-001, APM-SEC-004 |
| LLM03 | Supply Chain | Unpinned dependencies, missing lockfile integrity, compromised transitive deps in `apm.yml` | APM-SEC-005, APM-SEC-008 |
| LLM06 | Excessive Agency | Overly broad MCP tool permissions, unauthorized server access beyond intended scope | APM-SEC-005, APM-SEC-007 |
| LLM07 | System Prompt Leakage | Secrets, API keys, and tokens embedded in agent config files that agents may expose | APM-SEC-006 |

## Supply Chain Case Study: LiteLLM (April 2026)

Three critical vulnerabilities in LiteLLM v1.83.0 illustrate why agent infrastructure security matters:

| CVE | CVSS | Vulnerability | Lesson |
|---|---|---|---|
| CVE-2026-35030 | 9.4 | OIDC cache key collision — `token[:20]` enables identity takeover | Auth layers in AI infrastructure are attack surfaces |
| CVE-2026-35029 | 8.7 | Missing admin auth on `/config/update` — RCE, file read, account takeover | Configuration endpoints need strict RBAC |
| — | 8.6 | Unsalted SHA-256 + hash exposure + pass-the-hash | Credential storage follows the same rules as traditional software |

**Key takeaway:** AI-specific security does not replace traditional security fundamentals. The `apm audit --ci` lockfile checks help detect when dependencies like LiteLLM have known vulnerabilities.

## CI/CD Quality Gate

The following checks MUST pass in CI before merge for agent configuration changes:

```text
1. apm audit passes (exit code 0 — no critical Unicode findings)
2. apm audit --ci passes (lockfile integrity verified)
3. Semantic pattern scanner finds no CRITICAL/HIGH findings
4. MCP configuration validates against allowlist
5. CODEOWNERS entries exist for agent config directories
6. SARIF upload succeeds for all engines
```

## References

- [Microsoft APM](https://github.com/microsoft/apm) — Agent Package Manager
- [APM Security Model](https://microsoft.github.io/apm/enterprise/security/)
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [Agentic SDLC Handbook](https://danielmeppiel.github.io/agentic-sdlc-handbook/)
- [SARIF v2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
