# APM Demo App 005 — Go stdlib + Multi-Agent

Lockfile integrity demo targeting **Engine 2: `apm audit --ci`**.

This app contains 16 intentional violations focused on unpinned dependencies, missing lockfile, compromised transitive deps, and missing CODEOWNERS.

## Violations

| # | Type | File | Rule ID |
|---|------|------|---------|
| 1-5 | Unpinned dependencies | `apm.yml` | APM-SEC (lockfile) |
| 6 | Missing lockfile | `apm.lock.yaml` absent | APM-SEC (lockfile) |
| 7-9 | Deprecated packages | `apm.yml` | APM-SEC (lockfile) |
| 10-12 | Version conflicts | `apm.yml` | APM-SEC (lockfile) |
| 13-14 | Shell injection (cross-engine) | `.github/copilot-instructions.md` | APM-SEC-003 |
| 15 | Excessive tool permissions (cross-engine) | `mcp.json` | APM-SEC-007 |
| 16 | Missing CODEOWNERS | — | APM-SEC-008 |

## Run Locally

```bash
docker build -t apm-demo-app-005 .
docker run -p 8080:8080 apm-demo-app-005
```

Open http://localhost:8080 in your browser.
