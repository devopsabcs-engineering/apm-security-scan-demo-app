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

## Power BI Reporting

The `power-bi/` directory contains a Power BI Project (`.pbip`) that visualizes APM Security scan findings from ADLS Gen2.

### Architecture

```text
Scan Engines ──► SARIF files ──► ADLS Gen2 ──► Power BI Semantic Model ──► Report
                                (stapmscan*)    (star schema)
```

### Semantic Model

| Table | Type | Source |
|-------|------|--------|
| `Fact_APMSecurityFindings` | Fact | SARIF JSON files from ADLS Gen2 via `AzureStorage.DataLake()` |
| `Dim_Date` | Dimension | Auto-generated date table |
| `Dim_Engine` | Dimension | Static reference data (4 scanning engines) |
| `Dim_Repository` | Dimension | Static reference data (5 demo apps) |
| `Dim_Severity` | Dimension | Static reference data (CRITICAL/HIGH/MEDIUM/LOW) |
| `Dim_Rule` | Dimension | Static reference data (APM-SEC/APM-MCP/APM-UNI rules with CWE/OWASP mapping) |

### Scan & Store Pipeline

Run the scan-and-store script to populate ADLS Gen2 with SARIF results:

```powershell
./scripts/scan-and-store.ps1 -StorageAccountName "stapmscanst4mvnymfd6ru"
```

This scans all 5 demo apps with Engines 3 and 4, then uploads SARIF files to ADLS Gen2 at `{yyyy}/{MM}/{dd}/{app}-{engine}.sarif`.

### Storage Account Configuration

The ADLS Gen2 storage account (`stapmscanst4mvnymfd6ru`) is configured with:

- **HNS enabled** (Data Lake Storage Gen2)
- **Shared key access disabled** (Azure Policy requirement)
- **OAuth/Entra ID authentication only**
- **Storage Blob Data Contributor** RBAC role required for upload
- **Storage Blob Data Reader** RBAC role required for Power BI read access

### Network Access & Power BI Connectivity

Azure Policy requires `publicNetworkAccess: Disabled` on storage accounts. This affects how Power BI connects to ADLS Gen2:

| Scenario | Network Path | Works with public access disabled? |
|----------|--------------|-------------------------------------|
| PBI Desktop → ADLS Gen2 | Developer machine → public internet → storage | ❌ Blocked |
| PBI Service → ADLS Gen2 (trusted bypass) | Microsoft backbone (trusted Azure service) | ✅ Via `"bypass": "AzureServices"` |
| PBI Service → ADLS Gen2 (private endpoint) | Managed VNet or VNet data gateway | ✅ Via private endpoint |
| PBI Service → ADLS Gen2 (on-prem gateway) | Gateway VM in VNet → private endpoint | ✅ Via gateway |

**Recommended workflow:**

1. **Development** — Temporarily enable public network access to author and test in Power BI Desktop, or use a VM in the storage account's VNet.
2. **Publish** — Publish the report to a Power BI workspace (Premium or Fabric capacity recommended for managed VNet).
3. **Production** — Re-disable public network access. Configure scheduled refresh in the Power BI Service using one of:
   - **Trusted service bypass** — Already configured (`"bypass": "AzureServices"`). Use Organizational account (OAuth) credentials in the PBI Service data source settings.
   - **Managed VNet** — Available with Premium/Fabric capacity. The PBI Service connects over the Microsoft backbone without needing a gateway.
   - **VNet data gateway** — A managed gateway in the same VNet as the storage private endpoint.
   - **On-premises data gateway** — Install on a VM with network access to the storage private endpoint.

> **Note:** Power BI Desktop is only needed for authoring. Production data refresh runs server-side in the Power BI Service, where private connectivity options are available.

### Opening the Report in Power BI Desktop

1. Open `power-bi/APMSecurityReport.pbip` in Power BI Desktop (April 2026 or later).
2. When prompted for credentials, select **Organizational account** and sign in with your Entra ID account.
3. Click **Refresh** to load data from ADLS Gen2.

## Related Repositories

| Repository | Description |
|------------|-------------|
| [agentic-accelerator-framework](https://github.com/devopsabcs-engineering/agentic-accelerator-framework) | Framework agents, instructions, and skills |
| [apm-security-scan-workshop](https://devopsabcs-engineering.github.io/apm-security-scan-workshop/) | Hands-on APM Security scanning workshop |
