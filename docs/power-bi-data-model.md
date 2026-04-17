# Power BI Data Model

## Overview

The APM Security Power BI report connects to ADLS Gen2 storage where scan results are stored as SARIF JSON files.

## Star Schema

```text
Fact_APMSecurityFindings
  ├── Dim_Date (scan date)
  ├── Dim_Repository (demo app)
  ├── Dim_ScanTool (engine name)
  ├── Dim_Engine (engine 1-4)
  ├── Dim_Severity (critical/high/medium/low)
  ├── Dim_AttackCategory (OWASP LLM Top 10)
  └── Dim_Rule (APM-SEC-xxx, APM-MCP-xxx)
```

## Fact Table: Fact_APMSecurityFindings

| Column | Type | Description |
|--------|------|-------------|
| FindingId | Text | Unique finding identifier |
| DateKey | Int | FK to Dim_Date |
| RepositoryKey | Int | FK to Dim_Repository |
| EngineKey | Int | FK to Dim_Engine |
| SeverityKey | Int | FK to Dim_Severity |
| RuleKey | Int | FK to Dim_Rule |
| FilePath | Text | File where finding was detected |
| LineNumber | Int | Line number |
| Message | Text | Finding description |

## Report Pages

1. **Security Overview** — KPIs, severity distribution, trends over time
2. **Unicode Analysis** — Glassworm/bidi findings by repository and file
3. **Attack Category Distribution** — OWASP LLM Top 10 mapping treemap
4. **Engine Comparison** — Findings per engine, overlap analysis, coverage gaps
