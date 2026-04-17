# Workshop Setup Guide

## Prerequisites

- Azure subscription with Contributor access
- GitHub organization with Advanced Security enabled
- Azure CLI 2.60+
- PowerShell 7+
- Node.js 20+ (for APM CLI)
- Python 3.12+ (for custom scanners)

## Step 1: OIDC Federation

```powershell
./scripts/setup-oidc.ps1
```

This creates an Entra ID app registration with federated credentials for GitHub Actions.

## Step 2: Bootstrap Demo Apps

```powershell
./scripts/bootstrap-demo-apps.ps1
```

This creates 5 GitHub repos (`apm-demo-app-001` through `005`), pushes content, and sets OIDC secrets.

## Step 3: Deploy Infrastructure

Trigger the `deploy-all.yml` workflow on the scanner repo to deploy all 5 apps and the ADLS Gen2 storage.

## Step 4: Run Scans

Trigger the `apm-security-scan.yml` workflow to scan all 5 apps and upload SARIF to their Security tabs.

## Step 5: Verify

Check each demo app's Security > Code Scanning tab for findings.

## ADO Setup

For ADO-based workshops:

```powershell
./scripts/setup-oidc-ado.ps1
./scripts/bootstrap-demo-apps-ado.ps1
```

## Teardown

```powershell
# GitHub
# Trigger teardown-all.yml workflow

# Or manually:
# az group delete --name rg-apm-demo-001 --yes --no-wait
# ... repeat for 002-005
```
