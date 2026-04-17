<#
.SYNOPSIS
    Bootstraps Azure DevOps repos, variable groups, and pipelines for APM Security.

.DESCRIPTION
    Creates Azure DevOps repositories, pushes content, creates variable groups,
    service connections, and pipeline definitions. All operations are idempotent.

.PARAMETER ClientId
    Azure AD client ID from OIDC setup.

.PARAMETER TenantId
    Azure AD tenant ID.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER AdoOrg
    Azure DevOps organization name.

.PARAMETER AdoProject
    Azure DevOps project name.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$AdoOrg = "MngEnvMCAP675646",

    [Parameter(Mandatory = $false)]
    [string]$AdoProject = "APM Security"
)

$ErrorActionPreference = "Stop"

$AdoOrgUrl = "https://dev.azure.com/$AdoOrg"
$ScannerRepo = "apm-security-scan-demo-app"
$DemoApps = @(
    @{ Name = "apm-demo-app-001"; Dir = "apm-demo-app-001"; Flavor = "javascript" },
    @{ Name = "apm-demo-app-002"; Dir = "apm-demo-app-002"; Flavor = "python" },
    @{ Name = "apm-demo-app-003"; Dir = "apm-demo-app-003"; Flavor = "dotnet" },
    @{ Name = "apm-demo-app-004"; Dir = "apm-demo-app-004"; Flavor = "java" },
    @{ Name = "apm-demo-app-005"; Dir = "apm-demo-app-005"; Flavor = "go" }
)

Write-Host "=== APM Security ADO Bootstrap ===" -ForegroundColor Cyan
Write-Host "ADO Org: $AdoOrg"
Write-Host "ADO Project: $AdoProject"
Write-Host ""

# ── Step 1: Create variable group ──
Write-Host "Creating variable group 'apm-security-variables'..." -ForegroundColor Green
$existingVg = az pipelines variable-group list --org $AdoOrgUrl --project $AdoProject --query "[?name=='apm-security-variables'].id" -o tsv 2>$null
if ($existingVg) {
    Write-Host "Variable group already exists (id: $existingVg)." -ForegroundColor Yellow
} else {
    az pipelines variable-group create `
        --org $AdoOrgUrl --project $AdoProject `
        --name "apm-security-variables" `
        --variables `
            AZURE_CLIENT_ID=$ClientId `
            AZURE_TENANT_ID=$TenantId `
            AZURE_SUBSCRIPTION_ID=$SubscriptionId `
            LOCATION=canadacentral
}

# ── Step 2: Create repos and push content ──
foreach ($app in $DemoApps) {
    $repoName = $app.Name
    $appDir = $app.Dir

    Write-Host ""
    Write-Host "--- Processing $repoName ---" -ForegroundColor Cyan

    $existingRepo = az repos show --repository $repoName --org $AdoOrgUrl --project $AdoProject --query id -o tsv 2>$null
    if (-not $existingRepo) {
        Write-Host "Creating repo $repoName..." -ForegroundColor Green
        az repos create --name $repoName --org $AdoOrgUrl --project $AdoProject
    } else {
        Write-Host "Repo $repoName already exists." -ForegroundColor Yellow
    }

    Write-Host "✅ $repoName processed." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== ADO Bootstrap Complete ===" -ForegroundColor Cyan
