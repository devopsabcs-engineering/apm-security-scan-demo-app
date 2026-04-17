<#
.SYNOPSIS
    Sets up ADO Workload Identity Federation for apm-security-scan-demo-app.

.DESCRIPTION
    Creates an Azure AD app registration with WIF for Azure DevOps pipelines.
    Creates service connection in ADO using workload identity federation.

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
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$AdoOrg = "MngEnvMCAP675646",

    [Parameter(Mandatory = $false)]
    [string]$AdoProject = "APM Security"
)

$ErrorActionPreference = "Stop"

$AppDisplayName = "apm-security-scan-demo-app-ado-oidc"
$ServiceConnectionName = "apm-security-scan-demo-app-ado-sc"

Write-Host "=== APM Security ADO OIDC Setup ===" -ForegroundColor Cyan
Write-Host "App Name: $AppDisplayName"
Write-Host "ADO Org: $AdoOrg"
Write-Host "ADO Project: $AdoProject"
Write-Host ""

# ── Step 1: Create or reuse Azure AD app registration ──
$existingApp = az ad app list --display-name $AppDisplayName --query "[0].appId" -o tsv
if ($existingApp) {
    Write-Host "App registration '$AppDisplayName' already exists (appId: $existingApp)." -ForegroundColor Yellow
    $appId = $existingApp
} else {
    Write-Host "Creating app registration '$AppDisplayName'..." -ForegroundColor Green
    $appId = az ad app create --display-name $AppDisplayName --query appId -o tsv
    Write-Host "Created app registration with appId: $appId" -ForegroundColor Green
}

# ── Step 2: Create or reuse service principal ──
$existingSp = az ad sp list --filter "appId eq '$appId'" --query "[0].id" -o tsv
if ($existingSp) {
    Write-Host "Service principal already exists for appId $appId." -ForegroundColor Yellow
    $spId = $existingSp
} else {
    Write-Host "Creating service principal..." -ForegroundColor Green
    $spId = az ad sp create --id $appId --query id -o tsv
    Write-Host "Created service principal with id: $spId" -ForegroundColor Green
}

# ── Step 3: Assign Contributor role ──
$scope = "/subscriptions/$SubscriptionId"
$existingRole = az role assignment list --assignee $spId --role "Contributor" --scope $scope --query "[0]" -o tsv
if ($existingRole) {
    Write-Host "Role 'Contributor' already assigned — skipping." -ForegroundColor Yellow
} else {
    Write-Host "Assigning Contributor role to service principal..." -ForegroundColor Green
    az role assignment create --assignee $spId --role "Contributor" --scope $scope
    Write-Host "Role assigned successfully." -ForegroundColor Green
}

# ── Step 4: Create federated credential for ADO ──
$credName = "apm-security-ado-wif"
$existingCreds = az ad app federated-credential list --id $appId --query "[].name" -o tsv

if ($existingCreds -contains $credName) {
    Write-Host "Federated credential '$credName' already exists — skipping." -ForegroundColor Yellow
} else {
    Write-Host "Creating federated credential '$credName'..." -ForegroundColor Green
    $issuer = "https://vstoken.dev.azure.com/$AdoOrg"
    $subject = "sc://$AdoOrg/$AdoProject/$ServiceConnectionName"
    $credParams = @{
        name      = $credName
        issuer    = $issuer
        subject   = $subject
        audiences = @("api://AzureADTokenExchange")
    }
    $tempFile = [System.IO.Path]::GetTempFileName()
    $credParams | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
    az ad app federated-credential create --id $appId --parameters "@$tempFile"
    Remove-Item -Path $tempFile -Force
    Write-Host "Created federated credential '$credName'." -ForegroundColor Green
}

# ── Step 5: Output summary ──
$tenantId = az account show --query tenantId -o tsv

Write-Host ""
Write-Host "=== ADO OIDC Setup Complete ===" -ForegroundColor Cyan
Write-Host "App Display Name        : $AppDisplayName"
Write-Host "App (Client) ID         : $appId"
Write-Host "Tenant ID               : $tenantId"
Write-Host "Subscription ID         : $SubscriptionId"
Write-Host "Service Connection Name : $ServiceConnectionName"
