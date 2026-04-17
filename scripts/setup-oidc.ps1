<#
.SYNOPSIS
    Sets up GitHub OIDC federation for apm-security-scan-demo-app.

.DESCRIPTION
    Creates an Azure AD app registration with federated identity credentials
    for GitHub Actions OIDC login. Creates service principal and assigns
    Contributor role. Per-domain app registration (not shared).

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER GitHubOrg
    GitHub organization name.

.PARAMETER Location
    Azure region for resource groups (default: canadacentral).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$GitHubOrg = "devopsabcs-engineering",

    [Parameter(Mandatory = $false)]
    [string]$Location = "canadacentral"
)

$ErrorActionPreference = "Stop"

$AppDisplayName = "apm-security-scan-demo-app-oidc"
$ScannerRepo = "apm-security-scan-demo-app"
$DemoApps = @("apm-demo-app-001", "apm-demo-app-002", "apm-demo-app-003", "apm-demo-app-004", "apm-demo-app-005")
$AllRepos = @($ScannerRepo) + $DemoApps

Write-Host "=== APM Security OIDC Setup ===" -ForegroundColor Cyan
Write-Host "App Name: $AppDisplayName"
Write-Host "GitHub Org: $GitHubOrg"
Write-Host "Subscription: $SubscriptionId"
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

# ── Step 4: Create federated credentials for each repo ──
$existingCreds = az ad app federated-credential list --id $appId --query "[].name" -o tsv
$issuer = "https://token.actions.githubusercontent.com"
$audience = "api://AzureADTokenExchange"

foreach ($repo in $AllRepos) {
    # Environment: prod
    $credName = "$repo-environment-prod"
    $subject = "repo:${GitHubOrg}/${repo}:environment:prod"

    if ($existingCreds -contains $credName) {
        Write-Host "Federated credential '$credName' already exists — skipping." -ForegroundColor Yellow
    } else {
        Write-Host "Creating federated credential '$credName'..." -ForegroundColor Green
        $credParams = @{
            name      = $credName
            issuer    = $issuer
            subject   = $subject
            audiences = @($audience)
        }
        $tempFile = [System.IO.Path]::GetTempFileName()
        $credParams | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
        az ad app federated-credential create --id $appId --parameters "@$tempFile"
        Remove-Item -Path $tempFile -Force
        Write-Host "Created federated credential '$credName'." -ForegroundColor Green
    }

    # Branch: main
    $credName = "$repo-branch-main"
    $subject = "repo:${GitHubOrg}/${repo}:ref:refs/heads/main"

    if ($existingCreds -contains $credName) {
        Write-Host "Federated credential '$credName' already exists — skipping." -ForegroundColor Yellow
    } else {
        Write-Host "Creating federated credential '$credName'..." -ForegroundColor Green
        $credParams = @{
            name      = $credName
            issuer    = $issuer
            subject   = $subject
            audiences = @($audience)
        }
        $tempFile = [System.IO.Path]::GetTempFileName()
        $credParams | ConvertTo-Json | Set-Content -Path $tempFile -Encoding UTF8
        az ad app federated-credential create --id $appId --parameters "@$tempFile"
        Remove-Item -Path $tempFile -Force
        Write-Host "Created federated credential '$credName'." -ForegroundColor Green
    }
}

# ── Step 5: Output summary ──
$tenantId = az account show --query tenantId -o tsv

Write-Host ""
Write-Host "=== OIDC Setup Complete ===" -ForegroundColor Cyan
Write-Host "App Display Name : $AppDisplayName"
Write-Host "App (Client) ID  : $appId"
Write-Host "Tenant ID        : $tenantId"
Write-Host "Subscription ID  : $SubscriptionId"
Write-Host ""
Write-Host "Use these values for GitHub secrets:" -ForegroundColor Yellow
Write-Host "  AZURE_CLIENT_ID       = $appId"
Write-Host "  AZURE_TENANT_ID       = $tenantId"
Write-Host "  AZURE_SUBSCRIPTION_ID = $SubscriptionId"
