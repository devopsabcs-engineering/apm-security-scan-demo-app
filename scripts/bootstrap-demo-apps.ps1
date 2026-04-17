<#
.SYNOPSIS
    Bootstraps GitHub demo app repositories for the APM Security domain.

.DESCRIPTION
    Creates 5 GitHub repos (apm-demo-app-001 through 005), pushes content,
    sets OIDC secrets, creates prod environment, enables code scanning.
    Also sets OIDC secrets and prod environment on the scanner repo itself.
    All operations are idempotent — safe to re-run.

.PARAMETER ClientId
    Azure AD client ID from OIDC setup.

.PARAMETER TenantId
    Azure AD tenant ID.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER GitHubOrg
    GitHub organization name.
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
    [string]$GitHubOrg = "devopsabcs-engineering"
)

$ErrorActionPreference = "Stop"

$ScannerRepo = "apm-security-scan-demo-app"
$DemoApps = @(
    @{ Name = "apm-demo-app-001"; Dir = "apm-demo-app-001"; Description = "APM Security Demo App 001 — Next.js with Unicode injection violations" },
    @{ Name = "apm-demo-app-002"; Dir = "apm-demo-app-002"; Description = "APM Security Demo App 002 — Flask with Base64/exfiltration violations" },
    @{ Name = "apm-demo-app-003"; Dir = "apm-demo-app-003"; Description = "APM Security Demo App 003 — ASP.NET with MCP configuration violations" },
    @{ Name = "apm-demo-app-004"; Dir = "apm-demo-app-004"; Description = "APM Security Demo App 004 — Spring Boot with shell injection violations" },
    @{ Name = "apm-demo-app-005"; Dir = "apm-demo-app-005"; Description = "APM Security Demo App 005 — Go with lockfile integrity violations" }
)

$Topics = @('apm-security', 'sarif', 'agent-security', 'supply-chain', 'owasp-llm', 'demo-app', 'agentic-accelerator')

Write-Host "=== APM Security Demo App Bootstrap ===" -ForegroundColor Cyan
Write-Host "GitHub Org: $GitHubOrg"
Write-Host "Scanner Repo: $ScannerRepo"
Write-Host ""

function Set-OidcSecrets {
    param([string]$RepoFullName)
    Write-Host "  Setting OIDC secrets on $RepoFullName..." -ForegroundColor Gray
    gh secret set AZURE_CLIENT_ID --body $ClientId --repo $RepoFullName
    gh secret set AZURE_TENANT_ID --body $TenantId --repo $RepoFullName
    gh secret set AZURE_SUBSCRIPTION_ID --body $SubscriptionId --repo $RepoFullName
}

function New-ProdEnvironment {
    param([string]$RepoFullName)
    Write-Host "  Creating 'prod' environment on $RepoFullName..." -ForegroundColor Gray
    gh api "repos/$RepoFullName/environments/prod" --method PUT 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Environment 'prod' created/confirmed." -ForegroundColor Gray
    }
}

# ── Step 1: Set OIDC secrets on the scanner repo ──
Write-Host "Setting OIDC secrets on scanner repo ($GitHubOrg/$ScannerRepo)..." -ForegroundColor Green
Set-OidcSecrets -RepoFullName "$GitHubOrg/$ScannerRepo"
New-ProdEnvironment -RepoFullName "$GitHubOrg/$ScannerRepo"

# ── Step 2: Bootstrap each demo app repo ──
foreach ($app in $DemoApps) {
    $repoName = $app.Name
    $appDir = $app.Dir
    $description = $app.Description
    $fullRepo = "$GitHubOrg/$repoName"

    Write-Host ""
    Write-Host "--- Processing $repoName ---" -ForegroundColor Cyan

    $repoCheck = gh repo view $fullRepo --json name 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Creating repository $fullRepo..." -ForegroundColor Green
        gh repo create $fullRepo --public --description $description
    } else {
        Write-Host "Repository $fullRepo already exists — skipping creation." -ForegroundColor Yellow
    }

    $commitCount = gh api "repos/$fullRepo/commits?per_page=1" --jq 'length' 2>$null
    if ($LASTEXITCODE -ne 0 -or $commitCount -eq 0) {
        Write-Host "Pushing initial content from $appDir..." -ForegroundColor Green
        Push-Location $appDir
        try {
            if (-not (Test-Path ".git")) {
                git init
                git branch -M main
            }
            git add -A
            git commit -m "feat: initial scaffold for $repoName" --allow-empty
            git remote remove origin 2>$null
            git remote add origin "https://github.com/$fullRepo.git"
            git push -u origin main --force
        } finally {
            Pop-Location
        }
    } else {
        Write-Host "Repository $fullRepo already has content — skipping push." -ForegroundColor Yellow
    }

    foreach ($topic in $Topics) {
        gh repo edit $fullRepo --add-topic $topic
    }

    gh repo edit $fullRepo --description $description

    Set-OidcSecrets -RepoFullName $fullRepo
    New-ProdEnvironment -RepoFullName $fullRepo

    Write-Host "  Enabling code scanning on $fullRepo..." -ForegroundColor Gray
    try {
        gh api "repos/$fullRepo/code-scanning/default-setup" -X PATCH -f state=configured 2>$null
    } catch {
        Write-Host "  Code scanning setup may require manual configuration." -ForegroundColor Yellow
    }

    Write-Host "✅ $repoName bootstrapped successfully." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Bootstrap Complete ===" -ForegroundColor Cyan
Write-Host "All 5 demo app repos and the scanner repo have been configured."
Write-Host "Next steps:"
Write-Host "  1. Verify repos at https://github.com/$GitHubOrg"
Write-Host "  2. Run deploy-all.yml workflow from the scanner repo"
Write-Host "  3. Run apm-security-scan.yml to generate initial findings"
