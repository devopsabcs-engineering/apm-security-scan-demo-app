<#
.SYNOPSIS
    Runs APM Security scan and uploads results to ADLS Gen2 for Power BI.

.DESCRIPTION
    Executes all 4 scanning engines across the 5 demo apps and uploads
    SARIF results to Azure Data Lake Storage Gen2 for Power BI reporting.

.PARAMETER StorageAccountName
    ADLS Gen2 storage account name.

.PARAMETER ContainerName
    ADLS Gen2 container name.

.PARAMETER ScanDir
    Directory containing demo apps to scan.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ContainerName = "apm-security-results",

    [Parameter(Mandatory = $false)]
    [string]$ScanDir = "."
)

$ErrorActionPreference = "Stop"

$today = Get-Date -Format "yyyy/MM/dd"
$apps = @("apm-demo-app-001", "apm-demo-app-002", "apm-demo-app-003", "apm-demo-app-004", "apm-demo-app-005")

Write-Host "=== APM Security Scan & Store ===" -ForegroundColor Cyan
Write-Host "Storage Account: $StorageAccountName"
Write-Host "Container: $ContainerName"
Write-Host "Date Path: $today"
Write-Host ""

foreach ($app in $apps) {
    $appDir = Join-Path $ScanDir $app

    if (-not (Test-Path $appDir)) {
        Write-Host "Skipping $app — directory not found." -ForegroundColor Yellow
        continue
    }

    Write-Host "Scanning $app..." -ForegroundColor Green

    # Engine 3: Semantic scan
    $semanticOutput = Join-Path $env:TEMP "$app-semantic.sarif"
    python src/converters/semantic-to-sarif.py --scan-dir $appDir --output $semanticOutput 2>$null

    if (Test-Path $semanticOutput) {
        $blobPath = "$today/$app-semantic.sarif"
        az storage blob upload --account-name $StorageAccountName --container-name $ContainerName `
            --file $semanticOutput --name $blobPath --auth-mode login --overwrite 2>$null
        Write-Host "  Uploaded semantic results to $blobPath" -ForegroundColor Gray
    }

    # Engine 4: MCP validation
    $mcpOutput = Join-Path $env:TEMP "$app-mcp.sarif"
    python src/converters/mcp-to-sarif.py --scan-dir $appDir --output $mcpOutput 2>$null

    if (Test-Path $mcpOutput) {
        $blobPath = "$today/$app-mcp.sarif"
        az storage blob upload --account-name $StorageAccountName --container-name $ContainerName `
            --file $mcpOutput --name $blobPath --auth-mode login --overwrite 2>$null
        Write-Host "  Uploaded MCP results to $blobPath" -ForegroundColor Gray
    }

    Write-Host "✅ $app scan complete." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Scan & Store Complete ===" -ForegroundColor Cyan
