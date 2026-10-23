# Automated Disaster Recovery Restore Script (T23)
param(
    [Parameter(Mandatory=$true)]
    [string]$Bundle,
    [Parameter(Mandatory=$true)]
    [string]$TargetDbUrl,
    [string]$TargetEvidenceDir = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$runner = Join-Path $repoRoot "scripts\run-python.js"
$restorePy = Join-Path $scriptDir "restore.py"

$argsList = @($runner, $restorePy, "--bundle", $Bundle, "--target-db-url", $TargetDbUrl)
if ($TargetEvidenceDir -ne "") {
    $argsList += @("--target-evidence-dir", $TargetEvidenceDir)
}

Write-Host "[PowerShell Restore] Running restore CLI..." -ForegroundColor Cyan
node $argsList
if ($LASTEXITCODE -ne 0) {
    Write-Error "Restore failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
