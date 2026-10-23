# Automated Disaster Recovery Backup Script (T23)
param(
    [string]$OutputDir = "./backups",
    [string]$DbUrl = "sqlite:///cyber_audit_chain.db",
    [string]$EvidenceDir = "./evidence_store",
    [string]$Name = ""
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$runner = Join-Path $repoRoot "scripts\run-python.js"
$backupPy = Join-Path $scriptDir "backup.py"

$argsList = @($runner, $backupPy, "--output-dir", $OutputDir, "--db-url", $DbUrl, "--evidence-dir", $EvidenceDir)
if ($Name -ne "") {
    $argsList += @("--name", $Name)
}

Write-Host "[PowerShell Backup] Running backup CLI..." -ForegroundColor Cyan
node $argsList
if ($LASTEXITCODE -ne 0) {
    Write-Error "Backup failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
