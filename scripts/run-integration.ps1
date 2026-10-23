# PowerShell 7+ / Windows Integration Runner (T12)
param (
    [string]$RpcPort = "8545",
    [string]$ApiPort = "8000"
)

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Starting Iraq AML Audit Chain Integration Runner (PS)" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

$env:RPC_PORT = $RpcPort
$env:API_PORT = $ApiPort

node scripts/run-integration.js @args
$runnerExitCode = $LASTEXITCODE

if ($runnerExitCode -eq 0) {
    Write-Host "`n[SUCCESS] Integration flow passed G1 Gate!" -ForegroundColor Green
} else {
    Write-Host "`n[FAILED] Integration flow failed with exit code $runnerExitCode" -ForegroundColor Red
}

exit $runnerExitCode
