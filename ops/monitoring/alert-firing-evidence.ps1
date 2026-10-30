# H07 alert-firing evidence collector (staging, loopback-only).
# Stops aml_staging_worker_anchor, polls Prometheus until
# BurhanWorkerHeartbeatStale fires, prints the timeline and alert JSON,
# restarts the worker, and records recovery.
$ErrorActionPreference = 'Stop'
$prom = 'http://127.0.0.1:19090'

function Get-Alert([string]$name) {
    $a = Invoke-RestMethod -Uri "$prom/api/v1/alerts"
    return @($a.data.alerts | Where-Object { $_.labels.alertname -eq $name })
}

function Get-Age {
    $q = Invoke-RestMethod -Uri ($prom + '/api/v1/query?query=' + [uri]::EscapeDataString('burhan_worker_heartbeat_age_seconds{role="anchor"}'))
    if ($q.data.result.Count -gt 0) { return [math]::Round([double]$q.data.result[0].value[1], 1) }
    return -1
}

$t0 = (Get-Date).ToUniversalTime()
Write-Output ("T0=" + $t0.ToString('yyyy-MM-ddTHH:mm:ss') + "Z action=docker stop aml_staging_worker_anchor")
docker stop aml_staging_worker_anchor | Out-Null
$tStop = (Get-Date).ToUniversalTime()
Write-Output ("STOP_RETURNED=" + $tStop.ToString('yyyy-MM-ddTHH:mm:ss') + "Z")

$firedAt = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 5
    $now = (Get-Date).ToUniversalTime()
    $al = Get-Alert 'BurhanWorkerHeartbeatStale'
    $state = if ($al.Count -gt 0) { $al[0].state } else { 'none' }
    $age = Get-Age
    Write-Output ("POLL=" + $now.ToString('HH:mm:ss') + "Z alert=" + $state + " anchor_heartbeat_age=" + $age + "s")
    if ($al.Count -gt 0 -and $al[0].state -eq 'firing') { $firedAt = $now; break }
}

if ($firedAt) {
    Write-Output ("FIRED_AT=" + $firedAt.ToString('yyyy-MM-ddTHH:mm:ss') + "Z")
    Write-Output ("DELTA_T0_TO_FIRING_SECONDS=" + [math]::Round(($firedAt - $t0).TotalSeconds, 1))
    Write-Output ("DELTA_STOPRETURN_TO_FIRING_SECONDS=" + [math]::Round(($firedAt - $tStop).TotalSeconds, 1))
    $al = Get-Alert 'BurhanWorkerHeartbeatStale'
    Write-Output ("ALERT_JSON=" + ($al[0] | ConvertTo-Json -Depth 6 -Compress))
} else {
    Write-Output "RESULT=NOT_FIRED_WITHIN_300s"
}

Write-Output "RESTARTING worker_anchor"
docker start aml_staging_worker_anchor | Out-Null
Start-Sleep -Seconds 20
$al = Get-Alert 'BurhanWorkerHeartbeatStale'
$state = if ($al.Count -gt 0) { $al[0].state } else { 'none' }
Write-Output ("AFTER_RESTART_20s alert=" + $state + " anchor_heartbeat_age=" + (Get-Age) + "s")
for ($i = 0; $i -lt 24; $i++) {
    Start-Sleep -Seconds 5
    $al = Get-Alert 'BurhanWorkerHeartbeatStale'
    $state = if ($al.Count -gt 0) { $al[0].state } else { 'none' }
    if ($state -eq 'none' -or $state -eq 'inactive') {
        Write-Output ("RESOLVED_AT=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') + "Z")
        break
    }
    if ($i -eq 23) { Write-Output ("POST_RESTART_FINAL_STATE=" + $state) }
}
Write-Output ("WORKER_STATUS=" + (docker ps --filter name=aml_staging_worker_anchor --format "{{.Names}} {{.Status}}"))
