# H07 alert-firing evidence collector (staging, loopback-only).
# Stops aml_staging_worker_anchor, polls Prometheus until
# BurhanWorkerHeartbeatStale fires, prints the timeline and the RAW alert JSON,
# restarts the worker, and records recovery + the TSDB firing window.
#
# HTTP client: curl.exe (NOT Invoke-RestMethod — PS 5.1's WinINET-backed client
# served stale/empty bodies for identical repeated GETs against the same
# Prometheus that curl saw correctly; observed 2026-10-30). All evidence lines
# embed raw API bodies so the run is auditable without trusting any parser.
$ErrorActionPreference = 'Stop'
$prom = 'http://127.0.0.1:19090'
$alertName = 'BurhanWorkerHeartbeatStale'

function Get-AlertsBody {
    return ((curl.exe -s --max-time 4 "$prom/api/v1/alerts") -join '')
}

function Get-AlertState([string]$body) {
    if ($body -notmatch ('"alertname":"' + $alertName + '"')) { return 'none' }
    $m = [regex]::Match($body, '"state":"(\w+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return 'unknown'
}

function Get-ActiveAt([string]$body) {
    $m = [regex]::Match($body, '"activeAt":"([^"]+)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-Age {
    $q = 'burhan_worker_heartbeat_age_seconds{role="anchor"}'
    $body = ((curl.exe -s --max-time 4 ($prom + '/api/v1/query?query=' + [uri]::EscapeDataString($q))) -join '')
    $m = [regex]::Match($body, '"value":\[[0-9.]+,"([0-9.e+-]+)"\]')
    if ($m.Success) { return [math]::Round([double]$m.Groups[1].Value, 1) }
    return -1
}

function Get-FiringSeriesCount {
    $q = 'ALERTS{alertname="' + $alertName + '",alertstate="firing"}'
    $body = ((curl.exe -s --max-time 4 ($prom + '/api/v1/query?query=' + [uri]::EscapeDataString($q))) -join '')
    if ($body -match '"alertstate":"firing"') { return 1 }
    return 0
}

$t0 = (Get-Date).ToUniversalTime()
Write-Output ("T0=" + $t0.ToString('yyyy-MM-ddTHH:mm:ss') + "Z action=docker stop aml_staging_worker_anchor")
docker stop aml_staging_worker_anchor | Out-Null
$tStop = (Get-Date).ToUniversalTime()
Write-Output ("STOP_RETURNED=" + $tStop.ToString('yyyy-MM-ddTHH:mm:ss') + "Z")

$firedAt = $null
$activeAt = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 5
    $now = (Get-Date).ToUniversalTime()
    $body = Get-AlertsBody
    $state = Get-AlertState $body
    $fs = Get-FiringSeriesCount
    $age = Get-Age
    Write-Output ("POLL=" + $now.ToString('HH:mm:ss') + "Z api_alert=" + $state + " tsdb_firing_series=" + $fs + " anchor_heartbeat_age=" + $age + "s")
    if ($state -eq 'firing' -or $fs -eq 1) {
        $firedAt = $now
        $activeAt = Get-ActiveAt $body
        Write-Output ("RAW_ALERTS_BODY=" + $body)
        break
    }
}

if ($firedAt) {
    Write-Output ("FIRED_AT=" + $firedAt.ToString('yyyy-MM-ddTHH:mm:ss') + "Z")
    if ($activeAt) { Write-Output ("ACTIVE_AT=" + $activeAt) }
    Write-Output ("DELTA_T0_TO_FIRING_SECONDS=" + [math]::Round(($firedAt - $t0).TotalSeconds, 1))
    Write-Output ("DELTA_STOPRETURN_TO_FIRING_SECONDS=" + [math]::Round(($firedAt - $tStop).TotalSeconds, 1))
} else {
    Write-Output "RESULT=NOT_FIRED_WITHIN_300s"
}

Write-Output "RESTARTING worker_anchor"
docker start aml_staging_worker_anchor | Out-Null
$tStart = (Get-Date).ToUniversalTime()
Write-Output ("START_RETURNED=" + $tStart.ToString('yyyy-MM-ddTHH:mm:ss') + "Z")
$resolvedAt = $null
for ($i = 0; $i -lt 24; $i++) {
    Start-Sleep -Seconds 5
    $now = (Get-Date).ToUniversalTime()
    $body = Get-AlertsBody
    $state = Get-AlertState $body
    $fs = Get-FiringSeriesCount
    Write-Output ("RECOVER_POLL=" + $now.ToString('HH:mm:ss') + "Z api_alert=" + $state + " tsdb_firing_series=" + $fs + " anchor_heartbeat_age=" + (Get-Age) + "s")
    if ($state -eq 'none' -and $fs -eq 0) {
        $resolvedAt = $now
        Write-Output ("RAW_ALERTS_BODY_AFTER_RESOLVE=" + $body)
        break
    }
}
if ($resolvedAt) {
    Write-Output ("RESOLVED_AT=" + $resolvedAt.ToString('yyyy-MM-ddTHH:mm:ss') + "Z")
    Write-Output ("DELTA_STARTRETURN_TO_RESOLVED_SECONDS=" + [math]::Round(($resolvedAt - $tStart).TotalSeconds, 1))
} else {
    Write-Output "RESULT=NOT_RESOLVED_WITHIN_120s"
}

# TSDB corroboration: the ALERTS firing window recorded by the rule manager.
$endUnix = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$startUnix = [DateTimeOffset]::Parse($tStop.ToString('yyyy-MM-ddTHH:mm:ssZ')).ToUnixTimeSeconds()
$q = 'ALERTS{alertname="' + $alertName + '",alertstate="firing"}'
$u = $prom + '/api/v1/query_range?query=' + [uri]::EscapeDataString($q) + '&start=' + $startUnix + '&end=' + $endUnix + '&step=5s'
$tsdb = ((curl.exe -s --max-time 8 $u) -join '')
Write-Output ("TSDB_FIRING_WINDOW=" + $tsdb)
Write-Output ("WORKER_STATUS=" + (docker ps --filter name=aml_staging_worker_anchor --format "{{.Names}} {{.Status}}"))
