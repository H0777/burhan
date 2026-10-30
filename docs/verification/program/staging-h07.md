# Staging Verification — H07 Observability: Prometheus / Grafana / Alerts (DG2)

Date: 2026-10-30. Branch `main`, base `ce4ee5d` (three H07 commits already landed
by the prior session). Status: **COMPLETE**.
Closure for `.superpowers/sdd/2026-10-29-development-program/task-h07-brief.md`.

## 1. What was delivered

Golden metrics exposed by the engine, scraped by Prometheus, visualized in a
provisioned Grafana dashboard, guarded by 4 alert rules with runbooks, and
**proven with a live dependency-failure test in staging** (worker stopped →
heartbeat alert fired → worker restored → alert resolved):

| File | Purpose |
|---|---|
| `ai-engine/app/routes/internal/metrics.py` | `/internal/metrics` (Prometheus text format): worker heartbeat ages, oldest outbox age, outbox/chain-status gauges, confirmation depth, HTTP p95 histogram, upload rejections, RPC probe/errors, readiness latency + 503 counter. Labels are institution ids, roles, status enums, route templates and status codes only — **no PII, no secrets** |
| `ops/monitoring/prometheus.yml` | 5s scrape of `ai-engine:8000/internal/metrics` over the compose-internal network (engine publishes no host port) + 5s rule evaluation |
| `ops/monitoring/alerts.yml` | The 4 brief-mandated alerts: heartbeat >120s, outbox >300s, 5xx ratio >1% (5m), repeated readiness 503 (≥3 in 5m) — each with a `runbook` annotation |
| `ops/monitoring/docker-compose.monitoring.yml` | H07-owned override adding `prometheus` (127.0.0.1:19090) + `grafana` (127.0.0.1:18300), loopback-only; Grafana admin credentials interpolated from gitignored `.env`, fail-fast |
| `ops/monitoring/grafana/provisioning/**` | Datasource (`burhan-prom`, readOnly) + dashboard provider — provisioning-as-code, no manual UI steps |
| `ops/monitoring/dashboards/burhan-staging-health.json` | "Burhan Staging — System Health (H07)": 8 panels covering every golden metric |
| `docs/runbooks/alert-*.md` (4 files) | Response runbook per alert |
| `ops/monitoring/tests/alerts_test.yml` | promtool unit tests replaying the observed live-fire series against all 4 rules |
| `ops/monitoring/alert-firing-evidence.ps1` | Live-fire evidence collector (curl.exe-based — see §6) |
| `docs/verification/program/staging-h07-alert-firing.log.txt` | Raw transcript of the final live-fire run |

Commits (in order): `c870c4b` engine metrics + Prometheus config + alerts +
monitoring override, `28e46a0` Grafana provisioning-as-code, `ce4ee5d` runbooks,
`b3a3366` promtool unit tests + evidence collector, `4db4410` curl-based
collector fix (PS 5.1 client defect, §6).

## 2. Stack up (staging, Windows cmd)

```bat
REM Stacked on the H04 base — exit 0
docker compose --env-file infra/staging/.env ^
  -f infra/staging/docker-compose.staging.yml ^
  -f ops/monitoring/docker-compose.monitoring.yml up -d prometheus grafana

docker ps --filter name=aml_staging_prometheus --format "{{.Names}} {{.Status}} {{.Ports}}"
REM aml_staging_prometheus   Up ...   127.0.0.1:19090->9090/tcp   (loopback ONLY)
docker ps --filter name=aml_staging_grafana --format "{{.Names}} {{.Status}} {{.Ports}}"
REM aml_staging_grafana      Up ...   127.0.0.1:18300->3000/tcp   (loopback ONLY)
curl -s http://127.0.0.1:19090/-/healthy      REM -> Healthy
curl -s http://127.0.0.1:18300/api/health     REM -> {"database":"ok","version":"11.4.0",...}
```

The stack survived an overnight host reboot (containers restarted under the
`unless-stopped` policy); all verification below ran post-reboot.

## 3. Scrape targets UP (Prometheus API, 2026-10-30T06:23:50Z)

`GET /api/v1/targets` — both targets `"health":"up"`, `lastError:""`:

- `ai-engine:8000` (`/internal/metrics`) — last scrape duration 8.5ms
- `localhost:9090` (self)

`GET /api/v1/rules` — group `burhan-staging-golden`: all 4 rules loaded,
`health:"ok"`, evaluated every 5s. Engine `/internal/metrics` (fetched over the
internal network) exposes live values, e.g.
`burhan_worker_heartbeat_age_seconds{institution="INST-CENTRAL-STAGING",role="anchor"}`
≈ 4.5s, `burhan_metrics_db_up 1.0`, `burhan_rpc_probe_success 1.0`.

## 4. Alert-rule validation (promtool)

```bat
docker exec aml_staging_prometheus promtool check rules /etc/prometheus/alerts.yml
REM  Checking /etc/prometheus/alerts.yml
REM    SUCCESS: 4 rules found                              EXITCODE=0

docker cp ops/monitoring/tests aml_staging_prometheus:/tmp/h07-tests
docker exec aml_staging_prometheus promtool test rules /tmp/h07-tests/alerts_test.yml
REM    Unit Testing:  /tmp/h07-tests/alerts_test.yml
REM      SUCCESS                                              EXITCODE=0
```

The unit tests replay the exact series observed live: anchor heartbeat age
rising 1s/s (fires at t=120s, silent at 115s), a 2% 5xx window, outbox age past
300s, readiness 503 x3. Two expectations were corrected during validation —
alerts carry the series labels (`instance`, `job`) in addition to rule labels,
which the first draft of the test omitted.

## 5. LIVE-FIRE TEST (the brief's centerpiece)

`ops/monitoring/alert-firing-evidence.ps1` — full raw transcript:
`docs/verification/program/staging-h07-alert-firing.log.txt`. Final run
(2026-10-30, all times UTC):

```
T0=2026-10-30T06:59:47Z            action=docker stop aml_staging_worker_anchor
STOP_RETURNED=2026-10-30T06:59:50Z
FIRED_AT=2026-10-30T07:01:56Z      DELTA_STOPRETURN_TO_FIRING_SECONDS=126.3
ACTIVE_AT=2026-10-30T07:01:51.127768099Z   (121.1s after stop = the 120s threshold)
RAW_ALERTS_BODY={"status":"success","data":{"alerts":[{"labels":{"alertname":
  "BurhanWorkerHeartbeatStale",...,"role":"anchor","severity":"critical"},
  "annotations":{...,"runbook":"docs/runbooks/alert-worker-heartbeat.md"},
  "state":"firing","activeAt":"2026-10-30T07:01:51.127768099Z","value":"1.24e+02"}]}}
START_RETURNED=2026-10-30T07:01:56Z   (docker start aml_staging_worker_anchor)
RESOLVED_AT=2026-10-30T07:02:06Z   DELTA_STARTRETURN_TO_RESOLVED_SECONDS=10.1
RAW_ALERTS_BODY_AFTER_RESOLVE={"status":"success","data":{"alerts":[]}}
TSDB_FIRING_WINDOW=...ALERTS...alertstate="firing"... values=[[1793343715,"1"],[1793343720,"1"]]
WORKER_STATUS=aml_staging_worker_anchor Up 10 seconds
```

Acceptance reading: the alert becomes **active at 121.1s** after `docker stop` —
the configured threshold is exactly 120s, so this is the design floor plus one
scrape/eval cycle — and is observed **firing and documented at 126.3s**
(including the collector's 5s poll granularity). Alert carries
`severity=critical`, `role=anchor`, `institution=INST-CENTRAL-STAGING` and the
runbook pointer. Recovery: alert absent from the API 10.1s after
`docker start`; heartbeat age back to <1s. Three earlier stops this session
(06:24:56, 06:34:41, 06:40:29 runs) each produced the same firing, confirmed
independently in the TSDB (`ALERTS{alertstate="firing"}` samples via
`query_range`).

## 6. Tooling finding (recorded for operators)

PowerShell 5.1's `Invoke-RestMethod` **served stale/empty bodies for repeated
identical GETs** against Prometheus on this host — during one live-fire run it
reported `alerts:[]` for the entire 3-minute firing window in which the TSDB
recorded `ALERTS{alertstate="firing"}` continuously, while `curl` saw the
firing alert on the same port seconds later. The collector was therefore moved
to `curl.exe` (commit `4db4410`), which behaved identically across all runs,
and every evidence line now embeds the raw API body. Additionally, PS 5.1
strips embedded `"` when passing arguments to native executables — PromQL
strings are sent via `[uri]::EscapeDataString` to survive quoting.

## 7. Dashboard live (Grafana provisioning-as-code)

Via the Grafana API (admin credentials from gitignored `infra/staging/.env`,
never committed; provisioning is code — no manual UI screenshots per brief):

- `/api/search` → `uid=burhan-staging-health`,
  title **"Burhan Staging — System Health (H07)"**, tags `burhan,h07,staging`,
  inside provisioned folder **"Burhan Staging"**.
- `/api/datasources` → `uid=burhan-prom`, type prometheus,
  `url=http://prometheus:9090`, `readOnly=true`, default.
- Panels (8): worker heartbeat age by role (alert >120s), oldest outbox pending
  age (>300s), HTTP 5xx ratio 5m (>1%), confirmation depth, readiness latency
  p95 + 503 failures, case query latency p95, upload rejection rate, RPC health
  / outbox states / metrics DB up. All 14 `burhan_*` metrics referenced.
- Live datapath through Grafana's own datasource proxy
  (`/api/datasources/proxy/uid/burhan-prom/api/v1/query?...`) returned fresh
  heartbeat ages for both roles (indexer 2.9s, anchor 3.2s) — the dashboard
  reflects the same series the alert fired on, i.e. real system state.

## 8. No PII / no secrets

- Metric labels: institution ids, worker roles, delivery/status enums, route
  **templates**, HTTP codes — no user/case/evidence identifiers, no file names,
  no tokens (policy documented in the `metrics.py` header; verified against the
  actual exposition body).
- No secrets: Grafana admin credentials fail-fast from gitignored `.env`;
  neither Prometheus nor Grafana config embeds credentials; the collector reads
  credentials from `.env` at runtime and never prints them. `/internal/metrics`
  is reachable only inside the compose network (engine publishes no host port).
- The evidence log contains metric values and alert JSON only.

## 9. Not tested / limitations

- Only the heartbeat alert was live-fired (the brief's dependency-failure
  scenario). `BurhanOutboxOldestPendingStale`, `BurhanHTTP5xxRatioHigh` and
  `BurhanReadinessRepeated503` are validated by promtool unit tests replaying
  their series, not by live staging incidents.
- No Alertmanager is configured — rules fire in Prometheus (API/UI/TSDB);
  notification routing is a natural follow-up task.
- The evidence script polls at 5s granularity; the 126.3s stop→firing-observed
  figure includes one poll interval (precise threshold crossing: 121.1s).
- `burhan_readiness_latency_seconds` histogram showed `count 0` — no `/ready`
  probe hit the engine during the verification window; it populates under
  orchestration probes.
- `aml_staging_frontend` was `unhealthy` at verification time — outside H07
  scope, not investigated here.
- Grafana verified via API only (provisioning-as-code), not via a browser
  session, per the brief's no-manual-screenshots constraint.
