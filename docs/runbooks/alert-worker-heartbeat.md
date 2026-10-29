# Runbook: BurhanWorkerHeartbeatStale — worker heartbeat stale >120s

**Alert:** `BurhanWorkerHeartbeatStale` — `burhan_worker_heartbeat_age_seconds > 120` (fires immediately on threshold crossing).
**Severity:** critical. **Owner:** Operations (H07). **Source of truth:** `worker_heartbeats` table (R08) — every worker writes a heartbeat row per 5s cycle (`WORKER_POLL_INTERVAL_SECONDS`, `ai-engine/app/workers/runner.py`).

## Meaning

The freshest heartbeat row for worker role `{{ $labels.role }}` in institution
`{{ $labels.institution }}` is older than 120 seconds. Staging workers are
`anchor` and `indexer` (`aml_staging_worker_anchor`, `aml_staging_worker_indexer`).
Because the age grows from a FROZEN row, this means the worker process stopped
writing heartbeats — typically the container is stopped or crash-looping.

## First response (5 minutes)

1. Confirm the worker container state:
   `docker ps -a --filter name=aml_staging_worker_ --format "{{.Names}} {{.Status}}"`
2. If stopped: find out why BEFORE restarting —
   `docker logs --tail 200 aml_staging_worker_anchor` (or `_indexer`).
   An `exit 0` after SIGTERM means someone stopped it; a traceback means a crash.
3. Restart only after capture: `docker start aml_staging_worker_anchor`.
   Heartbeats resume within one 5s cycle; the alert resolves itself.
4. If the container is UP but the alert stays firing, check the shared
   dependencies: PostgreSQL (`docker logs aml_staging_postgres`) and the EVM
   node (an anchor worker cycle that cannot reach the chain still heartbeats;
   a worker stuck before the heartbeat write does not).

## Escalation

- Alert firing >15 minutes with no operator action: treat the anchoring
  pipeline as stalled — outbox events accumulate (watch
  `BurhanOutboxOldestPendingStale`, which fires at 300s).
- The engine's own metrics read (`burhan_metrics_db_up`) also firing means the
  DB, not the worker, is the problem — go to the PostgreSQL runbook instead.

## Verification after recovery

- `burhan_worker_heartbeat_age_seconds{role="anchor"}` drops below ~15s.
- Alert shows green on the Prometheus alerts page
  (`http://127.0.0.1:19090/alerts`).
