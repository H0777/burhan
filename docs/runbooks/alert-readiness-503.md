# Runbook: BurhanReadinessRepeated503 — readiness 503 three or more times in 5m

**Alert:** `BurhanReadinessRepeated503` — `increase(burhan_readiness_failures_total[5m]) >= 3` (fires immediately).
**Severity:** critical. **Owner:** Operations (H07). **Source of truth:** `burhan_readiness_failures_total` — incremented by the engine middleware whenever `/health/ready` (or `/startup`) answers 503. This is a READ-ONLY mirror of R15 honest readiness: the metrics path never changes what `/ready` checks.

## Meaning

The engine repeatedly reports itself NOT ready. `/ready` verifies, in order:
database connectivity, migration head, KMS/vault writability, EVM RPC
responsiveness, ML engine, active policy. Every 503 response body names the
failing subsystems explicitly.

## First response (10 minutes)

1. Reproduce once and READ the reasons (they are explicit):
   `curl -s http://127.0.0.1:18080/api/v2/health/ready | python -m json.tool`
   (or directly against the engine network: probe from inside the stack).
2. Map the failing check:
   - `database` / `migrations` → PostgreSQL down or schema drift: check
     `aml_staging_postgres`, then the migrations runbook. Do NOT re-run
     alembic casually — verify the head mismatch first.
   - `kms_vault` → evidence vault path or KMS provider: with H06's KMS
     override, `aml_staging_vault` being down fails this check (fail-closed
     by design).
   - `evm_rpc` → `aml_staging_evm` unreachable. NOTE: do NOT restart the
     Hardhat node — in-memory chain state is lost.
   - `ml_engine` / `policy_service` → engine-internal; read
     `docker logs aml_staging_engine --tail 200`.
3. Fix the SUBSYSTEM, never the readiness endpoint. `/ready` is honest by
   construction (R15); suppressing the alert instead of fixing the dependency
   is a process violation.

## Note on the 120s+ alert storms

If PostgreSQL is down, BOTH this alert and `BurhanWorkerHeartbeatStale` fire
(the metrics route cannot read heartbeats; `burhan_metrics_db_up` drops to 0).
Treat the DB as the root cause and clear the worker alert after DB recovery.

## Verification after recovery

- `/health/ready` returns 200 with `status: "ready"`.
- `burhan_readiness_failures_total` stops increasing; alert resolves.
