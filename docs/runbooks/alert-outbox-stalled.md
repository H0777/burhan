# Runbook: BurhanOutboxOldestPendingStale — oldest outbox event pending >300s

**Alert:** `BurhanOutboxOldestPendingStale` — `burhan_outbox_oldest_pending_age_seconds > 300` (fires immediately on threshold crossing).
**Severity:** critical. **Owner:** Operations (H07). **Source of truth:** `outbox` table, oldest row in `PENDING`/`PROCESSING` (R08 delivery pipeline the anchor worker drains; the 300s window matches the R08 lease/retry semantics).

## Meaning

An outbox event (evidence/case anchoring intent) has waited more than 300
seconds without leaving the delivery pipeline. The anchor worker normally
claims, signs and broadcasts within seconds. Causes, most likely first:

1. **Anchor worker down** — usually preceded by `BurhanWorkerHeartbeatStale`.
2. **Lease stuck** — a worker died mid-claim; the lease expires
   (`lease_expires_at`) and the item is reclaimed on a later cycle. Transient
   by design; fires only if reclaims keep failing.
3. **Chain submission failures** — EVM RPC down, anchor signer out of gas, or
   nonce stalls. Check `burhan_rpc_errors_total` and `docker logs aml_staging_evm`.
4. **Backoff exhaustion** — repeated `attempts` growth with `last_error` set.

## First response (10 minutes)

1. Check the worker heartbeat alert first; if it is also firing, follow
   `alert-worker-heartbeat.md`.
2. Inspect the stuck items (tenant-scoped read):
   `SELECT id, event_type, status, attempts, lease_owner, lease_expires_at, next_attempt_at, left(last_error,200) FROM outbox WHERE status IN ('PENDING','PROCESSING') ORDER BY created_at LIMIT 10;`
   (run as the app role with the tenant context set, e.g. via the engine's
   connection, or read-only as the migrator role).
3. If EVM RPC is failing: `docker ps` the `aml_staging_evm` container and check
   `burhan_rpc_probe_success` / `burhan_evm_block_number` on the dashboard.
4. If the signer is out of gas: re-run the anchor-funder one-shot from the
   staging compose (H04), then watch the pipeline drain.

## NEVER do

- Do NOT hand-edit outbox rows or lease columns from psql — every state
  transition is a conditional update guarded by `lease_token` (R08); manual
  writes can orphan a signed submission.
- Do NOT restart the EVM node to "fix" it: the Hardhat chain state is
  in-memory; stopping it loses the anchored history (submissions reference
  real tx hashes).

## Verification after recovery

- `burhan_outbox_oldest_pending_age_seconds` drops toward 0 (or the gauge
  reads 0 with an empty pipeline).
- `burhan_outbox_events{status="COMPLETED"|"SUBMITTED"}` grows;
  `PENDING` drains.
