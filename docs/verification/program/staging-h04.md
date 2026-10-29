# H04 — PostgreSQL حقيقي وبيئة staging (DG2) — Closure Record

> Task H04 of the 2026-10-29 development program. Branch `main`, base `a1434f3`.
> Everything below was executed on 2026-10-29 against the live staging stack.
> Working shell: Windows cmd; Python via `node scripts/run-python.js`.

## 1. What was built (committed)

| Commit | Subject |
|---|---|
| `f89b23c` | feat(staging): H04 staging compose stack — PostgreSQL 16, institutional engine, anchor/indexer workers, EVM, nginx (loopback-only host ports) |
| `c3c5765` | feat(engine): startup log proves the schema path — PG verifies alembic head (never create_all), SQLite-only create_all labeled explicitly |
| `b0356f4` | feat(hardhat): localhost network honors LOCALHOST_RPC_URL for staging retargeting |
| `73a30c0` | fix(frontend): complete package-lock with missing @noble/hashes@2.4.0 nodes (jsdom 30 family) |
| `84d98db` | fix(staging): EVM healthcheck probes 127.0.0.1 (musl localhost resolves to ::1; hardhat binds IPv4-only) |
| `2b86033` | fix(staging): mount repo shared/ read-only into engine+workers |
| `7d1331a` + `a9bf2aa` + `3e8d56e` | fix(engine): indexer worker writes under transaction-local tenant context (FORCE RLS on PostgreSQL) + regression test |
| `dfb183d` | feat(staging): in-cluster alembic migration + institution registry seed one-shots |
| `138bd14` | fix(staging): institution seed supplies created_at (ORM-side default, no server default) |
| `14fc065` | fix(engine): add verification_snapshots to RLS_TABLES enumeration (r07 migration tenant table) |
| `7677d31` | fix(engine): v2 read-model routes apply transaction-local tenant context (FORCE RLS on PostgreSQL) |
| `fb0da93` | fix(staging): disable image-level HTTP healthcheck on workers |

Files: `infra/staging/docker-compose.staging.yml`, `infra/staging/.env.example`,
`infra/staging/runtime-config.staging.json`, `ops/postgres/staging-init.sql`,
`ops/postgres/staging-init.sh`, `.env.example` (new, no secrets), engine fixes
under `ai-engine/app/**`, regression tests
`ai-engine/tests/integration/test_indexer_postgres_rls.py` and
`ai-engine/tests/integration/test_transactions_read_rls.py`.
`ops/postgres/init-roles.sql` (R11) is REUSED VERBATIM — never rewritten.

The demo `docker-compose.yml` and every protected user file are untouched.

## 2. Service / port map (live stack, left UP)

| Service | Container | Internal port | Host port | Notes |
|---|---|---|---|---|
| postgres | aml_staging_postgres | 5432 | 127.0.0.1:15432 (loopback only) | postgres:16-alpine; DB `iraq_aml_staging`; roles `ira_aml_migrator` (owner) / `ira_aml_app` (NOSUPERUSER NOBYPASSRLS) via init-roles.sql + staging-init |
| hardhat-node | aml_staging_evm | 8545 | 127.0.0.1:18545 (loopback only) | node:20-alpine, repo bind-mount, named volume node_modules |
| contract-deployer | aml_staging_deployer | — | — | one-shot; writes deployments/deployment-manifest.json (tracked file — see §7) |
| anchor-funder | aml_staging_anchor_funder | — | — | one-shot; funds the gitignored anchor signer key from Hardhat account #0 |
| db-migrate | aml_staging_db_migrate | — | — | one-shot; `python -m alembic upgrade head` as ira_aml_migrator |
| db-seed-institutions | aml_staging_db_seed | — | — | one-shot; INSERT institution registry row as the registry owner |
| ai-engine | aml_staging_engine | 8000 | none | APP_MODE=institutional; DATABASE_URL = ira_aml_app role |
| worker-anchor | aml_staging_worker_anchor | — | none | `python -m app.workers.runner anchor` |
| worker-indexer | aml_staging_worker_indexer | — | none | `python -m app.workers.runner indexer` |
| frontend | aml_staging_frontend | 3000 (nginx) | 127.0.0.1:18080 | only host-facing interface; proxies /api/ → ai-engine:8000 |

No port is published on 0.0.0.0; the two loopback bindings (15432 PG, 18545
EVM) exist because the RLS suite and the E2E runner execute on the host.

Stack start (documented contract):

```
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml up -d --build
```

All credentials interpolate from `infra/staging/.env` (gitignored; template
`infra/staging/.env.example`). Missing values fail the compose run (`:?`).
Secrets never appear in any committed file.

## 3. Alembic on a fresh, empty staging DB

`alembic heads` (host, ai-engine/): `outbox_delivery (head)`
(the brief's assumed head `r06_evidence_crypto` is mid-chain — the real single
head at execution time is `outbox_delivery`; conventions verified: one head,
unique slugs, chained down_revisions).

```
node <launcher> mig -m alembic upgrade head        (cwd ai-engine, MIGRATION_DATABASE_URL = ira_aml_migrator role)
```

Output: `Running upgrade -> r11_baseline ... institutional_wallet_challenges
... r06_evidence_crypto ... r07_verification_snapshots ... outbox_delivery` —
**exit 0**. In-cluster equivalent: `db-migrate` one-shot service, **exit 0**.

The full RLS suite's migration-conventions test also ran `upgrade head` against
fresh `r11_empty` (created + provisioned with init-roles.sql by the operator),
plus stamp-if-matches accept/refuse on `r11_existing` / `r11_unknown` — all
green inside `test_postgres_rls.py` (§5).

## 4. create_all proof (institutional mode)

Negative proof — engine one-off against the UNMIGRATED `r11_empty` database:

```
docker run --rm --network iraq-aml-staging_default -e DATABASE_URL=postgresql+psycopg://ira_aml_app:***@postgres:5432/r11_empty \
  iraq-aml/staging-engine:h04 python -c "from app.db.session import init_db; init_db(); print('UNEXPECTED')"
```

**exit 1** with `RuntimeError: Database schema is not migrated: alembic_version
is unreadable ...` — the institutional/PostgreSQL startup path refuses an
unmigrated database instead of creating anything; `r11_empty` verified 0 tables
in public afterwards (create_all would have "succeeded" silently).

Positive proof — engine startup log on the migrated staging DB (commit c3c5765
makes the path explicit):

```
[AI-Engine] PostgreSQL schema verified at alembic head outbox_delivery; create_all NOT called (migrations own the schema).
```

Also: `git grep -n create_all ai-engine/app` → the only call site is the
SQLite dev/demo branch in `app/db/session.py:init_db`.

## 5. RLS suite against staging PostgreSQL

Pre-provisioning (superuser, once): created `r11_empty`, `r11_existing`,
`r11_unknown` and applied `ops/postgres/init-roles.sql` to each (the suite's
migration-conventions test needs those databases to exist with the migrator as
owner — they are disposable test fixtures).

```
DATABASE_URL=postgresql://ira_aml_app:***@127.0.0.1:15432/iraq_aml_staging
MIGRATION_DATABASE_URL=postgresql://ira_aml_migrator:***@127.0.0.1:15432/iraq_aml_staging
node scripts/run-python.js -m pytest -q ai-engine/tests/integration/test_postgres_rls.py -v
```

Result history:

| Run | Result |
|---|---|
| 1st (as-found) | 1 failed, 10 passed — `test_force_rls_and_policies_on_all_institutional_tables`: `Extra items in the left set: verification_snapshots` |
| after `14fc065` (fix) | **11 passed** |

The finding: the r07 migration creates `verification_snapshots` with
ENABLE+FORCE RLS + `tenant_isolation_policy`, but the models-side
`RLS_TABLES` enumeration was never extended (the table has no ORM model — it is
consumed via raw SQL in `services/evidence_verifier.py`). Fixed by adding it to
`RLS_TABLES` (PG is the reference; the enumeration is the contract).

Final combined battery on staging PG (same env contract):
`test_postgres_rls.py + test_indexer_postgres_rls.py + test_transactions_read_rls.py`
→ **14 passed**.

## 6. SQLite↔PostgreSQL differences found — all FIXED with regression tests

Each fix committed separately; PG behavior is the reference; every regression
test was proven RED without the fix (via targeted stash) and GREEN with it.

1. **Indexer worker wrote with no tenant context (live failure).**
   Observed on the staging stack: anchor heartbeat failed with FK violation
   (`worker_heartbeats_institution_id_fkey` — institution row not yet seeded),
   indexer checkpoint INSERT failed with `new row violates row-level security
   policy` (checkpoints). Root cause: `run_indexer_step` /
   `record_heartbeat` never set `app.current_institution_id`; on SQLite there
   is no RLS so the logic suite was green. Fix: new
   `app/db/session.py:apply_tenant_context` (re-usable
   `set_config(..., is_local => true)`); indexer applies it at step start and
   in `record_heartbeat` (the runner calls the latter after the step's internal
   COMMIT, which evaporates transaction-local settings). Regression:
   `test_indexer_postgres_rls.py` (RED reproduced: exact RLS ProgrammingError).
   Live verification after fix: both workers write heartbeats + the indexer
   advances its checkpoint on the staging EVM.

2. **v2 read-model GET routes read with no tenant context (live E2E failure).**
   E2E trust-flow test 1.5 failed on staging: CSV import 201 (the write path
   already used tenant_transaction) but `GET /api/v2/transactions` returned 0
   rows under FORCE RLS. Survey of ALL v2/v3 routes found the same defect in
   reports (list/get/export), risk (preview, assessments) and evidence
   (metadata, download). cases + v3-evidence were already context-correct.
   Fix: `apply_tenant_context(db, identity.institution_id)` at route start
   (request-scoped session closes with rollback in get_db — nothing leaks).
   Regression: `test_transactions_read_rls.py` — full HTTP chain on real PG
   (import 201 + list ≥ 10 + foreign tenant reads 0); RED without fix.

3. **RLS_TABLES enumeration stale vs migrations** — see §5 (`14fc065`).

Operational (non-engine) differences/gaps found and fixed on the way:

4. `frontend/package-lock.json` was missing three nested
   `@noble/hashes@2.4.0` nodes (jsdom 30 family): `npm ci` on npm 10 (the
   node:20-alpine build) failed `Missing: @noble/hashes@2.4.0 from lock file`
   while npm 11 (host) tolerated the gap. Regenerated with npm 10 inside
   `node:20-alpine`; `npm ci --dry-run` exit 0 in the image environment;
   no version drift (ethers stays 6.17.0). (`73a30c0`)
5. EVM healthcheck: `nc -z localhost 8545` fails in node:20-alpine because
   musl resolves `localhost` to `::1` while hardhat binds IPv4-only — the demo
   compose carries the same latent bug. Staging probes `127.0.0.1`. (`84d98db`)
6. The engine image (build context `ai-engine/`) cannot contain
   `shared/python/evidence_crypto.py` (resolved by walking ancestors from
   `app/security/signing.py`) — staging mounts the repo `shared/` read-only.
   The demo compose has the same latent gap (untouched — out of H04 scope).
   (`2b86033`)
7. `institutions.created_at` has an ORM-side default only (no server default):
   raw-seed INSERT must supply `created_at` explicitly (`138bd14`).
8. Persistent staging DB vs disposable-DB assumptions: re-importing the same
   CSV fixture is correctly rejected as duplicate `external_id`s (connector
   behavior). The documented pre-run step for a staging E2E rerun is to clear
   the E2E tenant's `transactions`/`import_batches` (performed before the
   final green run). Not a bug — the SQLite runner wipes its DB each run.
9. Workers inherit the engine image's HTTP healthcheck but serve no HTTP —
   compose disables it (`fb0da93`); cosmetic `unhealthy` state removed.

## 7. Engine / workers / frontend health validation (all exit codes recorded)

* `GET http://127.0.0.1:18080/api/v2/health/ready` through nginx → **200**,
  `{"status":"ready", checks: database/migrations/kms_vault/evm_rpc/ml_engine/
  policy_service all true, schema_revision: "outbox_delivery",
  blockchain_status: "ONLINE", current_block: 133, active_eth_policy: "IRAQ_CBI"}`.
* `GET /runtime-config.json` through nginx → **200** (staging institutional
  config mounted over the built one; tracked `frontend/public/runtime-config.json`
  never modified — generated copies restored at the end, see §9).
* Institutional posture: `GET /api/v2/cases` without a token → **401**
  `{"detail":"Missing Authorization Bearer token"}` — the demo identity path is
  unreachable in institutional mode, as designed (R10).
* Worker heartbeats (SQL, app-role-written rows):
  `anchor_8f783f08 / anchor` and `indexer_INST-CENTRAL-STAGING / indexer` rows
  refresh every cycle in `worker_heartbeats`; `checkpoints` row advances
  (last_canonical_block tracked to block 133 on chain 31337).
* `docker ps` final state: postgres healthy, evm healthy, engine healthy,
  frontend healthy, workers up (no healthcheck by design).

## 8. E2E validation — exactly what was and was not covered

The brief's honesty rule was applied as follows. `scripts/run-integration.js`
spawns its OWN hardhat + engine; with `DATABASE_URL` env it can point that
engine at an arbitrary database. Two runs:

**(a) Staging-mode E2E (the real one):** full `trust-flow.spec.js` suite with
the spawned engine connected to the STAGING PostgreSQL as the least-privilege
`ira_aml_app` role (RLS enforced), against the STAGING EVM
(`RPC_PORT=18545`, `LOCALHOST_RPC_URL=http://127.0.0.1:18545`, `API_PORT=18000`):

```
LOCALHOST_RPC_URL=http://127.0.0.1:18545 RPC_PORT=18545 API_PORT=18000 \
DATABASE_URL=postgresql://ira_aml_app:***@127.0.0.1:15432/iraq_aml_staging \
INSTITUTION_ID=INST-CENTRAL-DEMO node scripts/run-integration.js
```

→ **8 passed (2.6s), RUNNER-EXIT=0.** (First run: 7 passed / 1 failed — test
1.5 — which exposed finding §6.2; after the fix + documented ledger clear: 8/8.)
This run exercised the production chain end-to-end ON PostgreSQL: contracts on
the staging EVM, HTTP API with the app role under RLS, CSV ingestion + read
model, evidence crypto + verification, MultiSig governance lifecycle.

**(b) Standard E2E as-is (regression):** `npm run verify:integration`
unmodified (runner-spawned SQLite engine) → **8 passed, Integration Test
Result: PASSED (0), RUNNER-EXIT=0** — no regression on the existing path.

**Not validated (honest limits):**

* **Authenticated API/UI flows against the institutional engine.** In
  institutional mode every protected endpoint requires an OIDC bearer token;
  the E2E suite sends none (it targets the demo identity path). Validating
  token-bearing flows requires the REAL provider — H05's deliverable. The OIDC
  configuration in staging is a DECLARED HONEST PLACEHOLDER
  (`OIDC_ENABLED=true`, issuer/JWKS = non-resolvable
  `keycloak.staging.iraq-aml.invalid` hostname): the R10 startup gate is
  satisfied and the demo path is provably closed (401 above), but NO fake
  provider was stood up and no token was minted or verified in staging.
  H05 replaces the placeholder with Keycloak and re-runs the E2E in
  institutional mode with tokens.
* **Browser UI login in institutional mode** — frontend runtime config is
  schema-valid (institutional + oidc block, redirect_uri
  `http://127.0.0.1:18080/auth/callback`) but login cannot complete before H05.
* **On-chain anchoring of outbox items through the worker loop** — the anchor
  signer is funded and cycles run (heartbeats recorded), but no outbox items
  were produced for `INST-CENTRAL-STAGING` during validation (evidence was
  submitted under the E2E demo institution), so no live anchor transaction was
  observed. Unit/integration coverage for anchoring exists in the SQLite suites;
  a staging anchor round-trip remains open until an institutional tenant
  submits evidence (post-H05 flow).
* **Wallet-binding / RoleManager paths in the engine** (on-chain authorization
  reads) — unresolved binding answers 503 by design; not exercised.

## 9. Generated-file hygiene

The staging/E2E deploys regenerate two TRACKED files in the working tree:
`deployments/deployment-manifest.json` and `frontend/public/runtime-config.json`
(the deployer owns them; they describe the CURRENT deployment). They were
restored with `git restore` at the end of validation — the running containers
hold the manifest in memory, and any full `down && up` re-runs the deployer
which regenerates both files. The working tree is clean; nothing generated was
committed. Root `package-lock.json` (npm side-effect) also restored.

## 10. Acceptance criteria vs reality

| Brief acceptance | Status |
|---|---|
| `docker compose -f infra/staging/docker-compose.staging.yml up` brings up a fully ready environment | DONE — single command, self-sufficient (postgres → init-roles → deployer → funder → migrate → seed → engine/workers → nginx); readiness 200 via nginx |
| Full E2E green on staging with PostgreSQL and a limited application role (no superuser) | DONE — 8/8, engine + workers connected ONLY as `ira_aml_app` (NOSUPERUSER NOBYPASSRLS, verified by the RLS suite's role-hygiene test on this very database) |
| H04 doc with commands, exit codes, differences found + fixed, service/port map, limits of what was not tested | THIS document |
