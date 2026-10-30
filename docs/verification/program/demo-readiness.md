# Demo readiness — Burhan AML audit-chain, full `docker compose up` demo (2026-10-30)

**Status: GREEN.** `docker compose down -v && docker compose up -d --build` from the
repository root brings up a fully working demo: EVM node healthy, all six contracts
deployed with a v3 manifest, PostgreSQL migrated and seeded with the demo tenant,
engine `ready` 200, frontend serving with a working `/api` proxy, and the CSV
import → transaction-ledger round trip proven end to end under the demo identity.

Commits that made it work (branch `main`):

| Commit | Fix |
|---|---|
| `9e7c4ad` | deployer runs `npm ci` before `npx hardhat` (anonymous `node_modules` starts empty → npx downloaded hardhat 3.x and died with HHE22); one-shot `db-migrate` (alembic) and `db-seed` (demo institution) gate the engine via `service_completed_successfully` |
| `59ba6f1` | deployer sets `LOCALHOST_RPC_URL` — `hardhat.config.js`'s `localhost` network reads that var, not `BLOCKCHAIN_RPC_URL`; without it hardhat dialed `127.0.0.1:8545` inside its own container (HH108 / ECONNREFUSED) |
| `cb0b7d2` | engine binds `./shared:/app/shared:ro` — `app/security/signing.py` walks up its own path for `shared/python/evidence_crypto.py`, which is outside the ai-engine-only build context (same as the staging engine) |
| `4397a67` | frontend healthcheck dials `127.0.0.1` — busybox wget resolves `localhost` to `::1` while nginx binds IPv4-only, so the container reported permanently unhealthy while serving fine |

## Run the demo (one step)

Prerequisites: Docker Desktop running; ports **8545 / 5432 / 8005 / 3005** free on the
host (they do not collide with the staging stack, which serves 15432/18545/18080
internally).

```bat
cd C:\Users\hussa\OneDrive\Desktop\test\iraq-aml-audit-chain
docker compose down -v
docker compose up -d --build
```

First cold run takes a few minutes (two `npm ci` runs for the hardhat toolbox, engine
image build). When `docker compose ps` shows `cyber_audit_evm`, `cyber_audit_postgres`,
`cyber_audit_ai`, `cyber_audit_frontend` **healthy** and `cyber_audit_db_migrate`,
`cyber_audit_db_seed`, `cyber_audit_deployer` **Exited (0)**, the demo is up.

- Dashboard: http://localhost:3005 (API proxied at `http://localhost:3005/api/...`)
- Engine API: http://localhost:8005

Service/port map:

| Service (compose) | Container | Host port | Expected end state |
|---|---|---|---|
| hardhat-node | cyber_audit_evm | 8545 | Up (healthy) |
| postgres | cyber_audit_postgres | 5432 | Up (healthy) |
| db-migrate (one-shot) | cyber_audit_db_migrate | — | Exited (0) — alembic `upgrade head` |
| db-seed (one-shot) | cyber_audit_db_seed | — | Exited (0) — inserts `institutions` row `INST-CENTRAL-DEMO`, idempotent |
| contract-deployer (one-shot) | cyber_audit_deployer | — | Exited (0) — 6 contracts + bootstrap + manifest v3 `[SUCCESS]` |
| ai-engine | cyber_audit_ai | 8005 → 8000 | Up (healthy), `/api/v2/health/ready` 200 |
| frontend | cyber_audit_frontend | 3005 → 3000 | Up (healthy), `/` 200, `/api/*` proxied to the engine |

## Proof transcript (canonical clean run, 2026-10-30)

Executed exactly as: `docker compose down -v && docker compose up -d --build` → **exit code 0**
(full chain: evm healthy → db-migrate Exited(0) → db-seed Exited(0) → deployer Exited(0)
→ ai-engine Healthy → frontend Started).

```
> docker compose ps --format "table {{.Name}}\t{{.Status}}"
cyber_audit_ai         Up About a minute (healthy)
cyber_audit_evm        Up 4 minutes (healthy)
cyber_audit_frontend   Up 59 seconds (healthy)
cyber_audit_postgres   Up 4 minutes (healthy)
(one-shots verified via docker inspect: migrate_exit=0 seed_exit=0 deployer_exit=0)

> docker inspect cyber_audit_db_migrate --format "{{.State.ExitCode}}"
0                                    [alembic r11_baseline → outbox_delivery, 5 revisions]

> docker logs cyber_audit_db_seed
[demo-seed] inserted institution 'INST-CENTRAL-DEMO' (dialect=postgresql).
(on later restarts: "[demo-seed] institution 'INST-CENTRAL-DEMO' already present; nothing to do.")

> docker logs cyber_audit_deployer  (tail)
====================================================
[SUCCESS] Manifest (v3) written atomically to /app/deployments/deployment-manifest.json
[SUCCESS] Exported frontend runtime config to /app/frontend/public/runtime-config.json

> docker logs cyber_audit_ai (startup)
[AI-Engine] PostgreSQL schema verified at alembic head outbox_delivery; create_all NOT called (migrations own the schema).

> curl -s -o p_ready.json -w "%{http_code}" http://localhost:8005/api/v2/health/ready
200   (errl=0)
{"status":"ready","live":true,"ready":true,"checks":{"database":true,"migrations":true,
 "kms_vault":true,"evm_rpc":true,"ml_engine":true,"policy_service":true},
 "details":{"schema_revision":"outbox_delivery","blockchain_status":"ONLINE",
 "current_block":18,"rpc_url":"http://hardhat-node:8545",
 "ml_type":"Hybrid Isolation Forest + Rule Ensemble","active_eth_policy":"IRAQ_CBI"}}

> curl -s -o NUL -w "%{http_code}" http://localhost:3005/
200   (errl=0)

> curl -s -o NUL -w "%{http_code}" http://localhost:3005/api/v2/health/ready
200   (errl=0)   ← nginx /api proxy works

> curl -s -w "%{http_code}" -F "file=@shared/fixtures/banking-iqd-demo.csv" ^
     "http://localhost:8005/api/v2/imports/transactions"
201   (errl=0)
{"import_id":"imp_fbf3bd22124241a5","institution_id":"INST-CENTRAL-DEMO",
 "filename":"banking-iqd-demo.csv","status":"COMPLETED","total_rows":10,
 "accepted_rows":10,"rejected_rows":0,"errors":[],
 "created_at":"2026-10-30T10:47:05.397190Z"}

> curl -s "http://localhost:8005/api/v2/transactions?limit=10"
200   (errl=0)   total=10 items=10 inst=INST-CENTRAL-DEMO
rows: TX-IQD-2026-0001 … TX-IQD-2026-0010 (status RECORDED, source IQD_CSV)

> curl -s "http://localhost:3005/api/v2/transactions?limit=10"
200   (errl=0)   total=10   ← same rows through the frontend proxy
```

The import→read round trip exercises the whole tenant chain at once: demo identity
dependency (`get_demo_identity`, active because `APP_MODE=demo`, `OIDC_ENABLED=false` —
both defaults in `ai-engine/app/config.py`) → `institution_id=INST-CENTRAL-DEMO` →
`tenant_transaction`/`apply_tenant_context` set `app.current_institution_id` per
transaction → PostgreSQL FORCE RLS on `transactions` passes → the FK target
(`institutions` row) was seeded by `db-seed`.

## How the traps were diagnosed (for the record)

1. **Deployer exit 1 (HHE22)** — its anonymous `node_modules` volume starts empty, so
   `npx hardhat` fetched hardhat 3.21.2 and refused the non-local install. Fix: `npm ci`
   first (root `package-lock.json` pins hardhat 2.x locally). Evidence: deployer log
   before the fix: `Deployment failed: HardhatError: HH108 … connect ECONNREFUSED
   127.0.0.1:8545` — which exposed trap (2).
2. **Deployer dialed itself** — `hardhat.config.js` `networks.localhost.url` reads
   `LOCALHOST_RPC_URL`; the compose file only set `BLOCKCHAIN_RPC_URL`. The staging
   deployer sets both; the demo now sets both too.
3. **Engine 503 on fresh volume** — R11 forbids `create_all` on PostgreSQL and the
   engine intentionally swallows its startup DB failure as a "note", leaving readiness
   at 503. Fix: `db-migrate` one-shot (same engine image,
   `MIGRATION_DATABASE_URL=postgresql+psycopg://audit_admin:audit_admin_secret@postgres:5432/cyber_audit`,
   `alembic upgrade head`) before the engine (`depends_on: service_completed_successfully`).
   `audit_admin` is the schema owner in the demo — acceptable for demo only.
4. **Missing FK target** — the engine's demo seed is confined to the SQLite dev path
   (R11). `db-seed` one-shot (`ai-engine/scripts/demo_seed.py`) inserts the
   `INST-CENTRAL-DEMO` institution row idempotently; proven idempotent across three
   restarts (second/third runs log "already present").
5. **Engine crash at import** — `signing.py` requires `shared/python/evidence_crypto.py`
   found by walking up from its own file; not inside the ai-engine build context. Fix:
   read-only bind mount exactly like the staging engine.
6. **Frontend permanently "unhealthy"** — container-level healthcheck used
   `wget http://localhost:3000/`; inside the container `localhost` resolves to `::1`
   first and nginx binds IPv4-only, so the check failed while the site served fine
   (`wget 127.0.0.1` OK, `wget localhost` FAIL verified via `docker exec`). Fix:
   `127.0.0.1` in `frontend/Dockerfile` healthcheck.

## Moving to institutional mode later (pointer, not execution)

The demo stack stays the defaults-driven demo path (`APP_MODE=demo`,
`OIDC_ENABLED=false`, `INSTITUTION_ID=INST-CENTRAL-DEMO`, demo tenant seeded,
no auth header required). The institutional path is the **staging** stack:
`infra/staging/docker-compose.staging.yml` (Keycloak OIDC, vault/KMS, indexer/anchor
workers, dedicated migration role, RLS-enforced app role) — see
`docs/verification/program/staging-h04.md` / `staging-h05.md` for its proven runbooks.
Nothing in the demo changes institutional behavior: `APP_MODE=institutional` requires
`OIDC_ENABLED=true` (hard startup gate in `app/config.py`), the demo identity
dependency answers 401, and PostgreSQL schema/seed management stays with the
migration/owner role workflow, never `create_all` (R11).

## Not tested / known caveats

- `npm run demo:simulate` (`scripts/simulate-fraud-case.js`) not run: the file is an
  untracked user file (protected — never staged or modified), and the chain-state
  mutation would happen after the recorded proof. It is optional per the demo brief.
- `GEMINI_API_KEY` unset in the demo: engine runs local-only ML (readiness is not
  dependent on it; `/api/v2/health/ready` proves `ml_engine: true` with the local
  hybrid model).
- The demo PostgreSQL volume is intentionally wiped by `docker compose down -v`; the
  demo re-migrates and re-seeds on every `up` (fast; one-shot containers are cached by
  compose state on plain `docker compose up` restarts).
- Frontend asset build warns about a >500 kB chunk (pre-existing vite warning,
  cosmetic; build succeeds).


## التشغيل عبر GitHub Actions

Action يدوي: **Demo Stack Smoke (manual)** في تبويب Actions → Run workflow — يبني الديمو من checkout نظيف، يشغل السلسلة كاملة (نشر+مهاجرة+بذر)، ويتحقق: ready عبر المنفذين + استيراد CSV 201 + صفوف مرئية، ويرفع الأدلة كـartifact. العدّاء مؤقت — لتصفح الواجهة من متصفحك: شغلها محلياً (`docker compose up -d`) أو استخدم self-hosted runner.

## DEMO badge (H14, runtime-driven)

The frontend shows a slim amber banner — `DEMO — نسخة تجريبية (بيانات وشبكة محلية)` —
fixed to the very top of the viewport whenever the **served** `/runtime-config.json`
has `app_mode: "demo"` (the badge reads `isDemoMode()` from the R13 runtime module on
every render — not a build-time constant). The shell reserves the banner's 24px strip
(root `pt-6`, sticky header `top-6`), the banner is `pointer-events-none`, so nothing
underneath is covered or blocked. In `app_mode: "institutional"` deployments the badge
renders **nothing**, and nothing renders before the config gate resolves the config.
Flipping a deployment between demo and institutional (new `runtime-config.json` +
reload) flips the badge with it — component: `frontend/src/components/DemoBadge.jsx`
(wired in `App.jsx`); tests: `DemoBadge.test.jsx` (not-loaded / demo / institutional /
reload-flip).
