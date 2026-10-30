# Staging Verification — H05 مزود OIDC إنتاجي حقيقي (DG2)

> Keycloak 26 (realm `burhan`) كـ provisioning-as-code داخل تكوين staging، والمحرك
> موصول بالمزود الحقيقي عبر discovery/JWKS/RS256/audience/claims (عقد R10 §8).
> التاريخ: 2026-10-30. الفرع: main (ce4ee5d → 8c9dc68). البيئة: Windows cmd.

## 1. What was delivered

- **Provider as code** — `infra/staging/docker-compose.staging.yml` service `keycloak`
  (quay.io/keycloak/keycloak:26.0, `start-dev --import-realm`), realm imported from
  `infra/staging/keycloak/realm-burhan.json`; host-facing on **loopback 18081 only**;
  browser-facing issuer `http://127.0.0.1:18081/realms/burhan` (Keycloak derives `iss`
  from the request Host, so tokens carry exactly the issuer the engine verifies);
  the engine fetches JWKS **service-to-service** (`http://keycloak:8080/...`, issuer-independent).
- **Idempotent operator/membership one-shot** — `keycloak-provision-operator` (committed in
  df0356e): Keycloak user + ACTIVE membership row (OWNER role, transaction-local tenant
  context), deactivates stale rows after a Keycloak volume wipe.
- **Realm tuning (30464a6)** — audience mapper config key fixed to `included.custom.audience`
  (the old `included-client-audience` key is silently ignored by Keycloak's Audience mapper,
  so `aud` was missing), hardcoded `nbf` (R10 mandatory claim Keycloak omits) and hardcoded
  `institution_id` staging tenant claim.
- **Engine wiring (30464a6)** — `CHAIN_ID: 31337` (SIWE wallet challenge must bind the
  actually-deployed chain id; engine default 1337 rejects every binding) and
  `ROLE_MANAGER_ADDRESS` (wallet bind fails closed without the on-chain reader).
- **API-level E2E (385aeba + 8c9dc68)** — `tests/integration/test_oidc_provider_staging.py`,
  real HTTP only, NO mocks, provider fixture stays confined to ai-engine tests.
- **Real-browser E2E (f8a860f)** — `tests/e2e/oidc-staging.spec.js`, actual Chromium through
  the nginx origin: R13 gate → PKCE S256 redirect → real Keycloak form login → callback →
  SPA completes the exchange → identity/me with a real Bearer JWT → console renders.
- **R13 callback race fix (133e09a + regression test)** — required for any real browser
  login; disclosed in section 6.

## 2. Commands and exit codes (staging, Windows cmd)

Stack was brought up post-reboot with:
```
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml up -d --build
```

```text
curl -s -o nul -w "%{http_code}" http://127.0.0.1:18080/api/v2/health/ready
  → 200            (exit 0)

curl -s http://127.0.0.1:18081/realms/burhan/.well-known/openid-configuration
  → 200, "issuer":"http://127.0.0.1:18081/realms/burhan",
        "jwks_uri":"http://127.0.0.1:18081/realms/burhan/protocol/openid-connect/certs",
        "code_challenge_methods_supported":["plain","S256"]     (exit 0)

set STAGING_OIDC_USER_PASSWORD=<gitignored infra/staging/.env>
set MIGRATION_DATABASE_URL=postgresql://ira_aml_migrator:<gitignored>@127.0.0.1:15432/iraq_aml_staging
node scripts\run-python.js -m pytest -q tests/integration/test_oidc_provider_staging.py
  → 7 passed in 1.23s          (exit 0)

npx playwright test tests/e2e/oidc-staging.spec.js --reporter=list
  → 1 passed (1.5s)            (exit 0)

cd frontend && npm test
  → 9 files, 67 tests passed   (exit 0)

npm run verify:integration
  → 8 passed ... "Integration Test Result: PASSED (0)"    (exit 0)
```

Both suites skip cleanly (exit 0, no failures) when the gitignored operator env is absent.

## 3. Provider discovery / JWKS evidence (through the REAL Keycloak)

```text
GET http://127.0.0.1:18081/realms/burhan/.well-known/openid-configuration → 200
  issuer            = http://127.0.0.1:18081/realms/burhan   (exact OIDC_ISSUER match)
  authorization_endpoint / token_endpoint / userinfo_endpoint / revocation_endpoint served
  code_challenge_methods_supported includes S256

GET http://127.0.0.1:18081/realms/burhan/protocol/openid-connect/certs → 200
  key 1: kid I2_FrEqcrvIvdoJ2…  RSA  RSA-OAEP  enc  2048-bit
  key 2: kid XBepQ2U-Z28P-Exy…  RSA  RS256     sig  2048-bit   ← signs the realm's tokens
```

Engine-side wiring (docker inspect aml_staging_engine):
```text
APP_MODE=institutional  OIDC_ENABLED=true
OIDC_ISSUER=http://127.0.0.1:18081/realms/burhan          (browser-facing, exact iss)
OIDC_JWKS_URL=http://keycloak:8080/realms/burhan/protocol/openid-connect/certs  (svc-to-svc)
OIDC_AUDIENCE=iraq-aml-audit-engine
ROLE_MANAGER_ADDRESS=0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
CHAIN_ID=31337
```

Engine proof that verification actually runs against the live JWKS: a token whose
signature byte was flipped gets **401** (`test_tampered_token_is_401_not_503` — signature
verification engaged, never 503), while the untouched token gets **200** — both through
nginx. Engine request log (docker logs aml_staging_engine), one suite run:

```text
GET  /api/v2/identity/me   200 OK          ← real token, verified against live JWKS
GET  /api/v2/identity/me   401 Unauthorized ← no token
GET  /api/v2/identity/me   401 Unauthorized ← tampered signature
POST /api/v2/wallet/challenge 200 OK
POST /api/v2/wallet/verify    200 OK         ← on-chain RoleManager participant proof
GET  /api/v2/identity/me   200 OK          ← participant_id + authorization_generation
GET  /api/v2/identity/me   403 Forbidden   ← SAME live token, membership deactivated
GET  /api/v2/identity/me   200 OK          ← membership restored
```

Provisioner idempotency (docker logs aml_staging_keycloak_provisioner — three runs):
```text
run 1: membership created: role=OPERATOR active=true ; done: sub=e01bad3d-…
run 2: membership created (new sub after Keycloak volume wipe) ; deactivated 1 stale row ; done: sub=6908b353-…
run 3: membership re-activated (idempotent re-run) ; done: sub=6908b353-…  (SAME sub)
```

## 4. Application registration at the provider (runbook facts)

Realm `burhan` (`infra/staging/keycloak/realm-burhan.json`, provisioning-as-code; contains
no users and no secrets — admin/operator credentials live in gitignored `infra/staging/.env`):

| Setting | Value |
|---|---|
| Realm | `burhan` (issuer `http://127.0.0.1:18081/realms/burhan`) |
| Client | `iraq-aml-frontend` — **public**, Authorization Code + PKCE **only** |
| Flow toggles | standardFlow ✓, implicit ✗, directAccessGrants (password grant) ✗, serviceAccounts ✗ |
| PKCE | enforced: attribute `pkce.code.challenge.method = S256` |
| redirect_uri | `http://127.0.0.1:18080/auth/callback` (single registered redirect) |
| webOrigins | `http://127.0.0.1:18080` |
| Scopes requested by the frontend | `openid profile email` |
| Audience | `iraq-aml-audit-engine` injected into the access token by an audience mapper |
| Mandatory claims | `nbf` (R10) via hardcoded-claim mapper (long), `institution_id = INST-CENTRAL-STAGING` (id/access/userinfo) |
| Token policy | access token lifespan 900s, refresh token revoked on reuse (`refreshTokenMaxReuse=0`) |
| Lockout | brute-force protection enabled (temporary, not permanent) |
| Admin | bootstrap admin via `STAGING_KEYCLOAK_ADMIN_USERNAME/PASSWORD` (gitignored env) |

Browser-observed authorization request (asserted live in the Playwright E2E):
`client_id=iraq-aml-frontend`, `response_type=code`, `code_challenge_method=S256`,
`code_challenge` present, `redirect_uri=http://127.0.0.1:18080/auth/callback`,
`scope=openid profile email`, `state` present.

## 5. Full-cycle test matrix (real provider, no mocks)

| # | Test | Level | Result |
|---|---|---|---|
| 1 | discovery serves the real provider (issuer, S256, RSA-RS256-sig key) | API | PASS |
| 2 | full PKCE Authorization Code login through the real Keycloak form (hidden-field POST, state CSRF check, code+verifier exchange), token verified against the LIVE JWKS (RS256 allowlist, iss/aud/exp/iat/nbf/sub, 60s skew), `institution_id` claim | API | PASS |
| 3 | identity/me through nginx with the real token (sub/issuer/institution/role) | API | PASS |
| 4 | no token → 401 through nginx | API | PASS |
| 5 | tampered-signature token → 401 (not 503) | API | PASS |
| 6 | SIWE wallet challenge → EIP-191 signature → bind with on-chain RoleManager participant proof → identity carries participant_id + authorization_generation | API | PASS |
| 7 | **revocation**: membership deactivated in DB → the SAME live token gets **403** on the very next request → restored → 200 again (R10 per-request membership semantics through the REAL provider) | API | PASS |
| 8 | real-browser login: gate → PKCE S256 → Keycloak form → callback → exchange → identity/me (Bearer JWT) → console renders; oidc-client-ts session store populated | **browser** | PASS |
| 9 | frontend vitest suite (incl. the new single-use-callback regression) | unit | 67/67 PASS |
| 10 | `npm run verify:integration` regression (trust-flow) | e2e | **8/8 PASS** |

## 6. Honest disclosures (bugs found/fixed and limits)

1. **R13 browser callback race (fixed, 133e09a).** The H05 browser E2E exposed that
   `OidcCallbackHandler` re-ran its effect mid-callback (App re-renders when `isLoading`
   flips recreate the inline `onDone` prop → deps change): two concurrent token exchanges
   for one login — Keycloak answered the loser `invalid_grant: Code not valid` (its log:
   `CODE_TO_TOKEN_ERROR ... error="invalid_code"`) while the winner's completion was
   swallowed by its own cleanup. Every real browser login landed on the error screen;
   the unit suite never saw it because `completeLogin` is mocked there. Fix: run-once ref
   guard, completion no longer gated on effect-scoped `isMounted`; vitest regression added
   (completeLogin exactly once across re-renders). Post-fix browser E2E: exactly ONE token
   exchange, PASS. The frontend staging image was rebuilt (`--build frontend`) to ship it.
2. **Realm import tuning was required (30464a6).** `--import-realm` imports only when the
   realm does not exist in the volume; after tuning the realm JSON, the realm must be
   re-imported (fresh `staging_keycloak_data` volume) for changes to apply — the
   provisioner then re-creates the operator idempotently (proven in section 3 logs).
3. **Keycloak runs `start-dev`** (development mode) — disclosed, same posture as H06's
   Vault dev-mode; production would require `start --optimized` with a real DB/TLS.
4. **`nbf` is a hardcoded claim** (fixed epoch 2026-10-29 lower bound) because Keycloak
   omits `nbf` and R10 requires it; a production provider would emit per-token `nbf`.
   Similarly `institution_id` is a per-client hardcoded value — acceptable for the
   single-institution staging registry, production would map a per-user attribute.
5. **The wallet-bind leg is not driven inside the headless browser** (no wallet extension
   in Chromium); it is covered at the API level with the deterministic dev-network key
   (public Hardhat account #5 — never a deployed secret; the on-chain RoleManager proof
   is the boundary). SIWE challenge → signature → on-chain proof → persisted binding are
   all real HTTP against the staging engine.
6. **Operational notes:** after engine recreation nginx may briefly answer 502 while the
   upstream re-resolves (observed once post-reboot; a frontend container restart clears
   it). `npm run verify:integration` needed `prometheus_client` in the host python env
   (H07's requirements line — synced via pip). Compose dependency re-runs regenerate the
   tracked `deployments/deployment-manifest.json` and `frontend/public/runtime-config.json`;
   they are restored with `git restore` after validation (H04 convention).
7. **Untested here:** production hardening (TLS, `start --optimized`, real hostname
   issuer), multi-institution claim routing, token refresh/rotation flows in the browser,
   and Keycloak-to-production user federation.

## 7. Verdict

**H05 يمر.** The institutional identity loop runs end-to-end in staging against a REAL
OIDC provider — discovery/JWKS/RS256/audience/claims per the §8 contract, full PKCE login
proven in an actual browser through the nginx origin, wallet challenge→bind with on-chain
participant proof, and identity revocation kills a live token on the very next request.
The provider fixture remains confined to automated tests and is never used in staging.
