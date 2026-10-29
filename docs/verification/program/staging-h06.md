# Staging Verification — H06 KMS/HSM خلف KeyProvider (DG2)

Date: 2026-10-29. Branch `main`, base `b004680`. Status: **COMPLETE**.
Closure for `.superpowers/sdd/2026-10-29-development-program/task-h06-brief.md`.

## 1. What was delivered

A real KMS-backed `KeyProvider` behind the UNCHANGED R05 ABC
(`ai-engine/app/security/key_provider.py`) — file-based keys are no longer
part of the institutional path:

| File | Purpose |
|---|---|
| `ai-engine/app/security/kms_provider.py` | `KmsProvider` (Vault Transit over its real HTTP API) + `VaultTransitSigner` delegate + `build_key_provider_from_settings()` wiring factory |
| `ai-engine/tests/test_kms_provider.py` | 10 tests against the REAL Vault API (no in-process mock), incl. `docker stop`/`docker start` fail-closed proof |
| `infra/staging/docker-compose.kms.yml` | H06-OWNED compose OVERRIDE (stacks with `-f base -f kms`): Vault 1.18 dev-mode + opt-in engine env merge; loopback 127.0.0.1:18200 only |
| `ops/key-ceremony.md` | Two-person key ceremony: generation, public-key export to trust registry, registry-outside-code, rotation, revocation; demo-vs-KMS custody table |
| `ai-engine/app/config.py`, `ai-engine/app/routes/v2/evidence.py` | Opt-in wiring: `KEY_PROVIDER=vault` builds the KMS provider into the evidence store; unset = exactly the historical provider-less fail-closed behavior |

Commits (in order): `80361c7` skeleton, `4a33203` compose override,
`ceb503b` provider implementation, `335ded8` end-to-end proof,
`5b057c3` engine wiring, `dd79fc3` ceremony runbook.
(H05's `df0356e` landed in parallel; zero file overlap — H06 never touched
`docker-compose.staging.yml`.)

## 2. Commands and exit codes (staging, Windows cmd)

```bat
REM 1. Vault up (H06 override stacked on H04 base) — exit 0
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml -f infra/staging/docker-compose.kms.yml up -d vault
docker ps --filter name=aml_staging_vault --format "{{.Names}} {{.Status}} {{.Ports}}"
REM aml_staging_vault   Up ...   127.0.0.1:18200->8200/tcp   (loopback ONLY)

REM 2. Vault health — HTTP 200
node scripts\run-python.js -c "import requests; print(requests.get('http://127.0.0.1:18200/v1/sys/health', params={'standbyok':'true','sealedcode':'200','uninitcode':'200'}, timeout=3).status_code)"

REM 3. Full H06 suite against the real Vault — 10 passed, exit code 0
node scripts\run-python.js -m pytest ai-engine\tests\test_kms_provider.py -v
REM ============================= 10 passed in 9.13s ==============================   EXITCODE=0

REM 4. Stacked compose still valid after H05's parallel base edits — STACKED_CONFIG_OK
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml -f infra/staging/docker-compose.kms.yml config --quiet

REM 5. Regressions — 25 passed (signing + health-readiness suites untouched)
node scripts\run-python.js -m pytest ai-engine\tests\test_signing.py ai-engine\tests\integration\test_health_readiness.py -q
```

Vault Transit API shapes were verified LIVE against the staging engine
(Vault 1.18) before/while implementing: `POST /transit/keys/:name` (200,
idempotent re-create), `POST /transit/sign/:name/sha2-512` with
`prehashed=false` + `marshaling_alg=ed25519` (returns `vault:v1:`-framed
base64url, raw 64 bytes), `POST /transit/encrypt|decrypt/:name` (aes256-gcm96;
tamper → 400 "cipher: message authentication failed"; unknown key → 400
"... key not found"), `GET /transit/keys/:name` (public key = base64 of the
raw 32 bytes — the exact trust-registry format).

## 3. Test matrix (all through the REAL Vault HTTP API)

| # | Test | Proves |
|---|---|---|
| 1 | `test_key_name_mapping_injective_and_validated` | reserved `--` separator refused → (institution,key)→Transit-key mapping is injective (offline) |
| 2 | `test_wrap_unwrap_roundtrip_via_real_vault_api` | DEK wrap/unwrap round-trips via Transit encrypt/decrypt; plaintext DEK leaks nowhere into the wrapped form |
| 3 | `test_wrong_institution_and_wrong_key_refused` | foreign tenant / forged tenant field refused (`ValueError`) |
| 4 | `test_tamper_fail_closed` | tampered ciphertext → Transit GCM auth failure → `ValueError`, nothing served |
| 5 | `test_two_institutions_isolated` | cross-institution unwrap refused both directions (structural: per-tenant Transit keys) |
| 6 | `test_recovery_unwrap_with_correct_key_only` | rotation: registry flips to k2, retained k1 still unwraps old envelopes, unknown generation fails closed |
| 7 | `test_vault_backed_signing_verifies_against_public_key` | sign-in-KMS delegate produces a REAL 64-byte Ed25519 signature verifying under the Vault-exported PUBLIC key only |
| 8 | `test_r05_r06_call_sites_end_to_end` | the actual R05 `Signer` + R06 `encrypt_bytes`/`decrypt_bytes` work through the KMS provider; wrong tenant → R06 fail-closed errors |
| 9 | `test_unknown_keys_fail_closed` | unknown institution/key → `KeyError` (ABC contract) |
| 10 | `test_network_failure_fail_closed_and_recovery` | `docker stop aml_staging_vault` → wrap/unwrap/sign all raise `KmsUnavailableError` (NO file fallback); `docker start` → transport recovery proven; dev-mode data loss disclosed (below) |

**Fail-closed proof (test 10, live):** while the container was stopped every
operation refused with `KmsUnavailableError` — nothing fell back to files,
no plaintext DEK was served. After restart the same provider instance served
new operations again. Additionally observed (and honestly mapped): a WRONG
token yields Vault 403 → `KmsUnavailableError` (credential failure is an
unavailable refusal, never a degradation).

## 4. ABC adaptation (the one interface-honest deviation)

The R05 ABC annotates `get_signing_key(...) -> Ed25519PrivateKey`. Vault
Transit is **non-exportable by design** — returning a local Ed25519 object
would require key material, defeating the purpose. Adaptation, verified
against every R05 call site (`shared/python/evidence_crypto.py` `Signer.sign`
is the only external consumer; it uses exactly `.sign(payload) -> bytes`):

- `get_signing_key` returns a `VaultTransitSigner` **delegate** that performs
  the Ed25519 signature INSIDE Vault via the Transit sign API and returns
  the raw 64 bytes. Duck-type-compatible with the single call site; NOT an
  `isinstance(Ed25519PrivateKey)`. The ABC type annotation is intentionally
  NOT relaxed (zero interface change, per brief); the delegate is documented
  in the module docstring and here.
- `wrap_data_key`/`unwrap_data_key` use Transit's managed AES-256-GCM
  envelope semantics (the Vault analogue of AWS KMS Encrypt/Decrypt) instead
  of the local X25519+HKDF path — Transit cannot export material to derive
  the X25519 key. The wrapped dict is provider-specific (carries
  `algorithm: VaultTransit-AES256GCM/v1`, `vault:v1:` ciphertext,
  `recipient_key_id` — the only field R06 consumes — plus `institution_id`
  for tenant-binding refusal). Consequence (documented, by design):
  KMS-wrapped DEKs decrypt only through the KMS; the offline verifier never
  needed to unwrap DEKs (it verifies signatures via trust-registry PUBLIC
  keys), so no offline path was broken.
- No hand-rolled crypto anywhere: signatures are Transit's; wrapping is
  Transit's; the only local transformations are base64 transport unframing
  (`vault:v1:` prefix strip) and registry-format re-encoding of PUBLIC keys.

## 5. Dev-mode disclosure (honest limits)

- **Vault runs dev-mode in staging** (`server -dev`): in-memory storage,
  auto-unseal, single root token from the gitignored `infra/staging/.env`
  (`STAGING_VAULT_DEV_ROOT_TOKEN_ID`). Disclosed everywhere it matters
  (compose comments, runbook, here). Production buys a durable managed KMS
  (AWS KMS / Azure Key Vault) or a sealed HA Vault cluster — behind the SAME
  ABC; the interface is the deliverable.
- **Dev-mode data loss proven, not hidden:** test 10 shows the pre-restart
  envelope can no longer be unwrapped after a dev-mode restart (fresh key
  material) — answered with a fail-closed `ValueError`, never silent
  nonsense. A durable KMS eliminates exactly this.
- **Ceremony caveat carried into `ops/key-ceremony.md`:** Transit's encrypt
  endpoint auto-creates a key on first use if absent (Vault behavior); the
  ceremony pre-creates BOTH keys of a generation explicitly with types
  (ed25519 / aes256-gcm96) so custody starts from the ceremony, not from an
  accidental first wrap.
- Engine container wiring is OPT-IN via the override's env
  (`KEY_PROVIDER=vault`, `VAULT_ADDR=http://vault:8200`); it activates on
  the next `up -d --build` with the override stacked. Without the override
  the engine behaves exactly as H04 left it (provider-less = fail-closed).
  The in-cluster wiring (engine→vault over the compose network) was NOT
  exercised live in this session (tests run host-side against
  127.0.0.1:18200) — noted as the one remaining integration step for the
  next stack rebuild.

## 6. No key material in files/logs/Git

- Provider holds only: Vault address, token reference, in-memory registry.
- Token: `infra/staging/.env` (gitignored — verified: `git ls-files
  infra/staging` shows only `.env.example`, the compose files, keycloak/, runtime config).
- Tests read the token at runtime from the gitignored env (or `TEST_VAULT_TOKEN`);
  nothing secret is hardcoded, printed or committed (seed-file paths are
  never used by the KMS path; no `.seed` files created).
- Ceremony log template records only a public-key fingerprint (first 8 chars).

## 7. Verdict

Brief acceptance: **wrap/unwrap and signing via a REAL KMS protocol in
staging — PASS (10/10, real Vault HTTP API); two-institution isolation —
PROVEN (structural + behavioral); network-failure fail-closed — PROVEN with
`docker stop` mid-test; no private key in any filesystem — TRUE BY CONSTRUCTION
(Transit non-exportable; provider stateless of material).**
