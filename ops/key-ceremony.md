# Key Ceremony Runbook — Institutional Key Custody (H06)

> Scope: two-person ceremony for generating, registering, rotating and
> revoking institution signing/wrapping keys held in the KMS (HashiCorp
> Vault **Transit** in staging). Audience: operations + security officers.
>
> Contract: every key operation in the platform goes through the R05
> `KeyProvider` ABC (`ai-engine/app/security/key_provider.py`). The
> `KmsProvider` (`ai-engine/app/security/kms_provider.py`) is the
> institutional implementation; **`LocalFileKeyProvider` is DEMO-ONLY** —
> see §6. No private key material exists in any filesystem in the KMS path.

## 1. Custody model

- **Where keys live:** inside the KMS only. Vault Transit keys are
  non-exportable (`exportable=false` by default): sign, wrap and unwrap
  happen inside the KMS through its HTTP API. Nothing in this platform
  requests, stores or logs private key material.
- **What the ceremony controls:** the (institution_id, key_id) registry —
  which key generation is *current* per institution. The registry lives
  OUTSIDE the code: staging keeps it in the gitignored
  `infra/staging/.env` as `STAGING_KMS_CURRENT_KEYS` (JSON, consumed by the
  compose override via `KMS_CURRENT_KEYS`); production keeps it in the
  ops secret manager. It is NEVER committed.
- **Key naming (deterministic, injective):** one key generation `key_id`
  materializes as two Transit keys:
  - signing: `<institution_id>--sig--<key_id>` (ed25519 — envelope signing)
  - wrapping: `<institution_id>--dek--<key_id>` (aes256-gcm96 — DEK wrap)
  Components must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` and MUST NOT
  contain the reserved separator `--` (the provider refuses them).

## 2. Roles and rules

| Role | Responsibility |
|---|---|
| Officer A (security) | Initiates, states institution + key_id, witnesses |
| Officer B (operations) | Executes, second-witnesses, updates registry |
| Both | Sign the ceremony log (§7) together; neither alone is sufficient |

Rules: never share the Vault token over chat/email; the token comes from
the gitignored env file only; every command below is run by Officer B
while Officer A verifies the transcript; the ceremony log is committed
WITHOUT tokens or outputs that contain secrets.

## 3. Prerequisites (staging)

```bat
cd C:\path\to\iraq-aml-audit-chain
REM stack running WITH the KMS override (Vault dev-mode, disclosed):
docker compose --env-file infra/staging/.env -f infra/staging/docker-compose.staging.yml -f infra/staging/docker-compose.kms.yml up -d vault
REM both officers verify Vault answers (HTTP 200, no token shown):
docker ps --format "{{.Names}} {{.Ports}}" | findstr aml_staging_vault
```

## 4. Ceremony: generate + register one key generation

Inputs agreed by both officers: `INSTITUTION_ID` (registry format,
no `--`), `KEY_ID` (e.g. `k1`; next generation `k2`, ...).

**Step 1 — create the Transit keys (idempotent; re-runs are no-ops).**

```bat
node scripts\run-python.js -c "from app.security.kms_provider import KmsProvider; from app.config import settings; p=KmsProvider(settings.VAULT_ADDR, settings.VAULT_TOKEN); p._ensure_transit(); print(p.create_key_generation('INSTITUTION_ID','KEY_ID'))"
```

(Pass `VAULT_ADDR`/`VAULT_TOKEN` in the environment from the gitignored
env file; never paste them on the command line in shared shells.)

**Step 2 — export the PUBLIC key for the trust registry.**

```bat
node scripts\run-python.js -c "from app.security.kms_provider import KmsProvider; p=KmsProvider(settings.VAULT_ADDR, settings.VAULT_TOKEN); print(p.public_key_b64('INSTITUTION_ID','KEY_ID'))"
```

The output is base64 of the raw 32-byte Ed25519 public key — the same
format as the R05 trust registry (`decode_public_key`). Both officers
independently record it; it goes into the institution trust registry
(verification side), which is PUBLIC material by design.

**Step 3 — update the current-key registry OUTSIDE the code.**

Staging: edit the gitignored `infra/staging/.env`:

```ini
STAGING_KMS_CURRENT_KEYS={"INST-X":"k1","INST-Y":"k1"}
```

then recreate the engine with the KMS override so the registry reaches the
service (`docker compose ... up -d ai-engine`). Production: the same JSON
lives in the ops secret manager. The registry is the ONLY place "current"
is decided — there is no pointer file, no code change, no re-signing of
old envelopes.

**Step 4 — verify before declaring done.**

```bat
node scripts\run-python.js -m pytest ai-engine\tests\test_kms_provider.py -q
```

All 10 tests must pass against the live Vault (they exercise wrap/unwrap,
isolation, tamper-refusal, fail-closed and the R05/R06 call-site paths).

## 5. Rotation and revocation

**Rotation (planned):** run §4 with the NEXT `key_id` (e.g. `k2`) for the
institution, then flip the registry entry to `k2`. Old evidence keeps
decrypting: every wrapped DEK stores the `recipient_key_id` that wrapped
it and unwraps under that retained generation (`test_recovery_unwrap_with_correct_key_only`
proves exactly this). Old SIGNING keys must stay in the trust registry
with their validity horizon — the offline Verifier invalidates only from
the recorded compromise point, never retroactively.

**Revocation (compromise):**
1. Both officers agree the (institution_id, key_id) is compromised.
2. Flip the registry to a NEW generation first (service continuity), then
   remove the compromised generation from the TRUST REGISTRY with
   `invalid_from` = the compromise horizon (shared-module semantics:
   signatures before the horizon stay valid, after it all fail).
3. Delete the Transit keys (Vault: `DELETE /v1/transit/keys/<name>` after
   allowing deletion via `POST /transit/keys/<name> {"deletion_allowed":true}`).
   With the keys gone, nothing can produce signatures or unwraps under the
   compromised generation — fail-closed by absence, not by policy.

**Emergency KMS outage:** there is deliberately NO file fallback. The
provider answers `KmsUnavailableError` and every dependent operation fails
closed (proven: `test_network_failure_fail_closed_and_recovery` stops the
KMS container mid-test). Recovery = restore the KMS; dev-mode data loss is
the reason production buys a durable managed KMS.

## 6. Demo path (NOT institutional custody)

`LocalFileKeyProvider` (seed files outside the repo, read-only mount)
remains for the DEMO compose only. Differences that matter:

| | LocalFileKeyProvider (demo) | KmsProvider (institutional) |
|---|---|---|
| Private key material | 32-byte seed files on a mounted volume | Never leaves the KMS |
| Signing | local Ed25519 object | sign-in-KMS delegate (`.sign()` via Transit API) |
| DEK wrap | X25519+HKDF+AES-GCM to the institution's public key | Transit-managed AES-256-GCM envelope (KMS Encrypt analogue) |
| Fail-closed on KMS outage | n/a (no KMS) | `KmsUnavailableError`, no file fallback |
| Custody proof | mount audit | this ceremony + two-person registry control |

A deployment that mounts seed files is a demo deployment, full stop; the
institutional mode takes its provider from the KMS wiring (H06) or refuses
to sign/wrap.

## 7. Ceremony log (append per run; commit without secrets)

```
date-utc | institution | key_id | purposes(sig/dek) | officers A+B | public_key_b64 fingerprint (first 8 chars) | result
```

Example (no secrets):
`2026-10-29T19:20Z | INST-CENTRAL-STAGING | k1 | sig+dek ok | A: sara.o B: omar.h | qWwNeykL | PASS`
