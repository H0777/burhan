# Runbook — Key Management & Signature Trust (R05)

Scope: Ed25519 signing keys, the external trust registry, data-key wrapping
and the canonical-JSON signature contract for the Iraq AML audit chain
(spec §6). Interface owners: `shared/python/evidence_crypto.py` (single
source of truth), `ai-engine/app/security/signing.py`,
`ai-engine/app/security/key_provider.py`, `ai-engine/app/security/trust_registry.py`.

## 1. Signature contract (invariants — do not weaken)

- **Algorithm:** Ed25519 via `cryptography` only. No HMAC, no key derived
  from `institution_id`, no `alg=none`, no fallback paths. A historical
  verifier accepted `INVALID-NO-PRIVATE-KEY` / `algorithm=none` signatures —
  that class of failure is what the current `Verifier` refuses by
  construction (`SignedEnvelope.from_dict` enforces `algorithm == "Ed25519"`).
- **Signature input:** `Ed25519(domain + 0x00 + canonical_bytes(body))` with
  exactly three domains: `AML_SERVICE_MANIFEST_V1`, `AML_DOSSIER_V1`,
  `AML_BACKUP_V1`. Unknown domains are refused by signer and verifier.
- **Canonical JSON:** UTF-8; `sort_keys=True`; `separators=(",",":")`;
  `ensure_ascii=False`; `allow_nan=False`; floats rejected; duplicate JSON
  keys rejected at parse time (`parse_strict_json`); NO Unicode
  normalization — Arabic content is signed byte-for-byte as received.
- **Envelopes:** `{body, algorithm: "Ed25519", signature: base64}`; the body
  carries `institution_id`, `key_id`, `schema_version` (=1).
- **Verification statuses:** `verified | invalid | unavailable` with fixed
  reasons (see `evidence_crypto.py` constants). Fail-closed: missing key or
  registry is `unavailable`, never `verified`; a network error fetching the
  registry is `unavailable`; a proven mismatch is `invalid`.

## 2. Trust registry (external, authoritative)

Schema: `shared/schemas/trust-registry-v1.schema.json`. The registry binds
`(institution_id, key_id)` to a base64 raw 32-byte Ed25519 public key with
`valid_from` / `valid_until` (start inclusive, end exclusive), `status`,
`revoked_at`, `invalid_from`.

Lifecycle semantics enforced by `Verifier`:

| status | rule |
|---|---|
| `active` | verify if the signature is inside `[valid_from, valid_until)` when `trusted_time` is supplied; verify on signature alone otherwise |
| `retired` | accepted ONLY with an external `trusted_time` inside the validity window; without it → `unavailable (trusted_time_required)` |
| `revoked` | always `invalid (key_revoked)`; `revoked_at` is recorded |
| `compromised` | `invalid_from` present → signatures with `trusted_time >= invalid_from` are `invalid`; `trusted_time` unknown → `unavailable`; **missing `invalid_from` → every signature of that key is invalid** |

**trusted_time must come from an external trusted source** (operator clock
synced to a trusted NTP, or a signing timestamp service). A date read from
inside a submitted ZIP/archive is attacker-controlled data and is NEVER
passed as `trusted_time`.

Load with `app.security.trust_registry.load_registry(path)` — missing or
malformed documents raise; callers must treat that as `unavailable` and stop.

## 3. Key custody — interim local arrangement

- Private keys live as 32-byte raw seed files:
  `<mount>/<institution_id>/<key_id>.seed`, plus an optional
  `<mount>/<institution_id>/current` pointer naming the active key id.
- The mount is **read-only**, located **outside the repository and outside
  any deployed ZIP**, **owned by the service account** the engine runs as
  (no other principal has read access). Example (Windows):
  `C:\ProgramData\iraq-aml\keys` ACLed to the service account only;
  container deployments: a read-only secret volume.
- `LocalFileKeyProvider(base_dir)` refuses path traversal (`..`), requires
  exact 32-byte seeds, and fails closed with `KeyError` on missing keys.
- **Key material is never returned in API responses, never logged, and never
  committed.** Only public keys (base64) appear in the registry and in the
  synthetic test fixture. Do not `str()`/`repr()` private key objects into
  logs; error messages carry institution/key ids only.
- Every committed file is swept for key material before release
  (`findstr /s /i "PRIVATE KEY" *.py *.json` + review of fixtures); the only
  allowed matches are the words "private key" inside this runbook and test
  comments.

### Generating an institution signing key

```text
# Python (service account, on the key mount host):
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import os
seed = os.urandom(32)                      # or Ed25519PrivateKey.generate().private_bytes_raw()
open(r"<mount>\<INSTITUTION_ID>\<KEY_ID>.seed", "wb").write(seed)
del seed                                   # discard; file is the only copy
# publish the PUBLIC key in the trust registry:
# base64(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw())
```

## 4. Data-key wrapping (DEK)

`KeyProvider.wrap_data_key(institution_id, dek)` wraps to the institution's
Curve25519 public key derived from the SAME Ed25519 seed
(`x25519_from_ed25519_seed`, libsodium-style conversion):
ephemeral X25519 + HKDF-SHA256 + AES-256-GCM, output
`{algorithm: "X25519-HKDF-SHA256-AES256GCM-V1", ephemeral_public_key, nonce,
ciphertext, recipient_key_id}`. Tampering fails authentication with
`ValueError` (fail-closed). The plaintext DEK never appears in logs or
responses.

## 5. KMS swap path

`KeyProvider` (`ai-engine/app/security/key_provider.py`) is the single
custody seam: signing, verification and wrapping only call
`get_signing_key` / `wrap_data_key` / `unwrap_data_key` /
`get_current_key_id`. A future KMS implementation replaces
`LocalFileKeyProvider` without touching `evidence_crypto.py`, the verifier
distribution, or call sites. No KMS purchase is part of the current plan.

## 6. Rotation / retirement / compromise

- **Rotation:** generate a new key id (`<INST>-K<yyyy-nn>.seed`), add its
  registry entry (`active`), switch the `current` pointer, keep the old key
  `active` for verification until its sunset date, then set it `retired`
  (it stays verifiable under external `trusted_time` only).
- **Retirement:** set `status=retired` in the registry. Do not delete the
  entry — historical envelopes must remain verifiable inside the recorded
  validity window.
- **Compromise:** set `status=compromised` with `invalid_from` = the last
  time the key is believed honest. If unknown, leave `invalid_from` null —
  this invalidates the key's ENTIRE signature history (fail-closed). Move to
  a fresh key immediately.
- Registry changes are operational edits to the mounted registry document
  (out-of-band, access-controlled); the engine picks them up on next load.

## 7. Verifier distribution

The offline verifier is built from CLI script + `shared/python/evidence_crypto.py`
+ `shared/schemas/*` + contract ABIs — no app code, no DB. The shared module
is loaded from a fixed path relative to the distribution layout; it never
accepts a module path chosen by input files (ZIP submissions cannot select
the code that verifies them). `cryptography` is pinned in
`ai-engine/requirements.lock` (verified at R05: 50.0.2 on Python 3.14.7).

## 8. Testing

`ai-engine/tests/test_signing.py` covers: tamper rejection, wrong
institution key, wrong domain, missing registry, embedded-key distrust,
duplicate-key and float rejection, retired/compromised lifecycle, expiry
and second-boundary semantics, envelope-digest sensitivity, JSON key-order
invariance and Arabic integrity (fixture `shared/fixtures/signatures-v1.json`
— synthetic keys only). Run:

```text
node scripts\run-python.js -m pytest -q ai-engine\tests\test_signing.py
```
