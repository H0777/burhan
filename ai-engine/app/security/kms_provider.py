"""KMS-backed :class:`~app.security.key_provider.KeyProvider` (H06, DG2).

Institutional key custody moves from seed files (``LocalFileKeyProvider`` —
DEMO ONLY) to a real KMS behind the SAME R05 ``KeyProvider`` ABC. Zero
interface change: the ABC's four methods are inherited verbatim.

Provider: HashiCorp Vault **Transit** secrets engine, reached through its
real HTTP API (``requests``; no in-process mock). The chosen staging
provider is disclosed as **dev-mode** (see ``ops/key-ceremony.md``);
production buys a managed KMS (AWS KMS / Azure Key Vault) behind the same
ABC — the interface is the deliverable.

Honest ABC adaptation (documented in ``docs/verification/program/staging-h06.md``):

- ``get_signing_key`` returns a :class:`VaultTransitSigner` delegate, not an
  ``Ed25519PrivateKey``. Vault Transit never exports private key material,
  so a local Ed25519 object is impossible BY DESIGN (that is the point of
  KMS custody). The only R05 call site (``Signer.sign`` ->
  ``sign_payload_bytes``) uses exactly one operation on the returned object:
  ``.sign(payload) -> 64-byte Ed25519 signature``. The delegate performs the
  signature INSIDE Vault via ``POST /v1/transit/keys/<name>/sign/sha2-512``
  (``prehashed=false``, ``marshaling_alg=ed25519``) — no hand-rolled crypto,
  no key material in-process, in files, or in logs.
- ``wrap_data_key``/``unwrap_data_key`` use Transit's managed AES-256-GCM
  envelope semantics (``/encrypt`` + ``/decrypt`` on an ``aes256-gcm96``
  Transit key) — the same wrap/unwrap pattern as AWS KMS
  ``Encrypt``/``Decrypt`` on a CMK. Transit keys cannot
  export material, so the local X25519+HKDF path is not reachable from a
  KMS provider; the wrapped dict is therefore provider-specific and carries
  ``recipient_key_id`` (the only field ``encrypt_bytes`` consumes) plus its
  own ``algorithm`` marker. Rotation semantics are unchanged: every wrapped
  DEK records the ``key_id`` that wrapped it and keeps unwrapping with that
  retained generation.

Fail-closed behaviour:

- unknown institution/key -> ``KeyError`` (matches the ABC contract);
- Vault unreachable / 5xx / timeout -> :class:`KmsUnavailableError`
  (an explicit "unavailable" refusal — nothing is served, nothing falls
  back to files); a tampered or cross-institution wrapped DEK ->
  ``ValueError`` (authentication failure), which ``decrypt_bytes`` maps to
  ``InvalidCiphertextError``.

Key naming (deterministic, injective): one key generation ``key_id`` of an
institution materializes as two Transit keys — signing
``<inst>--sig--<key_id>`` (ed25519) and wrapping ``<inst>--dek--<key_id>``
(aes256-gcm). ``--`` is a reserved separator: components containing ``--``
are refused, making the (institution_id, key_id) -> name mapping injective
so no two tenants can ever share a Transit key.

The current-key selection (``key_id`` per institution) lives in a registry
OUTSIDE the code (ops-managed; see the key ceremony runbook) and is
injected at construction. This module never persists key ids or tokens.

No key material is ever written to disk, returned in API responses, or
logged. The provider holds only: Vault address, auth token (from the
environment, gitignored) and the current-key registry mapping.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Mapping, Optional

import requests

from app.security.key_provider import (
    KeyProvider,
    _validate_component,
)

__all__ = [
    "KmsProvider",
    "KmsUnavailableError",
    "VaultTransitSigner",
    "TRANSIT_MOUNT",
]

TRANSIT_MOUNT = "transit"
_SEPARATOR = "--"
_SIG = "sig"
_DEK = "dek"

# Vault Transit endpoints (relative to the Vault API root, e.g. /v1).
# Vault 1.18 shapes: POST /transit/sign/:name/:hash_algorithm,
# POST /transit/encrypt/:name, POST /transit/decrypt/:name,
# GET/POST /transit/keys/:name (verified against the staging engine).
_SIGN_HASH_PATH = "sha2-512"  # ed25519 pure signing (prehashed=false)

_BLOB_PREFIX = "vault:"  # "vault:v1:<base64url-nopadding>" transport framing


def _decode_vault_blob(value: Any) -> bytes:
    """Decode a ``vault:v1:``-framed base64url blob to raw bytes (no crypto —
    transport unframing only)."""
    if not isinstance(value, str) or not value:
        raise KmsUnavailableError("KMS returned no blob")
    raw = value
    if raw.startswith(_BLOB_PREFIX):
        parts = raw.split(":", 2)
        if len(parts) != 3:
            raise KmsUnavailableError("malformed KMS blob framing")
        raw = parts[2]
    try:
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (ValueError, TypeError) as exc:
        raise KmsUnavailableError("malformed KMS blob encoding") from exc


class KmsUnavailableError(RuntimeError):
    """The KMS is unreachable or failing — the provider refuses to serve.

    Raised on transport errors, timeouts and 5xx responses. This is the
    fail-closed "unavailable" state required by H06: no key operation is
    answered, and there is deliberately NO file-based fallback.
    """


class VaultTransitSigner:
    """Duck-typed signing delegate backed by Vault Transit (ed25519).

    Satisfies the single operation R05 call sites need (``.sign(bytes)``)
    without ever holding private key material. Not an ``Ed25519PrivateKey`` —
    that is the documented ABC adaptation (see module docstring).
    """

    def __init__(self, request_fn, key_name: str, key_id: str, institution_id: str):
        self._request = request_fn
        self._key_name = key_name
        self.key_id = key_id
        self.institution_id = institution_id

    def sign(self, data: bytes) -> bytes:
        """Sign raw bytes inside Vault; return the raw 64-byte Ed25519 signature.

        Pure Ed25519 (``prehashed=false``) — Vault hashes nothing, the exact
        ``signing_payload`` bytes go over TLS and are signed inside the KMS.
        Vault returns ``vault:v1:<base64url-nopadding>``; the ``vault:v1:``
        envelope is transport framing, the 64 decoded bytes are the signature.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("signing payload must be bytes")
        try:
            data_out = self._request(
                "POST",
                f"transit/sign/{self._key_name}/{_SIGN_HASH_PATH}",
                payload={
                    "input": base64.b64encode(bytes(data)).decode("ascii"),
                    "prehashed": False,
                    "marshaling_alg": "ed25519",
                },
            )
        except KeyError as exc:
            raise KeyError(f"signing key vanished from KMS: {self._key_name}") from exc
        signature = _decode_vault_blob(data_out.get("signature"))
        if len(signature) != 64:
            raise KmsUnavailableError(
                f"KMS signature has unexpected length {len(signature)}"
            )
        return signature

    @property
    def key_name(self) -> str:
        """Transit key name (address only — never key material)."""
        return self._key_name


class KmsProvider(KeyProvider):
    """Vault-Transit-backed :class:`KeyProvider` — institutional custody.

    Constructor arguments are addresses/labels only:

    - ``vault_url``: e.g. ``http://127.0.0.1:18200`` (staging loopback).
    - ``token``: Vault auth token (staging dev-mode root; production uses a
      narrowly-scoped per-service credential). Never persisted by this class.
    - ``current_keys``: the ops-managed ``institution_id -> key_id`` registry
      (key ceremony runbook). Read-only, in-memory.
    """

    def __init__(
        self,
        vault_url: str,
        token: str,
        current_keys: Optional[Mapping[str, str]] = None,
        *,
        timeout: float = 5.0,
        session: Optional[requests.Session] = None,
    ):
        self._vault_url = vault_url.rstrip("/")
        self._token = token
        self._current_keys: Dict[str, str] = dict(current_keys or {})
        self._timeout = timeout
        self._session = session or requests.Session()

    # -- naming ------------------------------------------------------------

    @staticmethod
    def key_name(institution_id: str, key_id: str, purpose: str) -> str:
        """Deterministic, injective Transit key name for (institution, key, purpose)."""
        _validate_component(institution_id, "institution_id")
        _validate_component(key_id, "key_id")
        if purpose not in (_SIG, _DEK):
            raise ValueError(f"invalid key purpose: {purpose!r}")
        for part in (institution_id, key_id):
            if _SEPARATOR in part:
                raise ValueError(
                    f"{_SEPARATOR!r} is a reserved key-name separator and may not "
                    f"appear inside institution_id or key_id: {part!r}"
                )
        return _SEPARATOR.join((institution_id, purpose, key_id))

    # -- transport ---------------------------------------------------------

    def _request(self, method: str, path: str, payload: Optional[dict] = None) -> dict:
        """One Vault API call. Transport/5xx/auth failures raise KmsUnavailableError.

        Mapping (fail-closed by design):
        - 2xx            -> the response ``data`` dict (empty for 204);
        - 404            -> ``KeyError`` (unknown key/institution — the ABC
                            contract's fail-closed answer);
        - 400            -> ``ValueError`` (malformed/tampered input — e.g.
                            decrypt authentication failure);
        - 403/5xx/transport -> :class:`KmsUnavailableError` (refuse to serve).
        """
        url = f"{self._vault_url}/v1/{path}"
        try:
            response = self._session.request(
                method,
                url,
                json=payload,
                headers={"X-Vault-Token": self._token},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise KmsUnavailableError(f"KMS unreachable ({method} {path}): {exc}") from exc

        if response.status_code in (200, 204):
            try:
                body = response.json()
            except ValueError:
                body = {}
            return body.get("data") if isinstance(body, dict) and "data" in body else (body or {})

        if response.status_code == 404:
            raise KeyError(f"key not found in KMS: {path}")
        if response.status_code == 400:
            detail = ""
            try:
                detail = "; ".join(response.json().get("errors", []))
            except ValueError:
                pass
            # Transit reports unknown keys as 400 ("... key not found") — the
            # ABC's fail-closed answer for unknown keys is KeyError.
            if "key not found" in detail:
                raise KeyError(f"key not found in KMS: {path}")
            raise ValueError(f"KMS refused the operation ({path}): {detail or 'bad request'}")
        raise KmsUnavailableError(
            f"KMS unavailable ({method} {path}): HTTP {response.status_code}"
        )

    def _ensure_transit(self) -> None:
        """Idempotently enable the Transit engine (staging bootstrap).

        Production note: a managed KMS needs no mount bootstrap; this step
        exists only for the dev-mode staging Vault.
        """
        url = f"{self._vault_url}/v1/sys/mounts/{TRANSIT_MOUNT}"
        try:
            response = self._session.request(
                "POST", url, json={"type": "transit"},
                headers={"X-Vault-Token": self._token}, timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise KmsUnavailableError(f"KMS unreachable (mount transit): {exc}") from exc
        if response.status_code == 204:
            return
        if response.status_code == 400 and "already in use" in response.text:
            return  # already mounted — idempotent
        if response.status_code in (403, 500, 501, 502, 503):
            raise KmsUnavailableError(
                f"KMS unavailable (mount transit): HTTP {response.status_code}"
            )
        raise KmsUnavailableError(
            f"cannot enable Transit engine: HTTP {response.status_code} {response.text[:200]}"
        )

    def create_key_generation(self, institution_id: str, key_id: str) -> Dict[str, str]:
        """Ceremony operation: materialize both Transit keys of one key
        generation — the ed25519 signing key and the aes256-gcm wrapping key.
        Idempotent: POSTing an existing Transit key name only re-writes its
        config (verified against Vault 1.18 — it neither rotates nor errors).
        """
        names = {
            _SIG: self.key_name(institution_id, key_id, _SIG),
            _DEK: self.key_name(institution_id, key_id, _DEK),
        }
        for purpose, name in names.items():
            key_type = "ed25519" if purpose == _SIG else "aes256-gcm96"
            self._request("POST", f"transit/keys/{name}", payload={"type": key_type})
        return names

    def public_key_b64(self, institution_id: str, key_id: str) -> str:
        """Public half of the signing key, in the trust-registry format
        (base64 of the raw 32 bytes — same encoding as the R05
        ``encode_public_key``; drops straight into the ops registry). This is
        PUBLIC material only: Vault never returns the private half, which is
        exactly the KMS custody property under test.
        """
        name = self.key_name(institution_id, key_id, _SIG)
        data = self._request("GET", f"transit/keys/{name}")
        keys = data.get("keys") or {}
        latest = data.get("latest_version")
        entry = keys.get(str(latest)) or (next(iter(keys.values())) if keys else None)
        pem = (entry or {}).get("public_key")
        if not isinstance(pem, str) or not pem:
            raise KmsUnavailableError(f"KMS returned no public key for {name}")
        return pem

    # -- KeyProvider ABC ----------------------------------------------------

    def get_current_key_id(self, institution_id: str) -> str:
        """Current key id from the ops-managed registry; KeyError when unregistered.

        The registry lives OUTSIDE the code (key ceremony runbook) and is
        injected at construction. Unknown institutions fail closed.
        """
        _validate_component(institution_id, "institution_id")
        key_id = self._current_keys.get(institution_id)
        if not isinstance(key_id, str) or not key_id:
            raise KeyError(f"no KMS key registered for institution {institution_id!r}")
        _validate_component(key_id, "key_id")
        return key_id

    def get_signing_key(self, institution_id: str, key_id: str) -> VaultTransitSigner:
        """Return the Vault-backed signing delegate (documented ABC adaptation).

        Verifies the Transit key exists at call time — unknown keys raise
        ``KeyError`` (ABC contract), an unreachable KMS raises
        :class:`KmsUnavailableError`. The returned delegate holds no key
        material: only the Transit key NAME; signatures happen inside Vault.
        """
        name = self.key_name(institution_id, key_id, _SIG)
        self._request("GET", f"transit/keys/{name}")  # 404 -> KeyError; down -> unavailable
        return VaultTransitSigner(self._request, name, key_id, institution_id)

    def wrap_data_key(self, institution_id: str, dek: bytes) -> dict:
        """Wrap a DEK via Vault Transit /encrypt under the institution's
        current wrapping key (real KMS envelope semantics — Transit-managed
        AES-256-GCM, the Vault analogue of AWS KMS Encrypt)."""
        if not isinstance(dek, (bytes, bytearray)) or not dek:
            raise ValueError("DEK must be non-empty bytes")
        key_id = self.get_current_key_id(institution_id)
        name = self.key_name(institution_id, key_id, _DEK)
        data = self._request(
            "POST",
            f"transit/encrypt/{name}",
            payload={"plaintext": base64.b64encode(bytes(dek)).decode("ascii")},
        )
        ciphertext = data.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
            raise KmsUnavailableError("KMS returned no wrapped ciphertext")
        return {
            "algorithm": "VaultTransit-AES256GCM/v1",
            "ciphertext": ciphertext,
            "recipient_key_id": key_id,
            "institution_id": institution_id,
            "kms": "hashicorp-vault/transit",
        }

    def unwrap_data_key(self, institution_id: str, wrapped: dict) -> bytes:
        """Unwrap via Vault Transit /decrypt. Fail-closed matrix:

        - not a dict / missing or non-string fields -> ``ValueError``;
        - foreign institution's envelope -> ``ValueError`` (never silently
          attempted under the wrong tenant);
        - unknown key generation -> ``KeyError``;
        - tampered ciphertext (GCM auth failure inside Transit) -> ``ValueError``;
        - KMS unreachable -> :class:`KmsUnavailableError`.
        """
        if not isinstance(wrapped, dict):
            raise ValueError("wrapped key must be a dict")
        key_id = wrapped.get("recipient_key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("wrapped key is missing recipient_key_id")
        stored_inst = wrapped.get("institution_id")
        if not isinstance(stored_inst, str) or not stored_inst:
            raise ValueError("wrapped key is missing institution_id")
        if stored_inst != institution_id:
            raise ValueError(
                f"wrapped key belongs to {stored_inst!r}, refused for {institution_id!r}"
            )
        ciphertext = wrapped.get("ciphertext")
        if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
            raise ValueError("wrapped key is not a Vault Transit ciphertext")
        name = self.key_name(institution_id, key_id, _DEK)
        data = self._request(
            "POST",
            f"transit/decrypt/{name}",
            payload={"ciphertext": ciphertext},
        )
        plaintext_b64 = data.get("plaintext")
        if not isinstance(plaintext_b64, str) or not plaintext_b64:
            raise KmsUnavailableError("KMS returned no plaintext for the wrapped DEK")
        dek = base64.b64decode(plaintext_b64, validate=True)
        if not dek:
            raise ValueError("unwrapped DEK is empty")
        return dek


def build_key_provider_from_settings():
    """Opt-in engine wiring (H06): construct the KeyProvider from settings.

    - ``KEY_PROVIDER`` empty/``none`` -> ``None`` (historical behaviour: the
      evidence store runs provider-less and signing/wrapping fail closed).
    - ``KEY_PROVIDER=vault`` -> a :class:`KmsProvider` configured from
      ``VAULT_ADDR``/``VAULT_TOKEN``/``KMS_CURRENT_KEYS`` (all from the
      gitignored environment). Misconfiguration raises at startup rather
      than degrading to file-based keys — there is NO file fallback here.

    The Vault Transit mount is enabled idempotently; key material for key
    GENERATIONS is created by the ceremony (``ops/key-ceremony.md``), never
    by application startup.
    """
    import json

    from app.config import settings

    mode = (settings.KEY_PROVIDER or "").strip().lower()
    if mode in ("", "none"):
        return None
    if mode != "vault":
        raise RuntimeError(
            f"unknown KEY_PROVIDER {settings.KEY_PROVIDER!r} (supported: 'vault')"
        )
    if not settings.VAULT_TOKEN:
        raise RuntimeError("KEY_PROVIDER=vault requires VAULT_TOKEN in the environment")
    try:
        registry = json.loads(settings.KMS_CURRENT_KEYS or "{}")
    except ValueError as exc:
        raise RuntimeError("KMS_CURRENT_KEYS must be valid JSON") from exc
    if not isinstance(registry, dict):
        raise RuntimeError("KMS_CURRENT_KEYS must be a JSON object {institution_id: key_id}")
    for inst, kid in registry.items():
        _validate_component(inst, "KMS_CURRENT_KEYS institution_id")
        _validate_component(str(kid), "KMS_CURRENT_KEYS key_id")
    provider = KmsProvider(
        settings.VAULT_ADDR,
        settings.VAULT_TOKEN,
        {str(k): str(v) for k, v in registry.items()},
        timeout=float(settings.KMS_TIMEOUT_SECONDS),
    )
    provider._ensure_transit()
    return provider
