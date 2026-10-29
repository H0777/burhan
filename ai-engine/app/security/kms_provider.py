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
  envelope semantics (``/encrypt`` + ``/decrypt``) — the same wrap/unwrap
  pattern as AWS KMS ``Encrypt``/``Decrypt`` on a CMK. Transit keys cannot
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
_SIGN_HASH_PATH = "sha2-512"  # ed25519 pure signing (prehashed=false)


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
        """Sign raw bytes inside Vault; return the raw 64-byte Ed25519 signature."""
        raise NotImplementedError("H06 step 4")

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
        """One Vault API call. Transport/5xx failures raise KmsUnavailableError."""
        raise NotImplementedError("H06 step 4")

    def _ensure_transit(self) -> None:
        """Idempotently enable the Transit engine (staging bootstrap)."""
        raise NotImplementedError("H06 step 4")

    def create_key_generation(self, institution_id: str, key_id: str) -> Dict[str, str]:
        """Ceremony operation: create the (ed25519 signing + aes256-gcm wrapping)
        Transit key pair of names for one key generation. Idempotent re-run safe."""
        raise NotImplementedError("H06 step 4")

    def public_key_pem(self, institution_id: str, key_id: str) -> str:
        """Public half of the signing key (for the trust registry). Key material-safe."""
        raise NotImplementedError("H06 step 4")

    # -- KeyProvider ABC ----------------------------------------------------

    def get_current_key_id(self, institution_id: str) -> str:
        """Current key id from the ops registry; KeyError when unregistered."""
        raise NotImplementedError("H06 step 4")

    def get_signing_key(self, institution_id: str, key_id: str) -> VaultTransitSigner:
        """Return the Vault-backed signing delegate (documented ABC adaptation)."""
        raise NotImplementedError("H06 step 4")

    def wrap_data_key(self, institution_id: str, dek: bytes) -> dict:
        """Wrap a DEK via Vault Transit /encrypt under the institution's wrapping key."""
        raise NotImplementedError("H06 step 4")

    def unwrap_data_key(self, institution_id: str, wrapped: dict) -> bytes:
        """Unwrap via Vault Transit /decrypt; refuse foreign/tampered envelopes."""
        raise NotImplementedError("H06 step 4")
