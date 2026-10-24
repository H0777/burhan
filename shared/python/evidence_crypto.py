"""Shared canonical-JSON, Ed25519 signing and trust-registry primitives (R05).

Single source of truth used by the AI engine server (``ai-engine/app/security/*``)
and the offline verifier CLI. The verifier distribution is built from
script + this shared module + schemas + ABI -- never from an application
bundle or database, and this file is loaded from a fixed path relative to
the distribution layout (never a caller- or ZIP-chosen path).

Spec section 6 semantics (binding):

- Signatures are Ed25519 via ``cryptography``. No HMAC, no key derived from
  ``institution_id``, no fabricated fallback. Network error = ``unavailable``.
- Canonical JSON: UTF-8, ``sort_keys=True``, ``separators=(",",":")``,
  ``ensure_ascii=False``, ``allow_nan=False``. No floats, no duplicate JSON
  keys, no Unicode normalization (text content is signed as-is).
- ``signature = Ed25519(domain + NUL + canonical_bytes(body))`` over the
  three fixed domains: ``AML_SERVICE_MANIFEST_V1``, ``AML_DOSSIER_V1``,
  ``AML_BACKUP_V1``.
- The trust registry is external and authoritative: key material embedded in
  an envelope is never trusted. ``compromised`` invalidates signatures from
  ``invalid_from`` (a missing ``invalid_from`` invalidates every signature of
  that key). ``retired`` is accepted only when the caller supplies an external
  ``trusted_time`` -- a date read from inside a ZIP is never trusted_time.
  Missing key or registry is fail-closed (``unavailable``, never ``verified``).

Private keys never appear in this module's outputs: signers receive key
objects from a ``KeyProvider`` and this module returns only base64
signatures and JSON-safe envelopes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SCHEMA_VERSION = 1

DOMAIN_SERVICE_MANIFEST = "AML_SERVICE_MANIFEST_V1"
DOMAIN_DOSSIER = "AML_DOSSIER_V1"
DOMAIN_BACKUP = "AML_BACKUP_V1"
KNOWN_DOMAINS = frozenset({DOMAIN_SERVICE_MANIFEST, DOMAIN_DOSSIER, DOMAIN_BACKUP})

ALGORITHM = "Ed25519"
WRAP_ALGORITHM = "X25519-HKDF-SHA256-AES256GCM-V1"

_NUL = b"\x00"
_WRAP_INFO = b"AML-DEK-WRAP-V1"
_ED25519_KEY_LEN = 32

# statuses
STATUS_ACTIVE = "active"
STATUS_RETIRED = "retired"
STATUS_REVOKED = "revoked"
STATUS_COMPROMISED = "compromised"
KNOWN_STATUSES = frozenset({STATUS_ACTIVE, STATUS_RETIRED, STATUS_REVOKED, STATUS_COMPROMISED})

# SignatureResult statuses (fixed vocabulary)
STATUS_VERIFIED = "verified"
STATUS_INVALID = "invalid"
STATUS_UNAVAILABLE = "unavailable"

# Fixed reason strings -- stable contract for R06/R07/R09/R16 consumers.
REASON_SIGNATURE_MISMATCH = "signature_mismatch"
REASON_SIGNATURE_MALFORMED = "signature_malformed"
REASON_UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
REASON_UNKNOWN_DOMAIN = "unknown_domain"
REASON_BODY_FIELDS_MISSING = "body_missing_required_fields"
REASON_REGISTRY_UNAVAILABLE = "registry_unavailable"
REASON_KEY_NOT_IN_REGISTRY = "key_not_in_registry"
REASON_KEY_STATUS_UNKNOWN = "key_status_unknown"
REASON_TRUSTED_TIME_REQUIRED = "trusted_time_required"
REASON_KEY_NOT_VALID_AT_TRUSTED_TIME = "key_not_valid_at_trusted_time"
REASON_KEY_REVOKED = "key_revoked"
REASON_KEY_COMPROMISED = "key_compromised"
REASON_KEY_COMPROMISED_NO_INVALID_FROM = "key_compromised_no_invalid_from"

_REQUIRED_BODY_FIELDS = ("institution_id", "key_id", "schema_version")


class CanonicalizationError(ValueError):
    """Raised when a document cannot be canonicalized under spec section 6."""


class DuplicateJsonKeyError(CanonicalizationError):
    """Raised when parsed JSON contains a duplicate object key."""


class TrustRegistryError(ValueError):
    """Raised when a trust-registry document is structurally invalid."""


# ---------------------------------------------------------------------------
# canonical JSON
# ---------------------------------------------------------------------------


def _reject_duplicate_pairs(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key!r}")
        seen[key] = value
    return seen


def parse_strict_json(data: Any) -> Any:
    """Parse JSON text/bytes rejecting duplicate object keys.

    A ZIP- or user-supplied document parsed with this function can never hide
    a second value behind a repeated key, which is what a plain ``json.loads``
    would silently do (last-wins).
    """
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8")
    elif isinstance(data, str):
        text = data
    else:
        raise TypeError("parse_strict_json expects str or bytes")
    return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)


def _validate_plain(value: Any, path: str) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"float not allowed in canonical JSON at {path}")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key at {path}")
            _validate_plain(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_plain(item, f"{path}[{index}]")
        return
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {path}")


def canonical_bytes(body: dict) -> bytes:
    """Canonical JSON encoding per spec section 6.

    UTF-8, sorted keys, tight separators, non-escaped Unicode, no NaN/Inf,
    no floats, no Unicode normalization. Lists keep their order (semantic),
    object keys are sorted (syntactic).
    """
    if not isinstance(body, dict):
        raise CanonicalizationError("canonical JSON requires a top-level object")
    _validate_plain(body, "$")
    return json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_bytes_from_json(data: Any) -> bytes:
    """Parse strict JSON (duplicate keys rejected) then canonicalize."""
    return canonical_bytes(parse_strict_json(data))


def domain_separator(domain: str) -> bytes:
    """Domain-separation prefix: ``domain + NUL``. Unknown domains are refused."""
    if domain not in KNOWN_DOMAINS:
        raise ValueError(f"unknown signature domain: {domain!r}")
    return domain.encode("utf-8") + _NUL


def signing_payload(domain: str, body: dict) -> bytes:
    """The exact byte string covered by an Ed25519 signature."""
    return domain_separator(domain) + canonical_bytes(body)


# ---------------------------------------------------------------------------
# key encoding (public material only)
# ---------------------------------------------------------------------------


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    """base64 of the raw 32-byte Ed25519 public key."""
    raw = public_key.public_bytes_raw()
    if len(raw) != _ED25519_KEY_LEN:
        raise ValueError("unexpected Ed25519 public key length")
    return base64.b64encode(raw).decode("ascii")


def decode_public_key(value: str) -> Ed25519PublicKey:
    """Decode a base64 raw Ed25519 public key (registry format)."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustRegistryError("registry public_key is not valid base64") from exc
    if len(raw) != _ED25519_KEY_LEN:
        raise TrustRegistryError("registry public_key must be 32 raw bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_payload_bytes(private_key: Ed25519PrivateKey, domain: str, body: dict) -> str:
    """Sign and return the base64 signature. Private key is never exposed."""
    signature = private_key.sign(signing_payload(domain, body))
    return base64.b64encode(signature).decode("ascii")


def verify_payload_bytes(public_key: Ed25519PublicKey, domain: str, body: dict,
                         signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(signature) != 64:
        return False
    try:
        public_key.verify(signature, signing_payload(domain, body))
        return True
    except InvalidSignature:
        return False


def envelope_digest(envelope: dict) -> str:
    """sha256 hex digest over the canonical encoding of the full envelope.

    Changing the signature alone (with an identical body) changes this
    digest, because the signature field is part of the canonical document.
    """
    return hashlib.sha256(canonical_bytes(envelope)).hexdigest()


# ---------------------------------------------------------------------------
# envelope / result models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedEnvelope:
    """``{body, algorithm: "Ed25519", signature: base64}``.

    The body carries ``institution_id`` / ``key_id`` / ``schema_version``;
    the signature covers the canonical form of the body only (the algorithm
    field and the domain prefix are part of the verification contract, not
    the signed bytes).
    """

    body: dict
    algorithm: str
    signature: str

    def to_dict(self) -> dict:
        return {"body": self.body, "algorithm": self.algorithm, "signature": self.signature}

    @classmethod
    def from_dict(cls, obj: Any) -> "SignedEnvelope":
        if not isinstance(obj, dict):
            raise CanonicalizationError("envelope must be a JSON object")
        algorithm = obj.get("algorithm")
        signature = obj.get("signature")
        body = obj.get("body")
        if algorithm != ALGORITHM:
            raise UnsupportedAlgorithmError(algorithm)
        if not isinstance(signature, str) or not signature:
            raise CanonicalizationError("envelope signature must be a non-empty string")
        if not isinstance(body, dict):
            raise CanonicalizationError("envelope body must be a JSON object")
        return cls(body=body, algorithm=algorithm, signature=signature)


class UnsupportedAlgorithmError(CanonicalizationError):
    def __init__(self, algorithm: Any):
        super().__init__(f"unsupported envelope algorithm: {algorithm!r}")
        self.algorithm = algorithm


@dataclass(frozen=True)
class SignatureResult:
    """Fixed-status verification outcome: verified | invalid | unavailable."""

    status: str
    reason: Optional[str] = None

    @property
    def is_verified(self) -> bool:
        return self.status == STATUS_VERIFIED


def _result_invalid(reason: str) -> SignatureResult:
    return SignatureResult(status=STATUS_INVALID, reason=reason)


def _result_unavailable(reason: str) -> SignatureResult:
    return SignatureResult(status=STATUS_UNAVAILABLE, reason=reason)


# ---------------------------------------------------------------------------
# trust registry (external, authoritative)
# ---------------------------------------------------------------------------


def _parse_datetime(value: Any, field: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise TrustRegistryError(f"{label}.{field} must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustRegistryError(f"{label}.{field} is not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise TrustRegistryError(f"{label}.{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class RegistryEntry:
    """One trusted key binding for one institution.

    ``public_key`` is base64 of the raw 32-byte Ed25519 public key.
    ``valid_from``/``valid_until`` delimit the validity window (start
    inclusive, end exclusive). ``revoked_at`` records when the key was
    revoked. ``invalid_from`` is the compromise horizon: signatures with a
    trusted_time at/after it are invalid; when it is missing on a
    compromised key, every signature of that key is invalid.
    """

    institution_id: str
    key_id: str
    public_key: str
    valid_from: datetime
    valid_until: datetime
    status: str
    revoked_at: Optional[datetime] = None
    invalid_from: Optional[datetime] = None
    public_key_obj: Optional[Ed25519PublicKey] = None

    @classmethod
    def from_mapping(cls, obj: Any) -> "RegistryEntry":
        if not isinstance(obj, dict):
            raise TrustRegistryError("registry entry must be a JSON object")
        institution_id = obj.get("institution_id")
        key_id = obj.get("key_id")
        public_key = obj.get("public_key")
        status = obj.get("status")
        if not isinstance(institution_id, str) or not institution_id:
            raise TrustRegistryError("registry entry requires institution_id")
        if not isinstance(key_id, str) or not key_id:
            raise TrustRegistryError("registry entry requires key_id")
        if not isinstance(public_key, str):
            raise TrustRegistryError(f"registry entry {institution_id}/{key_id} requires public_key")
        if status not in KNOWN_STATUSES:
            raise TrustRegistryError(
                f"registry entry {institution_id}/{key_id} has unknown status {status!r}"
            )
        label = f"registry entry {institution_id}/{key_id}"
        valid_from = _parse_datetime(obj.get("valid_from"), "valid_from", label)
        valid_until = _parse_datetime(obj.get("valid_until"), "valid_until", label)
        if valid_until <= valid_from:
            raise TrustRegistryError(f"{label}: valid_until must be after valid_from")
        revoked_at = obj.get("revoked_at")
        invalid_from = obj.get("invalid_from")
        return cls(
            institution_id=institution_id,
            key_id=key_id,
            public_key=public_key,
            valid_from=valid_from,
            valid_until=valid_until,
            status=status,
            revoked_at=_parse_datetime(revoked_at, "revoked_at", label) if revoked_at else None,
            invalid_from=(
                _parse_datetime(invalid_from, "invalid_from", label) if invalid_from else None
            ),
            public_key_obj=decode_public_key(public_key),
        )

    def to_mapping(self) -> dict:
        return {
            "institution_id": self.institution_id,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "status": self.status,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "invalid_from": self.invalid_from.isoformat() if self.invalid_from else None,
        }


class TrustRegistry:
    """In-memory view of the external trust registry document."""

    def __init__(self, entries=()):
        self._entries: dict = {}
        for entry in entries:
            if not isinstance(entry, RegistryEntry):
                entry = RegistryEntry.from_mapping(entry)
            key = (entry.institution_id, entry.key_id)
            if key in self._entries:
                raise TrustRegistryError(f"duplicate registry entry {key[0]}/{key[1]}")
            self._entries[key] = entry

    @classmethod
    def from_mapping(cls, obj: Any) -> "TrustRegistry":
        if not isinstance(obj, dict):
            raise TrustRegistryError("trust registry must be a JSON object")
        entries = obj.get("entries")
        if not isinstance(entries, list):
            raise TrustRegistryError("trust registry requires an entries list")
        return cls(entries)

    def get(self, institution_id: str, key_id: str) -> Optional[RegistryEntry]:
        return self._entries.get((institution_id, key_id))

    def entries(self):
        return tuple(self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# signer / verifier
# ---------------------------------------------------------------------------


class Signer:
    """Produces SignedEnvelopes using keys obtained from a KeyProvider.

    The provider is injected (duck-typed: ``get_signing_key``); this keeps a
    future KMS swap outside the signing logic.
    """

    def __init__(self, key_provider):
        self._key_provider = key_provider

    def sign(self, institution_id: str, domain: str, body: dict) -> SignedEnvelope:
        if not isinstance(institution_id, str) or not institution_id:
            raise ValueError("institution_id must be a non-empty string")
        if not isinstance(body, dict):
            raise ValueError("body must be a dict")
        body_institution = body.get("institution_id")
        if body_institution != institution_id:
            raise ValueError("body.institution_id must match the signing institution")
        key_id = body.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("body.key_id is required")
        if "schema_version" not in body:
            body = dict(body, schema_version=SCHEMA_VERSION)
        private_key = self._key_provider.get_signing_key(institution_id, key_id)
        signature = sign_payload_bytes(private_key, domain, body)
        return SignedEnvelope(body=body, algorithm=ALGORITHM, signature=signature)


class Verifier:
    """Fail-closed envelope verification against the external trust registry."""

    def verify(
        self,
        domain: str,
        envelope: Any,
        registry: Optional[TrustRegistry],
        trusted_time: Optional[datetime] = None,
    ) -> SignatureResult:
        # 1. domain discipline
        if domain not in KNOWN_DOMAINS:
            return _result_invalid(REASON_UNKNOWN_DOMAIN)
        # 2. envelope shape (dict or SignedEnvelope)
        if isinstance(envelope, SignedEnvelope):
            env = envelope
            if env.algorithm != ALGORITHM:
                return _result_invalid(REASON_UNSUPPORTED_ALGORITHM)
            if not isinstance(env.signature, str) or not env.signature:
                return _result_invalid(REASON_SIGNATURE_MALFORMED)
        else:
            try:
                env = SignedEnvelope.from_dict(envelope)
            except UnsupportedAlgorithmError:
                return _result_invalid(REASON_UNSUPPORTED_ALGORITHM)
            except CanonicalizationError:
                return _result_invalid(REASON_SIGNATURE_MALFORMED)
        body = env.body
        for field_name in _REQUIRED_BODY_FIELDS:
            if field_name not in body:
                return _result_invalid(REASON_BODY_FIELDS_MISSING)
        # 3. registry availability (fail-closed)
        if registry is None or not isinstance(registry, TrustRegistry):
            return _result_unavailable(REASON_REGISTRY_UNAVAILABLE)
        entry = registry.get(body["institution_id"], body["key_id"])
        if entry is None:
            return _result_unavailable(REASON_KEY_NOT_IN_REGISTRY)
        # 4. lifecycle policy
        if entry.status == STATUS_REVOKED:
            return _result_invalid(REASON_KEY_REVOKED)
        if entry.status == STATUS_COMPROMISED:
            if entry.invalid_from is None:
                # no compromise horizon known -> every signature invalid
                return _result_invalid(REASON_KEY_COMPROMISED_NO_INVALID_FROM)
            if trusted_time is None:
                # cannot place the signature before/after the horizon
                return _result_unavailable(REASON_TRUSTED_TIME_REQUIRED)
            if trusted_time >= entry.invalid_from:
                return _result_invalid(REASON_KEY_COMPROMISED)
        elif entry.status == STATUS_RETIRED and trusted_time is None:
            # retired keys accept statements only under external trusted_time
            return _result_unavailable(REASON_TRUSTED_TIME_REQUIRED)
        if trusted_time is not None:
            if trusted_time < entry.valid_from or trusted_time >= entry.valid_until:
                return _result_invalid(REASON_KEY_NOT_VALID_AT_TRUSTED_TIME)
        # 5. cryptographic check against the REGISTRY public key only
        if verify_payload_bytes(entry.public_key_obj, domain, body, env.signature):
            return SignatureResult(status=STATUS_VERIFIED, reason=None)
        return _result_invalid(REASON_SIGNATURE_MISMATCH)


# ---------------------------------------------------------------------------
# data-key wrapping (KeyProvider primitives; Ed25519 -> X25519 + HKDF + AES-GCM)
# ---------------------------------------------------------------------------


def x25519_from_ed25519_seed(private_key: Ed25519PrivateKey) -> X25519PrivateKey:
    """Derive the Curve25519 keypair from an Ed25519 seed.

    The 32-byte Ed25519 seed is used directly as the X25519 scalar (the
    libsodium ``crypto_scalarmult_base``-style conversion). Wrap and unwrap
    MUST both use this derivation so both sides land on the same Curve25519
    keypair for the institution's key. Note the resulting X25519 public key
    is NOT the Ed25519 public point -- it cannot be derived from the
    Ed25519 public key alone.
    """
    return X25519PrivateKey.from_private_bytes(private_key.private_bytes_raw())


def wrap_data_key(recipient_x25519_public_key: X25519PublicKey, dek: bytes) -> dict:
    """Wrap a data-encryption key to an institution's Curve25519 public key.

    The recipient public key must come from
    :func:`x25519_from_ed25519_seed(private).public_key()` -- i.e. derived
    from the same seed the holder will unwrap with. Returns a JSON-safe
    WrappedKey dict: ephemeral X25519 public key, nonce and ciphertext only
    -- no private material, no plaintext DEK.
    """
    if not isinstance(dek, (bytes, bytearray)) or not dek:
        raise ValueError("dek must be non-empty bytes")
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(recipient_x25519_public_key)
    nonce = os.urandom(12)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=_WRAP_INFO)
    aes_key = hkdf.derive(shared)
    ciphertext = AESGCM(aes_key).encrypt(nonce, bytes(dek), WRAP_ALGORITHM.encode("ascii"))
    return {
        "algorithm": WRAP_ALGORITHM,
        "ephemeral_public_key": base64.b64encode(
            ephemeral.public_key().public_bytes_raw()
        ).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def unwrap_data_key(recipient_private_key: Ed25519PrivateKey, wrapped: dict) -> bytes:
    """Unwrap a WrappedKey with the institution's Ed25519 private key."""
    if not isinstance(wrapped, dict) or wrapped.get("algorithm") != WRAP_ALGORITHM:
        raise ValueError("unsupported wrapped-key algorithm")
    try:
        ephemeral_raw = base64.b64decode(wrapped["ephemeral_public_key"], validate=True)
        nonce = base64.b64decode(wrapped["nonce"], validate=True)
        ciphertext = base64.b64decode(wrapped["ciphertext"], validate=True)
    except (binascii.Error, ValueError, KeyError) as exc:
        raise ValueError("malformed wrapped key") from exc
    if len(ephemeral_raw) != 32 or len(nonce) != 12:
        raise ValueError("malformed wrapped key")
    recipient = x25519_from_ed25519_seed(recipient_private_key)
    shared = recipient.exchange(X25519PublicKey.from_public_bytes(ephemeral_raw))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=_WRAP_INFO)
    aes_key = hkdf.derive(shared)
    try:
        return AESGCM(aes_key).decrypt(nonce, ciphertext, WRAP_ALGORITHM.encode("ascii"))
    except InvalidTag as exc:
        raise ValueError("wrapped key failed authentication") from exc
