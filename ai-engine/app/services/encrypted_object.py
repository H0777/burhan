"""
Encrypted object primitives (R06) — spec §6.

AES-256-GCM envelope encryption for evidence objects:

- A fresh random 256-bit data-encryption key (DEK) per object. The DEK is
  used once in-process and is never stored anywhere in plaintext.
- The DEK is wrapped to the institution's external key via the R05
  ``KeyProvider`` (``wrap_data_key`` -> X25519 + HKDF-SHA256 + AES-256-GCM),
  and stored only in wrapped form together with the ``key_id`` that wrapped
  it. Rotation therefore never rewrites old objects: each object records the
  key that wrapped it and keeps decrypting with that retained key.
- The GCM AAD (additional authenticated data) canonically binds the three
  address dimensions — institution_id, evidence_id, object_version — so a
  ciphertext moved to another address, or decrypted under a different
  institution / version, fails the authentication tag.

Ciphertext layout per object (produced by :func:`encrypt_bytes`):

    nonce (12 bytes) || ciphertext || auth_tag (16 bytes)

where ``ciphertext`` and ``auth_tag`` are stored separately in the vault
(``object.bin`` holds ciphertext only; the tag lives in the metadata) and
recombined only in-process for verification.

Fail-closed: every decryption error — wrong key, tampered ciphertext, wrong
nonce/tag, wrong AAD dimension — raises before any plaintext is returned.
"""

from __future__ import annotations

import base64
import os
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.security.signing import canonical_bytes, load_evidence_crypto

_ec = load_evidence_crypto()
wrap_data_key = _ec.wrap_data_key
unwrap_data_key = _ec.unwrap_data_key

STORAGE_FORMAT = "aes256gcm_v1"
LEGACY_PLAINTEXT_FORMAT = "legacy_plaintext_read_only"
LEGACY_UNATTESTED_FORMAT = "legacy_unattested"
WRAP_ALGORITHM = _ec.WRAP_ALGORITHM

DEK_SIZE = 32       # AES-256
NONCE_SIZE = 12     # GCM standard nonce
TAG_SIZE = 16       # GCM auth tag


class EncryptedObjectError(Exception):
    """Base class for encrypted-object failures (fail-closed)."""


class MissingKeyMaterialError(EncryptedObjectError):
    """The institution key needed to wrap/unwrap the DEK is unavailable."""


class MalformedMetadataError(EncryptedObjectError):
    """The object's encryption metadata is missing required fields."""


class InvalidCiphertextError(EncryptedObjectError):
    """GCM authentication failed: tampered ciphertext/tag/nonce, wrong key,
    or wrong AAD binding."""


def compute_aad(institution_id: str, evidence_id: str, object_version: int) -> bytes:
    """Canonical AAD binding institution + evidence + version.

    Uses the R05 canonical-JSON encoder so the binding bytes are stable
    across processes and platforms. Any change to any of the three
    dimensions changes the AAD and fails the GCM tag.
    """
    payload = {
        "evidence_id": str(evidence_id),
        "institution_id": str(institution_id),
        "object_version": int(object_version),
    }
    return canonical_bytes(payload)


def encrypt_bytes(
    plaintext: bytes,
    *,
    institution_id: str,
    evidence_id: str,
    object_version: int,
    key_provider,
) -> Dict[str, Any]:
    """Encrypt one object under a fresh random DEK wrapped to the institution.

    Returns a JSON-safe metadata fragment (nonce/auth_tag base64, wrapped DEK,
    key id) plus the raw ciphertext under ``"ciphertext"``. The plaintext DEK
    exists only inside this call frame and is never included in the result.
    """
    if key_provider is None:
        raise MissingKeyMaterialError("no key provider configured; refusing unencrypted write")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    dek = os.urandom(DEK_SIZE)
    try:
        # Wrap FIRST: the plaintext DEK never leaves this frame unwrapped.
        try:
            wrapped = key_provider.wrap_data_key(institution_id, dek)
        except AttributeError:
            raise MissingKeyMaterialError("key provider does not support wrap_data_key") from None
        key_id = wrapped.get("recipient_key_id")
        if not isinstance(key_id, str) or not key_id:
            raise MissingKeyMaterialError("wrapped key is missing recipient_key_id")

        nonce = os.urandom(NONCE_SIZE)
        aad = compute_aad(institution_id, evidence_id, object_version)
        sealed = AESGCM(dek).encrypt(nonce, bytes(plaintext), aad)
    finally:
        del dek  # drop our reference; the DEK is never persisted in the clear
    ciphertext, auth_tag = sealed[:-TAG_SIZE], sealed[-TAG_SIZE:]

    return {
        "ciphertext": ciphertext,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "auth_tag": base64.b64encode(auth_tag).decode("ascii"),
        "wrapped_dek": wrapped,
        "encryption_key_id": key_id,
        "storage_format": STORAGE_FORMAT,
    }


def decrypt_bytes(
    ciphertext: bytes,
    *,
    nonce: bytes,
    auth_tag: bytes,
    wrapped_dek: Dict[str, Any],
    institution_id: str,
    evidence_id: str,
    object_version: int,
    key_provider,
) -> bytes:
    """Verify and decrypt one object. Fail-closed on any mismatch.

    The plaintext is produced only if the GCM tag verifies against the AAD
    bound to exactly (institution_id, evidence_id, object_version) and the
    DEK unwraps under the institution's key.
    """
    if key_provider is None:
        raise MissingKeyMaterialError("no key provider configured; refusing decryption")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    if len(nonce) != NONCE_SIZE:
        raise MalformedMetadataError(f"nonce must be {NONCE_SIZE} bytes")
    if len(auth_tag) != TAG_SIZE:
        raise MalformedMetadataError(f"auth_tag must be {TAG_SIZE} bytes")

    try:
        dek = key_provider.unwrap_data_key(institution_id, wrapped_dek)
    except KeyError as exc:
        raise MissingKeyMaterialError(
            f"institution key unavailable for {institution_id}: {exc}"
        ) from exc
    except ValueError as exc:
        raise InvalidCiphertextError(f"wrapped DEK failed authentication: {exc}") from exc

    aad = compute_aad(institution_id, evidence_id, object_version)
    sealed = bytes(ciphertext) + bytes(auth_tag)
    try:
        return AESGCM(dek).decrypt(nonce, sealed, aad)
    except InvalidTag as exc:
        raise InvalidCiphertextError(
            "GCM authentication failed: ciphertext, tag, nonce, key or AAD binding mismatch"
        ) from exc
    finally:
        del dek


__all__ = [
    "STORAGE_FORMAT",
    "LEGACY_PLAINTEXT_FORMAT",
    "LEGACY_UNATTESTED_FORMAT",
    "WRAP_ALGORITHM",
    "DEK_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "EncryptedObjectError",
    "MissingKeyMaterialError",
    "MalformedMetadataError",
    "InvalidCiphertextError",
    "compute_aad",
    "encrypt_bytes",
    "decrypt_bytes",
]
