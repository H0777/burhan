"""Server-facing key-provider interface (R05).

The ``KeyProvider`` interface isolates signing/wrapping key access so a
future KMS swap does not touch signing or verification logic. The local
arrangement (spec §6, interim): secret files are mounted READ-ONLY outside
the repository, owned by the service account; key material is never
returned inside API responses and never logged. See
``docs/runbooks/key-management.md``.

Crypto primitives (Ed25519 -> X25519 + HKDF-SHA256 + AES-256-GCM wrapping)
come from the shared module ``shared/python/evidence_crypto.py`` loaded from
a fixed path relative to the distribution — never a ZIP-chosen path.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security.signing import (
    load_evidence_crypto,
    unwrap_data_key,
    wrap_data_key,
    x25519_from_ed25519_seed,
)

_ec = load_evidence_crypto()

_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SEED_LEN = 32


class KeyProvider(ABC):
    """Interface isolating key custody (local files today, KMS tomorrow)."""

    @abstractmethod
    def get_signing_key(self, institution_id: str, key_id: str) -> Ed25519PrivateKey:
        """Return the signing key object for (institution_id, key_id).

        Fail-closed: raises ``KeyError`` when the key is unknown. The object
        stays in-process; it must never be serialized into a response.
        """

    @abstractmethod
    def wrap_data_key(self, institution_id: str, dek: bytes) -> dict:
        """Wrap a data-encryption key to the institution's current key."""

    @abstractmethod
    def unwrap_data_key(self, institution_id: str, wrapped: dict) -> bytes:
        """Unwrap a WrappedKey produced by :meth:`wrap_data_key`."""

    @abstractmethod
    def get_current_key_id(self, institution_id: str) -> str:
        """Return the key id currently used for new envelopes/wrapping."""


def _validate_component(value: str, label: str) -> str:
    if not isinstance(value, str) or not _COMPONENT_RE.match(value):
        raise ValueError(f"invalid key-provider {label}: {value!r}")
    return value


class LocalFileKeyProvider(KeyProvider):
    """Read-only seed-file key custody outside the repository.

    Layout under ``base_dir``::

        <base_dir>/<institution_id>/<key_id>.seed   (32 raw Ed25519 bytes)
        <base_dir>/<institution_id>/current          (optional pointer file)

    The mount is expected to be read-only for the service account and
    outside the repository tree (runbook: key-management). Missing keys,
    ambiguous current-key selection and path traversal all fail closed.
    """

    def __init__(self, base_dir: Union[str, Path]):
        self._base_dir = Path(base_dir).resolve()
        if not self._base_dir.is_dir():
            raise FileNotFoundError(f"key base directory not found: {self._base_dir}")

    @property
    def base_dir(self) -> Path:
        """Resolved base directory (path only — never key material)."""
        return self._base_dir

    def _institution_dir(self, institution_id: str) -> Path:
        _validate_component(institution_id, "institution_id")
        path = (self._base_dir / institution_id).resolve()
        if path != self._base_dir and self._base_dir not in path.parents:
            raise ValueError("resolved key path escapes the key base directory")
        return path

    def _seed_path(self, institution_id: str, key_id: str) -> Path:
        _validate_component(key_id, "key_id")
        path = (self._institution_dir(institution_id) / f"{key_id}.seed").resolve()
        if self._base_dir not in path.parents:
            raise ValueError("resolved key path escapes the key base directory")
        return path

    def get_signing_key(self, institution_id: str, key_id: str) -> Ed25519PrivateKey:
        seed_path = self._seed_path(institution_id, key_id)
        try:
            seed = seed_path.read_bytes()
        except FileNotFoundError:
            raise KeyError(f"no signing key mounted for {institution_id}/{key_id}") from None
        except OSError as exc:
            raise KeyError(f"signing key unreadable for {institution_id}/{key_id}") from exc
        if len(seed) != _SEED_LEN:
            raise KeyError(f"signing key for {institution_id}/{key_id} must be { _SEED_LEN } raw bytes")
        return Ed25519PrivateKey.from_private_bytes(seed)

    def get_current_key_id(self, institution_id: str) -> str:
        institution_dir = self._institution_dir(institution_id)
        pointer = institution_dir / "current"
        if pointer.is_file():
            key_id = pointer.read_text(encoding="utf-8").strip()
            _validate_component(key_id, "current-key pointer")
            return key_id
        seeds = sorted(p.stem for p in institution_dir.glob("*.seed")) if institution_dir.is_dir() else []
        if len(seeds) == 1:
            return seeds[0]
        raise KeyError(
            f"no unambiguous current key for {institution_id}: "
            "provide a 'current' pointer file or exactly one *.seed"
        )

    def wrap_data_key(self, institution_id: str, dek: bytes) -> dict:
        key_id = self.get_current_key_id(institution_id)
        private_key = self.get_signing_key(institution_id, key_id)
        recipient = x25519_from_ed25519_seed(private_key).public_key()
        wrapped = wrap_data_key(recipient, dek)
        return dict(wrapped, recipient_key_id=key_id)

    def unwrap_data_key(self, institution_id: str, wrapped: dict) -> bytes:
        if not isinstance(wrapped, dict):
            raise ValueError("wrapped key must be a dict")
        key_id = wrapped.get("recipient_key_id")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("wrapped key is missing recipient_key_id")
        private_key = self.get_signing_key(institution_id, key_id)
        return unwrap_data_key(private_key, wrapped)


__all__ = ["KeyProvider", "LocalFileKeyProvider"]
