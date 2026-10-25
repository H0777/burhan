"""Server-facing trust-registry interface (R05) — thin wrapper over the shared module.

The registry document is external and authoritative (spec §6): it is mounted
or supplied by the operator, never extracted from a ZIP. This module exposes
loading/typing helpers; the signing primitives live in
``shared/python/evidence_crypto.py`` loaded from a fixed distribution path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from app.security.signing import (
    RegistryEntry,
    TrustRegistry,
    TrustRegistryError,
    load_evidence_crypto,
    parse_strict_json,
)

_ec = load_evidence_crypto()

STATUS_ACTIVE = _ec.STATUS_ACTIVE
STATUS_RETIRED = _ec.STATUS_RETIRED
STATUS_REVOKED = _ec.STATUS_REVOKED
STATUS_COMPROMISED = _ec.STATUS_COMPROMISED
KNOWN_STATUSES = _ec.KNOWN_STATUSES


def load_registry(path: Union[str, Path]) -> TrustRegistry:
    """Load and validate a trust-registry JSON document (fail-closed).

    Raises ``FileNotFoundError`` / ``ValueError`` (``TrustRegistryError``) on
    missing or invalid documents — callers must treat that as
    ``unavailable``, never as "verify without registry".
    """
    document = parse_strict_json(Path(path).read_text(encoding="utf-8"))
    return TrustRegistry.from_mapping(document)


def load_registry_entry(obj: dict) -> RegistryEntry:
    """Validate a single registry entry mapping."""
    return RegistryEntry.from_mapping(obj)


def default_registry_document_schema_path() -> Path:
    """Fixed path of the registry JSON Schema, relative to the distribution."""
    module = load_evidence_crypto()
    return Path(module.__file__).resolve().parents[2] / "shared" / "schemas" / "trust-registry-v1.schema.json"


__all__ = [
    "RegistryEntry", "TrustRegistry", "TrustRegistryError",
    "STATUS_ACTIVE", "STATUS_RETIRED", "STATUS_REVOKED", "STATUS_COMPROMISED",
    "KNOWN_STATUSES", "load_registry", "load_registry_entry",
    "default_registry_document_schema_path",
]
