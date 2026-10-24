"""Server-facing signing interface (R05) — thin wrapper over the shared module.

The AI engine and the offline verifier MUST use the same primitives, so this
module only re-exports ``shared/python/evidence_crypto.py``. The shared
module is loaded from a fixed path relative to the distribution layout
(walking up from this file's location) — never from a caller- or
ZIP-chosen path.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SHARED_RELPATH = ("shared", "python", "evidence_crypto.py")
_MODULE_NAME = "evidence_crypto"


def _load_evidence_crypto():
    """Load the shared evidence-crypto module from the fixed distribution path.

    The walk is bounded to ancestors of this file, so untrusted input (e.g. an
    uploaded ZIP) can never choose the code path that gets executed.
    """
    existing = sys.modules.get(_MODULE_NAME)
    if existing is not None and getattr(existing, "__file__", None):
        return existing
    anchor = Path(__file__).resolve()
    for parent in (anchor, *anchor.parents):
        candidate = parent.joinpath(*_SHARED_RELPATH)
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location(_MODULE_NAME, candidate)
            if spec is None or spec.loader is None:  # pragma: no cover
                raise RuntimeError(f"cannot build import spec for {candidate}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[_MODULE_NAME] = module
            spec.loader.exec_module(module)
            return module
    raise RuntimeError(
        "shared/python/evidence_crypto.py not found relative to the distribution "
        "layout; refusing ZIP-chosen or caller-supplied paths"
    )


_ec = _load_evidence_crypto()

# --- re-exports (single source of truth: shared/python/evidence_crypto.py) ---
ALGORITHM = _ec.ALGORITHM
WRAP_ALGORITHM = _ec.WRAP_ALGORITHM
SCHEMA_VERSION = _ec.SCHEMA_VERSION

DOMAIN_SERVICE_MANIFEST = _ec.DOMAIN_SERVICE_MANIFEST
DOMAIN_DOSSIER = _ec.DOMAIN_DOSSIER
DOMAIN_BACKUP = _ec.DOMAIN_BACKUP
KNOWN_DOMAINS = _ec.KNOWN_DOMAINS

STATUS_VERIFIED = _ec.STATUS_VERIFIED
STATUS_INVALID = _ec.STATUS_INVALID
STATUS_UNAVAILABLE = _ec.STATUS_UNAVAILABLE

CanonicalizationError = _ec.CanonicalizationError
DuplicateJsonKeyError = _ec.DuplicateJsonKeyError
TrustRegistryError = _ec.TrustRegistryError
UnsupportedAlgorithmError = _ec.UnsupportedAlgorithmError

SignedEnvelope = _ec.SignedEnvelope
SignatureResult = _ec.SignatureResult
Signer = _ec.Signer
Verifier = _ec.Verifier
TrustRegistry = _ec.TrustRegistry
RegistryEntry = _ec.RegistryEntry

canonical_bytes = _ec.canonical_bytes
canonical_bytes_from_json = _ec.canonical_bytes_from_json
parse_strict_json = _ec.parse_strict_json
signing_payload = _ec.signing_payload
domain_separator = _ec.domain_separator
envelope_digest = _ec.envelope_digest
encode_public_key = _ec.encode_public_key
decode_public_key = _ec.decode_public_key
sign_payload_bytes = _ec.sign_payload_bytes
verify_payload_bytes = _ec.verify_payload_bytes
wrap_data_key = _ec.wrap_data_key
unwrap_data_key = _ec.unwrap_data_key
x25519_from_ed25519_seed = _ec.x25519_from_ed25519_seed

load_evidence_crypto = _load_evidence_crypto

__all__ = [
    "ALGORITHM", "WRAP_ALGORITHM", "SCHEMA_VERSION",
    "DOMAIN_SERVICE_MANIFEST", "DOMAIN_DOSSIER", "DOMAIN_BACKUP", "KNOWN_DOMAINS",
    "STATUS_VERIFIED", "STATUS_INVALID", "STATUS_UNAVAILABLE",
    "CanonicalizationError", "DuplicateJsonKeyError", "TrustRegistryError",
    "UnsupportedAlgorithmError",
    "SignedEnvelope", "SignatureResult", "Signer", "Verifier",
    "TrustRegistry", "RegistryEntry",
    "canonical_bytes", "canonical_bytes_from_json", "parse_strict_json",
    "signing_payload", "domain_separator", "envelope_digest",
    "encode_public_key", "decode_public_key",
    "sign_payload_bytes", "verify_payload_bytes",
    "wrap_data_key", "unwrap_data_key", "x25519_from_ed25519_seed",
    "load_evidence_crypto",
]
