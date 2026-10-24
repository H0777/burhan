"""R05 — Ed25519 signing, canonical JSON and external trust registry.

Spec §6 semantics under test:
- signature = Ed25519(domain + NUL + canonical_bytes(body)); domains are the
  three fixed AML_* constants; Ed25519 via ``cryptography`` only (no HMAC).
- canonical JSON: UTF-8, sort_keys=True, separators=(",",":"),
  ensure_ascii=False, allow_nan=False; no floats, no duplicate JSON keys,
  no Unicode normalization (Arabic text survives byte-for-byte).
- Trust registry is external and authoritative: embedded key material in an
  envelope is never trusted. compromised invalidates from ``invalid_from``
  (missing ``invalid_from`` -> every signature of that key is invalid).
  retired is accepted only with an external trusted_time; a date taken from
  inside a ZIP is never trusted_time. Fail-closed on missing key/registry.

All keys in this suite are generated at runtime or loaded from the clearly
synthetic test fixture (``shared/fixtures/signatures-v1.json``); no real
institution key material exists in this repository.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security.key_provider import LocalFileKeyProvider
from app.security.signing import (
    ALGORITHM,
    CanonicalizationError,
    DOMAIN_BACKUP,
    DOMAIN_DOSSIER,
    DOMAIN_SERVICE_MANIFEST,
    DuplicateJsonKeyError,
    SignatureResult,
    SignedEnvelope,
    Signer,
    TrustRegistry,
    Verifier,
    canonical_bytes,
    canonical_bytes_from_json,
    envelope_digest,
    parse_strict_json,
)
from app.security.trust_registry import RegistryEntry, load_registry

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "shared" / "fixtures" / "signatures-v1.json"

T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def new_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")


def registry_entry_dict(inst: str, key: Ed25519PrivateKey, status: str = "active", **overrides):
    entry = {
        "institution_id": inst,
        "key_id": f"{inst}-K1",
        "public_key": pub_b64(key),
        "valid_from": (T0 - timedelta(days=365)).isoformat(),
        "valid_until": (T0 + timedelta(days=3650)).isoformat(),
        "status": status,
        "revoked_at": None,
        "invalid_from": None,
    }
    entry.update(overrides)
    return entry


def make_registry(*entries) -> TrustRegistry:
    return TrustRegistry.from_mapping(
        {"schema_version": 1, "entries": list(entries)},
    )


class FixedKeyProvider:
    """Test double satisfying the KeyProvider interface from an in-memory map."""

    def __init__(self, keys):
        self._keys = keys  # {(institution_id, key_id): Ed25519PrivateKey}

    def get_signing_key(self, institution_id: str, key_id: str) -> Ed25519PrivateKey:
        try:
            return self._keys[(institution_id, key_id)]
        except KeyError:
            raise KeyError(f"no signing key for {institution_id}/{key_id}") from None

    def get_current_key_id(self, institution_id: str) -> str:
        candidates = [k for (i, k) in self._keys if i == institution_id]
        if len(candidates) != 1:
            raise KeyError(f"ambiguous current key for {institution_id}")
        return candidates[0]

    def wrap_data_key(self, institution_id: str, dek: bytes) -> dict:
        from app.security.signing import wrap_data_key

        key_id = self.get_current_key_id(institution_id)
        wrapped = wrap_data_key(self.get_signing_key(institution_id, key_id).public_key(), dek)
        wrapped["recipient_key_id"] = key_id
        return wrapped

    def unwrap_data_key(self, institution_id: str, wrapped: dict) -> bytes:
        from app.security.signing import unwrap_data_key

        return unwrap_data_key(self.get_signing_key(institution_id, wrapped["recipient_key_id"]), wrapped)


def make_provider(keys_by_inst):
    """keys_by_inst: {institution_id: (key_id, Ed25519PrivateKey)}"""
    return FixedKeyProvider({(i, kid): k for i, (kid, k) in keys_by_inst.items()})


def make_body(inst="INST-A", key_id="INST-A-K1", **extra):
    body = {
        "institution_id": inst,
        "key_id": key_id,
        "schema_version": 1,
        "manifest": {
            "service": "ai-engine",
            "statement_ar": "إفادة خدمة التدقيق المالي",
            "total_cases": 12,
        },
    }
    body.update(extra)
    return body


def sign_env(provider, inst, key_id, body, domain=DOMAIN_SERVICE_MANIFEST):
    signer = Signer(provider)
    return signer.sign(inst, domain, body)


# ---------------------------------------------------------------------------
# core signature semantics
# ---------------------------------------------------------------------------


def test_tampered_byte_invalid():
    key_a = new_key()
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    registry = make_registry(registry_entry_dict("INST-A", key_a))

    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())
    assert Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, T0).status == "verified"

    # tamper one byte of the body (as received, e.g. after decode/re-encode)
    tampered_body = dict(env.body)
    tampered_body["manifest"] = dict(env.body["manifest"])
    tampered_body["manifest"]["total_cases"] = 13
    env_t = {"body": tampered_body, "algorithm": env.algorithm, "signature": env.signature}
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env_t, registry, T0)
    assert result.status == "invalid"
    assert result.reason == "signature_mismatch"

    # tamper the signature itself
    raw = bytearray(base64.b64decode(env.signature))
    raw[0] ^= 0x01
    env_s = {"body": env.body, "algorithm": env.algorithm,
             "signature": base64.b64encode(bytes(raw)).decode("ascii")}
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env_s, registry, T0)
    assert result.status == "invalid"


def test_wrong_institution_key_invalid():
    key_a = new_key()
    key_b = new_key()
    registry = make_registry(
        registry_entry_dict("INST-A", key_a),
        registry_entry_dict("INST-B", key_b),
    )
    # Envelope claims institution B and B's registered key_id, but was signed
    # with A's private key (provider confusion / malicious signer).
    provider = make_provider({"INST-B": ("INST-B-K1", key_a)})
    env = sign_env(provider, "INST-B", "INST-B-K1", make_body("INST-B", "INST-B-K1"))
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, T0)
    assert result.status == "invalid"
    assert result.reason == "signature_mismatch"


def test_wrong_domain_invalid():
    key_a = new_key()
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    registry = make_registry(registry_entry_dict("INST-A", key_a))
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body(), domain=DOMAIN_DOSSIER)
    # same envelope verified under a different (valid) domain must fail:
    # the domain separator is bound into the signature.
    result = Verifier().verify(DOMAIN_BACKUP, env, registry, T0)
    assert result.status == "invalid"
    assert result.reason == "signature_mismatch"


def test_missing_registry_unavailable():
    key_a = new_key()
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())

    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, None, T0)
    assert result.status == "unavailable"
    assert result.reason == "registry_unavailable"

    # empty registry: key unknown -> fail-closed, not "valid"
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, make_registry(), T0)
    assert result.status == "unavailable"
    assert result.reason == "key_not_in_registry"

    # loading the registry itself fail-closed: missing file raises
    with pytest.raises(FileNotFoundError):
        load_registry(REPO_ROOT / "shared" / "fixtures" / "does-not-exist.json")


def test_embedded_key_not_trusted():
    key_a = new_key()          # registered institutional key
    attacker = new_key()       # NOT in the registry
    registry = make_registry(registry_entry_dict("INST-A", key_a))
    provider = make_provider({"INST-A": ("INST-A-K1", attacker)})

    # attacker embeds their own public key in the body and signs with it
    body = make_body("INST-A", "INST-A-K1", public_key=pub_b64(attacker))
    env = sign_env(provider, "INST-A", "INST-A-K1", body)
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, T0)
    assert result.status == "invalid"
    assert result.reason == "signature_mismatch"

    # even a fully attacker-controlled extra algorithm/field does not help:
    # verification uses only the registry public key.
    env_dict = env.to_dict()
    env_dict["public_key"] = pub_b64(attacker)
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env_dict, registry, T0)
    assert result.status == "invalid"


# ---------------------------------------------------------------------------
# canonical JSON rules
# ---------------------------------------------------------------------------


def test_duplicate_json_key_rejected():
    with pytest.raises(DuplicateJsonKeyError):
        parse_strict_json('{"a": 1, "a": 2}')
    with pytest.raises(DuplicateJsonKeyError):
        parse_strict_json('{"outer": {"x": 1, "x": 2}}')
    with pytest.raises(DuplicateJsonKeyError):
        canonical_bytes_from_json(b'{"institution_id": "A", "institution_id": "B"}')


def test_float_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"amount": 1.5})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"nested": {"list": [1, 2, 3.25]}})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"nan": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"inf": float("inf")})
    # integers and booleans are fine
    canonical_bytes({"count": 3, "flag": True, "none": None})


# ---------------------------------------------------------------------------
# registry lifecycle: retired / compromised
# ---------------------------------------------------------------------------


def test_retired_key_requires_trusted_time():
    key_a = new_key()
    registry = make_registry(registry_entry_dict("INST-A", key_a, status="retired"))
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())

    # no external trusted_time -> fail-closed (a date from inside a ZIP is
    # never trusted_time; the caller must pass one explicitly)
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, None)
    assert result.status == "unavailable"
    assert result.reason == "trusted_time_required"

    # external trusted_time inside the validity window -> accepted
    inside = datetime(2026, 6, 1, tzinfo=timezone.utc)
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, inside)
    assert result.status == "verified"

    # outside the window -> invalid even with trusted_time
    after = datetime(2036, 6, 1, tzinfo=timezone.utc)
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, after)
    assert result.status == "invalid"
    assert result.reason == "key_not_valid_at_trusted_time"


def test_compromised_key_rejects_from_invalid_from():
    key_a = new_key()
    invalid_from = T0 + timedelta(days=100)
    registry = make_registry(
        registry_entry_dict(
            "INST-A", key_a, status="compromised",
            invalid_from=invalid_from.isoformat(),
        )
    )
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())

    # at and after invalid_from -> invalid
    at = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, invalid_from)
    assert at.status == "invalid" and at.reason == "key_compromised"
    after = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, env, registry, invalid_from + timedelta(days=1)
    )
    assert after.status == "invalid" and after.reason == "key_compromised"

    # strictly before invalid_from the compromise does not invalidate:
    # falls through to window + crypto checks
    before = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, env, registry, invalid_from - timedelta(seconds=1)
    )
    assert before.status == "verified"

    # trusted_time unknown + compromised known -> fail-closed
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, None)
    assert result.status == "unavailable"
    assert result.reason == "trusted_time_required"

    # missing invalid_from -> ALL signatures of that key are invalid
    registry_no_if = make_registry(registry_entry_dict("INST-A", key_a, status="compromised"))
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry_no_if, invalid_from - timedelta(days=10))
    assert result.status == "invalid"
    assert result.reason == "key_compromised_no_invalid_from"
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry_no_if, None)
    assert result.status == "invalid"
    assert result.reason == "key_compromised_no_invalid_from"


# ---------------------------------------------------------------------------
# expiry and second boundaries
# ---------------------------------------------------------------------------


def test_key_expiry_boundary_second():
    key_a = new_key()
    start = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 3, 1, 12, 0, 10, tzinfo=timezone.utc)  # valid 10 seconds
    registry = make_registry(
        registry_entry_dict("INST-A", key_a, valid_from=start.isoformat(), valid_until=end.isoformat())
    )
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())

    one_second_before_start = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, env, registry, start - timedelta(seconds=1)
    )
    assert one_second_before_start.status == "invalid"
    assert one_second_before_start.reason == "key_not_valid_at_trusted_time"

    at_start = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, start)
    assert at_start.status == "verified"  # valid_from is inclusive

    one_second_before_end = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, env, registry, end - timedelta(seconds=1)
    )
    assert one_second_before_end.status == "verified"

    at_end = Verifier().verify(DOMAIN_SERVICE_MANIFEST, env, registry, end)
    assert at_end.status == "invalid"  # valid_until is exclusive
    assert at_end.reason == "key_not_valid_at_trusted_time"

    one_second_after_end = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, env, registry, end + timedelta(seconds=1)
    )
    assert one_second_after_end.status == "invalid"


# ---------------------------------------------------------------------------
# envelope digest sensitivity
# ---------------------------------------------------------------------------


def test_signature_change_alters_envelope_digest():
    key_a = new_key()
    key_b = new_key()
    provider = make_provider({
        "INST-A": ("INST-A-K1", key_a),
        "INST-B": ("INST-B-K1", key_b),
    })
    body = make_body("INST-A", "INST-A-K1")
    env_a = sign_env(provider, "INST-A", "INST-A-K1", body)
    # identical body (same key_id etc.), different signing key -> different
    # signature; the envelope digest must change even though the body did not.
    env_b = sign_env(provider, "INST-B", "INST-B-K1", json.loads(json.dumps(body)))

    assert canonical_bytes(env_a.body) == canonical_bytes(env_b.body)
    assert env_a.signature != env_b.signature
    assert envelope_digest(env_a.to_dict()) != envelope_digest(env_b.to_dict())
    # digest is stable for the identical envelope
    assert envelope_digest(env_a.to_dict()) == envelope_digest(env_a.to_dict())


# ---------------------------------------------------------------------------
# domain discipline
# ---------------------------------------------------------------------------


def test_unknown_domain_rejected():
    key_a = new_key()
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    registry = make_registry(registry_entry_dict("INST-A", key_a))
    with pytest.raises(ValueError):
        sign_env(provider, "INST-A", "INST-A-K1", make_body(), domain="AML_MADE_UP_V1")
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())
    result = Verifier().verify("AML_MADE_UP_V1", env, registry, T0)
    assert result.status == "invalid"
    assert result.reason == "unknown_domain"


def test_algorithm_field_enforced():
    key_a = new_key()
    provider = make_provider({"INST-A": ("INST-A-K1", key_a)})
    registry = make_registry(registry_entry_dict("INST-A", key_a))
    env = sign_env(provider, "INST-A", "INST-A-K1", make_body())
    forged = env.to_dict()
    forged["algorithm"] = "none"  # historical "alg=none" style downgrade
    result = Verifier().verify(DOMAIN_SERVICE_MANIFEST, forged, registry, T0)
    assert result.status == "invalid"
    assert result.reason == "unsupported_algorithm"


# ---------------------------------------------------------------------------
# fixtures: synthetic keys, JSON key order invariance, Arabic integrity
# ---------------------------------------------------------------------------


def test_fixture_envelope_verifies_and_key_order_is_irrelevant():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert fixture["note"].startswith("SYNTHETIC TEST FIXTURE")
    registry = TrustRegistry.from_mapping(fixture["trust_registry"])
    case = fixture["envelopes"][0]
    env = case["envelope"]

    result = Verifier().verify(case["domain"], env, registry, datetime.now(timezone.utc))
    assert result.status == "verified"

    # rebuild the body with every object's keys in reverse insertion order:
    # the canonical digest must not change.
    def reversed_keys(obj):
        if isinstance(obj, dict):
            return {k: reversed_keys(obj[k]) for k in reversed(list(obj))}
        if isinstance(obj, list):
            return [reversed_keys(v) for v in obj]
        return obj

    reordered = reversed_keys(env["body"])
    assert list(reordered.keys()) != list(env["body"].keys())
    assert canonical_bytes(reordered) == canonical_bytes(env["body"])
    tampered = {"body": reordered, "algorithm": env["algorithm"], "signature": env["signature"]}
    result = Verifier().verify(case["domain"], tampered, registry, datetime.now(timezone.utc))
    assert result.status == "verified"


def test_arabic_text_survives_canonical_encoding():
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    body = fixture["envelopes"][0]["envelope"]["body"]
    arabic = body["manifest"]["statement_ar"]
    assert any("\u0600" <= ch <= "\u06FF" for ch in arabic)

    # round-trips byte-for-byte: no Unicode normalization applied
    encoded = canonical_bytes({"t": arabic})
    assert json.loads(encoded.decode("utf-8"))["t"] == arabic

    # an intentionally non-NFC string (alef + combining hamza above) must NOT
    # be rewritten to its precomposed form
    non_nfc = "\u0627\u0654"
    raw = canonical_bytes({"t": non_nfc})
    assert b"\xd8\xa7\xd9\x94" in raw           # raw sequence preserved
    assert b"\xd8\xa3" not in raw               # NFC precomposed form absent


# ---------------------------------------------------------------------------
# KeyProvider: wrap/unwrap and fail-closed access
# ---------------------------------------------------------------------------


def _write_seed(tmp_path: Path, inst: str, key_id: str, key: Ed25519PrivateKey) -> Path:
    d = tmp_path / "secrets" / inst
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{key_id}.seed"
    p.write_bytes(key.private_bytes_raw())
    return tmp_path / "secrets"


def test_wrap_unwrap_roundtrip_and_tamper(tmp_path):
    key_a = new_key()
    base = _write_seed(tmp_path, "INST-A", "INST-A-K1", key_a)
    provider = LocalFileKeyProvider(base)

    dek = bytes(range(32))
    wrapped = provider.wrap_data_key("INST-A", dek)
    assert wrapped["algorithm"].startswith("X25519")
    assert base64.b64decode(wrapped["ciphertext"]) != dek  # no plaintext DEK in wrapped form

    assert provider.unwrap_data_key("INST-A", wrapped) == dek

    # tamper -> authentication failure, fail-closed
    raw = bytearray(base64.b64decode(wrapped["ciphertext"]))
    raw[0] ^= 0x01
    wrapped_t = dict(wrapped, ciphertext=base64.b64encode(bytes(raw)).decode("ascii"))
    with pytest.raises(ValueError):
        provider.unwrap_data_key("INST-A", wrapped_t)


def test_provider_fail_closed_on_missing_and_traversal(tmp_path):
    key_a = new_key()
    base = _write_seed(tmp_path, "INST-A", "INST-A-K1", key_a)
    provider = LocalFileKeyProvider(base)

    with pytest.raises(KeyError):
        provider.get_signing_key("INST-A", "UNKNOWN-KEY")
    with pytest.raises(KeyError):
        provider.get_signing_key("UNKNOWN-INST", "INST-A-K1")
    # path traversal must be refused, not resolved
    with pytest.raises(ValueError):
        provider.get_signing_key("..", "evil")
    with pytest.raises(ValueError):
        provider.get_signing_key("INST-A", "../INST-A-K1")
