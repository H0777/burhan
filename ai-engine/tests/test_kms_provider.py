"""KmsProvider (H06) — tests against a REAL Vault Transit engine.

These tests exercise the provider through Vault's actual HTTP API — no
in-process mock. The Vault dev-mode container comes from the staging
override ``infra/staging/docker-compose.kms.yml`` (disclosed as dev-mode;
see ``docs/verification/program/staging-h06.md``).

Environment (all optional — tests SKIP with an explicit reason when the
KMS is not reachable, so the suite stays runnable without the stack):

- ``TEST_VAULT_ADDR``      default ``http://127.0.0.1:18200``
- ``TEST_VAULT_TOKEN``     default ``kms-staging-root`` (dev-mode root)
- ``TEST_VAULT_CONTAINER`` default ``aml_staging_vault`` (used by the
  network-failure test to ``docker stop``/``docker start`` the container,
  proving genuine transport failure, fail-closed, and recovery).

The fail-closed matrix proven here:
- wrap/unwrap round-trip through the real Vault API;
- wrong institution / wrong key generation refused (isolation + recovery
  unwrap with the correct key only);
- tampered wrapped DEK refused (authentication failure);
- Vault down => KmsUnavailableError for every operation, no file fallback;
- the Vault-backed signing delegate produces signatures that verify against
  the PUBLIC key fetched from Vault (no private material ever in-process).
"""

from __future__ import annotations

import base64
import os
import subprocess
import uuid
from pathlib import Path

import pytest

from app.security.kms_provider import (
    KmsProvider,
    KmsUnavailableError,
    VaultTransitSigner,
)

_VAULT_ADDR = os.environ.get("TEST_VAULT_ADDR", "http://127.0.0.1:18200")
_VAULT_CONTAINER = os.environ.get("TEST_VAULT_CONTAINER", "aml_staging_vault")


def _default_token() -> str:
    """TEST_VAULT_TOKEN override, else the gitignored staging .env value.

    The token is read from the gitignored ops file at runtime — it is never
    hardcoded, never printed, and never persisted by the tests.
    """
    override = os.environ.get("TEST_VAULT_TOKEN")
    if override:
        return override
    env_file = Path(__file__).resolve().parents[2] / "infra" / "staging" / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("STAGING_VAULT_DEV_ROOT_TOKEN_ID="):
                return line.split("=", 1)[1].strip()
    return "kms-staging-root"


_VAULT_TOKEN = _default_token()

_INST_A = "inst-a-h06"
_INST_B = "inst-b-h06"


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60
    )


def _vault_up() -> bool:
    try:
        import requests

        r = requests.get(
            f"{_VAULT_ADDR}/v1/sys/health",
            params={"standbyok": "true", "sealedcode": "200", "uninitcode": "200"},
            timeout=3,
        )
        return r.status_code == 200
    except Exception:
        return False


def _registry():
    """Fresh per-test registry (unique institutions => rerunnable tests)."""
    suffix = uuid.uuid4().hex[:8]
    a, b = f"{_INST_A}-{suffix}", f"{_INST_B}-{suffix}"
    return a, b, {a: "k1", b: "k1"}


@pytest.fixture(scope="module")
def vault_ready():
    if not _vault_up():
        pytest.skip(
            f"Vault staging KMS not reachable at {_VAULT_ADDR} — start the "
            "staging stack with infra/staging/docker-compose.kms.yml (H06)"
        )
    return True


@pytest.fixture()
def provider(vault_ready):
    inst_a, inst_b, registry = _registry()
    prov = KmsProvider(_VAULT_ADDR, _VAULT_TOKEN, registry)
    prov._ensure_transit()
    for inst in (inst_a, inst_b):
        prov.create_key_generation(inst, "k1")
        prov.create_key_generation(inst, "k2")
    return prov, inst_a, inst_b


# ---------------------------------------------------------------------------
# always-on (offline) validation tests — no Vault needed
# ---------------------------------------------------------------------------


def test_key_name_mapping_injective_and_validated():
    assert (
        KmsProvider.key_name("INST-A", "k1", "sig") == "INST-A--sig--k1"
    )
    with pytest.raises(ValueError):
        KmsProvider.key_name("bad--inst", "k1", "sig")  # reserved separator
    with pytest.raises(ValueError):
        KmsProvider.key_name("INST-A", "k1", "evil")  # unknown purpose
    with pytest.raises(ValueError):
        KmsProvider.key_name("../traversal", "k1", "sig")


# ---------------------------------------------------------------------------
# real-KMS protocol tests (skipped when the staging Vault is not up)
# ---------------------------------------------------------------------------


def test_wrap_unwrap_roundtrip_via_real_vault_api(provider):
    prov, inst_a, _ = provider
    dek = bytes(range(32))
    wrapped = prov.wrap_data_key(inst_a, dek)

    assert wrapped["recipient_key_id"] == "k1"
    assert wrapped["institution_id"] == inst_a
    assert wrapped["algorithm"].startswith("VaultTransit-")
    assert "vault:v1:" in wrapped["ciphertext"]  # real Transit ciphertext
    # the plaintext DEK must not leak into the wrapped form (any encoding)
    b64dek = base64.b64encode(dek).decode("ascii")
    assert b64dek not in wrapped["ciphertext"]
    assert dek.hex() not in wrapped["ciphertext"]
    assert prov.unwrap_data_key(inst_a, wrapped) == dek


def test_wrong_institution_and_wrong_key_refused(provider):
    prov, inst_a, inst_b = provider
    dek = b"\x07" * 32
    wrapped = prov.wrap_data_key(inst_a, dek)

    # another institution must not be able to unwrap
    with pytest.raises(ValueError):
        prov.unwrap_data_key(inst_b, wrapped)
    # a foreign wrapped dict claiming our institution must be refused too
    with pytest.raises(ValueError):
        prov.unwrap_data_key(inst_a, dict(wrapped, institution_id=inst_b))


def test_tamper_fail_closed(provider):
    prov, inst_a, _ = provider
    wrapped = prov.wrap_data_key(inst_a, b"\x11" * 32)
    tampered = dict(wrapped, ciphertext=wrapped["ciphertext"][:-2] + ("AA" if not wrapped["ciphertext"].endswith("AA") else "BB"))
    with pytest.raises(ValueError):
        prov.unwrap_data_key(inst_a, tampered)


def test_two_institutions_isolated(provider):
    prov, inst_a, inst_b = provider
    dek_a, dek_b = b"\x01" * 32, b"\x02" * 32
    w_a = prov.wrap_data_key(inst_a, dek_a)
    w_b = prov.wrap_data_key(inst_b, dek_b)

    assert prov.unwrap_data_key(inst_a, w_a) == dek_a
    assert prov.unwrap_data_key(inst_b, w_b) == dek_b
    with pytest.raises(ValueError):
        prov.unwrap_data_key(inst_a, w_b)
    with pytest.raises(ValueError):
        prov.unwrap_data_key(inst_b, w_a)


def test_recovery_unwrap_with_correct_key_only(provider):
    prov, inst_a, _ = provider
    dek = b"\x33" * 32
    wrapped_k1 = prov.wrap_data_key(inst_a, dek)

    # rotation: ops flips the registry (outside the code) to k2; new wraps
    # target k2 while old wraps stay unwrappable under their retained key_id
    prov._current_keys[inst_a] = "k2"  # simulate the registry update
    assert prov.get_current_key_id(inst_a) == "k2"
    wrapped_k2 = prov.wrap_data_key(inst_a, b"\x44" * 32)
    assert wrapped_k2["recipient_key_id"] == "k2"

    assert prov.unwrap_data_key(inst_a, wrapped_k1) == dek  # retained key
    assert prov.unwrap_data_key(inst_a, wrapped_k2) == b"\x44" * 32

    # an envelope claiming a nonexistent generation must fail closed
    with pytest.raises((KeyError, ValueError)):
        prov.unwrap_data_key(inst_a, dict(wrapped_k1, recipient_key_id="kX"))


def test_vault_backed_signing_verifies_against_public_key(provider):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    prov, inst_a, _ = provider
    delegate: VaultTransitSigner = prov.get_signing_key(inst_a, "k1")
    assert isinstance(delegate, VaultTransitSigner)

    payload = b"H06: domain + canonical bytes signed inside Vault"
    sig = delegate.sign(payload)
    assert len(sig) == 64  # raw Ed25519 signature size

    # Vault's public key is base64(raw 32 bytes) — the trust-registry format.
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(prov.public_key_b64(inst_a, "k1")))
    pub.verify(sig, payload)  # raises InvalidSignature on mismatch
    with pytest.raises(Exception):
        pub.verify(sig, payload + b"x")


def test_unknown_keys_fail_closed(provider):
    prov, inst_a, _ = provider
    with pytest.raises(KeyError):
        prov.get_signing_key(inst_a, "no-such-key")
    with pytest.raises(KeyError):
        prov.get_signing_key("no-such-inst", "k1")
    with pytest.raises(KeyError):
        prov.get_current_key_id("no-such-inst")


def test_network_failure_fail_closed_and_recovery(vault_ready):
    """docker stop Vault => every operation refuses (fail-closed, no fallback).
    docker start => the provider recovers its availability behavior: the same
    instance serves new operations again, with NO poisoned state.

    Honest dev-mode caveat (disclosed in the closure doc + runbook): dev-mode
    Vault keeps state IN MEMORY, so keys created before the stop are gone
    after the restart — the pre-stop wrapped DEK can no longer be unwrapped
    (Transit answers GCM authentication failure). Production managed KMS is
    durable; this test proves TRANSPORT recovery, not dev-mode data recovery.
    """
    import time

    inst_a, inst_b, registry = _registry()
    prov = KmsProvider(_VAULT_ADDR, _VAULT_TOKEN, registry)
    prov._ensure_transit()
    prov.create_key_generation(inst_a, "k1")
    dek = b"\x55" * 32
    wrapped = prov.wrap_data_key(inst_a, dek)

    stop = _docker("stop", _VAULT_CONTAINER)
    assert stop.returncode == 0, stop.stderr
    try:
        with pytest.raises(KmsUnavailableError):
            prov.wrap_data_key(inst_a, b"\x66" * 32)
        with pytest.raises(KmsUnavailableError):
            prov.unwrap_data_key(inst_a, wrapped)
        with pytest.raises(KmsUnavailableError):
            prov.get_signing_key(inst_a, "k1")
    finally:
        start = _docker("start", _VAULT_CONTAINER)
        assert start.returncode == 0, start.stderr
        # wait for the dev server to answer again (bounded poll, no flakiness)
        for _ in range(60):
            if _vault_up():
                break
            time.sleep(0.5)
        else:
            pytest.fail("Vault dev server did not come back after docker start")

    # transport recovered: same provider instance serves new operations again
    prov._ensure_transit()  # dev-mode restarts with an empty mount table
    prov.create_key_generation(inst_a, "k1")
    dek2 = b"\x77" * 32
    wrapped2 = prov.wrap_data_key(inst_a, dek2)
    assert prov.unwrap_data_key(inst_a, wrapped2) == dek2

    # dev-mode data loss (disclosed): the pre-restart envelope no longer
    # unwraps — fail-closed authentication failure, never silent nonsense
    with pytest.raises(ValueError):
        prov.unwrap_data_key(inst_a, wrapped)
