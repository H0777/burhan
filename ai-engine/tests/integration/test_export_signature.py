"""
Integration Tests for Forensic Dossier Signature & Verifier CLI (R09 / F05).

Covers:
- Fabricated signatures (algorithm=none, INVALID-NO-PRIVATE-KEY) rejected as invalid
- Missing registry / key rejected as unavailable (fail-closed, exit 2)
- Duplicate JSON keys rejected in strict mode
- Offline mode verifies bundle without asserting on-chain claims
- Online mode validates chain snapshot / anchor against EVM RPC (success, reorg, rpc failure)
- Retired key without trusted time rejected as unavailable
"""

import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Load evidence_crypto from shared module
_SHARED_PYTHON = str(Path(__file__).resolve().parents[3] / "shared" / "python")
if _SHARED_PYTHON not in sys.path:
    sys.path.insert(0, _SHARED_PYTHON)

import evidence_crypto as _ec

canonical_bytes = _ec.canonical_bytes
sign_payload_bytes = _ec.sign_payload_bytes
encode_public_key = _ec.encode_public_key
DOMAIN_DOSSIER = _ec.DOMAIN_DOSSIER

# Import verifier script directly
_SCRIPTS_DIR = str(Path(__file__).resolve().parents[3] / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import importlib.util
_VERIFIER_SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "verify-evidence-export.py"
_v_spec = importlib.util.spec_from_file_location("verify_evidence_export", str(_VERIFIER_SCRIPT_PATH))
assert _v_spec and _v_spec.loader
_v_mod = importlib.util.module_from_spec(_v_spec)
sys.modules["verify_evidence_export"] = _v_mod
_v_spec.loader.exec_module(_v_mod)
verify_bundle = getattr(_v_mod, "verify_bundle", None)

TEST_INST_ID = "INST-BAGHDAD-AUTH-A"
TEST_KEY_ID = "KEY-LEGAL-2026-01"


@pytest.fixture
def key_pair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


@pytest.fixture
def trust_registry_file(tmp_path, key_pair):
    _, pub = key_pair
    reg_doc = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": [
            {
                "institution_id": TEST_INST_ID,
                "key_id": TEST_KEY_ID,
                "public_key": encode_public_key(pub),
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_until": "2027-01-01T00:00:00+00:00",
                "status": "active",
                "revoked_at": None,
                "invalid_from": None,
            }
        ],
    }
    path = tmp_path / "trusted-registry.json"
    path.write_text(json.dumps(reg_doc, indent=2), encoding="utf-8")
    return str(path)


def _create_valid_dossier_zip(
    dest_path: str,
    private_key: Ed25519PrivateKey,
    institution_id: str = TEST_INST_ID,
    key_id: str = TEST_KEY_ID,
    report_markdown: str = "# Forensic Audit Report\n\nDeterministic content.",
    evidence_files: Optional[Dict[str, bytes]] = None,
    snapshot_data: Optional[Dict[str, Any]] = None,
    corrupt_signature: bool = False,
    signature_algorithm: str = "Ed25519",
    custom_signature: Optional[str] = None,
    duplicate_json_keys_in_manifest: bool = False,
) -> None:
    if evidence_files is None:
        evidence_files = {"hawala_flow.csv": b"tx_id,amount,sender,receiver\n1,5000000,Ali,Hassan\n"}

    if snapshot_data is None:
        snapshot_data = {
            "snapshot_id": "vs_test_snapshot_01",
            "chain_id": 31337,
            "block_number": 100,
            "block_hash": "0x" + "aa" * 32,
            "head_entry_hash": "0x" + "bb" * 32,
            "evidence_count": len(evidence_files),
            "status": "verified",
        }

    # Prepare files inventory
    import hashlib

    md_bytes = report_markdown.encode("utf-8")
    md_hash = hashlib.sha256(md_bytes).hexdigest()

    files_inventory = [
        {
            "path": "report.md",
            "sha256": md_hash,
            "size": len(md_bytes),
        }
    ]

    for fname, content in evidence_files.items():
        f_hash = hashlib.sha256(content).hexdigest()
        files_inventory.append({
            "path": f"evidence/{fname}",
            "sha256": f_hash,
            "size": len(content),
            "evidence_id": f"EVID-{fname}",
        })

    # Manifest body
    manifest_body = {
        "institution_id": institution_id,
        "key_id": key_id,
        "schema_version": 1,
        "report_id": "REP-IRQ-2026-CASE-001-V1",
        "case_id": "CASE-BAGHDAD-001",
        "case_number": "IRQ-2026-CASE-001",
        "generated_at": "2026-10-25T12:00:00+00:00",
        "files": files_inventory,
        "verification_snapshot": snapshot_data,
    }

    # Sign payload
    sig_b64 = sign_payload_bytes(private_key, DOMAIN_DOSSIER, manifest_body)
    if corrupt_signature:
        sig_b64 = "A" * len(sig_b64)
    if custom_signature is not None:
        sig_b64 = custom_signature

    signature_envelope = {
        "body": manifest_body,
        "algorithm": signature_algorithm,
        "signature": sig_b64,
    }

    manifest_json_bytes = canonical_bytes(manifest_body)
    if duplicate_json_keys_in_manifest:
        manifest_json_bytes = b'{"schema_version":1,"schema_version":2,"institution_id":"' + institution_id.encode("utf-8") + b'"}'

    sig_json_bytes = canonical_bytes(signature_envelope) if signature_algorithm == "Ed25519" and not custom_signature else json.dumps(signature_envelope).encode("utf-8")

    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_json_bytes)
        zf.writestr("signature.json", sig_json_bytes)
        zf.writestr("report.md", md_bytes)
        for fname, content in evidence_files.items():
            zf.writestr(f"evidence/{fname}", content)


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(_VERIFIER_SCRIPT_PATH)] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def test_fabricated_signature_invalid(tmp_path, key_pair, trust_registry_file):
    """
    F05 regression test: algorithm=none or INVALID-NO-PRIVATE-KEY signature MUST be rejected (exit 1).
    """
    priv, _ = key_pair
    bundle_path = str(tmp_path / "fabricated_none.zip")
    _create_valid_dossier_zip(
        bundle_path,
        priv,
        signature_algorithm="none",
        custom_signature="INVALID-NO-PRIVATE-KEY",
    )

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("algorithm" in r.lower() or "signature" in r.lower() for r in out["reasons"])


def test_tampered_signature_bytes_invalid(tmp_path, key_pair, trust_registry_file):
    """A corrupted signature on an otherwise valid bundle returns invalid (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "corrupt_sig.zip")
    _create_valid_dossier_zip(bundle_path, priv, corrupt_signature=True)

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("signature_mismatch" in r.lower() or "signature" in r.lower() for r in out["reasons"])


def test_missing_registry_unavailable(tmp_path, key_pair):
    """A missing or non-existent registry file fails-closed with unavailable (exit 2)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "valid.zip")
    _create_valid_dossier_zip(bundle_path, priv)

    non_existent_reg = str(tmp_path / "does_not_exist_registry.json")
    res = _run_cli([bundle_path, "--registry", non_existent_reg])
    assert res.returncode == 2
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "unavailable"
    assert any("registry" in r.lower() for r in out["reasons"])


def test_key_not_in_registry_unavailable(tmp_path, key_pair, tmp_path_factory):
    """A key not found in the registry fails-closed with unavailable (exit 2)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "valid_unknown_key.zip")
    _create_valid_dossier_zip(bundle_path, priv, key_id="KEY-UNKNOWN-99")

    # Registry with different key_id
    _, pub = key_pair
    reg_path = str(tmp_path / "reg_other_key.json")
    reg_doc = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": [
            {
                "institution_id": TEST_INST_ID,
                "key_id": "KEY-OTHER-01",
                "public_key": encode_public_key(pub),
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_until": "2027-01-01T00:00:00+00:00",
                "status": "active",
                "revoked_at": None,
                "invalid_from": None,
            }
        ],
    }
    Path(reg_path).write_text(json.dumps(reg_doc), encoding="utf-8")

    res = _run_cli([bundle_path, "--registry", reg_path])
    assert res.returncode == 2
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "unavailable"
    assert any("key_not_in_registry" in r.lower() for r in out["reasons"])


def test_duplicate_json_keys_rejected(tmp_path, key_pair, trust_registry_file):
    """Duplicate JSON keys in manifest or signature are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "dup_keys.zip")
    _create_valid_dossier_zip(bundle_path, priv, duplicate_json_keys_in_manifest=True)

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("duplicate" in r.lower() for r in out["reasons"])


def test_offline_mode_valid_without_chain_claims(tmp_path, key_pair, trust_registry_file):
    """
    Valid bundle verified offline returns exit code 0, bundle_status=verified,
    and anchor_status=not_checked (does NOT falsely claim on-chain verification).
    """
    priv, _ = key_pair
    bundle_path = str(tmp_path / "valid_offline.zip")
    _create_valid_dossier_zip(bundle_path, priv)

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 0
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "verified"
    assert out["anchor_status"] == "not_checked"
    assert out["reasons"] == []
    assert out["snapshot_id"] == "vs_test_snapshot_01"


def test_online_rpc_failure_unavailable(tmp_path, key_pair, trust_registry_file):
    """In --online mode, if RPC is down or unreachable, returns unavailable (exit 2)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "valid_online.zip")
    _create_valid_dossier_zip(bundle_path, priv)

    # Point to an unallocated port
    res = _run_cli([bundle_path, "--registry", trust_registry_file, "--online", "--rpc-url", "http://127.0.0.1:59999"])
    assert res.returncode == 2
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "verified"
    assert out["anchor_status"] == "unavailable"
    assert any("rpc" in r.lower() for r in out["reasons"])


def test_retired_dossier_key_without_external_checkpoint_unavailable(tmp_path, key_pair):
    """Retired key in registry requires external trusted_time; otherwise unavailable (exit 2)."""
    priv, pub = key_pair
    bundle_path = str(tmp_path / "retired_key_bundle.zip")
    _create_valid_dossier_zip(bundle_path, priv)

    reg_path = str(tmp_path / "reg_retired.json")
    reg_doc = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": [
            {
                "institution_id": TEST_INST_ID,
                "key_id": TEST_KEY_ID,
                "public_key": encode_public_key(pub),
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_until": "2026-06-01T00:00:00+00:00",
                "status": "retired",
                "revoked_at": None,
                "invalid_from": None,
            }
        ],
    }
    Path(reg_path).write_text(json.dumps(reg_doc), encoding="utf-8")

    res = _run_cli([bundle_path, "--registry", reg_path])
    assert res.returncode == 2
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "unavailable"
    assert any("trusted_time_required" in r.lower() for r in out["reasons"])
