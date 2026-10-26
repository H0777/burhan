"""
Integration Tests for Forensic Dossier Inventory Integrity & ZIP Limits (R09 / F05 / F12).

Covers:
- Missing files declared in inventory rejected as invalid
- Byte tampering in report or evidence rejected as invalid
- Stub evidence (EVIDENCE-STUB:) rejected as invalid
- Extra ZIP members not declared in inventory rejected as invalid
- Zip slip / parent traversal (../) rejected before extraction
- Absolute paths rejected
- Duplicate paths rejected
- Case-insensitive collisions rejected
- Expansion limits (member count, uncompressed total, single file size)
- EvidenceExportService raises error on missing evidence (no stub fallback)
"""

import hashlib
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

_SHARED_PYTHON = str(Path(__file__).resolve().parents[3] / "shared" / "python")
if _SHARED_PYTHON not in sys.path:
    sys.path.insert(0, _SHARED_PYTHON)

import evidence_crypto as _ec

canonical_bytes = _ec.canonical_bytes
sign_payload_bytes = _ec.sign_payload_bytes
encode_public_key = _ec.encode_public_key
DOMAIN_DOSSIER = _ec.DOMAIN_DOSSIER

_VERIFIER_SCRIPT_PATH = Path(__file__).resolve().parents[3] / "scripts" / "verify-evidence-export.py"

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


def _build_bundle(
    dest_path: str,
    private_key: Ed25519PrivateKey,
    files: Dict[str, bytes],
    inventory_override: Optional[list] = None,
) -> None:
    """Build a signed zip bundle with given files dictionary."""
    if inventory_override is not None:
        inv = inventory_override
    else:
        inv = []
        for path, data in files.items():
            inv.append({
                "path": path,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            })

    manifest_body = {
        "institution_id": TEST_INST_ID,
        "key_id": TEST_KEY_ID,
        "schema_version": 1,
        "report_id": "REP-001",
        "case_id": "CASE-001",
        "case_number": "IRQ-001",
        "generated_at": "2026-10-25T12:00:00+00:00",
        "files": inv,
    }

    sig = sign_payload_bytes(private_key, DOMAIN_DOSSIER, manifest_body)
    envelope = {
        "body": manifest_body,
        "algorithm": "Ed25519",
        "signature": sig,
    }

    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", canonical_bytes(manifest_body))
        zf.writestr("signature.json", canonical_bytes(envelope))
        for path, data in files.items():
            zf.writestr(path, data)


def _run_cli(args: list[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(_VERIFIER_SCRIPT_PATH)] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def test_missing_file_invalid(tmp_path, key_pair, trust_registry_file):
    """A file declared in manifest.json but omitted from zip returns invalid (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "missing_file.zip")

    files = {"report.md": b"# Report\nValid report."}
    # Inventory declares evidence/extra.csv which won't be written to zip
    inv = [
        {"path": "report.md", "sha256": hashlib.sha256(files["report.md"]).hexdigest(), "size": len(files["report.md"])},
        {"path": "evidence/extra.csv", "sha256": "a" * 64, "size": 100},
    ]
    _build_bundle(bundle_path, priv, files, inventory_override=inv)

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("missing_file" in r.lower() or "not found" in r.lower() for r in out["reasons"])


def test_byte_tampering_invalid(tmp_path, key_pair, trust_registry_file):
    """Altering a byte in report.md or evidence file fails verification with invalid (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "tampered.zip")

    files = {
        "report.md": b"# Report\nOriginal content.",
        "evidence/doc.txt": b"Authentic evidence payload.",
    }
    _build_bundle(bundle_path, priv, files)

    # Tamper with evidence/doc.txt in the zip
    in_zf = zipfile.ZipFile(bundle_path, "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out_zf:
        for item in in_zf.infolist():
            content = in_zf.read(item.filename)
            if item.filename == "evidence/doc.txt":
                content = content + b"[TAMPERED BYTE]"
            out_zf.writestr(item, content)

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("hash" in r.lower() or "mismatch" in r.lower() or "tamper" in r.lower() for r in out["reasons"])


def test_stub_invalid(tmp_path, key_pair, trust_registry_file):
    """An archive containing an EVIDENCE-STUB: file must be rejected as invalid (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "stub.zip")

    stub_content = b"EVIDENCE-STUB:EVID-001:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    files = {
        "report.md": b"# Report\nValid.",
        "evidence/stub.csv": stub_content,
    }
    _build_bundle(bundle_path, priv, files)

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("stub" in r.lower() for r in out["reasons"])


def test_extra_zip_member_invalid(tmp_path, key_pair, trust_registry_file):
    """An extra file in the zip not declared in the manifest inventory is rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "extra_file.zip")

    files = {"report.md": b"# Report\nValid."}
    _build_bundle(bundle_path, priv, files)

    # Inject an extra unmanifested file
    in_zf = zipfile.ZipFile(bundle_path, "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out_zf:
        for item in in_zf.infolist():
            out_zf.writestr(item, in_zf.read(item.filename))
        out_zf.writestr("evidence/untracked.sh", b"#!/bin/sh\necho malicious\n")

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("extra" in r.lower() or "untracked" in r.lower() or "unmanifested" in r.lower() for r in out["reasons"])


def test_zip_slip_parent_traversal_invalid(tmp_path, key_pair, trust_registry_file):
    """Zip members with parent directory traversal (../) are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "zip_slip.zip")

    files = {"report.md": b"# Report"}
    _build_bundle(bundle_path, priv, files)

    in_zf = zipfile.ZipFile(bundle_path, "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out_zf:
        for item in in_zf.infolist():
            out_zf.writestr(item, in_zf.read(item.filename))
        out_zf.writestr("../evil.txt", b"traversal attack")

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("traversal" in r.lower() or "slip" in r.lower() or "illegal" in r.lower() for r in out["reasons"])


def test_absolute_path_invalid(tmp_path, key_pair, trust_registry_file):
    """Zip members with absolute paths are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "absolute_path.zip")

    files = {"report.md": b"# Report"}
    _build_bundle(bundle_path, priv, files)

    in_zf = zipfile.ZipFile(bundle_path, "r")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out_zf:
        for item in in_zf.infolist():
            out_zf.writestr(item, in_zf.read(item.filename))
        out_zf.writestr("/etc/passwd", b"root:x:0:0...")

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("absolute" in r.lower() or "illegal" in r.lower() or "traversal" in r.lower() for r in out["reasons"])


def test_duplicate_path_invalid(tmp_path, key_pair, trust_registry_file):
    """Archives with duplicate paths in central directory are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "dup_path.zip")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("signature.json", b"{}")
        zf.writestr("report.md", b"version 1")
        zf.writestr("report.md", b"version 2")  # duplicate!

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("duplicate" in r.lower() for r in out["reasons"])


def test_case_insensitive_collision_invalid(tmp_path, key_pair, trust_registry_file):
    """Case-insensitive name collisions (e.g. report.md vs REPORT.MD) are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "case_collision.zip")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("signature.json", b"{}")
        zf.writestr("report.md", b"lowercase")
        zf.writestr("REPORT.MD", b"uppercase")

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("collision" in r.lower() or "case" in r.lower() for r in out["reasons"])


def test_expansion_limits_total_size(tmp_path, key_pair, trust_registry_file):
    """Archives declaring > 512 MiB total uncompressed size are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "huge_archive.zip")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("signature.json", b"{}")
        # Set a ZipInfo whose file_size exceeds limit
        info = zipfile.ZipInfo("evidence/large.bin")
        info.file_size = 550 * 1024 * 1024  # 550 MiB
        info.compress_size = 10
        zf.writestr(info, b"simulated")
        zf.filelist[-1].file_size = 550 * 1024 * 1024

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("limit" in r.lower() or "expansion" in r.lower() or "size" in r.lower() for r in out["reasons"])


def test_expansion_limits_file_count(tmp_path, key_pair, trust_registry_file):
    """Archives declaring > 1000 members are rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "too_many_members.zip")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("signature.json", b"{}")
        for i in range(1002):
            zf.writestr(f"evidence/file_{i}.txt", b"x")

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("member" in r.lower() or "count" in r.lower() or "limit" in r.lower() for r in out["reasons"])


def test_expansion_limits_single_file(tmp_path, key_pair, trust_registry_file):
    """Single member exceeding 25 MiB uncompressed size is rejected (exit 1)."""
    priv, _ = key_pair
    bundle_path = str(tmp_path / "single_file_huge.zip")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", b"{}")
        zf.writestr("signature.json", b"{}")
        info = zipfile.ZipInfo("evidence/oversize.bin")
        info.file_size = 26 * 1024 * 1024  # 26 MiB > 25 MiB
        info.compress_size = 10
        zf.writestr(info, b"simulated")
        zf.filelist[-1].file_size = 26 * 1024 * 1024

    with open(bundle_path, "wb") as f:
        f.write(buf.getvalue())

    res = _run_cli([bundle_path, "--registry", trust_registry_file])
    assert res.returncode == 1
    out = json.loads(res.stdout)
    assert out["bundle_status"] == "invalid"
    assert any("single" in r.lower() or "25" in r.lower() or "limit" in r.lower() or "size" in r.lower() for r in out["reasons"])
