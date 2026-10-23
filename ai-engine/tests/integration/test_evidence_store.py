"""
Unit & Integration tests for EvidenceStore (T14)
Specification §6, §7 (R04, R08, R09, R14)
Tests 25MB limits, path traversal rejection, WORM immutability, and tampering detection.
"""

import os
import io
import pytest
import tempfile
import shutil
from pathlib import Path

from app.services.evidence_store import EvidenceStore, StoredEvidence


@pytest.fixture
def temp_vault():
    dirpath = tempfile.mkdtemp(prefix="evidence_vault_test_")
    yield dirpath
    shutil.rmtree(dirpath, ignore_errors=True)


@pytest.fixture
def evidence_store(temp_vault):
    # Set max size to 1 MB for fast testing of boundary limits
    return EvidenceStore(base_dir=temp_vault, max_size_bytes=1024 * 1024)


def test_put_and_open_valid_evidence(evidence_store):
    content = b"CRITICAL FORENSIC REPORT: Transaction #9948 unauthorized override detected."
    meta = {
        "file_name": "audit_override.txt",
        "content_type": "text/plain",
    }

    stored = evidence_store.put(
        stream_or_bytes=content,
        metadata=meta,
        institution_id="INST-CBI-IQ-01",
        evidence_id="ev-001",
        object_version=1,
    )

    assert stored.evidence_id == "ev-001"
    assert stored.object_version == 1
    assert stored.size == len(content)
    assert stored.sha256 is not None
    assert Path(stored.storage_path).exists()

    # Open and verify
    data, read_meta = evidence_store.open(
        institution_id="INST-CBI-IQ-01",
        evidence_id="ev-001",
        object_version=1,
    )
    assert data == content
    assert read_meta["sha256_hash"] == stored.sha256
    assert read_meta["institution_id"] == "INST-CBI-IQ-01"


def test_oversized_stream_rejected_early(evidence_store):
    """Files exceeding maximum threshold must be rejected immediately."""
    # Store threshold is 1 MB (1024 * 1024)
    oversized_data = b"0" * (1024 * 1024 + 10)

    with pytest.raises(ValueError, match="File size exceeds maximum allowed threshold"):
        evidence_store.put(
            stream_or_bytes=io.BytesIO(oversized_data),
            metadata={"file_name": "huge.bin"},
            institution_id="INST-CBI-IQ-01",
            evidence_id="ev-huge",
        )


def test_path_traversal_attempts_rejected(evidence_store):
    content = b"safe data"
    meta = {"file_name": "normal.pdf"}

    # 1. Traversal via institution_id
    with pytest.raises(ValueError, match="Directory traversal detected in institution_id"):
        evidence_store.put(
            stream_or_bytes=content,
            metadata=meta,
            institution_id="../../etc/passwd",
            evidence_id="ev-safe",
        )

    # 2. Traversal via evidence_id
    with pytest.raises(ValueError, match="Directory traversal detected in evidence_id"):
        evidence_store.put(
            stream_or_bytes=content,
            metadata=meta,
            institution_id="INST-CBI-IQ-01",
            evidence_id="../escape_id",
        )

    # 3. Hidden segment
    with pytest.raises(ValueError, match="Hidden or relative segment not allowed"):
        evidence_store.put(
            stream_or_bytes=content,
            metadata=meta,
            institution_id=".hidden_tenant",
            evidence_id="ev-1",
        )


def test_worm_immutability_overwrite_prohibited(evidence_store):
    content_v1 = b"Original Immutable Evidence v1"
    content_v2 = b"Malicious attempt to overwrite v1"

    # Save version 1
    evidence_store.put(
        stream_or_bytes=content_v1,
        metadata={"file_name": "evidence.txt"},
        institution_id="INST-CBI-IQ-01",
        evidence_id="ev-immutable",
        object_version=1,
    )

    # Attempting to put to the exact same version MUST raise WORM violation
    with pytest.raises(ValueError, match="WORM Violation: Evidence 'ev-immutable' version 1 already exists"):
        evidence_store.put(
            stream_or_bytes=content_v2,
            metadata={"file_name": "evidence.txt"},
            institution_id="INST-CBI-IQ-01",
            evidence_id="ev-immutable",
            object_version=1,
        )


def test_tampering_detection_on_read(evidence_store):
    content = b"Authentic untampered bytes"
    stored = evidence_store.put(
        stream_or_bytes=content,
        metadata={"file_name": "audit.log"},
        institution_id="INST-CBI-IQ-01",
        evidence_id="ev-tamper",
        object_version=1,
    )

    # Malicious actor tampers with underlying storage file on disk
    with open(stored.storage_path, "wb") as f:
        f.write(b"Compromised / Altered bytes by attacker!")

    # Open must detect checksum mismatch and reject
    with pytest.raises(ValueError, match="Integrity Compromised: File hash"):
        evidence_store.open(
            institution_id="INST-CBI-IQ-01",
            evidence_id="ev-tamper",
            object_version=1,
        )
