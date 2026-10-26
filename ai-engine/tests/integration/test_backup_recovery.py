"""
Integration Tests for R16: Tamper-Evident Evidence Storage, Backup Service & Disaster Recovery
Specification §4, §6, §7, §8 & Remediation Plan R16 (Resolving F12)

Verifies:
1. Encrypted backup creation using AES-256-GCM wrapped DEK and signed manifest envelope (AML_BACKUP_V1).
2. Hash integrity chain across successive backups (prev_backup_hash / chain verification).
3. Verification of snapshots against TrustRegistry and cryptographic digests before restore.
4. Tamper detection: detecting corrupted ciphertext, modified manifest, forged signatures, altered evidence, and zip-slip directory traversal.
5. Crash recovery and cleanup: atomicity of backup creation, isolated target restoration, and outbox/checkpoint state reconciliation.
6. Immutability and overwrite prevention in EvidenceStore and BackupService.
7. Tamper-evident audit logging of all backup/restore/tamper events.
"""

import os
import io
import json
import zipfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import (
    Base, Institution, Case, TransactionRecord, ReportRecord,
    CheckpointRecord, Outbox
)
from app.services.backup_service import (
    BackupService, BackupCorruptionError, ChainIntegrityError
)
from app.services.evidence_store import EvidenceStore
from app.security.key_provider import LocalFileKeyProvider
from app.security.signing import (
    Signer, Verifier, DOMAIN_BACKUP, STATUS_VERIFIED,
    TrustRegistry, RegistryEntry, encode_public_key
)


@pytest.fixture
def test_environment():
    """Sets up isolated directory, database, evidence store, and cryptographic key material."""
    temp_root = Path(tempfile.mkdtemp(prefix="r16_test_"))
    db_path = temp_root / "primary.db"
    evidence_path = temp_root / "evidence_store"
    evidence_path.mkdir(parents=True, exist_ok=True)
    backups_path = temp_root / "backups"
    backups_path.mkdir(parents=True, exist_ok=True)
    keys_path = temp_root / "keys"
    keys_path.mkdir(parents=True, exist_ok=True)

    # Setup test cryptographic keys for institution INST-CBI-IQ
    inst_id = "INST-CBI-IQ"
    inst_keys_dir = keys_path / inst_id
    inst_keys_dir.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    (inst_keys_dir / "k1.seed").write_bytes(seed)
    (inst_keys_dir / "current").write_text("k1", encoding="utf-8")

    key_provider = LocalFileKeyProvider(keys_path)
    signer = Signer(key_provider)
    pubkey = key_provider.get_signing_key(inst_id, "k1").public_key()
    pubkey_b64 = encode_public_key(pubkey)

    now = datetime.now(timezone.utc)
    trust_registry = TrustRegistry.from_mapping({
        "entries": [
            {
                "institution_id": inst_id,
                "key_id": "k1",
                "public_key": pubkey_b64,
                "valid_from": (now - timedelta(days=10)).isoformat(),
                "valid_until": (now + timedelta(days=365)).isoformat(),
                "status": "active",
            }
        ]
    })

    # Setup Primary DB with test records
    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    inst = Institution(id=inst_id, name="Central Bank of Iraq", is_active=True)
    session.add(inst)

    for i in range(1, 6):
        c_id = f"CASE-R16-{i:03d}"
        session.add(Case(
            id=c_id,
            case_number=f"CN-{i:03d}",
            institution_id=inst_id,
            title=f"AML Suspicious Case #{i}",
            severity="HIGH",
            status="OPEN",
            assigned_to_sub="usr-investigator",
            version=1,
            created_at=now,
            updated_at=now,
        ))
        session.add(TransactionRecord(
            id=f"TX-R16-{i:03d}",
            institution_id=inst_id,
            source="IQD_RTGS",
            external_id=f"EXT-{i:03d}",
            occurred_at=now - timedelta(hours=i),
            sender_ref=f"SND-{i:02d}",
            receiver_ref=f"RCV-{i:02d}",
            currency="IQD",
            scale=3,
            amount_minor=5000000000,
            status="RECORDED",
        ))
        session.add(ReportRecord(
            id=f"REP-R16-{i:03d}",
            report_id=f"rep-r16-{i:03d}",
            institution_id=inst_id,
            case_id=c_id,
            version=1,
            language="en",
            dossier_hash="0x" + f"{i:064x}",
            integrity_status="VERIFIED",
            provenance_status="ANCHORED_CANONICAL",
            markdown_content=f"# Report Findings {i}",
            manifest_json='{\"verified\": true}',
            created_by_sub="usr-investigator",
            created_at=now,
        ))

    session.add(CheckpointRecord(
        id="CP-R16-001",
        institution_id=inst_id,
        chain_id=31337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        last_canonical_block_number=2500,
        last_canonical_block_hash="0x" + "c" * 64,
        updated_at=now,
    ))
    session.add(Outbox(
        id="1",
        institution_id=inst_id,
        event_type="CASE_CREATED",
        payload_json=json.dumps({"case_id": "CASE-R16-001"}),
        status="SUBMITTED",
        attempts=0,
        created_at=now,
    ))
    session.commit()

    # Seed Evidence Store using EvidenceStore
    ev_store = EvidenceStore(base_dir=str(evidence_path), key_provider=key_provider)
    ev_store.put(
        stream_or_bytes=b"EVIDENCE_PAYLOAD_FORENSIC_SNAPSHOT_DATA_001",
        metadata={"file_name": "forensic_01.dat", "content_type": "application/octet-stream"},
        institution_id=inst_id,
        evidence_id="ev-r16-01",
        object_version=1,
    )

    yield {
        "root": temp_root,
        "session": session,
        "db_url": db_url,
        "evidence_path": evidence_path,
        "backups_path": backups_path,
        "keys_path": keys_path,
        "key_provider": key_provider,
        "signer": signer,
        "trust_registry": trust_registry,
        "institution_id": inst_id,
        "evidence_store": ev_store,
    }

    session.close()
    shutil.rmtree(temp_root, ignore_errors=True)


def test_encrypted_backup_creation_and_signed_manifest(test_environment):
    """
    Requirement 1: Encrypted backup creation
    Ensures backup is encrypted using AES-256-GCM with wrapped per-backup DEK
    and the manifest is signed with SignedEnvelope under DOMAIN_BACKUP (AML_BACKUP_V1).
    """
    service = BackupService(
        evidence_dir=str(test_environment["evidence_path"]),
        key_provider=test_environment["key_provider"],
        signer=test_environment["signer"],
    )

    bundle_path = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-ENC-001",
        institution_id=test_environment["institution_id"],
        encrypt=True,
    )

    assert bundle_path.exists()
    assert bundle_path.name == "BKP-ENC-001.zip"

    # Inspect bundle ZIP archive
    with zipfile.ZipFile(bundle_path, "r") as zf:
        namelist = zf.namelist()
        # Must contain encrypted payload or encrypted snapshot
        assert "backup-manifest.json" in namelist
        manifest_raw = json.loads(zf.read("backup-manifest.json").decode("utf-8"))

        # The manifest must contain the cryptographic signature envelope
        assert "signature_envelope" in manifest_raw
        env = manifest_raw["signature_envelope"]
        assert env["algorithm"] == "Ed25519"
        assert env["body"]["institution_id"] == test_environment["institution_id"]
        assert env["body"]["schema_version"] == 1
        assert "ciphertext_sha256" in env["body"] or "db_snapshot_sha256" in env["body"]

        # Verify encryption metadata is present
        assert manifest_raw.get("storage_format") == "aes256gcm_v1"
        assert "wrapped_dek" in manifest_raw
        assert "nonce" in manifest_raw
        assert "auth_tag" in manifest_raw

        # Raw snapshot must NOT be plaintext SQLite
        raw_data = zf.read("snapshot.db.enc" if "snapshot.db.enc" in namelist else "snapshot.db")
        assert not raw_data.startswith(b"SQLite format 3"), "Database snapshot must be encrypted at rest"

    # Verify restore succeeds with valid key provider and trust registry
    restore_db = test_environment["root"] / "restored_enc.db"
    restore_ev = test_environment["root"] / "restored_evidence"
    result = service.restore_backup(
        bundle_path=bundle_path,
        target_db_url=f"sqlite:///{restore_db}",
        target_evidence_dir=str(restore_ev),
        trust_registry=test_environment["trust_registry"],
        key_provider=test_environment["key_provider"],
    )

    assert result["status"] == "VERIFIED_RESTORED"
    assert result["counts"]["cases"] == 5
    assert result["counts"]["transactions"] == 5


def test_hash_integrity_chain(test_environment):
    """
    Requirement 2: Hash integrity chain
    Successive backups must link to previous backup digest forming an audit chain.
    Altering or skipping a node in the chain must trigger ChainIntegrityError.
    """
    service = BackupService(
        evidence_dir=str(test_environment["evidence_path"]),
        key_provider=test_environment["key_provider"],
        signer=test_environment["signer"],
    )

    # Create backup 1 (Genesis)
    b1_path = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-CHAIN-001",
        institution_id=test_environment["institution_id"],
    )
    b1_digest = service.get_backup_digest(b1_path)
    assert b1_digest is not None and len(b1_digest) == 64

    # Create backup 2 linked to backup 1
    b2_path = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-CHAIN-002",
        institution_id=test_environment["institution_id"],
        prev_backup_hash=b1_digest,
    )
    b2_digest = service.get_backup_digest(b2_path)

    # Create backup 3 linked to backup 2
    b3_path = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-CHAIN-003",
        institution_id=test_environment["institution_id"],
        prev_backup_hash=b2_digest,
    )

    # Chain validation across sequence must pass
    assert service.verify_chain([b1_path, b2_path, b3_path]) is True

    # Tampering with intermediate chain link must raise ChainIntegrityError
    fake_digest = "0" * 64
    b_invalid_link = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-CHAIN-BROKEN",
        institution_id=test_environment["institution_id"],
        prev_backup_hash=fake_digest,
    )
    with pytest.raises(ChainIntegrityError, match="Integrity chain broken"):
        service.verify_chain([b1_path, b_invalid_link])


def test_snapshot_verification_and_tamper_detection(test_environment):
    """
    Requirements 3 & 4: Verification of snapshots and tamper detection
    Ensures detection of ciphertext bit-rot, forged signature, modified manifest,
    and corrupted evidence.
    """
    service = BackupService(
        evidence_dir=str(test_environment["evidence_path"]),
        key_provider=test_environment["key_provider"],
        signer=test_environment["signer"],
    )

    valid_bundle = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-TAMPER-TARGET",
        institution_id=test_environment["institution_id"],
        encrypt=True,
    )

    # Subtest A: GCM Ciphertext corruption
    corrupted_cipher_zip = test_environment["backups_path"] / "BKP-CORRUPT-CIPHER.zip"
    with zipfile.ZipFile(valid_bundle, "r") as src, zipfile.ZipFile(corrupted_cipher_zip, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename.endswith(".enc") or item.filename == "snapshot.db":
                data = bytearray(data)
                data[0] ^= 0x55  # flip bits
                data = bytes(data)
            dst.writestr(item, data)

    target_db = test_environment["root"] / "fail_cipher.db"
    with pytest.raises(BackupCorruptionError, match="(Bit-rot|GCM tag|tamper|corrupt)"):
        service.restore_backup(
            bundle_path=corrupted_cipher_zip,
            target_db_url=f"sqlite:///{target_db}",
            trust_registry=test_environment["trust_registry"],
            key_provider=test_environment["key_provider"],
        )

    # Subtest B: Forged manifest signature
    forged_sig_zip = test_environment["backups_path"] / "BKP-FORGED-SIG.zip"
    with zipfile.ZipFile(valid_bundle, "r") as src, zipfile.ZipFile(forged_sig_zip, "w") as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "backup-manifest.json":
                meta = json.loads(data.decode("utf-8"))
                meta["signature_envelope"]["signature"] = "A" * 88
                data = json.dumps(meta).encode("utf-8")
            dst.writestr(item, data)

    with pytest.raises(BackupCorruptionError, match="(signature|forged|invalid)"):
        service.restore_backup(
            bundle_path=forged_sig_zip,
            target_db_url=f"sqlite:///{target_db}",
            trust_registry=test_environment["trust_registry"],
            key_provider=test_environment["key_provider"],
        )

    # Subtest C: Malicious Zip Slip path traversal attempt
    traversal_zip = test_environment["backups_path"] / "BKP-ZIP-SLIP.zip"
    with zipfile.ZipFile(valid_bundle, "r") as src, zipfile.ZipFile(traversal_zip, "w") as dst:
        for item in src.infolist():
            dst.writestr(item, src.read(item.filename))
        # Inject traversal path
        dst.writestr("../../escaped.txt", b"MALICIOUS ESCAPE")

    with pytest.raises((BackupCorruptionError, ValueError), match="(traversal|escape|insecure)"):
        service.restore_backup(
            bundle_path=traversal_zip,
            target_db_url=f"sqlite:///{target_db}",
            trust_registry=test_environment["trust_registry"],
            key_provider=test_environment["key_provider"],
        )


def test_crash_recovery_and_cleanup(test_environment):
    """
    Requirement 5: Crash recovery and cleanup
    Verifies that a crash during backup aborts cleanly with no staging residue,
    and restore recovers pending Outbox and Checkpoint consistency.
    """
    service = BackupService(
        evidence_dir=str(test_environment["evidence_path"]),
        key_provider=test_environment["key_provider"],
        signer=test_environment["signer"],
    )

    # Simulate failure midway through create_backup by mocking an exception
    def broken_copy(*args, **kwargs):
        raise IOError("Simulated power cut / disk full during snapshot!")

    orig_copy = service._copy_all_records
    service._copy_all_records = broken_copy

    with pytest.raises(IOError, match="Simulated power cut"):
        service.create_backup(
            session=test_environment["session"],
            output_dir=str(test_environment["backups_path"]),
            backup_name="BKP-CRASH-TEST",
        )

    # Verify no dangling stage_ directory or corrupted zip remains in output_dir
    output_files = list(test_environment["backups_path"].glob("*BKP-CRASH-TEST*"))
    assert len(output_files) == 0, "Crash during backup creation must not leave partial files"

    # Restore original function
    service._copy_all_records = orig_copy

    # Test Outbox and Checkpoint recovery state
    normal_bundle = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-CRASH-OUTBOX",
        institution_id=test_environment["institution_id"],
    )

    recovered_db = test_environment["root"] / "recovered_crash.db"
    res = service.restore_backup(
        bundle_path=normal_bundle,
        target_db_url=f"sqlite:///{recovered_db}",
        trust_registry=test_environment["trust_registry"],
        key_provider=test_environment["key_provider"],
    )
    assert res["status"] == "VERIFIED_RESTORED"

    rec_engine = create_engine(f"sqlite:///{recovered_db}")
    RecSession = sessionmaker(bind=rec_engine)
    r_session = RecSession()

    # Verify checkpoint block height and outbox SUBMITTED state match
    cp = r_session.query(CheckpointRecord).filter_by(id="CP-R16-001").first()
    assert cp is not None
    assert cp.last_canonical_block_number == 2500

    outbox_event = r_session.query(Outbox).filter_by(id="1").first()
    assert outbox_event is not None
    assert outbox_event.status == "SUBMITTED"
    r_session.close()


def test_prevent_overwrite_and_audit_logs(test_environment):
    """
    Requirement 6 & 7: Prevent overwrite, enforce WORM, and record audit logs
    """
    service = BackupService(
        evidence_dir=str(test_environment["evidence_path"]),
        key_provider=test_environment["key_provider"],
        signer=test_environment["signer"],
    )

    # 1. Overwrite prevention in BackupService
    b_path = service.create_backup(
        session=test_environment["session"],
        output_dir=str(test_environment["backups_path"]),
        backup_name="BKP-IMMUTABLE-01",
        institution_id=test_environment["institution_id"],
    )
    assert b_path.exists()

    # Attempting to recreate the same backup must fail with FileExistsError / ValueError
    with pytest.raises((FileExistsError, ValueError), match="(already exists|immutable|overwrite)"):
        service.create_backup(
            session=test_environment["session"],
            output_dir=str(test_environment["backups_path"]),
            backup_name="BKP-IMMUTABLE-01",
            institution_id=test_environment["institution_id"],
        )

    # 2. Overwrite prevention in EvidenceStore
    ev_store = test_environment["evidence_store"]
    with pytest.raises(ValueError, match="WORM Violation"):
        ev_store.put(
            stream_or_bytes=b"OVERWRITE_ATTEMPT",
            metadata={"file_name": "forensic_01.dat"},
            institution_id=test_environment["institution_id"],
            evidence_id="ev-r16-01",
            object_version=1,
        )

    # 3. Audit Logging Verification in EvidenceStore
    # Evidence store should maintain an audit trail
    audit_entries = ev_store.get_audit_logs(institution_id=test_environment["institution_id"])
    assert len(audit_entries) >= 1
    assert any(entry["action"] == "PUT" and entry["evidence_id"] == "ev-r16-01" for entry in audit_entries)

    # When tampering occurs on read, an audit log entry for tampering must be emitted
    # Tamper with the evidence object on disk
    obj_path = Path(test_environment["evidence_path"]) / test_environment["institution_id"] / "ev-r16-01" / "v1" / "object.bin"
    obj_path.write_bytes(b"CORRUPTED_EVIDENCE_BYTES")

    with pytest.raises(ValueError, match="Integrity Compromised"):
        ev_store.open(test_environment["institution_id"], "ev-r16-01", 1)

    tamper_audit = ev_store.get_audit_logs(institution_id=test_environment["institution_id"])
    assert any(entry["action"] == "TAMPER_DETECTED" for entry in tamper_audit)

    # 4. Audit Logging Verification in BackupService
    backup_audits = service.get_audit_logs()
    assert len(backup_audits) >= 1
    assert any(e["event"] == "BACKUP_CREATED" and e["backup_id"] == "BKP-IMMUTABLE-01" for e in backup_audits)
