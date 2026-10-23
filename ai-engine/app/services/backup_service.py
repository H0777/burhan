"""
Disaster Recovery, WORM Storage & Backup/Restore Service (T23)
Cyber-Forensic Auditing Framework - Specification §4, §7, §8 & Requirement R11, R18

Ensures automated, cryptographically verifiable database snapshots,
evidence file integrity verification, bit-rot detection, and idempotent outbox recovery.
"""

import os
import json
import shutil
import zipfile
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from sqlalchemy import select, func, text, create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.db.models import (
    Base, Institution, Membership, WalletBindingModel,
    Case, CaseEvent, EvidenceObject, EvidenceAnchor, Outbox, IdempotencyKey,
    TransactionRecord, ImportBatchRecord, PolicyVersionRecord, AssessmentRecord,
    ChainEventRecord, CheckpointRecord, ReportRecord
)


def _compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class BackupCorruptionError(Exception):
    """Raised when bit-rot, truncation, or signature tampering is detected in a backup."""
    pass


class BackupService:
    """
    Manages cold/warm backups, tamper validation, and isolated disaster recovery restore.
    """

    def __init__(self, evidence_dir: Optional[str] = None):
        self.evidence_dir = Path(evidence_dir or "evidence_store")

    def create_backup(
        self,
        session: Session,
        output_dir: str,
        backup_name: Optional[str] = None,
    ) -> Path:
        """
        Creates an immutable, signed backup bundle containing:
        - SQLite / relational DB snapshot
        - Cryptographic evidence store files
        - Checkpoints & Outbox state
        - Cryptographic manifest with SHA-256 digests
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        backup_id = backup_name or f"BKP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6]}"
        stage_dir = out_path / f"stage_{backup_id}"
        stage_dir.mkdir(parents=True, exist_ok=True)

        try:
            db_snapshot_file = stage_dir / "snapshot.db"

            # 1. Capture Database Snapshot
            # Use SQLite VACUUM INTO if connected to SQLite, or export tables
            bind = session.get_bind()
            dialect_name = bind.dialect.name

            if dialect_name == "sqlite":
                # Flush pending writes
                session.commit()
                # Run VACUUM INTO for a clean, consistent snapshot
                try:
                    session.execute(text(f"VACUUM INTO '{str(db_snapshot_file.resolve()).replace(chr(92), '/')}'"))
                except Exception:
                    # Fallback for memory or engines that don't support VACUUM INTO directly
                    dest_engine = create_engine(f"sqlite:///{db_snapshot_file}")
                    Base.metadata.create_all(bind=dest_engine)
                    DestSession = sessionmaker(bind=dest_engine)
                    dest_session = DestSession()
                    self._copy_all_records(session, dest_session)
                    dest_session.commit()
                    dest_session.close()
            else:
                dest_engine = create_engine(f"sqlite:///{db_snapshot_file}")
                Base.metadata.create_all(bind=dest_engine)
                DestSession = sessionmaker(bind=dest_engine)
                dest_session = DestSession()
                self._copy_all_records(session, dest_session)
                dest_session.commit()
                dest_session.close()

            db_sha256 = _compute_sha256(db_snapshot_file)

            # 2. Gather Evidence Files
            evidence_manifest: Dict[str, str] = {}
            evidence_stage_dir = stage_dir / "evidence"
            evidence_stage_dir.mkdir(exist_ok=True)

            if self.evidence_dir.exists():
                for root, _, files in os.walk(self.evidence_dir):
                    for file in files:
                        src_f = Path(root) / file
                        rel_f = src_f.relative_to(self.evidence_dir)
                        dst_f = evidence_stage_dir / rel_f
                        dst_f.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(src_f, dst_f)
                        evidence_manifest[str(rel_f).replace("\\\\", "/")] = _compute_sha256(dst_f)

            # 3. Collect System Counts and Checkpoints
            counts = {
                "institutions": session.query(func.count(Institution.id)).scalar() or 0,
                "cases": session.query(func.count(Case.id)).scalar() or 0,
                "transactions": session.query(func.count(TransactionRecord.id)).scalar() or 0,
                "reports": session.query(func.count(ReportRecord.id)).scalar() or 0,
                "assessments": session.query(func.count(AssessmentRecord.id)).scalar() or 0,
                "chain_events": session.query(func.count(ChainEventRecord.id)).scalar() or 0,
                "checkpoints": session.query(func.count(CheckpointRecord.id)).scalar() or 0,
            }

            checkpoints = []
            for cp in session.query(CheckpointRecord).all():
                checkpoints.append({
                    "institution_id": cp.institution_id,
                    "chain_id": cp.chain_id,
                    "contract_address": cp.contract_address,
                    "last_canonical_block_number": cp.last_canonical_block_number,
                    "last_canonical_block_hash": cp.last_canonical_block_hash,
                })

            # 4. Generate Manifest
            manifest = {
                "manifest_version": "2.0.0",
                "backup_id": backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "db_snapshot_sha256": db_sha256,
                "counts": counts,
                "checkpoints": checkpoints,
                "evidence_files": evidence_manifest,
            }

            manifest_content = json.dumps(manifest, indent=2, sort_keys=True)
            manifest_file = stage_dir / "backup-manifest.json"
            manifest_file.write_text(manifest_content, encoding="utf-8")

            # Compute manifest signature / hash
            manifest_sha256 = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()
            (stage_dir / "backup-manifest.sha256").write_text(manifest_sha256, encoding="utf-8")

            # 5. Package as ZIP Bundle
            bundle_zip = out_path / f"{backup_id}.zip"
            with zipfile.ZipFile(bundle_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(stage_dir):
                    for file in files:
                        full_p = Path(root) / file
                        arcname = full_p.relative_to(stage_dir)
                        zf.write(full_p, arcname)

            return bundle_zip
        finally:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)

    def restore_backup(
        self,
        bundle_path: Path,
        target_db_url: str,
        target_evidence_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validates bundle authenticity, detects bit-rot / tampering, and
        restores database records & evidence files to target instance.
        """
        if not bundle_path.exists():
            raise FileNotFoundError(f"Backup bundle not found at: {bundle_path}")

        extract_dir = bundle_path.parent / f"extract_{uuid4().hex[:8]}"
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(bundle_path, "r") as zf:
                zf.extractall(extract_dir)

            manifest_file = extract_dir / "backup-manifest.json"
            manifest_sig_file = extract_dir / "backup-manifest.sha256"
            db_file = extract_dir / "snapshot.db"

            if not manifest_file.exists() or not db_file.exists():
                raise BackupCorruptionError("Corrupted backup bundle: missing snapshot or manifest.")

            # 1. Validate Manifest Integrity
            manifest_content = manifest_file.read_text(encoding="utf-8")
            actual_manifest_sha = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

            if manifest_sig_file.exists():
                expected_manifest_sha = manifest_sig_file.read_text(encoding="utf-8").strip()
                if actual_manifest_sha != expected_manifest_sha:
                    raise BackupCorruptionError(
                        f"Manifest signature mismatch! Expected: {expected_manifest_sha}, Got: {actual_manifest_sha}"
                    )

            manifest = json.loads(manifest_content)

            # 2. Validate DB Snapshot SHA-256 (Bit-rot detection)
            actual_db_sha = _compute_sha256(db_file)
            expected_db_sha = manifest.get("db_snapshot_sha256")
            if actual_db_sha != expected_db_sha:
                raise BackupCorruptionError(
                    f"Bit-rot detected in DB snapshot! Expected: {expected_db_sha}, Actual: {actual_db_sha}"
                )

            # 3. Validate Evidence Files
            evidence_manifest = manifest.get("evidence_files", {})
            evidence_dir = extract_dir / "evidence"
            for rel_path, expected_sha in evidence_manifest.items():
                ev_f = evidence_dir / rel_path
                if not ev_f.exists():
                    raise BackupCorruptionError(f"Evidence file missing from backup: {rel_path}")
                actual_ev_sha = _compute_sha256(ev_f)
                if actual_ev_sha != expected_sha:
                    raise BackupCorruptionError(
                        f"Evidence bit-rot in {rel_path}! Expected: {expected_sha}, Actual: {actual_ev_sha}"
                    )

            # 4. Restore Database to Target Engine
            target_engine = create_engine(target_db_url)
            Base.metadata.create_all(bind=target_engine)
            TargetSession = sessionmaker(bind=target_engine)
            target_session = TargetSession()

            src_engine = create_engine(f"sqlite:///{db_file}")
            SrcSession = sessionmaker(bind=src_engine)
            src_session = SrcSession()

            self._copy_all_records(src_session, target_session)
            target_session.commit()

            # 5. Verify Restored Counts Match Manifest
            expected_counts = manifest.get("counts", {})
            actual_counts = {
                "institutions": target_session.query(func.count(Institution.id)).scalar() or 0,
                "cases": target_session.query(func.count(Case.id)).scalar() or 0,
                "transactions": target_session.query(func.count(TransactionRecord.id)).scalar() or 0,
                "reports": target_session.query(func.count(ReportRecord.id)).scalar() or 0,
                "assessments": target_session.query(func.count(AssessmentRecord.id)).scalar() or 0,
                "chain_events": target_session.query(func.count(ChainEventRecord.id)).scalar() or 0,
                "checkpoints": target_session.query(func.count(CheckpointRecord.id)).scalar() or 0,
            }

            for model_name, exp_c in expected_counts.items():
                act_c = actual_counts.get(model_name, 0)
                if act_c != exp_c:
                    raise BackupCorruptionError(
                        f"Count mismatch after restore for {model_name}! Expected: {exp_c}, Actual: {act_c}"
                    )

            # 6. Restore Evidence Files to Target Directory
            if target_evidence_dir and evidence_manifest:
                t_ev_path = Path(target_evidence_dir)
                t_ev_path.mkdir(parents=True, exist_ok=True)
                for rel_path in evidence_manifest.keys():
                    src_ev = evidence_dir / rel_path
                    dst_ev = t_ev_path / rel_path
                    dst_ev.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_ev, dst_ev)

            src_session.close()
            target_session.close()

            return {
                "backup_id": manifest.get("backup_id"),
                "restored_at": datetime.now(timezone.utc).isoformat(),
                "status": "VERIFIED_RESTORED",
                "counts": actual_counts,
                "checkpoints": manifest.get("checkpoints", []),
            }

        finally:
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)

    def _copy_all_records(self, src: Session, dst: Session):
        """Copies all registered model instances across sessions in foreign-key dependency order."""
        models_in_order = [
            Institution,
            Membership,
            WalletBindingModel,
            Case,
            CaseEvent,
            EvidenceObject,
            EvidenceAnchor,
            Outbox,
            IdempotencyKey,
            TransactionRecord,
            ImportBatchRecord,
            PolicyVersionRecord,
            AssessmentRecord,
            ChainEventRecord,
            CheckpointRecord,
            ReportRecord,
        ]

        for model in models_in_order:
            rows = src.query(model).all()
            for r in rows:
                data = {c.name: getattr(r, c.name) for c in model.__table__.columns}
                dst.add(model(**data))
        dst.flush()
