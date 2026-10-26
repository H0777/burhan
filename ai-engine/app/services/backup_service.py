"""
Disaster Recovery, WORM Storage & Backup/Restore Service (T23 / R16)
Cyber-Forensic Auditing Framework - Specification §4, §6, §7, §8 & Requirement R11, R16, R18

Ensures automated, cryptographically verifiable and encrypted database snapshots,
evidence file integrity verification, hash integrity chains, bit-rot detection,
and idempotent outbox recovery.
"""

import os
import io
import json
import base64
import shutil
import zipfile
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from sqlalchemy import select, func, text, create_engine
from sqlalchemy.orm import Session, sessionmaker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.db.models import (
    Base, Institution, Membership, WalletBindingModel,
    Case, CaseEvent, EvidenceObject, EvidenceAnchor, Outbox, IdempotencyKey,
    TransactionRecord, ImportBatchRecord, PolicyVersionRecord, AssessmentRecord,
    ChainEventRecord, CheckpointRecord, ReportRecord
)
from app.security.signing import (
    Signer, Verifier, DOMAIN_BACKUP, STATUS_VERIFIED,
    canonical_bytes, envelope_digest, SignedEnvelope
)
try:
    from shared.python.evidence_crypto import TrustRegistry
except ImportError:
    TrustRegistry = Any  # type: ignore


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


class ChainIntegrityError(BackupCorruptionError):
    """Raised when the hash integrity chain linking backups is broken or missing."""
    pass


class BackupService:
    """
    Manages cold/warm backups, tamper validation, hash integrity chains,
    AES-256-GCM encryption, and isolated disaster recovery restore.
    """

    def __init__(
        self,
        evidence_dir: Optional[str] = None,
        key_provider: Optional[Any] = None,
        signer: Optional[Any] = None,
        audit_log_path: Optional[str] = None,
    ):
        self.evidence_dir = Path(evidence_dir or "evidence_store")
        self.key_provider = key_provider
        self.signer = signer
        self.audit_log_path = Path(audit_log_path) if audit_log_path else (self.evidence_dir / "backup_audit_log.jsonl")
        self._audit_logs: List[Dict[str, Any]] = []

    def _log_event(self, event: str, **kwargs) -> Dict[str, Any]:
        """Appends structured audit log event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs,
        }
        self._audit_logs.append(entry)
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
        except Exception:
            pass
        return entry

    def get_audit_logs(self) -> List[Dict[str, Any]]:
        """Returns recorded audit log entries."""
        if self.audit_log_path.exists():
            logs = []
            try:
                with open(self.audit_log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            logs.append(json.loads(line))
                if logs:
                    return logs
            except Exception:
                pass
        return list(self._audit_logs)

    def get_backup_digest(self, bundle_path: Path) -> str:
        """Returns SHA-256 digest of backup manifest envelope or content."""
        if not bundle_path.exists():
            raise FileNotFoundError(f"Backup file not found: {bundle_path}")
        with zipfile.ZipFile(bundle_path, "r") as zf:
            if "backup-manifest.json" not in zf.namelist():
                raise BackupCorruptionError("backup-manifest.json missing from bundle")
            manifest_content = zf.read("backup-manifest.json").decode("utf-8")
            manifest = json.loads(manifest_content)
            if "signature_envelope" in manifest:
                return envelope_digest(manifest["signature_envelope"])
            return hashlib.sha256(
                canonical_bytes(manifest) if isinstance(manifest, dict) else manifest_content.encode("utf-8")
            ).hexdigest()

    def verify_chain(self, backup_paths: List[Path]) -> bool:
        """
        Verifies cryptographic hash integrity chain across successive backups.
        Raises ChainIntegrityError if any link is broken.
        """
        if not backup_paths or len(backup_paths) < 2:
            return True

        for i in range(1, len(backup_paths)):
            prev_path = backup_paths[i - 1]
            curr_path = backup_paths[i]

            prev_digest = self.get_backup_digest(prev_path)
            with zipfile.ZipFile(curr_path, "r") as zf:
                manifest = json.loads(zf.read("backup-manifest.json").decode("utf-8"))

            curr_prev_ref = manifest.get("prev_backup_hash")
            if curr_prev_ref != prev_digest:
                self._log_event(
                    "CHAIN_INTEGRITY_FAILED",
                    prev_backup=prev_path.name,
                    curr_backup=curr_path.name,
                    expected_prev=prev_digest,
                    actual_prev=curr_prev_ref,
                )
                raise ChainIntegrityError(
                    f"Integrity chain broken between {prev_path.name} and {curr_path.name}: "
                    f"expected prev_backup_hash {prev_digest}, got {curr_prev_ref}"
                )
        return True

    def create_backup(
        self,
        session: Session,
        output_dir: str,
        backup_name: Optional[str] = None,
        institution_id: Optional[str] = None,
        prev_backup_hash: Optional[str] = None,
        encrypt: bool = True,
    ) -> Path:
        """
        Creates an immutable, signed, and encrypted backup bundle containing:
        - Relational DB snapshot (encrypted with AES-256-GCM if key_provider available)
        - Cryptographic evidence store files
        - Checkpoints & Outbox state
        - Hash integrity chain link (prev_backup_hash)
        - Cryptographic manifest with SHA-256 digests and SignedEnvelope (AML_BACKUP_V1)
        """
        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)

        backup_id = backup_name or f"BKP-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6]}"
        bundle_zip = out_path / f"{backup_id}.zip"

        if bundle_zip.exists():
            self._log_event("OVERWRITE_REJECTED", backup_id=backup_id, path=str(bundle_zip))
            raise FileExistsError(f"Backup '{backup_id}' already exists and is immutable (WORM violation).")

        stage_dir = out_path / f"stage_{backup_id}_{uuid4().hex[:6]}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        tmp_zip = out_path / f"tmp_{backup_id}_{uuid4().hex[:6]}.zip"

        try:
            db_snapshot_file = stage_dir / "snapshot.db"

            # 1. Capture Database Snapshot
            bind = session.get_bind()
            dialect_name = bind.dialect.name

            if dialect_name == "sqlite":
                session.commit()
                try:
                    session.execute(text(f"VACUUM INTO '{str(db_snapshot_file.resolve()).replace(chr(92), '/')}'"))
                except Exception:
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
                        evidence_manifest[str(rel_f).replace("\\", "/")] = _compute_sha256(dst_f)

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

            # 4. Optional AES-256-GCM Encryption
            inst_id = institution_id or "INST-CBI-IQ"
            should_encrypt = bool(encrypt and (self.key_provider is not None))
            ciphertext_sha256 = None

            # 5. Generate Manifest
            now_iso = datetime.now(timezone.utc).isoformat()
            manifest: Dict[str, Any] = {
                "manifest_version": "2.0.0",
                "backup_id": backup_id,
                "created_at": now_iso,
                "db_snapshot_sha256": db_sha256,
                "counts": counts,
                "checkpoints": checkpoints,
                "evidence_files": evidence_manifest,
            }
            if prev_backup_hash:
                manifest["prev_backup_hash"] = prev_backup_hash

            if should_encrypt and self.key_provider is not None:
                dek = os.urandom(32)
                wrapped_dek = self.key_provider.wrap_data_key(inst_id, dek)
                key_id = self.key_provider.get_current_key_id(inst_id)

                db_bytes = db_snapshot_file.read_bytes()
                nonce = os.urandom(12)
                aesgcm = AESGCM(dek)
                aad = json.dumps({
                    "backup_id": backup_id,
                    "institution_id": inst_id,
                    "schema_version": 1,
                }, sort_keys=True).encode("utf-8")

                ciphertext_and_tag = aesgcm.encrypt(nonce, db_bytes, aad)
                auth_tag = ciphertext_and_tag[-16:]
                ciphertext_sha256 = hashlib.sha256(ciphertext_and_tag).hexdigest()

                enc_file = stage_dir / "snapshot.db.enc"
                enc_file.write_bytes(ciphertext_and_tag)
                db_snapshot_file.unlink()

                manifest["storage_format"] = "aes256gcm_v1"
                manifest["wrapped_dek"] = wrapped_dek
                manifest["nonce"] = base64.b64encode(nonce).decode("ascii")
                manifest["auth_tag"] = base64.b64encode(auth_tag).decode("ascii")
                manifest["encryption_key_id"] = key_id
                manifest["ciphertext_sha256"] = ciphertext_sha256

            # Sign with Signer (AML_BACKUP_V1)
            if self.signer is not None and (institution_id or should_encrypt):
                key_id = self.key_provider.get_current_key_id(inst_id) if self.key_provider else "k1"
                sign_body = {
                    "institution_id": inst_id,
                    "key_id": key_id,
                    "schema_version": 1,
                    "backup_id": backup_id,
                    "created_at": now_iso,
                    "db_snapshot_sha256": db_sha256,
                }
                if ciphertext_sha256:
                    sign_body["ciphertext_sha256"] = ciphertext_sha256
                if prev_backup_hash:
                    sign_body["prev_backup_hash"] = prev_backup_hash

                envelope = self.signer.sign(inst_id, DOMAIN_BACKUP, sign_body)
                manifest["signature_envelope"] = envelope.to_dict()

            manifest_content = json.dumps(manifest, indent=2, sort_keys=True)
            manifest_file = stage_dir / "backup-manifest.json"
            manifest_file.write_text(manifest_content, encoding="utf-8")

            # Manifest sha256
            manifest_sha256 = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

            (stage_dir / "backup-manifest.sha256").write_text(manifest_sha256, encoding="utf-8")

            # 6. Package as ZIP Bundle atomically
            with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(stage_dir):
                    for file in files:
                        full_p = Path(root) / file
                        arcname = full_p.relative_to(stage_dir)
                        zf.write(full_p, arcname)

            tmp_zip.replace(bundle_zip)
            self._log_event("BACKUP_CREATED", backup_id=backup_id, path=str(bundle_zip), counts=counts)
            return bundle_zip
        except Exception as exc:
            if bundle_zip.exists():
                try:
                    bundle_zip.unlink()
                except OSError:
                    pass
            self._log_event("BACKUP_FAILED", backup_id=backup_id, error=str(exc))
            raise
        finally:
            if stage_dir.exists():
                shutil.rmtree(stage_dir, ignore_errors=True)
            if tmp_zip.exists():
                try:
                    tmp_zip.unlink()
                except OSError:
                    pass

    def restore_backup(
        self,
        bundle_path: Path,
        target_db_url: str,
        target_evidence_dir: Optional[str] = None,
        trust_registry: Optional[Any] = None,
        key_provider: Optional[Any] = None,
        trusted_time: Optional[datetime] = None,
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
                # Zip Slip / Directory traversal detection
                for member in zf.infolist():
                    name = member.filename
                    if ".." in name or name.startswith("/") or name.startswith("\\"):
                        self._log_event("RESTORE_REJECTED", reason="zip_slip_traversal", file=name)
                        raise BackupCorruptionError(f"Directory traversal / zip-slip attack detected: {name}")
                    dest = (extract_dir / name).resolve()
                    try:
                        dest.relative_to(extract_dir.resolve())
                    except ValueError:
                        self._log_event("RESTORE_REJECTED", reason="insecure_extraction_path", file=name)
                        raise BackupCorruptionError(f"Insecure file extraction path outside target directory: {name}")

                zf.extractall(extract_dir)

            manifest_file = extract_dir / "backup-manifest.json"
            manifest_sig_file = extract_dir / "backup-manifest.sha256"
            db_file = extract_dir / "snapshot.db"
            enc_db_file = extract_dir / "snapshot.db.enc"

            if not manifest_file.exists():
                raise BackupCorruptionError("Corrupted backup bundle: missing manifest.")
            if not db_file.exists() and not enc_db_file.exists():
                raise BackupCorruptionError("Corrupted backup bundle: missing snapshot.")

            # 1. Validate Manifest Integrity
            manifest_content = manifest_file.read_text(encoding="utf-8")
            actual_manifest_sha = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

            if manifest_sig_file.exists():
                expected_manifest_sha = manifest_sig_file.read_text(encoding="utf-8").strip()
                if actual_manifest_sha != expected_manifest_sha:
                    self._log_event("RESTORE_REJECTED", reason="manifest_sha_mismatch")
                    raise BackupCorruptionError(
                        f"Manifest signature mismatch! Expected: {expected_manifest_sha}, Got: {actual_manifest_sha}"
                    )

            manifest = json.loads(manifest_content)

            # 2. Validate Signature Envelope (if present)
            if "signature_envelope" in manifest:
                envelope = manifest["signature_envelope"]
                verifier = Verifier()
                result = verifier.verify(
                    DOMAIN_BACKUP,
                    envelope,
                    registry=trust_registry,
                    trusted_time=trusted_time,
                )
                if not result.is_verified:
                    self._log_event("RESTORE_REJECTED", reason="signature_verification_failed", detail=result.reason)
                    raise BackupCorruptionError(f"Backup signature verification failed: {result.reason}")

            # 3. Decrypt Encrypted Snapshot (if encrypted)
            storage_format = manifest.get("storage_format")
            if storage_format == "aes256gcm_v1":
                provider = key_provider or self.key_provider
                if provider is None:
                    raise BackupCorruptionError("Encrypted backup bundle requires key_provider to decrypt.")

                target_enc_file = enc_db_file if enc_db_file.exists() else db_file
                if not target_enc_file.exists():
                    raise BackupCorruptionError("Encrypted DB snapshot file missing from backup bundle.")

                inst_id = manifest.get("signature_envelope", {}).get("body", {}).get("institution_id") or "INST-CBI-IQ"
                wrapped_dek = manifest.get("wrapped_dek")
                if not wrapped_dek:
                    raise BackupCorruptionError("Encrypted backup missing wrapped_dek.")

                try:
                    dek = provider.unwrap_data_key(inst_id, wrapped_dek)
                except Exception as exc:
                    self._log_event("RESTORE_REJECTED", reason="unwrap_key_failed")
                    raise BackupCorruptionError(f"Failed to unwrap DEK: {exc}") from exc

                ciphertext_and_tag = target_enc_file.read_bytes()
                nonce = base64.b64decode(manifest["nonce"])
                aesgcm = AESGCM(dek)
                aad = json.dumps({
                    "backup_id": manifest["backup_id"],
                    "institution_id": inst_id,
                    "schema_version": 1,
                }, sort_keys=True).encode("utf-8")

                try:
                    plain_bytes = aesgcm.decrypt(nonce, ciphertext_and_tag, aad)
                except Exception as exc:
                    self._log_event("RESTORE_REJECTED", reason="gcm_tag_mismatch")
                    raise BackupCorruptionError(
                        f"Bit-rot / tampering detected in encrypted DB snapshot (GCM tag verification failed): {exc}"
                    ) from exc

                db_file = extract_dir / "snapshot.db"
                db_file.write_bytes(plain_bytes)

            # 4. Validate DB Snapshot SHA-256 (Bit-rot detection)
            actual_db_sha = _compute_sha256(db_file)
            expected_db_sha = manifest.get("db_snapshot_sha256")
            if actual_db_sha != expected_db_sha:
                self._log_event("RESTORE_REJECTED", reason="db_snapshot_bit_rot")
                raise BackupCorruptionError(
                    f"Bit-rot detected in DB snapshot! Expected: {expected_db_sha}, Actual: {actual_db_sha}"
                )

            # 5. Validate Evidence Files
            evidence_manifest = manifest.get("evidence_files", {})
            evidence_dir = extract_dir / "evidence"
            for rel_path, expected_sha in evidence_manifest.items():
                ev_f = evidence_dir / rel_path
                if not ev_f.exists():
                    self._log_event("RESTORE_REJECTED", reason="missing_evidence_file", file=rel_path)
                    raise BackupCorruptionError(f"Evidence file missing from backup: {rel_path}")
                actual_ev_sha = _compute_sha256(ev_f)
                if actual_ev_sha != expected_sha:
                    self._log_event("RESTORE_REJECTED", reason="evidence_bit_rot", file=rel_path)
                    raise BackupCorruptionError(
                        f"Evidence bit-rot in {rel_path}! Expected: {expected_sha}, Actual: {actual_ev_sha}"
                    )

            # 6. Restore Database to Target Engine
            target_engine = create_engine(target_db_url)
            Base.metadata.create_all(bind=target_engine)
            TargetSession = sessionmaker(bind=target_engine)
            target_session = TargetSession()

            src_engine = create_engine(f"sqlite:///{db_file}")
            SrcSession = sessionmaker(bind=src_engine)
            src_session = SrcSession()

            self._copy_all_records(src_session, target_session)
            target_session.commit()

            # 7. Verify Restored Counts Match Manifest
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
                    self._log_event("RESTORE_REJECTED", reason="count_mismatch", model=model_name)
                    raise BackupCorruptionError(
                        f"Count mismatch after restore for {model_name}! Expected: {exp_c}, Actual: {act_c}"
                    )

            # 8. Restore Evidence Files to Target Directory
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

            self._log_event("RESTORE_VERIFIED", backup_id=manifest.get("backup_id"), counts=actual_counts)
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
