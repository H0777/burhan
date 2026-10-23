"""
Evidence Vault & Immutable Object Store (T14)
Specification §6, §7 (R04, R08, R09, R14)
Enforces streaming SHA-256 calculation, 25MB limits, path-traversal prevention,
and immutable Write-Once-Read-Many (WORM) versioning.
"""

import os
import re
import io
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import BinaryIO, Dict, Any, Tuple, Optional
from pydantic import BaseModel, ConfigDict

from app.config import settings


class StoredEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    object_version: int
    sha256: str
    size: int
    storage_path: str
    file_name: str
    content_type: str
    created_at: datetime


class EvidenceStore:
    def __init__(
        self,
        base_dir: Optional[str] = None,
        max_size_bytes: Optional[int] = None,
    ):
        self.base_dir = Path(base_dir or settings.EVIDENCE_STORE_PATH).resolve()
        self.max_size_bytes = max_size_bytes or settings.MAX_EVIDENCE_SIZE_BYTES
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_path_segment(self, segment: str, name: str) -> str:
        """
        Prevents directory traversal attacks (../, absolute paths, null bytes, unicode control chars).
        """
        if not segment or not isinstance(segment, str):
            raise ValueError(f"Invalid {name}: must be a non-empty string")

        clean = segment.strip()
        # Reject traversal attempts
        if ".." in clean or "/" in clean or "\\" in clean or "\0" in clean:
            raise ValueError(f"Directory traversal detected in {name}")

        # Strict character set: alphanumeric, hyphens, underscores, dots (no leading dot)
        if clean.startswith("."):
            raise ValueError(f"Hidden or relative segment not allowed for {name}")

        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
            raise ValueError(f"Illegal characters in {name}")

        return clean

    def put(
        self,
        stream_or_bytes: BinaryIO | bytes,
        metadata: Dict[str, Any],
        institution_id: str,
        evidence_id: str,
        object_version: int = 1,
    ) -> StoredEvidence:
        """
        Saves evidence file with streaming hash and size limit enforcement.
        Rejects sizes > 25MB immediately without buffering the entire oversized file into memory.
        """
        clean_inst = self._sanitize_path_segment(institution_id, "institution_id")
        clean_ev_id = self._sanitize_path_segment(evidence_id, "evidence_id")
        raw_filename = metadata.get("file_name", f"{clean_ev_id}.dat")
        # Sanitize filename
        safe_filename = Path(raw_filename).name
        safe_filename = re.sub(r"[^\w\.\-]", "_", safe_filename)

        # Build scoped directory: <base_dir>/<institution_id>/<evidence_id>/
        ev_dir = (self.base_dir / clean_inst / clean_ev_id).resolve()
        # Security invariant: Assert path is strictly within base_dir
        if not str(ev_dir).startswith(str(self.base_dir)):
            raise ValueError("Target path escapes evidence vault boundary")

        ev_dir.mkdir(parents=True, exist_ok=True)

        target_file = (ev_dir / f"v{object_version}_{safe_filename}").resolve()
        meta_file = (ev_dir / f"v{object_version}_meta.json").resolve()

        # WORM Invariant: Overwriting an existing version is strictly prohibited
        if target_file.exists() or meta_file.exists():
            raise ValueError(
                f"WORM Violation: Evidence '{clean_ev_id}' version {object_version} already exists and is immutable"
            )

        # Stream reader
        if isinstance(stream_or_bytes, bytes):
            stream = io.BytesIO(stream_or_bytes)
        else:
            stream = stream_or_bytes

        sha256 = hashlib.sha256()
        total_bytes = 0
        chunk_size = 64 * 1024  # 64 KB chunks

        # Stream into temporary staging file
        temp_file = (ev_dir / f".staging_v{object_version}_{safe_filename}.tmp").resolve()
        try:
            with open(temp_file, "wb") as f_out:
                while True:
                    chunk = stream.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > self.max_size_bytes:
                        raise ValueError(
                            f"File size exceeds maximum allowed threshold of {self.max_size_bytes} bytes (25MB)"
                        )
                    sha256.update(chunk)
                    f_out.write(chunk)

            # Atomic rename from staging to final immutable location
            temp_file.rename(target_file)
        except Exception:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            raise

        digest = sha256.hexdigest()
        now = datetime.now(timezone.utc)
        content_type = metadata.get("content_type", "application/octet-stream")

        record_meta = {
            "evidence_id": clean_ev_id,
            "object_version": object_version,
            "institution_id": clean_inst,
            "file_name": safe_filename,
            "content_type": content_type,
            "file_size": total_bytes,
            "sha256_hash": digest,
            "created_at": now.isoformat(),
            "metadata": metadata,
        }

        with open(meta_file, "w", encoding="utf-8") as f_meta:
            json.dump(record_meta, f_meta, indent=2)

        return StoredEvidence(
            evidence_id=clean_ev_id,
            object_version=object_version,
            sha256=digest,
            size=total_bytes,
            storage_path=str(target_file),
            file_name=safe_filename,
            content_type=content_type,
            created_at=now,
        )

    def open(
        self,
        institution_id: str,
        evidence_id: str,
        object_version: int = 1,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Opens and verifies stored evidence, verifying cryptographic integrity on read.
        """
        clean_inst = self._sanitize_path_segment(institution_id, "institution_id")
        clean_ev_id = self._sanitize_path_segment(evidence_id, "evidence_id")

        ev_dir = (self.base_dir / clean_inst / clean_ev_id).resolve()
        meta_file = (ev_dir / f"v{object_version}_meta.json").resolve()

        if not meta_file.exists():
            raise FileNotFoundError(f"Evidence {clean_ev_id} v{object_version} not found in vault")

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        file_name = meta["file_name"]
        target_file = (ev_dir / f"v{object_version}_{file_name}").resolve()
        if not target_file.exists():
            raise FileNotFoundError(f"Underlying evidence object missing at {target_file}")

        with open(target_file, "rb") as f_in:
            data = f_in.read()

        # Integrity verification
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != meta["sha256_hash"]:
            raise ValueError(
                f"Integrity Compromised: File hash '{actual_sha256}' does not match vault manifest '{meta['sha256_hash']}'"
            )

        return data, meta

    def get_signed_manifest(
        self,
        institution_id: str,
        case_id: str,
        evidence_id: str,
        sha256_hash: str,
        anchor_request_id: str,
        participant_id: str,
    ) -> Dict[str, Any]:
        """
        Produces verifiable service manifest linking institution, case, file hash, and chain anchor.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "schema_version": "SERVICE_MANIFEST_V2",
            "institution_id": institution_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "file_sha256": sha256_hash,
            "anchor_request_id": anchor_request_id,
            "submitted_by_participant": participant_id,
            "issued_at": now.isoformat(),
        }
        # Manifest signature / certificate hash
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        payload["manifest_digest"] = "0x" + hashlib.sha256(payload_bytes).hexdigest()
        return payload
