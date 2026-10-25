"""
Evidence Vault & Immutable Object Store (T14 / R06)
Specification §6, §7 (R04, R06, R08, R09, R14)

R06 contract:

- AES-256-GCM at rest: every write through a key-provider-backed store is
  encrypted under a fresh random per-object DEK, wrapped by the institution
  key (key_id). The plaintext DEK is never stored anywhere. Objects written
  without a key provider are labelled ``legacy_plaintext_read_only`` (honest
  classification — never claimed encrypted).
- AAD binds institution + evidence + version (see encrypted_object).
- Atomic no-replace version publish: each version lives in its own directory
  ``<base>/<inst>/<evid>/v<n>/``; the directory name is claimed with
  ``os.mkdir`` (atomic, fails when it already exists — never
  exists-then-rename). Content is staged in a UNIQUE staging directory and
  moved into the claimed version directory; the ``COMMITTED.marker`` file is
  created only after object + metadata are in place. Readers refuse any
  version without the marker, so a crash can never expose a readable object.
- Path containment: every resolved path is verified with
  ``Path.relative_to`` against the store root (never string prefixes), and
  symlinked components are rejected.
- 25 * 1024 * 1024 byte limit enforced during streaming, before publication.
- Legacy flat-layout objects (pre-R06) remain readable as
  ``legacy_plaintext_read_only`` — no silent conversion, no retroactive
  signing or encryption. ``migrate_to_encrypted`` creates a LATER encrypted
  copy that records the original hash and a migration record; the original
  bytes and their provenance level stay untouched.
"""

import hashlib
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Tuple

from pydantic import BaseModel, ConfigDict

from app.config import settings
from app.services.encrypted_object import (
    InvalidCiphertextError,
    LEGACY_PLAINTEXT_FORMAT,
    MalformedMetadataError,
    MissingKeyMaterialError,
    STORAGE_FORMAT,
    decrypt_bytes,
    encrypt_bytes,
)

MAX_SIZE_BYTES = 25 * 1024 * 1024

_OBJECT_FILE = "object.bin"
_META_FILE = "meta.json"
_MARKER_FILE = "COMMITTED.marker"
_STAGING_PREFIX = ".staging_v"

_REQUIRED_META_FIELDS = (
    "evidence_id",
    "object_version",
    "institution_id",
    "file_name",
    "content_type",
    "file_size",
    "sha256_hash",
    "created_at",
)


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
    display_name: str = ""
    storage_format: str = ""


class EvidenceStore:
    def __init__(
        self,
        base_dir: Optional[str] = None,
        max_size_bytes: Optional[int] = None,
        key_provider=None,
    ):
        self.base_dir = Path(base_dir or settings.EVIDENCE_STORE_PATH).resolve()
        self.max_size_bytes = max_size_bytes or settings.MAX_EVIDENCE_SIZE_BYTES
        self.key_provider = key_provider
        self.base_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # path safety
    # ------------------------------------------------------------------

    def _sanitize_path_segment(self, segment: str, name: str) -> str:
        """
        Prevents directory traversal attacks (../, absolute paths, null bytes,
        unicode control chars).
        """
        if not segment or not isinstance(segment, str):
            raise ValueError(f"Invalid {name}: must be a non-empty string")

        clean = segment.strip()
        if ".." in clean or "/" in clean or "\\" in clean or "\0" in clean:
            raise ValueError(f"Directory traversal detected in {name}")
        if clean.startswith("."):
            raise ValueError(f"Hidden or relative segment not allowed for {name}")
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
            raise ValueError(f"Illegal characters in {name}")
        return clean

    def _sanitize_file_name(self, raw: Any) -> Tuple[str, str]:
        """Reject traversal payloads in metadata['file_name']; return
        (safe_internal_ascii_name, original_display_name)."""
        if raw is None:
            return "", ""
        if not isinstance(raw, str) or not raw:
            raise ValueError("metadata file_name must be a non-empty string")
        display = raw
        # Traversal payloads are REJECTED, never silently sanitized.
        if ".." in raw or "/" in raw or "\\" in raw or "\0" in raw or Path(raw).name != raw:
            raise ValueError(f"Directory traversal detected in file_name: {raw!r}")
        internal = re.sub(r"[^A-Za-z0-9\.\-_]", "_", raw)
        if not internal or not internal.isascii() or internal.startswith("."):
            internal = ""
        return internal, display

    def validate_within_root(self, path: Path) -> Path:
        """Containment via Path.relative_to — sibling-prefix paths fail."""
        resolved = Path(path).resolve()
        try:
            resolved.relative_to(self.base_dir)
        except ValueError:
            raise ValueError(
                f"Path escapes the evidence vault root: {resolved} is outside {self.base_dir}"
            ) from None
        return resolved

    def _check_no_symlinks(self, path: Path) -> None:
        """Reject any symlinked (or junction — the privilege-free Windows
        equivalent) component between the store root and path."""
        resolved = Path(path).resolve()
        if resolved == self.base_dir:
            return
        current = resolved
        while current != self.base_dir:
            if current.is_symlink():
                raise ValueError(f"symlink detected in vault path: {current}")
            if current.is_junction():
                raise ValueError(f"symlink/junction detected in vault path: {current}")
            parent = current.parent
            if parent == current:
                break
            current = parent

    def _check_no_symlinks_below_root(self, candidate: Path) -> None:
        """Walk the UNRESOLVED candidate below the root and reject symlinked
        components BEFORE resolution (a symlinked component would otherwise
        surface as a containment escape, hiding the real cause)."""
        current = candidate
        while current != self.base_dir:
            if current.is_symlink():
                raise ValueError(f"symlink detected in vault path: {current}")
            if current.is_junction():
                raise ValueError(f"symlink/junction detected in vault path: {current}")
            parent = current.parent
            if parent == current:
                break
            current = parent

    def _scoped_evidence_dir(self, institution_id: str, evidence_id: str) -> Path:
        clean_inst = self._sanitize_path_segment(institution_id, "institution_id")
        clean_ev = self._sanitize_path_segment(evidence_id, "evidence_id")
        candidate = self.base_dir / clean_inst / clean_ev
        self._check_no_symlinks_below_root(candidate)
        ev_dir = candidate.resolve()
        self.validate_within_root(ev_dir)
        self._check_no_symlinks(ev_dir)
        return ev_dir

    # ------------------------------------------------------------------
    # write path
    # ------------------------------------------------------------------

    def put(
        self,
        stream_or_bytes: BinaryIO | bytes,
        metadata: Dict[str, Any],
        institution_id: str,
        evidence_id: str,
        object_version: int = 1,
    ) -> StoredEvidence:
        """
        Saves evidence with streaming hash, size-limit enforcement,
        AES-256-GCM encryption when a key provider is configured, and atomic
        no-replace version publication.
        """
        if not isinstance(object_version, int) or object_version < 1:
            raise ValueError("object_version must be a positive integer")
        if metadata is None or not isinstance(metadata, dict):
            raise ValueError("metadata must be a non-empty dict")

        # Validate everything BEFORE creating any directory, so rejected
        # requests leave nothing behind on disk.
        clean_inst = self._sanitize_path_segment(institution_id, "institution_id")
        clean_ev = self._sanitize_path_segment(evidence_id, "evidence_id")
        raw_name = metadata.get("file_name")
        internal_name, display_name = self._sanitize_file_name(raw_name)
        if not internal_name:
            internal_name = f"{clean_ev}.bin"
        content_type = metadata.get("content_type", "application/octet-stream")

        ev_dir = self._scoped_evidence_dir(institution_id, evidence_id)
        ev_dir.mkdir(parents=True, exist_ok=True)

        staging_dir = ev_dir / f"{_STAGING_PREFIX}{object_version}_{uuid.uuid4().hex}"
        staging_dir.mkdir()  # unique per writer; no cross-writer collisions

        try:
            # 1. Stream plaintext into staging, hashing and enforcing the size
            #    limit before any publication.
            plain_tmp = staging_dir / "plain.tmp"
            sha256 = hashlib.sha256()
            total_bytes = 0
            chunk_size = 64 * 1024
            source = (
                io.BytesIO(stream_or_bytes)
                if isinstance(stream_or_bytes, bytes)
                else stream_or_bytes
            )
            with open(plain_tmp, "wb") as f_out:
                while True:
                    chunk = source.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > self.max_size_bytes:
                        raise ValueError(
                            f"File size exceeds maximum allowed threshold of "
                            f"{self.max_size_bytes} bytes (25MB)"
                        )
                    sha256.update(chunk)
                    f_out.write(chunk)

            with open(plain_tmp, "rb") as f_plain:
                plaintext = f_plain.read()
            plain_tmp.unlink()

            # 2. Encrypt (or honestly label as legacy plaintext when no key
            #    provider is configured).
            if self.key_provider is not None:
                enc = encrypt_bytes(
                    plaintext,
                    institution_id=clean_inst,
                    evidence_id=clean_ev,
                    object_version=object_version,
                    key_provider=self.key_provider,
                )
                storage_format = enc["storage_format"]
                object_bytes = enc["ciphertext"]
            else:
                enc = None
                storage_format = LEGACY_PLAINTEXT_FORMAT
                object_bytes = plaintext

            (staging_dir / _OBJECT_FILE).write_bytes(object_bytes)

            now = datetime.now(timezone.utc)
            record_meta = {
                "evidence_id": clean_ev,
                "object_version": object_version,
                "institution_id": clean_inst,
                "file_name": internal_name,
                "display_name": display_name or internal_name,
                "content_type": content_type,
                "file_size": total_bytes,
                "sha256_hash": sha256.hexdigest(),
                "created_at": now.isoformat(),
                "storage_format": storage_format,
                "metadata": metadata,
            }
            if enc is not None:
                record_meta.update(
                    {
                        "encryption_key_id": enc["encryption_key_id"],
                        "wrapped_dek": enc["wrapped_dek"],
                        "nonce": enc["nonce"],
                        "auth_tag": enc["auth_tag"],
                    }
                )
            if isinstance(metadata.get("migration"), dict):
                # First-class migration record (legacy -> encrypted copy):
                # preserves original hash + provenance level, never silently.
                record_meta["migration"] = metadata["migration"]
            (staging_dir / _META_FILE).write_text(
                json.dumps(record_meta, indent=2), encoding="utf-8"
            )

            # 3. Atomic no-replace publish.
            return self._publish_version(
                staging_dir=staging_dir,
                ev_dir=ev_dir,
                institution_id=clean_inst,
                evidence_id=clean_ev,
                object_version=object_version,
                record_meta=record_meta,
            )
        except FileExistsError:
            raise ValueError(
                f"WORM Violation: Evidence '{clean_ev}' version {object_version} "
                "already exists and is immutable"
            ) from None
        except Exception:
            raise
        finally:
            if staging_dir.exists():
                self._rmtree(staging_dir)

    def _publish_version(
        self,
        staging_dir: Path,
        ev_dir: Path,
        institution_id: str,
        evidence_id: str,
        object_version: int,
        record_meta: Dict[str, Any],
    ) -> StoredEvidence:
        """Claim the version directory atomically (no-replace), move the
        staged object + metadata in, then write the completion marker.

        If anything fails after the claim but before the marker, the claim is
        rolled back here: the claiming writer owns the version directory until
        the marker exists, so removing an unmarked claim cannot race another
        writer (they can never have created it).
        """
        version_dir = (ev_dir / f"v{object_version}").resolve()
        self.validate_within_root(version_dir)

        # os.mkdir is the no-replace primitive: it fails atomically when the
        # version directory already exists. We never exists-then-rename.
        version_dir.mkdir(exist_ok=False)

        marker_written = False
        try:
            # Move staged content into the claimed directory (same volume,
            # os.replace semantics; only the claim owner writes here).
            os.replace(staging_dir / _OBJECT_FILE, version_dir / _OBJECT_FILE)
            os.replace(staging_dir / _META_FILE, version_dir / _META_FILE)

            # Completion marker LAST: readers refuse versions without it.
            marker = version_dir / _MARKER_FILE
            fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, record_meta["created_at"].encode("ascii"))
            finally:
                os.close(fd)
            marker_written = True
        finally:
            if not marker_written:
                try:
                    self._rmtree(version_dir)
                except OSError:
                    pass

        return StoredEvidence(
            evidence_id=evidence_id,
            object_version=object_version,
            sha256=record_meta["sha256_hash"],
            size=record_meta["file_size"],
            storage_path=str(version_dir / _OBJECT_FILE),
            file_name=record_meta["file_name"],
            content_type=record_meta["content_type"],
            created_at=datetime.fromisoformat(record_meta["created_at"]),
            display_name=record_meta.get("display_name", ""),
            storage_format=record_meta.get("storage_format", ""),
        )

    def _rmtree(self, path: Path) -> None:
        try:
            for child in path.iterdir():
                try:
                    if child.is_dir() and not child.is_symlink():
                        self._rmtree(child)
                    else:
                        child.unlink()
                except OSError:
                    continue
            path.rmdir()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # read path
    # ------------------------------------------------------------------

    def _load_version_meta(self, version_dir: Path) -> Dict[str, Any]:
        if not (version_dir / _MARKER_FILE).exists():
            raise FileNotFoundError(
                f"Evidence version {version_dir.name} has no completion marker; "
                "unpublished or incomplete objects are never readable"
            )
        meta_file = version_dir / _META_FILE
        if not meta_file.exists():
            raise ValueError(
                f"Evidence object at {version_dir} is missing required metadata; refusing to open"
            )
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(
                f"Evidence object at {version_dir} has unreadable metadata; refusing to open"
            ) from exc
        missing = [f for f in _REQUIRED_META_FIELDS if f not in meta]
        if missing:
            raise ValueError(
                f"Evidence object at {version_dir} is missing required metadata fields: {missing}"
            )
        return meta

    def open(
        self,
        institution_id: str,
        evidence_id: str,
        object_version: int = 1,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """
        Opens and verifies stored evidence. For encrypted objects the GCM tag
        is verified (with the AAD bound to institution+evidence+version)
        before any plaintext is released. Legacy flat-layout objects are read
        as ``legacy_plaintext_read_only`` with SHA-256 verification only.
        """
        ev_dir = self._scoped_evidence_dir(institution_id, evidence_id)
        clean_ev = self._sanitize_path_segment(evidence_id, "evidence_id")
        version_dir = (ev_dir / f"v{object_version}").resolve()
        self.validate_within_root(version_dir)
        self._check_no_symlinks(version_dir)

        if version_dir.is_dir():
            meta = self._load_version_meta(version_dir)
            self._assert_meta_identity(meta, institution_id, clean_ev, object_version)
            object_file = version_dir / _OBJECT_FILE
            if not object_file.exists():
                raise FileNotFoundError(
                    f"Underlying evidence object missing at {object_file}"
                )
            self._check_no_symlinks(object_file)
            stored_bytes = object_file.read_bytes()
            storage_format = meta.get("storage_format", LEGACY_PLAINTEXT_FORMAT)
            if storage_format == STORAGE_FORMAT:
                data = self._decrypt_verified(stored_bytes, meta, institution_id, clean_ev, object_version)
            else:
                data = stored_bytes
                self._verify_legacy_hash(data, meta)
                meta = dict(meta, storage_format=LEGACY_PLAINTEXT_FORMAT)
            return data, meta

        # Legacy (pre-R06) flat layout: v{n}_meta.json + v{n}_{file_name}.
        return self._open_legacy_flat(ev_dir, institution_id, evidence_id, object_version)

    def _open_legacy_flat(
        self, ev_dir: Path, institution_id: str, evidence_id: str, object_version: int
    ) -> Tuple[bytes, Dict[str, Any]]:
        meta_file = (ev_dir / f"v{object_version}_meta.json").resolve()
        if not meta_file.exists():
            raise FileNotFoundError(
                f"Evidence {evidence_id} v{object_version} not found in vault"
            )
        self._check_no_symlinks(meta_file)
        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)
        file_name = meta["file_name"]
        target_file = (ev_dir / f"v{object_version}_{file_name}").resolve()
        self.validate_within_root(target_file)
        self._check_no_symlinks(target_file)
        if not target_file.exists():
            raise FileNotFoundError(f"Underlying evidence object missing at {target_file}")
        data = target_file.read_bytes()
        self._verify_legacy_hash(data, meta)
        meta = dict(meta, storage_format=LEGACY_PLAINTEXT_FORMAT)
        return data, meta

    @staticmethod
    def _assert_meta_identity(
        meta: Dict[str, Any], institution_id: str, evidence_id: str, object_version: int
    ) -> None:
        if (
            meta.get("institution_id") != institution_id
            or meta.get("evidence_id") != evidence_id
            or int(meta.get("object_version", -1)) != int(object_version)
        ):
            raise ValueError(
                "Integrity Compromised: object metadata does not match the requested "
                "institution/evidence/version address"
            )

    @staticmethod
    def _verify_legacy_hash(data: bytes, meta: Dict[str, Any]) -> None:
        actual = hashlib.sha256(data).hexdigest()
        if actual != meta["sha256_hash"]:
            raise ValueError(
                f"Integrity Compromised: File hash '{actual}' does not match vault "
                f"manifest '{meta['sha256_hash']}'"
            )

    def _decrypt_verified(
        self,
        stored_bytes: bytes,
        meta: Dict[str, Any],
        institution_id: str,
        evidence_id: str,
        object_version: int,
    ) -> bytes:
        import base64 as _b64

        for field in ("wrapped_dek", "nonce", "auth_tag", "encryption_key_id"):
            if field not in meta:
                raise ValueError(
                    f"Evidence object is missing required metadata field '{field}'; "
                    "refusing to open an encrypted object"
                )
        try:
            nonce = _b64.b64decode(meta["nonce"], validate=True)
            auth_tag = _b64.b64decode(meta["auth_tag"], validate=True)
        except Exception as exc:
            raise ValueError("Integrity Compromised: malformed nonce/auth_tag metadata") from exc
        try:
            data = decrypt_bytes(
                stored_bytes,
                nonce=nonce,
                auth_tag=auth_tag,
                wrapped_dek=meta["wrapped_dek"],
                institution_id=institution_id,
                evidence_id=evidence_id,
                object_version=object_version,
                key_provider=self.key_provider,
            )
        except MissingKeyMaterialError:
            raise
        except MalformedMetadataError as exc:
            raise ValueError(f"Integrity Compromised: {exc}") from exc
        except InvalidCiphertextError as exc:
            raise ValueError(
                "Integrity Compromised: File hash verification failed "
                f"(GCM tag mismatch): {exc}"
            ) from exc
        actual = hashlib.sha256(data).hexdigest()
        if actual != meta["sha256_hash"]:
            raise ValueError(
                f"Integrity Compromised: File hash '{actual}' does not match vault "
                f"manifest '{meta['sha256_hash']}'"
            )
        return data

    def get_object_meta(
        self,
        institution_id: str,
        evidence_id: str,
        object_version: int = 1,
    ) -> Dict[str, Any]:
        """Load a published version's metadata WITHOUT reading the object
        bytes (used by the broker to persist encryption metadata)."""
        ev_dir = self._scoped_evidence_dir(institution_id, evidence_id)
        version_dir = (ev_dir / f"v{object_version}").resolve()
        self.validate_within_root(version_dir)
        self._check_no_symlinks(version_dir)
        if not version_dir.is_dir():
            raise FileNotFoundError(
                f"Evidence {evidence_id} v{object_version} not found in vault"
            )
        return self._load_version_meta(version_dir)

    def open_verified_stream(
        self,
        institution_id: str,
        evidence_id: str,
        object_version: int,
    ) -> BinaryIO:
        """Large/verified read: plaintext is released as a stream only AFTER
        the GCM tag (or legacy hash) verification succeeds. The verified
        plaintext is staged into a protected temp file inside the vault's
        ``.tmp`` directory (never the caller's paths)."""
        data, _meta = self.open(institution_id, evidence_id, object_version)

        tmp_dir = (self.base_dir / ".tmp").resolve()
        self.validate_within_root(tmp_dir)
        tmp_dir.mkdir(exist_ok=True)
        tmp_file = tmp_dir / f"verified_{uuid.uuid4().hex}.tmp"
        fd = os.open(str(tmp_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        try:
            os.chmod(tmp_file, 0o600)  # best-effort on Windows ACLs
        except OSError:
            pass
        return open(tmp_file, "rb")

    # ------------------------------------------------------------------
    # legacy migration (explicit, never silent)
    # ------------------------------------------------------------------

    def migrate_to_encrypted(
        self,
        institution_id: str,
        evidence_id: str,
        legacy_version: int = 1,
        key_provider=None,
        object_version: Optional[int] = None,
    ) -> StoredEvidence:
        """Create a LATER encrypted copy of a legacy object.

        The original version is left byte-for-byte unchanged
        (``legacy_plaintext_read_only``); the new version records the
        original SHA-256 and a migration record. Provenance level of the
        original is not upgraded — the migration record says so explicitly.
        """
        provider = key_provider or self.key_provider
        if provider is None:
            raise MissingKeyMaterialError("migrate_to_encrypted requires a key provider")

        data, meta = self.open(institution_id, evidence_id, legacy_version)
        if meta.get("storage_format") == STORAGE_FORMAT:
            raise ValueError("object is already encrypted; migration applies to legacy objects only")

        target_version = object_version if object_version is not None else legacy_version + 1
        migration_meta = dict(meta.get("metadata") or {})
        migration_meta.setdefault("file_name", meta.get("display_name") or meta["file_name"])
        migration_meta["content_type"] = meta.get("content_type", "application/octet-stream")
        migration_meta["migration"] = {
            "migrated_from_version": legacy_version,
            "original_sha256": meta["sha256_hash"],
            "original_storage_format": meta.get("storage_format", LEGACY_PLAINTEXT_FORMAT),
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "provenance_level": "unchanged_from_original",
        }
        # Write through a store configured with the encryption provider (the
        # source store may be legacy-plaintext by configuration).
        writer = self if provider is self.key_provider else EvidenceStore(
            base_dir=str(self.base_dir),
            max_size_bytes=self.max_size_bytes,
            key_provider=provider,
        )
        return writer.put(
            stream_or_bytes=io.BytesIO(data),
            metadata=migration_meta,
            institution_id=institution_id,
            evidence_id=evidence_id,
            object_version=target_version,
        )

    # ------------------------------------------------------------------
    # signed manifest (R06: real signature, not a digest named signature)
    # ------------------------------------------------------------------

    def get_signed_manifest(
        self,
        institution_id: str,
        case_id: str,
        evidence_id: str,
        sha256_hash: str,
        anchor_request_id: str,
        participant_id: str,
        *,
        object_version: int = 1,
        size: int = 0,
        key_id: str = "",
        issued_at: Optional[datetime] = None,
        signer=None,
    ) -> Dict[str, Any]:
        """Produce a REAL Ed25519 SignedEnvelope (R05) over the service
        manifest body. Returns the envelope dict; the caller computes
        ``manifest_digest`` over the canonical SIGNED envelope (signature
        included) — a digest of the body alone is not acceptable."""
        if signer is None:
            raise ValueError(
                "get_signed_manifest requires a Signer; refusing to emit an unsigned manifest"
            )
        from app.security.signing import DOMAIN_SERVICE_MANIFEST

        now = issued_at or datetime.now(timezone.utc)
        body = {
            "institution_id": institution_id,
            "case_id": case_id,
            "evidence_id": evidence_id,
            "object_version": int(object_version),
            "file_sha256": sha256_hash,
            "size": int(size),
            "anchor_request_id": anchor_request_id,
            "participant_id": participant_id,
            "issued_at": now.isoformat(),
            "key_id": key_id,
        }
        envelope = signer.sign(institution_id, DOMAIN_SERVICE_MANIFEST, body)
        return envelope.to_dict()
