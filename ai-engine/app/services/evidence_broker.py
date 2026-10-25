"""
Evidence Broker Service (T14 / R06)
Specification §4, §5, §6, §7 (R01, R04, R06, R08, R09, R14)

Validates assignment and role, stores into the WORM evidence store (R06:
AES-256-GCM at rest, atomic no-replace version publish), issues a REAL
signed service manifest (R05 SignedEnvelope over AML_SERVICE_MANIFEST_V1 —
a signature, not a digest named signature), and writes EvidenceObject,
EvidenceAnchor (PENDING_ANCHOR), and the Outbox item inside ONE tenant
transaction.

Ordering guarantee (R06): the signed envelope is persisted on the
EvidenceObject row (manifest_envelope_json + manifest_digest) BEFORE the
outbox event that references it is created — an outbox event never points at
an unstored manifest. manifest_digest is SHA-256 of the canonical SIGNED
envelope (the signature itself is inside the digest input), never a digest
of the body alone.

Failure semantics: if the DB write fails, the session is rolled back and
only unpublished staging is deleted (the store deletes its own staging).
A disk object whose DB row rolled back becomes an ORPHAN; orphan collection
is later-retention work — this broker never deletes published/anchored
files (spec §6: disk presence alone is not WORM, and provenance files must
not be destroyed on the basis of a rolled-back transaction).
"""

import uuid
import json
import hashlib
from typing import BinaryIO, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.schemas.identity import Identity, RoleEnum
from app.services.evidence_store import EvidenceStore, StoredEvidence
from app.security.signing import Signer, envelope_digest
from app.repositories import (
    case_repository,
    evidence_repository,
    outbox_repository,
)
from app.db.models import IdempotencyKey, Case


class EvidenceBrokerError(Exception):
    pass


class RoleNotAuthorizedError(EvidenceBrokerError):
    pass


class CaseAssignmentError(EvidenceBrokerError):
    pass


class IdempotencyConflictError(EvidenceBrokerError):
    pass


class MissingSignerError(EvidenceBrokerError):
    """No signer configured: a signed manifest is mandatory, an unsigned or
    digest-only manifest is never emitted (fail-closed)."""


def compute_anchor_request_id(institution_id: str, case_id: str, evidence_id: str, sha256_hash: str) -> str:
    """
    Computes a deterministic bytes32 hex string (0x...) for on-chain deduplication.
    """
    data = f"{institution_id}:{case_id}:{evidence_id}:{sha256_hash}".encode("utf-8")
    return "0x" + hashlib.sha256(data).hexdigest()


class EvidenceBroker:
    def __init__(
        self,
        evidence_store: EvidenceStore,
        signer: Optional[Signer] = None,
        key_provider=None,
    ):
        self.evidence_store = evidence_store
        self.signer = signer
        self.key_provider = key_provider or evidence_store.key_provider

    def submit_case_evidence(
        self,
        session: Session,
        identity: Identity,
        case_id: str,
        file_name: str,
        content_type: str,
        stream: BinaryIO,
        evidence_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        chain_id: int = 1337,
        contract_address: str = "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    ) -> Dict[str, Any]:
        institution_id = identity.institution_id
        actor_sub = identity.sub
        role_str = identity.role.value if hasattr(identity.role, "value") else str(identity.role)

        # 0. Signed-manifest capability is mandatory (fail-closed).
        if self.signer is None or self.key_provider is None:
            raise MissingSignerError(
                "EvidenceBroker requires a Signer and a key provider; "
                "refusing to accept evidence without a signed manifest"
            )

        # 1. Role validation
        allowed_roles = {"OPERATOR", "SUPER_ADMIN", "ADMIN", "INVESTIGATOR", "COMPLIANCE_OFFICER"}
        if role_str not in allowed_roles:
            raise RoleNotAuthorizedError(f"Role '{role_str}' is not authorized to submit case evidence")

        # 2. Case retrieval and assignment validation
        case = case_repository.get_case(session, institution_id, case_id)
        if not case:
            raise case_repository.CaseNotFoundError(f"Case {case_id} not found for institution {institution_id}")

        is_admin = role_str in {"SUPER_ADMIN", "ADMIN"}
        if case.assigned_to_sub and not is_admin and case.assigned_to_sub != actor_sub:
            raise CaseAssignmentError(f"User '{actor_sub}' is not assigned to case '{case_id}'")

        # 3. Check idempotency key if provided
        request_fingerprint = hashlib.sha256(
            f"{institution_id}:{case_id}:{file_name}".encode("utf-8")
        ).hexdigest()

        if idempotency_key:
            existing_key = session.execute(
                select(IdempotencyKey).where(
                    IdempotencyKey.institution_id == institution_id,
                    IdempotencyKey.key == idempotency_key,
                )
            ).scalars().first()
            if existing_key:
                if existing_key.request_hash != request_fingerprint:
                    raise IdempotencyConflictError(
                        f"Idempotency key '{idempotency_key}' was previously used with a different request payload"
                    )
                if existing_key.response_json:
                    return json.loads(existing_key.response_json)

        # 4. Stream into the WORM evidence store (R06: encrypted, no-replace)
        ev_id = evidence_id or f"ev_{uuid.uuid4().hex[:16]}"
        stored: StoredEvidence = self.evidence_store.put(
            stream_or_bytes=stream,
            metadata={
                "file_name": file_name,
                "content_type": content_type,
                "case_id": case_id,
            },
            institution_id=institution_id,
            evidence_id=ev_id,
            object_version=1,
        )

        # 5. Deterministic anchorRequestId + REAL signed service manifest
        anchor_request_id = compute_anchor_request_id(
            institution_id=institution_id,
            case_id=case_id,
            evidence_id=ev_id,
            sha256_hash=stored.sha256,
        )

        key_id = self.key_provider.get_current_key_id(institution_id)
        envelope = self.evidence_store.get_signed_manifest(
            institution_id=institution_id,
            case_id=case_id,
            evidence_id=ev_id,
            sha256_hash=stored.sha256,
            anchor_request_id=anchor_request_id,
            participant_id=identity.participant_id,
            object_version=stored.object_version,
            size=stored.size,
            key_id=key_id,
            signer=self.signer,
        )
        # Digest over the canonical SIGNED envelope — the Ed25519 signature
        # is part of the digested document (spec §6).
        manifest_digest = envelope_digest(envelope)
        manifest_hash = "0x" + manifest_digest

        try:
            # 6. Database atomic persistence — ONE transaction.
            # The object metadata (incl. wrapped DEK material) comes from the
            # published version's metadata record.
            obj_meta = self.evidence_store.get_object_meta(
                institution_id=institution_id,
                evidence_id=ev_id,
                object_version=stored.object_version,
            )
            evidence_obj = evidence_repository.save_evidence_object(
                session=session,
                institution_id=institution_id,
                case_id=case_id,
                evidence_id=ev_id,
                file_name=file_name,
                content_type=content_type,
                file_size=stored.size,
                sha256_hash=stored.sha256,
                storage_path=stored.storage_path,
                object_version=stored.object_version,
                storage_format=obj_meta.get("storage_format"),
                encryption_key_id=obj_meta.get("encryption_key_id"),
                wrapped_dek=(
                    json.dumps(obj_meta["wrapped_dek"], sort_keys=True)
                    if obj_meta.get("wrapped_dek") is not None
                    else None
                ),
                nonce=obj_meta.get("nonce"),
                auth_tag=obj_meta.get("auth_tag"),
                # Signed envelope stored BEFORE the outbox event exists.
                manifest_envelope_json=json.dumps(envelope, sort_keys=True),
                manifest_digest=manifest_digest,
            )

            anchor = evidence_repository.create_anchor(
                session=session,
                institution_id=institution_id,
                case_id=case_id,
                evidence_id=ev_id,
                anchor_request_id=anchor_request_id,
                chain_id=chain_id,
                contract_address=contract_address,
                status="PENDING_ANCHOR",
            )

            # Append Case Event
            case_repository.add_case_event(
                session=session,
                institution_id=institution_id,
                case_id=case_id,
                event_type="EVIDENCE_SUBMITTED",
                actor_sub=actor_sub,
                payload_json=json.dumps({
                    "evidence_id": ev_id,
                    "file_name": file_name,
                    "sha256": stored.sha256,
                    "anchor_request_id": anchor_request_id,
                    "manifest_digest": manifest_digest,
                    "manifest_key_id": key_id,
                }),
            )

            # Transactional Outbox Item — created only AFTER the signed
            # envelope row has been flushed (evidence_repository flushed).
            outbox_payload = {
                "institution_id": institution_id,
                "case_id": case_id,
                "evidence_id": ev_id,
                "anchor_request_id": anchor_request_id,
                "chain_id": chain_id,
                "contract_address": contract_address,
                "file_sha256": "0x" + stored.sha256,
                "manifest_hash": manifest_hash,
                "service_manifest": envelope,
            }
            outbox_repository.enqueue_event(
                session=session,
                institution_id=institution_id,
                event_type="ANCHOR_EVIDENCE",
                payload=outbox_payload,
            )

            result_payload = {
                "evidence_id": ev_id,
                "case_id": case_id,
                "object_version": stored.object_version,
                "sha256_hash": stored.sha256,
                "file_size": stored.size,
                "anchor_request_id": anchor_request_id,
                "status": "PENDING_ANCHOR",
                "manifest": envelope,
                "manifest_hash": manifest_hash,
                "manifest_digest": manifest_digest,
                "storage_format": stored.storage_format,
            }

            # Save Idempotency Record if key provided
            if idempotency_key:
                from datetime import timedelta
                ik = IdempotencyKey(
                    id=f"ik_{uuid.uuid4().hex[:16]}",
                    institution_id=institution_id,
                    key=idempotency_key,
                    request_hash=request_fingerprint,
                    response_json=json.dumps(result_payload),
                    status_code=201,
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                )
                session.add(ik)

            session.flush()
            return result_payload
        except Exception:
            # One transaction: everything written above rolls back together.
            # Only unpublished staging is deleted (the store already removed
            # its own staging on its own failures). The disk object published
            # before the DB write stays as an ORPHAN — collecting orphans is
            # later-retention work; we never delete published evidence here.
            session.rollback()
            raise
