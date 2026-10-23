"""
Evidence Broker Service (T14)
Specification §4, §5, §7 (R01, R04, R08, R09, R14)
Validates assignment and role, stores into WORM evidence store,
issues canonical service manifest, and atomically writes EvidenceObject,
EvidenceAnchor (PENDING_ANCHOR), and Outbox item within a tenant transaction.
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


def compute_anchor_request_id(institution_id: str, case_id: str, evidence_id: str, sha256_hash: str) -> str:
    """
    Computes a deterministic bytes32 hex string (0x...) for on-chain deduplication.
    """
    data = f"{institution_id}:{case_id}:{evidence_id}:{sha256_hash}".encode("utf-8")
    return "0x" + hashlib.sha256(data).hexdigest()


class EvidenceBroker:
    def __init__(self, evidence_store: EvidenceStore):
        self.evidence_store = evidence_store

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

        # 4. Stream into WORM evidence store
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

        # 5. Build deterministic anchorRequestId and service manifest
        anchor_request_id = compute_anchor_request_id(
            institution_id=institution_id,
            case_id=case_id,
            evidence_id=ev_id,
            sha256_hash=stored.sha256,
        )

        manifest = {
            "schema_version": 2,
            "service_cert": "IRQA-AML-AUDIT-CHAIN-V2",
            "institution_id": institution_id,
            "case_id": case_id,
            "case_number": case.case_number,
            "evidence_id": ev_id,
            "object_version": stored.object_version,
            "file_name": file_name,
            "content_type": content_type,
            "file_size": stored.size,
            "sha256_hash": stored.sha256,
            "anchor_request_id": anchor_request_id,
            "submitted_by_sub": actor_sub,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
        }
        manifest_hash = "0x" + hashlib.sha256(json.dumps(manifest, sort_keys=True).encode("utf-8")).hexdigest()

        # 6. Database atomic persistence
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
            }),
        )

        # Transactional Outbox Item
        outbox_payload = {
            "institution_id": institution_id,
            "case_id": case_id,
            "evidence_id": ev_id,
            "anchor_request_id": anchor_request_id,
            "chain_id": chain_id,
            "contract_address": contract_address,
            "file_sha256": "0x" + stored.sha256,
            "manifest_hash": manifest_hash,
            "service_manifest": manifest,
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
            "manifest": manifest,
            "manifest_hash": manifest_hash,
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
