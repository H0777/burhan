"""
Institutional Case Lifecycle and Four-Eyes Governance Service (T16)
Specification §7 (R01, R08, R09, R15)
Implements table-driven case state machine, Four-Eyes principle, Separation of Duties (SoD),
optimistic locking, and append-only audit event logging.
"""

import uuid
import json
import hashlib
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.models import Case, CaseEvent, IdempotencyKey, EvidenceObject
from app.schemas.identity import Identity, RoleEnum
from app.schemas.cases import (
    CaseResponse,
    CaseEventResponse,
    CaseDetailResponse,
    CaseListResponse,
)
from app.repositories import case_repository


class CaseServiceError(Exception):
    pass


class VersionConflictError(CaseServiceError):
    pass


class InvalidTransitionError(CaseServiceError):
    pass


class UnauthorizedRoleError(CaseServiceError):
    pass


class SelfApprovalProhibitedError(CaseServiceError):
    pass


class CaseNotFoundError(CaseServiceError):
    pass


class CaseService:
    @staticmethod
    def _get_role_str(role: Any) -> str:
        return role.value if hasattr(role, "value") else str(role)

    def create_case(
        self,
        session: Session,
        identity: Identity,
        case_number: str,
        title: str,
        description: str = "",
        severity: str = "MEDIUM",
        assigned_to_sub: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> CaseResponse:
        role_str = self._get_role_str(identity.role)
        if role_str == "REGULATOR":
            raise UnauthorizedRoleError("REGULATOR role has read-only audit access and cannot create cases")

        institution_id = identity.institution_id

        # Check idempotency
        req_hash = hashlib.sha256(f"{institution_id}:{case_number}:{title}".encode("utf-8")).hexdigest()
        if idempotency_key:
            ik = session.execute(
                select(IdempotencyKey).where(
                    IdempotencyKey.institution_id == institution_id,
                    IdempotencyKey.key == idempotency_key,
                )
            ).scalars().first()
            if ik:
                if ik.request_hash != req_hash:
                    raise CaseServiceError(f"Idempotency key '{idempotency_key}' conflict with different payload")
                if ik.response_json:
                    return CaseResponse.model_validate_json(ik.response_json)

        case = case_repository.create_case(
            session=session,
            institution_id=institution_id,
            case_number=case_number,
            title=title,
            description=description,
            severity=severity,
            assigned_to_sub=assigned_to_sub or identity.sub,
        )

        resp = CaseResponse(
            id=case.id,
            case_number=case.case_number,
            institution_id=case.institution_id,
            title=case.title,
            description=case.description or "",
            severity=case.severity,
            status=case.status,
            assigned_to_sub=case.assigned_to_sub,
            version=case.version,
            created_at=case.created_at,
            updated_at=case.updated_at,
        )

        if idempotency_key:
            ik = IdempotencyKey(
                id=f"ik_{uuid.uuid4().hex[:16]}",
                institution_id=institution_id,
                key=idempotency_key,
                request_hash=req_hash,
                response_json=resp.model_dump_json(),
                status_code=201,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            session.add(ik)

        session.flush()
        return resp

    def get_case(self, session: Session, identity: Identity, case_id: str) -> CaseDetailResponse:
        institution_id = identity.institution_id
        case = case_repository.get_case(session, institution_id, case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' not found for institution '{institution_id}'")

        events = case_repository.get_case_events(session, institution_id, case_id)

        evidence_count = session.execute(
            select(EvidenceObject).where(
                EvidenceObject.institution_id == institution_id,
                EvidenceObject.case_id == case_id,
            )
        ).scalars().all()

        return CaseDetailResponse(
            case=CaseResponse(
                id=case.id,
                case_number=case.case_number,
                institution_id=case.institution_id,
                title=case.title,
                description=case.description or "",
                severity=case.severity,
                status=case.status,
                assigned_to_sub=case.assigned_to_sub,
                version=case.version,
                created_at=case.created_at,
                updated_at=case.updated_at,
            ),
            events=[
                CaseEventResponse(
                    id=e.id,
                    case_id=e.case_id,
                    institution_id=e.institution_id,
                    event_type=e.event_type,
                    actor_sub=e.actor_sub,
                    payload=json.loads(e.payload_json) if e.payload_json else {},
                    created_at=e.created_at,
                )
                for e in events
            ],
            evidence_count=len(evidence_count),
        )

    def list_cases(
        self,
        session: Session,
        identity: Identity,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> CaseListResponse:
        institution_id = identity.institution_id
        cases = case_repository.list_cases(session, institution_id, limit=limit, cursor=cursor)

        items = [
            CaseResponse(
                id=c.id,
                case_number=c.case_number,
                institution_id=c.institution_id,
                title=c.title,
                description=c.description or "",
                severity=c.severity,
                status=c.status,
                assigned_to_sub=c.assigned_to_sub,
                version=c.version,
                created_at=c.created_at,
                updated_at=c.updated_at,
            )
            for c in cases
        ]
        return CaseListResponse(items=items, next_cursor=None, total=len(items))

    def transition_case(
        self,
        session: Session,
        identity: Identity,
        case_id: str,
        action: str,
        expected_version: int,
        reason: Optional[str] = "",
        new_assignee_sub: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> CaseResponse:
        role_str = self._get_role_str(identity.role)
        actor_sub = identity.sub
        institution_id = identity.institution_id

        if role_str == "REGULATOR":
            raise UnauthorizedRoleError("REGULATOR role has read-only audit access and cannot transition cases")

        # Idempotency check
        req_hash = hashlib.sha256(
            f"{institution_id}:{case_id}:{action}:{expected_version}:{reason}".encode("utf-8")
        ).hexdigest()
        if idempotency_key:
            ik = session.execute(
                select(IdempotencyKey).where(
                    IdempotencyKey.institution_id == institution_id,
                    IdempotencyKey.key == idempotency_key,
                )
            ).scalars().first()
            if ik:
                if ik.request_hash != req_hash:
                    raise CaseServiceError(f"Idempotency key '{idempotency_key}' conflict with different payload")
                if ik.response_json:
                    return CaseResponse.model_validate_json(ik.response_json)

        case = case_repository.get_case(session, institution_id, case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' not found for institution '{institution_id}'")

        # Optimistic locking check
        if case.version != expected_version:
            raise VersionConflictError(
                f"Version conflict on case '{case_id}': expected {expected_version}, current is {case.version}"
            )

        current_status = case.status
        new_status = current_status
        is_admin = role_str == "SUPER_ADMIN"
        is_auditor = role_str in ("AUDITOR", "SUPER_ADMIN")
        is_operator = role_str in ("OPERATOR", "SUPER_ADMIN")

        # -------------------------------------------------------------
        # STATE MACHINE TRANSITIONS (Spec §7 Table)
        # -------------------------------------------------------------
        if action == "assign":
            if not is_auditor and not is_operator:
                raise UnauthorizedRoleError("Not authorized to assign case")
            if not new_assignee_sub:
                raise ValueError("new_assignee_sub is required for assign action")
            case.assigned_to_sub = new_assignee_sub

        elif action == "start_review":
            if current_status != "OPEN":
                raise InvalidTransitionError(f"Cannot start_review from status '{current_status}' (must be OPEN)")
            if not is_auditor and not is_operator:
                raise UnauthorizedRoleError("Only assigned reviewer or auditor can start review")
            new_status = "IN_REVIEW"

        elif action == "request_approval":
            if current_status != "IN_REVIEW":
                raise InvalidTransitionError(f"Cannot request_approval from status '{current_status}' (must be IN_REVIEW)")
            if not is_auditor and not is_operator:
                raise UnauthorizedRoleError("Only assigned reviewer or auditor can request approval")
            new_status = "AWAITING_APPROVAL"

        elif action == "approve_resolution":
            if current_status != "AWAITING_APPROVAL":
                raise InvalidTransitionError(f"Cannot approve_resolution from status '{current_status}' (must be AWAITING_APPROVAL)")
            if not is_auditor:
                raise UnauthorizedRoleError("Only an AUDITOR or SUPER_ADMIN can approve a case resolution")

            # FOUR-EYES PRINCIPLE: Check who requested approval in past case_events
            last_request_event = session.execute(
                select(CaseEvent)
                .where(
                    CaseEvent.institution_id == institution_id,
                    CaseEvent.case_id == case_id,
                    CaseEvent.event_type == "request_approval",
                )
                .order_by(desc(CaseEvent.created_at))
            ).scalars().first()

            if last_request_event and last_request_event.actor_sub == actor_sub:
                raise SelfApprovalProhibitedError(
                    "Four-Eyes Principle violation: Resolution cannot be self-approved by the same user who submitted it for approval"
                )
            new_status = "RESOLVED"

        elif action == "reject_resolution":
            if current_status != "AWAITING_APPROVAL":
                raise InvalidTransitionError(f"Cannot reject_resolution from status '{current_status}' (must be AWAITING_APPROVAL)")
            if not is_auditor:
                raise UnauthorizedRoleError("Only an AUDITOR or SUPER_ADMIN can reject a resolution")
            if not reason:
                raise ValueError("Justification reason is required when rejecting resolution")
            new_status = "IN_REVIEW"

        elif action == "escalate":
            if current_status not in ("IN_REVIEW", "AWAITING_APPROVAL"):
                raise InvalidTransitionError(f"Cannot escalate from status '{current_status}'")
            if not is_auditor and not is_operator:
                raise UnauthorizedRoleError("Not authorized to escalate case")
            new_status = "ESCALATED"

        elif action == "return_to_review":
            if current_status != "ESCALATED":
                raise InvalidTransitionError(f"Cannot return_to_review from status '{current_status}' (must be ESCALATED)")
            if not is_admin:
                raise UnauthorizedRoleError("Only SUPER_ADMIN can return an escalated case to review")
            if not reason:
                raise ValueError("Reason is required when returning an escalated case to review")
            if new_assignee_sub:
                case.assigned_to_sub = new_assignee_sub
            new_status = "IN_REVIEW"

        elif action == "close":
            if current_status != "RESOLVED":
                raise InvalidTransitionError(f"Cannot close case from status '{current_status}' (must be RESOLVED)")
            if not is_auditor:
                raise UnauthorizedRoleError("Only reviewing AUDITOR or SUPER_ADMIN can close a resolved case")
            new_status = "CLOSED"

        elif action == "reopen":
            if current_status != "CLOSED":
                raise InvalidTransitionError(f"Cannot reopen case from status '{current_status}' (must be CLOSED)")
            if not is_admin:
                raise UnauthorizedRoleError("Only SUPER_ADMIN can reopen a closed case")
            if not reason:
                raise ValueError("Reason is required when reopening a closed case")
            if new_assignee_sub:
                case.assigned_to_sub = new_assignee_sub
            new_status = "IN_REVIEW"

        else:
            raise InvalidTransitionError(f"Unknown case action '{action}'")

        # Update case
        old_status = case.status
        case.status = new_status
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        # Record append-only event
        event = CaseEvent(
            id=f"ce_{uuid.uuid4().hex[:16]}",
            case_id=case.id,
            institution_id=institution_id,
            event_type=action,
            actor_sub=actor_sub,
            payload_json=json.dumps({
                "from_status": old_status,
                "to_status": new_status,
                "action": action,
                "reason": reason or "",
                "assignee": case.assigned_to_sub,
                "version": case.version,
            }),
        )
        session.add(event)

        resp = CaseResponse(
            id=case.id,
            case_number=case.case_number,
            institution_id=case.institution_id,
            title=case.title,
            description=case.description or "",
            severity=case.severity,
            status=case.status,
            assigned_to_sub=case.assigned_to_sub,
            version=case.version,
            created_at=case.created_at,
            updated_at=case.updated_at,
        )

        if idempotency_key:
            ik = IdempotencyKey(
                id=f"ik_{uuid.uuid4().hex[:16]}",
                institution_id=institution_id,
                key=idempotency_key,
                request_hash=req_hash,
                response_json=resp.model_dump_json(),
                status_code=200,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
            session.add(ik)

        session.flush()
        return resp
