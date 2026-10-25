"""
Institutional Case Lifecycle and Four-Eyes Governance Service (T16, R12)
Specification §7, §8 (R01, R08, R09, R15)
Implements table-driven case state machine, Four-Eyes principle, Separation of Duties (SoD),
optimistic locking via SQL compare-and-swap, append-only audit event logging, semantic
idempotency (scoped key + full-body digest, TTL 24h) and keyset cursor pagination.

R12 concurrency contract: the state transition winner is decided ONLY by the atomic
UPDATE ... WHERE institution_id/case_id/version[ AND status] in the repository — there
is deliberately NO Python-side version check here. The case row, its CaseEvent and the
idempotency reservation are written in ONE transaction (the caller's tenant_transaction),
so a failure rolls back all three together.

R12 idempotency contract: the idempotency key scope is
institution + sub + HTTP method + path + key (the (institution_id, key) unique
constraint reserves it atomically), and the stored request_hash is a canonical-JSON
digest over ALL semantic body fields — a changed description/severity/new_assignee_sub
under the same key raises IdempotencyConflictError (HTTP 409) instead of replaying a
stale success. Entries live for 24h; expired entries are never replayed.
"""

import base64
import uuid
import json
import hashlib
from typing import Optional, Dict, Any, Tuple
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

IDEMPOTENCY_TTL = timedelta(hours=24)


class CaseServiceError(Exception):
    """Base: mapped to HTTP 400 by the routes unless a subclass matches first."""
    pass


class IdempotencyConflictError(CaseServiceError):
    """Same idempotency key reused with a DIFFERENT semantic payload (or racing a
    concurrent request under the same key): HTTP 409, never a stale success."""
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


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_digest(payload: Any) -> str:
    """Digest over ALL semantic fields of a request body (canonical JSON)."""
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _as_aware(dt: datetime) -> datetime:
    """SQLite (dev/test) returns naive datetimes from DateTime(timezone=True)
    columns; every stored value is written as UTC. Normalize before comparing."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _idempotency_scope_key(institution_id: str, sub: str, scope: Tuple[str, str], raw_key: str) -> str:
    """
    The stored `key` for an idempotency reservation: a digest of
    institution + sub + method + path + client key. Combined with the
    (institution_id, key) unique constraint this reserves the key exactly per
    the spec scope: institution+sub+method+path+key.
    """
    method, path = scope
    material = "\x1f".join([institution_id, sub, method or "", path or "", raw_key])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Cursor codec: opaque, bound to institution + filter set + keyset position
# ---------------------------------------------------------------------------


def _encode_case_list_cursor(institution_id: str, filters: Dict[str, Optional[str]], last_key: Tuple[datetime, str]) -> str:
    payload = {
        "i": institution_id,
        "f": {k: v for k, v in (filters or {}).items() if v},
        "c": [last_key[0].isoformat(), last_key[1]],
    }
    raw = _canonical_json(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_case_list_cursor(cursor: str, institution_id: str, filters: Dict[str, Optional[str]]) -> Tuple[datetime, str]:
    """Decode and BIND the cursor: a cursor minted for another institution or for a
    different filter set is rejected (400) — it must never widen a query."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
        cursor_inst = payload["i"]
        cursor_filters = {k: v for k, v in (payload.get("f") or {}).items() if v}
        ts_iso, last_id = payload["c"]
        last_ts = datetime.fromisoformat(ts_iso)
        if not isinstance(last_id, str) or not last_id:
            raise ValueError("cursor id must be a non-empty string")
    except CaseServiceError:
        raise
    except Exception as exc:
        raise CaseServiceError("Invalid pagination cursor") from exc

    if cursor_inst != institution_id:
        raise CaseServiceError("Pagination cursor belongs to a different institution")
    incoming_filters = {k: v for k, v in (filters or {}).items() if v}
    if cursor_filters != incoming_filters:
        raise CaseServiceError("Pagination cursor does not match the requested filters")
    return (last_ts, last_id)


class CaseService:
    @staticmethod
    def _get_role_str(role: Any) -> str:
        return role.value if hasattr(role, "value") else str(role)

    @staticmethod
    def _scope(request_scope: Optional[Tuple[str, str]]) -> Tuple[str, str]:
        if not request_scope:
            return ("", "")
        return (str(request_scope[0] or ""), str(request_scope[1] or ""))

    # -- idempotency helpers ------------------------------------------------

    def _replay_idempotent(
        self,
        session: Session,
        institution_id: str,
        scope_key: str,
        digest: str,
        raw_key: str,
    ) -> Optional[CaseResponse]:
        """Return the stored response for an unexpired key with the SAME semantic
        digest. Changed digest -> IdempotencyConflictError (409). Expired entries are
        removed so the request re-executes (TTL = 24h)."""
        now = datetime.now(timezone.utc)
        ik = session.execute(
            select(IdempotencyKey).where(
                IdempotencyKey.institution_id == institution_id,
                IdempotencyKey.key == scope_key,
            )
        ).scalars().first()
        if ik is None:
            return None
        if ik.expires_at is not None and _as_aware(ik.expires_at) <= now:
            session.delete(ik)
            session.flush()
            return None
        if (ik.request_hash or "") != digest:
            raise IdempotencyConflictError(
                f"Idempotency key '{raw_key}' was already used with a different payload"
            )
        if ik.response_json:
            return CaseResponse.model_validate_json(ik.response_json)
        # A reservation without a stored response cannot exist across committed
        # transactions (outcome and reservation share one transaction); treat as
        # expired and re-execute.
        session.delete(ik)
        session.flush()
        return None

    def _reserve_idempotent(
        self,
        session: Session,
        institution_id: str,
        scope_key: str,
        digest: str,
        response: CaseResponse,
        status_code: int,
        raw_key: str,
    ) -> None:
        """Insert the idempotency reservation together with the outcome. The
        (institution_id, key) unique constraint is the arbiter: a concurrent request
        under the same scope key loses the race here and gets a 409."""
        ik = IdempotencyKey(
            id=f"ik_{uuid.uuid4().hex[:16]}",
            institution_id=institution_id,
            key=scope_key,
            request_hash=digest,
            response_json=response.model_dump_json(),
            status_code=status_code,
            expires_at=datetime.now(timezone.utc) + IDEMPOTENCY_TTL,
        )
        session.add(ik)
        try:
            session.flush()
        except Exception as exc:
            from sqlalchemy.exc import IntegrityError

            if isinstance(exc, IntegrityError):
                raise IdempotencyConflictError(
                    f"Idempotency key '{raw_key}' is being processed concurrently"
                ) from exc
            raise

    # -- commands ------------------------------------------------------------

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
        request_scope: Optional[Tuple[str, str]] = None,
    ) -> CaseResponse:
        role_str = self._get_role_str(identity.role)
        if role_str == "REGULATOR":
            raise UnauthorizedRoleError("REGULATOR role has read-only audit access and cannot create cases")

        institution_id = identity.institution_id

        if idempotency_key:
            scope_key = _idempotency_scope_key(
                institution_id, identity.sub, self._scope(request_scope), idempotency_key
            )
            # Digest over ALL semantic body fields — description and severity included.
            digest = _canonical_digest(
                {
                    "case_number": case_number,
                    "title": title,
                    "description": description or "",
                    "severity": severity,
                    "assigned_to_sub": assigned_to_sub,
                }
            )
            replayed = self._replay_idempotent(session, institution_id, scope_key, digest, idempotency_key)
            if replayed is not None:
                return replayed
        else:
            digest = None
            scope_key = None

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
            self._reserve_idempotent(session, institution_id, scope_key, digest, resp, 201, idempotency_key)

        session.flush()
        return resp

    # -- queries ---------------------------------------------------------------

    def get_case(self, session: Session, identity: Identity, case_id: str) -> CaseDetailResponse:
        institution_id = identity.institution_id
        case = case_repository.get_case(session, institution_id, case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' not found for institution '{institution_id}'")

        events = case_repository.get_case_events(session, institution_id, case_id)

        evidence_rows = session.execute(
            select(EvidenceObject.id).where(
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
            evidence_count=len(evidence_rows),
        )

    def list_cases(
        self,
        session: Session,
        identity: Identity,
        limit: int = 50,
        cursor: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> CaseListResponse:
        """Keyset pagination on (created_at DESC, id DESC). The cursor is bound to
        this institution and to the active filter set; next_cursor is produced ONLY
        when a further row exists (limit+1 was fetched)."""
        institution_id = identity.institution_id
        filters: Dict[str, Optional[str]] = {"status": status, "severity": severity}
        cursor_key = (
            _decode_case_list_cursor(cursor, institution_id, filters) if cursor else None
        )

        rows, has_more = case_repository.list_cases(
            session,
            institution_id,
            limit=limit,
            cursor=cursor_key,
            status=status,
            severity=severity,
        )

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
            for c in rows
        ]
        next_cursor = None
        if has_more and items:
            last = rows[-1]
            next_cursor = _encode_case_list_cursor(
                institution_id, filters, (last.created_at, last.id)
            )
        return CaseListResponse(items=items, next_cursor=next_cursor, total=len(items))

    # -- state machine ----------------------------------------------------------

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
        request_scope: Optional[Tuple[str, str]] = None,
    ) -> CaseResponse:
        role_str = self._get_role_str(identity.role)
        actor_sub = identity.sub
        institution_id = identity.institution_id

        if role_str == "REGULATOR":
            raise UnauthorizedRoleError("REGULATOR role has read-only audit access and cannot transition cases")

        if idempotency_key:
            scope_key = _idempotency_scope_key(
                institution_id, identity.sub, self._scope(request_scope), idempotency_key
            )
            # Digest over ALL semantic fields of the transition — the path-scoped
            # case id, action, expected_version, reason AND new_assignee_sub.
            digest = _canonical_digest(
                {
                    "case_id": case_id,
                    "action": action,
                    "expected_version": expected_version,
                    "reason": reason or "",
                    "new_assignee_sub": new_assignee_sub,
                }
            )
            replayed = self._replay_idempotent(session, institution_id, scope_key, digest, idempotency_key)
            if replayed is not None:
                return replayed
        else:
            digest = None
            scope_key = None

        case = case_repository.get_case(session, institution_id, case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' not found for institution '{institution_id}'")

        current_status = case.status
        new_status = current_status
        is_admin = role_str == "SUPER_ADMIN"
        is_auditor = role_str in ("AUDITOR", "SUPER_ADMIN")
        is_operator = role_str in ("OPERATOR", "SUPER_ADMIN")
        cas_updates: Dict[str, Any] = {}

        # -------------------------------------------------------------
        # STATE MACHINE TRANSITIONS (Spec §7 Table)
        # -------------------------------------------------------------
        if action == "assign":
            if not is_auditor and not is_operator:
                raise UnauthorizedRoleError("Not authorized to assign case")
            if not new_assignee_sub:
                raise ValueError("new_assignee_sub is required for assign action")
            cas_updates["assigned_to_sub"] = new_assignee_sub

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
                cas_updates["assigned_to_sub"] = new_assignee_sub
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
                cas_updates["assigned_to_sub"] = new_assignee_sub
            new_status = "IN_REVIEW"

        else:
            raise InvalidTransitionError(f"Unknown case action '{action}'")

        # -------------------------------------------------------------
        # SQL COMPARE-AND-SWAP (R12): the ONLY concurrency gate. The UPDATE,
        # the append-only event and the idempotency reservation below share
        # the caller's single transaction.
        # -------------------------------------------------------------
        try:
            case = case_repository.update_case_status(
                session,
                institution_id,
                case_id,
                expected_version,
                new_status,
                cas_updates or None,
                expected_status=current_status,
                actor_sub=actor_sub,
                reason=reason or "",
                action_type=action,
                event_payload={
                    "assignee": cas_updates.get("assigned_to_sub", case.assigned_to_sub),
                },
            )
        except case_repository.CaseVersionConflict as exc:
            raise VersionConflictError(str(exc)) from exc
        except case_repository.CaseNotFoundError as exc:
            raise CaseNotFoundError(str(exc)) from exc

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
            self._reserve_idempotent(session, institution_id, scope_key, digest, resp, 200, idempotency_key)

        session.flush()
        return resp
