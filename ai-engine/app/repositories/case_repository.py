"""
Multi-Tenant Case Repository (T14, T16)
Specification §7, R01, R08, R09, R15
Strictly scoped by institution_id on every operation.
"""

import uuid
import json
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.models import Case, CaseEvent


class VersionConflictError(Exception):
    """Raised when expected_version does not match current case version."""
    pass


class CaseNotFoundError(Exception):
    """Raised when case is not found within institution scope."""
    pass


def create_case(
    session: Session,
    institution_id: str,
    case_number: str,
    title: str,
    description: str = "",
    severity: str = "MEDIUM",
    assigned_to_sub: Optional[str] = None,
    case_id: Optional[str] = None,
) -> Case:
    cid = case_id or f"case_{uuid.uuid4().hex[:16]}"
    case = Case(
        id=cid,
        case_number=case_number,
        institution_id=institution_id,
        title=title,
        description=description,
        severity=severity,
        status="OPEN",
        assigned_to_sub=assigned_to_sub,
        version=1,
    )
    session.add(case)
    session.flush()

    # Append initial creation event
    event = CaseEvent(
        id=f"ce_{uuid.uuid4().hex[:16]}",
        case_id=case.id,
        institution_id=institution_id,
        event_type="CASE_CREATED",
        actor_sub=assigned_to_sub or "system",
        payload_json=json.dumps({"title": title, "severity": severity}),
    )
    session.add(event)
    session.flush()
    return case


def get_case(session: Session, institution_id: str, case_id: str) -> Optional[Case]:
    stmt = select(Case).where(
        Case.institution_id == institution_id,
        Case.id == case_id,
    )
    return session.execute(stmt).scalars().first()


def list_cases(
    session: Session,
    institution_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> List[Case]:
    limit = min(max(1, limit), 100)
    stmt = (
        select(Case)
        .where(Case.institution_id == institution_id)
        .order_by(desc(Case.created_at), desc(Case.id))
        .limit(limit)
    )
    return list(session.execute(stmt).scalars().all())


def update_case_status(
    session: Session,
    institution_id: str,
    case_id: str,
    expected_version: int,
    new_status: str,
    actor_sub: str,
    reason: str = "",
    action_type: str = "STATUS_TRANSITION",
) -> Case:
    case = get_case(session, institution_id, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found for institution {institution_id}")

    if case.version != expected_version:
        raise VersionConflictError(
            f"Version conflict on case {case_id}: expected {expected_version}, current {case.version}"
        )

    old_status = case.status
    case.status = new_status
    case.version += 1
    case.updated_at = datetime.now(timezone.utc)
    session.flush()

    # Append immutable event
    event = CaseEvent(
        id=f"ce_{uuid.uuid4().hex[:16]}",
        case_id=case.id,
        institution_id=institution_id,
        event_type=action_type,
        actor_sub=actor_sub,
        payload_json=json.dumps({
            "from_status": old_status,
            "to_status": new_status,
            "reason": reason,
            "version": case.version,
        }),
    )
    session.add(event)
    session.flush()
    return case


def add_case_event(
    session: Session,
    institution_id: str,
    case_id: str,
    event_type: str,
    actor_sub: str,
    payload_json: str = "{}",
) -> CaseEvent:
    case = get_case(session, institution_id, case_id)
    if not case:
        raise CaseNotFoundError(f"Case {case_id} not found for institution {institution_id}")

    event = CaseEvent(
        id=f"ce_{uuid.uuid4().hex[:16]}",
        case_id=case_id,
        institution_id=institution_id,
        event_type=event_type,
        actor_sub=actor_sub,
        payload_json=payload_json,
    )
    session.add(event)
    session.flush()
    return event


def get_case_events(session: Session, institution_id: str, case_id: str) -> List[CaseEvent]:
    stmt = (
        select(CaseEvent)
        .where(
            CaseEvent.institution_id == institution_id,
            CaseEvent.case_id == case_id,
        )
        .order_by(CaseEvent.created_at.asc())
    )
    return list(session.execute(stmt).scalars().all())
