"""
Multi-Tenant Case Repository (T14, T16, R12)
Specification §7, §8, R01, R08, R09, R15
Strictly scoped by institution_id on every operation.

R12: the state transition is a real SQL compare-and-swap —
UPDATE cases SET ... WHERE institution_id = :inst AND id = :case AND version = :expected
[AND status = :expected_status] — with RETURNING. A zero rowcount means a concurrent
writer changed the case first: the caller gets CaseVersionConflict (mapped to 409).
There is deliberately NO read-then-check version validation here: only the atomic
UPDATE decides the winner. The transition outcome (case row) and its append-only
CaseEvent are written in the SAME transaction as the idempotency reservation.
"""

import uuid
import json
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.models import Case, CaseEvent


class VersionConflictError(Exception):
    """Base: raised when the expected case state does not match the stored state."""
    pass


class CaseVersionConflict(VersionConflictError):
    """Raised when the SQL compare-and-swap updates zero rows: a concurrent writer
    changed the case (version and/or status) before this transaction could."""
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
    cursor: Optional[Tuple[datetime, str]] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
) -> Tuple[List[Case], bool]:
    """
    Keyset pagination on the stable (created_at DESC, id DESC) order.

    Fetches limit+1 rows: the caller serves `limit` items and knows a further page
    exists exactly when limit+1 was found (next_cursor is therefore never returned
    while the result set is exhausted). `cursor` is the decoded (created_at, id)
    keyset bound to this institution and filter set; the SQL row-value comparison
    is strictly "after the last served row" so pages never overlap or skip.
    """
    limit = min(max(1, limit), 100)
    from sqlalchemy import tuple_

    conditions = [Case.institution_id == institution_id]
    if status:
        conditions.append(Case.status == status)
    if severity:
        conditions.append(Case.severity == severity)
    if cursor is not None:
        cursor_ts, cursor_id = cursor
        conditions.append(tuple_(Case.created_at, Case.id) < tuple_(cursor_ts, cursor_id))
    stmt = (
        select(Case)
        .where(*conditions)
        .order_by(Case.created_at.desc(), Case.id.desc())
        .limit(limit + 1)
    )
    rows = list(session.execute(stmt).scalars().all())
    has_more = len(rows) > limit
    return rows[:limit], has_more


def update_case_status(
    session: Session,
    institution_id: str,
    case_id: str,
    expected_version: int,
    new_status: str,
    updates: Optional[Dict[str, Any]] = None,
    *,
    expected_status: Optional[str] = None,
    actor_sub: str = "system",
    reason: str = "",
    action_type: str = "STATUS_TRANSITION",
    event_payload: Optional[Dict[str, Any]] = None,
) -> Case:
    """
    SQL compare-and-swap state transition (R12, spec §8):

        UPDATE cases SET status=:new, version=version+1, ...
        WHERE institution_id=:inst AND id=:case AND version=:expected
          [AND status=:expected_status]

    One UPDATE decides the winner atomically — no Python-side read/compare. Zero
    rowcount raises CaseVersionConflict (HTTP 409 upstream). The append-only
    CaseEvent is inserted in the SAME transaction as the row update, so a failure
    anywhere rolls back state, event and idempotency together.

    `expected_status` closes the state-machine TOCTOU: if the status read earlier in
    this transaction changed under us, the UPDATE matches zero rows and conflicts.
    `updates` carries additional column writes (e.g. assigned_to_sub for assign).
    """
    values: Dict[str, Any] = {
        "status": new_status,
        "version": Case.version + 1,
        "updated_at": datetime.now(timezone.utc),
    }
    # Whitelist: `updates` may only touch non-identity, non-lifecycle columns.
    _CAS_UPDATABLE_COLUMNS = {"assigned_to_sub", "description", "severity", "title"}
    for key, value in (updates or {}).items():
        if key in _CAS_UPDATABLE_COLUMNS and key not in values:
            values[key] = value

    conditions = [
        Case.institution_id == institution_id,
        Case.id == case_id,
        Case.version == expected_version,
    ]
    if expected_status is not None:
        conditions.append(Case.status == expected_status)

    stmt = (
        update(Case)
        .where(*conditions)
        .values(**values)
        .returning(Case.version, Case.status, Case.assigned_to_sub)
        .execution_options(synchronize_session=False)
    )
    row = session.execute(stmt).first()
    if row is None:
        current = get_case(session, institution_id, case_id)
        if current is None:
            raise CaseNotFoundError(f"Case {case_id} not found for institution {institution_id}")
        raise CaseVersionConflict(
            f"Version conflict on case {case_id}: expected version {expected_version}"
            f" (status {expected_status!r}), but the stored case is at version"
            f" {current.version} (status {current.status!r})"
        )

    # The identity map may hold the pre-CAS instance (loaded by the caller's
    # earlier SELECT); expire it so the returned object reflects the UPDATE.
    cached = session.get(Case, case_id)
    if cached is not None:
        session.expire(cached)

    new_version = row.version
    payload: Dict[str, Any] = {
        "from_status": expected_status,
        "to_status": row.status,
        "reason": reason,
        "version": new_version,
    }
    if event_payload:
        payload.update(event_payload)

    event = CaseEvent(
        id=f"ce_{uuid.uuid4().hex[:16]}",
        case_id=case_id,
        institution_id=institution_id,
        event_type=action_type,
        actor_sub=actor_sub,
        payload_json=json.dumps(payload),
    )
    session.add(event)
    session.flush()
    return cached if cached is not None else session.get(Case, case_id)


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
