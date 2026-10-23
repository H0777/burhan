"""
Multi-Tenant Outbox Repository (T14, T15)
Specification §5, §7 (R01, R04, R09)
Provides transactional outbox pattern to guarantee at-least-once reliable delivery.
"""

import uuid
import json
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models import Outbox


def enqueue_event(
    session: Session,
    institution_id: str,
    event_type: str,
    payload: Dict[str, Any],
) -> Outbox:
    entry = Outbox(
        id=f"out_{uuid.uuid4().hex[:16]}",
        institution_id=institution_id,
        event_type=event_type,
        payload_json=json.dumps(payload),
        status="PENDING",
        attempts=0,
    )
    session.add(entry)
    session.flush()
    return entry


def get_pending_events(
    session: Session,
    institution_id: Optional[str] = None,
    limit: int = 50,
) -> List[Outbox]:
    stmt = (
        select(Outbox)
        .where(Outbox.status.in_(["PENDING", "FAILED"]))
        .where(Outbox.attempts < 5)
        .order_by(Outbox.created_at.asc())
        .limit(limit)
    )
    if institution_id:
        stmt = stmt.where(Outbox.institution_id == institution_id)
    return list(session.execute(stmt).scalars().all())


def mark_processing(session: Session, outbox_id: str) -> Optional[Outbox]:
    stmt = select(Outbox).where(Outbox.id == outbox_id)
    entry = session.execute(stmt).scalars().first()
    if entry:
        entry.status = "PROCESSING"
        entry.attempts += 1
        session.flush()
    return entry


def mark_completed(session: Session, outbox_id: str) -> Optional[Outbox]:
    stmt = select(Outbox).where(Outbox.id == outbox_id)
    entry = session.execute(stmt).scalars().first()
    if entry:
        entry.status = "COMPLETED"
        entry.processed_at = datetime.now(timezone.utc)
        session.flush()
    return entry


def mark_failed(session: Session, outbox_id: str, error_message: str) -> Optional[Outbox]:
    stmt = select(Outbox).where(Outbox.id == outbox_id)
    entry = session.execute(stmt).scalars().first()
    if entry:
        entry.status = "FAILED"
        entry.error_message = error_message
        session.flush()
    return entry
