"""
Multi-Tenant Outbox Repository (T14, T15, R08)
Specification §5, §7 (R01, R04, R08, R09)

Transactional outbox with lease-based claiming (spec §7):
  - claim_batch: FOR UPDATE SKIP LOCKED on PostgreSQL, lease = 60s with a
    random owner token; every later transition (renew / submitted /
    complete / fail) is a CONDITIONAL UPDATE on that token, so a worker
    whose lease expired can never mutate an item another worker reclaimed.
  - Retries: max 5 attempts with backoffs 5/30/120/600/1800 seconds. The
    fifth failure moves the item to DEAD with the reason and an explicit
    recorded reschedule timestamp.
  - States: PENDING, PROCESSING, SUBMITTED, COMPLETED, FAILED, DEAD.
    SUBMITTED is NOT final and does NOT consume a retry: slow confirmation
    keeps reconciling. Timing always comes from an injected clock
    (`now`/`clock` parameters), never from real sleeps.
  - An expired-lease reclaim is just another claim: it never broadcasts
    anything by itself — the pipeline must check request_id/tx_hash via the
    persisted chain_submissions row before any re-send (ChainSender).
"""

import uuid
import json
import secrets
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from app.db.models import Outbox

# Spec §7 timing constants (seconds).
LEASE_SECONDS = 60
RENEW_AFTER_SECONDS = 20
MAX_ATTEMPTS = 5
RETRY_BACKOFFS = (5, 30, 120, 600, 1800)

# Claimable delivery states.
CLAIMABLE_DUE_STATES = ("PENDING", "FAILED")
LEASE_HELD_STATES = ("PROCESSING", "SUBMITTED")


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
        .where(Outbox.status.in_(CLAIMABLE_DUE_STATES))
        .where(Outbox.attempts < MAX_ATTEMPTS)
        .order_by(Outbox.created_at.asc())
        .limit(limit)
    )
    if institution_id:
        stmt = stmt.where(Outbox.institution_id == institution_id)
    return list(session.execute(stmt).scalars().all())


def claim_batch(
    session: Session,
    institution_id: str,
    worker_id: str,
    now: datetime,
    limit: int = 20,
) -> List[Outbox]:
    """Atomically claim up to `limit` deliverable outbox rows for one worker.

    PostgreSQL renders `with_for_update(skip_locked=True)` as
    FOR UPDATE SKIP LOCKED, so concurrent workers partition the batch with
    no overlap and no blocking (the R08 tests close this on real
    PostgreSQL; SQLite ignores the locking hint — dev/demo path only).

    Claimable:
      * PENDING / FAILED whose next_attempt_at is due (or NULL);
      * PROCESSING / SUBMITTED rows whose lease expired — a crashed
        worker's item is taken over with a FRESH owner token. The takeover
        itself never re-broadcasts: the pipeline resolves the persisted
        chain_submissions row (request_id/tx_hash) first.

    Each claim is an attempt: attempts += 1 (bounded by MAX_ATTEMPTS on the
    failure path; SUBMITTED transitions never consume retries).
    """
    if not isinstance(now, datetime):
        raise TypeError("claim_batch requires an injected clock datetime")

    now = _aware(now)
    due = (
        (Outbox.next_attempt_at.is_(None))
        | (Outbox.next_attempt_at <= now)
    )
    stmt = (
        select(Outbox)
        .where(Outbox.institution_id == institution_id)
        .where(
            (Outbox.status.in_(CLAIMABLE_DUE_STATES) & due & (Outbox.attempts < MAX_ATTEMPTS))
            | (
                Outbox.status.in_(LEASE_HELD_STATES)
                & (Outbox.lease_expires_at.is_not(None))
                & (Outbox.lease_expires_at <= now)
            )
        )
        .order_by(Outbox.created_at.asc())
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = list(session.execute(stmt).scalars().all())

    for row in rows:
        row.lease_owner = worker_id
        row.lease_token = secrets.token_hex(16)
        row.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
        row.attempts += 1
        # A reclaimed SUBMITTED row keeps its SUBMITTED state (the tx is
        # already on-chain or persisted); the reclaim must reconcile, not
        # re-send. Everything else moves to PROCESSING.
        if row.status not in ("SUBMITTED",):
            row.status = "PROCESSING"
    session.flush()
    return rows


def renew_lease(
    session: Session,
    outbox_id: str,
    lease_token: str,
    now: datetime,
) -> bool:
    """Extend the lease (owner-token conditional). Workers holding an item
    longer than RENEW_AFTER_SECONDS renew every 20s of lease lifetime."""
    result = session.execute(
        update(Outbox)
        .where(Outbox.id == outbox_id)
        .where(Outbox.lease_token == lease_token)
        .where(Outbox.status.in_(LEASE_HELD_STATES))
        .values(lease_expires_at=_aware(now) + timedelta(seconds=LEASE_SECONDS))
    )
    return bool(result.rowcount)


def mark_submitted(
    session: Session,
    outbox_id: str,
    lease_token: str,
    now: datetime,
) -> bool:
    """SUBMITTED is not final and consumes no retry: the transaction is out;
    reconciliation continues until a receipt (or reorg) resolves it."""
    result = session.execute(
        update(Outbox)
        .where(Outbox.id == outbox_id)
        .where(Outbox.lease_token == lease_token)
        .where(Outbox.status.in_(LEASE_HELD_STATES))
        .values(status="SUBMITTED")
    )
    return bool(result.rowcount)


def complete_claimed(
    session: Session,
    outbox_id: str,
    lease_token: str,
    now: datetime,
) -> bool:
    """Owner-token conditional completion — a stale token never mutates."""
    result = session.execute(
        update(Outbox)
        .where(Outbox.id == outbox_id)
        .where(Outbox.lease_token == lease_token)
        .values(status="COMPLETED", processed_at=_aware(now), lease_token=None, lease_owner=None)
    )
    return bool(result.rowcount)


def fail_claimed(
    session: Session,
    outbox_id: str,
    lease_token: str,
    error_message: str,
    now: datetime,
    force_dead: bool = False,
) -> Optional[str]:
    """Record a failure for a claimed item under its owner token.

    Applies the 5/30/120/600/1800 backoff ladder; the FIFTH failure moves
    the item to DEAD with the reason and an explicit recorded reschedule
    timestamp (operator review). Terminal contradictions (payload conflicts)
    pass force_dead=True: DEAD immediately, same bookkeeping. Returns the
    resulting status ("FAILED" or "DEAD") or None when the token did not
    own the row.
    """
    now = _aware(now)
    stmt = select(Outbox).where(Outbox.id == outbox_id).with_for_update(skip_locked=False)
    row = session.execute(stmt).scalars().first()
    if row is None or row.lease_token != lease_token:
        return None

    attempts = row.attempts
    row.last_error = error_message
    row.error_message = error_message
    if force_dead or attempts >= MAX_ATTEMPTS:
        reschedule_at = now + timedelta(seconds=RETRY_BACKOFFS[-1])
        row.status = "DEAD"
        row.next_attempt_at = reschedule_at
        row.last_error = (
            f"DEAD after {MAX_ATTEMPTS} attempts: {error_message} "
            f"(explicit operator reschedule recorded for {reschedule_at.isoformat()})"
        )
        row.error_message = row.last_error
        row.lease_token = None
        row.lease_owner = None
        row.lease_expires_at = None
        session.flush()
        return "DEAD"

    backoff = RETRY_BACKOFFS[min(attempts, len(RETRY_BACKOFFS)) - 1]
    row.status = "FAILED"
    row.next_attempt_at = now + timedelta(seconds=backoff)
    row.lease_token = None
    row.lease_owner = None
    row.lease_expires_at = None
    session.flush()
    return "FAILED"


def release_claim(session: Session, outbox_id: str, lease_token: str) -> bool:
    """Graceful shutdown path: drop the lease so another worker can take the
    item immediately instead of waiting for expiry (payload untouched)."""
    result = session.execute(
        update(Outbox)
        .where(Outbox.id == outbox_id)
        .where(Outbox.lease_token == lease_token)
        .values(lease_token=None, lease_owner=None, lease_expires_at=None)
    )
    return bool(result.rowcount)


# ---------------------------------------------------------------------------
# Legacy helpers (pre-R08 call sites; kept for compatibility)
# ---------------------------------------------------------------------------


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


def _aware(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now
