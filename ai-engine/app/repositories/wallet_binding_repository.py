"""
Persistent PostgreSQL repository for SIWE wallet challenges and bindings (R10).

Replaces the in-memory fixture repository on every institutional path: a
challenge is a DATABASE row (it survives process restarts) and consumption is
an atomic compare-and-swap over `consumed_at`/`expires_at`, so two concurrent
sessions can never both win. All methods take the caller's session — the
service layer owns the transaction boundaries (tenant_transaction), keeping
row-level security context and data access in one transaction.

Records (ChallengeRecord/BindingRecord) live here so that both the repository
and the service layer can import them without a circular import. The
in-memory double for unit tests stays in app.security.wallet_binding.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update

from app.db.models import WalletBindingModel, WalletChallengeModel
from app.schemas.identity import RoleEnum

# The one-active-wallet-per-membership constraint at rest: exactly one binding
# row per (institution_id, sub) — enforced by the database unique constraint
# uq_wallet_binding_institution_sub (R11 baseline) and re-asserted by the
# upsert in save_binding().


class ChallengeRecord:
    """In-memory mirror of one wallet_challenges row."""

    def __init__(
        self,
        challenge_id: str,
        institution_id: str,
        sub: str,
        wallet_address: str,
        chain_id: int,
        nonce: str,
        message: str,
        expires_at: datetime,
        domain: str = "",
        issued_at: Optional[datetime] = None,
        consumed_at: Optional[datetime] = None,
    ):
        self.challenge_id = challenge_id
        self.institution_id = institution_id
        self.sub = sub
        self.wallet_address = wallet_address.lower()
        self.chain_id = chain_id
        self.domain = domain
        self.nonce = nonce
        self.message = message
        self.issued_at = issued_at or datetime.now(timezone.utc)
        self.expires_at = expires_at
        self.consumed_at = consumed_at

    @property
    def used(self) -> bool:
        return self.consumed_at is not None


class BindingRecord:
    """In-memory mirror of one wallet_bindings row (the ACTIVE wallet binding)."""

    def __init__(
        self,
        institution_id: str,
        sub: str,
        wallet_address: str,
        participant_id: str,
        role: RoleEnum,
        authorization_generation: int,
        bound_at: datetime,
    ):
        self.institution_id = institution_id
        self.sub = sub
        self.wallet_address = wallet_address.lower()
        self.participant_id = participant_id
        self.role = role
        self.authorization_generation = authorization_generation
        self.bound_at = bound_at


def _challenge_to_record(row: WalletChallengeModel) -> ChallengeRecord:
    return ChallengeRecord(
        challenge_id=row.id,
        institution_id=row.institution_id,
        sub=row.sub,
        wallet_address=row.wallet_address,
        chain_id=row.chain_id,
        nonce=row.nonce,
        message=row.message,
        expires_at=row.expires_at,
        domain=row.domain,
        issued_at=row.issued_at,
        consumed_at=row.consumed_at,
    )


def _binding_to_record(row: WalletBindingModel) -> BindingRecord:
    try:
        role = RoleEnum(row.role)
    except ValueError:
        role = RoleEnum.NONE
    return BindingRecord(
        institution_id=row.institution_id,
        sub=row.sub,
        wallet_address=row.wallet_address,
        participant_id=row.participant_id,
        role=role,
        authorization_generation=row.authorization_generation,
        bound_at=row.bound_at,
    )


class WalletBindingRepository:
    """Session-bound PostgreSQL repository (works on the SQLite dev path too)."""

    requires_session = True

    def __init__(self, session_factory=None):
        # The factory is only used when the repository must open a session for
        # itself; the service layer normally passes the caller's session.
        self.session_factory = session_factory

    def save_challenge(self, session, record: ChallengeRecord) -> None:
        session.add(
            WalletChallengeModel(
                id=record.challenge_id,
                institution_id=record.institution_id,
                sub=record.sub,
                wallet_address=record.wallet_address,
                domain=record.domain,
                chain_id=record.chain_id,
                nonce=record.nonce,
                message=record.message,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
                consumed_at=record.consumed_at,
            )
        )
        session.flush()

    def get_challenge(self, session, challenge_id: str) -> Optional[ChallengeRecord]:
        row = session.get(WalletChallengeModel, challenge_id)
        return _challenge_to_record(row) if row else None

    def consume_challenge(
        self,
        session,
        challenge_id: str,
        institution_id: str,
        sub: str,
        now: datetime,
    ) -> ChallengeRecord:
        """
        Atomic single-use consumption (compare-and-swap).

        One UPDATE statement flips consumed_at from NULL to `now` only while the
        row is unconsumed, unexpired, and bound to the exact
        (challenge_id, institution_id, sub) triple. On PostgreSQL the row lock
        held by the UPDATE serializes racing sessions: the first caller flips
        the marker and commits; every later caller's UPDATE matches zero rows.
        Raises ValueError when the CAS matches nothing (used, expired, unknown,
        or addressed under a foreign tenant/subject).
        """
        result = session.execute(
            update(WalletChallengeModel)
            .where(
                WalletChallengeModel.id == challenge_id,
                WalletChallengeModel.institution_id == institution_id,
                WalletChallengeModel.sub == sub,
                WalletChallengeModel.consumed_at.is_(None),
                WalletChallengeModel.expires_at > now,
            )
            .values(consumed_at=now)
        )
        if result.rowcount != 1:
            raise ValueError(
                "Challenge already used or expired: no unconsumed, unexpired "
                "challenge exists for this challenge id, tenant and subject"
            )
        row = session.get(WalletChallengeModel, challenge_id)
        return _challenge_to_record(row)

    def save_binding(self, session, record: BindingRecord) -> BindingRecord:
        """Upsert the ACTIVE wallet binding for (institution_id, sub).

        The unique constraint uq_wallet_binding_institution_sub makes this the
        one-active-wallet-per-membership rule: a rotation REPLACES the active
        row; it can never create a second active wallet for the membership.
        """
        existing = session.execute(
            select(WalletBindingModel).where(
                WalletBindingModel.institution_id == record.institution_id,
                WalletBindingModel.sub == record.sub,
            )
        ).scalars().first()
        if existing:
            existing.wallet_address = record.wallet_address
            existing.participant_id = record.participant_id
            existing.role = record.role.value if hasattr(record.role, "value") else str(record.role)
            existing.authorization_generation = record.authorization_generation
            existing.bound_at = record.bound_at
            session.flush()
            return _binding_to_record(existing)

        row = WalletBindingModel(
            id=f"wb_{uuid.uuid4().hex[:16]}",
            institution_id=record.institution_id,
            sub=record.sub,
            wallet_address=record.wallet_address,
            participant_id=record.participant_id,
            role=record.role.value if hasattr(record.role, "value") else str(record.role),
            authorization_generation=record.authorization_generation,
            bound_at=record.bound_at,
        )
        session.add(row)
        session.flush()
        return _binding_to_record(row)

    def get_binding(self, session, institution_id: str, sub: str) -> Optional[BindingRecord]:
        row = session.execute(
            select(WalletBindingModel).where(
                WalletBindingModel.institution_id == institution_id,
                WalletBindingModel.sub == sub,
            )
        ).scalars().first()
        return _binding_to_record(row) if row else None

    def wallet_bound_elsewhere(self, session, wallet_address: str, institution_id: str, sub: str) -> bool:
        """R02 invariant: a wallet already bound to a DIFFERENT identity (retired
        wallets included) can never be re-bound to another membership."""
        row = session.execute(
            select(WalletBindingModel.id).where(
                WalletBindingModel.wallet_address == wallet_address.lower(),
                (WalletBindingModel.institution_id != institution_id)
                | (WalletBindingModel.sub != sub),
            )
        ).scalars().first()
        return row is not None
