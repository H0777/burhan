"""
Multi-Tenant Institution, Membership & Wallet Binding Repository (T13, T14, R10)
Specification §4, §7 (R01, R03, R09, R10)
"""

import uuid
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models import Institution, Membership, WalletBindingModel
from app.db.session import tenant_transaction
from app.schemas.identity import Identity, RoleEnum
from app.security.wallet_binding import get_wallet_service


class MembershipResolutionError(Exception):
    """
    The verified token subject has no ACTIVE institutional membership (or the
    membership role is not a valid RBAC role). Raised by resolve_identity and
    mapped to 403 by the routes: a valid JWT alone grants nothing and never
    creates a membership.
    """


def resolve_identity(session: Session, claims: dict) -> Identity:
    """
    R10 interface: resolve the institutional Identity from VERIFIED OIDC claims.

    - The role comes EXCLUSIVELY from the stored, active membership row — never
      from the JWT role claim, and a token can never create a membership.
    - institution_id from the claims only ROUTES the lookup: the identity is
      only granted when an active membership exists under exactly that
      institution for this subject.
    - Wallet, participant_id and authorization_generation come from the stored
      binding (DB) plus the RoleManager (see the wallet binding service).
    - permissions are institutional and stored-side only (membership rows carry
      no permission list; the resolved permission set is empty until an
      institutional permission model exists).

    Raises MembershipResolutionError (-> 403) when no active membership exists
    for (institution_id, sub).
    """
    sub = claims.get("sub")
    institution_id = claims.get("institution_id")
    if not sub or not institution_id:
        raise MembershipResolutionError(
            "Verified claims are missing 'sub' or 'institution_id'; cannot resolve membership"
        )

    inst_id = str(institution_id).strip()
    subject = str(sub).strip()

    # Read the membership INSIDE the transaction-local tenant context and
    # snapshot it: after tenant_transaction commits, the ORM instance is
    # expired and any lazy refresh would re-SELECT WITHOUT the RLS context
    # (and correctly see nothing).
    membership_snapshot: Optional[tuple] = None
    with tenant_transaction(session, inst_id):
        membership = get_membership(session, inst_id, subject)
        if membership is not None:
            membership_snapshot = (membership.is_active, membership.role, membership.email)

    if membership_snapshot is None or not membership_snapshot[0]:
        raise MembershipResolutionError(
            "No active institutional membership for this subject and institution"
        )

    is_active, role_str, membership_email = membership_snapshot
    try:
        role = RoleEnum(role_str)
    except ValueError:
        role = RoleEnum.NONE  # fail-closed: unknown stored roles grant nothing

    binding = get_wallet_service().get_active_binding(inst_id, subject)

    return Identity(
        sub=subject,
        issuer=str(claims.get("iss", "")),
        institution_id=inst_id,
        role=role,
        permissions=[],
        email=membership_email,
        participant_id=binding.participant_id if binding else None,
        wallet_address=binding.wallet_address if binding else None,
        authorization_generation=binding.authorization_generation if binding else None,
    )


def create_institution(session: Session, institution_id: str, name: str) -> Institution:
    inst = Institution(id=institution_id, name=name, is_active=True)
    session.add(inst)
    session.flush()
    return inst


def get_institution(session: Session, institution_id: str) -> Optional[Institution]:
    stmt = select(Institution).where(Institution.id == institution_id)
    return session.execute(stmt).scalars().first()


def create_membership(
    session: Session,
    institution_id: str,
    sub: str,
    role: str,
    email: Optional[str] = None,
) -> Membership:
    mem = Membership(
        id=f"mem_{uuid.uuid4().hex[:16]}",
        institution_id=institution_id,
        sub=sub,
        role=role,
        email=email,
        is_active=True,
    )
    session.add(mem)
    session.flush()
    return mem


def get_membership(session: Session, institution_id: str, sub: str) -> Optional[Membership]:
    stmt = select(Membership).where(
        Membership.institution_id == institution_id,
        Membership.sub == sub,
    )
    return session.execute(stmt).scalars().first()


def bind_wallet(
    session: Session,
    institution_id: str,
    sub: str,
    wallet_address: str,
    participant_id: str,
    role: str,
    authorization_generation: int = 1,
) -> WalletBindingModel:
    # Look for existing binding to update, or create new
    binding = session.execute(
        select(WalletBindingModel).where(
            WalletBindingModel.institution_id == institution_id,
            WalletBindingModel.sub == sub,
        )
    ).scalars().first()

    if binding:
        binding.wallet_address = wallet_address.lower()
        binding.participant_id = participant_id
        binding.role = role
        binding.authorization_generation = authorization_generation
    else:
        binding = WalletBindingModel(
            id=f"wb_{uuid.uuid4().hex[:16]}",
            institution_id=institution_id,
            sub=sub,
            wallet_address=wallet_address.lower(),
            participant_id=participant_id,
            role=role,
            authorization_generation=authorization_generation,
        )
        session.add(binding)

    session.flush()
    return binding


def get_wallet_binding(
    session: Session,
    institution_id: str,
    sub: str,
) -> Optional[WalletBindingModel]:
    stmt = select(WalletBindingModel).where(
        WalletBindingModel.institution_id == institution_id,
        WalletBindingModel.sub == sub,
    )
    return session.execute(stmt).scalars().first()
