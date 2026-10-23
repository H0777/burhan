"""
Multi-Tenant Institution, Membership & Wallet Binding Repository (T13, T14)
Specification §4, §7 (R01, R03, R09, R10)
"""

import uuid
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models import Institution, Membership, WalletBindingModel


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
