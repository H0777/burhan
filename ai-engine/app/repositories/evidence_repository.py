"""
Multi-Tenant Evidence Repository (T14)
Specification §5, §7 (R01, R04, R08, R09, R14)
Strictly scoped by institution_id on every operation.
"""

import uuid
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.models import EvidenceObject, EvidenceAnchor, Case


class EvidenceNotFoundError(Exception):
    pass


class VersionOverwriteProhibitedError(Exception):
    pass


def save_evidence_object(
    session: Session,
    institution_id: str,
    case_id: str,
    evidence_id: str,
    file_name: str,
    content_type: str,
    file_size: int,
    sha256_hash: str,
    storage_path: str,
    object_version: int = 1,
) -> EvidenceObject:
    # Verify that case exists for this institution
    case = session.execute(
        select(Case).where(
            Case.institution_id == institution_id,
            Case.id == case_id,
        )
    ).scalars().first()
    if not case:
        raise ValueError(f"Case {case_id} does not exist for institution {institution_id}")

    # Check for existing version
    existing = session.execute(
        select(EvidenceObject).where(
            EvidenceObject.institution_id == institution_id,
            EvidenceObject.evidence_id == evidence_id,
            EvidenceObject.object_version == object_version,
        )
    ).scalars().first()
    if existing:
        raise VersionOverwriteProhibitedError(
            f"Evidence {evidence_id} version {object_version} already exists for institution {institution_id}"
        )

    obj = EvidenceObject(
        id=f"ev_{uuid.uuid4().hex[:16]}",
        institution_id=institution_id,
        case_id=case_id,
        evidence_id=evidence_id,
        object_version=object_version,
        file_name=file_name,
        content_type=content_type,
        file_size=file_size,
        sha256_hash=sha256_hash,
        storage_path=storage_path,
        encrypted=True,
    )
    session.add(obj)
    session.flush()
    return obj


def get_evidence_object(
    session: Session,
    institution_id: str,
    evidence_id: str,
    version: Optional[int] = None,
) -> Optional[EvidenceObject]:
    stmt = select(EvidenceObject).where(
        EvidenceObject.institution_id == institution_id,
        EvidenceObject.evidence_id == evidence_id,
    )
    if version is not None:
        stmt = stmt.where(EvidenceObject.object_version == version)
    else:
        stmt = stmt.order_by(desc(EvidenceObject.object_version))
    return session.execute(stmt).scalars().first()


def list_evidence_for_case(
    session: Session,
    institution_id: str,
    case_id: str,
) -> List[EvidenceObject]:
    stmt = (
        select(EvidenceObject)
        .where(
            EvidenceObject.institution_id == institution_id,
            EvidenceObject.case_id == case_id,
        )
        .order_by(desc(EvidenceObject.created_at))
    )
    return list(session.execute(stmt).scalars().all())


def create_anchor(
    session: Session,
    institution_id: str,
    case_id: str,
    evidence_id: str,
    anchor_request_id: str,
    chain_id: int,
    contract_address: str,
    status: str = "PENDING_ANCHOR",
) -> EvidenceAnchor:
    anchor = EvidenceAnchor(
        id=f"anc_{uuid.uuid4().hex[:16]}",
        institution_id=institution_id,
        case_id=case_id,
        evidence_id=evidence_id,
        anchor_request_id=anchor_request_id,
        chain_id=chain_id,
        contract_address=contract_address,
        status=status,
    )
    session.add(anchor)
    session.flush()
    return anchor


def get_anchor_by_request_id(
    session: Session,
    institution_id: str,
    anchor_request_id: str,
) -> Optional[EvidenceAnchor]:
    stmt = select(EvidenceAnchor).where(
        EvidenceAnchor.institution_id == institution_id,
        EvidenceAnchor.anchor_request_id == anchor_request_id,
    )
    return session.execute(stmt).scalars().first()


def get_anchors_for_evidence(
    session: Session,
    institution_id: str,
    evidence_id: str,
) -> List[EvidenceAnchor]:
    stmt = (
        select(EvidenceAnchor)
        .where(
            EvidenceAnchor.institution_id == institution_id,
            EvidenceAnchor.evidence_id == evidence_id,
        )
        .order_by(desc(EvidenceAnchor.created_at))
    )
    return list(session.execute(stmt).scalars().all())


def update_anchor_status(
    session: Session,
    institution_id: str,
    anchor_request_id: str,
    status: str,
    transaction_hash: Optional[str] = None,
    block_number: Optional[int] = None,
    block_hash: Optional[str] = None,
    entry_hash: Optional[str] = None,
) -> EvidenceAnchor:
    anchor = get_anchor_by_request_id(session, institution_id, anchor_request_id)
    if not anchor:
        raise EvidenceNotFoundError(
            f"Anchor request {anchor_request_id} not found for institution {institution_id}"
        )

    anchor.status = status
    if transaction_hash:
        anchor.transaction_hash = transaction_hash
    if block_number is not None:
        anchor.block_number = block_number
    if block_hash:
        anchor.block_hash = block_hash
    if entry_hash:
        anchor.entry_hash = entry_hash
    if status == "ANCHORED":
        anchor.anchored_at = datetime.now(timezone.utc)

    session.flush()
    return anchor
