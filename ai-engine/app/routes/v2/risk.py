"""
Authoritative Risk Scoring & Assessment Routes (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (T18, R07, R12)
"""

import json
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.session import get_db, tenant_transaction, apply_tenant_context
from app.db.models import AssessmentRecord
from app.schemas.identity import Identity, RoleEnum
from app.schemas.assessment import (
    AssessmentRequest,
    AssessmentResponse,
    AssessmentListResponse,
)
from app.services.assessment_service import AssessmentService
from app.routes.v2.identity import get_current_identity

router = APIRouter()
_assessment_service = AssessmentService()


@router.post(
    "/assess",
    status_code=status.HTTP_201_CREATED,
    response_model=AssessmentResponse,
    summary="Perform authoritative risk assessment on an indexed transaction",
)
def assess_transaction_endpoint(
    request: AssessmentRequest,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    """
    Evaluates an authoritative transaction from the database against active compliance policies.
    Records an immutable AssessmentRecord in the tenant ledger.
    """
    if identity.role == RoleEnum.REGULATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="REGULATOR role has read-only access and cannot trigger stateful risk assessments",
        )

    try:
        with tenant_transaction(db, identity.institution_id):
            return _assessment_service.assess_transaction(
                session=db,
                identity=identity,
                transaction_id=request.transaction_id,
                as_of=request.as_of,
                is_preview=False,
            )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Assessment failed: {str(exc)}")


@router.post(
    "/preview",
    response_model=AssessmentResponse,
    summary="Preview transaction risk score in simulation mode without persisting",
)
def preview_transaction_endpoint(
    request: AssessmentRequest,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    """
    Simulates compliance risk evaluation for a transaction without persisting an AssessmentRecord.
    """
    # H04 (PostgreSQL/RLS): preview reads the transaction row — needs the
    # transaction-local tenant context under FORCE RLS (invisible on SQLite).
    apply_tenant_context(db, identity.institution_id)
    try:
        return _assessment_service.assess_transaction(
            session=db,
            identity=identity,
            transaction_id=request.transaction_id,
            as_of=request.as_of,
            is_preview=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Preview failed: {str(exc)}")


@router.get(
    "/assessments/{transaction_id}",
    response_model=AssessmentListResponse,
    summary="Get assessment history for a specific transaction",
)
def get_transaction_assessments(
    transaction_id: str,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    """
    Retrieves all historical assessment snapshots for a given transaction.
    """
    # H04 (PostgreSQL/RLS): see preview_transaction_endpoint.
    apply_tenant_context(db, identity.institution_id)
    records = db.execute(
        select(AssessmentRecord).where(
            AssessmentRecord.institution_id == identity.institution_id,
            AssessmentRecord.transaction_id == transaction_id,
        ).order_by(desc(AssessmentRecord.created_at))
    ).scalars().all()

    items = []
    for rec in records:
        items.append(
            AssessmentResponse(
                assessment_id=rec.id,
                transaction_id=rec.transaction_id,
                institution_id=rec.institution_id,
                as_of=rec.created_at,
                policy_id=rec.policy_id,
                policy_version=rec.policy_version,
                fraud_score=float(rec.fraud_score),
                risk_level=rec.risk_level,
                structuring_detected=rec.structuring_detected,
                rules_triggered=json.loads(rec.rules_triggered_json) if rec.rules_triggered_json else [],
                feature_snapshot=json.loads(rec.feature_snapshot_json) if rec.feature_snapshot_json else {},
                features_hash=rec.features_hash,
                engine_version=rec.engine_version,
                model_loaded=rec.model_loaded,
                source=rec.source,
                created_at=rec.created_at,
            )
        )

    return AssessmentListResponse(items=items, total=len(items))
