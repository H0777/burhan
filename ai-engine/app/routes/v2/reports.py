"""
Forensic Report & Dossier Verification Routes (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (T20, R04, R15)
"""

import json
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, status, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.session import get_db, tenant_transaction
from app.db.models import ReportRecord
from app.schemas.identity import Identity, RoleEnum
from app.schemas.report import (
    ReportCreateRequest,
    ReportResponse,
    ReportListResponse,
)
from app.services.report_service import ReportService
from app.services.evidence_export import EvidenceExportService
from app.routes.v2.identity import get_current_identity

router = APIRouter()
_report_service = ReportService()
_export_service = EvidenceExportService()


@router.post(
    "/cases/{case_id}/reports",
    status_code=status.HTTP_201_CREATED,
    response_model=ReportResponse,
    summary="Generate authoritative versioned case investigation report",
)
def create_case_report_endpoint(
    case_id: str,
    request: ReportCreateRequest,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    if identity.role == RoleEnum.REGULATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="REGULATOR role has read-only access and cannot generate reports",
        )

    try:
        with tenant_transaction(db, identity.institution_id):
            return _report_service.generate_case_report(
                session=db,
                identity=identity,
                case_id=case_id,
                language=request.language,
                evidence_ids=request.evidence_ids,
                assessment_ids=request.assessment_ids,
            )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Report creation failed: {str(exc)}")


@router.get(
    "/cases/{case_id}/reports",
    response_model=ReportListResponse,
    summary="List all historical reports for a case",
)
def list_case_reports_endpoint(
    case_id: str,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    records = db.execute(
        select(ReportRecord).where(
            ReportRecord.institution_id == identity.institution_id,
            ReportRecord.case_id == case_id,
        ).order_by(desc(ReportRecord.version))
    ).scalars().all()

    items = []
    for rec in records:
        manifest = json.loads(rec.manifest_json)
        items.append(
            ReportResponse(
                report_id=rec.report_id,
                case_id=rec.case_id,
                institution_id=rec.institution_id,
                version=rec.version,
                language=rec.language,
                dossier_hash=rec.dossier_hash,
                integrity_status=rec.integrity_status,
                provenance_status=rec.provenance_status,
                markdown=rec.markdown_content,
                engine="ForensicDossierSynthesizer v2.0",
                manifest=manifest,
                created_by=rec.created_by_sub,
                created_at=rec.created_at,
            )
        )

    return ReportListResponse(items=items, total=len(items))


@router.get(
    "/cases/{case_id}/reports/{report_id}",
    response_model=ReportResponse,
    summary="Retrieve specific case report version",
)
def get_case_report_endpoint(
    case_id: str,
    report_id: str,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    rec = db.execute(
        select(ReportRecord).where(
            ReportRecord.institution_id == identity.institution_id,
            ReportRecord.case_id == case_id,
            ReportRecord.report_id == report_id,
        )
    ).scalars().first()

    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found for case '{case_id}'",
        )

    manifest = json.loads(rec.manifest_json)
    return ReportResponse(
        report_id=rec.report_id,
        case_id=rec.case_id,
        institution_id=rec.institution_id,
        version=rec.version,
        language=rec.language,
        dossier_hash=rec.dossier_hash,
        integrity_status=rec.integrity_status,
        provenance_status=rec.provenance_status,
        markdown=rec.markdown_content,
        engine="ForensicDossierSynthesizer v2.0",
        manifest=manifest,
        created_by=rec.created_by_sub,
        created_at=rec.created_at,
    )


@router.get(
    "/cases/{case_id}/reports/{report_id}/export",
    summary="Download self-verifying court-admissible zip archive bundle",
)
def export_case_report_bundle_endpoint(
    case_id: str,
    report_id: str,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    try:
        zip_stream = _export_service.export_report_bundle(
            session=db,
            institution_id=identity.institution_id,
            report_id=report_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Export failed: {str(exc)}")

    headers = {
        "Content-Disposition": f'attachment; filename="evidence_bundle_{report_id}.zip"'
    }
    return Response(
        content=zip_stream.getvalue(),
        media_type="application/zip",
        headers=headers,
    )
