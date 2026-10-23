"""
Case Lifecycle Management and Governance Route (V2)
Cyber-Forensic Auditing Framework - Specification §7 (R01, R08, R09, R15)
Provides endpoints for institutional case creation, state transitions (Four-Eyes governance),
pagination, and case timeline details.
"""

from typing import Optional
from fastapi import (
    APIRouter,
    Depends,
    Header,
    Query,
    UploadFile,
    File,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session

from app.db.session import get_db, tenant_transaction
from app.schemas.identity import Identity
from app.schemas.cases import (
    CaseCreateRequest,
    CaseTransitionRequest,
    CaseResponse,
    CaseDetailResponse,
    CaseListResponse,
)
from app.services.case_service import (
    CaseService,
    CaseNotFoundError,
    VersionConflictError,
    SelfApprovalProhibitedError,
    UnauthorizedRoleError,
    InvalidTransitionError,
    CaseServiceError,
)
from app.services.evidence_store import EvidenceStore
from app.routes.v2.identity import get_current_identity
from app.routes.v2.evidence import get_evidence_store, _handle_upload_case_evidence

router = APIRouter()

_case_service: Optional[CaseService] = None


def get_case_service() -> CaseService:
    global _case_service
    if _case_service is None:
        _case_service = CaseService()
    return _case_service


def set_case_service(svc: Optional[CaseService]) -> None:
    global _case_service
    _case_service = svc


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=CaseResponse,
    summary="Create institutional case",
)
def create_case(
    req: CaseCreateRequest,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    try:
        with tenant_transaction(identity) as session:
            return service.create_case(
                session=session,
                identity=identity,
                case_number=req.case_number,
                title=req.title,
                description=req.description or "",
                severity=req.severity,
                assigned_to_sub=req.assigned_to_sub,
                idempotency_key=idempotency_key,
            )
    except UnauthorizedRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except CaseServiceError as exc:
        msg = str(exc)
        if "conflict" in msg.lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List institutional cases with cursor pagination",
)
def list_cases(
    limit: int = Query(50, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    with tenant_transaction(identity) as session:
        return service.list_cases(
            session=session,
            identity=identity,
            limit=limit,
            cursor=cursor,
        )


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Get case details and event history",
)
def get_case_detail(
    case_id: str,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    try:
        with tenant_transaction(identity) as session:
            return service.get_case(
                session=session,
                identity=identity,
                case_id=case_id,
            )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/{case_id}/transition",
    response_model=CaseResponse,
    summary="Execute state transition on case with Four-Eyes governance",
)
def transition_case(
    case_id: str,
    req: CaseTransitionRequest,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    try:
        with tenant_transaction(identity) as session:
            return service.transition_case(
                session=session,
                identity=identity,
                case_id=case_id,
                action=req.action,
                expected_version=req.expected_version,
                reason=req.reason,
                new_assignee_sub=req.new_assignee_sub,
                idempotency_key=idempotency_key,
            )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except VersionConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except SelfApprovalProhibitedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except UnauthorizedRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except InvalidTransitionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except CaseServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/{case_id}/evidence",
    status_code=status.HTTP_201_CREATED,
    summary="Upload non-fungible evidence for case",
)
async def upload_case_evidence(
    case_id: str,
    file: UploadFile = File(...),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    store: EvidenceStore = Depends(get_evidence_store),
):
    return await _handle_upload_case_evidence(
        case_id=case_id,
        file=file,
        idempotency_key=idempotency_key,
        identity=identity,
        db=db,
        store=store,
    )
