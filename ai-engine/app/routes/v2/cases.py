"""
Case Lifecycle Management and Governance Route (V2)
Cyber-Forensic Auditing Framework - Specification §7, §8 (R01, R08, R09, R12, R15)
Provides endpoints for institutional case creation, state transitions (Four-Eyes governance),
pagination, and case timeline details.

R12 (closes F07): every institutional path runs inside
`with tenant_transaction(db, identity.institution_id)` — the R10 signature
(session, institution_id) — so the transaction-local RLS context
(app.current_institution_id) is always set before any institutional query.
The HTTP request scope (method + path) is passed into the service so idempotency
keys are reserved per institution+sub+method+path+key.
"""

from typing import Optional
from fastapi import (
    APIRouter,
    Depends,
    Header,
    Query,
    Request,
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
    IdempotencyConflictError,
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
    request: Request,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    try:
        with tenant_transaction(db, identity.institution_id) as session:
            return service.create_case(
                session=session,
                identity=identity,
                case_number=req.case_number,
                title=req.title,
                description=req.description or "",
                severity=req.severity,
                assigned_to_sub=req.assigned_to_sub,
                idempotency_key=idempotency_key,
                request_scope=(request.method, request.url.path),
            )
    except UnauthorizedRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except CaseServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List institutional cases with cursor pagination",
)
def list_cases(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    cursor: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity_filter: Optional[str] = Query(None, alias="severity"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    try:
        with tenant_transaction(db, identity.institution_id) as session:
            return service.list_cases(
                session=session,
                identity=identity,
                limit=limit,
                cursor=cursor,
                status=status_filter,
                severity=severity_filter,
            )
    except CaseServiceError as exc:
        # Invalid / foreign-institution / filter-mismatched cursors -> 400.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


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
        with tenant_transaction(db, identity.institution_id) as session:
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
    request: Request,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
):
    try:
        with tenant_transaction(db, identity.institution_id) as session:
            return service.transition_case(
                session=session,
                identity=identity,
                case_id=case_id,
                action=req.action,
                expected_version=req.expected_version,
                reason=req.reason,
                new_assignee_sub=req.new_assignee_sub,
                idempotency_key=idempotency_key,
                request_scope=(request.method, request.url.path),
            )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except VersionConflictError as exc:
        # Stale expected_version lost the SQL compare-and-swap: 409.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except IdempotencyConflictError as exc:
        # Same key, different semantic payload (e.g. new_assignee_sub): 409.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except SelfApprovalProhibitedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except UnauthorizedRoleError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except InvalidTransitionError as exc:
        # A transition that contradicts the case's current state conflicts with it.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
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
