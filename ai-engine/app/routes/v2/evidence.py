"""
Evidence Verification and Management Route (V2)
Cyber-Forensic Auditing Framework - Specification §5, §7 (R01, R04, R08, R09, R14)
Provides independent verification, WORM evidence ingestion, and download endpoints.
"""

from typing import Optional, Dict, Any, List
from fastapi import (
    APIRouter,
    Depends,
    UploadFile,
    File,
    Header,
    HTTPException,
    status,
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db, tenant_transaction
from app.schemas.identity import Identity
from app.schemas.evidence import EvidenceVerificationRequest, EvidenceVerificationResult
from app.services.evidence_verifier import verify_evidence
from app.services.evidence_store import EvidenceStore
from app.services.evidence_broker import (
    EvidenceBroker,
    RoleNotAuthorizedError,
    CaseAssignmentError,
    IdempotencyConflictError,
)
from app.repositories import (
    evidence_repository,
    case_repository,
)
from app.routes.v2.identity import get_current_identity
from app.services.evm_rpc_client import EvmRpcClient

router = APIRouter()
cases_router = APIRouter()

# Global or configurable RPC provider hook for integration/unit testing
_rpc_provider = None
_evidence_store: Optional[EvidenceStore] = None


def set_rpc_provider(provider):
    global _rpc_provider
    _rpc_provider = provider


def get_rpc_provider():
    global _rpc_provider
    if _rpc_provider is not None:
        return _rpc_provider
    if settings.BLOCKCHAIN_RPC_URL:
        try:
            return EvmRpcClient(
                rpc_url=settings.BLOCKCHAIN_RPC_URL,
                manifest_path=settings.DEPLOYMENT_MANIFEST_PATH,
            )
        except Exception:
            return None
    return None


def get_evidence_store() -> EvidenceStore:
    global _evidence_store
    if _evidence_store is None:
        _evidence_store = EvidenceStore()
    return _evidence_store


def set_evidence_store(store: Optional[EvidenceStore]) -> None:
    global _evidence_store
    _evidence_store = store


# ---------------------------------------------------------------------------
# Independent Verification (T05)
# ---------------------------------------------------------------------------
@router.post("/verify", response_model=EvidenceVerificationResult, summary="Verify evidence chain independently")
async def verify_evidence_endpoint(payload: EvidenceVerificationRequest):
    """
    Independently verifies an Evidence V2 payload against cryptographic hashing rules
    and on-chain anchor consensus.
    """
    rpc_client = get_rpc_provider()
    result = verify_evidence(payload, rpc_client=rpc_client)
    return result


# ---------------------------------------------------------------------------
# Case Evidence Upload Endpoint (T14)
# ---------------------------------------------------------------------------
async def _handle_upload_case_evidence(
    case_id: str,
    file: UploadFile = File(...),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    store: EvidenceStore = Depends(get_evidence_store),
) -> Dict[str, Any]:
    broker = EvidenceBroker(evidence_store=store)

    try:
        with tenant_transaction(db, identity.institution_id):
            result = broker.submit_case_evidence(
                session=db,
                identity=identity,
                case_id=case_id,
                file_name=file.filename or "evidence.dat",
                content_type=file.content_type or "application/octet-stream",
                stream=file.file,
                idempotency_key=idempotency_key,
            )
            return result
    except RoleNotAuthorizedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except CaseAssignmentError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except case_repository.CaseNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except IdempotencyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except ValueError as exc:
        msg = str(exc)
        if "exceeds maximum allowed threshold" in msg:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=msg,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg,
        )


@cases_router.post("/{case_id}/evidence", status_code=status.HTTP_201_CREATED, summary="Submit evidence for case")
async def upload_case_evidence_for_cases_path(
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


@router.post("/cases/{case_id}", status_code=status.HTTP_201_CREATED, summary="Submit evidence for case (alt route)")
async def upload_case_evidence_for_evidence_path(
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


# ---------------------------------------------------------------------------
# Evidence Metadata and Download Endpoints (T14)
# ---------------------------------------------------------------------------
@router.get("/{evidence_id}", summary="Get evidence metadata and anchors")
async def get_evidence_endpoint(
    evidence_id: str,
    version: Optional[int] = None,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    obj = evidence_repository.get_evidence_object(
        session=db,
        institution_id=identity.institution_id,
        evidence_id=evidence_id,
        version=version,
    )
    if not obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence {evidence_id} not found for institution {identity.institution_id}",
        )

    anchors = evidence_repository.get_anchors_for_evidence(
        session=db,
        institution_id=identity.institution_id,
        evidence_id=evidence_id,
    )

    return {
        "evidence_id": obj.evidence_id,
        "case_id": obj.case_id,
        "object_version": obj.object_version,
        "file_name": obj.file_name,
        "content_type": obj.content_type,
        "file_size": obj.file_size,
        "sha256_hash": obj.sha256_hash,
        "created_at": obj.created_at.isoformat() if obj.created_at else None,
        "anchors": [
            {
                "anchor_request_id": a.anchor_request_id,
                "chain_id": a.chain_id,
                "contract_address": a.contract_address,
                "status": a.status,
                "transaction_hash": a.transaction_hash,
                "block_number": a.block_number,
                "entry_hash": a.entry_hash,
                "anchored_at": a.anchored_at.isoformat() if a.anchored_at else None,
            }
            for a in anchors
        ],
    }


@router.get("/{evidence_id}/download", summary="Download verified evidence file")
async def download_evidence_endpoint(
    evidence_id: str,
    version: int = 1,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
    store: EvidenceStore = Depends(get_evidence_store),
):
    obj = evidence_repository.get_evidence_object(
        session=db,
        institution_id=identity.institution_id,
        evidence_id=evidence_id,
        version=version,
    )
    if not obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence {evidence_id} not found for institution {identity.institution_id}",
        )

    try:
        # Opens stream with real-time SHA-256 tamper verification
        stream, meta = store.open(
            institution_id=identity.institution_id,
            evidence_id=evidence_id,
            object_version=version,
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file not found in storage vault",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )

    return StreamingResponse(
        stream,
        media_type=meta.get("content_type", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{meta.get("file_name", "evidence.dat")}"',
            "X-Content-SHA256": meta.get("sha256", ""),
        },
    )
