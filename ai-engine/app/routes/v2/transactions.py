"""
Transactions and Banking Import Routes (V2)
Cyber-Forensic Auditing Framework - Specification §7 & T17 (R07, R08, R09, R11, R18)
Provides endpoints for streaming CSV ingestion and indexed paginated transaction ledger queries.
"""

from typing import Optional, List
from datetime import datetime
from fastapi import (
    APIRouter,
    Depends,
    UploadFile,
    File,
    Query,
    HTTPException,
    status,
)
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, func

from app.db.session import get_db, tenant_transaction, apply_tenant_context
from app.db.models import TransactionRecord, ImportBatchRecord
from app.schemas.identity import Identity, RoleEnum
from app.schemas.transactions import (
    TransactionResponse,
    TransactionListResponse,
    TransactionImportResponse,
)
from app.connectors.csv_import import (
    CsvImportConnector,
    CsvImportError,
    OversizedFileError,
)
from app.routes.v2.identity import get_current_identity

router = APIRouter()
imports_router = APIRouter()

_csv_connector = CsvImportConnector()


@imports_router.post(
    "/transactions",
    status_code=status.HTTP_201_CREATED,
    response_model=TransactionImportResponse,
    summary="Stream import banking CSV transactions",
)
async def import_banking_transactions(
    file: UploadFile = File(...),
    source: str = Query("IQD_CSV", description="Transaction origin source identifier"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    if identity.role == RoleEnum.REGULATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="REGULATOR role has read-only access and cannot import transaction batches",
        )

    content = await file.read()
    try:
        with tenant_transaction(db, identity.institution_id):
            return _csv_connector.parse_and_import(
                session=db,
                identity=identity,
                file_content=content,
                filename=file.filename or "transactions.csv",
                source=source,
            )
    except OversizedFileError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        )
    except CsvImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=TransactionListResponse,
    summary="Get paginated indexed transactions for institution",
)
def list_transactions(
    limit: int = Query(50, ge=1, le=100),
    cursor: Optional[str] = Query(None, description="Pagination cursor (transaction ID)"),
    source: Optional[str] = Query(None, description="Filter by source (IQD_CSV, EVM, MANUAL)"),
    currency: Optional[str] = Query(None, description="Filter by currency (IQD, ETH, USD)"),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    institution_id = identity.institution_id

    # H04 (PostgreSQL/RLS): read-model queries must run inside the
    # transaction-local tenant context — without it the least-privilege app role
    # sees nothing under FORCE RLS (invisible on SQLite). The import write path
    # already used tenant_transaction; this read path did not — found by the E2E
    # trust-flow suite against the staging PostgreSQL (test 1.5). The request
    # session closes (rollback) in get_db, so the context never leaks.
    apply_tenant_context(db, institution_id)

    query = select(TransactionRecord).where(
        TransactionRecord.institution_id == institution_id
    )

    if source:
        query = query.where(TransactionRecord.source == source)
    if currency:
        query = query.where(TransactionRecord.currency == currency.upper())

    # Deterministic ordering by occurred_at desc, id desc
    query = query.order_by(
        desc(TransactionRecord.occurred_at),
        desc(TransactionRecord.id),
    )

    # Simple cursor-based offset / key pagination
    if cursor:
        cursor_tx = db.execute(
            select(TransactionRecord).where(
                TransactionRecord.institution_id == institution_id,
                TransactionRecord.id == cursor,
            )
        ).scalars().first()
        if cursor_tx:
            query = query.where(
                (TransactionRecord.occurred_at < cursor_tx.occurred_at)
                | (
                    (TransactionRecord.occurred_at == cursor_tx.occurred_at)
                    & (TransactionRecord.id < cursor_tx.id)
                )
            )

    rows = db.execute(query.limit(limit + 1)).scalars().all()

    has_more = len(rows) > limit
    items_to_return = rows[:limit]
    next_cursor = items_to_return[-1].id if has_more and items_to_return else None

    # Total count query
    total_count = db.execute(
        select(func.count(TransactionRecord.id)).where(
            TransactionRecord.institution_id == institution_id
        )
    ).scalar_one()

    return TransactionListResponse(
        items=[
            TransactionResponse(
                id=tx.id,
                institution_id=tx.institution_id,
                source=tx.source,
                external_id=tx.external_id,
                occurred_at=tx.occurred_at,
                sender_ref=tx.sender_ref,
                receiver_ref=tx.receiver_ref,
                currency=tx.currency,
                scale=tx.scale,
                amount_minor=tx.amount_minor,
                status=tx.status,
                risk_score=tx.risk_score,
                created_at=tx.created_at,
            )
            for tx in items_to_return
        ],
        next_cursor=next_cursor,
        total=total_count,
    )
