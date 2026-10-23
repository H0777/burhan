"""
Transaction and Import Schemas (V2)
Cyber-Forensic Auditing Framework - Specification §7 & T17 (R07, R08, R09, R11, R18)
Provides typed data models for streaming banking CSV imports and indexed transaction queries.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class TransactionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    institution_id: str
    source: str
    external_id: str
    occurred_at: datetime
    sender_ref: str
    receiver_ref: str
    currency: str
    scale: int
    amount_minor: int
    status: str
    risk_score: Optional[int] = None
    created_at: datetime


class TransactionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: List[TransactionResponse]
    next_cursor: Optional[str] = None
    total: int


class TransactionImportRowError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    row_index: int = Field(..., description="1-indexed row number in the CSV file")
    error_code: str = Field(..., description="Standardized error code (e.g. MISSING_TIMEZONE, INVALID_AMOUNT)")
    message: str = Field(..., description="Sanitized, non-PII explanation of validation failure")


class TransactionImportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    import_id: str
    institution_id: str
    filename: str
    status: str
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    errors: List[TransactionImportRowError]
    created_at: datetime
