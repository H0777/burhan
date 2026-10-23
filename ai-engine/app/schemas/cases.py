"""
Case Lifecycle and Transition Schemas (V2)
Specification §7 (R01, R08, R09, R15)
Strict typing and extra='forbid' validation for institutional case workflows.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class CaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_number: str = Field(..., description="Unique human-readable institutional case identifier")
    title: str = Field(..., description="Descriptive case title")
    description: Optional[str] = Field(default="", description="Detailed investigative context")
    severity: str = Field(default="MEDIUM", description="Case severity: LOW, MEDIUM, HIGH, CRITICAL")
    assigned_to_sub: Optional[str] = Field(default=None, description="Initial assigned investigator/auditor sub")


class CaseTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(
        ...,
        description="Transition action: start_review, request_approval, approve_resolution, reject_resolution, escalate, return_to_review, close, reopen, assign",
    )
    expected_version: int = Field(..., description="Current case version for optimistic locking")
    reason: Optional[str] = Field(default="", description="Required justification for resolutions, rejections, escalations")
    new_assignee_sub: Optional[str] = Field(default=None, description="Target assignee sub when reassigning or returning to review")


class CaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    case_number: str
    institution_id: str
    title: str
    description: Optional[str] = ""
    severity: str
    status: str
    assigned_to_sub: Optional[str] = None
    version: int
    created_at: datetime
    updated_at: datetime


class CaseEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    case_id: str
    institution_id: str
    event_type: str
    actor_sub: str
    payload: Dict[str, Any]
    created_at: datetime


class CaseDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case: CaseResponse
    events: List[CaseEventResponse]
    evidence_count: int


class CaseListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: List[CaseResponse]
    next_cursor: Optional[str] = None
    total: int
