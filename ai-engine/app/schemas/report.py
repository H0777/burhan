"""
Forensic Report & Verifiable Dossier Schemas (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (T20, R04, R15)
"""

from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class ReportCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: Literal["en", "ar"] = Field(
        default="en",
        description="Target report language ('en' for English, 'ar' for Arabic)"
    )
    evidence_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional list of specific evidence IDs to include; defaults to all case evidence"
    )
    assessment_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional list of assessment IDs to include in the findings section"
    )


class ReportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_id: str = Field(..., description="Unique report identifier")
    case_id: str = Field(..., description="Associated case ID")
    institution_id: str = Field(..., description="Issuing tenant institution ID")
    version: int = Field(..., ge=1, description="Sequential report version number")
    language: str = Field(..., description="Report language ('en' or 'ar')")
    dossier_hash: str = Field(..., pattern=r"^0x[0-9a-fA-F]{64}$", description="SHA-256 hash of entire dossier")
    integrity_status: Literal["VERIFIED", "UNANCHORED", "TAMPER_DETECTED", "UNAVAILABLE"] = Field(
        ...,
        description="Cryptographic chain anchor and evidence integrity status"
    )
    provenance_status: str = Field(..., description="Provenance explanation string")
    markdown: str = Field(..., description="Deterministic formatted markdown document")
    engine: str = Field(..., description="Report generation engine identifier")
    manifest: Dict[str, Any] = Field(..., description="Comprehensive dossier manifest")
    created_by: str = Field(..., description="Subject identity of creator")
    created_at: datetime = Field(..., description="Timestamp of report issuance in UTC")


class ReportListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: List[ReportResponse] = Field(..., description="Historical list of reports for the case")
    total: int = Field(..., ge=0, description="Total number of report versions")
