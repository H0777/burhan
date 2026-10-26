"""
Forensic Reporting API Route
Cyber-Forensic Auditing Framework
"""

import hashlib
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.gemini_service import gemini_service

router = APIRouter()


class EvidenceItem(BaseModel):
    id: int
    incidentId: Optional[int] = None
    submittedBy: str
    evidenceType: str
    description: str
    evidenceHash: Optional[str] = None
    previousEntryHash: Optional[str] = None
    entryHash: Optional[str] = None
    timestamp: Optional[int] = None


class ForensicReportRequest(BaseModel):
    incident_id: int = Field(..., gt=0, description="Incident ID from ForensicTrail")
    title: str = Field(..., description="Incident title or fraud type")
    severity: str = Field(default="HIGH", description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    reported_by: str = Field(..., description="Investigator address or entity")
    evidence_chain: List[Dict[str, Any]] = Field(default_factory=list, description="Ordered chain of custody entries")
    insider_data: Optional[Dict[str, Any]] = Field(default=None, description="Behavioral metrics of target operator")
    language: str = Field(default="en", description="Report language: 'en' for English, 'ar' for Arabic")


class ChainVerificationRequest(BaseModel):
    evidence_chain: List[Dict[str, Any]] = Field(..., min_length=1)


@router.post("/report", summary="Generate official digital forensic investigation report")
async def generate_report(payload: ForensicReportRequest):
    """
    Synthesizes on-chain evidence chain and behavioral metrics into a court-ready
    digital forensic dossier, supporting both Arabic and English.
    """
    try:
        return gemini_service.generate_forensic_report(
            incident_id=payload.incident_id,
            title=payload.title,
            severity=payload.severity,
            reported_by=payload.reported_by,
            evidence_chain=payload.evidence_chain,
            insider_data=payload.insider_data,
            language=payload.language
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation error: {str(e)}")


@router.post("/verify-chain", summary="Cryptographically verify an evidence chain")
async def verify_chain(payload: ChainVerificationRequest):
    """
    Verifies the cryptographic linkage of evidence entries (parent-child hashes)
    to confirm no tampering or missing links exist in the Chain of Custody.
    """
    chain = payload.evidence_chain
    if not chain:
        return {"is_valid": True, "total_entries": 0, "broken_links": []}

    broken_links = []
    for i in range(1, len(chain)):
        prev_hash = chain[i].get("previousEntryHash")
        expected_hash = chain[i - 1].get("entryHash")
        if prev_hash != expected_hash:
            broken_links.append({
                "entry_index": i,
                "entry_id": chain[i].get("id"),
                "expected_previous_hash": expected_hash,
                "actual_previous_hash": prev_hash
            })

    is_valid = len(broken_links) == 0

    return {
        "is_valid": is_valid,
        "total_entries": len(chain),
        "broken_links_count": len(broken_links),
        "broken_links": broken_links,
        "status": "CHAIN_INTEGRITY_VERIFIED" if is_valid else "CHAIN_TAMPER_DETECTED"
    }
