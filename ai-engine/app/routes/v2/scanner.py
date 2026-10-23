"""
Smart Contract Scanner & Privacy Narrative Routes (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §9 (T21, R12, R14, R15)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, ConfigDict

from app.schemas.identity import Identity
from app.services.scanner_service import ContractScannerService, ScanResult
from app.services.llm_provider import LLMProviderService, NarrativeResult
from app.routes.v2.identity import get_current_identity
from app.config import settings

router = APIRouter()
_scanner_service = ContractScannerService()
_llm_service = LLMProviderService()


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_code: str = Field(..., min_length=1, description="Solidity contract source code")
    mode: str = Field(default="patterns", description="Scanner mode: 'patterns'")


class NarrativeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_title: str = Field(..., min_length=1)
    case_description: str = Field(default="")
    evidence_descriptions: List[str] = Field(default_factory=list)
    enable_cloud: bool = Field(default=False, description="Explicit opt-in to cloud generative models")


@router.post(
    "/scan",
    response_model=ScanResult,
    summary="Scan Solidity smart contract for security anti-patterns with honest limitations",
)
def scan_contract_endpoint(
    request: ScanRequest,
    identity: Identity = Depends(get_current_identity),
):
    try:
        return _scanner_service.scan_contract(
            source_code=request.source_code,
            mode=request.mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Scan error: {str(exc)}")


@router.post(
    "/narrative",
    response_model=NarrativeResult,
    summary="Generate privacy-redacted narrative summary for forensic investigation",
)
def generate_narrative_endpoint(
    request: NarrativeRequest,
    identity: Identity = Depends(get_current_identity),
):
    try:
        return _llm_service.generate_investigation_narrative(
            case_title=request.case_title,
            case_description=request.case_description,
            evidence_descriptions=request.evidence_descriptions,
            institution_id=identity.institution_id,
            enable_cloud=request.enable_cloud,
            gemini_api_key=settings.GEMINI_API_KEY,
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Narrative error: {str(exc)}")
