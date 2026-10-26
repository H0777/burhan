"""
Smart Contract Security Scanner API Route
Cyber-Forensic Auditing Framework
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.gemini_service import gemini_service

router = APIRouter()


class ContractScanRequest(BaseModel):
    code: str = Field(..., min_length=10, description="Solidity smart contract source code")
    contract_name: str = Field(default="SmartContract", description="Name of the contract under audit")


@router.post("/scan", summary="Scan smart contract for vulnerabilities & backdoors")
async def scan_contract(payload: ContractScanRequest):
    """
    Performs dual-mode automated security audit on Solidity smart contract:
    - Checks for reentrancy, tx.origin, arbitrary selfdestruct, delegatecall injection, and public mints.
    - If Gemini API is available, enhances analysis with deep contextual vulnerability reasoning.
    """
    try:
        return gemini_service.scan_contract(payload.code, payload.contract_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Contract scan failed: {str(e)}")
