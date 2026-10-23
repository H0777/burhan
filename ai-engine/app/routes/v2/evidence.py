"""
Evidence Verification Route (V2)
Cyber-Forensic Auditing Framework - Specification §7
"""

from fastapi import APIRouter
from app.schemas.evidence import EvidenceVerificationRequest, EvidenceVerificationResult
from app.services.evidence_verifier import verify_evidence

router = APIRouter()

# Global or configurable RPC provider hook for integration/unit testing
_rpc_provider = None


def set_rpc_provider(provider):
    global _rpc_provider
    _rpc_provider = provider


def get_rpc_provider():
    return _rpc_provider


@router.post("/verify", response_model=EvidenceVerificationResult, summary="Verify evidence chain independently")
async def verify_evidence_endpoint(payload: EvidenceVerificationRequest):
    """
    Independently verifies an Evidence V2 payload against cryptographic hashing rules
    and on-chain anchor consensus.
    """
    rpc_client = get_rpc_provider()
    result = verify_evidence(payload, rpc_client=rpc_client)
    return result
