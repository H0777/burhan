"""
Evidence Verification Route (V2)
Cyber-Forensic Auditing Framework - Specification §7
"""

from fastapi import APIRouter
from app.schemas.evidence import EvidenceVerificationRequest, EvidenceVerificationResult
from app.services.evidence_verifier import verify_evidence

router = APIRouter()

from app.config import settings
from app.services.evm_rpc_client import EvmRpcClient

# Global or configurable RPC provider hook for integration/unit testing
_rpc_provider = None


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


@router.post("/verify", response_model=EvidenceVerificationResult, summary="Verify evidence chain independently")
async def verify_evidence_endpoint(payload: EvidenceVerificationRequest):
    """
    Independently verifies an Evidence V2 payload against cryptographic hashing rules
    and on-chain anchor consensus.
    """
    rpc_client = get_rpc_provider()
    result = verify_evidence(payload, rpc_client=rpc_client)
    return result
