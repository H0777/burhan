"""
Active Policy Route (V2)
Cyber-Forensic Auditing Framework - Specification §7
"""

from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from app.schemas.policy import PolicyVersion
from app.services.policy_service import get_active_policy

router = APIRouter()

# Global or configurable RPC provider hook for integration/unit testing
_rpc_provider = None


def set_policy_rpc_provider(provider):
    global _rpc_provider
    _rpc_provider = provider


def get_policy_rpc_provider():
    return _rpc_provider


@router.get("/active", response_model=PolicyVersion, summary="Get active compliance policy")
async def get_active_policy_endpoint(
    asset: str = Query(default="ETH", description="Asset identifier (ETH, IQD)"),
    institution_id: Optional[str] = Query(default=None, alias="institutionId", description="Institution partition ID")
):
    """
    Returns the authoritative active AML/KYC policy version and minor-unit thresholds
    for the requested asset and institutional scope.
    """
    try:
        rpc_client = get_policy_rpc_provider()
        policy = get_active_policy(
            institution_id=institution_id,
            asset=asset,
            rpc_client=rpc_client
        )
        return policy
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Policy source unavailable: {str(e)}")
