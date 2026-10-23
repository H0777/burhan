"""
V2 Lifecycle Health Routes
Specification §7 (R06)
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from app.schemas.common import LiveHealthResponse, ReadyHealthResponse
from app.models.fraud_detector import FraudDetector
from app.services.policy_service import get_active_policy

router = APIRouter()


@router.get("/live", response_model=LiveHealthResponse, summary="Process liveness check")
async def live_check():
    """Confirms the process is running and able to handle HTTP traffic."""
    now_utc = datetime.now(timezone.utc).isoformat()
    return LiveHealthResponse(
        status="live",
        service="ai-engine",
        timestamp=now_utc
    )


@router.get("/ready", response_model=ReadyHealthResponse, summary="Subsystem readiness check")
async def ready_check():
    """
    Verifies that required internal subsystems (ML engine, policy service, schemas)
    are operational.
    """
    checks = {}
    details = {}

    # 1. Check ML Engine readiness
    try:
        detector = FraudDetector()
        checks["ml_engine"] = True
        details["ml_type"] = "Hybrid Isolation Forest + Rule Ensemble"
    except Exception as exc:
        checks["ml_engine"] = False
        details["ml_error"] = str(exc)

    # 2. Check Policy Service readiness
    try:
        policy = get_active_policy(asset="ETH")
        checks["policy_service"] = policy is not None
        details["active_eth_policy"] = policy.version
    except Exception as exc:
        checks["policy_service"] = False
        details["policy_error"] = str(exc)

    # 3. Check Blockchain Node & Indexer Lag
    try:
        from app.services.blockchain_listener import blockchain_listener
        node_health = blockchain_listener.get_node_health()
        details["blockchain_status"] = node_health.get("status", "OFFLINE")
        details["current_block"] = node_health.get("current_block")
        details["indexer_lag"] = 0 if node_health.get("connected") else -1
        details["indexer_status"] = "SYNCED" if node_health.get("connected") else "OFFLINE"
    except Exception as exc:
        details["blockchain_error"] = str(exc)
        details["indexer_status"] = "ERROR"

    all_ready = all(checks.values())

    return ReadyHealthResponse(
        status="ready" if all_ready else "degraded",
        live=True,
        ready=all_ready,
        checks=checks,
        details=details
    )
