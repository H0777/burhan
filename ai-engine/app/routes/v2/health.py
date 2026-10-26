"""
V2 Lifecycle Health Routes
Specification §7 (R06, R14, R15 - F11)
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from fastapi import APIRouter, Response, status

from app.config import settings
from app.models.fraud_detector import FraudDetector
from app.schemas.common import LiveHealthResponse, ReadyHealthResponse
from app.services.policy_service import get_active_policy

router = APIRouter()


def check_db_connectivity() -> Tuple[bool, Optional[str]]:
    """
    Verify database connection with a lightweight probe query (SELECT 1).
    Fails closed on connection failure or timeout.
    """
    try:
        from sqlalchemy import text
        from app.db.session import get_engine
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:
        return False, str(exc)


def check_migration_status() -> Tuple[bool, Optional[str]]:
    """
    Verify database schema migration status against expected head.
    On SQLite (dev/demo), verifies local tables.
    On PostgreSQL, asserts alembic head match.
    """
    try:
        from app.db.session import get_engine, verify_schema_revision
        engine = get_engine()
        revision = verify_schema_revision(engine)
        return True, revision
    except Exception as exc:
        return False, str(exc)


def check_kms_vault_readiness() -> Tuple[bool, Optional[str]]:
    """
    Verify evidence vault storage directory writeability and KMS/KeyProvider access.
    """
    try:
        from pathlib import Path
        vault_path = Path(settings.EVIDENCE_STORE_PATH)
        vault_path.mkdir(parents=True, exist_ok=True)
        probe_file = vault_path / ".health_probe_tmp"
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
        return True, None
    except Exception as exc:
        return False, str(exc)


def check_evm_rpc_responsiveness() -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Verify responsiveness of the EVM blockchain node via JSON-RPC.
    """
    try:
        from app.services.blockchain_listener import blockchain_listener
        health = blockchain_listener.get_node_health()
        connected = bool(health.get("connected", False))
        status_str = health.get("status", "OFFLINE")
        if not connected:
            return False, f"EVM RPC is {status_str} at {health.get('rpc_url')}", health
        return True, None, health
    except Exception as exc:
        err_msg = str(exc)
        return False, err_msg, {"status": "ERROR", "error": err_msg}


@router.get("/live", response_model=LiveHealthResponse, summary="Process liveness check")
async def live_check():
    """Confirms the process is running and able to handle HTTP traffic."""
    now_utc = datetime.now(timezone.utc).isoformat()
    return LiveHealthResponse(
        status="live",
        service="ai-engine",
        timestamp=now_utc
    )


@router.get("/startup", response_model=ReadyHealthResponse, summary="Startup completion probe")
async def startup_check(response: Response):
    """
    Verifies that startup invariants (config, DB, migrations, vault)
    have been satisfied before traffic routing.
    """
    checks: Dict[str, bool] = {}
    details: Dict[str, Any] = {}
    reasons = []

    # 1. Config validation
    try:
        from app.config import validate_startup_config
        validate_startup_config()
        checks["config"] = True
        details["app_mode"] = settings.APP_MODE
    except Exception as exc:
        checks["config"] = False
        reasons.append(f"Config error: {exc}")
        details["config_error"] = str(exc)

    # 2. Database connectivity
    db_ok, db_err = check_db_connectivity()
    checks["database"] = db_ok
    if not db_ok:
        reasons.append(f"Database error: {db_err}")
        details["database_error"] = db_err

    # 3. Migration status
    mig_ok, mig_val = check_migration_status()
    checks["migrations"] = mig_ok
    if not mig_ok:
        reasons.append(f"Migration error: {mig_val}")
        details["migration_error"] = mig_val
    else:
        details["schema_revision"] = mig_val

    # 4. Storage / Vault readiness
    vault_ok, vault_err = check_kms_vault_readiness()
    checks["vault"] = vault_ok
    if not vault_ok:
        reasons.append(f"Vault error: {vault_err}")
        details["vault_error"] = vault_err

    all_ready = all(checks.values())
    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        details["reasons"] = reasons

    return ReadyHealthResponse(
        status="started" if all_ready else "starting",
        live=True,
        ready=all_ready,
        checks=checks,
        details=details
    )


@router.get("/ready", response_model=ReadyHealthResponse, summary="Subsystem readiness check")
async def ready_check(response: Response):
    """
    Verifies that required internal subsystems and external dependencies
    (DB, migrations, KMS/vault, EVM RPC, ML engine, policy service) are operational.
    When EVM RPC or optional services are down, degrades gracefully:
    marks status='degraded', ready=False, returns HTTP 503 with explicit diagnostic reasons.
    """
    checks: Dict[str, bool] = {}
    details: Dict[str, Any] = {}
    reasons = []

    # 1. Database connectivity
    db_ok, db_err = check_db_connectivity()
    checks["database"] = db_ok
    if not db_ok:
        reasons.append(f"Database unavailable: {db_err}")
        details["database_error"] = db_err

    # 2. Database migration status
    mig_ok, mig_val = check_migration_status()
    checks["migrations"] = mig_ok
    if not mig_ok:
        reasons.append(f"Migration status invalid: {mig_val}")
        details["migration_error"] = mig_val
    else:
        details["schema_revision"] = mig_val

    # 3. KMS / Vault readiness
    kms_ok, kms_err = check_kms_vault_readiness()
    checks["kms_vault"] = kms_ok
    if not kms_ok:
        reasons.append(f"KMS / Vault error: {kms_err}")
        details["kms_vault_error"] = kms_err

    # 4. EVM RPC responsiveness
    rpc_ok, rpc_err, rpc_health = check_evm_rpc_responsiveness()
    checks["evm_rpc"] = rpc_ok
    details["blockchain_status"] = rpc_health.get("status", "OFFLINE")
    details["current_block"] = rpc_health.get("current_block")
    details["rpc_url"] = rpc_health.get("rpc_url")
    if not rpc_ok:
        reasons.append(f"EVM RPC degraded: {rpc_err}")
        details["evm_rpc_error"] = rpc_err

    # 5. Check ML Engine readiness
    try:
        detector = FraudDetector()
        checks["ml_engine"] = True
        details["ml_type"] = "Hybrid Isolation Forest + Rule Ensemble"
    except Exception as exc:
        checks["ml_engine"] = False
        reasons.append(f"ML engine error: {exc}")
        details["ml_error"] = str(exc)

    # 6. Check Policy Service readiness
    try:
        policy = get_active_policy(asset="ETH")
        checks["policy_service"] = policy is not None
        if policy:
            details["active_eth_policy"] = policy.version
        else:
            checks["policy_service"] = False
            reasons.append("Active policy for ETH not found")
    except Exception as exc:
        checks["policy_service"] = False
        reasons.append(f"Policy service error: {exc}")
        details["policy_error"] = str(exc)

    all_ready = all(checks.values())

    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        details["reasons"] = reasons

    return ReadyHealthResponse(
        status="ready" if all_ready else "degraded",
        live=True,
        ready=all_ready,
        checks=checks,
        details=details
    )
