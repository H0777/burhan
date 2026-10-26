"""
Integration & TDD Tests for Health, Startup, and Readiness Probes (R14, R15 - F11)

Validates:
1. /health/live and /api/v2/health/live (Liveness probe)
2. /health/startup and /api/v2/health/startup (Startup probe: config, DB, migrations, vault)
3. /health/ready and /api/v2/health/ready (Readiness probe: DB, migrations, KMS/vault, EVM RPC, ML, Policy)
4. Graceful degradation: when EVM RPC, DB, migrations, or KMS/vault fail,
   the endpoint does not crash, marks status as degraded, sets ready=False,
   returns HTTP 503 Service Unavailable with explicit diagnostic reasons.
"""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.common import LiveHealthResponse, ReadyHealthResponse

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Liveness Tests (/health/live & /api/v2/health/live)
# ---------------------------------------------------------------------------

def test_health_live_endpoint_returns_200_and_valid_schema():
    """Liveness probe: verifies process is alive on both root and V2 paths."""
    for path in ["/health/live", "/api/v2/health/live"]:
        res = client.get(path)
        assert res.status_code == 200, f"Failed on path {path}: {res.text}"
        data = res.json()
        # Validate using Pydantic schema (extra='forbid')
        validated = LiveHealthResponse(**data)
        assert validated.status == "live"
        assert validated.service == "ai-engine"
        assert validated.timestamp is not None


# ---------------------------------------------------------------------------
# 2. Startup Tests (/health/startup & /api/v2/health/startup)
# ---------------------------------------------------------------------------

def test_health_startup_healthy():
    """Startup probe: returns 200 and ready=True when initial configuration and DB are ready."""
    for path in ["/health/startup", "/api/v2/health/startup"]:
        res = client.get(path)
        assert res.status_code == 200, f"Failed on path {path}: {res.text}"
        data = res.json()
        assert data["live"] is True
        assert data["ready"] is True
        assert data["status"] in ("ready", "started")
        assert "checks" in data
        assert data["checks"].get("database") is True
        assert data["checks"].get("migrations") is True
        assert data["checks"].get("vault") is True


def test_health_startup_fails_when_db_down():
    """Startup probe fails with 503 if DB is unreachable during initialization."""
    with patch("app.routes.v2.health.check_db_connectivity", return_value=(False, "Connection refused")):
        for path in ["/health/startup", "/api/v2/health/startup"]:
            res = client.get(path)
            assert res.status_code == 503
            data = res.json()
            assert data["ready"] is False
            assert data["checks"].get("database") is False
            assert "Connection refused" in str(data.get("details", {}))


# ---------------------------------------------------------------------------
# 3. Readiness Tests (/health/ready & /api/v2/health/ready)
# ---------------------------------------------------------------------------

def test_health_ready_all_subsystems_healthy(monkeypatch):
    """Readiness probe returns 200 and ready=True when all subsystems are operational."""
    from app.services.blockchain_listener import blockchain_listener
    monkeypatch.setattr(
        blockchain_listener,
        "get_node_health",
        lambda: {"connected": True, "rpc_url": "http://127.0.0.1:8545", "current_block": 12345, "status": "ONLINE"}
    )

    for path in ["/health/ready", "/api/v2/health/ready"]:
        res = client.get(path)
        assert res.status_code == 200, f"Failed on {path}: {res.text}"
        data = res.json()
        validated = ReadyHealthResponse(**data)
        assert validated.status == "ready"
        assert validated.live is True
        assert validated.ready is True
        assert validated.checks.get("database") is True
        assert validated.checks.get("migrations") is True
        assert validated.checks.get("kms_vault") is True
        assert validated.checks.get("evm_rpc") is True
        assert validated.checks.get("ml_engine") is True
        assert validated.checks.get("policy_service") is True


def test_health_ready_evm_rpc_down_degrades_gracefully(monkeypatch):
    """
    When EVM RPC is unreachable:
    - Must degrade gracefully (prevent cascading crashes)
    - Mark status='degraded' and ready=False
    - Return explicit HTTP 503
    - Supply explicit diagnostic reason in details
    """
    from app.services.blockchain_listener import blockchain_listener
    monkeypatch.setattr(
        blockchain_listener,
        "get_node_health",
        lambda: {"connected": False, "rpc_url": "http://127.0.0.1:8545", "current_block": None, "status": "OFFLINE"}
    )

    for path in ["/health/ready", "/api/v2/health/ready"]:
        res = client.get(path)
        assert res.status_code == 503
        data = res.json()
        validated = ReadyHealthResponse(**data)
        assert validated.status == "degraded"
        assert validated.ready is False
        assert validated.live is True
        assert validated.checks.get("evm_rpc") is False
        assert "OFFLINE" in str(validated.details) or "rpc" in str(validated.details).lower()


def test_health_ready_db_down_degrades_gracefully():
    """When database connection fails, return 503 degraded without 500 error."""
    with patch("app.routes.v2.health.check_db_connectivity", return_value=(False, "Database unreachable")):
        for path in ["/health/ready", "/api/v2/health/ready"]:
            res = client.get(path)
            assert res.status_code == 503
            data = res.json()
            validated = ReadyHealthResponse(**data)
            assert validated.status == "degraded"
            assert validated.ready is False
            assert validated.checks.get("database") is False
            assert "Database unreachable" in str(validated.details)


def test_health_ready_migrations_unmigrated_degrades_gracefully():
    """When database migrations are unmigrated or mismatched, return 503 degraded."""
    with patch("app.routes.v2.health.check_migration_status", return_value=(False, "Schema revision mismatch: expected head_123 got unmigrated")):
        for path in ["/health/ready", "/api/v2/health/ready"]:
            res = client.get(path)
            assert res.status_code == 503
            data = res.json()
            validated = ReadyHealthResponse(**data)
            assert validated.status == "degraded"
            assert validated.ready is False
            assert validated.checks.get("migrations") is False
            assert "Schema revision mismatch" in str(validated.details)


def test_health_ready_kms_vault_failure_degrades_gracefully():
    """When evidence vault / KMS check fails, return 503 degraded."""
    with patch("app.routes.v2.health.check_kms_vault_readiness", return_value=(False, "Vault storage directory is not writable")):
        for path in ["/health/ready", "/api/v2/health/ready"]:
            res = client.get(path)
            assert res.status_code == 503
            data = res.json()
            validated = ReadyHealthResponse(**data)
            assert validated.status == "degraded"
            assert validated.ready is False
            assert validated.checks.get("kms_vault") is False
            assert "Vault storage directory is not writable" in str(validated.details)
