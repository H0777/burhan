"""
H07 internal metrics route — /internal/metrics (Prometheus text format).

Brief H07, binding constraints:
  * NO PII, NO secrets in labels: labels are institution ids (tenant
    identifiers), worker roles, delivery/status enums, route templates and
    HTTP codes only. No user identifiers, no case numbers, no file names,
    no payload content, no error-message text.
  * No auth required, but the endpoint is only reachable on the compose
    internal network: the staging engine publishes NO host port (see
    infra/staging/docker-compose.staging.yml — the only host-facing port is
    nginx 18080); Prometheus reaches it as `ai-engine:8000`.
  * Read-only observability path (R15 control): these metrics READ the same
    sources of truth as /ready (worker_heartbeats, outbox, chain_submissions,
    EVM RPC) but NEVER mutate anything and never change /ready semantics.

DB-sourced gauges are sampled at scrape time per trusted institution with the
transaction-local tenant context (apply_tenant_context) — the same RLS-safe
read path the institutional routes use; never a context-less all-tenant query
(R08 rule mirrored from workers.runner.trusted_institutions).
"""

import os
import time
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST
from sqlalchemy import text

from app.config import settings
from app.observability import (
    CHAIN_SUBMISSIONS,
    CHAIN_SUBMISSIONS_AWAITING,
    EVM_BLOCK_NUMBER,
    METRICS_DB_UP,
    OUTBOX_EVENTS,
    OUTBOX_OLDEST_AGE,
    RPC_ERRORS_TOTAL,
    RPC_PROBE_LATENCY,
    RPC_PROBE_SUCCESS,
    WORKER_HEARTBEAT_AGE,
    render_metrics,
)

router = APIRouter()

# Awaiting-confirmation statuses (R08 ChainSubmission states before receipt).
_AWAITING_STATUSES = ("SIGNED", "BROADCAST")

_RPC_PROBE_TIMEOUT_SECONDS = 2.0


def _trusted_institutions() -> List[str]:
    """Trusted tenant list (mirror of workers.runner.trusted_institutions):
    explicit WORKER_INSTITUTIONS env registry first, then the configured
    INSTITUTION_ID. Never a bare all-rows query over the registry."""
    raw = os.environ.get("WORKER_INSTITUTIONS", "").strip()
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    inst = settings.INSTITUTION_ID
    return [inst] if inst else []


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalize a DB datetime to aware-UTC (SQLite returns naive UTC)."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _age_seconds(value: Optional[datetime]) -> Optional[float]:
    """Age of a DB timestamp in seconds, from the process clock. The engine
    and the PostgreSQL container share the host clock (Docker Desktop), so
    the skew is negligible; a future date is clamped to 0."""
    utc_value = _as_utc(value)
    if utc_value is None:
        return None
    age = (datetime.now(timezone.utc) - utc_value).total_seconds()
    return max(age, 0.0)


def _sample_db_gauges() -> bool:
    """Sample the DB-sourced golden gauges for every trusted institution.

    Returns True when at least one institution's reads succeeded. Each query
    is tenant-context scoped (RLS-safe); a failure marks burhan_metrics_db_up
    = 0 so a frozen-gauge situation is itself observable.
    """
    from app.db.session import apply_tenant_context, get_session_factory

    any_ok = False
    for institution_id in _trusted_institutions():
        factory = get_session_factory()
        session = factory()
        try:
            apply_tenant_context(session, institution_id)

            # 1. Worker heartbeats (R08): freshest heartbeat per role.
            rows = session.execute(
                text(
                    "SELECT role, MAX(heartbeat_at) AS latest "
                    "FROM worker_heartbeats GROUP BY role"
                )
            ).fetchall()
            for role, latest in rows:
                age = _age_seconds(latest)
                if age is not None:
                    WORKER_HEARTBEAT_AGE.labels(
                        institution=institution_id, role=str(role)
                    ).set(age)

            # 2. Oldest outbox event still in the delivery pipeline + counts.
            # Statuses are fixed module constants (no injection surface).
            oldest = session.execute(
                text(
                    "SELECT MIN(created_at) FROM outbox "
                    "WHERE status IN ('PENDING', 'PROCESSING')"
                )
            ).scalar()
            oldest_age = _age_seconds(oldest)
            if oldest_age is not None:
                OUTBOX_OLDEST_AGE.labels(institution=institution_id).set(oldest_age)
            else:
                OUTBOX_OLDEST_AGE.labels(institution=institution_id).set(0.0)
            status_rows = session.execute(
                text("SELECT status, COUNT(*) FROM outbox GROUP BY status")
            ).fetchall()
            for status_name, count in status_rows:
                OUTBOX_EVENTS.labels(
                    institution=institution_id, status=str(status_name)
                ).set(int(count))

            # 3. Confirmation depth (R08 chain_submissions).
            awaiting = 0
            submission_rows = session.execute(
                text("SELECT status, COUNT(*) FROM chain_submissions GROUP BY status")
            ).fetchall()
            for status_name, count in submission_rows:
                status_name = str(status_name)
                CHAIN_SUBMISSIONS.labels(
                    institution=institution_id, status=status_name
                ).set(int(count))
                if status_name in _AWAITING_STATUSES:
                    awaiting += int(count)
            CHAIN_SUBMISSIONS_AWAITING.labels(
                institution=institution_id
            ).set(awaiting)

            any_ok = True
        except Exception:
            # Metrics must never take the API down; db_up=0 exposes the outage.
            METRICS_DB_UP.set(0.0)
            return False
        finally:
            session.close()
    METRICS_DB_UP.set(1.0 if any_ok else 0.0)
    return any_ok


def _probe_rpc() -> None:
    """Scrape-time eth_blockNumber probe — a REAL current RPC observation
    (like a blackbox check), driving burhan_rpc_probe_success/latency and the
    burhan_rpc_errors_total{op="probe"} counter."""
    import httpx

    started = time.monotonic()
    try:
        with httpx.Client(timeout=_RPC_PROBE_TIMEOUT_SECONDS) as client:
            resp = client.post(
                settings.BLOCKCHAIN_RPC_URL,
                json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            block_hex = resp.json()["result"]
        EVM_BLOCK_NUMBER.set(int(str(block_hex), 16))
        RPC_PROBE_LATENCY.set(time.monotonic() - started)
        RPC_PROBE_SUCCESS.set(1.0)
    except Exception:
        RPC_PROBE_LATENCY.set(time.monotonic() - started)
        RPC_PROBE_SUCCESS.set(0.0)
        RPC_ERRORS_TOTAL.labels(op="probe").inc()


@router.get(
    "/internal/metrics",
    summary="Internal Prometheus metrics (no PII; compose-internal only)",
    tags=["Internal"],
)
def internal_metrics() -> Response:
    """Prometheus text exposition. DB gauges are sampled at scrape time from
    the R08 sources of truth; the EVM RPC is probed live per scrape."""
    _sample_db_gauges()
    _probe_rpc()
    return Response(content=render_metrics(), media_type=CONTENT_TYPE_LATEST)
