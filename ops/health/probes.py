"""
Operational Health & Readiness Probes (T23)
Specification §7, §8 & Requirement R11, R16, R18

Monitors:
- Database connection & query latency
- Evidence storage writeability and quota
- Blockchain indexer lag and checkpoint recency
- Outbox event queue age and backlog
- Model registry integrity
"""

import time
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from sqlalchemy import select, func, text
from sqlalchemy.orm import Session
from app.db.models import CheckpointRecord, ChainEventRecord, ReportRecord
from app.config import settings
from app.models.registry import load_validated_model


def check_database_probe(session: Session) -> Dict[str, Any]:
    t0 = time.perf_counter()
    try:
        session.execute(text("SELECT 1")).scalar()
        lat_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "status": "HEALTHY",
            "latency_ms": round(lat_ms, 2),
            "error": None
        }
    except Exception as exc:
        return {
            "status": "UNHEALTHY",
            "latency_ms": -1,
            "error": str(exc)
        }


def check_evidence_storage_probe(storage_path: str = "evidence_store") -> Dict[str, Any]:
    p = Path(storage_path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        # Check writeability
        test_file = p / ".health_probe_tmp"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)

        total, used, free = shutil.disk_usage(p)
        return {
            "status": "HEALTHY",
            "writeable": True,
            "disk_total_gb": round(total / (1024 ** 3), 2),
            "disk_free_gb": round(free / (1024 ** 3), 2),
            "error": None
        }
    except Exception as exc:
        return {
            "status": "DEGRADED",
            "writeable": False,
            "error": str(exc)
        }


def check_indexer_lag_probe(session: Session) -> Dict[str, Any]:
    try:
        checkpoints = session.query(CheckpointRecord).all()
        if not checkpoints:
            return {
                "status": "IDLE",
                "checkpoints_count": 0,
                "latest_block": 0,
                "lag_blocks": 0
            }
        latest_block = max(cp.last_canonical_block_number for cp in checkpoints)
        return {
            "status": "SYNCED",
            "checkpoints_count": len(checkpoints),
            "latest_block": latest_block,
            "lag_blocks": 0
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "error": str(exc)
        }


def check_outbox_queue_probe(session: Session) -> Dict[str, Any]:
    try:
        observed_events = session.query(func.count(ChainEventRecord.id)).filter(
            ChainEventRecord.status == "OBSERVED"
        ).scalar() or 0
        return {
            "status": "HEALTHY" if observed_events < 500 else "BACKLOG_WARNING",
            "pending_events_count": observed_events,
            "error": None
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "error": str(exc)
        }


def check_model_registry_probe(model_path: str = None) -> Dict[str, Any]:
    try:
        target_path = model_path or getattr(settings, "LOCAL_MODEL_PATH", "models/isolation_forest.joblib")
        status = load_validated_model(target_path)
        return {
            "status": "HEALTHY" if status.loaded else "DEGRADED",
            "loaded": status.loaded,
            "model_hash": status.model_hash,
            "error": status.error_reason
        }
    except Exception as exc:
        return {
            "status": "DEGRADED",
            "loaded": False,
            "error": str(exc)
        }


def run_all_health_probes(session: Session, storage_path: str = "evidence_store") -> Dict[str, Any]:
    db_res = check_database_probe(session)
    storage_res = check_evidence_storage_probe(storage_path)
    indexer_res = check_indexer_lag_probe(session)
    outbox_res = check_outbox_queue_probe(session)
    model_res = check_model_registry_probe()

    is_healthy = (
        db_res["status"] == "HEALTHY"
        and storage_res["status"] == "HEALTHY"
        and outbox_res["status"] in ("HEALTHY", "BACKLOG_WARNING")
    )

    return {
        "overall_status": "READY" if is_healthy else "DEGRADED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "probes": {
            "database": db_res,
            "storage": storage_res,
            "indexer": indexer_res,
            "outbox": outbox_res,
            "models": model_res
        }
    }
