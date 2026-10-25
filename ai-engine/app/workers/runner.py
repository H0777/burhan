"""
R08 worker runner — two independent operating processes (spec §7):

    python -m app.workers.runner anchor
    python -m app.workers.runner indexer

No HTTP dependency: each process claims its own work under the tenant
context of one institution per cycle.

  * Tenant list from a TRUSTED registry (WORKER_INSTITUTIONS env or the
    deployment manifest's institution list) — never a bare all-rows outbox
    query without tenant context.
  * Per-worker heartbeat every cycle (worker_heartbeats).
  * Graceful shutdown on SIGINT/SIGTERM: stop claiming, finish the current
    item, leave held leases recoverable (they expire; the next process
    reclaims) — process death is always a recoverable state.
  * Per-institution anchoring signer: ANCHOR_SIGNER_PRIVATE_KEY (single
    institution) or ANCHOR_SIGNER_PRIVATE_KEY__<INSTITUTION_ID> per
    institution (nonce allocation is tenant-scoped under RLS).

Interval sleeps only exist in this OS-facing loop — all timing semantics
(leases, backoffs, 300s) are clock-injected inside the workers.
"""

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Callable, List, Optional

from app.config import settings
from app.db.session import get_session_factory, set_engine
from sqlalchemy import create_engine

logger = logging.getLogger("worker_runner")

POLL_INTERVAL_SECONDS = float(os.environ.get("WORKER_POLL_INTERVAL_SECONDS", "5"))


def _clock() -> datetime:
    """System clock for the runner loop (workers accept an injected clock)."""
    return datetime.now(timezone.utc)


def trusted_institutions() -> List[str]:
    """Trusted institution list: explicit env registry first, then the
    deployment manifest. Never a raw SELECT over all tenants."""
    raw = os.environ.get("WORKER_INSTITUTIONS", "").strip()
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]
    from app.services.chain_registry import ChainRegistry

    registry = ChainRegistry()
    inst = registry.get_institution_id()
    return [inst] if inst else []


def _build_anchor_worker():
    from app.services.chain_sender import ChainSender, SignerCredentials
    from app.services.evm_rpc_client import JsonRpcSendAdapter
    from app.services.chain_registry import ChainRegistry
    from app.workers.evidence_anchor import EvidenceAnchorWorker

    registry = ChainRegistry()
    chain_id = registry.get_chain_id()
    contract = registry.get_contract_address("ForensicTrail")
    adapter = JsonRpcSendAdapter(
        rpc_url=os.environ.get("BLOCKCHAIN_RPC_URL", settings.BLOCKCHAIN_RPC_URL),
        contract_address=contract,
    )

    single_key = os.environ.get(SignerCredentials.ENV_KEY_VAR, "").strip()
    if single_key:
        worker = EvidenceAnchorWorker(
            chain_sender=ChainSender(
                adapter=adapter, credentials=SignerCredentials(single_key), clock=_clock,
            ),
            deployment_id=str(registry.manifest.get("deployment_id", "")),
        )
        return worker

    cache: dict = {}

    def factory(institution_id: str):
        if institution_id in cache:
            return cache[institution_id]
        env_name = (
            SignerCredentials.ENV_KEY_VAR + "__" + "".join(
                ch if ch.isalnum() else "_" for ch in institution_id
            )
        ).upper()
        key_hex = os.environ.get(env_name, "").strip()
        if not key_hex:
            raise RuntimeError(
                f"no anchoring signer provisioned for {institution_id} "
                f"(set {env_name} or {SignerCredentials.ENV_KEY_VAR})"
            )
        cache[institution_id] = ChainSender(
            adapter=adapter, credentials=SignerCredentials(key_hex), clock=_clock,
        )
        return cache[institution_id]

    worker = EvidenceAnchorWorker(
        chain_sender_factory=factory,
        deployment_id=str(registry.manifest.get("deployment_id", "")),
    )
    return worker


def _build_indexer_worker():
    from app.services.blockchain_listener import BlockchainListener
    from app.services.chain_registry import ChainRegistry
    from app.workers.indexer import BlockchainIndexerWorker

    registry = ChainRegistry()
    listener = BlockchainListener(
        rpc_url=os.environ.get("BLOCKCHAIN_RPC_URL", settings.BLOCKCHAIN_RPC_URL)
    )
    return BlockchainIndexerWorker(listener=listener, registry=registry), registry


def run_anchor(stop: "signal.EventHook" = None) -> int:  # pragma: no cover - OS loop
    set_engine(create_engine(settings.DATABASE_URL, pool_pre_ping=True))
    session_factory = get_session_factory()
    worker = _build_anchor_worker()
    institutions = trusted_institutions()
    logger.info("anchor worker %s starting for institutions=%s", worker.worker_id, institutions)

    while not (stop and stop.is_set()):
        for institution_id in institutions:
            if stop and stop.is_set():
                break
            try:
                stats = worker.process_cycle(
                    session_factory=session_factory,
                    institution_id=institution_id,
                    clock=_clock,
                )
                if stats["claimed"]:
                    logger.info("anchor cycle %s: %s", institution_id, stats)
            except Exception:
                logger.exception("anchor cycle failed for %s", institution_id)
        time.sleep(POLL_INTERVAL_SECONDS)
    logger.info("anchor worker %s stopped (leases left recoverable)", worker.worker_id)
    return 0


def run_indexer(stop: "signal.EventHook" = None) -> int:  # pragma: no cover - OS loop
    set_engine(create_engine(settings.DATABASE_URL, pool_pre_ping=True))
    session_factory = get_session_factory()
    (indexer, registry) = _build_indexer_worker()
    institutions = trusted_institutions()
    chain_id = registry.get_chain_id()
    contract = registry.get_contract_address("ForensicTrail") or ""
    logger.info("indexer worker starting for institutions=%s chain=%s", institutions, chain_id)

    while not (stop and stop.is_set()):
        for institution_id in institutions:
            if stop and stop.is_set():
                break
            session = session_factory()
            try:
                result = indexer.run_indexer_step(
                    session=session,
                    institution_id=institution_id,
                    chain_id=chain_id,
                    contract_address=contract,
                )
                indexer.record_heartbeat(
                    session=session, institution_id=institution_id,
                    worker_id=f"indexer_{institution_id}", clock=_clock,
                )
                session.commit()
                if result.events_ingested or result.reorg_detected:
                    logger.info("indexer step %s: %s", institution_id, result)
            except Exception:
                session.rollback()
                logger.exception("indexer step failed for %s", institution_id)
            finally:
                session.close()
        time.sleep(POLL_INTERVAL_SECONDS)
    logger.info("indexer worker stopped (checkpoint state is committed atomically)")
    return 0


class _StopHook:
    """Graceful-shutdown flag set by SIGINT/SIGTERM."""

    def __init__(self) -> None:
        self._flag = False

    def set(self) -> None:
        self._flag = True

    def is_set(self) -> bool:
        return self._flag


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(
        level=os.environ.get("WORKER_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(prog="python -m app.workers.runner")
    parser.add_argument("role", choices=["anchor", "indexer"])
    args = parser.parse_args(argv)

    stop = _StopHook()

    def _handle(signum, frame):  # noqa: ANN001
        logger.info("signal %s received: stopping after current item", signum)
        stop.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    if args.role == "anchor":
        return run_anchor(stop)
    return run_indexer(stop)


if __name__ == "__main__":
    sys.exit(main())
