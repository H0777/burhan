"""
Blockchain Event Indexer and Reorg Recovery Worker (T15, R08)
Specification §4, §6, §7 (R09, R11, R08)

Polls bounded block ranges, validates canonical consensus, detects chain reorgs,
marks orphaned events without data loss, and commits events and checkpoints
atomically in a single tenant transaction.

R08 additions:
  * record_heartbeat: per-worker heartbeat row each cycle (worker_heartbeats).
  * Reorg handling (unchanged semantics, now spec §7-named): checkpoint
    rollback to the last canonical block, affected projections/snapshots
    (chain_events rows) invalidated to ORPHANED — the original payload_json
    and every original file are NEVER deleted; unique constraints
    (uq_chain_event_inst_log) make re-ingestion after a rewind idempotent.
"""

import uuid
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.models import ChainEventRecord, CheckpointRecord, WorkerHeartbeat
from app.services.chain_registry import ChainRegistry
from app.services.blockchain_listener import BlockchainListener

logger = logging.getLogger("BlockchainIndexer")


@dataclass
class IndexerResult:
    institution_id: str
    chain_id: int
    contract_address: str
    from_block: int
    to_block: int
    events_ingested: int
    orphaned_events_count: int
    current_head: int
    checkpoint_block: int
    lag: int
    reorg_detected: bool


class BlockchainIndexerWorker:
    def __init__(
        self,
        listener: BlockchainListener,
        registry: Optional[ChainRegistry] = None,
    ):
        self.listener = listener
        self.registry = registry or ChainRegistry()

    def record_heartbeat(
        self,
        session: Session,
        institution_id: str,
        worker_id: str,
        clock: Optional[Any] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> WorkerHeartbeat:
        """Per-worker heartbeat (R08): one row per (institution, worker, role),
        refreshed every cycle. `clock` is injectable for tests."""
        now = clock() if callable(clock) else datetime.now(timezone.utc)
        hb = session.execute(
            select(WorkerHeartbeat).where(
                WorkerHeartbeat.institution_id == institution_id,
                WorkerHeartbeat.worker_id == worker_id,
                WorkerHeartbeat.role == "indexer",
            )
        ).scalars().first()
        payload = json.dumps(detail or {}, sort_keys=True)
        if hb is None:
            hb = WorkerHeartbeat(
                id=f"hb_{uuid.uuid4().hex[:16]}",
                institution_id=institution_id,
                worker_id=worker_id,
                role="indexer",
                heartbeat_at=now,
                detail_json=payload,
            )
            session.add(hb)
        else:
            hb.heartbeat_at = now
            hb.detail_json = payload
        session.flush()
        return hb

    def get_or_create_checkpoint(
        self,
        session: Session,
        institution_id: str,
        chain_id: int,
        contract_address: str,
        initial_block: int = 0,
        initial_hash: str = "0x" + ("0" * 64),
    ) -> CheckpointRecord:
        addr = contract_address.lower()
        stmt = select(CheckpointRecord).where(
            CheckpointRecord.institution_id == institution_id,
            CheckpointRecord.chain_id == chain_id,
            CheckpointRecord.contract_address == addr,
        )
        cp = session.execute(stmt).scalars().first()
        if not cp:
            cp = CheckpointRecord(
                id=f"cp_{uuid.uuid4().hex[:16]}",
                institution_id=institution_id,
                chain_id=chain_id,
                contract_address=addr,
                last_canonical_block_number=initial_block,
                last_canonical_block_hash=initial_hash,
            )
            session.add(cp)
            session.flush()
        return cp

    def detect_and_handle_reorg(
        self,
        session: Session,
        institution_id: str,
        chain_id: int,
        checkpoint: CheckpointRecord,
    ) -> tuple[bool, int]:
        """
        Verifies that checkpoint.last_canonical_block_hash matches current RPC chain.
        If a divergence is detected, steps backwards to find the canonical fork block,
        marks invalidated events as ORPHANED, and rewinds the checkpoint.
        Returns (reorg_detected, orphaned_count).
        """
        last_num = checkpoint.last_canonical_block_number
        last_hash = checkpoint.last_canonical_block_hash

        if last_num <= 0:
            return (False, 0)

        # Query block header from RPC
        on_chain_block = self.listener.get_block_by_number(last_num)
        if not on_chain_block:
            logger.warning(f"Could not retrieve block {last_num} from RPC to verify canonicality")
            return (False, 0)

        # If block hashes match, no reorg has occurred at checkpoint
        if on_chain_block["hash"].lower() == last_hash.lower():
            return (False, 0)

        logger.warning(
            f"REORG DETECTED: Checkpoint block {last_num} hash {last_hash} != on-chain hash {on_chain_block['hash']}"
        )

        # Retrieve recorded block hashes in DB to verify fork point integrity
        stmt_ev = select(ChainEventRecord.block_number, ChainEventRecord.block_hash).where(
            ChainEventRecord.institution_id == institution_id,
            ChainEventRecord.chain_id == chain_id,
            ChainEventRecord.status == "CONFIRMED",
        )
        recorded = dict(session.execute(stmt_ev).all())

        # Step backwards to find the true fork point where recorded block hashes match RPC
        fork_block = last_num - 1
        canonical_fork_hash = "0x" + ("0" * 64)

        while fork_block > 0:
            b = self.listener.get_block_by_number(fork_block)
            if b:
                # If this block had an event recorded, verify the hash matches!
                if fork_block in recorded:
                    if b["hash"].lower() == recorded[fork_block].lower():
                        canonical_fork_hash = b["hash"]
                        break
                else:
                    canonical_fork_hash = b["hash"]
                    break
            fork_block -= 1

        # Mark orphaned events for blocks > fork_block
        stmt = (
            select(ChainEventRecord)
            .where(
                ChainEventRecord.institution_id == institution_id,
                ChainEventRecord.chain_id == chain_id,
                ChainEventRecord.block_number > fork_block,
                ChainEventRecord.status == "CONFIRMED",
            )
        )
        orphaned_events = session.execute(stmt).scalars().all()
        for ev in orphaned_events:
            ev.status = "ORPHANED"

        # Rewind checkpoint
        checkpoint.last_canonical_block_number = fork_block
        checkpoint.last_canonical_block_hash = canonical_fork_hash
        checkpoint.updated_at = datetime.now(timezone.utc)
        session.flush()

        logger.info(f"Reorg handled: rewound to block {fork_block}. Marked {len(orphaned_events)} events as ORPHANED.")
        return (True, len(orphaned_events))

    def run_indexer_step(
        self,
        session: Session,
        institution_id: str,
        chain_id: int,
        contract_address: str,
        max_blocks: int = 50,
    ) -> IndexerResult:
        """
        Executes one atomic indexing step over bounded block range.
        Commits events and checkpoint together in a single transaction.
        """
        clean_addr = contract_address.lower()
        checkpoint = self.get_or_create_checkpoint(
            session=session,
            institution_id=institution_id,
            chain_id=chain_id,
            contract_address=clean_addr,
        )

        current_head = self.listener.get_block_number() or 0
        depth = self.registry.get_confirmation_depth(chain_id)
        safe_head = max(0, current_head - depth)

        # 1. Reorg check on existing checkpoint
        reorg_detected, orphaned_count = self.detect_and_handle_reorg(
            session=session,
            institution_id=institution_id,
            chain_id=chain_id,
            checkpoint=checkpoint,
        )

        last_processed = checkpoint.last_canonical_block_number
        if safe_head <= last_processed:
            # Already up to date with confirmed depth
            session.commit()
            return IndexerResult(
                institution_id=institution_id,
                chain_id=chain_id,
                contract_address=clean_addr,
                from_block=last_processed,
                to_block=last_processed,
                events_ingested=0,
                orphaned_events_count=orphaned_count,
                current_head=current_head,
                checkpoint_block=last_processed,
                lag=current_head - last_processed,
                reorg_detected=reorg_detected,
            )

        from_block = last_processed + 1
        to_block = min(from_block + max_blocks - 1, safe_head)

        # 2. Fetch logs for bounded range
        logs = self.listener.get_contract_logs(
            contract_address=clean_addr,
            from_block=hex(from_block),
            to_block=hex(to_block),
        )

        events_ingested = 0
        for log in logs:
            b_num = int(log.get("blockNumber", "0x0"), 16)
            b_hash = log.get("blockHash", "")
            tx_hash = log.get("transactionHash", "")
            log_idx = int(log.get("logIndex", "0x0"), 16)
            is_removed = bool(log.get("removed", False))

            topics = log.get("topics", [])
            event_sig = topics[0] if topics else "0x" + ("0" * 64)

            # Check if event already exists
            existing = session.execute(
                select(ChainEventRecord).where(
                    ChainEventRecord.institution_id == institution_id,
                    ChainEventRecord.chain_id == chain_id,
                    ChainEventRecord.block_hash == b_hash,
                    ChainEventRecord.transaction_hash == tx_hash,
                    ChainEventRecord.log_index == log_idx,
                )
            ).scalars().first()

            if existing:
                if is_removed and existing.status != "ORPHANED":
                    existing.status = "ORPHANED"
                continue

            event_status = "ORPHANED" if is_removed else "CONFIRMED"

            event_rec = ChainEventRecord(
                id=f"ce_{uuid.uuid4().hex[:16]}",
                institution_id=institution_id,
                chain_id=chain_id,
                block_number=b_num,
                block_hash=b_hash,
                transaction_hash=tx_hash,
                log_index=log_idx,
                event_signature=event_sig,
                event_name="EventLogged",
                status=event_status,
                payload_json=json.dumps(log),
            )
            session.add(event_rec)
            events_ingested += 1

        # 3. Update checkpoint to latest processed block header
        head_block_info = self.listener.get_block_by_number(to_block)
        latest_hash = head_block_info["hash"] if head_block_info else checkpoint.last_canonical_block_hash

        checkpoint.last_canonical_block_number = to_block
        checkpoint.last_canonical_block_hash = latest_hash
        checkpoint.updated_at = datetime.now(timezone.utc)

        # 4. Atomic commit of both events and checkpoint
        session.commit()

        return IndexerResult(
            institution_id=institution_id,
            chain_id=chain_id,
            contract_address=clean_addr,
            from_block=from_block,
            to_block=to_block,
            events_ingested=events_ingested,
            orphaned_events_count=orphaned_count,
            current_head=current_head,
            checkpoint_block=to_block,
            lag=current_head - to_block,
            reorg_detected=reorg_detected,
        )
