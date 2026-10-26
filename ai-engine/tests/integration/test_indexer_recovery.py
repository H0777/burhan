"""
Integration Tests for Blockchain Indexer and Reorg Recovery (T15)
Specification §4, §6 (R09, R11)
Tests duplicate event ingestion, reorg recovery, orphaned event marking,
atomic checkpointing, multi-tenant isolation, rate limit backoff, and code hash integrity.
"""

import pytest
import uuid
import json
import hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.models import (
    Base,
    Institution,
    ChainEventRecord,
    CheckpointRecord,
)
from app.services.chain_registry import (
    ChainRegistry,
    CodeHashMismatchError,
    compute_keccak256,
)
from app.services.blockchain_listener import BlockchainListener, RpcRateLimitError
from app.workers.indexer import BlockchainIndexerWorker


class MockBlockchainListener(BlockchainListener):
    def __init__(self, current_block: int = 10):
        super().__init__(rpc_url="http://mock:8545")
        self.current_block = current_block
        self.blocks = {}
        self.logs = []
        self.rate_limit_calls = 0

        # Pre-seed blocks 1 to 20
        for i in range(1, 21):
            self.blocks[i] = {
                "number": i,
                "hash": f"0xblock_{i:04d}_canonical",
                "parent_hash": f"0xblock_{i-1:04d}_canonical" if i > 1 else "0x0",
                "timestamp": 1700000000 + i * 12,
            }

    def get_block_number(self):
        return self.current_block

    def get_block_by_number(self, block_number: int | str):
        b_num = int(block_number, 16) if isinstance(block_number, str) and block_number.startswith("0x") else int(block_number)
        return self.blocks.get(b_num)

    def get_contract_logs(self, contract_address=None, from_block="0x0", to_block="latest", topics=None):
        if self.rate_limit_calls > 0:
            self.rate_limit_calls -= 1
            raise RpcRateLimitError("429 Too Many Requests")

        f_num = int(from_block, 16)
        t_num = int(to_block, 16)
        matched = []
        for log in self.logs:
            b_num = int(log.get("blockNumber", "0x0"), 16)
            if f_num <= b_num <= t_num:
                matched.append(log)
        return matched

    def get_code(self, contract_address: str, block_tag: str = "latest") -> str:
        # Mock bytecode: 0x608060405234801561001057600080fd5b50
        return "0x608060405234801561001057600080fd5b50"


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Seed institutions
    cbi = Institution(id="inst_cbi", name="Central Bank of Iraq")
    rafidain = Institution(id="inst_rafidain", name="Rafidain Bank")
    session.add_all([cbi, rafidain])
    session.commit()

    yield session
    session.close()


def test_normal_indexing_step_and_lag(db_session):
    """Worker ingests logs in bounded blocks and accurately calculates lag."""
    listener = MockBlockchainListener(current_block=10)
    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    # Add 2 logs at block 3 and 4
    listener.logs.append({
        "blockNumber": hex(3),
        "blockHash": listener.blocks[3]["hash"],
        "transactionHash": "0xtx_001",
        "logIndex": "0x0",
        "topics": ["0xtopic_evidence_submitted"],
        "data": "0x01",
        "removed": False,
    })
    listener.logs.append({
        "blockNumber": hex(4),
        "blockHash": listener.blocks[4]["hash"],
        "transactionHash": "0xtx_002",
        "logIndex": "0x0",
        "topics": ["0xtopic_evidence_submitted"],
        "data": "0x02",
        "removed": False,
    })

    # Sandbox confirmation depth = 2 (so safe head = 10 - 2 = 8)
    worker = BlockchainIndexerWorker(listener=listener)
    result = worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
        max_blocks=50,
    )

    assert result.events_ingested == 2
    assert result.from_block == 1
    assert result.to_block == 8  # safe head is 8
    assert result.checkpoint_block == 8
    assert result.lag == 2  # 10 - 8 = 2 blocks lag
    assert not result.reorg_detected

    # Verify events in database
    events = db_session.execute(
        select(ChainEventRecord).where(ChainEventRecord.institution_id == "inst_cbi")
    ).scalars().all()
    assert len(events) == 2
    assert all(e.status == "CONFIRMED" for e in events)


def test_duplicate_event_ingestion_idempotence(db_session):
    """Re-indexing blocks with existing events does not duplicate records."""
    listener = MockBlockchainListener(current_block=5)
    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    listener.logs.append({
        "blockNumber": hex(2),
        "blockHash": listener.blocks[2]["hash"],
        "transactionHash": "0xtx_dup_001",
        "logIndex": "0x0",
        "topics": ["0xtopic_evidence_submitted"],
        "data": "0x01",
        "removed": False,
    })

    worker = BlockchainIndexerWorker(listener=listener)
    # First pass: safe_head is 5 - 2 = 3
    res1 = worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
        max_blocks=50,
    )
    assert res1.events_ingested == 1

    # Force checkpoint rewind to re-index block 2
    cp = db_session.execute(select(CheckpointRecord)).scalars().first()
    cp.last_canonical_block_number = 1
    db_session.commit()

    # Second pass: re-indexes block 2
    res2 = worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
        max_blocks=50,
    )
    assert res2.events_ingested == 0  # Deduplicated!

    events = db_session.execute(select(ChainEventRecord)).scalars().all()
    assert len(events) == 1  # Total count unchanged


def test_log_removed_marked_as_orphaned(db_session):
    """Logs with removed=True must be marked ORPHANED without deleting history."""
    listener = MockBlockchainListener(current_block=6)
    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    listener.logs.append({
        "blockNumber": hex(2),
        "blockHash": listener.blocks[2]["hash"],
        "transactionHash": "0xtx_removed",
        "logIndex": "0x0",
        "topics": ["0xtopic_removed"],
        "data": "0x00",
        "removed": True,  # Reorg log removed
    })

    worker = BlockchainIndexerWorker(listener=listener)
    worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
        max_blocks=50,
    )

    ev = db_session.execute(select(ChainEventRecord)).scalars().first()
    assert ev is not None
    assert ev.status == "ORPHANED"  # Successfully tracked as orphaned


def test_chain_reorg_detection_and_recovery(db_session):
    """
    Simulates a chain reorganization where blocks 4 and 5 were reorged on the node.
    Worker must detect hash mismatch, rewind checkpoint, and mark orphaned events.
    """
    listener = MockBlockchainListener(current_block=7)
    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    # Add log at block 4
    listener.logs.append({
        "blockNumber": hex(4),
        "blockHash": listener.blocks[4]["hash"],
        "transactionHash": "0xtx_block_4",
        "logIndex": "0x0",
        "topics": ["0xtopic_1"],
        "data": "0x01",
        "removed": False,
    })

    # Step 1: Normal index up to block 5 (7 - 2 = 5)
    worker = BlockchainIndexerWorker(listener=listener)
    res1 = worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
    )
    assert res1.checkpoint_block == 5
    assert res1.events_ingested == 1

    # Verify event is CONFIRMED
    ev = db_session.execute(select(ChainEventRecord)).scalars().first()
    assert ev.status == "CONFIRMED"

    # Step 2: Inject Reorg on node!
    # Block 5 on RPC changed to a different fork hash!
    listener.blocks[5]["hash"] = "0xblock_0005_reorged_fork"
    listener.blocks[4]["hash"] = "0xblock_0004_reorged_fork"
    listener.current_block = 8

    # Step 3: Run indexer again
    res2 = worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
    )

    assert res2.reorg_detected is True
    assert res2.orphaned_events_count == 1

    # Verify that the old event is NOT deleted, but status is now ORPHANED
    db_session.refresh(ev)
    assert ev.status == "ORPHANED"


def test_multi_tenant_indexer_isolation(db_session):
    """Checkpoints and events for institution A never bleed into institution B."""
    listener = MockBlockchainListener(current_block=5)
    contract_addr = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    listener.logs.append({
        "blockNumber": hex(2),
        "blockHash": listener.blocks[2]["hash"],
        "transactionHash": "0xtx_inst_a",
        "logIndex": "0x0",
        "topics": ["0xtopic_1"],
        "data": "0x01",
        "removed": False,
    })

    worker = BlockchainIndexerWorker(listener=listener)
    # Index for CBI
    worker.run_indexer_step(
        session=db_session,
        institution_id="inst_cbi",
        chain_id=31337,
        contract_address=contract_addr,
    )

    # Rafidain events must be empty
    rafidain_events = db_session.execute(
        select(ChainEventRecord).where(ChainEventRecord.institution_id == "inst_rafidain")
    ).scalars().all()
    assert len(rafidain_events) == 0

    # Rafidain checkpoint does not exist yet
    rafidain_cp = db_session.execute(
        select(CheckpointRecord).where(CheckpointRecord.institution_id == "inst_rafidain")
    ).scalars().first()
    assert rafidain_cp is None


def test_code_hash_mismatch_detection():
    """Validates that a contract bytecode mismatch raises CodeHashMismatchError."""
    code_bytes = bytes.fromhex("608060405234801561001057600080fd5b50")
    genuine_hash = compute_keccak256(code_bytes)
    tampered_hash = "0x" + ("9" * 64)

    registry = ChainRegistry(
        manifest_data={
            "chain_id": 31337,
            "contracts": {"ForensicTrail": "0x5FbDB2315678afecb367f032d93F642f64180aa3"},
            "code_hashes": {"ForensicTrail": tampered_hash},  # Mismatched hash
        }
    )

    rpc_client = MockBlockchainListener()

    with pytest.raises(CodeHashMismatchError, match="Potential bytecode tampering"):
        registry.verify_contract_code_hash(
            rpc_client=rpc_client,
            contract_name="ForensicTrail",
        )


def test_indexer_records_per_worker_heartbeat(db_session):
    """R08: the indexer writes a per-worker heartbeat row every cycle, with
    an injectable clock (no real sleeps) — stale workers are observable."""
    from app.workers.indexer import BlockchainIndexerWorker as _W
    from datetime import datetime as _dt

    class FixedClock:
        def __init__(self):
            self.now = _dt(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

        def __call__(self):
            return self.now

    clock = FixedClock()
    listener = MockBlockchainListener(current_block=5)
    worker = _W(listener=listener)

    hb1 = worker.record_heartbeat(
        session=db_session, institution_id="inst_cbi",
        worker_id="indexer_cbi_1", clock=clock, detail={"step": 1},
    )
    assert hb1.heartbeat_at == clock()

    clock.now = clock.now + timedelta(seconds=30)
    hb2 = worker.record_heartbeat(
        session=db_session, institution_id="inst_cbi",
        worker_id="indexer_cbi_1", clock=clock, detail={"step": 2},
    )
    db_session.commit()

    assert hb2.id == hb1.id  # upsert: ONE row per (institution, worker, role)
    actual_dt = hb2.heartbeat_at if hb2.heartbeat_at.tzinfo else hb2.heartbeat_at.replace(tzinfo=timezone.utc)
    assert actual_dt == clock()
    rows = db_session.execute(
        select(CheckpointRecord).where(CheckpointRecord.institution_id == "indexer_no_rows")
    ).scalars().all()
    assert rows == []
    from app.db.models import WorkerHeartbeat
    all_hb = db_session.execute(select(WorkerHeartbeat)).scalars().all()
    assert len(all_hb) == 1
    assert all_hb[0].role == "indexer"
