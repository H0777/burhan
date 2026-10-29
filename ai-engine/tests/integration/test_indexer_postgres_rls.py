"""
PostgreSQL RLS regression test for the indexer worker write path (H04).

DISCOVERED ON STAGING (H04): run_indexer_step / record_heartbeat wrote
checkpoints, chain_events and worker_heartbeats WITHOUT any tenant context.
On SQLite (dev/demo) there is no server-side RLS, so the logic suite was green;
on real PostgreSQL the app role is subject to FORCE ROW LEVEL SECURITY and
every write failed with "new row violates row-level security policy"
(checkpoints) — observed live in the staging stack. PostgreSQL behavior is the
reference (brief H04): the worker now re-applies the transaction-local tenant
context (apply_tenant_context) at the start of each transaction segment.

These are PostgreSQL-INTEGRATION tests with the same environment contract as
test_postgres_rls.py (R11):
  - DATABASE_URL            -> least-privilege APP role (ira_aml_app).
  - MIGRATION_DATABASE_URL  -> separate migration OWNER role (ira_aml_migrator).
Without them the module SKIPS. The app-role sessions below are NEVER given a
tenant context by the test itself — the WORKER must establish it; that is the
regression being pinned.
"""

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker

from app.db.models import ChainEventRecord, CheckpointRecord, Institution, WorkerHeartbeat
from app.db.session import tenant_transaction
from app.services.chain_registry import ChainRegistry
from app.services.blockchain_listener import BlockchainListener
from app.workers.indexer import BlockchainIndexerWorker

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT = "inst_idx_cbi"
CONTRACT = "0x" + "ab" * 20
CHAIN_ID = 31337
EXPECTED_CHECKPOINT_BLOCK = 8  # head 10 - confirmation depth 2


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "H04 indexer PostgreSQL RLS tests require DATABASE_URL (app role) and "
            f"MIGRATION_DATABASE_URL (migration owner) pointing at a disposable "
            "PostgreSQL test database"
        )
    return app_url, migration_url


def _run_python(args, env_overrides=None, cwd=AI_ENGINE_DIR, timeout=300):
    cmd = ["node", str(REPO_ROOT / "scripts" / "run-python.js"), *args]
    return subprocess.run(
        cmd, cwd=str(cwd), env={**os.environ, **(env_overrides or {})},
        capture_output=True, text=True, timeout=timeout,
    )


class _StubListener(BlockchainListener):
    """Deterministic RPC stub: head at block 10, one ForensicTrail-like log at 5."""

    def __init__(self):
        super().__init__(rpc_url="http://stub:8545")
        self.blocks = {
            i: {"hash": f"0xblock_{i:04d}", "number": i} for i in range(0, 21)
        }
        self.log = {
            "blockNumber": hex(5),
            "blockHash": "0xblock_0005",
            "transactionHash": "0x" + "cd" * 32,
            "logIndex": "0x0",
            "topics": ["0x" + "ef" * 32],
            "data": "0x1234",
            "removed": False,
        }

    def get_block_number(self):
        return 10

    def get_block_by_number(self, block_number):
        n = int(block_number, 16) if isinstance(block_number, str) and block_number.startswith("0x") else int(block_number)
        return self.blocks.get(n)

    def get_contract_logs(self, contract_address=None, from_block="0x0", to_block="latest", topics=None):
        f = int(from_block, 16) if from_block.startswith("0x") else int(from_block)
        t = 10**9 if to_block == "latest" else (int(to_block, 16) if to_block.startswith("0x") else int(to_block))
        return [self.log] if f <= 5 <= t else []


def _worker() -> BlockchainIndexerWorker:
    return BlockchainIndexerWorker(
        listener=_StubListener(),
        registry=ChainRegistry(manifest_data={"chain_id": CHAIN_ID}),
    )


@pytest.fixture(scope="module")
def pg_urls():
    return _require_pg_urls()


@pytest.fixture(scope="module")
def app_session_factory(pg_urls):
    engine = create_engine(pg_urls[0], pool_pre_ping=True)
    yield sessionmaker(bind=engine)
    engine.dispose()


@pytest.fixture(scope="module")
def owner_engine(pg_urls):
    engine = create_engine(pg_urls[1], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def seeded_tenant(owner_engine):
    """Alembic head + the tenant registry row the worker FKs depend on.

    Operational seeding runs as the migration owner; institutions is
    RLS-ENABLED but not FORCEd, so its owner may insert the registry row
    directly (the same convention as test_postgres_rls.py)."""
    result = _run_python(["-m", "alembic", "upgrade", "head"])
    assert result.returncode == 0, (
        f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}"
    )
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        if session.get(Institution, TENANT) is None:
            session.add(Institution(id=TENANT, name="Indexer RLS Regression Tenant"))
            session.commit()
        # The test database persists across suite runs (same convention as
        # test_postgres_rls.py): clear this tenant's indexer rows so each run
        # starts from a clean slate. FORCEd RLS applies to the owner too, so
        # the delete goes through the tenant context.
        from app.db.session import tenant_transaction as _tt
        from sqlalchemy import delete as _delete
        with _tt(session, TENANT):
            for model in (ChainEventRecord, CheckpointRecord, WorkerHeartbeat):
                session.execute(_delete(model).where(model.institution_id == TENANT))
    yield


def test_indexer_writes_pass_force_rls_as_app_role(app_session_factory, seeded_tenant):
    """THE regression: the full runner call sequence (run_indexer_step, then
    record_heartbeat, then commit) as the least-privilege app role with NO
    test-side tenant context. Before the H04 fix this raised
    ProgrammingError: new row violates row-level security policy (checkpoints).

    After the step: rows must exist (visible through the tenant context),
    a context-less pooled connection must still read nothing, and an idempotent
    re-run must ingest zero duplicate events."""
    worker = _worker()
    with app_session_factory() as session:
        result = worker.run_indexer_step(
            session=session,
            institution_id=TENANT,
            chain_id=CHAIN_ID,
            contract_address=CONTRACT,
        )
        assert result.events_ingested == 1
        assert result.checkpoint_block == EXPECTED_CHECKPOINT_BLOCK
        assert result.reorg_detected is False

        worker.record_heartbeat(
            session=session, institution_id=TENANT,
            worker_id="indexer_regression",
            clock=lambda: datetime.now(timezone.utc),
        )
        session.commit()

    # Rows exist and are visible through the tenant context (app role).
    with app_session_factory() as session:
        with tenant_transaction(session, TENANT):
            events = session.execute(
                select(ChainEventRecord).where(ChainEventRecord.institution_id == TENANT)
            ).scalars().all()
            assert len(events) == 1 and events[0].status == "CONFIRMED"
            cps = session.execute(
                select(CheckpointRecord).where(CheckpointRecord.institution_id == TENANT)
            ).scalars().all()
            assert len(cps) == 1
            assert cps[0].last_canonical_block_number == EXPECTED_CHECKPOINT_BLOCK
            hbs = session.execute(
                select(WorkerHeartbeat).where(WorkerHeartbeat.institution_id == TENANT)
            ).scalars().all()
            assert len(hbs) == 1 and hbs[0].worker_id == "indexer_regression"

    # Isolation: a context-less app-role connection reads nothing.
    with app_session_factory() as session:
        assert session.execute(
            text("SELECT current_setting('app.current_institution_id', true)")
        ).scalar() in (None, "")
        assert session.execute(
            select(func.count()).select_from(CheckpointRecord)
        ).scalar_one() == 0

    # Idempotent re-run (fresh session, worker-established context):
    # safe_head <= checkpoint -> early return, zero duplicate events (R08).
    with app_session_factory() as session:
        second = worker.run_indexer_step(
            session=session, institution_id=TENANT,
            chain_id=CHAIN_ID, contract_address=CONTRACT,
        )
        session.commit()
        assert second.events_ingested == 0
        assert second.from_block == second.to_block == EXPECTED_CHECKPOINT_BLOCK
