"""
R08 outbox claim/lease integration tests — REAL PostgreSQL only.

The brief is explicit: SQLite/mock cannot close FOR UPDATE SKIP LOCKED or
nonce concurrency, so every test here runs against a disposable PostgreSQL
(r08-pg-test) migrated with alembic to head, mirroring the R11/R12
environment contract:

  DATABASE_URL            -> least-privilege APP role (ira_aml_app), NOSUPERUSER NOBYPASSRLS.
  MIGRATION_DATABASE_URL  -> migration OWNER role (ira_aml_migrator).

Without both variables the module SKIPS (never reports false success).

Spec §7 bindings under test (first four RED cases):
  - no_rpc_never_anchors: a worker without a chain sender cannot exist (no
    optional RPC in the institutional constructor) and a dead RPC adapter
    must leave the outbox item un-anchored with NO fabricated tx/entry hash.
  - two_workers_claim_disjoint: claim_batch uses FOR UPDATE SKIP LOCKED so
    two concurrent workers partition the batch with no overlap and no loss.
  - expired_lease_reclaimed: a lease past lease_expires_at (60s) is taken
    over by another worker via claim, not by direct completion.
  - wrong_owner_cannot_complete: outbox completion is an owner-token
    conditional update — a stale/foreign token must fail without mutating
    the row.
"""

import json
import os
import subprocess
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.db.models import EvidenceAnchor, Institution, Outbox
from app.db.session import tenant_transaction

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R08 outbox claim tests require DATABASE_URL (app role) and "
            "MIGRATION_DATABASE_URL (migration owner) pointing at a disposable "
            "PostgreSQL test database (r08-pg-test)"
        )
    return app_url, migration_url


@pytest.fixture(scope="module")
def pg_urls():
    return _require_pg_urls()


@pytest.fixture(scope="module")
def owner_engine(pg_urls):
    engine = create_engine(pg_urls[1], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def app_engine(pg_urls):
    engine = create_engine(pg_urls[0], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def migrated_db(pg_urls):
    result = subprocess.run(
        ["node", str(REPO_ROOT / "scripts" / "run-python.js"), "-m", "alembic", "upgrade", "head"],
        cwd=str(AI_ENGINE_DIR),
        env={**os.environ, "MIGRATION_DATABASE_URL": pg_urls[1]},
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(
            "alembic upgrade head failed against the R08 test database "
            f"(exit {result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    with create_engine(pg_urls[1]).connect() as conn:
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    return head


class FakeClock:
    """Injected clock — lease/backoff timing without real sleeps (spec §7)."""

    def __init__(self, start: datetime | None = None):
        self.now = start or datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture()
def tenant(migrated_db, owner_engine):
    """Fresh tenant (institution) with its own outbox rows per test."""
    tenant_id = f"inst_r08_{uuid.uuid4().hex[:10]}"
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        session.add(Institution(id=tenant_id, name=f"R08 test {tenant_id}"))
        session.commit()
    return tenant_id


def seed_outbox(owner_engine, tenant_id: str, n: int) -> list[str]:
    OwnerSession = sessionmaker(bind=owner_engine)
    ids = []
    with OwnerSession() as session:
        with tenant_transaction(session, tenant_id):
            for i in range(n):
                oid = f"out_r08_{uuid.uuid4().hex[:14]}"
                ids.append(oid)
                session.add(
                    Outbox(
                        id=oid,
                        institution_id=tenant_id,
                        event_type="ANCHOR_EVIDENCE",
                        payload_json=json.dumps(
                            {
                                "institution_id": tenant_id,
                                "case_id": "case_r08_001",
                                "evidence_id": f"ev_{i}",
                                "anchor_request_id": "0x" + f"{i:064x}",
                                "chain_id": 31337,
                                "contract_address": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
                                "file_sha256": "0x" + "ab" * 32,
                                "manifest_hash": "0x" + "cd" * 32,
                            }
                        ),
                        status="PENDING",
                        attempts=0,
                    )
                )
        # rows committed by tenant_transaction
    return ids


def fetch_outbox(owner_engine, tenant_id: str, outbox_id: str) -> Outbox:
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        row = session.execute(
            text("SELECT status, attempts, lease_owner, lease_token, lease_expires_at, last_error "
                 "FROM outbox WHERE id = :i"),
            {"i": outbox_id},
        ).first()
    return row


# ---------------------------------------------------------------------------
# RED test 1: two_workers_claim_disjoint
# ---------------------------------------------------------------------------

def test_two_workers_claim_disjoint(pg_urls, tenant, app_engine):
    from app.repositories import outbox_repository

    ids = seed_outbox(app_engine, tenant, 4)
    clock = FakeClock()

    AppSession = sessionmaker(bind=app_engine)
    results: dict[str, list] = {"w1": [], "w2": []}
    barrier = threading.Barrier(3)

    def claim(worker: str):
        session = AppSession()
        try:
            with tenant_transaction(session, tenant):
                barrier.wait(timeout=30)
                results[worker] = outbox_repository.claim_batch(
                    session=session,
                    institution_id=tenant,
                    worker_id=worker,
                    now=clock(),
                    limit=2,
                )
        finally:
            session.close()

    t1 = threading.Thread(target=claim, args=("worker_r08_a",))
    t2 = threading.Thread(target=claim, args=("worker_r08_b",))
    t1.start()
    t2.start()
    barrier.wait(timeout=30)
    t1.join(timeout=30)
    t2.join(timeout=30)

    claimed_ids = sorted(o.id for o in results["w1"] + results["w2"])
    assert claimed_ids == sorted(ids), (
        f"SKIP LOCKED claim must partition all rows once: got {claimed_ids}"
    )
    a = {o.id for o in results["w1"]}
    b = {o.id for o in results["w2"]}
    assert a.isdisjoint(b), f"workers claimed the same rows: {a & b}"

    for o in results["w1"]:
        assert o.status == "PROCESSING"
        assert o.lease_owner == "worker_r08_a"
        assert o.lease_token
        assert o.lease_expires_at == clock() + timedelta(seconds=60)


# ---------------------------------------------------------------------------
# RED test 2: expired_lease_reclaimed
# ---------------------------------------------------------------------------

def test_expired_lease_reclaimed(pg_urls, tenant, app_engine):
    from app.repositories import outbox_repository

    ids = seed_outbox(app_engine, tenant, 1)
    clock = FakeClock()
    AppSession = sessionmaker(bind=app_engine)

    s1 = AppSession()
    with tenant_transaction(s1, tenant):
        claimed = outbox_repository.claim_batch(
            session=s1, institution_id=tenant, worker_id="worker_r08_a", now=clock(), limit=5,
        )
    s1.close()
    assert [o.id for o in claimed] == ids
    old_token = claimed[0].lease_token

    # Lease still fresh: another worker claims nothing.
    s2 = AppSession()
    with tenant_transaction(s2, tenant):
        still_locked = outbox_repository.claim_batch(
            session=s2, institution_id=tenant, worker_id="worker_r08_b", now=clock(), limit=5,
        )
    s2.close()
    assert still_locked == []

    # Advance past the 60s lease WITHOUT sleeping: reclaim by worker B.
    clock.advance(61)
    s3 = AppSession()
    with tenant_transaction(s3, tenant):
        reclaimed = outbox_repository.claim_batch(
            session=s3, institution_id=tenant, worker_id="worker_r08_b", now=clock(), limit=5,
        )
    s3.close()

    assert [o.id for o in reclaimed] == ids
    assert reclaimed[0].lease_owner == "worker_r08_b"
    assert reclaimed[0].lease_token != old_token, "reclaim must issue a fresh owner token"


# ---------------------------------------------------------------------------
# RED test 3: wrong_owner_cannot_complete
# ---------------------------------------------------------------------------

def test_wrong_owner_cannot_complete(pg_urls, tenant, app_engine):
    from app.repositories import outbox_repository

    ids = seed_outbox(app_engine, tenant, 1)
    clock = FakeClock()
    AppSession = sessionmaker(bind=app_engine)

    s1 = AppSession()
    with tenant_transaction(s1, tenant):
        claimed = outbox_repository.claim_batch(
            session=s1, institution_id=tenant, worker_id="worker_r08_a", now=clock(), limit=5,
        )
    s1.close()
    token = claimed[0].lease_token

    # Foreign/stale token must NOT complete the row.
    s2 = AppSession()
    with tenant_transaction(s2, tenant):
        ok = outbox_repository.complete_claimed(
            session=s2, outbox_id=ids[0], lease_token="not-the-owner-token", now=clock(),
        )
    s2.close()
    assert ok is False

    row = fetch_outbox(app_engine, tenant, ids[0])
    assert row.status == "PROCESSING", f"foreign token mutated status to {row.status}"

    # Correct token completes.
    s3 = AppSession()
    with tenant_transaction(s3, tenant):
        ok = outbox_repository.complete_claimed(
            session=s3, outbox_id=ids[0], lease_token=token, now=clock(),
        )
    s3.close()
    assert ok is True
    row = fetch_outbox(app_engine, tenant, ids[0])
    assert row.status == "COMPLETED"


# ---------------------------------------------------------------------------
# RED test 4: no_rpc_never_anchors
# ---------------------------------------------------------------------------

def test_no_rpc_never_anchors(pg_urls, tenant, app_engine):
    from app.workers.evidence_anchor import EvidenceAnchorWorker

    # No optional RPC in the institutional constructor: a worker without a
    # chain sender must refuse to exist rather than silently mock anchoring.
    with pytest.raises((TypeError, ValueError)):
        EvidenceAnchorWorker()

    # And a worker whose RPC adapter is dead must FAIL the item honestly —
    # never fabricate tx_hash/entry_hash/block data out of wait time.
    class DeadAdapter:
        RPC_URL = "http://127.0.0.1:1/"

        def eth_chain_id(self):
            raise ConnectionError("RPC connection refused (test)")

    ids = seed_outbox(app_engine, tenant, 1)
    clock = FakeClock()
    worker = EvidenceAnchorWorker(chain_sender=None, rpc_adapter=DeadAdapter())
    stats = worker.process_cycle(
        session_factory=lambda: _scoped_session(app_engine, tenant),
        institution_id=tenant,
        clock=clock,
    )

    row = fetch_outbox(app_engine, tenant, ids[0])
    assert row.status == "FAILED", f"dead RPC must leave FAILED, got {row.status}"
    assert row.last_error, "failure reason must be recorded"
    # next retry only after the first backoff (5s), driven by the injected clock
    AppSession = sessionmaker(bind=app_engine)
    with AppSession() as session:
        with tenant_transaction(session, tenant):
            ob = session.get(Outbox, ids[0])
            assert ob.next_attempt_at == clock() + timedelta(seconds=5)

    # Nothing anchored, nothing fabricated:
    with AppSession() as session:
        with tenant_transaction(session, tenant):
            anchors = session.execute(
                select(EvidenceAnchor).where(EvidenceAnchor.institution_id == tenant)
            ).scalars().all()
            for a in anchors:
                assert a.status != "ANCHORED"
                assert a.transaction_hash is None
                assert a.entry_hash is None
            subs = session.execute(text("SELECT COUNT(*) FROM chain_submissions")).scalar_one()
            assert subs == 0, "dead RPC must not persist phantom submissions"
    assert stats["anchored"] == 0


class _ScopedSession:
    """Minimal session factory wrapper: yields a session bound to a tenant tx."""

    def __init__(self, session):
        self._session = session

    def __call__(self):
        return self._session


def _scoped_session(app_engine, tenant):
    AppSession = sessionmaker(bind=app_engine)
    return AppSession()
