"""
R08 nonce-discipline integration tests — REAL PostgreSQL (r08-pg-test).

Named case: nonce_consumed_externally_pauses_signer. Plus the two
disciplines that make nonce allocation safe under concurrency:
advisory-lock serialization (two concurrent prepares allocate DISTINCT
nonces against the real database unique constraint) and the 300s stuck
semantics (alert once + pause new sends for the signer, reconciliation
continues, payload never changes, no automatic replacement).
"""

import threading

import pytest

from app.services.chain_sender import (
    NonceConsumedExternallyError,
    SenderBinding,
    SignerPausedError,
    SubmissionState,
)
from app.workers.evidence_anchor import EvidenceAnchorWorker

from chain_sim import PGHarness, FakeClock, SimulatedEvmAdapter, make_sender, require_pg_urls


@pytest.fixture(scope="module")
def harness():
    app_url, migration_url = require_pg_urls()
    h = PGHarness(app_url, migration_url)
    h.migrate()
    yield h
    h.close()


def test_nonce_consumed_externally_pauses_signer(harness):
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    sender, account = make_sender(adapter, clock)
    worker = EvidenceAnchorWorker(
        chain_sender=sender, worker_id="anchor_pause", deployment_id="0x" + "22" * 32,
    )

    # Someone else consumed the signer's nonce 0 outside this service.
    adapter.bump_nonce(sender.signer_address, 1)

    stats = worker.process_cycle(
        session_factory=harness.AppSession,
        institution_id=task["institution_id"],
        clock=clock,
    )
    assert stats["dead"] + stats["failed"] == 1, stats

    # The signer is PAUSED: no new sends, honest error recorded.
    assert sender.paused
    assert sender.paused_reason and "externally" in sender.paused_reason
    row = harness.query(
        "SELECT status, last_error FROM outbox WHERE id = :i",
        {"i": task["outbox_id"]}, task["institution_id"],
    )[0]
    assert row[0] == "FAILED"
    assert "paused" in row[1]
    # Nothing was signed/persisted/sent by the paused pipeline.
    assert harness.query(
        "SELECT COUNT(*) FROM chain_submissions WHERE institution_id = :i AND submission_kind = 'EVIDENCE_ATTESTED'",
        {"i": task["institution_id"]}, task["institution_id"],
    )[0][0] == 0
    assert adapter.stats()["evidence"] == 0

    # New prepare attempts are refused while paused.
    binding = SenderBinding(chain_id=31337, contract_address=adapter.blocks.get(1, "0x" + "9" * 40),
                            institution_id=task["institution_id"], deployment_id="0x" + "22" * 32)
    with harness.AppSession() as session:
        with pytest.raises(SignerPausedError):
            sender.prepare_and_persist(
                session, binding,
                {"kind": "EVIDENCE_ATTESTED", "to": binding.contract_address,
                 "data": "0xdeadbeef", "value": 0},
                request_id="0x" + "7" * 64, now=clock(),
            )


def test_concurrent_prepares_allocate_distinct_nonces(harness):
    """The per-(chain, signer) advisory lock serializes nonce allocation:
    two concurrent prepares for different requests get DIFFERENT nonces and
    both persist (the unique(chain_id, signer, nonce) constraint holds)."""
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    sender, _account = make_sender(adapter, clock)
    binding = SenderBinding(chain_id=31337, contract_address="0x" + "9" * 40,
                            institution_id=task["institution_id"], deployment_id="0x" + "22" * 32)

    barrier = threading.Barrier(3)
    results = {}
    errors = []

    def prepare(tag, request_id):
        session = harness.AppSession()
        try:
            from app.db.session import tenant_transaction

            with tenant_transaction(session, task["institution_id"]):
                barrier.wait(timeout=30)
                results[tag] = sender.prepare_and_persist(
                    session, binding,
                    {"kind": "EVIDENCE_ATTESTED", "to": binding.contract_address,
                     "data": "0xdeadbeef", "value": 0},
                    request_id=request_id, now=clock(),
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            session.close()

    t1 = threading.Thread(target=prepare, args=(1, "0x" + "1" * 64))
    t2 = threading.Thread(target=prepare, args=(2, "0x" + "2" * 64))
    t1.start(); t2.start()
    barrier.wait(timeout=30)
    t1.join(timeout=30); t2.join(timeout=30)

    assert not errors, errors
    nonces = {results[1].nonce, results[2].nonce}
    assert len(nonces) == 2, f"concurrent prepares collided on nonce: {nonces}"
    assert nonces == {0, 1}

    persisted = harness.query(
        "SELECT nonce, COUNT(*) FROM chain_submissions "
        "WHERE institution_id = :i GROUP BY nonce ORDER BY nonce",
        {"i": task["institution_id"]}, task["institution_id"],
    )
    assert persisted == [(0, 1), (1, 1)]


def test_stuck_after_300s_alerts_once_and_pauses_new_sends(harness):
    """No automatic replacement: a tx unconfirmed past 300s alerts ONCE,
    pauses new sends for the signer, and reconciliation keeps running with
    the payload unchanged."""
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    sender, _account = make_sender(adapter, clock)
    adapter.hold_receipts = True  # the tx never confirms

    binding = SenderBinding(chain_id=31337, contract_address="0x" + "8" * 40,
                            institution_id=task["institution_id"], deployment_id="0x" + "22" * 32)
    from app.db.session import tenant_transaction

    with harness.AppSession() as session:
        with tenant_transaction(session, task["institution_id"]):
            sub = sender.prepare_and_persist(
                session, binding,
                {"kind": "EVIDENCE_ATTESTED", "to": binding.contract_address,
                 "data": "0xdeadbeef", "value": 0},
                request_id="0x" + "3" * 64, now=clock(),
            )
            tx_hash, raw_before = sub.tx_hash, sub.protected_raw_tx
        sender.broadcast(sub, now=clock())
        with tenant_transaction(session, task["institution_id"]):
            session.flush()
        with tenant_transaction(session, task["institution_id"]):
            state = sender.reconcile(sub, now=clock(), session=session)
        assert state == SubmissionState.PENDING  # under 300s: just pending

        clock.advance(301)
        with tenant_transaction(session, task["institution_id"]):
            state = sender.reconcile(sub, now=clock(), session=session)
        assert state == SubmissionState.STUCK
        assert sender.paused, "300s stuck must pause new sends for the signer"
        assert sub.stuck_alerted_at == clock()

        # Alert is one-time; reconciliation continues without payload change.
        clock.advance(60)
        with tenant_transaction(session, task["institution_id"]):
            state = sender.reconcile(sub, now=clock(), session=session)
        assert state == SubmissionState.STUCK
        assert sub.protected_raw_tx == raw_before
        assert sub.tx_hash == tx_hash

        # New sends are refused; no replacement transaction is built.
        with tenant_transaction(session, task["institution_id"]):
            with pytest.raises(SignerPausedError):
                sender.prepare_and_persist(
                    session, binding,
                    {"kind": "EVIDENCE_ATTESTED", "to": binding.contract_address,
                     "data": "0xdeadbeef", "value": 0},
                    request_id="0x" + "4" * 64, now=clock(),
                )
    stuck_rows = harness.query(
        "SELECT status, stuck_alerted_at FROM chain_submissions WHERE tx_hash = :t",
        {"t": tx_hash}, task["institution_id"],
    )
    assert stuck_rows[0][0] == "BROADCAST"
    assert stuck_rows[0][1] is not None
