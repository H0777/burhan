"""
R08 crash-recovery integration tests — REAL PostgreSQL (r08-pg-test) with a
behavior-faithful local EVM simulator (chain_sim.SimulatedEvmAdapter).

Named cases (spec §7 / brief): crash_after_claim, after_signed_tx_commit,
after_broadcast_before_receipt, after_receipt_before_db_commit. After every
restart there is exactly ONE incident, ONE evidence entry, ONE COMPLETED
outbox item, and the SAME tx_hash/nonce on re-broadcast — no second on-chain
effect at any crash boundary.
"""

import pytest

from app.workers.evidence_anchor import CrashSimulated, EvidenceAnchorWorker
from app.services.chain_sender import SIGNED, BROADCAST

from chain_sim import PGHarness, FakeClock, SimulatedEvmAdapter, make_sender, require_pg_urls

RESTART_ADVANCE_SECONDS = 61  # lease is 60s; restart reclaims after expiry


@pytest.fixture(scope="module")
def harness():
    app_url, migration_url = require_pg_urls()
    h = PGHarness(app_url, migration_url)
    h.migrate()
    yield h
    h.close()


def _worker(adapter, clock, worker_id="anchor_r08"):
    sender, _account = make_sender(adapter, clock)
    return EvidenceAnchorWorker(chain_sender=sender, worker_id=worker_id, deployment_id="0x" + "22" * 32)


def _multi_tenant_worker(adapter, clock, worker_id="anchor_r08"):
    """Per-institution anchoring signer (the R08 deployment shape: nonce
    allocation is tenant-scoped under RLS, so each institution has its own
    exclusive anchoring signer on the same chain/adapter)."""
    senders: dict[str, object] = {}

    def factory(institution_id):
        if institution_id not in senders:
            senders[institution_id] = make_sender(adapter, clock)[0]
        return senders[institution_id]

    return EvidenceAnchorWorker(
        chain_sender_factory=factory, worker_id=worker_id, deployment_id="0x" + "22" * 32,
    )


def _counts(h, task):
    inst = task["institution_id"]
    return {
        "outbox": h.query(
            "SELECT status, COUNT(*) FROM outbox WHERE institution_id = :i GROUP BY status", {"i": inst}, inst,
        ),
        "submissions": h.query(
            "SELECT submission_kind, status, COUNT(*) FROM chain_submissions "
            "WHERE institution_id = :i GROUP BY submission_kind, status", {"i": inst}, inst,
        ),
        "mappings": h.query(
            "SELECT case_id, incident_id FROM case_incident_mappings WHERE institution_id = :i",
            {"i": inst}, inst,
        ),
        "anchors": h.query(
            "SELECT status, transaction_hash FROM evidence_anchors WHERE institution_id = :i",
            {"i": inst}, inst,
        ),
    }


def _restart_and_finish(h, adapter, clock, task):
    clock.advance(RESTART_ADVANCE_SECONDS)  # lease expiry — no real sleep
    worker = _worker(adapter, clock, worker_id="anchor_r08_restart")
    stats = worker.process_cycle(
        session_factory=h.AppSession, institution_id=task["institution_id"], clock=clock,
    )
    return stats


def _assert_single_effect(h, task, adapter):
    c = _counts(h, task)
    # ONE completed delivery
    assert c["outbox"] == [("COMPLETED", 1)], f"outbox: {c['outbox']}"
    # ONE incident mapping (the REAL incident id, not an assumption)
    assert len(c["mappings"]) == 1
    incident_id = c["mappings"][0][1]
    # ONE incident and ONE evidence entry on-chain
    assert adapter.stats()["incidents"] == 1, adapter.stats()
    assert adapter.stats()["evidence"] == 1, adapter.stats()
    # ONE ANCHORED anchor row tied to the mined tx
    assert len(c["anchors"]) == 1
    assert c["anchors"][0][0] == "ANCHORED"
    assert c["anchors"][0][1] and c["anchors"][0][1].startswith("0x")
    return incident_id


# ---------------------------------------------------------------------------


def test_crash_after_claim(harness):
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    worker = _worker(adapter, clock)

    with pytest.raises(CrashSimulated, match="after_claim"):
        worker.process_cycle(
            session_factory=harness.AppSession,
            institution_id=task["institution_id"],
            clock=clock,
            crash_before="after_claim",
        )

    # Crash left only a held lease: nothing signed, nothing sent.
    rows = harness.query(
        "SELECT COUNT(*) FROM chain_submissions", None, task["institution_id"],
    )[0][0]
    assert rows == 0
    assert adapter.stats()["broadcasts"] == {}

    stats = _restart_and_finish(harness, adapter, clock, task)
    assert stats["anchored"] == 1
    incident_id = _assert_single_effect(harness, task, adapter)
    assert incident_id == 1  # first registration keeps the id — mapping is real


def test_after_signed_tx_commit(harness):
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    worker = _worker(adapter, clock)

    with pytest.raises(CrashSimulated, match="after_prepare_commit"):
        worker.process_cycle(
            session_factory=harness.AppSession,
            institution_id=task["institution_id"],
            clock=clock,
            crash_before="after_prepare_commit",
        )

    # The incident tx was mined; the EVIDENCE raw tx is persisted but NOT sent.
    assert adapter.stats()["incidents"] == 1
    persisted = harness.query(
        "SELECT tx_hash, nonce, status, protected_raw_tx FROM chain_submissions "
        "WHERE institution_id = :i AND submission_kind = 'EVIDENCE_ATTESTED'",
        {"i": task["institution_id"]}, task["institution_id"],
    )
    assert len(persisted) == 1
    tx_hash, nonce, status, raw_tx = persisted[0]
    assert status == SIGNED
    # only the incident tx was broadcast; the evidence tx itself never was
    assert tx_hash not in adapter.stats()["broadcasts"]
    assert len(adapter.stats()["broadcasts"]) == 1

    stats = _restart_and_finish(harness, adapter, clock, task)
    assert stats["anchored"] == 1

    # Re-broadcast used the SAME persisted transaction: same hash, same nonce.
    after = harness.query(
        "SELECT tx_hash, nonce FROM chain_submissions "
        "WHERE institution_id = :i AND submission_kind = 'EVIDENCE_ATTESTED'",
        {"i": task["institution_id"]}, task["institution_id"],
    )
    assert after[0][0] == tx_hash
    assert after[0][1] == nonce
    mined = adapter.txs[tx_hash]
    assert mined["nonce"] == nonce
    assert adapter.stats()["broadcasts"][tx_hash] == 1  # sent exactly once
    _assert_single_effect(harness, task, adapter)


def test_after_broadcast_before_receipt(harness):
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    worker = _worker(adapter, clock)

    with pytest.raises(CrashSimulated, match="after_broadcast"):
        worker.process_cycle(
            session_factory=harness.AppSession,
            institution_id=task["institution_id"],
            clock=clock,
            crash_before="after_broadcast",
        )

    # Broadcast happened once; the worker died before reconciliation.
    sent = adapter.stats()["broadcasts"]
    assert len(sent) == 2  # incident + evidence

    subs = harness.query(
        "SELECT tx_hash, nonce, status FROM chain_submissions WHERE institution_id = :i "
        "AND submission_kind = 'EVIDENCE_ATTESTED'", {"i": task["institution_id"]},
        task["institution_id"],
    )
    assert len(subs) == 1
    evidence_tx, nonce, status = subs[0]
    assert status == BROADCAST

    stats = _restart_and_finish(harness, adapter, clock, task)
    assert stats["anchored"] == 1

    # NO re-send: the persisted tx hash was reconciled, not re-broadcast.
    assert adapter.stats()["broadcasts"][evidence_tx] == 1
    after = harness.query(
        "SELECT tx_hash, nonce FROM chain_submissions WHERE institution_id = :i "
        "AND submission_kind = 'EVIDENCE_ATTESTED'", {"i": task["institution_id"]},
        task["institution_id"],
    )
    assert after[0] == (evidence_tx, nonce)
    _assert_single_effect(harness, task, adapter)


def test_after_receipt_before_db_commit(harness):
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    worker = _worker(adapter, clock)

    with pytest.raises(CrashSimulated, match="after_receipt_before_commit"):
        worker.process_cycle(
            session_factory=harness.AppSession,
            institution_id=task["institution_id"],
            clock=clock,
            crash_before="after_receipt_before_commit",
        )

    # Receipt exists on-chain but the DB never recorded ANCHORED/COMPLETED.
    assert adapter.stats()["evidence"] == 1
    anchors = harness.query(
        "SELECT status FROM evidence_anchors WHERE institution_id = :i",
        {"i": task["institution_id"]}, task["institution_id"],
    )
    assert anchors[0][0] != "ANCHORED"

    stats = _restart_and_finish(harness, adapter, clock, task)
    assert stats["anchored"] == 1
    _assert_single_effect(harness, task, adapter)


def test_two_tenants_two_incidents_not_one(harness):
    """Two institutions with the SAME case_id anchor independently: separate
    case references -> two real incidents, one COMPLETED each — never a
    shared incident_id=1 collapse."""
    task_a = harness.seed_anchor_task(institution_id=None)
    task_b = harness.seed_anchor_task(institution_id=None)
    assert task_a["institution_id"] != task_b["institution_id"]

    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    worker = _multi_tenant_worker(adapter, clock)

    stats_a = worker.process_cycle(
        session_factory=harness.AppSession, institution_id=task_a["institution_id"], clock=clock,
    )
    assert stats_a["anchored"] == 1
    inc_a = _assert_single_effect(harness, task_a, adapter)  # tenant A alone: 1/1

    stats_b = worker.process_cycle(
        session_factory=harness.AppSession, institution_id=task_b["institution_id"], clock=clock,
    )
    assert stats_b["anchored"] == 1

    # Second tenant: its own mapping, its own incident, its own entry.
    c = _counts(harness, task_b)
    assert c["outbox"] == [("COMPLETED", 1)]
    assert len(c["mappings"]) == 1
    inc_b = c["mappings"][0][1]
    assert inc_a != inc_b, "tenants must never share one incident"
    assert adapter.stats()["incidents"] == 2
    assert adapter.stats()["evidence"] == 2


def test_request_payload_conflict_is_dead(harness):
    """Same request_id persisted with a DIFFERENT payload is terminal DEAD."""
    task = harness.seed_anchor_task()
    adapter = SimulatedEvmAdapter()
    clock = FakeClock()
    worker = _worker(adapter, clock)

    # First cycle anchors normally.
    stats = worker.process_cycle(
        session_factory=harness.AppSession, institution_id=task["institution_id"], clock=clock,
    )
    assert stats["anchored"] == 1

    # A second delivery for the SAME request_id but a MUTATED payload.
    import json as _json

    harness.query(
        "UPDATE outbox SET status = 'PENDING', attempts = 0, next_attempt_at = NULL, "
        "lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL "
        "WHERE id = :i", {"i": task["outbox_id"]}, task["institution_id"],
    )
    # also flip the STORED manifest digest -> different payload -> conflict
    harness.query(
        "UPDATE evidence_objects SET manifest_digest = :d WHERE institution_id = :i",
        {"i": task["institution_id"], "d": "ef" * 32}, task["institution_id"],
    )

    clock.advance(RESTART_ADVANCE_SECONDS)
    stats2 = worker.process_cycle(
        session_factory=harness.AppSession, institution_id=task["institution_id"], clock=clock,
    )
    assert stats2["dead"] == 1, stats2

    row = harness.query(
        "SELECT status, last_error FROM outbox WHERE id = :i",
        {"i": task["outbox_id"]}, task["institution_id"],
    )[0]
    assert row[0] == "DEAD"
    assert "different" in row[1] or "conflict" in row[1].lower()
    # No second on-chain effect from the conflict.
    assert adapter.stats()["evidence"] == 1
