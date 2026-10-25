"""
R07 — chain snapshot semantics (spec §5).

Named cases (exact, from the task brief):
  all_reads_use_same_block, append_preserves_snapshot, reorg_marks_unavailable,
  current_head_not_snapshot_head, writer_add_then_revoke_same_block,
  revoke_then_submit_same_block, grant_after_submit,
  manifest_signature_changed_after_anchor_invalid,
  retired_service_key_anchor_time_proven, historical_logs_unavailable.

Snapshot rules under test:
  - block_number = latest - depth + 1, then block_hash is PINNED;
  - every eth_call/get_code/eth_getLogs/read_incident happens at that block;
  - block_hash is re-checked before the result; a reorg to a different hash
    => unavailable: snapshot_reorged;
  - a later append never disturbs a prior valid snapshot (re-verification
    with snapshot_id keeps the original pin while the chain head advances);
  - writer authorization is ordered by (blockNumber, transactionIndex,
    logIndex) BEFORE the append event — add-then-revoke in the same block
    keeps the evidence valid, revoke-then-add in the same block invalidates,
    and a grant that arrives only after the submit invalidates.

Shared seeding lives in test_evidence_verification_v3.shared_state() (one
process-wide migration + seed + key set).
"""

import pytest

from test_evidence_verification_v3 import (
    CASE_A,
    CONFIRMATION_DEPTH,
    DEPLOYED_AT_BLOCK,
    EV1,
    EV2,
    LATEST_BLOCK,
    SNAPSHOT_BLOCK,
    SNAPSHOT_HASH,
    WRITER,
    FakeChain,
    build_chain_for,
    make_binding,
    make_identity,
    shared_state,
    verify_service,
)


@pytest.fixture(scope="module")
def shared():
    return shared_state()


@pytest.fixture(scope="module")
def seeded(shared):
    return shared["seeded"]


def _verify(chain, evidence_ids=(EV1, EV2), snapshot_id=None, binding=None, shared=None):
    sh = shared or shared_state()
    return verify_service(
        None, chain, list(evidence_ids), snapshot_id=snapshot_id, binding=binding,
        db_engine=sh["app_engine"], keys_fixture=sh["keys"], store_fixture=sh["store"],
        registry_fixture=sh["trust_registry"],
    )


def test_all_reads_use_same_block(seeded, shared):
    chain = build_chain_for(seeded)
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "verified", result.reasons
    assert result.snapshot_id
    assert chain.journal, "reader must journal its reads"
    data_reads = {b for (m, b) in chain.journal if m != "eth_getBlockByNumber"}
    assert data_reads == {SNAPSHOT_BLOCK}, (
        f"every data read (eth_call/getCode/getLogs/read_incident) must use the "
        f"pinned block {SNAPSHOT_BLOCK}, got {data_reads}"
    )
    block_reads = {b for (m, b) in chain.journal if m == "eth_getBlockByNumber"}
    # only snapshot acquisition (latest) and the pin/recheck itself may touch other blocks
    assert block_reads <= {SNAPSHOT_BLOCK, LATEST_BLOCK}


def test_snapshot_block_is_latest_minus_depth_plus_one(seeded, shared):
    chain = build_chain_for(seeded)
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "verified", result.reasons
    assert SNAPSHOT_BLOCK == LATEST_BLOCK - CONFIRMATION_DEPTH + 1


def test_append_preserves_snapshot(seeded, shared):
    chain = build_chain_for(seeded)
    first = _verify(chain, (EV1, EV2), shared=shared)
    assert first.status == "verified", first.reasons

    # A NEW evidence append lands on-chain (head advances)...
    from app.services.anchor_reader import AnchoredEntry, EventPosition

    chain.latest = LATEST_BLOCK + 5
    chain.add_entry(
        1,
        AnchoredEntry(
            evidence_id="3",
            incident_id="1",
            submitted_by=WRITER,
            timestamp=1770000500,
            evidence_type_hash="0x" + "11" * 32,
            description_hash="0x" + "22" * 32,
            evidence_hash="0x" + "77" * 32,
            previous_entry_hash="0x" + "88" * 32,
            entry_hash="0x" + "99" * 32,
            request_id="0x" + "ab" * 32,
            manifest_digest="0x" + "cd" * 32,
            event_position=EventPosition(block_number=LATEST_BLOCK + 5, transaction_index=0, log_index=0),
        ),
    )

    # ...re-verifying the ORIGINAL set with the pinned snapshot stays verified
    # and keeps the SAME pin (append never disturbs a prior valid snapshot).
    again = _verify(chain, (EV1, EV2), snapshot_id=first.snapshot_id, shared=shared)
    assert again.status == "verified", again.reasons
    assert again.snapshot_id == first.snapshot_id


def test_reorg_marks_unavailable(seeded, shared):
    chain = build_chain_for(seeded)
    first = _verify(chain, (EV1,), shared=shared)
    assert first.status == "verified", first.reasons

    chain.reorged = True  # the pinned block now resolves to a DIFFERENT hash
    again = _verify(chain, (EV1,), snapshot_id=first.snapshot_id, shared=shared)
    assert again.status == "unavailable"
    assert any("snapshot_reorged" in r for r in again.reasons)


def test_current_head_not_snapshot_head(seeded, shared):
    """Verification is pinned to the snapshot block, not the current head."""
    chain = build_chain_for(seeded)
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "verified", result.reasons
    # the chain advanced far beyond the pinned snapshot before re-verification
    chain.latest = LATEST_BLOCK + 50
    chain.journal.clear()
    again = _verify(chain, (EV1,), snapshot_id=result.snapshot_id, shared=shared)
    assert again.status == "verified", again.reasons
    assert max(entry[1] for entry in chain.journal) <= SNAPSHOT_BLOCK


# ---------------------------------------------------------------------------
# writer authorization is EVENT-ORDERED, not end-of-block state
# ---------------------------------------------------------------------------

def test_writer_add_then_revoke_same_block(seeded, shared):
    """Writer granted BEFORE the append and revoked AFTER it in the SAME
    block: the evidence stays valid."""
    chain = build_chain_for(seeded)
    chain.grant(FakeChain.pos(DEPLOYED_AT_BLOCK, 0, 0), WRITER, False)  # start unauthorized
    submit_block = SNAPSHOT_BLOCK  # same block as the entries' anchor
    chain.grant(FakeChain.pos(submit_block, 0, 1), WRITER, True)   # add first
    chain.grant(FakeChain.pos(submit_block, 9, 0), WRITER, False)  # revoke later
    for e in chain.entries[1]:
        from app.services.anchor_reader import EventPosition

        e.event_position = EventPosition(block_number=submit_block, transaction_index=5, log_index=0)
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "verified", result.reasons


def test_revoke_then_submit_same_block(seeded, shared):
    """Writer revoked BEFORE the append in the same block: invalid."""
    chain = build_chain_for(seeded)
    submit_block = SNAPSHOT_BLOCK
    chain.grant(FakeChain.pos(DEPLOYED_AT_BLOCK, 0, 0), WRITER, True)
    chain.grant(FakeChain.pos(submit_block, 0, 1), WRITER, False)  # revoke first
    chain.grant(FakeChain.pos(submit_block, 9, 0), WRITER, True)   # re-add after
    for e in chain.entries[1]:
        from app.services.anchor_reader import EventPosition

        e.event_position = EventPosition(block_number=submit_block, transaction_index=5, log_index=0)
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "invalid"
    assert any("writer" in r for r in result.reasons)


def test_grant_after_submit(seeded, shared):
    """A grant that only arrives AFTER the submit event does not authorize it."""
    from app.schemas.evidence import EvidenceV2, hash_entry
    from app.services.anchor_reader import EventPosition
    from test_evidence_verification_v3 import CHAIN_ID, CONTRACT, OTHER_WRITER

    chain = build_chain_for(seeded)
    chain.writer_events.clear()  # no authorization history at all
    prev = "0x" + "00" * 32
    for idx, e in enumerate(chain.entries[1]):
        e.submitted_by = OTHER_WRITER  # a NEW writer, never bootstrapped
        e.event_position = EventPosition(block_number=SNAPSHOT_BLOCK, transaction_index=idx, log_index=idx)
        # re-link + re-hash over the new writer so the chain itself stays
        # internally valid: the decisive failure must be AUTHORIZATION
        e.previous_entry_hash = prev
        v2 = EvidenceV2(
            schema_version=2, chain_id=CHAIN_ID, contract_address=CONTRACT, incident_id=1,
            evidence_id=int(e.evidence_id), submitted_by=OTHER_WRITER, timestamp=e.timestamp,
            evidence_type_hash=e.evidence_type_hash, description_hash=e.description_hash,
            evidence_hash=e.evidence_hash, previous_entry_hash=prev,
        )
        e.entry_hash = hash_entry(v2)
        prev = e.entry_hash
    # grant lands strictly after both appends
    chain.grant(FakeChain.pos(SNAPSHOT_BLOCK + 1, 0, 0), OTHER_WRITER, True)
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "invalid"
    assert any("writer" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# availability of the historical record itself
# ---------------------------------------------------------------------------

def test_historical_logs_unavailable(seeded, shared):
    """Without the writer-grant history the authorization cannot be proven:
    unavailable (never fabricated from the current allowlist)."""
    chain = build_chain_for(seeded)
    chain.missing_method = True
    result = _verify(chain, (EV1,), shared=shared)
    assert result.status == "unavailable"
    assert any("historical" in r for r in result.reasons)
