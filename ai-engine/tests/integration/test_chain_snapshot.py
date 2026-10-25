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
  - every eth_call/get_code/eth_getLogs read happens at that same block;
  - block_hash is re-checked before the result is produced; a reorg to a
    different hash => unavailable: snapshot_reorged;
  - a later append never disturbs a prior valid snapshot (re-verification
    with snapshot_id keeps the original pin while the chain head advances);
  - writer authorization is ordered by (blockNumber, transactionIndex,
    logIndex) BEFORE the append event — add-then-revoke in the same block
    keeps the evidence valid, revoke-then-add in the same block invalidates,
    and a grant that arrives only after the submit invalidates.
"""

import pytest

from test_evidence_verification_v3 import (  # noqa: F401  (shared fixtures/helpers)
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
    app_engine,  # noqa: F401
    build_chain_for,
    keys,  # noqa: F401
    make_binding,
    make_fake_reader,
    make_identity,
    seeded,  # noqa: F401
    store,  # noqa: F401
    trust_registry,  # noqa: F401
    verify_service,
)


def _verify(chain, evidence_ids=(EV1, EV2), snapshot_id=None, binding=None):
    return verify_service(
        None, chain, list(evidence_ids), snapshot_id=snapshot_id, binding=binding,
        db_engine=app_engine, keys_fixture=keys, store_fixture=store,
        registry_fixture=trust_registry,
    )


def test_all_reads_use_same_block(seeded):
    chain = build_chain_for(seeded)
    result = _verify(chain, (EV1,))
    assert result.status == "verified", result.reasons
    assert result.snapshot_id
    assert chain.journal, "reader must journal its reads"
    blocks = {entry[1] for entry in chain.journal}
    assert blocks == {SNAPSHOT_BLOCK}, f"all reads must use the pinned block {SNAPSHOT_BLOCK}, got {blocks}"


def test_snapshot_block_is_latest_minus_depth_plus_one(seeded):
    chain = build_chain_for(seeded)
    result = _verify(chain, (EV1,))
    assert result.status == "verified", result.reasons
    assert SNAPSHOT_BLOCK == LATEST_BLOCK - CONFIRMATION_DEPTH + 1


def test_append_preserves_snapshot(seeded):
    chain = build_chain_for(seeded)
    first = _verify(chain, (EV1, EV2))
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
    again = _verify(chain, (EV1, EV2), snapshot_id=first.snapshot_id)
    assert again.status == "verified", again.reasons
    assert again.snapshot_id == first.snapshot_id


def test_reorg_marks_unavailable(seeded):
    chain = build_chain_for(seeded)
    first = _verify(chain, (EV1,))
    assert first.status == "verified", first.reasons

    chain.reorged = True  # the pinned block now resolves to a DIFFERENT hash
    again = _verify(chain, (EV1,), snapshot_id=first.snapshot_id)
    assert again.status == "unavailable"
    assert any("snapshot_reorged" in r for r in again.reasons)


def test_current_head_not_snapshot_head(seeded):
    """Verification is pinned to the snapshot block, not the current head."""
    chain = build_chain_for(seeded)
    result = _verify(chain, (EV1,))
    assert result.status == "verified", result.reasons
    # the chain advanced far beyond the pinned snapshot before re-verification
    chain.latest = LATEST_BLOCK + 50
    chain.journal.clear()
    again = _verify(chain, (EV1,), snapshot_id=result.snapshot_id)
    assert again.status == "verified", again.reasons
    assert max(entry[1] for entry in chain.journal) <= SNAPSHOT_BLOCK


# ---------------------------------------------------------------------------
# writer authorization is EVENT-ORDERED, not end-of-block state
# ---------------------------------------------------------------------------

def test_writer_add_then_revoke_same_block(seeded):
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
    result = _verify(chain, (EV1,))
    assert result.status == "verified", result.reasons


def test_revoke_then_submit_same_block(seeded):
    """Writer revoked BEFORE the append in the same block: invalid."""
    chain = build_chain_for(seeded)
    submit_block = SNAPSHOT_BLOCK
    chain.grant(FakeChain.pos(DEPLOYED_AT_BLOCK, 0, 0), WRITER, True)
    chain.grant(FakeChain.pos(submit_block, 0, 1), WRITER, False)  # revoke first
    chain.grant(FakeChain.pos(submit_block, 9, 0), WRITER, True)   # re-add after
    for e in chain.entries[1]:
        from app.services.anchor_reader import EventPosition

        e.event_position = EventPosition(block_number=submit_block, transaction_index=5, log_index=0)
    result = _verify(chain, (EV1,))
    assert result.status == "invalid"
    assert any("writer" in r for r in result.reasons)


def test_grant_after_submit(seeded):
    """A grant that only arrives AFTER the submit event does not authorize it."""
    chain = build_chain_for(seeded)
    chain.writer_events.clear()  # no authorization at deploy
    for e in chain.entries[1]:
        from app.services.anchor_reader import EventPosition

        e.event_position = EventPosition(block_number=SNAPSHOT_BLOCK, transaction_index=0, log_index=0)
    # grant lands strictly after both appends
    chain.grant(FakeChain.pos(SNAPSHOT_BLOCK + 1, 0, 0), WRITER, True)
    result = _verify(chain, (EV1,))
    assert result.status == "invalid"
    assert any("writer" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# availability of the historical record itself
# ---------------------------------------------------------------------------

def test_historical_logs_unavailable(seeded):
    """Without the writer-grant history the authorization cannot be proven:
    unavailable (never fabricated from the current allowlist)."""
    chain = build_chain_for(seeded)
    chain.missing_method = True
    result = _verify(chain, (EV1,))
    assert result.status == "unavailable"
    assert any("historical" in r for r in result.reasons)
