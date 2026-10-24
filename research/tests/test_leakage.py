"""R17 leakage tests — temporal ordering, actor disjointness, full fingerprints.

RED phase: these tests run against the pre-R17 leaky sender-sorted partitioner
(via the conftest seam) and document its failures behaviourally — wrong
partitioning semantics, not fixture errors. GREEN phase: identical assertions
run against ``research.run_experiments.partition_splits`` / ``validate_splits``.

Policy under test (spec §9 / brief §R17, verbatim semantics):
  train      = records with occurred_at <= train_end
  validation = ONLY participants with first_seen > train_end AND
               last_seen <= validation_end, and their in-window records
  test       = ONLY participants with first_seen > validation_end, and their
               later records
  later records of train participants are dropped; anyone crossing the
  validation/test boundary enters neither evaluation set; every drop gets a
  recorded reason; no random-split fallback exists.
"""
from datetime import timedelta

import numpy as np
import pytest

from conftest import (
    BASE_TIME,
    TRAIN_END,
    VALIDATION_END,
    build_records,
    cohort_plan,
    impl,
    manifest_records,
    partition_under_test,
    participant_ids_of,
    record_time,
)
from research import run_experiments


def _dataset_with_transient_and_spill():
    """Standard cohorts plus (a) a deliberately planted transient participant
    crossing the validation/test boundary and (b) a train participant whose
    timeline continues past train_end (hours 4, 8 in train window; 30 and 100
    after it)."""
    cohorts = cohort_plan()
    cohorts.append({"name": "transient", "participants": 1, "per_participant": 3,
                    "start_h": 40, "end_h": 90,
                    "label_fn": lambda p, j: 1 if j == 1 else 0})
    cohorts.append({"name": "spill", "participants": 1, "times": [4, 8, 30, 100],
                    "label_fn": lambda p, j: 1 if j == 3 else 0})
    return build_records(cohorts)


def test_temporal_order_and_actor_disjoint():
    """Planted transient participant: strict temporal separation holds and all
    three pairwise actor-set intersections are empty; the transient actor
    enters no evaluation split and is dropped with a recorded reason."""
    records = _dataset_with_transient_and_spill()
    manifest = partition_under_test(records, TRAIN_END, VALIDATION_END)

    train = manifest_records(manifest, "train")
    validation = manifest_records(manifest, "validation")
    test = manifest_records(manifest, "test")

    assert train and validation and test, "all three splits must be non-empty"
    assert max(record_time(r) for r in train) < min(record_time(r) for r in validation)
    assert max(record_time(r) for r in validation) < min(record_time(r) for r in test)

    train_actors = participant_ids_of(manifest, "train")
    val_actors = participant_ids_of(manifest, "validation")
    test_actors = participant_ids_of(manifest, "test")
    assert train_actors.isdisjoint(val_actors)
    assert train_actors.isdisjoint(test_actors)
    assert val_actors.isdisjoint(test_actors)

    # the planted transient participant crosses validation/test -> neither set
    transient_ids = {r["id"] for r in records if "TRANSIENT" in r["id"]}
    for name in ("train", "validation", "test"):
        split_ids = set(manifest.splits[name].record_ids)
        assert not (transient_ids & split_ids), (
            f"crossing participant record {name}-side leaked into an evaluation split")
    dropped_by_id = {d.record_id: d for d in manifest.dropped}
    for rid in transient_ids:
        assert rid in dropped_by_id, "every dropped record must be recorded"
        assert dropped_by_id[rid].reason == \
            run_experiments.DROP_REASON_CROSSES_VALIDATION_TEST_BOUNDARY


def test_no_future_record_for_training():
    """A train participant's later records must never appear in training (and
    must not be migrated into validation/test to compensate size); each one is
    dropped with an explicit reason."""
    records = _dataset_with_transient_and_spill()
    manifest = partition_under_test(records, TRAIN_END, VALIDATION_END)

    train = manifest_records(manifest, "train")
    future_in_train = [r for r in train if record_time(r) > TRAIN_END]
    assert future_in_train == [], (
        "training contains records after train_end (temporal leakage)")

    spill_ids = {r["id"] for r in records if "SPILL" in r["id"]}
    dropped_by_id = {d.record_id: d for d in manifest.dropped}
    future_spill = [r for r in records
                    if r["id"] in spill_ids and record_time(r) > TRAIN_END]
    assert len(future_spill) == 2, "fixture must plant exactly two spill records"
    for r in future_spill:
        assert r["id"] in dropped_by_id, "future train-participant record must be dropped"
        assert dropped_by_id[r["id"]].reason == \
            run_experiments.DROP_REASON_TRAIN_PARTICIPANT_FUTURE_RECORD
        for name in ("train", "validation", "test"):
            assert r["id"] not in set(manifest.splits[name].record_ids)

    # coverage: every source record is either in exactly one split or dropped
    seen = []
    for name in ("train", "validation", "test"):
        seen.extend(manifest.splits[name].record_ids)
    seen.extend(dropped_by_id.keys())
    assert sorted(seen) == sorted(r["id"] for r in records)
    assert len(seen) == len(set(seen))


def test_full_manifest_hash_changes_if_record_51_changes():
    """The manifest fingerprint covers FULL ordered lists (source + every
    split), not the first 50 IDs — altering the 51st record in canonical order
    must change the manifest hash and the fingerprint of the split holding it."""
    records = build_records(cohort_plan())  # 160 train / 160 val / 160 test
    manifest_a = partition_under_test(records, TRAIN_END, VALIDATION_END)

    ordered = sorted(records, key=lambda r: (r["occurred_at"], r["id"]))
    target = dict(ordered[50])  # the 51st record in canonical order
    target["amount_minor"] += 1
    altered = [target if r["id"] == target["id"] else r for r in records]

    manifest_b = partition_under_test(altered, TRAIN_END, VALIDATION_END)

    assert manifest_a.manifest_hash != manifest_b.manifest_hash, (
        "manifest hash ignored record #51 (first-50-IDs-only fingerprint)")
    # the full ordered ID lists are stored, not truncated to 50
    assert len(manifest_b.splits["train"].record_ids) == 160
    holding_split = next(n for n in ("train", "validation", "test")
                         if target["id"] in manifest_b.splits[n].record_ids)
    assert manifest_a.splits[holding_split].fingerprint != \
        manifest_b.splits[holding_split].fingerprint


def test_scaler_fit_uses_train_only():
    """Feature-scaler statistics must be computed on the training records
    only — never pooled with validation/test statistics."""
    fit_feature_scaler = impl(run_experiments, "fit_feature_scaler")
    records_to_matrix = impl(run_experiments, "records_to_matrix")

    train_a = build_records([{"name": "train", "participants": 12,
                              "per_participant": 20, "start_h": 0, "end_h": 20}])
    train_b = [dict(r, amount_minor=r["amount_minor"] * 10) for r in train_a]

    scaler_a = fit_feature_scaler(train_a)
    scaler_b = fit_feature_scaler(train_b)

    expected_a = records_to_matrix(train_a).mean(axis=0)
    assert np.allclose(scaler_a.mean_, expected_a), (
        "scaler statistics are not the train-only statistics")
    assert not np.allclose(scaler_b.mean_, expected_a), (
        "scaler statistics did not track the training data")
    assert scaler_a.n_samples_seen_ == len(train_a)


def test_feature_history_cannot_read_future():
    """Historical window features must be derived from events at or before the
    record's own time only — a later event must not influence any earlier
    record, even when the input list is scrambled."""
    derive = impl(run_experiments, "derive_historical_features")

    sender = "ACC-HIST-001"
    t0 = BASE_TIME
    t1 = t0 + timedelta(minutes=4)
    t2 = t0 + timedelta(minutes=8)
    t_future = t0 + timedelta(minutes=20)

    def rec(idx, t, amount):
        return {"id": f"TX-HIST-{idx:04d}", "sender_ref": sender,
                "occurred_at": t.isoformat(), "amount_minor": amount}

    base = [rec(0, t0, 1_000_000), rec(1, t1, 500_000), rec(2, t2, 2_000_000)]
    scrambled_with_future = [rec(3, t_future, 900_000_000)] + base

    out_base = derive([dict(r) for r in base])
    out_future = derive([dict(r) for r in scrambled_with_future])

    history_fields = ("sender_daily_volume_minor", "sender_daily_count",
                      "sender_window_burst_10m")
    for i in range(3):
        for field in history_fields:
            assert out_base[i][field] == out_future[i][field], (
                f"{field} of record {i} changed when a future event was added")

    # the history must genuinely aggregate the past (not a tautology):
    assert out_future[2]["sender_daily_volume_minor"] == 3_500_000
    assert out_future[2]["sender_daily_count"] == 3
    assert out_future[2]["sender_window_burst_10m"] == 3  # t0, t1, t2 within 10m
    # the future event itself is not folded back into earlier records
    assert out_future[0]["sender_daily_volume_minor"] == 1_000_000


def test_empty_or_too_small_or_single_class_split_fails():
    """Fail closed: empty, below-minimum, or single-class splits raise
    SplitValidationError. No random-split fallback ever runs."""
    split_validation_error = impl(run_experiments, "SplitValidationError")

    # 1. empty evaluation splits: everything happens before train_end
    empty = build_records([{"name": "train", "participants": 10,
                            "per_participant": 20, "start_h": 0, "end_h": 20}])
    with pytest.raises(split_validation_error) as exc_empty:
        partition_under_test(empty, TRAIN_END, VALIDATION_END)
    assert "validation" in str(exc_empty.value).lower()

    # 2. too small: validation cohort of 40 records is below the 100 minimum
    small = build_records([
        {"name": "train", "participants": 8, "per_participant": 20,
         "start_h": 0, "end_h": 20},
        {"name": "val", "participants": 2, "per_participant": 20,
         "start_h": 30, "end_h": 66},
        {"name": "test", "participants": 8, "per_participant": 20,
         "start_h": 80, "end_h": 140},
    ])
    with pytest.raises(split_validation_error) as exc_small:
        partition_under_test(small, TRAIN_END, VALIDATION_END)
    assert "validation" in str(exc_small.value).lower()

    # 3. single class: validation cohort labelled all-benign
    monoclass = build_records([
        {"name": "train", "participants": 8, "per_participant": 20,
         "start_h": 0, "end_h": 20},
        {"name": "val", "participants": 8, "per_participant": 20,
         "start_h": 30, "end_h": 66, "label_fn": lambda p, j: 0},
        {"name": "test", "participants": 8, "per_participant": 20,
         "start_h": 80, "end_h": 140},
    ])
    with pytest.raises(split_validation_error) as exc_class:
        partition_under_test(monoclass, TRAIN_END, VALIDATION_END)
    assert "class" in str(exc_class.value).lower()
