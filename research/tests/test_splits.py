"""R17 split-policy tests — temporal + participant-disjoint partitioning,
full-fingerprint manifests, and fail-closed validation (spec §6, §8, §9).

Rewritten for the R17 cutoff-based ``partition_splits`` /
``validate_splits`` interface. The pre-R17 sender-sorted partitioner and its
hash-over-first-50-IDs scheme are replaced; the hash-stability-on-tamper
expectation of the old ``test_zero_holdout_leakage_on_alteration`` is
INVERTED (full-content fingerprints must catch holdout tampering).
"""
import copy
import json

import pytest

from conftest import (
    TRAIN_END,
    VALIDATION_END,
    build_records,
    cohort_plan,
    impl,
    partition_under_test,
    participant_ids_of,
    record_time,
)
from research import run_experiments


def test_subject_isolation_zero_overlap():
    """No participant appears in more than one partition."""
    records = build_records(cohort_plan())
    manifest = partition_under_test(records, TRAIN_END, VALIDATION_END)

    train_actors = participant_ids_of(manifest, "train")
    val_actors = participant_ids_of(manifest, "validation")
    test_actors = participant_ids_of(manifest, "test")

    assert train_actors and val_actors and test_actors
    assert train_actors.isdisjoint(val_actors), "leakage: train and val share actors"
    assert train_actors.isdisjoint(test_actors), "leakage: train and test share actors"
    assert val_actors.isdisjoint(test_actors), "leakage: val and test share actors"


def test_split_determinism_and_hash():
    """Identical input data yields an identical manifest hash and full
    ordered ID lists (deterministic partition, no sampling)."""
    records_a = build_records(cohort_plan())
    records_b = build_records(cohort_plan())

    m_a = partition_under_test(records_a, TRAIN_END, VALIDATION_END)
    m_b = partition_under_test(records_b, TRAIN_END, VALIDATION_END)

    assert m_a.manifest_hash == m_b.manifest_hash
    assert m_a.manifest_hash.startswith("0x") and len(m_a.manifest_hash) == 66
    for name in ("train", "validation", "test"):
        assert m_a.splits[name].record_ids == m_b.splits[name].record_ids
        assert len(m_a.splits[name].record_ids) == 160  # FULL list, not [:50]


def test_zero_holdout_leakage_on_alteration():
    """Altering holdout content changes the manifest hash and the test-split
    fingerprint (full-content fingerprints expose holdout tampering)."""
    records = build_records(cohort_plan())
    m_orig = partition_under_test(records, TRAIN_END, VALIDATION_END)

    test_ids = list(m_orig.splits["test"].record_ids)
    altered = []
    for r in records:
        if r["id"] == test_ids[0]:
            r = dict(r)
            r["amount_minor"] += 99999
        altered.append(r)

    m_altered = partition_under_test(altered, TRAIN_END, VALIDATION_END)

    assert m_altered.manifest_hash != m_orig.manifest_hash, (
        "holdout content tampering left the manifest fingerprint unchanged")
    assert m_altered.splits["test"].fingerprint != m_orig.splits["test"].fingerprint
    # partition membership itself is unchanged (IDs, not content, decide splits)
    assert m_altered.splits["test"].record_ids == m_orig.splits["test"].record_ids


def test_validate_splits_rejects_tampered_manifest():
    """validate_splits fails closed on any mismatch between the manifest and
    the source records: membership tampering, fingerprint tampering, dropped
    coverage, or cutoff tampering."""
    validate_splits = impl(run_experiments, "validate_splits")
    split_validation_error = impl(run_experiments, "SplitValidationError")

    records = build_records(cohort_plan())
    manifest = partition_under_test(records, TRAIN_END, VALIDATION_END)
    validate_splits(manifest, records)  # a valid manifest must pass

    # tamper 1: a train record ID moved into the validation list
    tampered = copy.deepcopy(manifest)
    moved = tampered.splits["train"].record_ids.pop()
    tampered.splits["validation"].record_ids.append(moved)
    with pytest.raises(split_validation_error):
        validate_splits(tampered, records)

    # tamper 2: forged split fingerprint
    tampered = copy.deepcopy(manifest)
    tampered.splits["train"].fingerprint = "0x" + "0" * 64
    with pytest.raises(split_validation_error):
        validate_splits(tampered, records)

    # tamper 3: a record silently removed from the manifest (no coverage)
    tampered = copy.deepcopy(manifest)
    tampered.splits["train"].record_ids.pop()
    with pytest.raises(split_validation_error):
        validate_splits(tampered, records)

    # tamper 4: cutoffs edited after the fact
    tampered = copy.deepcopy(manifest)
    tampered.cutoffs["validation_end"] = "2030-01-01T00:00:00Z"
    with pytest.raises(split_validation_error):
        validate_splits(tampered, records)


def test_every_source_id_in_exactly_one_split_or_dropped():
    """Every source record is either in exactly one split or carries a
    recorded drop reason; drop reasons use the fixed R17 codes."""
    cohorts = cohort_plan()
    cohorts.append({"name": "transient", "participants": 1, "per_participant": 3,
                    "start_h": 40, "end_h": 90,
                    "label_fn": lambda p, j: 1 if j == 1 else 0})
    cohorts.append({"name": "spill", "participants": 1, "times": [4, 8, 30, 100],
                    "label_fn": lambda p, j: 1 if j == 3 else 0})
    records = build_records(cohorts)

    manifest = partition_under_test(records, TRAIN_END, VALIDATION_END)

    seen = []
    for name in ("train", "validation", "test"):
        seen.extend(manifest.splits[name].record_ids)

    seen.extend(d.record_id for d in manifest.dropped)
    assert sorted(seen) == sorted(r["id"] for r in records), "coverage gap"
    assert len(seen) == len(set(seen)), "a record entered two splits"
    valid_reasons = {run_experiments.DROP_REASON_TRAIN_PARTICIPANT_FUTURE_RECORD,
                     run_experiments.DROP_REASON_CROSSES_VALIDATION_TEST_BOUNDARY}
    assert manifest.dropped, "the planted crossing/spill records must be dropped"
    for d in manifest.dropped:
        assert d.reason in valid_reasons
        assert d.participant_id


def test_run_pipeline_reports_insufficient_data_honestly():
    """The runner must record INSUFFICIENT_DATA (never SUPPORTED) when strict
    temporal+participant-disjoint splitting leaves an evaluation split below
    the minimum, and must not produce metrics or a model artifact."""
    suite = run_experiments.run_experiment_suite
    root_dir = run_experiments.ROOT_DIR

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        result = suite(str(root_dir / "research" / "protocol.json"),
                       max_records=200, results_dir=tmp)
        assert result["outcome"] == "INSUFFICIENT_DATA"

        run_manifest = json.loads(
            (result["run_dir"] / "run-manifest.json").read_text(encoding="utf-8"))
        assert run_manifest["outcome"] == "INSUFFICIENT_DATA"
        assert "metrics" not in run_manifest
        assert "model_hash" not in run_manifest
        readme = (result["run_dir"] / "README.md").read_text(encoding="utf-8")
        assert "SUPPORTED" not in readme
        assert not (result["run_dir"] / "model.joblib").exists()
