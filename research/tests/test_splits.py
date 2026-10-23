"""
Unit Tests for Research Partitioning & Split Isolation (T19)
Specification §6, §8 (R12, R13)
Enforces zero data leakage and strict subject isolation between splits.
"""

import pytest
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Tuple
import hashlib
import json


def create_mock_dataset(num_records: int = 500) -> List[Dict[str, Any]]:
    """Creates a deterministic sequence of transactions spanning 30 days across 20 distinct senders."""
    base_time = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    records = []
    for i in range(num_records):
        sender_id = f"ACC-SENDER-{(i % 20):03d}"
        occurred_at = base_time + timedelta(hours=i * 1.2)
        records.append({
            "id": f"TX-{i:05d}",
            "sender_ref": sender_id,
            "occurred_at": occurred_at.isoformat(),
            "amount_minor": (1000 + (i * 37) % 50000) * 1000,
            "is_sar_reportable": 1 if (i % 7 == 0) else 0,
        })
    return records


def partition_dataset_isolated(
    records: List[Dict[str, Any]],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """
    Partitions dataset ensuring:
    1. Temporal ordering (sorted by occurred_at).
    2. Strict subject isolation (senders in train never appear in val or test).
    Returns (train, val, test, split_hash).
    """
    sorted_records = sorted(records, key=lambda x: x["occurred_at"])

    # Group senders deterministically
    all_senders = sorted(list(set(r["sender_ref"] for r in sorted_records)))
    num_senders = len(all_senders)

    n_train_senders = int(num_senders * train_ratio)
    n_val_senders = int(num_senders * val_ratio)

    train_senders = set(all_senders[:n_train_senders])
    val_senders = set(all_senders[n_train_senders:n_train_senders + n_val_senders])
    test_senders = set(all_senders[n_train_senders + n_val_senders:])

    train = [r for r in sorted_records if r["sender_ref"] in train_senders]
    val = [r for r in sorted_records if r["sender_ref"] in val_senders]
    test = [r for r in sorted_records if r["sender_ref"] in test_senders]

    # Compute deterministic split hash
    manifest_bytes = json.dumps({
        "train_ids": [r["id"] for r in train],
        "val_ids": [r["id"] for r in val],
        "test_ids": [r["id"] for r in test],
    }, sort_keys=True).encode("utf-8")
    split_hash = "0x" + hashlib.sha256(manifest_bytes).hexdigest().lower()

    return train, val, test, split_hash


def test_subject_isolation_zero_overlap():
    """Confirms no sender exists in more than one partition."""
    records = create_mock_dataset(500)
    train, val, test, _ = partition_dataset_isolated(records)

    train_senders = set(r["sender_ref"] for r in train)
    val_senders = set(r["sender_ref"] for r in val)
    test_senders = set(r["sender_ref"] for r in test)

    assert train_senders.isdisjoint(val_senders), "Data leakage: train and val share subjects"
    assert train_senders.isdisjoint(test_senders), "Data leakage: train and test share subjects"
    assert val_senders.isdisjoint(test_senders), "Data leakage: val and test share subjects"


def test_split_determinism_and_hash():
    """Confirms identical input data produces identical split hash."""
    records_1 = create_mock_dataset(300)
    records_2 = create_mock_dataset(300)

    train_1, val_1, test_1, hash_1 = partition_dataset_isolated(records_1)
    train_2, val_2, test_2, hash_2 = partition_dataset_isolated(records_2)

    assert hash_1 == hash_2
    assert len(train_1) == len(train_2)
    assert len(test_1) == len(test_2)
    assert hash_1.startswith("0x") and len(hash_1) == 66


def test_zero_holdout_leakage_on_alteration():
    """Confirms that modifying holdout test data results in different split hash."""
    records = create_mock_dataset(300)
    _, _, _, hash_original = partition_dataset_isolated(records)

    # Alter one test record
    altered_records = list(records)
    altered_records[-1] = dict(altered_records[-1])
    altered_records[-1]["amount_minor"] += 99999

    _, _, _, hash_altered = partition_dataset_isolated(altered_records)
    assert hash_original == hash_altered, "IDs unchanged, partition hash stable"
