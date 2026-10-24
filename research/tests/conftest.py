"""Shared helpers for R17 split-policy / leakage tests.

Provides a deterministic windowed record builder and the partition seam used
by both test modules to call ``research.run_experiments.partition_splits``.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "ai-engine")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from research import run_experiments  # noqa: E402

BASE_TIME = datetime(2026, 3, 1, 6, 0, 0, tzinfo=timezone.utc)
TRAIN_END = BASE_TIME + timedelta(hours=24)          # 2026-03-02T06:00:00Z
VALIDATION_END = BASE_TIME + timedelta(hours=72)     # 2026-03-04T06:00:00Z


def cohort_plan():
    """Standard three windowed cohorts: 160/160/160 records, disjoint actors.

    train cohort:  hours [0, 20)   -> entirely <= TRAIN_END (+24h)
    validation:    hours [30, 66)  -> first_seen > 24h, last_seen <= 72h
    test:          hours [80, 140) -> first_seen > 72h
    """
    return [
        {"name": "train", "participants": 8, "per_participant": 20,
         "start_h": 0, "end_h": 20},
        {"name": "val", "participants": 8, "per_participant": 20,
         "start_h": 30, "end_h": 66},
        {"name": "test", "participants": 8, "per_participant": 20,
         "start_h": 80, "end_h": 140},
    ]


def transient_cohort():
    """One crossing participant: first_seen 40h (validation window),
    last_seen 90h (test window) -> must enter NO evaluation split."""
    return [{"name": "transient", "participants": 1, "per_participant": 3,
             "start_h": 40, "end_h": 90,
             "label_fn": lambda p, j: 1 if j == 1 else 0}]


def build_records(cohorts, base_time=BASE_TIME):
    """Build deterministic synthetic records.

    Each cohort dict: {name, participants, per_participant, start_h, end_h,
    label_fn(optional fn(participant_idx, record_idx) -> 0/1)}.
    Participant p gets per_participant records spread evenly over
    [start_h, end_h). Every record has a globally unique id.
    """
    records = []
    seq = 0
    for cohort in cohorts:
        prefix = cohort["name"].upper()
        if cohort.get("times") is not None:
            # explicit per-record hour offsets (same for every participant)
            hour_list = cohort["times"]
            span = None
        else:
            span = cohort["end_h"] - cohort["start_h"]
        label_fn = cohort.get("label_fn") or (
            lambda pi, rj: 1 if (pi * 31 + rj) % 7 == 0 else 0)
        for p in range(cohort["participants"]):
            sender = f"ACC-{prefix}-{p:03d}"
            hours = (hour_list if cohort.get("times") is not None
                     else [cohort["start_h"] + span * (j / cohort["per_participant"])
                           for j in range(cohort["per_participant"])])
            for j, h in enumerate(hours):
                seq += 1
                amount_minor = 250_000_000 + seq * 1_000
                tx_hour = int(h) % 24
                records.append({
                    "id": f"TX-{prefix}-{p:03d}-{j:04d}",
                    "sender_ref": sender,
                    "receiver_ref": "ACC-RCV-000",
                    "occurred_at": (base_time + timedelta(hours=h)).isoformat(),
                    "amount_minor": amount_minor,
                    "currency": "IQD",
                    "scale": 3,
                    "is_after_hours": 1 if (tx_hour < 5 or tx_hour >= 14) else 0,
                    "structuring_ratio": round(amount_minor / 15_000_000_000, 4),
                    "is_sar_reportable": label_fn(p, j),
                })
    return records


def impl(module, name):
    """Resolve a to-be-implemented symbol; RED phase fails with a clear message."""
    obj = getattr(module, name, None)
    if obj is None:
        pytest.fail(f"{module.__name__}.{name} is not implemented (R17 RED)")
    return obj


def partition_under_test(records, train_end, validation_end, **kwargs):
    """Seam: call the R17 implementation under test.

    (RED phase adapted the pre-R17 leaky sender-sorted partitioner here; that
    adapter was removed once partition_splits took the cutoff-based signature —
    see commit c26c73c for the RED adapter and its captured failures.)
    """
    return run_experiments.partition_splits(
        records, train_end, validation_end, **kwargs)


def manifest_records(manifest, name):
    return manifest.records(name)


def participant_ids_of(manifest, name):
    return set(manifest.participant_ids(name))


def record_time(record):
    return datetime.fromisoformat(record["occurred_at"])
