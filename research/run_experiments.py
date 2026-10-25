"""
Empirical Experiments Runner (T19) — R17 strict-split research regime
Cyber-Forensic Auditing Framework - Specification §6, §8, §9 (R12, R13, R17)

Executes reproducible research experiments governed by research/protocol.json
(the single configuration source). Partitioning is temporal AND
participant-disjoint:

    train      = records with occurred_at <= train_end
    validation = ONLY participants with first_seen > train_end AND
                 last_seen <= validation_end, and their in-window records
    test       = ONLY participants with first_seen > validation_end, and
                 their later records

Later records of train participants are dropped; any participant crossing the
validation/test boundary enters neither evaluation set; every drop carries an
explicit reason. There is NO random-split fallback. The SplitManifest carries
every record ID per split, participant IDs, UTC cutoffs, the seed, drop
reasons/counts, and SHA-256 fingerprints of the source and of every FULL
ordered split list (never truncated to the first 50 IDs).
"""

import os
import sys
import json
import time
import random
import hashlib
import argparse
import platform
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Ensure workspace root and ai-engine are in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
AI_ENGINE_DIR = ROOT_DIR / "ai-engine"
for p in [ROOT_DIR, AI_ENGINE_DIR]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from research.evaluate import compute_metrics
from app.models.registry import compute_file_sha256, FEATURE_SCHEMA_V2

ENGINE_VERSION = "2.0.0"
LABEL_COLUMN = "is_sar_reportable"
SPLIT_MANIFEST_SCHEMA_VERSION = "split-manifest/1"
DROP_REASON_TRAIN_PARTICIPANT_FUTURE_RECORD = "TRAIN_PARTICIPANT_FUTURE_RECORD"
DROP_REASON_CROSSES_VALIDATION_TEST_BOUNDARY = "PARTICIPANT_CROSSES_VALIDATION_TEST_BOUNDARY"


class SplitValidationError(RuntimeError):
    """Raised when a partition violates the R17 separation policy, when a
    split is empty / below minimum size / single-class, or when a manifest
    does not match the records it claims to describe. Fail-closed: there is
    no random-split fallback."""

    def __init__(self, message: str, split_manifest: Optional["SplitManifest"] = None):
        super().__init__(message)
        self.split_manifest = split_manifest
        self.violations = list(split_manifest.validation_errors) if split_manifest else []


# ---------------------------------------------------------------------------
# Canonical serialization / fingerprinting
# ---------------------------------------------------------------------------

def _parse_utc(value, field_name: str = "timestamp") -> datetime:
    """Parse an ISO-8601 timestamp or pass through a datetime; require a
    timezone-aware UTC value."""
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise ValueError(f"{field_name}: not an ISO-8601 timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"{field_name}: timezone-naive timestamps are not allowed "
                         f"(got {value!r}); cutoffs and record times must be UTC-aware")
    return dt.astimezone(timezone.utc)


def _utc_iso(dt: datetime) -> str:
    return _parse_utc(dt).isoformat().replace("+00:00", "Z")


def _canonical_records_bytes(records: List[Dict[str, Any]]) -> bytes:
    """Canonical byte serialization of a FULL ordered record list: records
    sorted by (occurred_at, id), every record with sorted keys, compact JSON.
    This is what split fingerprints are computed over (never truncated)."""
    ordered = sorted(records, key=lambda r: (_parse_utc(r["occurred_at"]), r["id"]))
    canonical = json.dumps(
        [{k: r[k] for k in sorted(r.keys())} for r in ordered],
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return canonical


def _sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest().lower()


def _git_short_revision() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT_DIR),
            capture_output=True, text=True, timeout=10)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return "unknown"


def collect_environment() -> Dict[str, str]:
    """ACTUAL runtime/library versions — never hardcoded."""
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "numpy_version": np.__version__,
        "scikit_learn_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "os": f"{platform.system()} {platform.release()}",
        "platform_machine": platform.machine(),
    }


# ---------------------------------------------------------------------------
# SplitManifest
# ---------------------------------------------------------------------------

@dataclass
class SplitEntry:
    name: str
    record_ids: List[str] = field(default_factory=list)
    participant_ids: List[str] = field(default_factory=list)
    fingerprint: str = ""
    records: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def record_count(self) -> int:
        return len(self.record_ids)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "record_ids": list(self.record_ids),
            "participant_ids": list(self.participant_ids),
            "record_count": len(self.record_ids),
            "fingerprint": self.fingerprint,
        }


@dataclass
class DropEntry:
    record_id: str
    participant_id: str
    reason: str
    occurred_at: str

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "participant_id": self.participant_id,
            "reason": self.reason,
            "occurred_at": self.occurred_at,
        }


@dataclass
class SplitManifest:
    """Full-fingerprint manifest of a temporal/participant-disjoint split.

    Serialized form (to_json_dict + manifest_hash) conforms to
    research/schemas/split-manifest.schema.json. The manifest hash covers the
    ENTIRE serialized manifest (all record IDs, all drops, cutoffs, policy,
    fingerprints) except created_at — so any change to any record, including
    records beyond the first 50, changes the hash.
    """
    cutoffs: Dict[str, str]
    seed: int
    policy: Dict[str, Any]
    source_fingerprint: str
    splits: Dict[str, SplitEntry]
    dropped: List[DropEntry] = field(default_factory=list)
    drop_summary: Dict[str, int] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    accepted: bool = True
    validation_errors: List[str] = field(default_factory=list)

    def records(self, name: str) -> List[Dict[str, Any]]:
        return list(self.splits[name].records)

    def participant_ids(self, name: str) -> List[str]:
        return list(self.splits[name].participant_ids)

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
            "created_at": self.created_at,
            "cutoffs": dict(self.cutoffs),
            "seed": self.seed,
            "policy": dict(self.policy),
            "source_fingerprint": self.source_fingerprint,
            "splits": {name: entry.to_json_dict()
                       for name, entry in self.splits.items()},
            "dropped": [d.to_json_dict() for d in self.dropped],
            "drop_summary": dict(self.drop_summary),
            "accepted": self.accepted,
            "validation_errors": list(self.validation_errors),
        }

    def serialized(self) -> Dict[str, Any]:
        doc = self.to_json_dict()
        doc["manifest_hash"] = self.manifest_hash
        return doc

    @property
    def manifest_hash(self) -> str:
        doc = self.to_json_dict()
        doc.pop("created_at", None)  # keep the fingerprint deterministic
        return _sha256_hex(json.dumps(doc, sort_keys=True,
                                      separators=(",", ":")).encode("utf-8"))


# ---------------------------------------------------------------------------
# Partitioning (R17 policy)
# ---------------------------------------------------------------------------

def compute_partition_plan(records: List[Dict[str, Any]],
                           train_end: datetime,
                           validation_end: datetime) -> Dict[str, Any]:
    """Pure deterministic partition plan. Returns ordered split record lists
    and the drop list. Every source record lands in exactly one split or gets
    exactly one drop reason."""
    train_end = _parse_utc(train_end, "train_end")
    validation_end = _parse_utc(validation_end, "validation_end")
    if train_end >= validation_end:
        raise SplitValidationError(
            f"train_end ({_utc_iso(train_end)}) must be strictly before "
            f"validation_end ({_utc_iso(validation_end)})")

    ordered = sorted(records, key=lambda r: (_parse_utc(r["occurred_at"]), r["id"]))
    bounds: Dict[str, Tuple[datetime, datetime]] = {}
    for r in ordered:
        t = _parse_utc(r["occurred_at"])
        pid = r["sender_ref"]
        lo, hi = bounds.get(pid, (t, t))
        bounds[pid] = (min(lo, t), max(hi, t))

    splits: Dict[str, List[Dict[str, Any]]] = {
        "train": [], "validation": [], "test": []}
    dropped: List[DropEntry] = []

    for r in ordered:
        t = _parse_utc(r["occurred_at"])
        pid = r["sender_ref"]
        first_seen, last_seen = bounds[pid]
        if t <= train_end:
            splits["train"].append(r)          # train = records <= train_end
        elif first_seen <= train_end:
            # train participant's later record: dropped, never migrated
            dropped.append(DropEntry(r["id"], pid,
                                     DROP_REASON_TRAIN_PARTICIPANT_FUTURE_RECORD,
                                     r["occurred_at"]))
        elif last_seen <= validation_end:
            splits["validation"].append(r)     # actor fully inside the window
        elif first_seen > validation_end:
            splits["test"].append(r)           # actor starts after validation
        else:
            # actor crosses validation/test: enters neither evaluation set
            dropped.append(DropEntry(r["id"], pid,
                                     DROP_REASON_CROSSES_VALIDATION_TEST_BOUNDARY,
                                     r["occurred_at"]))

    return {"ordered_source": ordered, "splits": splits, "dropped": dropped,
            "train_end": train_end, "validation_end": validation_end}


def _fail_closed_checks(plan: Dict[str, Any], min_split_size: int,
                        require_both_classes: bool) -> List[str]:
    violations: List[str] = []
    if not plan["ordered_source"]:
        violations.append("source dataset is empty")
    for name in ("train", "validation", "test"):
        recs = plan["splits"][name]
        if len(recs) < min_split_size:
            violations.append(
                f"{name} split has {len(recs)} records (< minimum {min_split_size})")
        labels = set()
        missing = 0
        for r in recs:
            if LABEL_COLUMN not in r:
                missing += 1
            else:
                labels.add(r[LABEL_COLUMN])
        if missing:
            violations.append(
                f"{name} split has {missing} records missing the label column "
                f"{LABEL_COLUMN}")
        elif require_both_classes and not ({0, 1} <= labels):
            violations.append(
                f"{name} split lacks a required class "
                f"(present labels: {sorted(labels)})")
    return violations


def partition_splits(records: List[Dict[str, Any]],
                     train_end: datetime,
                     validation_end: datetime,
                     *,
                     seed: int = 42,
                     min_split_size: int = 100,
                     require_both_classes: bool = True) -> SplitManifest:
    """Partition records temporally and by participant (R17 policy).

    Returns a full-fingerprint SplitManifest. Fails closed (SplitValidationError,
    no random-split fallback) when any split would be empty, below
    min_split_size, or missing a class.
    """
    policy = {
        "name": "temporal_participant_disjoint",
        "min_split_size": int(min_split_size),
        "require_both_classes": bool(require_both_classes),
        "random_split_fallback_allowed": False,
        "drop_reason_codes": [
            DROP_REASON_TRAIN_PARTICIPANT_FUTURE_RECORD,
            DROP_REASON_CROSSES_VALIDATION_TEST_BOUNDARY,
        ],
    }
    plan = compute_partition_plan(records, train_end, validation_end)

    violations = _fail_closed_checks(plan, min_split_size, require_both_classes)
    source_fingerprint = _sha256_hex(_canonical_records_bytes(plan["ordered_source"]))

    splits: Dict[str, SplitEntry] = {}
    for name in ("train", "validation", "test"):
        recs = plan["splits"][name]
        splits[name] = SplitEntry(
            name=name,
            record_ids=[r["id"] for r in recs],
            participant_ids=sorted({r["sender_ref"] for r in recs}),
            fingerprint=_sha256_hex(_canonical_records_bytes(recs)),
            records=list(recs),
        )

    manifest = SplitManifest(
        cutoffs={
            "train_end": _utc_iso(plan["train_end"]),
            "validation_end": _utc_iso(plan["validation_end"]),
        },
        seed=int(seed),
        policy=policy,
        source_fingerprint=source_fingerprint,
        splits=splits,
        dropped=plan["dropped"],
        drop_summary=dict(Counter(d.reason for d in plan["dropped"])),
        accepted=not violations,
        validation_errors=violations,
    )
    if violations:
        raise SplitValidationError("; ".join(violations), manifest)
    return manifest


def validate_splits(manifest: SplitManifest,
                    records: List[Dict[str, Any]]) -> None:
    """Validate a SplitManifest against the source records. Fails closed on:
    coverage gaps, membership/window violations, actor overlap, participant
    eligibility violations, below-minimum or single-class splits, fingerprint
    mismatches, or a tampered manifest hash."""
    errors: List[str] = []

    try:
        train_end = _parse_utc(manifest.cutoffs.get("train_end"), "cutoffs.train_end")
        validation_end = _parse_utc(manifest.cutoffs.get("validation_end"),
                                    "cutoffs.validation_end")
    except (ValueError, AttributeError) as exc:
        raise SplitValidationError(f"manifest cutoffs are invalid: {exc}") from exc

    policy = manifest.policy or {}
    min_split_size = int(policy.get("min_split_size", 100))
    require_both_classes = bool(policy.get("require_both_classes", True))

    by_id = {r["id"]: r for r in records}
    for name in ("train", "validation", "test"):
        if name not in manifest.splits:
            raise SplitValidationError(f"manifest is missing the '{name}' split entry")
    plan = None
    try:
        plan = compute_partition_plan(records, train_end, validation_end)
    except SplitValidationError as exc:
        errors.append(f"partition plan recompute failed: {exc}")

    # 1. membership matches a fresh deterministic partition of the records
    if plan is not None:
        for name in ("train", "validation", "test"):
            expected_ids = [r["id"] for r in plan["splits"][name]]
            actual_ids = list(manifest.splits[name].record_ids)
            if actual_ids != expected_ids:
                errors.append(
                    f"{name} split record list does not match the recomputed "
                    f"partition (len manifest={len(actual_ids)}, "
                    f"len recomputed={len(expected_ids)})")
        expected_drops = {(d.record_id, d.reason) for d in plan["dropped"]}
        actual_drops = {(d.record_id, d.reason) for d in manifest.dropped}
        if actual_drops != expected_drops:
            errors.append("dropped records/reasons do not match the recomputed partition")
        expected_summary = dict(Counter(d.reason for d in plan["dropped"]))
        if manifest.drop_summary != expected_summary:
            errors.append("drop_summary does not match the recomputed drop counts")
        for name in ("train", "validation", "test"):
            recs = plan["splits"][name]
            recomputed_fp = _sha256_hex(_canonical_records_bytes(recs))
            if manifest.splits[name].fingerprint != recomputed_fp:
                errors.append(f"{name} split fingerprint mismatch")

    recomputed_source_fp = _sha256_hex(_canonical_records_bytes(records))
    if manifest.source_fingerprint != recomputed_source_fp:
        errors.append("source fingerprint mismatch")

    # 2. independent policy invariants (not just recompute equality)
    seen: List[str] = []
    actor_sets: Dict[str, set] = {}
    split_records: Dict[str, List[Dict[str, Any]]] = {}
    for name in ("train", "validation", "test"):
        ids = list(manifest.splits[name].record_ids)
        seen.extend(ids)
        recs = [by_id[i] for i in ids if i in by_id]
        unknown = [i for i in ids if i not in by_id]
        if unknown:
            errors.append(f"{name} split references {len(unknown)} unknown record IDs")
        split_records[name] = recs
        actor_sets[name] = {r["sender_ref"] for r in recs}
        times = [_parse_utc(r["occurred_at"]) for r in recs]
        if name == "train" and any(t > train_end for t in times):
            errors.append("train split contains records after train_end")
        if name == "validation" and any(
                not (train_end < t <= validation_end) for t in times):
            errors.append("validation split contains records outside "
                          "(train_end, validation_end]")
        if name == "test" and any(t <= validation_end for t in times):
            errors.append("test split contains records at or before validation_end")

    for d in manifest.dropped:
        seen.append(d.record_id)
        if not d.reason:
            errors.append(f"dropped record {d.record_id} has no reason")
        if d.record_id in by_id and d.participant_id != by_id[d.record_id]["sender_ref"]:
            errors.append(f"dropped record {d.record_id} has wrong participant")

    if len(seen) != len(set(seen)):
        errors.append("a record ID appears in more than one split or drop")
    if sorted(seen) != sorted(by_id.keys()):
        errors.append("coverage gap: manifest does not account for exactly the "
                      "source record IDs")

    pairs = [("train", "validation"), ("train", "test"), ("validation", "test")]
    for a, b in pairs:
        if actor_sets[a] & actor_sets[b]:
            errors.append(f"actor overlap between {a} and {b} splits")

    bounds: Dict[str, Tuple[datetime, datetime]] = {}
    for r in records:
        t = _parse_utc(r["occurred_at"])
        pid = r["sender_ref"]
        lo, hi = bounds.get(pid, (t, t))
        bounds[pid] = (min(lo, t), max(hi, t))
    for name in ("train", "validation", "test"):
        for pid in manifest.participant_ids(name):
            if pid not in bounds:
                errors.append(f"{name} split lists unknown participant {pid}")
                continue
            first_seen, last_seen = bounds[pid]
            if name == "train" and first_seen > train_end:
                errors.append(f"train participant {pid} first_seen after train_end")
            if name == "validation" and not (
                    first_seen > train_end and last_seen <= validation_end):
                errors.append(f"validation participant {pid} violates "
                              f"first_seen > train_end and last_seen <= validation_end")
            if name == "test" and first_seen <= validation_end:
                errors.append(f"test participant {pid} first_seen <= validation_end")

    # 3. fail-closed size/class checks per the recorded policy
    for name in ("train", "validation", "test"):
        recs = split_records[name]
        if len(recs) < min_split_size:
            errors.append(
                f"{name} split has {len(recs)} records (< minimum {min_split_size})")
        labels = {r.get(LABEL_COLUMN) for r in recs if LABEL_COLUMN in r}
        if require_both_classes and recs and not ({0, 1} <= labels):
            errors.append(f"{name} split lacks a required class "
                          f"(present labels: {sorted(labels)})")

    if errors:
        raise SplitValidationError("; ".join(errors))


# ---------------------------------------------------------------------------
# Feature derivation (history cannot read the future) + scaler (train-only fit)
# ---------------------------------------------------------------------------

def derive_historical_features(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Derive per-record historical window features using ONLY events at or
    before the record's own time (per participant). Returns new record dicts
    in canonical (occurred_at, id) order with sender_daily_volume_minor,
    sender_daily_count and sender_window_burst_10m added. A future event can
    never influence an earlier record, regardless of input list order."""
    ordered = sorted(records, key=lambda r: (_parse_utc(r["occurred_at"]), r["id"]))
    events_by_sender: Dict[str, List[Tuple[datetime, int]]] = {}
    enriched: List[Dict[str, Any]] = []

    for r in ordered:
        t = _parse_utc(r["occurred_at"])
        sender = r["sender_ref"]
        amount = int(r["amount_minor"])
        events = events_by_sender.setdefault(sender, [])
        events.append((t, amount))  # current event included (<= its own time)

        win_24h = [a for (et, a) in events if t - timedelta(hours=24) <= et <= t]
        win_10m = [a for (et, a) in events if t - timedelta(minutes=10) <= et <= t]

        out = dict(r)
        out["sender_daily_volume_minor"] = sum(win_24h)
        out["sender_daily_count"] = len(win_24h)
        out["sender_window_burst_10m"] = len(win_10m)
        enriched.append(out)

    return enriched


FEATURE_COLUMNS = (
    "amount_minor_k_iqd",
    "sender_daily_volume_minor_k_iqd",
    "sender_daily_count",
    "sender_window_burst_10m",
    "is_after_hours",
    "structuring_ratio",
)


def records_to_matrix(records: List[Dict[str, Any]]) -> np.ndarray:
    """Feature matrix in FEATURE_SCHEMA_V2-compatible order (identical to the
    pre-R17 pipeline matrix construction)."""
    return np.array([
        [
            r["amount_minor"] / 1000.0,
            r["sender_daily_volume_minor"] / 1000.0,
            r["sender_daily_count"],
            r["sender_window_burst_10m"],
            r["is_after_hours"],
            r["structuring_ratio"],
        ]
        for r in records
    ])


def fit_feature_scaler(train_records: List[Dict[str, Any]]) -> StandardScaler:
    """Fit the feature scaler on TRAINING records only."""
    if not train_records:
        raise ValueError("cannot fit the feature scaler on an empty training set")
    scaler = StandardScaler()
    scaler.fit(records_to_matrix(train_records))
    return scaler


# ---------------------------------------------------------------------------
# Dataset generation (synthetic, pinned seed — unchanged statistical shape)
# ---------------------------------------------------------------------------

def generate_benchmark_dataset(
    seed: int = 42,
    num_records: int = 5000,
    num_senders: int = 150,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Generates synthetic but statistically realistic IQD banking transactions.
    Enforces seed determinism and returns (records, dataset_sha256).
    Historical window features are derived via derive_historical_features
    (shared implementation — a future event cannot influence an earlier
    record). The dataset remains SYNTHETIC and is described as such.
    """
    random.seed(seed)
    np.random.seed(seed)

    base_time = datetime(2026, 1, 1, 6, 0, 0, tzinfo=timezone.utc)
    senders = [f"ACC-IQD-SND-{i:04d}" for i in range(1, num_senders + 1)]
    receivers = [f"ACC-IQD-RCV-{i:04d}" for i in range(1, 300)]

    raw = []
    for i in range(1, num_records + 1):
        sender = random.choice(senders)
        receiver = random.choice(receivers)
        tx_time = base_time + timedelta(minutes=i * 5 + random.randint(0, 3))

        rand_type = random.random()
        is_fraud = 0

        if rand_type < 0.82:
            # Benign normal transfers: 50,000 to 4,000,000 IQD (scale 3)
            amount_iqd = random.uniform(50_000, 4_000_000)
            is_after_hours = 1 if (tx_time.hour < 5 or tx_time.hour >= 14) else 0
        elif rand_type < 0.90:
            # Structuring / Smurfing: 13,000,000 to 14,900,000 IQD
            amount_iqd = random.uniform(13_000_000, 14_900_000)
            is_after_hours = random.choice([0, 1])
            is_fraud = 1
        elif rand_type < 0.95:
            # Velocity burst / smurfing rapid fire
            amount_iqd = random.uniform(2_000_000, 6_000_000)
            is_after_hours = 0
            is_fraud = 1
        else:
            # Massive single transfer exceeding ceiling: 20M - 60M IQD
            amount_iqd = random.uniform(20_000_000, 60_000_000)
            is_after_hours = 1
            is_fraud = 1

        amount_minor = int(round(amount_iqd * 1000))
        structuring_ratio = round(amount_minor / 15_000_000_000, 4)

        raw.append({
            "id": f"TX-BENCH-{i:06d}",
            "sender_ref": sender,
            "receiver_ref": receiver,
            "occurred_at": tx_time.isoformat(),
            "amount_minor": amount_minor,
            "currency": "IQD",
            "scale": 3,
            "is_after_hours": is_after_hours,
            "structuring_ratio": structuring_ratio,
            "is_sar_reportable": is_fraud,
        })

    records = derive_historical_features(raw)

    # Compute canonical dataset hash — byte-identical serialization to the
    # pre-R17 generator (sort_keys, default separators, generation order ==
    # canonical time order), so the same seed/size yields the same dataset
    # hash recorded in the T19 manifest.
    dataset_canonical = json.dumps(
        [
            {k: r[k] for k in sorted(r.keys())}
            for r in records
        ],
        sort_keys=True
    ).encode("utf-8")
    dataset_hash = _sha256_hex(dataset_canonical)

    return records, dataset_hash


# ---------------------------------------------------------------------------
# Rules baseline
# ---------------------------------------------------------------------------

def evaluate_rules_baseline(records: List[Dict[str, Any]],
                            min_score: float = 50.0) -> Tuple[List[int], List[float], List[float]]:
    """Evaluates the deterministic regulatory rule-matrix against holdout data."""
    preds = []
    scores = []
    latencies = []

    for r in records:
        t0 = time.perf_counter()
        score = 5.0

        if r["structuring_ratio"] >= 1.0 or r["amount_minor"] >= 15_000_000_000:
            score += 30.0
        if 0.85 <= r["structuring_ratio"] < 1.0:
            score += 35.0
        if r["sender_daily_volume_minor"] >= 75_000_000_000:
            score += 25.0
        if r["sender_daily_count"] >= 20:
            score += 20.0
        if r["sender_window_burst_10m"] >= 3:
            score += 20.0
        if r["is_after_hours"]:
            score += 15.0

        final_score = min(100.0, score)
        pred = 1 if final_score >= min_score else 0
        lat_ms = (time.perf_counter() - t0) * 1000.0

        preds.append(pred)
        scores.append(round(final_score / 100.0, 4))
        latencies.append(lat_ms)

    return preds, scores, latencies


# ---------------------------------------------------------------------------
# Experiment suite
# ---------------------------------------------------------------------------

def _write_json(path: Path, doc: Dict[str, Any]) -> None:
    with open(str(path), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)


def run_experiment_suite(config_path: str,
                         seed: Optional[int] = None,
                         max_records: Optional[int] = None,
                         results_dir: Optional[str] = None) -> Dict[str, Any]:
    """Executes the empirical pipeline under the R17 strict-split regime.

    All bounds (cutoffs, minimum split size, class requirement, thresholds,
    gates) come from research/protocol.json — the single configuration source.
    Cutoffs are fixed in config before training and are never derived from
    labels or from result quality.
    """
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    config_bytes = json.dumps(config, sort_keys=True).encode("utf-8")
    config_hash = _sha256_hex(config_bytes)

    splits_cfg = config["splits"]
    train_end = _parse_utc(splits_cfg["train_end"], "splits.train_end")
    validation_end = _parse_utc(splits_cfg["validation_end"],
                                "splits.validation_end")
    min_split_size = int(splits_cfg.get("min_split_size", 100))
    require_both_classes = bool(splits_cfg.get("require_both_classes", True))
    if splits_cfg.get("random_split_fallback_allowed", False):
        raise ValueError("protocol.json must never enable a random-split fallback")

    seed = int(seed) if seed is not None else int(config.get("default_seed", 42))
    num_records = int(max_records) if max_records else int(
        config.get("dataset", {}).get("total_records", 5000))

    print(f"[*] Running Experiment Suite with Seed {seed} "
          f"(records={num_records}, strict temporal/participant-disjoint splits)...")
    records, dataset_hash = generate_benchmark_dataset(seed=seed,
                                                       num_records=num_records)

    run_id = f"EXP-AML-{seed}-{int(time.time())}"
    base_results = Path(results_dir) if results_dir else (ROOT_DIR / "research" / "results")
    run_dir = base_results / "runs" / run_id
    os.makedirs(run_dir, exist_ok=True)

    environment = collect_environment()
    code_revision = _git_short_revision()
    policy_version = next(
        (m.get("policy_id", "DEMO-IQD-1") for m in config.get("models", [])
         if m.get("type") == "RULES_BASELINE"), "DEMO-IQD-1")

    base_manifest = {
        "experiment_id": run_id,
        "protocol_version": config.get("protocol_version", "unknown"),
        "dataset_hash": dataset_hash,
        "code_revision": code_revision,
        "config_hash": config_hash,
        "config_path": str(Path(config_path).name),
        "seed": seed,
        "policy_version": policy_version,
        "engine_version": ENGINE_VERSION,
        "environment": environment,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_nature": "synthetic",
        "identifier_source": (
            "generate_benchmark_dataset(seed=...) synthetic generator: record ids "
            "TX-BENCH-%06d, senders ACC-IQD-SND-%04d (NOT institutional data)"),
        "dataset_size": {"requested": num_records, "generated": len(records)},
        "max_records": max_records,
    }

    # ---- strict partition (fail-closed) -----------------------------------
    try:
        split_manifest = partition_splits(
            records, train_end, validation_end, seed=seed,
            min_split_size=min_split_size,
            require_both_classes=require_both_classes)
    except SplitValidationError as exc:
        rejected = exc.split_manifest
        sizes = {name: 0 for name in ("train", "validation", "test")}
        drop_summary: Dict[str, int] = {}
        if rejected is not None:
            _write_json(run_dir / "split-manifest.json", rejected.serialized())
            sizes = {name: len(rejected.splits[name].record_ids)
                     for name in ("train", "validation", "test")}
            drop_summary = rejected.drop_summary
        rejected_hash = rejected.manifest_hash if rejected is not None else "0x" + "0" * 64
        run_manifest = dict(base_manifest)
        run_manifest.update({
            "split_hash": rejected_hash,
            "split_manifest": {
                "manifest_hash": rejected_hash,
                "accepted": False,
                "record_counts": sizes,
                "drop_summary": drop_summary,
            },
            "outcome": "INSUFFICIENT_DATA",
            "insufficient_data": {
                "reason": str(exc),
                "split_sizes": sizes,
                "drop_summary": drop_summary,
                "validation_errors": list(exc.violations),
            },
        })
        _write_json(run_dir / "run-manifest.json", run_manifest)
        _write_insufficient_readme(run_dir / "README.md", run_manifest)
        print("\n[OUTCOME] INSUFFICIENT_DATA — strict temporal/participant-disjoint "
              "partitioning did not leave viable evaluation splits.")
        print(f"    Reason: {exc}")
        print(f"    Run artifacts -> {run_dir}")
        return {"outcome": "INSUFFICIENT_DATA", "run_dir": run_dir,
                "run_manifest": run_manifest}

    _write_json(run_dir / "split-manifest.json", split_manifest.serialized())
    validate_splits(split_manifest, records)  # defense in depth; must pass

    train_set = split_manifest.records("train")
    val_set = split_manifest.records("validation")
    test_set = split_manifest.records("test")
    print(f"    Train: {len(train_set)} | Val: {len(val_set)} | "
          f"Test (Holdout): {len(test_set)} | Dropped: {len(split_manifest.dropped)}")

    thresholds = config.get("activation_policy", {}).get("decision_thresholds", {})
    rules_min_score = float(thresholds.get("rules_min_score", 50.0))
    hybrid_min_score = float(thresholds.get("hybrid_min_score", 0.45))

    # Features are scaled with statistics fit on TRAIN ONLY; every historical
    # feature was derived without reading any event after the record's time.
    scaler = fit_feature_scaler(train_set)
    X_train = scaler.transform(records_to_matrix(train_set))
    X_test = scaler.transform(records_to_matrix(test_set))
    y_test = [r[LABEL_COLUMN] for r in test_set]

    # 1. Rules-Only Baseline
    rules_preds, rules_scores, rules_lats = evaluate_rules_baseline(
        test_set, min_score=rules_min_score)
    rules_metrics = compute_metrics(y_test, rules_preds, rules_scores, rules_lats)

    # 2. ML-Only (Isolation Forest) — hyperparameters from protocol.json
    ml_cfg = next(m for m in config["models"] if m.get("name") == "ml_isolation_forest")
    ml_params = dict(ml_cfg.get("hyperparameters", {}))
    model = IsolationForest(random_state=seed, **ml_params)
    model.fit(X_train)

    ml_lats = []
    ml_preds = []
    ml_scores = []
    for row in X_test:
        t0 = time.perf_counter()
        raw_pred = model.predict([row])[0]
        anomaly_score = -float(model.score_samples([row])[0])
        lat_ms = (time.perf_counter() - t0) * 1000.0
        ml_preds.append(1 if raw_pred == -1 else 0)
        ml_scores.append(round(anomaly_score, 4))
        ml_lats.append(lat_ms)

    ml_metrics = compute_metrics(y_test, ml_preds, ml_scores, ml_lats)

    # 3. Hybrid Ensemble — weights/threshold frozen in config BEFORE test
    hybrid_cfg = next(m for m in config["models"] if m.get("name") == "hybrid_ensemble")
    rule_weight = float(hybrid_cfg.get("rule_weight", 0.60))
    ml_weight = float(hybrid_cfg.get("ml_weight", 0.40))

    hybrid_preds = []
    hybrid_scores = []
    hybrid_lats = []
    for r_score, m_score, r_lat, m_lat in zip(rules_scores, ml_scores,
                                              rules_lats, ml_lats):
        combined_score = (rule_weight * r_score) + (ml_weight * m_score)
        pred = 1 if combined_score >= hybrid_min_score else 0
        hybrid_preds.append(pred)
        hybrid_scores.append(round(combined_score, 4))
        hybrid_lats.append(r_lat + m_lat)

    hybrid_metrics = compute_metrics(y_test, hybrid_preds, hybrid_scores, hybrid_lats)

    # Model artifact + meta (hash recorded; meta carries ACTUAL versions)
    model_dir = ROOT_DIR / "ai-engine" / "models" / "pretrained"
    os.makedirs(model_dir, exist_ok=True)
    model_path = model_dir / "fraud_model.joblib"
    joblib.dump(model, str(model_path))
    model_hash = compute_file_sha256(str(model_path))
    model_meta = {
        "model_hash": model_hash,
        "feature_schema": FEATURE_SCHEMA_V2,
        "training_dataset_hash": dataset_hash,
        "split_manifest_hash": split_manifest.manifest_hash,
        "library_versions": {
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "joblib": joblib.__version__,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metrics": hybrid_metrics,
    }
    with open(str(model_path) + ".meta.json", "w", encoding="utf-8") as f:
        json.dump(model_meta, f, indent=2)

    # Verdict computed from the acceptance gates — never hardcoded.
    gates = config.get("acceptance_gates", {})
    supported = (
        hybrid_metrics["recall"] >= gates.get("min_recall", 0.85)
        and hybrid_metrics["fpr_per_1000"] <= gates.get("max_fpr_per_1000", 50.0)
        and hybrid_metrics["pr_auc"] >= gates.get("min_pr_auc", 0.80)
        and hybrid_metrics["latency_p95_ms"] <= gates.get("max_latency_p95_ms", 25.0)
    )
    outcome = "SUPPORTED" if supported else "FAILED"

    run_manifest = dict(base_manifest)
    run_manifest.update({
        "split_hash": split_manifest.manifest_hash,
        "split_manifest": {
            "manifest_hash": split_manifest.manifest_hash,
            "accepted": True,
            "record_counts": {name: len(split_manifest.splits[name].record_ids)
                              for name in ("train", "validation", "test")},
            "drop_summary": split_manifest.drop_summary,
        },
        "outcome": outcome,
        "metrics": {
            "precision": hybrid_metrics["precision"],
            "recall": hybrid_metrics["recall"],
            "f1_score": hybrid_metrics["f1_score"],
            "pr_auc": hybrid_metrics["pr_auc"],
            "fpr_per_1000": hybrid_metrics["fpr_per_1000"],
        },
        "metrics_by_model": {"rules_only": rules_metrics,
                             "ml_isolation_forest": ml_metrics,
                             "hybrid_ensemble": hybrid_metrics},
        "model_hash": model_hash,
    })
    _write_json(run_dir / "run-manifest.json", run_manifest)
    _write_accepted_readme(run_dir / "README.md", run_manifest, rules_metrics,
                           ml_metrics, hybrid_metrics, gates)

    print(f"\n[OUTCOME] {outcome}")
    print(f"    Hybrid Metrics: Precision={hybrid_metrics['precision']}, "
          f"Recall={hybrid_metrics['recall']}, F1={hybrid_metrics['f1_score']}")
    print(f"    Run artifacts -> {run_dir}")
    return {"outcome": outcome, "run_dir": run_dir, "run_manifest": run_manifest}


def _write_insufficient_readme(path: Path, run_manifest: Dict[str, Any]) -> None:
    info = run_manifest["insufficient_data"]
    lines = [
        "# Empirical Evaluation Run — INSUFFICIENT_DATA",
        "",
        f"**Protocol:** `research/protocol.json` "
        f"(protocol_version {run_manifest.get('protocol_version')}) | "
        f"**Run:** `{run_manifest['experiment_id']}`",
        f"**Config hash:** `{run_manifest['config_hash']}`",
        f"**Dataset hash (synthetic):** `{run_manifest['dataset_hash']}` "
        f"({run_manifest['dataset_size']['generated']} records)",
        "",
        "## Outcome: INSUFFICIENT_DATA",
        "",
        "Strict temporal + participant-disjoint partitioning (R17 policy) did not "
        "leave viable evaluation splits, so the acceptance gates were NOT evaluated "
        "and the hybrid ensemble is NOT activated. The rules-only baseline remains "
        "the operative detector. No metrics are recorded for this run because no "
        "admissible holdout evaluation exists.",
        "",
        f"**Reason:** {info['reason']}",
        "",
        "## Split sizes (rejected split manifest)",
        "",
        "| Split | Records |",
        "|---|---|",
        "\n".join(f"| {k} | {v} |" for k, v in info["split_sizes"].items()),
        "",
        "## Drop summary",
        "",
        "| Drop reason | Count |",
        "|---|---|",
        "\n".join(f"| {k} | {v} |" for k, v in info["drop_summary"].items()) or
        "| (none) | 0 |",
        "",
        "This negative result is recorded as produced: it is NOT a model failure "
        "verdict and NOT a pass. The synthetic generator assigns senders uniformly "
        "across the whole timeline, so under honest temporal/participant separation "
        "essentially every sender is a train participant and no participant is "
        "eligible for the evaluation windows.",
        "",
        f"**Environment:** Python {run_manifest['environment']['python_version']}, "
        f"NumPy {run_manifest['environment']['numpy_version']}, "
        f"scikit-learn {run_manifest['environment']['scikit_learn_version']}, "
        f"{run_manifest['environment']['os']}",
    ]
    with open(str(path), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _write_accepted_readme(path: Path, run_manifest: Dict[str, Any],
                           rules_metrics: Dict[str, Any],
                           ml_metrics: Dict[str, Any],
                           hybrid_metrics: Dict[str, Any],
                           gates: Dict[str, Any]) -> None:
    verdict = run_manifest["outcome"]
    lines = [
        "# Empirical Evaluation Run (strict splits)",
        "",
        f"**Protocol:** `research/protocol.json` "
        f"(protocol_version {run_manifest.get('protocol_version')}) | "
        f"**Run:** `{run_manifest['experiment_id']}` | **Outcome:** {verdict}",
        f"**Dataset hash (synthetic):** `{run_manifest['dataset_hash']}`",
        f"**Split manifest hash:** `{run_manifest['split_hash']}`",
        f"**Model hash:** `{run_manifest['model_hash']}`",
        "",
        "## Comparative Performance Matrix (Holdout Test Partition, "
        "temporal + participant-disjoint)",
        "",
        "| Model Configuration | Precision | Recall | F1-Score | PR-AUC | "
        "FPR per 1,000 | Latency p95 (ms) |",
        "|---|---|---|---|---|---|---|",
        f"| **Rules-Only Baseline** | {rules_metrics['precision']:.4f} | "
        f"{rules_metrics['recall']:.4f} | {rules_metrics['f1_score']:.4f} | "
        f"{rules_metrics['pr_auc']:.4f} | {rules_metrics['fpr_per_1000']:.2f} | "
        f"{rules_metrics['latency_p95_ms']:.2f} |",
        f"| **ML-Only (Isolation Forest)** | {ml_metrics['precision']:.4f} | "
        f"{ml_metrics['recall']:.4f} | {ml_metrics['f1_score']:.4f} | "
        f"{ml_metrics['pr_auc']:.4f} | {ml_metrics['fpr_per_1000']:.2f} | "
        f"{ml_metrics['latency_p95_ms']:.2f} |",
        f"| **Hybrid Ensemble (Rules + ML)** | **{hybrid_metrics['precision']:.4f}** | "
        f"**{hybrid_metrics['recall']:.4f}** | **{hybrid_metrics['f1_score']:.4f}** | "
        f"**{hybrid_metrics['pr_auc']:.4f}** | **{hybrid_metrics['fpr_per_1000']:.2f}** | "
        f"**{hybrid_metrics['latency_p95_ms']:.2f}** |",
        "",
        "## Hypothesis Verification (computed from gates, not asserted)",
        "",
        f"- Recall = {hybrid_metrics['recall'] * 100:.1f}% "
        f"(gate >= {gates.get('min_recall', 0.85) * 100:.1f}%), "
        f"FPR = {hybrid_metrics['fpr_per_1000']} per 1,000 "
        f"(gate <= {gates.get('max_fpr_per_1000', 50.0)}), "
        f"PR-AUC = {hybrid_metrics['pr_auc']} "
        f"(gate >= {gates.get('min_pr_auc', 0.80)}), "
        f"p95 latency = {hybrid_metrics['latency_p95_ms']} ms "
        f"(gate <= {gates.get('max_latency_p95_ms', 25.0)} ms).",
        f"- Verdict: **{verdict}** (computed by comparing the hybrid metrics "
        f"against `acceptance_gates` in protocol.json).",
        "",
        "Thresholds and cutoffs were frozen in protocol.json before the test "
        "split was evaluated; no threshold was adjusted after seeing test data.",
        "",
        f"**Environment:** Python {run_manifest['environment']['python_version']}, "
        f"NumPy {run_manifest['environment']['numpy_version']}, "
        f"scikit-learn {run_manifest['environment']['scikit_learn_version']}, "
        f"{run_manifest['environment']['os']}",
    ]
    with open(str(path), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run empirical AML experiments")
    parser.add_argument("--config", default=str(ROOT_DIR / "research" / "protocol.json"))
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--max-records", type=int, default=None,
                        help="Short-run cap on generated records (recorded in the run manifest)")
    args = parser.parse_args()

    run_experiment_suite(args.config, seed=args.seed, max_records=args.max_records)
