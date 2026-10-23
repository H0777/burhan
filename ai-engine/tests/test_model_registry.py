"""
Unit Tests for Model Registry and Cryptographic Integrity Checks (T19)
Specification §6, §7 (R12, R13)
"""

import os
import json
import pytest
import joblib
from sklearn.ensemble import IsolationForest
import numpy as np

from app.models.registry import (
    load_validated_model,
    compute_file_sha256,
    FEATURE_SCHEMA_V2,
)


@pytest.fixture
def temp_model(tmp_path):
    """Generates a valid trained Isolation Forest artifact for testing."""
    model_path = str(tmp_path / "valid_model.joblib")
    meta_path = str(tmp_path / "valid_model.joblib.meta.json")

    X = np.random.RandomState(42).randn(100, 6)
    clf = IsolationForest(n_estimators=10, random_state=42)
    clf.fit(X)
    joblib.dump(clf, model_path)

    expected_hash = compute_file_sha256(model_path)
    metadata = {
        "model_hash": expected_hash,
        "feature_schema": FEATURE_SCHEMA_V2,
        "training_dataset_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "library_versions": {"scikit_learn": "1.9.1"},
        "created_at": "2026-10-23T12:00:00Z",
        "metrics": {"f1_score": 0.88, "pr_auc": 0.91},
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f)

    return model_path, meta_path, expected_hash


def test_missing_model_returns_not_loaded():
    status = load_validated_model("/nonexistent/path/model.joblib")
    assert not status.loaded
    assert "not found" in status.error_reason.lower()


def test_dummy_placeholder_marker_rejected(tmp_path):
    dummy_path = str(tmp_path / "dummy.joblib")
    with open(dummy_path, "wb") as f:
        f.write(b"OFFLINE_HEURISTIC_ENSEMBLE_V2")

    status = load_validated_model(dummy_path)
    assert not status.loaded
    assert "placeholder" in status.error_reason.lower()


def test_tampered_model_rejected_on_hash_mismatch(temp_model):
    model_path, meta_path, expected_hash = temp_model

    # Flip one byte in the model file
    with open(model_path, "r+b") as f:
        f.seek(10)
        byte = f.read(1)
        f.seek(10)
        f.write(bytes([byte[0] ^ 0xFF]))

    status = load_validated_model(model_path, expected_hash=expected_hash)
    assert not status.loaded
    assert "tampering detected" in status.error_reason.lower()
    assert status.model_hash != expected_hash


def test_valid_model_loads_successfully(temp_model):
    model_path, meta_path, expected_hash = temp_model

    status = load_validated_model(model_path, expected_hash=expected_hash)
    assert status.loaded
    assert status.model is not None
    assert status.model_hash == expected_hash
    assert status.feature_schema == FEATURE_SCHEMA_V2
    assert status.metadata is not None
    assert status.metadata.metrics["f1_score"] == 0.88

    # Verify model makes predictions
    pred = status.model.predict(np.zeros((1, 6)))
    assert len(pred) == 1


def test_mismatched_feature_schema_rejected(temp_model):
    model_path, meta_path, expected_hash = temp_model

    # Corrupt feature schema in metadata
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    meta["feature_schema"] = ["wrong_field_1", "wrong_field_2"]
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f)

    status = load_validated_model(model_path, expected_hash=expected_hash, enforce_schema=True)
    assert not status.loaded
    assert "feature schema mismatch" in status.error_reason.lower()


def test_corrupt_unpicklable_file_rejected(tmp_path):
    corrupt_path = str(tmp_path / "corrupt.joblib")
    with open(corrupt_path, "wb") as f:
        f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09GARBAGE")

    status = load_validated_model(corrupt_path)
    assert not status.loaded
    assert "deserialization failure" in status.error_reason.lower()
