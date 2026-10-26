"""
Unit tests for FraudDetector (Local AML/ML Model)
"""

import pytest
from app.models.fraud_detector import FraudDetector, TransactionFeatures


def test_normal_transaction():
    detector = FraudDetector()
    features = TransactionFeatures(
        amount=150.0,
        sender_daily_volume=300.0,
        sender_daily_count=2,
        is_after_hours=False,
        is_kyc_verified=True
    )
    result = detector.calculate_risk(features)
    assert result["risk_level"] == "LOW"
    assert result["fraud_score"] < 25.0
    assert result["recommendation"] == "AUTO_CLEAR"


def test_structuring_detection():
    detector = FraudDetector()
    # Amount is 9,500 ETH (95% of 10,000 threshold -> structuring flag)
    features = TransactionFeatures(
        amount=9500.0,
        sender_daily_volume=9500.0,
        sender_daily_count=1,
        is_after_hours=False,
        is_kyc_verified=True,
        large_threshold=10000.0
    )
    result = detector.calculate_risk(features)
    factor_names = [f["factor"] for f in result["risk_factors"]]
    assert "STRUCTURING_SUSPICION" in factor_names
    assert result["fraud_score"] >= 25.0


def test_unverified_high_value():
    detector = FraudDetector()
    # High value 6,000 ETH with KYC not verified
    features = TransactionFeatures(
        amount=6000.0,
        sender_daily_volume=6000.0,
        sender_daily_count=1,
        is_after_hours=False,
        is_kyc_verified=False,
        large_threshold=10000.0
    )
    result = detector.calculate_risk(features)
    factor_names = [f["factor"] for f in result["risk_factors"]]
    assert "UNVERIFIED_HIGH_VALUE" in factor_names
    assert result["fraud_score"] >= 30.0


def test_daily_volume_exceeded():
    detector = FraudDetector()
    features = TransactionFeatures(
        amount=5000.0,
        sender_daily_volume=48000.0,  # 48k + 5k = 53k > 50k limit
        sender_daily_count=5,
        is_after_hours=False,
        is_kyc_verified=True,
        daily_volume_limit=50000.0
    )
    result = detector.calculate_risk(features)
    factor_names = [f["factor"] for f in result["risk_factors"]]
    assert "DAILY_VOLUME_EXCEEDED" in factor_names
    assert result["fraud_score"] >= 30.0


def test_after_hours_flag():
    detector = FraudDetector()
    features = TransactionFeatures(
        amount=200.0,
        sender_daily_volume=500.0,
        sender_daily_count=2,
        is_after_hours=True,
        is_kyc_verified=True
    )
    result = detector.calculate_risk(features)
    factor_names = [f["factor"] for f in result["risk_factors"]]
    assert "AFTER_HOURS_ACTIVITY" in factor_names
