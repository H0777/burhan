"""
Unit tests for InsiderThreatAnalyzer (Behavioral Anomaly Model)
"""

import pytest
from app.models.insider_analyzer import InsiderThreatAnalyzer, OperatorActivityMetrics


def test_benign_operator_profile():
    analyzer = InsiderThreatAnalyzer()
    metrics = OperatorActivityMetrics(
        operator_address="0x1111111111111111111111111111111111111111",
        total_actions=20,
        override_count=0,
        after_hours_count=0,
        flag_count=0,
        max_beneficiary_approvals=2
    )
    result = analyzer.analyze(metrics)
    assert result["threat_level"] == "LOW"
    assert result["insider_threat_score"] == 0.0
    assert result["recommended_action"] == "NORMAL_MONITORING"


def test_excessive_overrides_detection():
    analyzer = InsiderThreatAnalyzer()
    metrics = OperatorActivityMetrics(
        operator_address="0x2222222222222222222222222222222222222222",
        total_actions=10,
        override_count=7,  # > 5 threshold
        after_hours_count=0,
        flag_count=1,
        max_beneficiary_approvals=2
    )
    result = analyzer.analyze(metrics)
    indicators = [ind["indicator"] for ind in result["indicators"]]
    assert "EXCESSIVE_COMPLIANCE_OVERRIDES" in indicators
    assert result["insider_threat_score"] >= 45.0
    assert result["threat_level"] in ("HIGH", "CRITICAL")


def test_beneficiary_collusion_suspicion():
    analyzer = InsiderThreatAnalyzer()
    metrics = OperatorActivityMetrics(
        operator_address="0x3333333333333333333333333333333333333333",
        total_actions=15,
        override_count=1,
        after_hours_count=0,
        flag_count=0,
        max_beneficiary_approvals=12  # > 10 threshold
    )
    result = analyzer.analyze(metrics)
    indicators = [ind["indicator"] for ind in result["indicators"]]
    assert "BENEFICIARY_COLLUSION_SUSPICION" in indicators
    assert result["insider_threat_score"] >= 30.0


def test_habitual_after_hours_activity():
    analyzer = InsiderThreatAnalyzer()
    metrics = OperatorActivityMetrics(
        operator_address="0x4444444444444444444444444444444444444444",
        total_actions=10,
        override_count=0,
        after_hours_count=5,  # > 3 threshold
        flag_count=0,
        max_beneficiary_approvals=1
    )
    result = analyzer.analyze(metrics)
    indicators = [ind["indicator"] for ind in result["indicators"]]
    assert "HABITUAL_AFTER_HOURS_ACTIVITY" in indicators
    assert result["insider_threat_score"] >= 25.0


def test_rubber_stamping_and_reversal():
    analyzer = InsiderThreatAnalyzer()
    metrics = OperatorActivityMetrics(
        operator_address="0x5555555555555555555555555555555555555555",
        total_actions=8,
        override_count=2,
        after_hours_count=0,
        flag_count=0,
        max_beneficiary_approvals=2,
        rapid_approval_count=4,
        reversed_decisions_count=1
    )
    result = analyzer.analyze(metrics)
    indicators = [ind["indicator"] for ind in result["indicators"]]
    assert "RUBBER_STAMPING_APPROVALS" in indicators
    assert "DECISION_REVERSAL_ANOMALY" in indicators
