"""
End-to-End API Integration Tests for FastAPI Application
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "capabilities" in data
    assert data["capabilities"]["local_ml"] is True
    assert data["capabilities"]["forensic_reports"] is True


def test_risk_score_endpoint():
    payload = {
        "amount": 9500.0,
        "sender_daily_volume": 12000.0,
        "sender_daily_count": 3,
        "is_after_hours": False,
        "large_threshold": 10000.0,
        "daily_volume_limit": 50000.0,
        "max_daily_transactions": 20,
        "is_kyc_verified": True
    }
    response = client.post("/api/v1/risk/score", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "fraud_score" in data
    assert "risk_level" in data
    assert "risk_factors" in data
    assert data["fraud_score"] >= 20.0


def test_batch_risk_score_endpoint():
    payload = {
        "transactions": [
            {
                "amount": 100.0,
                "sender_daily_volume": 200.0,
                "sender_daily_count": 1,
                "is_after_hours": False,
                "is_kyc_verified": True
            },
            {
                "amount": 9800.0,
                "sender_daily_volume": 15000.0,
                "sender_daily_count": 2,
                "is_after_hours": False,
                "is_kyc_verified": True
            }
        ]
    }
    response = client.post("/api/v1/risk/batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_evaluated"] == 2
    assert len(data["results"]) == 2
    # Verify sorted by fraud score descending
    assert data["results"][0]["fraud_score"] >= data["results"][1]["fraud_score"]


def test_insider_analyze_endpoint():
    payload = {
        "operator_address": "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
        "total_actions": 12,
        "override_count": 6,  # > 5 alert threshold
        "after_hours_count": 1,
        "flag_count": 1,
        "max_beneficiary_approvals": 3
    }
    response = client.post("/api/v1/insider/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["operator_address"] == payload["operator_address"]
    assert "insider_threat_score" in data
    assert data["threat_level"] in ("HIGH", "CRITICAL")
    assert len(data["indicators"]) > 0


def test_contract_scan_endpoint():
    payload = {
        "contract_name": "TestToken",
        "code": """
        pragma solidity ^0.8.0;
        contract TestToken {
            address public admin;
            function withdraw() external {
                require(tx.origin == admin);
            }
        }
        """
    }
    response = client.post("/api/v1/contract/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["contract_name"] == "TestToken"
    assert data["passed_audit"] is False
    assert len(data["findings"]) > 0


def test_forensic_report_endpoint():
    payload = {
        "incident_id": 42,
        "title": "Collusion and Structuring Dossier",
        "severity": "CRITICAL",
        "reported_by": "0xLeadAuditor",
        "evidence_chain": [
            {
                "id": 1,
                "submittedBy": "0x111",
                "evidenceType": "STRUCTURING",
                "entryHash": "0xhash1",
                "previousEntryHash": "0x000"
            }
        ],
        "language": "en"
    }
    response = client.post("/api/v1/forensic/report", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == 42
    assert "report_markdown" in data
    assert data["chain_integrity_valid"] is True


def test_chain_verification_endpoint():
    payload = {
        "evidence_chain": [
            {"id": 1, "entryHash": "0x111", "previousEntryHash": "0x000"},
            {"id": 2, "entryHash": "0x222", "previousEntryHash": "0x111"},
            {"id": 3, "entryHash": "0x333", "previousEntryHash": "0x222"}
        ]
    }
    response = client.post("/api/v1/forensic/verify-chain", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert data["status"] == "CHAIN_INTEGRITY_VERIFIED"
