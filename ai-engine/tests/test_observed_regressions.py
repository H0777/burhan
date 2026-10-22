"""
Security Regressions Baseline Reproduction (T01)
Demonstrates:
1. altered_content_claimed_verified: A modified evidence content claiming to be verified.
2. frontend_payload_mismatch: Incompatible payload sent from UI without strict schema validation.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_altered_content_claimed_verified_should_be_rejected():
    """
    R04: Independent verification MUST recompute content hash and reject altered evidence.
    If the service marks altered evidence as verified, this test fails.
    """
    tampered_evidence = [{
        "id": 1,
        "submittedBy": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "evidenceType": "SUSPICIOUS_TX",
        "description": "Altered evidence text that was modified post-hoc",
        "entryHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "previousEntryHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
    }]

    response = client.post("/api/v1/forensic/report", json={
        "incident_id": 1,
        "title": "Tampered Evidence Audit",
        "reported_by": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "evidence_chain": tampered_evidence,
        "severity": "CRITICAL"
    })
    assert response.status_code == 200
    data = response.json()
    # In legacy v1, gemini_service claims VALID & UNALTERED even though content is completely unverified against on-chain anchor!
    # Expected secure behavior: must NOT declare it cryptographically verified or valid!
    report_text = data.get("report_markdown", "")
    assert "VALID & UNALTERED (Cryptographically Verified)" not in report_text, (
        "Security Regression: Unverified tampered evidence was falsely claimed as 'VALID & UNALTERED (Cryptographically Verified)'"
    )


def test_frontend_payload_mismatch_should_be_rejected():
    """
    R06: API schemas must strictly reject malformed or extra unexpected fields with 422.
    """
    # Sending invalid data type for amount (e.g. nested object or string that cannot parse as float)
    mismatched_payload = {
        "amount": "INVALID_AMOUNT_STRING",
        "receiver": "0x123",
        "unknown_extra_field_from_old_ui": 12345
    }
    response = client.post("/api/v1/risk/score", json=mismatched_payload)
    # Pydantic validation must reject this with 422
    assert response.status_code == 422
