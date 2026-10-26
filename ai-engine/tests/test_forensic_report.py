"""
Unit tests for Forensic Report & Chain Verification
"""

import pytest
from app.services.gemini_service import gemini_service


def test_generate_forensic_report_english():
    evidence_chain = [
        {
            "id": 1,
            "submittedBy": "0x1234567890123456789012345678901234567890",
            "evidenceType": "TRANSACTION_ANOMALY",
            "entryHash": "0xaaaa1111",
            "previousEntryHash": "0x00000000"
        },
        {
            "id": 2,
            "submittedBy": "0x1234567890123456789012345678901234567890",
            "evidenceType": "INSIDER_OVERRIDE",
            "entryHash": "0xbbbb2222",
            "previousEntryHash": "0xaaaa1111"
        }
    ]

    report = gemini_service.generate_forensic_report(
        incident_id=1,
        title="Smurfing & Warning Override Investigation",
        severity="HIGH",
        reported_by="0xAdminLeadInvestigator",
        evidence_chain=evidence_chain,
        language="en"
    )

    assert report["incident_id"] == 1
    assert report["chain_integrity_valid"] is True
    assert "Digital Forensic & Financial Audit Report" in report["report_markdown"]
    assert report["dossier_hash"] is not None


def test_generate_forensic_report_arabic():
    evidence_chain = [
        {
            "id": 1,
            "submittedBy": "0x1111",
            "evidenceType": "AML_FLAG",
            "entryHash": "0xhash1",
            "previousEntryHash": "0x0000"
        }
    ]

    report = gemini_service.generate_forensic_report(
        incident_id=2,
        title="قضية غسيل أموال وتجاوز صلاحيات",
        severity="CRITICAL",
        reported_by="0xLeadInvestigator",
        evidence_chain=evidence_chain,
        language="ar"
    )

    assert report["incident_id"] == 2
    assert "تقرير التحقيق الجنائي الرقمي والتدقيق المالي" in report["report_markdown"]
    assert "البنك المركزي العراقي" in report["report_markdown"]


def test_broken_chain_detection():
    broken_chain = [
        {
            "id": 1,
            "entryHash": "0xhash_1",
            "previousEntryHash": "0x0000"
        },
        {
            "id": 2,
            "entryHash": "0xhash_2",
            "previousEntryHash": "0xTAMPERED_HASH"  # Mismatch! Should be 0xhash_1
        }
    ]

    report = gemini_service.generate_forensic_report(
        incident_id=3,
        title="Tampered Evidence Case",
        severity="CRITICAL",
        reported_by="0xAuditor",
        evidence_chain=broken_chain,
        language="en"
    )

    assert report["chain_integrity_valid"] is False
    assert "COMPROMISED" in report["report_markdown"]
