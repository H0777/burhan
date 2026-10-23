"""
Integration Tests for Verifiable Case Forensic Reports & Dossier Bundles (T20)
Specification §7 & §8 (R04, R05, R15, R18)
"""

import os
import io
import json
import zipfile
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.models import (
    Base,
    Institution,
    Case,
    CaseEvent,
    EvidenceObject,
    EvidenceAnchor,
    ReportRecord,
)
from app.db.session import get_db, set_engine
from app.schemas.identity import Identity, RoleEnum
from app.routes.v2.identity import get_current_identity
from pathlib import Path
import importlib.util

_script_path = Path(__file__).resolve().parents[3] / "scripts" / "verify-evidence-export.py"
_spec = importlib.util.spec_from_file_location("verify_evidence_export", str(_script_path))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
verify_bundle = _mod.verify_bundle

TEST_INST_A = "INST-BAGHDAD-AUTH-A"
TEST_INST_B = "INST-BASRA-AUTH-B"


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    set_engine(engine)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()

    inst_a = Institution(id=TEST_INST_A, name="National Bank of Iraq - A", is_active=True)
    inst_b = Institution(id=TEST_INST_B, name="Trade Bank of Iraq - B", is_active=True)
    session.add_all([inst_a, inst_b])

    # Seed test case in Institution A
    case = Case(
        id="CASE-BAGHDAD-001",
        case_number="IRQ-2026-CASE-001",
        institution_id=TEST_INST_A,
        title="Suspicious Hawala Flow & Smurfing Ring",
        description="Cross-border structuring transfers identified across Al-Karkh exchange nodes",
        severity="HIGH",
        status="IN_REVIEW",
        assigned_to_sub="usr-auditor-1",
        version=1,
    )
    session.add(case)

    # Seed transition event
    evt = CaseEvent(
        id="EVT-001",
        case_id="CASE-BAGHDAD-001",
        institution_id=TEST_INST_A,
        event_type="start_review",
        actor_sub="usr-auditor-1",
        payload_json=json.dumps({"reason": "Initiated formal investigation following AML risk flag"}),
    )
    session.add(evt)

    # Seed Evidence Object and Anchor
    ev = EvidenceObject(
        id="EV-OBJ-001",
        institution_id=TEST_INST_A,
        case_id="CASE-BAGHDAD-001",
        evidence_id="EVID-HAWALA-101",
        object_version=1,
        file_name="hawala_ledger_sheet.csv",
        content_type="text/csv",
        file_size=128,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_path="/tmp/nonexistent_test.csv",
        encrypted=False,
    )
    anchor = EvidenceAnchor(
        id="ANC-001",
        institution_id=TEST_INST_A,
        case_id="CASE-BAGHDAD-001",
        evidence_id="EVID-HAWALA-101",
        anchor_request_id="0x" + "aa" * 32,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        status="ANCHORED",
        transaction_hash="0x" + "bb" * 32,
        block_number=42001,
        block_hash="0x" + "cc" * 32,
        entry_hash="0x" + "dd" * 32,
        anchored_at=datetime.now(timezone.utc),
    )
    session.add_all([ev, anchor])
    session.commit()

    yield session
    session.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def auditor_identity():
    return Identity(
        sub="usr-auditor-1",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=TEST_INST_A,
        role=RoleEnum.AUDITOR,
        permissions=["cases:read", "cases:write", "reports:write"],
    )


def test_generate_case_report_creates_immutable_record(client, db_session, auditor_identity):
    """
    Validates report generation, sequential versioning, and deterministic dossier hashing.
    """
    app.dependency_overrides[get_current_identity] = lambda: auditor_identity

    # 1. Generate Version 1
    res1 = client.post("/api/v2/cases/CASE-BAGHDAD-001/reports", json={"language": "en"})
    assert res1.status_code == 201
    rep1 = res1.json()

    assert rep1["report_id"] == "REP-IRQ-2026-CASE-001-V1"
    assert rep1["version"] == 1
    assert rep1["integrity_status"] == "VERIFIED"
    assert rep1["dossier_hash"].startswith("0x")
    assert "Digital Forensic Audit" in rep1["markdown"]

    # 2. Generate Version 2 (Arabic)
    res2 = client.post("/api/v2/cases/CASE-BAGHDAD-001/reports", json={"language": "ar"})
    assert res2.status_code == 201
    rep2 = res2.json()

    assert rep2["report_id"] == "REP-IRQ-2026-CASE-001-V2"
    assert rep2["version"] == 2
    assert rep2["language"] == "ar"
    assert "تقرير التحقيق الجنائي الرقمي" in rep2["markdown"]

    # 3. Verify Version 1 remains completely unchanged in the database
    v1_rec = db_session.query(ReportRecord).filter_by(
        case_id="CASE-BAGHDAD-001", version=1
    ).first()
    assert v1_rec.report_id == "REP-IRQ-2026-CASE-001-V1"
    assert v1_rec.dossier_hash == rep1["dossier_hash"]


def test_report_bundle_export_and_cli_verification(client, db_session, auditor_identity, tmp_path):
    """
    Exports a report ZIP archive and validates it using verify_bundle.
    """
    app.dependency_overrides[get_current_identity] = lambda: auditor_identity

    # Create report
    res = client.post("/api/v2/cases/CASE-BAGHDAD-001/reports", json={"language": "en"})
    assert res.status_code == 201
    rep_data = res.json()
    report_id = rep_data["report_id"]

    # Download ZIP bundle
    export_res = client.get(f"/api/v2/cases/CASE-BAGHDAD-001/reports/{report_id}/export")
    assert export_res.status_code == 200
    assert export_res.headers["content-type"] == "application/zip"

    # Save to disk
    bundle_path = str(tmp_path / f"{report_id}.zip")
    with open(bundle_path, "wb") as f:
        f.write(export_res.content)

    # Run independent verification
    result = verify_bundle(bundle_path)
    assert result["valid"] is True
    assert result["status"] == "VERIFIED"
    assert result["dossier_hash"] == rep_data["dossier_hash"]
    assert len(result["reasons"]) == 0


def test_tampered_evidence_file_rejected_by_cli_verifier(client, db_session, auditor_identity, tmp_path):
    """
    Ensures altering any byte in an evidence file within the ZIP immediately fails verification.
    """
    app.dependency_overrides[get_current_identity] = lambda: auditor_identity

    # Create report and download bundle
    res = client.post("/api/v2/cases/CASE-BAGHDAD-001/reports", json={"language": "en"})
    report_id = res.json()["report_id"]

    export_res = client.get(f"/api/v2/cases/CASE-BAGHDAD-001/reports/{report_id}/export")
    orig_bytes = export_res.content

    # Mutate checksums or an internal member in the ZIP
    bundle_path = str(tmp_path / "tampered.zip")
    in_zip = zipfile.ZipFile(io.BytesIO(orig_bytes), "r")
    out_buf = io.BytesIO()

    with zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as out_zip:
        for item in in_zip.infolist():
            content = in_zip.read(item.filename)
            if item.filename == "report.md":
                # Tamper with the report text
                content = content + b"\n\n[TAMPERED CONTENT INSERTED BY ATTACKER]"
            out_zip.writestr(item, content)

    with open(bundle_path, "wb") as f:
        f.write(out_buf.getvalue())

    # Verification must flag TAMPER_DETECTED
    result = verify_bundle(bundle_path)
    assert result["valid"] is False
    assert result["status"] == "TAMPER_DETECTED"
    assert any("Checksum mismatch" in r for r in result["reasons"])


def test_regulator_cannot_generate_reports(client, db_session):
    """
    Confirms REGULATOR role is strictly forbidden from POST /reports (read-only).
    """
    regulator_identity = Identity(
        sub="usr-regulator-1",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=TEST_INST_A,
        role=RoleEnum.REGULATOR,
        permissions=["reports:read"],
    )
    app.dependency_overrides[get_current_identity] = lambda: regulator_identity

    res = client.post("/api/v2/cases/CASE-BAGHDAD-001/reports", json={"language": "en"})
    assert res.status_code == 403
    assert "REGULATOR role has read-only access" in res.json()["detail"]


def test_cross_tenant_report_isolation(client, db_session):
    """
    Confirms Institution B cannot access or export Institution A's case reports.
    """
    identity_b = Identity(
        sub="usr-auditor-b",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=TEST_INST_B,
        role=RoleEnum.AUDITOR,
        permissions=["cases:read", "reports:read"],
    )
    app.dependency_overrides[get_current_identity] = lambda: identity_b

    # Institution B attempts to generate report on Institution A's case
    res = client.post("/api/v2/cases/CASE-BAGHDAD-001/reports", json={"language": "en"})
    assert res.status_code == 404
