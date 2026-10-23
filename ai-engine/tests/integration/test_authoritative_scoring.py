"""
Integration Tests for Authoritative Server-Side Risk Scoring (T18)
Specification §7 & §8 (R07, R12)
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.models import Base, Institution, TransactionRecord, AssessmentRecord
from app.db.session import get_db, set_engine
from app.schemas.identity import Identity, RoleEnum
from app.routes.v2.identity import get_current_identity

from sqlalchemy.pool import StaticPool

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
def operator_identity():
    return Identity(
        sub="usr-operator-lead",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=TEST_INST_A,
        role=RoleEnum.OPERATOR,
        permissions=["assess:write", "assess:read"],
    )


@pytest.fixture
def regulator_identity():
    return Identity(
        sub="usr-regulator-inspector",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=TEST_INST_A,
        role=RoleEnum.REGULATOR,
        permissions=["assess:read"],
    )


def test_client_injected_extra_fields_rejected(client, db_session, operator_identity):
    """
    Ensures client-side attempts to self-assert KYC or volume bypass are rejected with 422.
    """
    app.dependency_overrides[get_current_identity] = lambda: operator_identity

    tx = TransactionRecord(
        id="TX-TEST-001",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-001",
        occurred_at=datetime.now(timezone.utc),
        sender_ref="ACC-ALICE-100",
        receiver_ref="ACC-BOB-200",
        currency="IQD",
        scale=3,
        amount_minor=10000000000,
        status="RECORDED",
    )
    db_session.add(tx)
    db_session.commit()

    # Attempt to inject unverified risk attributes
    malicious_payload = {
        "transaction_id": "TX-TEST-001",
        "is_kyc_verified": True,
        "sender_daily_volume": 0.0,
    }

    res = client.post("/api/v2/risk/assess", json=malicious_payload)
    assert res.status_code == 422


def test_structuring_smurfing_detected_authoritatively(client, db_session, operator_identity):
    """
    Validates detection of structured sub-threshold transfers (85% - 99% of 15,000,000 IQD).
    13,500,000.000 IQD = 13500000000 minor units (90% threshold ratio).
    """
    app.dependency_overrides[get_current_identity] = lambda: operator_identity

    tx = TransactionRecord(
        id="TX-STRUCT-001",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-STRUCT-001",
        occurred_at=datetime.now(timezone.utc),
        sender_ref="ACC-SMURF-101",
        receiver_ref="ACC-BENEF-202",
        currency="IQD",
        scale=3,
        amount_minor=13500000000,  # 90% of 15,000,000 IQD threshold
        status="RECORDED",
    )
    db_session.add(tx)
    db_session.commit()

    res = client.post("/api/v2/risk/assess", json={"transaction_id": "TX-STRUCT-001"})
    assert res.status_code == 201
    data = res.json()

    assert data["structuring_detected"] is True
    assert "STRUCTURING_SMURFING_SUSPECTED" in data["rules_triggered"]
    assert data["fraud_score"] >= 40.0
    assert data["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert data["feature_snapshot"]["structuring_ratio"] == 0.9
    assert data["features_hash"].startswith("0x")


def test_historical_volume_and_burst_aggregation(client, db_session, operator_identity):
    """
    Confirms 24-hour daily volume and 10-minute burst counts are computed from ledger history.
    """
    app.dependency_overrides[get_current_identity] = lambda: operator_identity
    now = datetime.now(timezone.utc)

    # Prior transactions for the same sender within 24h
    t1 = TransactionRecord(
        id="TX-HIST-001",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-HIST-001",
        occurred_at=now - timedelta(hours=3),
        sender_ref="ACC-BURST-101",
        receiver_ref="ACC-BENEF-999",
        currency="IQD",
        scale=3,
        amount_minor=40000000000,  # 40,000,000 IQD
        status="RECORDED",
    )
    t2 = TransactionRecord(
        id="TX-HIST-002",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-HIST-002",
        occurred_at=now - timedelta(minutes=5),
        sender_ref="ACC-BURST-101",
        receiver_ref="ACC-BENEF-999",
        currency="IQD",
        scale=3,
        amount_minor=40000000000,  # 40,000,000 IQD (Cumulative reaches 80M > 75M limit)
        status="RECORDED",
    )
    # Current transaction
    t3 = TransactionRecord(
        id="TX-HIST-003",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-HIST-003",
        occurred_at=now,
        sender_ref="ACC-BURST-101",
        receiver_ref="ACC-BENEF-999",
        currency="IQD",
        scale=3,
        amount_minor=5000000000,
        status="RECORDED",
    )
    db_session.add_all([t1, t2, t3])
    db_session.commit()

    res = client.post("/api/v2/risk/assess", json={"transaction_id": "TX-HIST-003"})
    assert res.status_code == 201
    data = res.json()

    assert "DAILY_VOLUME_EXCEEDED" in data["rules_triggered"]
    assert data["feature_snapshot"]["sender_daily_volume_minor"] >= 80000000000
    assert data["feature_snapshot"]["sender_daily_count"] >= 3


def test_simulation_preview_does_not_mutate_db(client, db_session, operator_identity):
    """
    Verifies /preview endpoint returns evaluation without mutating database or tx.risk_score.
    """
    app.dependency_overrides[get_current_identity] = lambda: operator_identity

    tx = TransactionRecord(
        id="TX-PREVIEW-001",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-PREVIEW-001",
        occurred_at=datetime.now(timezone.utc),
        sender_ref="ACC-PREVIEW-101",
        receiver_ref="ACC-PREVIEW-202",
        currency="IQD",
        scale=3,
        amount_minor=20000000000,  # 20,000,000 IQD > threshold
        status="RECORDED",
        risk_score=None,
    )
    db_session.add(tx)
    db_session.commit()

    res = client.post("/api/v2/risk/preview", json={"transaction_id": "TX-PREVIEW-001"})
    assert res.status_code == 200
    data = res.json()

    assert data["source"] == "SIMULATION"
    assert data["assessment_id"].startswith("SIM-")

    # Verify no persistent record was inserted
    count = db_session.query(AssessmentRecord).filter_by(transaction_id="TX-PREVIEW-001").count()
    assert count == 0

    # Verify transaction risk_score remains unmutated
    db_session.refresh(tx)
    assert tx.risk_score is None


def test_regulator_cannot_trigger_authoritative_assessment(client, db_session, regulator_identity):
    """
    Ensures REGULATOR role is strictly forbidden from invoking mutation endpoints (HTTP 403).
    """
    app.dependency_overrides[get_current_identity] = lambda: regulator_identity

    tx = TransactionRecord(
        id="TX-REG-001",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-REG-001",
        occurred_at=datetime.now(timezone.utc),
        sender_ref="ACC-REG-101",
        receiver_ref="ACC-REG-202",
        currency="IQD",
        scale=3,
        amount_minor=1000000000,
        status="RECORDED",
    )
    db_session.add(tx)
    db_session.commit()

    res = client.post("/api/v2/risk/assess", json={"transaction_id": "TX-REG-001"})
    assert res.status_code == 403
    assert "REGULATOR role has read-only access" in res.json()["detail"]


def test_cross_tenant_assessment_isolation(client, db_session):
    """
    Confirms Institution B cannot assess or access Institution A's transactions.
    """
    identity_b = Identity(
        sub="usr-tenant-b",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=TEST_INST_B,
        role=RoleEnum.OPERATOR,
        permissions=["assess:write"],
    )
    app.dependency_overrides[get_current_identity] = lambda: identity_b

    # Transaction belongs to Institution A
    tx_a = TransactionRecord(
        id="TX-TENANT-A-001",
        institution_id=TEST_INST_A,
        source="IQD_CSV",
        external_id="EXT-A-001",
        occurred_at=datetime.now(timezone.utc),
        sender_ref="ACC-A-1",
        receiver_ref="ACC-A-2",
        currency="IQD",
        scale=3,
        amount_minor=5000000000,
        status="RECORDED",
    )
    db_session.add(tx_a)
    db_session.commit()

    # Institution B attempts to assess Institution A's transaction
    res = client.post("/api/v2/risk/assess", json={"transaction_id": "TX-TENANT-A-001"})
    assert res.status_code == 404
