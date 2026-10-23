"""
Integration Tests for Banking Transaction CSV Import (T17)
Cyber-Forensic Auditing Framework - Specification §7 & T17 (R07, R08, R09, R11, R18)
Verifies streaming parser limits, non-PII errors, timezone enforcement, and conflict rejection.
"""

import io
import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models import Base, Institution, TransactionRecord, ImportBatchRecord
from app.db.session import get_engine, get_session_factory, tenant_transaction
from app.schemas.identity import Identity, RoleEnum
from app.connectors.csv_import import CsvImportConnector, OversizedFileError, CsvImportError

TEST_INSTITUTION_A = "inst_rafidain_bank"
TEST_INSTITUTION_B = "inst_rasheed_bank"


@pytest.fixture
def db_session():
    engine = get_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    factory = get_session_factory(engine)
    session = factory()

    inst_a = Institution(id=TEST_INSTITUTION_A, name="Al-Rafidain Bank", is_active=True)
    inst_b = Institution(id=TEST_INSTITUTION_B, name="Al-Rasheed Bank", is_active=True)
    session.add_all([inst_a, inst_b])
    session.commit()

    yield session
    session.close()


@pytest.fixture
def identity_a():
    return Identity(
        sub="operator_a",
        issuer="https://auth.cbi.iq",
        institution_id=TEST_INSTITUTION_A,
        role=RoleEnum.OPERATOR,
        permissions=["transactions:import", "transactions:read"],
    )


@pytest.fixture
def identity_b():
    return Identity(
        sub="operator_b",
        issuer="https://auth.cbi.iq",
        institution_id=TEST_INSTITUTION_B,
        role=RoleEnum.OPERATOR,
        permissions=["transactions:import", "transactions:read"],
    )


def test_valid_csv_import_success(db_session, identity_a):
    csv_data = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-IQD-001,2026-10-23T08:00:00Z,ACC-101,ACC-202,IQD,3,15000000000\n"
        "TX-IQD-002,2026-10-23T08:30:00+03:00,ACC-303,ACC-404,IQD,3,7500000000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        resp = connector.parse_and_import(
            session=db_session,
            identity=identity_a,
            file_content=csv_data,
            filename="valid_batch.csv",
        )

    assert resp.status == "COMPLETED"
    assert resp.total_rows == 2
    assert resp.accepted_rows == 2
    assert resp.rejected_rows == 0
    assert len(resp.errors) == 0

    # Verify rows in DB
    records = db_session.execute(
        select(TransactionRecord).where(
            TransactionRecord.institution_id == TEST_INSTITUTION_A
        )
    ).scalars().all()
    assert len(records) >= 2


def test_missing_timezone_rejected(db_session, identity_a):
    csv_data = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-NO-TZ,2026-10-23 08:00:00,ACC-101,ACC-202,IQD,3,1000000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        resp = connector.parse_and_import(
            session=db_session,
            identity=identity_a,
            file_content=csv_data,
            filename="no_tz.csv",
        )

    assert resp.status == "REJECTED"
    assert resp.accepted_rows == 0
    assert resp.rejected_rows == 1
    err = resp.errors[0]
    assert err.error_code == "MISSING_TIMEZONE"
    # Ensure no PII in message
    assert "ACC-101" not in err.message
    assert "ACC-202" not in err.message


def test_invalid_amount_and_scale_rejected(db_session, identity_a):
    csv_data = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-NEG,2026-10-23T08:00:00Z,ACC-1,ACC-2,IQD,3,-5000\n"
        "TX-DEC,2026-10-23T08:00:00Z,ACC-1,ACC-2,IQD,3,1250.50\n"
        "TX-BAD-SCALE,2026-10-23T08:00:00Z,ACC-1,ACC-2,IQD,-1,10000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        resp = connector.parse_and_import(
            session=db_session,
            identity=identity_a,
            file_content=csv_data,
        )

    assert resp.status == "REJECTED"
    assert resp.accepted_rows == 0
    assert resp.rejected_rows == 3
    error_codes = [e.error_code for e in resp.errors]
    assert "INVALID_AMOUNT" in error_codes
    assert "INVALID_SCALE" in error_codes


def test_duplicate_in_same_file_with_conflicting_data(db_session, identity_a):
    csv_data = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-DUP-1,2026-10-23T08:00:00Z,ACC-A,ACC-B,IQD,3,1000000\n"
        "TX-DUP-1,2026-10-23T08:00:00Z,ACC-A,ACC-B,IQD,3,2000000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        resp = connector.parse_and_import(
            session=db_session,
            identity=identity_a,
            file_content=csv_data,
        )

    assert resp.status == "PARTIALLY_ACCEPTED"
    assert resp.accepted_rows == 1
    assert resp.rejected_rows == 1
    assert resp.errors[0].error_code == "CONFLICT_DIFFERENT_DATA"


def test_reimport_conflict_against_existing_database_record(db_session, identity_a):
    # First import
    csv_initial = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-CONFLICT-DB,2026-10-23T08:00:00Z,ACC-1,ACC-2,IQD,3,5000000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        resp1 = connector.parse_and_import(
            session=db_session,
            identity=identity_a,
            file_content=csv_initial,
        )
    assert resp1.accepted_rows == 1

    # Second import with altered amount for same external_id
    csv_conflict = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-CONFLICT-DB,2026-10-23T08:00:00Z,ACC-1,ACC-2,IQD,3,9999999\n"
    ).encode("utf-8")

    with tenant_transaction(db_session, identity_a.institution_id):
        resp2 = connector.parse_and_import(
            session=db_session,
            identity=identity_a,
            file_content=csv_conflict,
        )

    assert resp2.status == "REJECTED"
    assert resp2.accepted_rows == 0
    assert resp2.rejected_rows == 1
    assert resp2.errors[0].error_code == "CONFLICT_DIFFERENT_DATA"

    # Verify original record unchanged in DB
    rec = db_session.execute(
        select(TransactionRecord).where(
            TransactionRecord.institution_id == TEST_INSTITUTION_A,
            TransactionRecord.external_id == "TX-CONFLICT-DB",
        )
    ).scalars().first()
    assert rec.amount_minor == 5000000  # Not overwritten!


def test_idempotent_reimport_of_identical_data(db_session, identity_a):
    csv_data = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-IDEMPOTENT,2026-10-23T09:00:00Z,ACC-X,ACC-Y,IQD,3,3000000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        r1 = connector.parse_and_import(db_session, identity_a, csv_data)
        assert r1.accepted_rows == 1

    # Re-import identical data
    with tenant_transaction(db_session, identity_a.institution_id):
        r2 = connector.parse_and_import(db_session, identity_a, csv_data)
        assert r2.accepted_rows == 0
        assert r2.rejected_rows == 0
        assert r2.status == "COMPLETED"


def test_oversized_file_aborted_early():
    connector = CsvImportConnector(max_rows=5)
    # Generate 6 rows
    lines = ["external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor"]
    for i in range(6):
        lines.append(f"TX-{i},2026-10-23T10:00:00Z,A,B,IQD,3,1000")
    csv_bytes = "\n".join(lines).encode("utf-8")

    # Should raise OversizedFileError
    with pytest.raises(OversizedFileError) as exc_info:
        connector.parse_and_import(
            None,
            Identity(sub="u", issuer="https://auth.cbi.iq", institution_id="i", role=RoleEnum.OPERATOR),
            csv_bytes,
        )

    assert "maximum allowable limit of 5 rows" in str(exc_info.value)


def test_tenant_isolation_on_transactions(db_session, identity_a, identity_b):
    # Import for Tenant A
    csv_a = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-SHARED-001,2026-10-23T12:00:00Z,ACC-A1,ACC-A2,IQD,3,11000000\n"
    ).encode("utf-8")

    connector = CsvImportConnector()
    with tenant_transaction(db_session, identity_a.institution_id):
        resp_a = connector.parse_and_import(db_session, identity_a, csv_a)
        assert resp_a.accepted_rows == 1

    # Import for Tenant B with same external_id as Tenant A
    csv_b = (
        "external_id,occurred_at,sender_ref,receiver_ref,currency,scale,amount_minor\n"
        "TX-SHARED-001,2026-10-23T12:00:00Z,ACC-B1,ACC-B2,IQD,3,44000000\n"
    ).encode("utf-8")

    with tenant_transaction(db_session, identity_b.institution_id):
        resp_b = connector.parse_and_import(db_session, identity_b, csv_b)
        assert resp_b.accepted_rows == 1

    # Check Tenant A's record has ACC-A1, and Tenant B's has ACC-B1
    rec_a = db_session.execute(
        select(TransactionRecord).where(
            TransactionRecord.institution_id == TEST_INSTITUTION_A,
            TransactionRecord.external_id == "TX-SHARED-001",
        )
    ).scalars().first()
    assert rec_a.sender_ref == "ACC-A1"

    rec_b = db_session.execute(
        select(TransactionRecord).where(
            TransactionRecord.institution_id == TEST_INSTITUTION_B,
            TransactionRecord.external_id == "TX-SHARED-001",
        )
    ).scalars().first()
    assert rec_b.sender_ref == "ACC-B1"
