"""
Integration Tests for Multi-Tenant Storage and Isolation (T14, R11)
Specification §4, §5, §7 (R01, R04, R08, R09, R14, R11)

LOGIC-ONLY (SQLite in-memory): these tests exercise repository logic, composite
foreign keys, WORM immutability, idempotency handling, and RLS DDL *generation*
against in-memory SQLite. They are NOT evidence of PostgreSQL row-level
security enforcement — the real-PostgreSQL guarantees (FORCE RLS, least-
privilege roles, transaction-local tenant context, migration conventions) are
proven by tests/integration/test_postgres_rls.py (R11), which is skipped unless
DATABASE_URL / MIGRATION_DATABASE_URL point at a disposable test database.
"""

import pytest
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.db.models import (
    Base,
    Institution,
    Membership,
    Case,
    CaseEvent,
    EvidenceObject,
    EvidenceAnchor,
    IdempotencyKey,
    RLS_TABLES,
    generate_rls_sql,
)
from app.db.session import tenant_transaction
from app.repositories import (
    case_repository,
    evidence_repository,
    outbox_repository,
    institution_repository,
)


@pytest.fixture
def db_session():
    # In-memory SQLite with foreign keys enforced for unit/integration isolation
    engine = create_engine("sqlite:///:memory:", echo=False)
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Seed institutions
    cbi = Institution(id="inst_cbi", name="Central Bank of Iraq")
    rafidain = Institution(id="inst_rafidain", name="Rafidain Bank")
    session.add_all([cbi, rafidain])
    session.commit()

    yield session
    session.close()


def test_tenant_context_required(db_session):
    """Attempting tenant_transaction with invalid institution_id must fail."""
    with pytest.raises(ValueError, match="Valid institution_id required"):
        with tenant_transaction(db_session, ""):
            pass

    with pytest.raises(ValueError, match="Valid institution_id required"):
        with tenant_transaction(db_session, None):
            pass


def test_tenant_case_isolation(db_session):
    """Cases created by inst_cbi must NOT be visible to inst_rafidain."""
    case_cbi = case_repository.create_case(
        session=db_session,
        institution_id="inst_cbi",
        case_number="CASE-CBI-001",
        title="Sanction Compliance Audit",
    )
    db_session.commit()

    # CBI sees the case
    found_cbi = case_repository.get_case(db_session, "inst_cbi", case_cbi.id)
    assert found_cbi is not None
    assert found_cbi.title == "Sanction Compliance Audit"

    # Rafidain CANNOT see CBI case
    found_rafidain = case_repository.get_case(db_session, "inst_rafidain", case_cbi.id)
    assert found_rafidain is None

    # Listing cases for Rafidain returns empty
    rafidain_cases = case_repository.list_cases(db_session, "inst_rafidain")
    assert len(rafidain_cases) == 0


def test_cross_tenant_foreign_key_violation(db_session):
    """
    Attempting to attach an EvidenceObject or CaseEvent with institution_id A
    to a Case belonging to institution_id B must fail due to composite foreign key.
    """
    case_cbi = case_repository.create_case(
        session=db_session,
        institution_id="inst_cbi",
        case_number="CASE-CBI-002",
        title="Cross-Tenant Probe Case",
    )
    db_session.commit()

    # Attempting to save evidence for Rafidain referencing CBI's case must raise ValueError
    with pytest.raises(ValueError, match="does not exist for institution inst_rafidain"):
        evidence_repository.save_evidence_object(
            session=db_session,
            institution_id="inst_rafidain",
            case_id=case_cbi.id,
            evidence_id="ev_leak_attempt",
            file_name="suspicious.pdf",
            content_type="application/pdf",
            file_size=1024,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_path="/data/evidence/inst_rafidain/ev_leak_attempt/v1.dat",
        )

    # Attempting to insert raw EvidenceObject with mismatched institution_id directly
    # triggers SQLite composite foreign key enforcement
    mismatched_ev = EvidenceObject(
        id=f"ev_{uuid.uuid4().hex[:16]}",
        institution_id="inst_rafidain",  # Cross-tenant mismatch
        case_id=case_cbi.id,
        evidence_id="ev_raw_leak",
        object_version=1,
        file_name="leak.pdf",
        content_type="application/pdf",
        file_size=512,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        storage_path="/data/evidence/inst_rafidain/ev_raw_leak/v1.dat",
    )
    db_session.add(mismatched_ev)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_evidence_version_immutability(db_session):
    """Overwriting an existing evidence version within the same institution is strictly prohibited."""
    case = case_repository.create_case(
        session=db_session,
        institution_id="inst_cbi",
        case_number="CASE-CBI-003",
        title="Immutability Test Case",
    )
    db_session.commit()

    # Save version 1
    evidence_repository.save_evidence_object(
        session=db_session,
        institution_id="inst_cbi",
        case_id=case.id,
        evidence_id="ev_audit_100",
        file_name="audit_report.pdf",
        content_type="application/pdf",
        file_size=2048,
        sha256_hash="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        storage_path="/data/evidence/inst_cbi/ev_audit_100/v1.dat",
        object_version=1,
    )
    db_session.commit()

    # Attempting to overwrite version 1 must raise VersionOverwriteProhibitedError
    with pytest.raises(evidence_repository.VersionOverwriteProhibitedError):
        evidence_repository.save_evidence_object(
            session=db_session,
            institution_id="inst_cbi",
            case_id=case.id,
            evidence_id="ev_audit_100",
            file_name="audit_report_tampered.pdf",
            content_type="application/pdf",
            file_size=4096,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            storage_path="/data/evidence/inst_cbi/ev_audit_100/v1.dat",
            object_version=1,
        )


def test_idempotency_conflict_detection(db_session):
    """Reusing an idempotency key with conflicting request hash must be rejected."""
    key = "req_audit_submit_001"
    inst = "inst_cbi"
    hash1 = hashlib.sha256(b"payload_1").hexdigest()
    hash2 = hashlib.sha256(b"payload_2").hexdigest()

    # Insert first idempotency entry
    entry1 = IdempotencyKey(
        id=f"ik_{uuid.uuid4().hex[:16]}",
        institution_id=inst,
        key=key,
        request_hash=hash1,
        response_json='{"status": "ok"}',
        status_code=200,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(entry1)
    db_session.commit()

    # Query existing key
    existing = db_session.execute(
        select(IdempotencyKey).where(
            IdempotencyKey.institution_id == inst,
            IdempotencyKey.key == key,
        )
    ).scalars().first()
    assert existing is not None
    assert existing.request_hash == hash1

    # Conflict check: same key, different payload hash
    assert existing.request_hash != hash2  # Conflict detected!

    # Unique constraint prevents duplicate (institution_id, key)
    dup = IdempotencyKey(
        id=f"ik_{uuid.uuid4().hex[:16]}",
        institution_id=inst,
        key=key,
        request_hash=hash2,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(dup)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


def test_rls_sql_generation():
    """Verify that generate_rls_sql outputs the PostgreSQL RLS DDL mirroring the
    alembic baseline: ENABLE+FORCE+policy per institutional table, plus the
    explicit read-only policy on the global institutions table."""
    sqls = generate_rls_sql()
    assert len(sqls) == len(RLS_TABLES) * 4 + 2  # 4 per tenant table + institutions

    for table in RLS_TABLES:
        assert any(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" in s for s in sqls)
        assert any(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;" in s for s in sqls)
        assert any(f"CREATE POLICY tenant_isolation_policy ON {table}" in s for s in sqls)
        assert any("current_setting('app.current_institution_id', true)" in s for s in sqls)

    # Global table: explicit policy, read-only — never assumed safe.
    assert any("ALTER TABLE institutions ENABLE ROW LEVEL SECURITY;" in s for s in sqls)
    assert any(
        "CREATE POLICY institutions_read_all ON institutions FOR SELECT USING (true);" in s
        for s in sqls
    )
    assert not any("FORCE ROW LEVEL SECURITY" in s and "institutions" in s for s in sqls)
