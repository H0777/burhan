"""
Integration Tests for Case Lifecycle and Four-Eyes Governance (T16)
Specification §7 (R01, R08, R09, R15)
Tests state machine transitions, Four-Eyes principle, Separation of Duties (SoD),
optimistic concurrency locking, REGULATOR write restrictions, and idempotent replay.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, Institution
from app.schemas.identity import Identity, RoleEnum
from app.services.case_service import (
    CaseService,
    VersionConflictError,
    InvalidTransitionError,
    UnauthorizedRoleError,
    SelfApprovalProhibitedError,
    CaseNotFoundError,
)


@pytest.fixture
def db_session():
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

    cbi = Institution(id="inst_cbi", name="Central Bank of Iraq")
    session.add(cbi)
    session.commit()

    yield session
    session.close()


def test_full_lifecycle_table_driven_success(db_session):
    """
    Table-driven verification of the complete canonical case resolution lifecycle:
    OPEN -> start_review -> request_approval -> approve_resolution (Four-Eyes) -> close
    """
    svc = CaseService()

    auditor_1 = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_1",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )
    auditor_2 = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_2",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )

    # 1. Create Case (OPEN, v1)
    case_res = svc.create_case(
        session=db_session,
        identity=auditor_1,
        case_number="CASE-2026-LIFECYCLE-001",
        title="Sanction Evasion Investigation",
        severity="HIGH",
    )
    db_session.commit()
    assert case_res.status == "OPEN"
    assert case_res.version == 1

    # 2. start_review (IN_REVIEW, v2)
    step1 = svc.transition_case(
        session=db_session,
        identity=auditor_1,
        case_id=case_res.id,
        action="start_review",
        expected_version=1,
    )
    db_session.commit()
    assert step1.status == "IN_REVIEW"
    assert step1.version == 2

    # 3. request_approval (AWAITING_APPROVAL, v3)
    step2 = svc.transition_case(
        session=db_session,
        identity=auditor_1,
        case_id=case_res.id,
        action="request_approval",
        expected_version=2,
        reason="Evidence collected: AML structuring confirmed.",
    )
    db_session.commit()
    assert step2.status == "AWAITING_APPROVAL"
    assert step2.version == 3

    # 4. approve_resolution by SECOND auditor (RESOLVED, v4) - Four-Eyes Principle
    step3 = svc.transition_case(
        session=db_session,
        identity=auditor_2,
        case_id=case_res.id,
        action="approve_resolution",
        expected_version=3,
        reason="Second audit review confirmed finding.",
    )
    db_session.commit()
    assert step3.status == "RESOLVED"
    assert step3.version == 4

    # 5. close (CLOSED, v5)
    step4 = svc.transition_case(
        session=db_session,
        identity=auditor_2,
        case_id=case_res.id,
        action="close",
        expected_version=4,
        reason="Final closure after supervisor review.",
    )
    db_session.commit()
    assert step4.status == "CLOSED"
    assert step4.version == 5

    # Verify history integrity
    detail = svc.get_case(db_session, auditor_1, case_res.id)
    assert len(detail.events) == 5  # creation + 4 transitions


def test_self_approval_strictly_prohibited(db_session):
    """Four-Eyes Principle: Reviewer who submitted for approval CANNOT approve resolution."""
    svc = CaseService()

    auditor_1 = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_self",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )

    case_res = svc.create_case(
        session=db_session,
        identity=auditor_1,
        case_number="CASE-2026-FOUR-EYES",
        title="Self-Approval Probe",
    )
    db_session.commit()

    # Move to IN_REVIEW then AWAITING_APPROVAL
    svc.transition_case(db_session, auditor_1, case_res.id, "start_review", expected_version=1)
    svc.transition_case(db_session, auditor_1, case_res.id, "request_approval", expected_version=2)
    db_session.commit()

    # Attempt self-approval by same auditor_1 MUST FAIL
    with pytest.raises(SelfApprovalProhibitedError, match="Four-Eyes Principle violation"):
        svc.transition_case(
            session=db_session,
            identity=auditor_1,  # Same user!
            case_id=case_res.id,
            action="approve_resolution",
            expected_version=3,
        )


def test_reject_resolution_and_rework(db_session):
    """Rejection returns case to IN_REVIEW with mandatory justification reason."""
    svc = CaseService()

    auditor_1 = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_worker",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )
    auditor_2 = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_reviewer",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )

    case_res = svc.create_case(
        session=db_session,
        identity=auditor_1,
        case_number="CASE-2026-REJECT-REWORK",
        title="Rejection Flow Case",
    )
    db_session.commit()

    svc.transition_case(db_session, auditor_1, case_res.id, "start_review", 1)
    svc.transition_case(db_session, auditor_1, case_res.id, "request_approval", 2)
    db_session.commit()

    # Rejection without reason fails
    with pytest.raises(ValueError, match="Justification reason is required"):
        svc.transition_case(
            db_session, auditor_2, case_res.id, "reject_resolution", expected_version=3, reason=""
        )

    # Rejection with reason succeeds
    res = svc.transition_case(
        db_session, auditor_2, case_res.id, "reject_resolution", expected_version=3, reason="Insufficient bank statement evidence"
    )
    db_session.commit()
    assert res.status == "IN_REVIEW"
    assert res.version == 4


def test_escalation_and_admin_return_to_review(db_session):
    """Cases can be escalated, and only SUPER_ADMIN can return them to review."""
    svc = CaseService()

    operator = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_operator",
        institution_id="inst_cbi",
        role=RoleEnum.OPERATOR,
    )
    admin = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_super_admin",
        institution_id="inst_cbi",
        role=RoleEnum.SUPER_ADMIN,
    )

    case_res = svc.create_case(db_session, operator, "CASE-ESCALATE-01", "High Political Risk")
    db_session.commit()

    svc.transition_case(db_session, operator, case_res.id, "start_review", 1)
    # Operator escalates
    esc = svc.transition_case(db_session, operator, case_res.id, "escalate", 2, reason="PEP involved")
    db_session.commit()
    assert esc.status == "ESCALATED"

    # Operator cannot return escalated case to review
    with pytest.raises(UnauthorizedRoleError, match="Only SUPER_ADMIN can return an escalated case"):
        svc.transition_case(db_session, operator, case_res.id, "return_to_review", 3, reason="Rework")

    # SUPER_ADMIN returns to review
    ret = svc.transition_case(
        db_session, admin, case_res.id, "return_to_review", 3, reason="Reassigned to senior team", new_assignee_sub="usr_senior"
    )
    db_session.commit()
    assert ret.status == "IN_REVIEW"
    assert ret.assigned_to_sub == "usr_senior"


def test_regulator_write_prohibited(db_session):
    """REGULATOR role has read-only access and cannot create or transition cases."""
    svc = CaseService()

    regulator = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_cbi_inspector",
        institution_id="inst_cbi",
        role=RoleEnum.REGULATOR,
    )

    with pytest.raises(UnauthorizedRoleError, match="REGULATOR role has read-only audit access"):
        svc.create_case(db_session, regulator, "CASE-REG-01", "Unauthorized Creation")


def test_optimistic_concurrency_conflict_409(db_session):
    """Two concurrent transitions with the same expected_version: second one must fail with VersionConflictError."""
    svc = CaseService()

    auditor = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_race",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )

    case_res = svc.create_case(db_session, auditor, "CASE-RACE-01", "Concurrent Update Case")
    db_session.commit()

    # First transition advances version to 2
    svc.transition_case(db_session, auditor, case_res.id, "start_review", expected_version=1)
    db_session.commit()

    # Second concurrent call with stale version 1 must raise VersionConflictError
    with pytest.raises(VersionConflictError, match="Version conflict"):
        svc.transition_case(db_session, auditor, case_res.id, "escalate", expected_version=1)


def test_idempotent_transition_retry(db_session):
    """Submitting the same transition with same Idempotency-Key returns previous result without duplicate events."""
    svc = CaseService()

    auditor = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor_idem",
        institution_id="inst_cbi",
        role=RoleEnum.AUDITOR,
    )

    case_res = svc.create_case(db_session, auditor, "CASE-IDEM-01", "Idempotent Case")
    db_session.commit()

    key = "idem_tx_step_100"

    # First attempt
    res1 = svc.transition_case(
        session=db_session,
        identity=auditor,
        case_id=case_res.id,
        action="start_review",
        expected_version=1,
        idempotency_key=key,
    )
    db_session.commit()
    assert res1.version == 2

    # Second attempt (network retry)
    res2 = svc.transition_case(
        session=db_session,
        identity=auditor,
        case_id=case_res.id,
        action="start_review",
        expected_version=1,
        idempotency_key=key,
    )
    assert res2.version == 2
    assert res2.status == "IN_REVIEW"

    # Verify event count: only creation event + 1 transition event
    detail = svc.get_case(db_session, auditor, case_res.id)
    assert len(detail.events) == 2
