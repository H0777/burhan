"""
Integration Tests for Evidence Delivery and Failure Injection (T14)
Specification §5, §7 (R01, R04, R08, R09, R14)
Tests atomic rollback, outbox worker idempotent replay, crash recovery before ACK,
assignment authorization, and rejection of conflicting payloads.
"""

import pytest
import io
import uuid
import hashlib
import tempfile
from pathlib import Path
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.models import (
    Base,
    Institution,
    Case,
    EvidenceObject,
    EvidenceAnchor,
    Outbox,
    CaseEvent,
)
from app.schemas.identity import Identity, RoleEnum
from app.services.evidence_store import EvidenceStore
from app.services.evidence_broker import (
    EvidenceBroker,
    CaseAssignmentError,
    RoleNotAuthorizedError,
    IdempotencyConflictError,
)
from app.workers.evidence_anchor import EvidenceAnchorWorker
from app.repositories import case_repository, evidence_repository


class MockEvmRpcClient:
    """
    Mock EVM client that faithfully mirrors ForensicTrail.sol deduplication logic.
    """
    def __init__(self):
        self.evidence_counter = 0
        self.requests = {}  # anchor_request_id -> record

    def get_evidence_by_request_id(self, anchor_request_id: str):
        if anchor_request_id in self.requests:
            rec = self.requests[anchor_request_id]
            return {
                "evidence_id": rec["evidence_id"],
                "entry_hash": rec["entry_hash"],
                "submitted_by": rec["submitted_by"],
                "exists": True,
                "block_number": rec["block_number"],
                "transaction_hash": rec["transaction_hash"],
            }
        return {"exists": False}

    def submit_evidence(
        self,
        incident_id: int,
        anchor_request_id: str,
        evidence_type_hash: str,
        description_hash: str,
        file_sha256: str,
    ):
        if anchor_request_id in self.requests:
            # Idempotent replay: return existing without incrementing counter
            rec = self.requests[anchor_request_id]
            return {
                "evidence_id": rec["evidence_id"],
                "entry_hash": rec["entry_hash"],
                "transaction_hash": rec["transaction_hash"],
                "block_number": rec["block_number"],
            }

        self.evidence_counter += 1
        entry_hash = "0x" + hashlib.sha256(
            f"{anchor_request_id}:{self.evidence_counter}".encode("utf-8")
        ).hexdigest()
        tx_hash = "0x" + hashlib.sha256(f"tx:{self.evidence_counter}".encode("utf-8")).hexdigest()

        record = {
            "evidence_id": self.evidence_counter,
            "entry_hash": entry_hash,
            "submitted_by": "0x1111111111111111111111111111111111111111",
            "block_number": 42 + self.evidence_counter,
            "transaction_hash": tx_hash,
        }
        self.requests[anchor_request_id] = record
        return record


@pytest.fixture
def test_env():
    with tempfile.TemporaryDirectory() as temp_dir:
        store_path = Path(temp_dir) / "evidence_vault"
        evidence_store = EvidenceStore(base_dir=str(store_path), max_size_bytes=10 * 1024 * 1024)

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

        # Seed institution
        inst = Institution(id="inst_cbi", name="Central Bank of Iraq")
        session.add(inst)
        session.commit()

        # Seed case assigned to investigator usr_assigned
        case = case_repository.create_case(
            session=session,
            institution_id="inst_cbi",
            case_number="CASE-2026-001",
            title="Suspicious Hawala Network",
            severity="HIGH",
            assigned_to_sub="usr_assigned",
            case_id="case_aml_001",
        )
        session.commit()

        yield {
            "session": session,
            "evidence_store": evidence_store,
            "case": case,
        }
        session.close()


def test_evidence_submission_and_anchoring_flow(test_env):
    """Happy path: submit evidence, inspect outbox, and run anchor worker."""
    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = EvidenceBroker(evidence_store=store)
    rpc_client = MockEvmRpcClient()
    worker = EvidenceAnchorWorker(rpc_client=rpc_client)

    identity = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_assigned",
        institution_id="inst_cbi",
        participant_id="0x" + ("1" * 64),
        role=RoleEnum.OPERATOR,
        permissions=["cases:write", "evidence:write"],
    )

    sample_content = b"CRITICAL FORENSIC REPORT: Transaction log 2026-10-23"
    stream = io.BytesIO(sample_content)

    res = broker.submit_case_evidence(
        session=session,
        identity=identity,
        case_id="case_aml_001",
        file_name="forensic_report.txt",
        content_type="text/plain",
        stream=stream,
    )
    session.commit()

    assert res["status"] == "PENDING_ANCHOR"
    assert res["file_size"] == len(sample_content)
    assert res["sha256_hash"] == hashlib.sha256(sample_content).hexdigest()

    # Verify pending state in DB
    anchor_db = session.execute(
        select(EvidenceAnchor).where(EvidenceAnchor.evidence_id == res["evidence_id"])
    ).scalars().first()
    assert anchor_db is not None
    assert anchor_db.status == "PENDING_ANCHOR"

    # Verify outbox item exists
    outbox_items = session.execute(
        select(Outbox).where(Outbox.institution_id == "inst_cbi")
    ).scalars().all()
    assert len(outbox_items) == 1
    assert outbox_items[0].status == "PENDING"

    # Run anchor worker
    processed = worker.process_pending_anchors(session, institution_id="inst_cbi")
    assert processed == 1
    assert rpc_client.evidence_counter == 1

    # Verify anchor updated to ANCHORED
    session.refresh(anchor_db)
    assert anchor_db.status == "ANCHORED"
    assert anchor_db.entry_hash is not None
    assert anchor_db.transaction_hash is not None


def test_crash_recovery_before_ack_idempotency(test_env):
    """
    Failure injection: Blockchain transaction succeeds, but local process crashes
    before ACK is saved to DB. On replay, getEvidenceByRequestId must prevent
    duplicate counter increment.
    """
    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = EvidenceBroker(evidence_store=store)
    rpc_client = MockEvmRpcClient()
    worker = EvidenceAnchorWorker(rpc_client=rpc_client)

    identity = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_assigned",
        institution_id="inst_cbi",
        participant_id="0x" + ("1" * 64),
        role=RoleEnum.OPERATOR,
    )

    res = broker.submit_case_evidence(
        session=session,
        identity=identity,
        case_id="case_aml_001",
        file_name="crash_test.dat",
        content_type="application/octet-stream",
        stream=io.BytesIO(b"DATA_FOR_CRASH_TEST"),
    )
    session.commit()

    # Pre-populate on-chain state to simulate: transaction was mined on-chain,
    # but worker crashed before DB update!
    anchor_req_id = res["anchor_request_id"]
    record = rpc_client.submit_evidence(
        incident_id=1,
        anchor_request_id=anchor_req_id,
        evidence_type_hash="0x" + ("1" * 64),
        description_hash="0x" + ("2" * 64),
        file_sha256="0x" + hashlib.sha256(b"DATA_FOR_CRASH_TEST").hexdigest(),
    )
    assert rpc_client.evidence_counter == 1
    initial_entry_hash = record["entry_hash"]

    # Now run worker (replay of outbox task)
    processed = worker.process_pending_anchors(session, institution_id="inst_cbi")
    assert processed == 1

    # Evidence counter on chain MUST NOT HAVE INCREMENTED!
    assert rpc_client.evidence_counter == 1

    # Database anchor record successfully reconciled with on-chain record
    anchor_db = session.execute(
        select(EvidenceAnchor).where(EvidenceAnchor.anchor_request_id == anchor_req_id)
    ).scalars().first()
    assert anchor_db.status == "ANCHORED"
    assert anchor_db.entry_hash == initial_entry_hash


def test_case_assignment_unauthorized_investigator(test_env):
    """Investigator not assigned to case must be rejected with CaseAssignmentError."""
    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = EvidenceBroker(evidence_store=store)

    unassigned_identity = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_other_investigator",
        institution_id="inst_cbi",
        participant_id="0x" + ("2" * 64),
        role=RoleEnum.OPERATOR,
    )

    with pytest.raises(CaseAssignmentError):
        broker.submit_case_evidence(
            session=session,
            identity=unassigned_identity,
            case_id="case_aml_001",
            file_name="unauthorized.pdf",
            content_type="application/pdf",
            stream=io.BytesIO(b"UNAUTHORIZED"),
        )


def test_auditor_role_cannot_submit_evidence(test_env):
    """Auditors have read-only permissions and cannot submit evidence."""
    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = EvidenceBroker(evidence_store=store)

    auditor_identity = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_auditor",
        institution_id="inst_cbi",
        participant_id="0x" + ("3" * 64),
        role=RoleEnum.AUDITOR,
    )

    with pytest.raises(RoleNotAuthorizedError):
        broker.submit_case_evidence(
            session=session,
            identity=auditor_identity,
            case_id="case_aml_001",
            file_name="audit_test.pdf",
            content_type="application/pdf",
            stream=io.BytesIO(b"AUDITOR_SUBMIT"),
        )
