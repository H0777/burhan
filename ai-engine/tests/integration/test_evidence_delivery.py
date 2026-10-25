"""
Integration Tests for Evidence Delivery and Failure Injection (T14 / R06)
Specification §5, §6, §7 (R01, R04, R06, R08, R09, R14)
Tests atomic rollback, outbox worker idempotent replay, crash recovery before ACK,
assignment authorization, rejection of conflicting payloads — and the R06
signed-manifest semantics: a REAL Ed25519 SignedEnvelope stored BEFORE the
outbox event, with manifest_digest taken over the canonical SIGNED envelope
(signature included), all inside one transaction.
"""

import pytest
import io
import json
import uuid
import os
import hashlib
import tempfile
from datetime import datetime, timedelta, timezone
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
from app.security.key_provider import LocalFileKeyProvider
from app.security.signing import (
    DOMAIN_SERVICE_MANIFEST,
    Signer,
    Verifier,
    TrustRegistry,
    RegistryEntry,
    encode_public_key,
    envelope_digest,
)
from app.services.evidence_store import EvidenceStore
from app.services.evidence_broker import (
    EvidenceBroker,
    CaseAssignmentError,
    RoleNotAuthorizedError,
    IdempotencyConflictError,
    MissingSignerError,
)
from app.workers.evidence_anchor import CrashSimulated, EvidenceAnchorWorker
from app.repositories import case_repository, evidence_repository

# R08: the anchor worker runs the REAL ChainSender pipeline. The chain is
# simulated by chain_sim.SimulatedEvmAdapter (real signatures, RLP-decoded
# nonce enforcement, ForensicTrail dedupe semantics) — the worker, sender,
# repositories and persistence under test are the real ones.
from chain_sim import FakeClock, SimulatedEvmAdapter, make_sender


@pytest.fixture
def test_env():
    with tempfile.TemporaryDirectory() as temp_dir:
        store_path = Path(temp_dir) / "evidence_vault"
        # R06: institution signing/wrapping key mounted outside the vault.
        keys = Path(temp_dir) / "keys" / "inst_cbi"
        keys.mkdir(parents=True)
        seed = os.urandom(32)
        (keys / "k1.seed").write_bytes(seed)
        (keys / "current").write_text("k1", encoding="utf-8")
        key_provider = LocalFileKeyProvider(Path(temp_dir) / "keys")
        signer = Signer(key_provider)

        evidence_store = EvidenceStore(
            base_dir=str(store_path),
            max_size_bytes=10 * 1024 * 1024,
            key_provider=key_provider,
        )

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
            "key_provider": key_provider,
            "signer": signer,
            "seed": seed,
        }
        session.close()


def _registry_for(seed: bytes, institution_id: str = "inst_cbi", key_id: str = "k1") -> TrustRegistry:
    """External trust registry binding the institution key (test stand-in
    for the authoritative registry document)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    public_key = encode_public_key(Ed25519PrivateKey.from_private_bytes(seed).public_key())
    now = datetime.now(timezone.utc)
    return TrustRegistry(
        [
            RegistryEntry.from_mapping(
                {
                    "institution_id": institution_id,
                    "key_id": key_id,
                    "public_key": public_key,
                    "valid_from": (now - timedelta(days=1)).isoformat(),
                    "valid_until": (now + timedelta(days=365)).isoformat(),
                    "status": "active",
                }
            )
        ]
    )


def _broker(test_env) -> EvidenceBroker:
    return EvidenceBroker(
        evidence_store=test_env["evidence_store"],
        signer=test_env["signer"],
        key_provider=test_env["key_provider"],
    )


def test_evidence_submission_and_anchoring_flow(test_env):
    """Happy path: submit evidence, inspect outbox, and run the R08 anchor
    worker (real ChainSender pipeline, simulated chain)."""
    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = _broker(test_env)

    adapter = SimulatedEvmAdapter(chain_id=1337)  # broker payload chain (settings.CHAIN_ID)
    clock = FakeClock()
    sender, _account = make_sender(adapter, clock)
    worker = EvidenceAnchorWorker(
        chain_sender=sender, deployment_id="0x" + "22" * 32,
    )

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

    # R06: the manifest is a REAL SignedEnvelope, not a digest named manifest.
    envelope = res["manifest"]
    assert envelope["algorithm"] == "Ed25519"
    assert set(envelope) == {"body", "algorithm", "signature"}
    body = envelope["body"]
    for field in (
        "institution_id", "case_id", "evidence_id", "object_version",
        "file_sha256", "size", "anchor_request_id", "participant_id",
        "issued_at", "key_id",
    ):
        assert field in body, f"manifest body missing spec section 6 field {field}"
    assert body["file_sha256"] == res["sha256_hash"]
    assert body["anchor_request_id"] == res["anchor_request_id"]

    # The digest covers the canonical SIGNED envelope (signature included).
    assert res["manifest_digest"] == envelope_digest(envelope)
    assert res["manifest_hash"] == "0x" + envelope_digest(envelope)

    # The signature verifies against the external trust registry.
    result = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, envelope, _registry_for(test_env["seed"])
    )
    assert result.is_verified, f"manifest signature did not verify: {result}"

    # EvidenceObject row: signed envelope stored with the encryption metadata.
    ev_row = session.execute(
        select(EvidenceObject).where(EvidenceObject.evidence_id == res["evidence_id"])
    ).scalars().first()
    assert ev_row is not None
    assert ev_row.encrypted is True
    assert ev_row.storage_format == "aes256gcm_v1"
    assert ev_row.encryption_key_id == "k1"
    assert ev_row.wrapped_dek is not None and "ciphertext" in ev_row.wrapped_dek
    assert ev_row.nonce is not None and ev_row.auth_tag is not None
    assert ev_row.manifest_envelope_json is not None
    assert json.loads(ev_row.manifest_envelope_json) == envelope
    assert ev_row.manifest_digest == res["manifest_digest"]

    # Signed envelope stored BEFORE the outbox event: the outbox payload
    # carries exactly the stored envelope.
    anchor_db = session.execute(
        select(EvidenceAnchor).where(EvidenceAnchor.evidence_id == res["evidence_id"])
    ).scalars().first()
    assert anchor_db is not None
    assert anchor_db.status == "PENDING_ANCHOR"

    outbox_items = session.execute(
        select(Outbox).where(Outbox.institution_id == "inst_cbi")
    ).scalars().all()
    assert len(outbox_items) == 1
    assert outbox_items[0].status == "PENDING"
    ob_payload = json.loads(outbox_items[0].payload_json)
    assert ob_payload["service_manifest"] == envelope
    assert ob_payload["manifest_hash"] == "0x" + res["manifest_digest"]

    # Run the R08 anchor worker cycle (claim -> incident -> attested
    # submission -> receipt/depth/entry verification -> COMPLETED).
    from sqlalchemy.orm import sessionmaker as _sm

    SessionFactory = _sm(bind=session.get_bind(), expire_on_commit=False)
    stats = worker.process_cycle(
        session_factory=SessionFactory, institution_id="inst_cbi", clock=clock,
    )
    assert stats["anchored"] == 1
    assert adapter.stats()["evidence"] == 1  # exactly one on-chain entry

    # Verify anchor updated to ANCHORED
    session.expire_all()
    anchor_db = session.execute(
        select(EvidenceAnchor).where(EvidenceAnchor.evidence_id == res["evidence_id"])
    ).scalars().first()
    assert anchor_db.status == "ANCHORED"
    assert anchor_db.entry_hash is not None
    assert anchor_db.transaction_hash is not None

    outbox_row = session.execute(select(Outbox)).scalars().first()
    assert outbox_row.status == "COMPLETED"


def test_crash_recovery_before_ack_idempotency(test_env):
    """
    Failure injection (R08 semantics): the chain transaction is mined, but
    the worker crashes BEFORE the DB records the ack. On replay,
    getEvidenceByRequestId must reconcile the anchor WITHOUT a second
    on-chain entry.
    """
    session = test_env["session"]
    broker = _broker(test_env)

    adapter = SimulatedEvmAdapter(chain_id=1337)  # broker payload chain (settings.CHAIN_ID)
    clock = FakeClock()
    sender, _account = make_sender(adapter, clock)
    worker = EvidenceAnchorWorker(
        chain_sender=sender, deployment_id="0x" + "22" * 32,
    )

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

    from sqlalchemy.orm import sessionmaker as _sm

    SessionFactory = _sm(bind=session.get_bind(), expire_on_commit=False)

    # Mine the evidence, then crash before the ANCHORED/COMPLETED commit.
    with pytest.raises(CrashSimulated, match="after_receipt_before_commit"):
        worker.process_cycle(
            session_factory=SessionFactory,
            institution_id="inst_cbi",
            clock=clock,
            crash_before="after_receipt_before_commit",
        )
    assert adapter.stats()["evidence"] == 1  # mined exactly once

    # Restart (same provisioned signer; lease expired via the injected clock)
    clock.advance(61)
    worker2 = EvidenceAnchorWorker(
        chain_sender=sender, worker_id="anchor_restart",
        deployment_id="0x" + "22" * 32,
    )
    stats = worker2.process_cycle(
        session_factory=SessionFactory, institution_id="inst_cbi", clock=clock,
    )
    assert stats["anchored"] == 1

    # Evidence counter on chain MUST NOT HAVE INCREMENTED!
    assert adapter.stats()["evidence"] == 1

    # Database anchor record successfully reconciled with on-chain record
    session.expire_all()
    anchor_db = session.execute(
        select(EvidenceAnchor).where(EvidenceAnchor.anchor_request_id == res["anchor_request_id"])
    ).scalars().first()
    assert anchor_db.status == "ANCHORED"
    assert anchor_db.entry_hash is not None


def test_case_assignment_unauthorized_investigator(test_env):
    """Investigator not assigned to case must be rejected with CaseAssignmentError."""
    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = _broker(test_env)

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
    broker = _broker(test_env)

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


def test_manifest_digest_covers_signature(test_env):
    """R06: manifest_digest is SHA-256 of the canonical SIGNED envelope.
    Changing ONLY the signature (identical body) changes the digest — a
    digest of the body alone could never detect that."""
    session = test_env["session"]
    broker = _broker(test_env)
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
        file_name="digest_semantics.txt",
        content_type="text/plain",
        stream=io.BytesIO(b"digest over signed envelope"),
    )
    session.commit()

    envelope = res["manifest"]
    base_digest = envelope_digest(envelope)
    assert res["manifest_digest"] == base_digest

    # Tamper ONLY the signature: digest must change, verification must fail.
    first_char = "A" if envelope["signature"][0] != "A" else "B"
    tampered = dict(envelope, signature=first_char + envelope["signature"][1:])
    assert tampered["body"] == envelope["body"]
    assert envelope_digest(tampered) != base_digest
    result = Verifier().verify(
        DOMAIN_SERVICE_MANIFEST, tampered, _registry_for(test_env["seed"])
    )
    assert not result.is_verified


def test_db_failure_rolls_back_and_leaves_no_unpublished_staging(test_env, monkeypatch):
    """R06 failure semantics: when the DB write fails, the transaction rolls
    back as ONE unit (no evidence row, no anchor, no outbox, no case event),
    only unpublished staging is deleted, and the already-published disk
    object remains as an ORPHAN for later-retention collection — the broker
    never deletes published evidence files."""
    from app.repositories import outbox_repository

    session = test_env["session"]
    store = test_env["evidence_store"]
    broker = _broker(test_env)
    identity = Identity(
        issuer="https://auth.cbi.iq",
        sub="usr_assigned",
        institution_id="inst_cbi",
        participant_id="0x" + ("1" * 64),
        role=RoleEnum.OPERATOR,
    )

    def explode(*args, **kwargs):
        raise RuntimeError("simulated DB failure at outbox enqueue")

    monkeypatch.setattr(outbox_repository, "enqueue_event", explode)

    with pytest.raises(RuntimeError, match="simulated DB failure"):
        broker.submit_case_evidence(
            session=session,
            identity=identity,
            case_id="case_aml_001",
            file_name="rollback.bin",
            content_type="application/octet-stream",
            stream=io.BytesIO(b"bytes whose DB row must roll back"),
        )

    # One transaction: nothing persisted (the CASE_CREATED event from the
    # fixture predates the broker call; no EVIDENCE_SUBMITTED event exists).
    assert session.execute(select(EvidenceObject)).scalars().all() == []
    assert session.execute(select(Outbox)).scalars().all() == []
    case_events = session.execute(
        select(CaseEvent).where(CaseEvent.event_type == "EVIDENCE_SUBMITTED")
    ).scalars().all()
    assert case_events == []
    assert session.execute(select(EvidenceAnchor)).scalars().all() == []

    # Only unpublished staging is deleted: no staging residue anywhere.
    vault_root = store.base_dir
    residue = [str(p) for p in vault_root.rglob(".staging*")]
    assert residue == [], f"staging leaked after DB failure: {residue}"

    # The disk object published before the DB write is an ORPHAN: it stays
    # (documented; later-retention work collects it, and we never delete
    # published or anchored files on the basis of a rolled-back transaction).
    orphans = list(vault_root.rglob("COMMITTED.marker"))
    assert len(orphans) == 1, f"expected the orphaned published object, got {orphans}"
