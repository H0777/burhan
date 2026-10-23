"""
SQLAlchemy Multi-Tenant Models (T14)
Specification §4, §5, §7 (R01, R04, R08, R09, R14)
All tenant-scoped tables carry mandatory `institution_id` with composite constraints.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    BigInteger,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    UniqueConstraint,
    Index,
    ForeignKeyConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class Institution(Base):
    __tablename__ = "institutions"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Membership(Base):
    __tablename__ = "memberships"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    sub = Column(String(128), nullable=False, index=True)
    role = Column(String(32), nullable=False, default="NONE")
    email = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "sub", name="uq_membership_institution_sub"),
    )


class WalletBindingModel(Base):
    __tablename__ = "wallet_bindings"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    sub = Column(String(128), nullable=False, index=True)
    wallet_address = Column(String(42), nullable=False, index=True)
    participant_id = Column(String(66), nullable=False)
    role = Column(String(32), nullable=False)
    authorization_generation = Column(Integer, nullable=False, default=1)
    bound_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "sub", name="uq_wallet_binding_institution_sub"),
        Index("ix_wallet_bindings_inst_addr", "institution_id", "wallet_address"),
    )


class Case(Base):
    __tablename__ = "cases"

    id = Column(String(64), primary_key=True)
    case_number = Column(String(64), nullable=False)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(32), nullable=False, default="MEDIUM")
    status = Column(String(32), nullable=False, default="OPEN")
    assigned_to_sub = Column(String(128), nullable=True)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "case_number", name="uq_case_institution_number"),
        UniqueConstraint("institution_id", "id", name="uq_case_institution_id"),
        Index("ix_cases_inst_status_created", "institution_id", "status", "created_at"),
    )


class CaseEvent(Base):
    __tablename__ = "case_events"

    id = Column(String(64), primary_key=True)
    case_id = Column(String(64), nullable=False, index=True)
    institution_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    actor_sub = Column(String(128), nullable=False)
    payload_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["institution_id", "case_id"],
            ["cases.institution_id", "cases.id"],
            ondelete="CASCADE",
            name="fk_case_events_case",
        ),
        Index("ix_case_events_inst_case", "institution_id", "case_id"),
    )


class EvidenceObject(Base):
    __tablename__ = "evidence_objects"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), nullable=False, index=True)
    case_id = Column(String(64), nullable=False, index=True)
    evidence_id = Column(String(64), nullable=False, index=True)
    object_version = Column(Integer, nullable=False, default=1)
    file_name = Column(String(255), nullable=False)
    content_type = Column(String(128), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    storage_path = Column(String(512), nullable=False)
    encrypted = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["institution_id", "case_id"],
            ["cases.institution_id", "cases.id"],
            ondelete="CASCADE",
            name="fk_evidence_objects_case",
        ),
        UniqueConstraint(
            "institution_id", "evidence_id", "object_version",
            name="uq_evidence_object_version",
        ),
        Index("ix_evidence_objects_inst_case", "institution_id", "case_id"),
    )


class EvidenceAnchor(Base):
    __tablename__ = "evidence_anchors"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), nullable=False, index=True)
    case_id = Column(String(64), nullable=False, index=True)
    evidence_id = Column(String(64), nullable=False, index=True)
    anchor_request_id = Column(String(66), nullable=False, index=True)
    chain_id = Column(Integer, nullable=False)
    contract_address = Column(String(42), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING_ANCHOR")  # PENDING_ANCHOR, ANCHORED, FAILED
    transaction_hash = Column(String(66), nullable=True)
    block_number = Column(BigInteger, nullable=True)
    block_hash = Column(String(66), nullable=True)
    entry_hash = Column(String(66), nullable=True)
    anchored_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["institution_id", "case_id"],
            ["cases.institution_id", "cases.id"],
            ondelete="CASCADE",
            name="fk_evidence_anchors_case",
        ),
        UniqueConstraint("institution_id", "anchor_request_id", name="uq_evidence_anchor_request"),
        Index("ix_evidence_anchors_inst_ev", "institution_id", "evidence_id"),
    )


class Outbox(Base):
    __tablename__ = "outbox"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    payload_json = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="PENDING")  # PENDING, PROCESSING, COMPLETED, FAILED
    attempts = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_outbox_status_attempts", "status", "attempts"),
    )


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    key = Column(String(128), nullable=False)
    request_hash = Column(String(64), nullable=False)
    response_json = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "key", name="uq_idempotency_inst_key"),
    )


class TransactionRecord(Base):
    __tablename__ = "transactions"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(32), nullable=False)  # "IQD_CSV", "EVM", "MANUAL"
    external_id = Column(String(128), nullable=False)
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    sender_ref = Column(String(128), nullable=False)
    receiver_ref = Column(String(128), nullable=False)
    currency = Column(String(16), nullable=False, default="IQD")
    scale = Column(Integer, nullable=False, default=2)
    amount_minor = Column(BigInteger, nullable=False)
    status = Column(String(32), nullable=False, default="RECORDED")
    risk_score = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "source", "external_id", name="uq_tx_inst_source_ext"),
        Index("ix_tx_inst_occurred", "institution_id", "occurred_at"),
        Index("ix_tx_inst_sender_occurred", "institution_id", "sender_ref", "occurred_at"),
    )


class ImportBatchRecord(Base):
    __tablename__ = "import_batches"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(32), nullable=False, default="IQD_CSV")
    filename = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False, default="COMPLETED")
    total_rows = Column(Integer, nullable=False, default=0)
    accepted_rows = Column(Integer, nullable=False, default=0)
    rejected_rows = Column(Integer, nullable=False, default=0)
    errors_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_import_inst_created", "institution_id", "created_at"),
    )



class PolicyVersionRecord(Base):
    __tablename__ = "policy_versions"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    policy_id = Column(String(64), nullable=False, index=True)
    version = Column(String(32), nullable=False)
    version_number = Column(Integer, nullable=True)
    policy_hash = Column(String(64), nullable=True)
    rules_json = Column(Text, nullable=True)
    currency = Column(String(8), nullable=False, default="IQD")
    scale = Column(Integer, nullable=False, default=3)
    large_threshold_minor = Column(BigInteger, nullable=False, default=15000000000)
    daily_volume_limit_minor = Column(BigInteger, nullable=False, default=75000000000)
    max_daily_transactions = Column(Integer, nullable=False, default=20)
    max_after_hours_actions = Column(Integer, nullable=False, default=3)
    max_warning_overrides = Column(Integer, nullable=False, default=5)
    is_active = Column(Boolean, default=True, nullable=False)
    activated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "policy_id", "version", name="uq_policy_version_inst_ver"),
    )


class AssessmentRecord(Base):
    __tablename__ = "assessments"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    transaction_id = Column(String(64), ForeignKey("transactions.id", ondelete="CASCADE"), nullable=True, index=True)
    case_id = Column(String(64), nullable=True)
    assessment_type = Column(String(32), nullable=True, default="RULES")
    policy_id = Column(String(64), nullable=True)
    policy_version = Column(String(32), nullable=True)
    score = Column(Integer, nullable=True)
    fraud_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(16), nullable=False, default="LOW")
    structuring_detected = Column(Boolean, default=False, nullable=False)
    rules_triggered_json = Column(Text, nullable=False, default="[]")
    feature_snapshot_json = Column(Text, nullable=False, default="{}")
    features_hash = Column(String(66), nullable=True)
    engine_version = Column(String(32), nullable=False, default="2.0.0")
    model_loaded = Column(Boolean, default=False, nullable=False)
    source = Column(String(32), nullable=False, default="AUTHORITATIVE")
    reasons_json = Column(Text, nullable=True, default="[]")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_assessments_inst_tx", "institution_id", "transaction_id"),
        Index("ix_assessments_inst_created", "institution_id", "created_at"),
    )


class ChainEventRecord(Base):
    __tablename__ = "chain_events"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    chain_id = Column(Integer, nullable=False)
    block_number = Column(BigInteger, nullable=False)
    block_hash = Column(String(66), nullable=False)
    transaction_hash = Column(String(66), nullable=False)
    log_index = Column(Integer, nullable=False)
    event_signature = Column(String(66), nullable=False)
    event_name = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="OBSERVED")  # OBSERVED, CONFIRMED, ORPHANED
    payload_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "institution_id", "chain_id", "block_hash", "transaction_hash", "log_index",
            name="uq_chain_event_inst_log",
        ),
        Index("ix_chain_events_inst_block", "institution_id", "chain_id", "block_number"),
    )


class CheckpointRecord(Base):
    __tablename__ = "checkpoints"

    id = Column(String(64), primary_key=True)
    institution_id = Column(String(64), ForeignKey("institutions.id", ondelete="CASCADE"), nullable=False, index=True)
    chain_id = Column(Integer, nullable=False)
    contract_address = Column(String(42), nullable=False)
    last_canonical_block_number = Column(BigInteger, nullable=False)
    last_canonical_block_hash = Column(String(66), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("institution_id", "chain_id", "contract_address", name="uq_checkpoint_inst_chain_contract"),
    )


class ReportRecord(Base):
    """
    Immutable Versioned Case Forensic Report Record (T20, R04, R15)
    Carries complete snapshot of findings, evidence manifest, and dossier hash.
    """
    __tablename__ = "case_reports"

    id = Column(String(64), primary_key=True)
    report_id = Column(String(64), nullable=False, index=True)
    institution_id = Column(String(64), nullable=False, index=True)
    case_id = Column(String(64), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    language = Column(String(8), nullable=False, default="en")
    dossier_hash = Column(String(66), nullable=False)
    integrity_status = Column(String(32), nullable=False)  # VERIFIED, UNANCHORED, TAMPER_DETECTED, UNAVAILABLE
    provenance_status = Column(String(64), nullable=False)
    markdown_content = Column(Text, nullable=False)
    manifest_json = Column(Text, nullable=False)
    created_by_sub = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["institution_id", "case_id"],
            ["cases.institution_id", "cases.id"],
            ondelete="CASCADE",
            name="fk_case_reports_case",
        ),
        UniqueConstraint("institution_id", "case_id", "version", name="uq_case_report_version"),
        Index("ix_case_reports_inst_case", "institution_id", "case_id"),
    )


# List of tables requiring PostgreSQL Row-Level Security
RLS_TABLES = [
    "memberships",
    "wallet_bindings",
    "cases",
    "case_events",
    "evidence_objects",
    "evidence_anchors",
    "case_reports",
    "outbox",
    "idempotency_keys",
    "transactions",
    "import_batches",
    "policy_versions",
    "assessments",
    "chain_events",
    "checkpoints",
]


def generate_rls_sql() -> list[str]:
    """
    Generates PostgreSQL RLS statements for all tenant-scoped tables.
    """
    statements = []
    for table in RLS_TABLES:
        statements.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        statements.append(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        statements.append(f"DROP POLICY IF EXISTS tenant_isolation_policy ON {table};")
        statements.append(
            f"CREATE POLICY tenant_isolation_policy ON {table} "
            f"USING (institution_id = NULLIF(current_setting('app.current_institution_id', true), '')) "
            f"WITH CHECK (institution_id = NULLIF(current_setting('app.current_institution_id', true), ''));"
        )
    return statements
