"""R08 outbox delivery — leases, raw-transaction persistence, case incidents.

Spec §7 (binding). Extends the outbox with lease/claim columns and creates
three new institutional tables:

- outbox (existing tenant table, EXTENDED only): lease_owner, lease_token,
  lease_expires_at, next_attempt_at, last_error. Existing rows/columns are
  untouched; RLS posture (ENABLE + FORCE + tenant_isolation_policy on
  current_setting) already covers whole rows, so the new columns inherit
  the policy scope; FORCE is re-asserted after the ALTER (idempotent,
  belt-and-braces, exactly like the r06_evidence_crypto revision).
- chain_submissions (NEW): signed raw tx + tx_hash + nonce persisted BEFORE
  broadcast. unique(chain_id, signer_address, nonce) and
  unique(institution_id, request_id, submission_kind). Full R11 RLS
  checklist for new tables.
- case_incident_mappings (NEW): unique(institution_id, deployment_id,
  case_id) with case_reference_hash + the real incident_id returned by
  createIncidentForCase (never an incident_id=1 assumption). Full RLS.
- worker_heartbeats (NEW): per-worker heartbeat rows. Full RLS.

Migration conventions (R11, binding): unique descriptive slug
('outbox_delivery'), down_revision = the sole head at merge time
('r06_evidence_crypto' — verified the versions/ head chain is
r11_baseline -> institutional_wallet_challenges -> r06_evidence_crypto),
single head maintained. On SQLite (dev/demo) the same tables/columns are
created without the RLS section.
"""

from alembic import op
import sqlalchemy as sa

revision = "outbox_delivery"
down_revision = "r07_verification_snapshots"
branch_labels = None
depends_on = None

NEW_OUTBOX_COLUMNS = [
    ("lease_owner", sa.String(length=128)),
    ("lease_token", sa.String(length=64)),
    ("lease_expires_at", sa.DateTime(timezone=True)),
    ("next_attempt_at", sa.DateTime(timezone=True)),
    ("last_error", sa.Text()),
]


def _rls_new_table(table: str) -> None:
    """R11 RLS checklist for a new institutional table."""
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation_policy ON {table} "
        "USING (institution_id = NULLIF(current_setting('app.current_institution_id', true), '')) "
        "WITH CHECK (institution_id = NULLIF(current_setting('app.current_institution_id', true), ''))"
    )


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # --- outbox: extend the existing tenant table with lease columns ------
    existing = {
        col["name"]
        for col in sa.inspect(bind).get_columns("outbox")
    }
    for name, col_type in NEW_OUTBOX_COLUMNS:
        if name not in existing:
            op.add_column("outbox", sa.Column(name, col_type, nullable=True))
    existing_idx = {
        ix["name"]
        for ix in sa.inspect(bind).get_indexes("outbox")
    }
    if "ix_outbox_claim" not in existing_idx:
        op.create_index(
            "ix_outbox_claim", "outbox",
            ["institution_id", "status", "next_attempt_at"],
        )
    if is_postgres:
        # Re-assert RLS posture on the extended table (idempotent; whole-row
        # policies already cover the new columns).
        op.execute("ALTER TABLE outbox ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE outbox FORCE ROW LEVEL SECURITY")

    # --- chain_submissions ------------------------------------------------
    op.create_table(
        "chain_submissions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("institution_id", sa.String(length=64), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("signer_address", sa.String(length=42), nullable=False),
        sa.Column("nonce", sa.BigInteger(), nullable=False),
        sa.Column("submission_kind", sa.String(length=32), nullable=False),
        sa.Column("request_id", sa.String(length=66), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("protected_raw_tx", sa.Text(), nullable=False),
        sa.Column("tx_hash", sa.String(length=66), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="SIGNED"),
        sa.Column("broadcast_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stuck_alerted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt_block_number", sa.BigInteger(), nullable=True),
        sa.Column("receipt_block_hash", sa.String(length=66), nullable=True),
        sa.Column("receipt_status", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["institution_id"], ["institutions.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("chain_id", "signer_address", "nonce", name="uq_chain_submission_nonce"),
        sa.UniqueConstraint("institution_id", "request_id", "submission_kind", name="uq_chain_submission_request"),
    )
    op.create_index("ix_chain_submissions_inst", "chain_submissions", ["institution_id"])
    op.create_index("ix_chain_submissions_signer", "chain_submissions", ["chain_id", "signer_address", "nonce"])

    # --- case_incident_mappings -------------------------------------------
    op.create_table(
        "case_incident_mappings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("institution_id", sa.String(length=64), nullable=False),
        sa.Column("deployment_id", sa.String(length=66), nullable=False),
        sa.Column("case_id", sa.String(length=64), nullable=False),
        sa.Column("case_reference_hash", sa.String(length=66), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["institution_id"], ["institutions.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("institution_id", "deployment_id", "case_id", name="uq_case_incident_mapping"),
    )
    op.create_index("ix_case_incident_mappings_inst", "case_incident_mappings", ["institution_id"])
    op.create_index("ix_case_incident_mappings_case", "case_incident_mappings", ["institution_id", "case_id"])

    # --- worker_heartbeats -------------------------------------------------
    op.create_table(
        "worker_heartbeats",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("institution_id", sa.String(length=64), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["institution_id"], ["institutions.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("institution_id", "worker_id", "role", name="uq_worker_heartbeat"),
    )
    op.create_index("ix_worker_heartbeats_inst", "worker_heartbeats", ["institution_id"])

    if is_postgres:
        for table in ("chain_submissions", "case_incident_mappings", "worker_heartbeats"):
            _rls_new_table(table)


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        for table in ("worker_heartbeats", "case_incident_mappings", "chain_submissions"):
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation_policy ON {table}")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_worker_heartbeats_inst", table_name="worker_heartbeats")
    op.drop_table("worker_heartbeats")
    op.drop_index("ix_case_incident_mappings_case", table_name="case_incident_mappings")
    op.drop_index("ix_case_incident_mappings_inst", table_name="case_incident_mappings")
    op.drop_table("case_incident_mappings")
    op.drop_index("ix_chain_submissions_signer", table_name="chain_submissions")
    op.drop_index("ix_chain_submissions_inst", table_name="chain_submissions")
    op.drop_table("chain_submissions")

    existing_idx = {
        ix["name"]
        for ix in sa.inspect(bind).get_indexes("outbox")
    }
    if "ix_outbox_claim" in existing_idx:
        op.drop_index("ix_outbox_claim", table_name="outbox")
    existing = {
        col["name"]
        for col in sa.inspect(bind).get_columns("outbox")
    }
    for name, _col_type in reversed(NEW_OUTBOX_COLUMNS):
        if name in existing:
            op.drop_column("outbox", name)
