"""R11 baseline schema — the complete institutional data model.

Created as the schema authority for the remediation platform: every
later revision chains onto this head with a unique descriptive slug and
down_revision = current HEAD at merge time (R11 convention).

PostgreSQL-only section: FORCE ROW LEVEL SECURITY on every institutional
data table with the transaction-local tenant policy, plus an explicit
read-only policy on the global institutions table. On SQLite this
migration creates the same tables without the RLS section (dev/demo only).
"""

from alembic import op
import sqlalchemy as sa

revision = "r11_baseline"
down_revision = None
branch_labels = None
depends_on = None

# Frozen at baseline; institutional (tenant-scoped) tables.
TENANT_TABLES = [
    'memberships',
    'wallet_bindings',
    'cases',
    'case_events',
    'evidence_objects',
    'evidence_anchors',
    'case_reports',
    'outbox',
    'idempotency_keys',
    'transactions',
    'import_batches',
    'policy_versions',
    'assessments',
    'chain_events',
    'checkpoints',
]

TABLE_ORDER = [
    'institutions',
    'cases',
    'chain_events',
    'checkpoints',
    'idempotency_keys',
    'import_batches',
    'memberships',
    'outbox',
    'policy_versions',
    'transactions',
    'wallet_bindings',
    'assessments',
    'case_events',
    'case_reports',
    'evidence_anchors',
    'evidence_objects',
]


def upgrade() -> None:
    op.create_table(
        'institutions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_institutions_id', 'institutions', ['id'])

    op.create_table(
        'cases',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('case_number', sa.String(length=64), nullable=False),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('assigned_to_sub', sa.String(length=128)),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'id', name='uq_case_institution_id'),
        sa.UniqueConstraint('institution_id', 'case_number', name='uq_case_institution_number'),
    )
    op.create_index('ix_cases_inst_status_created', 'cases', ['institution_id', 'status', 'created_at'])
    op.create_index('ix_cases_institution_id', 'cases', ['institution_id'])

    op.create_table(
        'chain_events',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('chain_id', sa.Integer(), nullable=False),
        sa.Column('block_number', sa.BigInteger(), nullable=False),
        sa.Column('block_hash', sa.String(length=66), nullable=False),
        sa.Column('transaction_hash', sa.String(length=66), nullable=False),
        sa.Column('log_index', sa.Integer(), nullable=False),
        sa.Column('event_signature', sa.String(length=66), nullable=False),
        sa.Column('event_name', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'chain_id', 'block_hash', 'transaction_hash', 'log_index', name='uq_chain_event_inst_log'),
    )
    op.create_index('ix_chain_events_inst_block', 'chain_events', ['institution_id', 'chain_id', 'block_number'])
    op.create_index('ix_chain_events_institution_id', 'chain_events', ['institution_id'])

    op.create_table(
        'checkpoints',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('chain_id', sa.Integer(), nullable=False),
        sa.Column('contract_address', sa.String(length=42), nullable=False),
        sa.Column('last_canonical_block_number', sa.BigInteger(), nullable=False),
        sa.Column('last_canonical_block_hash', sa.String(length=66), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'chain_id', 'contract_address', name='uq_checkpoint_inst_chain_contract'),
    )
    op.create_index('ix_checkpoints_institution_id', 'checkpoints', ['institution_id'])

    op.create_table(
        'idempotency_keys',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('key', sa.String(length=128), nullable=False),
        sa.Column('request_hash', sa.String(length=64), nullable=False),
        sa.Column('response_json', sa.Text()),
        sa.Column('status_code', sa.Integer()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'key', name='uq_idempotency_inst_key'),
    )
    op.create_index('ix_idempotency_keys_institution_id', 'idempotency_keys', ['institution_id'])

    op.create_table(
        'import_batches',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('total_rows', sa.Integer(), nullable=False),
        sa.Column('accepted_rows', sa.Integer(), nullable=False),
        sa.Column('rejected_rows', sa.Integer(), nullable=False),
        sa.Column('errors_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_import_batches_institution_id', 'import_batches', ['institution_id'])
    op.create_index('ix_import_inst_created', 'import_batches', ['institution_id', 'created_at'])

    op.create_table(
        'memberships',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('sub', sa.String(length=128), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('email', sa.String(length=255)),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'sub', name='uq_membership_institution_sub'),
    )
    op.create_index('ix_memberships_institution_id', 'memberships', ['institution_id'])
    op.create_index('ix_memberships_sub', 'memberships', ['sub'])

    op.create_table(
        'outbox',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('error_message', sa.Text()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('processed_at', sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_outbox_institution_id', 'outbox', ['institution_id'])
    op.create_index('ix_outbox_status_attempts', 'outbox', ['status', 'attempts'])

    op.create_table(
        'policy_versions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('policy_id', sa.String(length=64), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('version_number', sa.Integer()),
        sa.Column('policy_hash', sa.String(length=64)),
        sa.Column('rules_json', sa.Text()),
        sa.Column('currency', sa.String(length=8), nullable=False),
        sa.Column('scale', sa.Integer(), nullable=False),
        sa.Column('large_threshold_minor', sa.BigInteger(), nullable=False),
        sa.Column('daily_volume_limit_minor', sa.BigInteger(), nullable=False),
        sa.Column('max_daily_transactions', sa.Integer(), nullable=False),
        sa.Column('max_after_hours_actions', sa.Integer(), nullable=False),
        sa.Column('max_warning_overrides', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'policy_id', 'version', name='uq_policy_version_inst_ver'),
    )
    op.create_index('ix_policy_versions_institution_id', 'policy_versions', ['institution_id'])
    op.create_index('ix_policy_versions_policy_id', 'policy_versions', ['policy_id'])

    op.create_table(
        'transactions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('external_id', sa.String(length=128), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sender_ref', sa.String(length=128), nullable=False),
        sa.Column('receiver_ref', sa.String(length=128), nullable=False),
        sa.Column('currency', sa.String(length=16), nullable=False),
        sa.Column('scale', sa.Integer(), nullable=False),
        sa.Column('amount_minor', sa.BigInteger(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('risk_score', sa.Integer()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'source', 'external_id', name='uq_tx_inst_source_ext'),
    )
    op.create_index('ix_transactions_institution_id', 'transactions', ['institution_id'])
    op.create_index('ix_tx_inst_occurred', 'transactions', ['institution_id', 'occurred_at'])
    op.create_index('ix_tx_inst_sender_occurred', 'transactions', ['institution_id', 'sender_ref', 'occurred_at'])

    op.create_table(
        'wallet_bindings',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('sub', sa.String(length=128), nullable=False),
        sa.Column('wallet_address', sa.String(length=42), nullable=False),
        sa.Column('participant_id', sa.String(length=66), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('authorization_generation', sa.Integer(), nullable=False),
        sa.Column('bound_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('institution_id', 'sub', name='uq_wallet_binding_institution_sub'),
    )
    op.create_index('ix_wallet_bindings_inst_addr', 'wallet_bindings', ['institution_id', 'wallet_address'])
    op.create_index('ix_wallet_bindings_institution_id', 'wallet_bindings', ['institution_id'])
    op.create_index('ix_wallet_bindings_sub', 'wallet_bindings', ['sub'])
    op.create_index('ix_wallet_bindings_wallet_address', 'wallet_bindings', ['wallet_address'])

    op.create_table(
        'assessments',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('transaction_id', sa.String(length=64)),
        sa.Column('case_id', sa.String(length=64)),
        sa.Column('assessment_type', sa.String(length=32)),
        sa.Column('policy_id', sa.String(length=64)),
        sa.Column('policy_version', sa.String(length=32)),
        sa.Column('score', sa.Integer()),
        sa.Column('fraud_score', sa.Integer(), nullable=False),
        sa.Column('risk_level', sa.String(length=16), nullable=False),
        sa.Column('structuring_detected', sa.Boolean(), nullable=False),
        sa.Column('rules_triggered_json', sa.Text(), nullable=False),
        sa.Column('feature_snapshot_json', sa.Text(), nullable=False),
        sa.Column('features_hash', sa.String(length=66)),
        sa.Column('engine_version', sa.String(length=32), nullable=False),
        sa.Column('model_loaded', sa.Boolean(), nullable=False),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('reasons_json', sa.Text()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['transaction_id'], ['transactions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['institution_id'], ['institutions.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_assessments_inst_created', 'assessments', ['institution_id', 'created_at'])
    op.create_index('ix_assessments_inst_tx', 'assessments', ['institution_id', 'transaction_id'])
    op.create_index('ix_assessments_institution_id', 'assessments', ['institution_id'])
    op.create_index('ix_assessments_transaction_id', 'assessments', ['transaction_id'])

    op.create_table(
        'case_events',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('actor_sub', sa.String(length=128), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id', 'case_id'], ['cases.institution_id', 'cases.id'], ondelete='CASCADE', name='fk_case_events_case'),
    )
    op.create_index('ix_case_events_case_id', 'case_events', ['case_id'])
    op.create_index('ix_case_events_inst_case', 'case_events', ['institution_id', 'case_id'])
    op.create_index('ix_case_events_institution_id', 'case_events', ['institution_id'])

    op.create_table(
        'case_reports',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('report_id', sa.String(length=64), nullable=False),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('language', sa.String(length=8), nullable=False),
        sa.Column('dossier_hash', sa.String(length=66), nullable=False),
        sa.Column('integrity_status', sa.String(length=32), nullable=False),
        sa.Column('provenance_status', sa.String(length=64), nullable=False),
        sa.Column('markdown_content', sa.Text(), nullable=False),
        sa.Column('manifest_json', sa.Text(), nullable=False),
        sa.Column('created_by_sub', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id', 'case_id'], ['cases.institution_id', 'cases.id'], ondelete='CASCADE', name='fk_case_reports_case'),
        sa.UniqueConstraint('institution_id', 'case_id', 'version', name='uq_case_report_version'),
    )
    op.create_index('ix_case_reports_case_id', 'case_reports', ['case_id'])
    op.create_index('ix_case_reports_inst_case', 'case_reports', ['institution_id', 'case_id'])
    op.create_index('ix_case_reports_institution_id', 'case_reports', ['institution_id'])
    op.create_index('ix_case_reports_report_id', 'case_reports', ['report_id'])

    op.create_table(
        'evidence_anchors',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=False),
        sa.Column('anchor_request_id', sa.String(length=66), nullable=False),
        sa.Column('chain_id', sa.Integer(), nullable=False),
        sa.Column('contract_address', sa.String(length=42), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('transaction_hash', sa.String(length=66)),
        sa.Column('block_number', sa.BigInteger()),
        sa.Column('block_hash', sa.String(length=66)),
        sa.Column('entry_hash', sa.String(length=66)),
        sa.Column('anchored_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id', 'case_id'], ['cases.institution_id', 'cases.id'], ondelete='CASCADE', name='fk_evidence_anchors_case'),
        sa.UniqueConstraint('institution_id', 'anchor_request_id', name='uq_evidence_anchor_request'),
    )
    op.create_index('ix_evidence_anchors_anchor_request_id', 'evidence_anchors', ['anchor_request_id'])
    op.create_index('ix_evidence_anchors_case_id', 'evidence_anchors', ['case_id'])
    op.create_index('ix_evidence_anchors_evidence_id', 'evidence_anchors', ['evidence_id'])
    op.create_index('ix_evidence_anchors_inst_ev', 'evidence_anchors', ['institution_id', 'evidence_id'])
    op.create_index('ix_evidence_anchors_institution_id', 'evidence_anchors', ['institution_id'])

    op.create_table(
        'evidence_objects',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('institution_id', sa.String(length=64), nullable=False),
        sa.Column('case_id', sa.String(length=64), nullable=False),
        sa.Column('evidence_id', sa.String(length=64), nullable=False),
        sa.Column('object_version', sa.Integer(), nullable=False),
        sa.Column('file_name', sa.String(length=255), nullable=False),
        sa.Column('content_type', sa.String(length=128), nullable=False),
        sa.Column('file_size', sa.BigInteger(), nullable=False),
        sa.Column('sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('storage_path', sa.String(length=512), nullable=False),
        sa.Column('encrypted', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['institution_id', 'case_id'], ['cases.institution_id', 'cases.id'], ondelete='CASCADE', name='fk_evidence_objects_case'),
        sa.UniqueConstraint('institution_id', 'evidence_id', 'object_version', name='uq_evidence_object_version'),
    )
    op.create_index('ix_evidence_objects_case_id', 'evidence_objects', ['case_id'])
    op.create_index('ix_evidence_objects_evidence_id', 'evidence_objects', ['evidence_id'])
    op.create_index('ix_evidence_objects_inst_case', 'evidence_objects', ['institution_id', 'case_id'])
    op.create_index('ix_evidence_objects_institution_id', 'evidence_objects', ['institution_id'])

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite (dev/demo): tables above only; RLS is a PostgreSQL concern.
        return
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation_policy ON {table} "
            "USING (institution_id = NULLIF(current_setting('app.current_institution_id', true), '')) "
            "WITH CHECK (institution_id = NULLIF(current_setting('app.current_institution_id', true), ''))"
        )
    # Global table: explicit policy, read-only for the app role (never assumed
    # safe just because it has no institution_id).
    op.execute("ALTER TABLE institutions ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY institutions_read_all ON institutions FOR SELECT USING (true)"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in TENANT_TABLES:
            op.execute(f"DROP POLICY IF EXISTS tenant_isolation_policy ON {table}")
        op.execute("DROP POLICY IF EXISTS institutions_read_all ON institutions")
        op.execute("ALTER TABLE institutions DISABLE ROW LEVEL SECURITY")
    for table in reversed(TABLE_ORDER):
        op.drop_table(table)

