"""R07 verification snapshots — persisted pinned-snapshot verification records.

Adds ``verification_snapshots``: one row per verification run (or reused
snapshot), binding the institution, the case, the deployment binding used,
the PINNED chain read point (block_number + block_hash at
latest-confirmation_depth+1), the incident head/count AT that pin, the
checked evidence ids and the final status/reasons. A later evidence append
never disturbs a prior valid snapshot: re-verification with a snapshot_id
re-reads at the SAME pin (the new head is beyond it by construction).

Conventions (R11, binding): unique revision slug, down_revision = the sole
head at merge time ('r06_evidence_crypto'), single head maintained.
RLS checklist for the new tenant table: ENABLE + FORCE ROW LEVEL SECURITY +
tenant_isolation_policy USING/WITH CHECK on current_setting
('app.current_institution_id') — identical posture to every other tenant
table from the r11 baseline; the app role keeps its existing DML grants via
the baseline's default privileges, so no new grants are issued here.
"""

from alembic import op
import sqlalchemy as sa

revision = "r07_verification_snapshots"
down_revision = "r06_evidence_crypto"
branch_labels = None
depends_on = None

TABLE = "verification_snapshots"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("institution_id", sa.String(64), nullable=False),
        sa.Column("case_id", sa.String(64), nullable=False),
        sa.Column("deployment_id", sa.String(80), nullable=True),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("block_number", sa.BigInteger(), nullable=False),
        sa.Column("block_hash", sa.String(66), nullable=False),
        sa.Column("head_entry_hash", sa.String(66), nullable=True),
        sa.Column("evidence_count", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reasons_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("evidence_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["institution_id", "case_id"],
            ["cases.institution_id", "cases.id"],
            ondelete="CASCADE",
            name="fk_verification_snapshots_case",
        ),
    )
    op.create_index(f"ix_{TABLE}_institution_id", TABLE, ["institution_id"])
    op.create_index(f"ix_{TABLE}_inst_case", TABLE, ["institution_id", "case_id"])

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite (dev/demo): table only; RLS is a PostgreSQL concern.
        return
    op.execute(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {TABLE} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation_policy ON {TABLE} "
        "USING (institution_id = NULLIF(current_setting('app.current_institution_id', true), '')) "
        "WITH CHECK (institution_id = NULLIF(current_setting('app.current_institution_id', true), ''))"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_policy ON {TABLE}")
    op.drop_index(f"ix_{TABLE}_inst_case", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_institution_id", table_name=TABLE)
    op.drop_table(TABLE)
