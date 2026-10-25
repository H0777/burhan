"""Persistent single-use SIWE wallet challenges for institutional wallet binding.

Created for the R10 identity work (persistent institutional identity with OIDC,
wallet binding and membership revocation). The wallet_challenges table stores
every issued SIWE challenge bound to its user (sub), institution, SIWE domain
and chain id, with a globally unique nonce and a consumed_at single-use marker
so consumption is an atomic compare-and-swap that survives process restarts.

R11 migration conventions (binding — see docs/verification/remediation/R11.md §6):
  * unique descriptive revision slug (not tied to plan task ids);
  * down_revision = current HEAD at merge time (r11_baseline);
  * new institutional table: institution_id with a tenant FK to institutions,
    per-institution indexes, and the baseline-pattern RLS section
    (ENABLE + FORCE + tenant_isolation_policy with USING + WITH CHECK);
  * app-role grants flow from ALTER DEFAULT PRIVILEGES FOR ROLE ira_aml_migrator
    (already provisioned by ops/postgres/init-roles.sql).

On SQLite (dev/demo) this migration creates the same table without the RLS
section, mirroring the r11_baseline structure.
"""

from alembic import op
import sqlalchemy as sa

revision = "institutional_wallet_challenges"
down_revision = "r11_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wallet_challenges",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("institution_id", sa.String(length=64), nullable=False),
        sa.Column("sub", sa.String(length=128), nullable=False),
        sa.Column("wallet_address", sa.String(length=42), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("chain_id", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False, unique=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["institution_id"], ["institutions.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_wallet_challenges_institution_id", "wallet_challenges", ["institution_id"])
    op.create_index("ix_wallet_challenges_sub", "wallet_challenges", ["sub"])
    op.create_index("ix_wallet_challenges_inst_sub", "wallet_challenges", ["institution_id", "sub"])
    op.create_index("ix_wallet_challenges_inst_wallet", "wallet_challenges", ["institution_id", "wallet_address"])

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite (dev/demo): table only; RLS is a PostgreSQL concern.
        return
    # RLS checklist for the new institutional table (R11 §6): ENABLE + FORCE +
    # tenant policy with USING and WITH CHECK, exactly like the baseline.
    op.execute("ALTER TABLE wallet_challenges ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE wallet_challenges FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation_policy ON wallet_challenges "
        "USING (institution_id = NULLIF(current_setting('app.current_institution_id', true), '')) "
        "WITH CHECK (institution_id = NULLIF(current_setting('app.current_institution_id', true), ''))"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS tenant_isolation_policy ON wallet_challenges")
        op.execute("ALTER TABLE wallet_challenges DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_wallet_challenges_inst_wallet", table_name="wallet_challenges")
    op.drop_index("ix_wallet_challenges_inst_sub", table_name="wallet_challenges")
    op.drop_index("ix_wallet_challenges_sub", table_name="wallet_challenges")
    op.drop_index("ix_wallet_challenges_institution_id", table_name="wallet_challenges")
    op.drop_table("wallet_challenges")
