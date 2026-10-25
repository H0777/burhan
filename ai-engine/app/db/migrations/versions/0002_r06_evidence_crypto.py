"""R06 evidence crypto — encrypted-object metadata + signed manifest columns.

Adds the R06 columns to evidence_objects (only what the r11_baseline schema
does not already have; the baseline carries id/institution_id/case_id/
evidence_id/object_version/file_name/content_type/file_size/sha256_hash/
storage_path/encrypted/created_at and the uq_evidence_object_version unique
constraint, all preserved untouched):

- storage_format        : 'aes256gcm_v1' for R06 objects; legacy rows are
                          backfilled 'legacy_plaintext_read_only' (honest
                          classification, no retroactive conversion).
- encryption_key_id     : institution key id that wrapped the object's DEK.
- wrapped_dek           : JSON WrappedKey (ephemeral X25519 + nonce +
                          ciphertext) — the plaintext DEK is never stored.
- nonce / auth_tag      : base64 GCM nonce and authentication tag.
- manifest_envelope_json: the REAL signed service-manifest envelope
                          {body, algorithm:"Ed25519", signature} stored
                          BEFORE the outbox event referencing it.
- manifest_digest       : SHA-256 of the canonical SIGNED envelope (the
                          signature itself is inside the digest input).

Conventions (R11 binding): unique revision slug, down_revision = the sole
head at merge time ('institutional_wallet_challenges' — re-pointed from
'r11_baseline' after a parallel merge to restore the single head; the two
revisions touch independent tables, so the re-order is behaviorally safe),
single head maintained. evidence_objects
is an existing tenant table: its RLS policies (ENABLE + FORCE +
tenant_isolation_policy USING/WITH CHECK on current_setting) already cover
whole rows, so new columns are protected without new policies; this revision
re-asserts FORCE after the ALTER (belt-and-braces, idempotent) and does NOT
create new grants — default privileges from the baseline remain in effect.
"""

from alembic import op
import sqlalchemy as sa

revision = "r06_evidence_crypto"
down_revision = "institutional_wallet_challenges"
branch_labels = None
depends_on = None

NEW_COLUMNS = [
    ("storage_format", sa.String(length=32), sa.text("'legacy_plaintext_read_only'")),
    ("encryption_key_id", sa.String(length=128), None),
    ("wrapped_dek", sa.Text(), None),
    ("nonce", sa.String(length=64), None),
    ("auth_tag", sa.String(length=64), None),
    ("manifest_envelope_json", sa.Text(), None),
    ("manifest_digest", sa.String(length=64), None),
]


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    existing = {
        col["name"]
        for col in sa.inspect(bind).get_columns("evidence_objects")
    }
    for name, col_type, server_default in NEW_COLUMNS:
        if name in existing:
            continue  # add only what the current schema is missing
        op.add_column(
            "evidence_objects",
            sa.Column(name, col_type, nullable=True, server_default=server_default),
        )

    if is_postgres:
        # FORCEd RLS applies to the table OWNER too (the migrator), and the
        # tenant policy would hide every row from the maintenance UPDATEs
        # below (no app.current_institution_id is set on a migration
        # connection). Row-level maintenance is an owner operation: disable
        # for the backfill, then re-assert the full R11 posture.
        op.execute("ALTER TABLE evidence_objects DISABLE ROW LEVEL SECURITY")

    # Backfill: pre-R06 rows are plaintext reads of attested files. They stay
    # legacy_plaintext_read_only; `encrypted` is corrected to FALSE for them
    # (the previous default of TRUE was a false claim under R18 honesty).
    op.execute(
        "UPDATE evidence_objects SET storage_format = 'legacy_plaintext_read_only' "
        "WHERE storage_format IS NULL"
    )
    op.execute(
        "UPDATE evidence_objects SET encrypted = FALSE "
        "WHERE storage_format = 'legacy_plaintext_read_only'"
    )

    if is_postgres:
        # Re-assert the R11 RLS posture on the altered table (idempotent):
        # row-level policies cover whole rows, so the new columns are inside
        # the existing tenant_isolation_policy USING/WITH CHECK scope.
        op.execute("ALTER TABLE evidence_objects ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE evidence_objects FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    bind = op.get_bind()
    existing = {
        col["name"]
        for col in sa.inspect(bind).get_columns("evidence_objects")
    }
    for name, _col_type, _server_default in reversed(NEW_COLUMNS):
        if name in existing:
            op.drop_column("evidence_objects", name)
