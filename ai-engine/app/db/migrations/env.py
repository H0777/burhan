"""
Alembic migration environment (R11).

Conventions (binding for every later revision — see docs/verification/remediation/R11.md):

  * The migration database URL comes EXCLUSIVELY from the MIGRATION_DATABASE_URL
    environment variable — the dedicated migration/owner role, never the app role
    and never a credential committed to the repository.
  * SQLite URLs are refused. Migrations are a PostgreSQL concern; SQLite is the
    local dev/demo path where Base.metadata.create_all is confined (R11 spec §8).
    This also protects the developer's local cyber_audit_chain.db from accidents.
  * target_metadata is the live SQLAlchemy metadata, so `alembic check` and
    autogenerate stay honest against the models.
  * Revision naming: every revision gets a unique descriptive slug; its
    down_revision must point at the current HEAD at merge time. Never more than
    one head; never tie down_revision to plan task numbers.

CLI (script mode):
    python app/db/migrations/env.py stamp-if-matches

    Baselines a PRE-EXISTING database whose schema already matches the current
    models: it compares the live schema against Base.metadata and stamps the
    current head ONLY when there is no drift. An unknown/drifted schema is
    refused with a non-zero exit and nothing is stamped — there is never an
    auto-stamp of a database we cannot verify.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

AI_ENGINE_DIR = Path(__file__).resolve().parents[3]
ALEMBIC_INI_PATH = AI_ENGINE_DIR / "alembic.ini"
MIGRATION_URL_ENV_VAR = "MIGRATION_DATABASE_URL"


def _migration_url() -> str:
    url = os.environ.get(MIGRATION_URL_ENV_VAR, "")
    if not url:
        raise SystemExit(
            f"{MIGRATION_URL_ENV_VAR} must be set: migrations run with the dedicated "
            "migration/owner role, never the app role and never a committed credential."
        )
    if url.startswith("sqlite"):
        raise SystemExit(
            "SQLite URLs are refused for migrations: migrations are a PostgreSQL "
            "concern (R11); SQLite dev databases are created via Base.metadata."
        )
    return url


def _stamp_if_matches() -> int:
    """Compare a pre-existing database against the models and stamp only on match."""
    from alembic.autogenerate import compare_metadata
    from alembic.command import stamp
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from sqlalchemy import create_engine

    cfg = Config(str(ALEMBIC_INI_PATH))
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    if head is None:
        print("stamp-if-matches: no revision head found", file=sys.stderr)
        return 2

    engine = create_engine(_migration_url())
    try:
        with engine.connect() as conn:
            existing = MigrationContext.configure(conn).get_current_revision()
            if existing is not None:
                if existing == head:
                    print(f"stamp-if-matches: already stamped at {existing!r}")
                    return 0
                print(
                    f"stamp-if-matches: database is stamped at {existing!r} which is not "
                    f"head {head!r}; refusing (run migrations instead)",
                    file=sys.stderr,
                )
                return 2

            diff = compare_metadata(
                MigrationContext.configure(conn, opts={"compare_type": True}),
                _target_metadata(),
            )
            if diff:
                print(
                    "stamp-if-matches: REFUSED — database schema does not match the "
                    f"baseline models ({len(diff)} difference(s)). An unknown database "
                    "is never stamped automatically. Resolve the drift manually:",
                    file=sys.stderr,
                )
                for item in diff:
                    print(f"  - {item}", file=sys.stderr)
                return 2
        print(f"stamp-if-matches: schema matches the models; stamping {head!r}")
    finally:
        engine.dispose()

    stamp(cfg, head)
    print(f"stamp-if-matches: stamped {head!r}")
    return 0


def _target_metadata():
    from app.db.models import Base

    return Base.metadata


if __name__ == "__main__":
    # Script mode: no alembic runtime context is available here, so the normal
    # env.py body below must not run in this mode.
    _command = sys.argv[1] if len(sys.argv) > 1 else ""
    if _command != "stamp-if-matches":
        print(
            "usage: python app/db/migrations/env.py stamp-if-matches\n"
            "(alembic itself invokes this file without arguments)",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(_stamp_if_matches())


# ---------------------------------------------------------------------------
# Normal alembic runtime (invoked by alembic; __name__ != "__main__")
# ---------------------------------------------------------------------------

from logging.config import fileConfig  # noqa: E402

from alembic import context  # noqa: E402
from sqlalchemy import engine_from_config, pool  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = _target_metadata()


def run_migrations_offline() -> None:
    """Offline mode emits SQL to stdout without a DBAPI connection."""
    context.configure(
        url=_migration_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Online mode connects with the migration role from MIGRATION_DATABASE_URL."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _migration_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
