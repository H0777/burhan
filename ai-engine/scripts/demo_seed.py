"""
Demo-only institution seed for the PostgreSQL demo compose stack.

R11 boundary: schema bootstrap on PostgreSQL belongs to alembic migrations and
the engine's startup NEVER seeds data on PostgreSQL — seeding stays confined to
the SQLite dev/demo path (app.db.session.init_db). The demo compose stack runs
the engine on PostgreSQL with the demo identity (APP_MODE=demo), so the FK
target for the demo tenant (settings.INSTITUTION_ID) must be seeded explicitly
by this one-shot container step (compose service db-seed), AFTER db-migrate.

Idempotent: inserts the row only when missing, so `docker compose up` on an
existing demo volume is a no-op. Exits non-zero on any failure so the
`service_completed_successfully` gate actually gates the engine start.

This script is NOT part of the institutional path: institutional deployments
seed institutions through their own operator workflow (infra/staging), never
through this file.
"""

import sys

from app.config import settings
from app.db.models import Institution
from app.db.session import get_engine, get_session_factory


def main() -> int:
    engine = get_engine()
    dialect = engine.dialect.name
    institution_id = settings.INSTITUTION_ID

    session_factory = get_session_factory(engine)
    with session_factory() as session:
        existing = session.get(Institution, institution_id)
        if existing is not None:
            print(
                f"[demo-seed] institution {institution_id!r} already present "
                f"(dialect={dialect}); nothing to do."
            )
            return 0
        session.add(
            Institution(
                id=institution_id,
                name="Central Bank of Iraq (CBI) Demo Institution",
                is_active=True,
            )
        )
        session.commit()
        print(
            f"[demo-seed] inserted institution {institution_id!r} "
            f"(dialect={dialect})."
        )
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — one-shot must fail loudly
        print(f"[demo-seed] FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
