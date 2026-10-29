"""
Database Session and Tenant Transaction Management (T14, R11)
Specification §4, §7 (R01, R09, R11)
Enforces transaction-scoped tenant isolation via
`SELECT set_config('app.current_institution_id', :id, true)` — transaction-local,
so the context can never leak to a reused pooled connection.

R11: PostgreSQL schema ownership belongs to alembic migrations (run with the
dedicated migration/owner role, see ops/postgres/init-roles.sql). The
production startup path verifies the schema revision and NEVER creates tables
or seeds data; create_all/seed are confined to the SQLite dev/demo path.
"""

from pathlib import Path
from typing import Generator, Optional
from contextlib import contextmanager
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine

from app.config import settings
from app.db.models import Base, Institution
from app.security.tenant_context import TenantContext

_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker] = None

ALEMBIC_INI_PATH = Path(__file__).resolve().parents[2] / "alembic.ini"
# Used only when alembic.ini/alembic itself is unavailable (e.g. minimal
# deployments without the migration scripts); the real head comes from the
# alembic script directory whenever possible.
FALLBACK_HEAD_REVISION = "r11_baseline"


def get_engine(database_url: Optional[str] = None) -> Engine:
    global _engine
    if _engine is None or database_url is not None:
        url = database_url or settings.DATABASE_URL
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            from sqlalchemy.pool import StaticPool
            kwargs = {"connect_args": connect_args, "echo": settings.DATABASE_ECHO}
            if ":memory:" in url:
                kwargs["poolclass"] = StaticPool
            eng = create_engine(url, **kwargs)
            # Enable SQLite foreign keys
            @event.listens_for(eng, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        else:
            eng = create_engine(
                url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
                echo=settings.DATABASE_ECHO,
            )

        _engine = eng
        _session_factory = None
        return eng

    return _engine


def set_engine(engine: Optional[Engine]) -> None:
    global _engine, _session_factory
    _engine = engine
    _session_factory = None


def get_session_factory(engine: Optional[Engine] = None) -> sessionmaker:
    global _session_factory
    eng = engine or get_engine()
    if _session_factory is None or engine is not None:
        factory = sessionmaker(autocommit=False, autoflush=False, bind=eng)
        if engine is None:
            _session_factory = factory
        return factory
    return _session_factory


def _alembic_head_revision() -> str:
    """Best-effort current head of the alembic script directory."""
    try:
        from alembic.config import Config as AlembicConfig
        from alembic.script import ScriptDirectory

        if not ALEMBIC_INI_PATH.exists():
            return FALLBACK_HEAD_REVISION
        script = ScriptDirectory.from_config(AlembicConfig(str(ALEMBIC_INI_PATH)))
        return script.get_current_head() or FALLBACK_HEAD_REVISION
    except Exception:
        return FALLBACK_HEAD_REVISION


def verify_schema_revision(engine: Optional[Engine] = None) -> str:
    """
    R11 production startup gate: the PostgreSQL database must be migrated to the
    current alembic head. Never creates tables and never seeds data.

    Raises RuntimeError when the database is unmigrated (no alembic_version) or
    not at head. On SQLite (dev/demo) this check is a no-op and returns a marker.
    """
    eng = engine or get_engine()
    if eng.dialect.name != "postgresql":
        return "sqlite-dev"

    expected = _alembic_head_revision()
    try:
        with eng.connect() as conn:
            row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
    except Exception as exc:
        raise RuntimeError(
            "Database schema is not migrated: alembic_version is unreadable. "
            "Run 'alembic upgrade head' with the migration role before starting "
            f"(original error: {exc})."
        ) from exc

    if row is None:
        raise RuntimeError(
            "Database schema is not migrated: alembic_version is empty. "
            "Run 'alembic upgrade head' with the migration role before starting."
        )
    current = row[0]
    if current != expected:
        raise RuntimeError(
            f"Database schema revision {current!r} is not the expected head {expected!r}. "
            "Run 'alembic upgrade head' with the migration role before starting."
        )
    return current


def init_db(engine: Optional[Engine] = None) -> Optional[str]:
    """
    Startup database initialization (R11).

    PostgreSQL (production/institutional path): verifies the schema is migrated to
    the alembic head and nothing else — migrations own the schema; create_all and
    seeding are never called here. Returns the verified revision string so the
    startup log can PROVE the migration-owned path was taken (H04).

    SQLite (local dev/demo/test ONLY): creates tables and seeds the demo
    institution, which is where schema bootstrap is confined per spec §8.
    Returns None (create_all path).
    """
    eng = engine or get_engine()
    if eng.dialect.name != "postgresql":
        Base.metadata.create_all(bind=eng)
        _seed_demo_institution(eng)
        return None
    return verify_schema_revision(eng)


def _seed_demo_institution(eng: Engine) -> None:
    """Dev/demo-only default institution seed (SQLite path)."""
    session_factory = get_session_factory(eng)
    with session_factory() as session:
        default_inst = session.get(Institution, settings.INSTITUTION_ID)
        if not default_inst:
            session.add(
                Institution(
                    id=settings.INSTITUTION_ID,
                    name="Central Bank of Iraq (CBI) Demo Institution",
                    is_active=True,
                )
            )
            session.commit()


def apply_tenant_context(session: Session, institution_id: str) -> None:
    """
    (Re)apply the transaction-local tenant context on `session` (H04).

    `tenant_transaction` scopes one WHOLE unit of work. Background workers that
    manage their own transaction boundaries (the indexer commits mid-step) must
    re-apply the context at the start of every new transaction segment:
    set_config(..., is_local => true) evaporates at COMMIT, and on PostgreSQL
    every later statement would otherwise run context-less under FORCE RLS.
    On SQLite this is a no-op (no server-side tenant context).
    """
    if not institution_id or not isinstance(institution_id, str):
        raise ValueError("Valid institution_id required for apply_tenant_context")

    inst_id = institution_id.strip()
    # Shared validation type for the institutional tenant context.
    TenantContext(inst_id)

    bind = session.get_bind()
    if bool(bind) and bind.dialect.name == "postgresql":
        with session.no_autoflush:
            session.execute(
                text("SELECT set_config('app.current_institution_id', :inst_id, true)"),
                {"inst_id": inst_id},
            )


@contextmanager
def tenant_transaction(session: Session, institution_id: str) -> Generator[Session, None, None]:
    """
    Context manager that applies the transaction-local tenant context within one
    transaction, committing on success and rolling back on any error.

    PostgreSQL: `SELECT set_config('app.current_institution_id', :inst_id, true)`.
    The third argument (is_local=true) makes the setting vanish at COMMIT or
    ROLLBACK, so a pooled connection is always reused WITHOUT a tenant context
    (R11: `SET LOCAL` cannot take bound parameters — set_config is the only
    valid bindable form).

    SQLite: there is no server-side tenant context; isolation is enforced by the
    repositories (logic-only dev/test path).
    """
    if not institution_id or not isinstance(institution_id, str):
        raise ValueError("Valid institution_id required for tenant_transaction")

    inst_id = institution_id.strip()
    # Shared validation type for the institutional tenant context.
    TenantContext(inst_id)

    bind = session.get_bind()
    is_postgres = bool(bind) and bind.dialect.name == "postgresql"

    try:
        if is_postgres:
            # R08: set the tenant context BEFORE any autoflush can fire —
            # a dirty ORM object flushed during this execute would otherwise
            # run its UPDATE/INSERT outside the tenant policy and fail under
            # FORCEd RLS (StaleDataError / 0 rows matched). no_autoflush
            # scopes to exactly this statement; later executes inside the
            # transaction flush normally, with the context applied.
            with session.no_autoflush:
                session.execute(
                    text("SELECT set_config('app.current_institution_id', :inst_id, true)"),
                    {"inst_id": inst_id},
                )
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a database session and ensuring proper closure.
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
