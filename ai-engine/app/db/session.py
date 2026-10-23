"""
Database Session and Tenant Transaction Management (T14)
Specification §4, §7 (R01, R09)
Enforces transaction-scoped tenant isolation (SET LOCAL app.current_institution_id).
"""

from typing import Generator, Optional
from contextlib import contextmanager
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine

from app.config import settings
from app.db.models import Base, Institution, generate_rls_sql

_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker] = None


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


def init_db(engine: Optional[Engine] = None) -> None:
    """
    Initializes database tables, seeds default demo institution, and applies RLS policies if PostgreSQL.
    """
    eng = engine or get_engine()
    Base.metadata.create_all(bind=eng)
    if "postgresql" in str(eng.url):
        with eng.connect() as conn:
            for sql in generate_rls_sql():
                conn.execute(text(sql))
            conn.commit()

    # Ensure default institution exists for development and testing
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


@contextmanager
def tenant_transaction(session: Session, institution_id: str) -> Generator[Session, None, None]:
    """
    Context manager that sets the local tenant context within a transaction.
    Guarantees rollback on error and proper session cleanup.
    """
    if not institution_id or not isinstance(institution_id, str):
        raise ValueError("Valid institution_id required for tenant_transaction")

    inst_id = institution_id.strip()

    # If running on PostgreSQL, set transaction-local tenant variable
    bind = session.get_bind()
    is_postgres = "postgresql" in str(bind.url) if bind else False

    try:
        if is_postgres:
            session.execute(
                text("SET LOCAL app.current_institution_id = :inst_id"),
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

