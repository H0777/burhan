"""
PostgreSQL Row-Level Security and Migration Integration Tests (R11).

These are PostgreSQL-INTEGRATION tests, NOT logic tests. They require a disposable
PostgreSQL 16 test database and two roles provisioned by ops/postgres/init-roles.sql:

  - DATABASE_URL            -> least-privilege APP role (ira_aml_app), NOSUPERUSER
                               NOBYPASSRLS, non-owner.
  - MIGRATION_DATABASE_URL  -> separate migration OWNER role (ira_aml_migrator).

Both must be postgresql:// URLs pointing at the SAME disposable test database.
Without them the module SKIPS (the SQLite suites in this project are logic-only;
see tests/integration/test_tenant_storage.py).

Superuser policy: NO assertion uses a superuser connection. Behavioral assertions
always run as the app role; operational seeding runs as the migration owner role;
database/role provisioning happens out-of-band via ops/postgres/init-roles.sql.

Binding spec (remediation plan §8 / brief):
  - tenant_transaction uses SELECT set_config('app.current_institution_id', :id, true)
    inside one transaction; the context must never leak to a reused connection.
  - App role: NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE, owns no tables, no DDL.
  - FORCE ROW LEVEL SECURITY on every institutional data table; the global
    institutions table carries an explicit policy.
  - Migrations are the only schema authority: empty DB -> upgrade head;
    pre-existing matching DB -> comparison then stamp; unknown DB -> refusal (no stamp).
"""

import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    func,
    select,
    text,
    update,
)
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.models import (
    Base,
    Case,
    CaseEvent,
    EvidenceObject,
    IdempotencyKey,
    Institution,
    Membership,
    Outbox,
    ReportRecord,
    RLS_TABLES,
    TransactionRecord,
    WalletBindingModel,
)
from app.db.session import tenant_transaction

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT_A = "inst_cbi"
TENANT_B = "inst_rafidain"
MIGRATION_OWNER_ENV_VAR = "MIGRATION_DATABASE_URL"
BASELINE_REVISION = "r11_baseline"


def _require_pg_urls() -> tuple[str, str]:
    """Return (app_role_url, migration_owner_url) or skip when not provided."""
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get(MIGRATION_OWNER_ENV_VAR, "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R11 PostgreSQL integration tests require DATABASE_URL (app role) and "
            f"{MIGRATION_OWNER_ENV_VAR} (migration owner) pointing at a disposable "
            "PostgreSQL test database"
        )
    return app_url, migration_url


def _swap_db(url: str, db: str) -> str:
    """Point the same credentials at another database on the same test server."""
    return url.rsplit("/", 1)[0] + "/" + db


def _run_python(args, env_overrides=None, cwd=REPO_ROOT, timeout=300):
    """Run a command through the project's cross-platform Python runner."""
    cmd = ["node", str(REPO_ROOT / "scripts" / "run-python.js"), *args]
    merged_env = {**os.environ, **(env_overrides or {})}
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=merged_env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.fixture(scope="session")
def pg_urls():
    return _require_pg_urls()


@pytest.fixture(scope="session")
def app_engine(pg_urls):
    """Engine for the least-privilege app role (ira_aml_app)."""
    engine = create_engine(pg_urls[0], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def owner_engine(pg_urls):
    """Engine for the migration owner role (ira_aml_migrator) — operational writes only."""
    engine = create_engine(pg_urls[1], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def migrated_db(owner_engine):
    """Bring the session test database to the alembic head as the migration owner."""
    result = _run_python(["-m", "alembic", "upgrade", "head"], cwd=AI_ENGINE_DIR)
    if result.returncode != 0:
        pytest.fail(
            "alembic upgrade head failed against the test database "
            f"(exit {result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    with owner_engine.connect() as conn:
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    assert head == BASELINE_REVISION
    return head


@pytest.fixture(scope="session")
def seeded(migrated_db, owner_engine):
    """Seed two institutions plus one row-set each as the migration owner.

    The migration owner is subject to RLS too (tables are FORCEd), so operational
    seeding itself goes through tenant_transaction — the same mechanism the app uses.
    """
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        for inst_id, name in ((TENANT_A, "Central Bank of Iraq"), (TENANT_B, "Rafidain Bank")):
            if session.get(Institution, inst_id) is None:
                session.add(Institution(id=inst_id, name=name))
        session.commit()

        for inst in (TENANT_A, TENANT_B):
            # The test database persists across suite runs — seed only when absent.
            # The existence check itself must run under the tenant context: the
            # migration owner is subject to FORCE RLS on institutional tables too.
            with tenant_transaction(session, inst):
                already_seeded = session.get(Membership, f"memb_{inst}") is not None
            if already_seeded:
                continue
            with tenant_transaction(session, inst):
                session.add_all(
                    [
                        Membership(
                            id=f"memb_{inst}",
                            institution_id=inst,
                            sub=f"sub_{inst}",
                            role="ANALYST",
                        ),
                        WalletBindingModel(
                            id=f"wb_{inst}",
                            institution_id=inst,
                            sub=f"sub_{inst}",
                            wallet_address="0x" + "1" * 40,
                            participant_id="0x" + "2" * 64,
                            role="SIGNER",
                        ),
                        Case(
                            id=f"case_{inst}",
                            case_number=f"CASE-{inst}-001",
                            institution_id=inst,
                            title=f"Case of {inst}",
                        ),
                        CaseEvent(
                            id=f"evt_{inst}",
                            case_id=f"case_{inst}",
                            institution_id=inst,
                            event_type="CREATED",
                            actor_sub=f"sub_{inst}",
                        ),
                        Outbox(
                            id=f"out_{inst}",
                            institution_id=inst,
                            event_type="CASE_CREATED",
                            payload_json="{}",
                        ),
                        TransactionRecord(
                            id=f"tx_{inst}",
                            institution_id=inst,
                            source="MANUAL",
                            external_id=f"ext_{inst}",
                            occurred_at=datetime.now(timezone.utc),
                            sender_ref="sender",
                            receiver_ref="receiver",
                            amount_minor=1000,
                        ),
                        ReportRecord(
                            id=f"rep_{inst}",
                            report_id=f"repid_{inst}",
                            institution_id=inst,
                            case_id=f"case_{inst}",
                            version=1,
                            dossier_hash="0x" + "3" * 64,
                            integrity_status="VERIFIED",
                            provenance_status="OK",
                            markdown_content="# report",
                            manifest_json="{}",
                            created_by_sub=f"sub_{inst}",
                        ),
                        IdempotencyKey(
                            id=f"ik_{inst}",
                            institution_id=inst,
                            key="shared-key",
                            request_hash=f"hash-{inst}",
                            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                        ),
                    ]
                )
    yield


def _unique_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Role hygiene
# ---------------------------------------------------------------------------


def test_app_role_flags_limited(app_engine):
    """The app role is NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS, can login,
    owns no tables and no schemas, is a member of nothing, and is distinct from the
    (also unprivileged) migration role. All catalog assertions run AS the app role."""
    with app_engine.connect() as conn:
        app_row = conn.execute(
            text(
                "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, "
                "rolbypassrls, rolreplication FROM pg_roles WHERE rolname = 'ira_aml_app'"
            )
        ).one()
        assert app_row.rolcanlogin is True
        assert app_row.rolsuper is False
        assert app_row.rolcreaterole is False
        assert app_row.rolcreatedb is False
        assert app_row.rolbypassrls is False
        assert app_row.rolreplication is False

        owned_tables = conn.execute(
            text(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = 'public' AND tableowner = 'ira_aml_app'"
            )
        ).scalars().all()
        owned_schemas = conn.execute(
            text(
                "SELECT nspname FROM pg_namespace WHERE nspowner = "
                "(SELECT oid FROM pg_roles WHERE rolname = 'ira_aml_app')"
            )
        ).scalars().all()
        role_memberships = conn.execute(
            text(
                "SELECT r.rolname FROM pg_auth_members m "
                "JOIN pg_roles r ON r.oid = m.member "
                "WHERE r.rolname = 'ira_aml_app'"
            )
        ).scalars().all()
        mig_row = conn.execute(
            text(
                "SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolcanlogin "
                "FROM pg_roles WHERE rolname = 'ira_aml_migrator'"
            )
        ).one()

    assert owned_tables == [], f"app role must own no tables, owns {owned_tables}"
    assert owned_schemas == [], f"app role must own no schemas, owns {owned_schemas}"
    assert role_memberships == [], "app role must not be a member of any role"
    assert (
        mig_row.rolsuper is False
        and mig_row.rolbypassrls is False
        and mig_row.rolcreatedb is False
        and mig_row.rolcreaterole is False
        and mig_row.rolcanlogin is True
    ), "migration role must be a separate, also-unprivileged login"


# ---------------------------------------------------------------------------
# Tenant isolation via RLS (real app-role connections only)
# ---------------------------------------------------------------------------


def test_tenant_a_cannot_select_update_delete_b(app_engine, seeded):
    """Two REAL connections as the app role: tenant A can never select, update or
    delete tenant B's rows in any institutional table (RLS USING clause)."""
    engine_a = create_engine(app_engine.url, pool_size=1, max_overflow=0)
    engine_b = create_engine(app_engine.url, pool_size=1, max_overflow=0)
    try:
        SessionA, SessionB = sessionmaker(bind=engine_a), sessionmaker(bind=engine_b)
        with SessionA() as sa_, SessionB() as sb_:
            pid_a = sa_.execute(text("SELECT pg_backend_pid()")).scalar_one()
            pid_b = sb_.execute(text("SELECT pg_backend_pid()")).scalar_one()
            assert pid_a != pid_b, "expected two distinct real connections"

            with tenant_transaction(sa_, TENANT_A):
                assert set(sa_.execute(select(Case.institution_id)).scalars()) == {TENANT_A}
                for model in (Outbox, ReportRecord, Membership, WalletBindingModel):
                    seen = set(sa_.execute(select(model.institution_id)).scalars())
                    assert seen == {TENANT_A}, f"{model.__tablename__} leaked other tenants"

                # Targeted UPDATE/DELETE against B: filtered by USING -> 0 rows affected.
                targeted_update = sa_.execute(
                    update(Case)
                    .where(Case.institution_id == TENANT_B)
                    .values(title="TAMPERED")
                )
                assert targeted_update.rowcount == 0
                targeted_delete = sa_.execute(
                    delete(Case).where(Case.institution_id == TENANT_B)
                )
                assert targeted_delete.rowcount == 0

                # A blind UPDATE without WHERE must still only touch A's own rows.
                blind_update = sa_.execute(update(Case).values(severity="HIGH"))
                assert blind_update.rowcount == 1

            with tenant_transaction(sb_, TENANT_B):
                # B's data is intact: untouched by A's statements.
                b_case = sb_.execute(
                    select(Case).where(Case.id == f"case_{TENANT_B}")
                ).scalar_one()
                assert b_case.title == f"Case of {TENANT_B}"
                assert set(sb_.execute(select(Case.institution_id)).scalars()) == {TENANT_B}
    finally:
        engine_a.dispose()
        engine_b.dispose()


def test_insert_wrong_tenant_rejected(app_engine, seeded):
    """Inserting a row tagged with another institution under the current tenant
    context must be rejected by the RLS WITH CHECK clause."""
    Session = sessionmaker(bind=app_engine)
    with Session() as session:
        with pytest.raises(DBAPIError) as excinfo:
            with tenant_transaction(session, TENANT_A):
                session.add(
                    Case(
                        id=_unique_id("case_wrong"),
                        case_number="CASE-SMUGGLE-1",
                        institution_id=TENANT_B,
                        title="cross-tenant smuggle attempt",
                    )
                )
                session.flush()
        assert "row-level security" in str(excinfo.value).lower()
        session.rollback()

        # Nothing was written.
        with tenant_transaction(session, TENANT_A):
            found = session.execute(
                select(func.count()).select_from(Case).where(Case.case_number == "CASE-SMUGGLE-1")
            ).scalar_one()
        assert found == 0


def test_no_context_reads_nothing(app_engine, seeded):
    """Without a tenant context the app role reads nothing from any institutional
    table, cannot write the global institutions table, and the live setting is empty."""
    Session = sessionmaker(bind=app_engine)
    with Session() as session:
        for model in (
            Case,
            Outbox,
            TransactionRecord,
            Membership,
            WalletBindingModel,
            ReportRecord,
            IdempotencyKey,
            EvidenceObject,
            CaseEvent,
        ):
            count = session.execute(select(func.count()).select_from(model)).scalar_one()
            assert count == 0, f"{model.__tablename__} readable without tenant context"

        setting = session.execute(
            text("SELECT current_setting('app.current_institution_id', true)")
        ).scalar()
        assert setting in (None, ""), f"unexpected tenant context: {setting!r}"

        # The global institutions table has an explicit policy: readable, never writable.
        assert session.execute(
            select(func.count()).select_from(Institution)
        ).scalar_one() >= 2
        with pytest.raises(DBAPIError) as excinfo:
            session.add(Institution(id="inst_evil", name="Evil Institution"))
            session.flush()
        assert "row-level security" in str(excinfo.value).lower()
        session.rollback()


def test_connection_reused_does_not_leak(app_engine, seeded):
    """A pooled app-role connection reused after a tenant transaction carries no
    tenant context: current_setting is empty and every institutional table reads
    as empty — verified twice (after A and after B) on the same physical connection."""
    pooled = create_engine(app_engine.url, pool_size=1, max_overflow=0)
    try:
        Session = sessionmaker(bind=pooled)
        with Session() as first:
            with tenant_transaction(first, TENANT_A):
                pid_ctx_a = first.execute(text("SELECT pg_backend_pid()")).scalar_one()
                assert first.execute(
                    select(Case.institution_id)
                ).scalars().all() == [TENANT_A]

        with Session() as second:
            pid_clean_a = second.execute(text("SELECT pg_backend_pid()")).scalar_one()
            assert pid_clean_a == pid_ctx_a, "expected the same pooled connection to be reused"
            setting = second.execute(
                text("SELECT current_setting('app.current_institution_id', true)")
            ).scalar()
            assert setting in (None, ""), f"tenant context leaked across reuse: {setting!r}"
            assert second.execute(select(func.count()).select_from(Case)).scalar_one() == 0
            assert second.execute(select(func.count()).select_from(Outbox)).scalar_one() == 0
            assert second.execute(
                select(func.count()).select_from(TransactionRecord)
            ).scalar_one() == 0

        with Session() as third:
            with tenant_transaction(third, TENANT_B):
                pid_ctx_b = third.execute(text("SELECT pg_backend_pid()")).scalar_one()
                assert third.execute(
                    select(Case.institution_id)
                ).scalars().all() == [TENANT_B]

        with Session() as fourth:
            assert fourth.execute(text("SELECT pg_backend_pid()")).scalar_one() == pid_ctx_b
            setting = fourth.execute(
                text("SELECT current_setting('app.current_institution_id', true)")
            ).scalar()
            assert setting in (None, ""), f"tenant context leaked across reuse: {setting!r}"
            assert fourth.execute(select(func.count()).select_from(Case)).scalar_one() == 0
    finally:
        pooled.dispose()


def test_rollback_clears_context(app_engine, seeded):
    """An error inside tenant_transaction rolls the transaction back: the written row
    is gone and the transaction-local context does not survive on the connection."""
    pooled = create_engine(app_engine.url, pool_size=1, max_overflow=0)
    try:
        Session = sessionmaker(bind=pooled)
        marker = _unique_id("rb_case")
        with pytest.raises(RuntimeError, match="boom"):
            with Session() as session:
                with tenant_transaction(session, TENANT_A):
                    session.add(
                        Case(
                            id=marker,
                            case_number=marker,
                            institution_id=TENANT_A,
                            title="must be rolled back",
                        )
                    )
                    session.flush()
                    raise RuntimeError("boom")

        with Session() as session:
            remaining = session.execute(
                select(func.count()).select_from(Case).where(Case.id == marker)
            ).scalar_one()
            assert remaining == 0, "row survived rollback"
            setting = session.execute(
                text("SELECT current_setting('app.current_institution_id', true)")
            ).scalar()
            assert setting in (None, ""), f"tenant context leaked after rollback: {setting!r}"
    finally:
        pooled.dispose()


# ---------------------------------------------------------------------------
# Role privilege boundaries
# ---------------------------------------------------------------------------


def test_role_cannot_ddl(app_engine, migrated_db):
    """The app role cannot perform any DDL: no CREATE TABLE/SCHEMA/INDEX, no ALTER,
    no DROP — it owns nothing. Assertions run as the app role."""
    statements = (
        "CREATE TABLE r11_evil_ddl (id int)",
        "CREATE SCHEMA r11_evil_schema",
        "ALTER TABLE cases ADD COLUMN r11_evil_col int",
        "DROP TABLE memberships",
        "CREATE INDEX r11_evil_ix ON cases (title)",
    )
    with app_engine.connect() as conn:
        for statement in statements:
            with pytest.raises(DBAPIError) as excinfo:
                conn.execute(text(statement))
            message = str(excinfo.value).lower()
            assert (
                "permission denied" in message or "must be owner" in message
            ), f"{statement!r} failed with unexpected error: {message}"
            conn.rollback()


# ---------------------------------------------------------------------------
# Schema-level guarantees: FORCE RLS, explicit global policy, constraints
# ---------------------------------------------------------------------------


def test_force_rls_and_policies_on_all_institutional_tables(app_engine, migrated_db):
    """Every institutional data table is FORCEd under RLS with the tenant policy; the
    global institutions table has RLS enabled with exactly one explicit read policy."""
    with app_engine.connect() as conn:
        flags = {
            row.relname: (row.relrowsecurity, row.relforcerowsecurity)
            for row in conn.execute(
                text(
                    "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                    "WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'"
                )
            )
        }
        for table in RLS_TABLES:
            assert table in flags, f"missing institutional table {table}"
            assert flags[table] == (
                True,
                True,
            ), f"{table} must have ENABLE + FORCE ROW LEVEL SECURITY, got {flags[table]}"
        assert flags["institutions"][0] is True, "institutions must have RLS enabled"

        policies = conn.execute(
            text(
                "SELECT tablename, policyname, cmd FROM pg_policies WHERE schemaname = 'public'"
            )
        ).all()
        tenant_policy_tables = {
            p.tablename for p in policies if p.policyname == "tenant_isolation_policy"
        }
        assert tenant_policy_tables == set(RLS_TABLES), (
            "tenant_isolation_policy must exist on exactly the institutional tables"
        )
        institution_policies = [p for p in policies if p.tablename == "institutions"]
        assert len(institution_policies) == 1, "institutions needs exactly one explicit policy"
        assert institution_policies[0].policyname == "institutions_read_all"
        assert institution_policies[0].cmd == "SELECT"


def _expect_integrity_error(session, institution_id, add_row):
    with pytest.raises(IntegrityError):
        with tenant_transaction(session, institution_id):
            add_row()
            session.flush()
    session.rollback()


def test_institutional_constraints_enforced_on_postgres(app_engine, seeded):
    """Institutional FK/unique constraints hold on real PostgreSQL as the app role:
    composite tenant FKs, per-institution uniqueness on cases/memberships/idempotency/
    reports — the constraints the baseline migration must preserve."""
    Session = sessionmaker(bind=app_engine)
    with Session() as session:
        # Composite FK: evidence for MY institution may not reference ANOTHER tenant's case.
        _expect_integrity_error(
            session,
            TENANT_A,
            lambda: session.add(
                EvidenceObject(
                    id=_unique_id("ev_fk"),
                    institution_id=TENANT_A,
                    case_id=f"case_{TENANT_B}",
                    evidence_id="ev_fk_probe",
                    object_version=1,
                    file_name="x.pdf",
                    content_type="application/pdf",
                    file_size=1,
                    sha256_hash="0" * 64,
                    storage_path="/tmp/x.dat",
                )
            ),
        )
        # Same rule for case events.
        _expect_integrity_error(
            session,
            TENANT_A,
            lambda: session.add(
                CaseEvent(
                    id=_unique_id("evt_fk"),
                    case_id=f"case_{TENANT_B}",
                    institution_id=TENANT_A,
                    event_type="PROBE",
                    actor_sub="sub_inst_cbi",
                )
            ),
        )
        # Unique (institution_id, case_number).
        _expect_integrity_error(
            session,
            TENANT_A,
            lambda: session.add(
                Case(
                    id=_unique_id("case_dup"),
                    case_number=f"CASE-{TENANT_A}-001",
                    institution_id=TENANT_A,
                    title="duplicate case number",
                )
            ),
        )
        # Unique (institution_id, sub) on memberships.
        _expect_integrity_error(
            session,
            TENANT_A,
            lambda: session.add(
                Membership(
                    id=_unique_id("memb_dup"),
                    institution_id=TENANT_A,
                    sub=f"sub_{TENANT_A}",
                    role="ANALYST",
                )
            ),
        )
        # Unique (institution_id, key) on idempotency keys.
        _expect_integrity_error(
            session,
            TENANT_A,
            lambda: session.add(
                IdempotencyKey(
                    id=_unique_id("ik_dup"),
                    institution_id=TENANT_A,
                    key="shared-key",
                    request_hash="other-hash",
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                )
            ),
        )
        # Unique (institution_id, case_id, version) on reports.
        _expect_integrity_error(
            session,
            TENANT_A,
            lambda: session.add(
                ReportRecord(
                    id=_unique_id("rep_dup"),
                    report_id=_unique_id("repid"),
                    institution_id=TENANT_A,
                    case_id=f"case_{TENANT_A}",
                    version=1,
                    dossier_hash="0x" + "4" * 64,
                    integrity_status="VERIFIED",
                    provenance_status="OK",
                    markdown_content="# dup",
                    manifest_json="{}",
                    created_by_sub="sub_inst_cbi",
                )
            ),
        )


# ---------------------------------------------------------------------------
# Migration conventions (alembic baseline)
# ---------------------------------------------------------------------------

_CREATE_ALL_SNIPPET = (
    "from app.db.models import Base\n"
    "from sqlalchemy import create_engine\n"
    "import os\n"
    "engine = create_engine(os.environ['MIGRATION_DATABASE_URL'])\n"
    "Base.metadata.create_all(engine)\n"
    "engine.dispose()\n"
    "print('R11_CREATE_ALL_OK')\n"
)

_CREATE_UNKNOWN_SNIPPET = (
    "from app.db.models import Base\n"
    "from sqlalchemy import create_engine, text\n"
    "import os\n"
    "engine = create_engine(os.environ['MIGRATION_DATABASE_URL'])\n"
    "Base.metadata.create_all(engine)\n"
    "with engine.connect() as conn:\n"
    "    conn.execute(text('CREATE TABLE IF NOT EXISTS r11_stranger (id int primary key)'))\n"
    "    conn.commit()\n"
    "engine.dispose()\n"
    "print('R11_UNKNOWN_OK')\n"
)


def test_migrations_from_empty_and_existing_fixture(pg_urls):
    """Migration conventions (R11):
    1. An empty database: 'alembic upgrade head' creates the full baseline schema.
    2. A pre-existing database whose schema matches the models: comparison passes and
       the revision is stamped (explicit opt-in via stamp-if-matches, never automatic).
    3. An unknown database (schema drift): stamp-if-matches REFUSES and does not stamp.
    """
    app_url, migration_url = pg_urls

    # 1) empty database -> upgrade head
    empty_migration_url = _swap_db(migration_url, "r11_empty")
    result = _run_python(
        ["-m", "alembic", "upgrade", "head"],
        env_overrides={MIGRATION_OWNER_ENV_VAR: empty_migration_url},
        cwd=AI_ENGINE_DIR,
    )
    assert result.returncode == 0, (
        f"alembic upgrade head failed on empty DB:\n{result.stdout}\n{result.stderr}"
    )
    app_empty = create_engine(_swap_db(app_url, "r11_empty"))
    try:
        with app_empty.connect() as conn:
            tables = set(
                conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                ).scalars()
            )
            for table in ("institutions", "alembic_version", *RLS_TABLES):
                assert table in tables, f"baseline table {table} missing after upgrade"
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == BASELINE_REVISION
            )
    finally:
        app_empty.dispose()

    # 2) pre-existing matching schema -> comparison then stamp (idempotent)
    existing_migration_url = _swap_db(migration_url, "r11_existing")
    created = _run_python(
        ["-c", _CREATE_ALL_SNIPPET],
        env_overrides={MIGRATION_OWNER_ENV_VAR: existing_migration_url},
    )
    assert created.returncode == 0, (
        f"seeding r11_existing failed:\n{created.stdout}\n{created.stderr}"
    )
    for _ in range(2):  # second run proves idempotence
        stamped = _run_python(
            ["ai-engine/app/db/migrations/env.py", "stamp-if-matches"],
            env_overrides={MIGRATION_OWNER_ENV_VAR: existing_migration_url},
        )
        assert stamped.returncode == 0, (
            f"stamp-if-matches refused a matching schema:\n{stamped.stdout}\n{stamped.stderr}"
        )
    existing_engine = create_engine(existing_migration_url)
    try:
        with existing_engine.connect() as conn:
            assert (
                conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == BASELINE_REVISION
            )
    finally:
        existing_engine.dispose()

    # 3) unknown schema -> refusal, no stamp, no alembic_version table
    unknown_migration_url = _swap_db(migration_url, "r11_unknown")
    drifted = _run_python(
        ["-c", _CREATE_UNKNOWN_SNIPPET],
        env_overrides={MIGRATION_OWNER_ENV_VAR: unknown_migration_url},
    )
    assert drifted.returncode == 0, (
        f"seeding r11_unknown failed:\n{drifted.stdout}\n{drifted.stderr}"
    )
    refused = _run_python(
        ["ai-engine/app/db/migrations/env.py", "stamp-if-matches"],
        env_overrides={MIGRATION_OWNER_ENV_VAR: unknown_migration_url},
    )
    assert refused.returncode != 0, (
        f"stamp-if-matches must refuse an unknown schema, output was:\n{refused.stdout}"
    )
    unknown_engine = create_engine(unknown_migration_url)
    try:
        with unknown_engine.connect() as conn:
            has_version_table = conn.execute(
                text("SELECT to_regclass('public.alembic_version') IS NOT NULL")
            ).scalar_one()
            assert has_version_table is False, "unknown DB must never be stamped"
    finally:
        unknown_engine.dispose()


# ---------------------------------------------------------------------------
# API process environment hygiene
# ---------------------------------------------------------------------------

_API_BOOT_SNIPPET = (
    "import os\n"
    f"assert {MIGRATION_OWNER_ENV_VAR!r} not in os.environ, "
    "'owner env leaked into API process'\n"
    "from app.config import settings  # the API settings surface\n"
    "from app.db.session import init_db\n"
    "init_db()  # production startup path: schema revision check only\n"
    f"assert {MIGRATION_OWNER_ENV_VAR!r} not in os.environ, "
    "'owner env appeared after startup'\n"
    "print('R11_API_BOOT_OK')\n"
)


def test_migration_owner_env_absent_from_api_process(pg_urls):
    """The migration-owner credential must never reach the API process: no app source
    references MIGRATION_DATABASE_URL (the scan covers app/main.py too), and the API
    startup path — config load plus the init_db schema-revision check — runs against
    PostgreSQL using only the app-role DATABASE_URL.

    Note: the boot snippet exercises the shared startup surface (settings + init_db)
    rather than importing app.main directly, because the v1 route modules referenced
    by app/main.py are uncommitted user edits that exist only in the main workspace;
    app/main.py itself is inside the scanned tree, so the env-var guarantee covers it.
    """
    app_url, _ = pg_urls

    offenders = []
    app_source_dir = AI_ENGINE_DIR / "app"
    for path in app_source_dir.rglob("*.py"):
        # The alembic runner (app/db/migrations/env.py) is the ONE legitimate
        # consumer of the owner env var — it executes only inside the migration
        # job, never inside the API process. Everything else (config, main,
        # session, routes, services, workers) must not reference it at all.
        if "migrations" in path.parts:
            continue
        if MIGRATION_OWNER_ENV_VAR in path.read_text(encoding="utf-8", errors="ignore"):
            offenders.append(str(path))
    assert offenders == [], f"app source must not reference {MIGRATION_OWNER_ENV_VAR}: {offenders}"

    env = {k: v for k, v in os.environ.items() if k != MIGRATION_OWNER_ENV_VAR}
    env["DATABASE_URL"] = app_url
    result = subprocess.run(
        ["node", "scripts/run-python.js", "-c", _API_BOOT_SNIPPET],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, (
        f"API process boot without owner env failed:\n{result.stdout}\n{result.stderr}"
    )
    assert "R11_API_BOOT_OK" in result.stdout
