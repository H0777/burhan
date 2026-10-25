"""
Case concurrency and idempotency-rollback integration tests (R12) — real PostgreSQL,
least-privilege app role, real CaseService + case_repository (no mocks of the
persistence path).

Requires the same environment contract as test_postgres_rls.py (R11):
  DATABASE_URL            -> least-privilege APP role (ira_aml_app), NOSUPERUSER NOBYPASSRLS.
  MIGRATION_DATABASE_URL  -> migration OWNER role (ira_aml_migrator).
Without them the module SKIPS.

Spec §8 bindings (RED evidence: the pre-R12 repository "optimistic lock" was a
Python-only read/compare — both racers passed it and BOTH wrote, producing two
winners and two CaseEvents):
  - concurrent_expected_version_one_winner: two sessions, barrier immediately before
    the SQL UPDATE, one success + one 409-class conflict, version +1, exactly one
    CaseEvent;
  - exception_after_event_rolls_back_all: state + event + idempotency reservation are
    written in ONE transaction, so a failure after the event rolls everything back;
  - tenant-coverage proof (controller-mandated): every institutional query path only
    returns data inside tenant_transaction — outside the RLS tenant context the app
    role reads zero rows and cannot INSERT.
"""

import os
import subprocess
import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db.models import Case, CaseEvent, IdempotencyKey, Institution, Membership
from app.db.session import tenant_transaction
from app.schemas.identity import Identity, RoleEnum
from app.services.case_service import CaseService, VersionConflictError

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT = "inst_r12_conc"
AUDITOR_1 = "sub_r12_conc_auditor_1"
AUDITOR_2 = "sub_r12_conc_auditor_2"


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R12 concurrency tests require DATABASE_URL (app role) and "
            "MIGRATION_DATABASE_URL (migration owner) pointing at a disposable "
            "PostgreSQL test database"
        )
    return app_url, migration_url


@pytest.fixture(scope="module")
def pg_urls():
    return _require_pg_urls()


@pytest.fixture(scope="module")
def app_engine(pg_urls):
    engine = create_engine(pg_urls[0], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def owner_engine(pg_urls):
    engine = create_engine(pg_urls[1], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def migrated_db(pg_urls):
    result = subprocess.run(
        ["node", str(REPO_ROOT / "scripts" / "run-python.js"), "-m", "alembic", "upgrade", "head"],
        cwd=str(AI_ENGINE_DIR),
        env={**os.environ, "MIGRATION_DATABASE_URL": pg_urls[1]},
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(
            "alembic upgrade head failed against the R12 test database "
            f"(exit {result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    with create_engine(pg_urls[1]).connect() as conn:
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    return head


@pytest.fixture(scope="module")
def seeded(migrated_db, owner_engine):
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        if session.get(Institution, TENANT) is None:
            session.add(Institution(id=TENANT, name="R12 Concurrency Test Institution"))
        session.commit()
        with tenant_transaction(session, TENANT):
            existing = {
                sub
                for sub in session.execute(
                    text("SELECT sub FROM memberships WHERE institution_id = :i"), {"i": TENANT}
                ).scalars()
            }
            for sub in (AUDITOR_1, AUDITOR_2):
                if sub not in existing:
                    session.add(
                        Membership(
                            id=f"mem_{uuid.uuid4().hex[:16]}",
                            institution_id=TENANT,
                            sub=sub,
                            role="AUDITOR",
                            is_active=True,
                        )
                    )
    yield


def _identity(sub) -> Identity:
    return Identity(
        issuer="https://auth.institutional-cbi.iq/oauth2",
        sub=sub,
        institution_id=TENANT,
        role=RoleEnum.AUDITOR,
    )


def _create_committed_case(engine, sub, case_number) -> Case:
    """Create one case through the real service inside a real tenant transaction."""
    Session = sessionmaker(bind=engine)
    with Session() as session:
        with tenant_transaction(session, TENANT):
            case = CaseService().create_case(
                session=session,
                identity=_identity(sub),
                case_number=case_number,
                title=f"R12 concurrency {case_number}",
                severity="HIGH",
            )
            case_id = case.id
    return case_id


# ---------------------------------------------------------------------------
# CAS concurrency: two racers, one winner
# ---------------------------------------------------------------------------


def test_concurrent_expected_version_one_winner(app_engine, seeded):
    """Two sessions race the SAME expected_version with a barrier right before the
    SQL UPDATE. The SQL compare-and-swap lets exactly one commit win: one success,
    one conflict, version advanced exactly once, exactly one transition event."""
    case_id = _create_committed_case(app_engine, AUDITOR_1, f"R12-RACE-{uuid.uuid4().hex[:8]}")

    Session = sessionmaker(bind=app_engine)
    barrier = threading.Barrier(2, timeout=15)
    results = {}
    ready = threading.Barrier(2, timeout=15)

    def _wait_at_case_update(conn, cursor, statement, parameters, context, executemany):
        # Fired per statement on the shared engine: park both threads immediately
        # before their UPDATE on cases so both arrive with expected_version=1 read.
        if statement.lstrip().upper().startswith("UPDATE cases"):
            barrier.wait()

    def _race(tag, sub):
        identity = _identity(sub)
        svc = CaseService()
        try:
            with Session() as session:
                # Park until both threads exist (avoids one racer finishing early).
                ready.wait()
                with tenant_transaction(session, TENANT):
                    resp = svc.transition_case(
                        session=session,
                        identity=identity,
                        case_id=case_id,
                        action="start_review",
                        expected_version=1,
                    )
                    session.flush()
            results[tag] = {"ok": True, "version": resp.version, "status": resp.status}
        except VersionConflictError as exc:
            results[tag] = {"ok": False, "conflict": True, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 — surfaced in assertions below
            results[tag] = {"ok": False, "conflict": False, "error": repr(exc)}

    listener_id = event.listen(app_engine, "before_cursor_execute", _wait_at_case_update)
    try:
        t1 = threading.Thread(target=_race, args=("a", AUDITOR_1))
        t2 = threading.Thread(target=_race, args=("b", AUDITOR_2))
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)
    finally:
        event.remove(app_engine, "before_cursor_execute", _wait_at_case_update)

    assert len(results) == 2, f"a racer never finished: {results}"
    winners = [r for r in results.values() if r["ok"]]
    losers = [r for r in results.values() if not r["ok"]]
    assert len(winners) == 1, f"expected exactly one winner, got {results}"
    assert len(losers) == 1, f"expected exactly one 409-class conflict, got {results}"
    assert losers[0]["conflict"], f"loser failed with a non-conflict error: {losers[0]}"
    assert winners[0]["version"] == 2 and winners[0]["status"] == "IN_REVIEW"

    # One winner on the ROW too: version advanced exactly once, exactly one event.
    with Session() as verify:
        with tenant_transaction(verify, TENANT):
            row = verify.execute(
                select(Case.version, Case.status).where(Case.id == case_id)
            ).one()
            assert row.version == 2, f"version advanced {row.version} times under CAS"
            assert row.status == "IN_REVIEW"
            transition_events = verify.execute(
                select(func.count())
                .select_from(CaseEvent)
                .where(CaseEvent.case_id == case_id, CaseEvent.event_type == "start_review")
            ).scalar_one()
            assert transition_events == 1, (
                f"{transition_events} transition events survived the race, expected exactly 1"
            )


# ---------------------------------------------------------------------------
# Atomicity: state + event + idempotency in ONE transaction
# ---------------------------------------------------------------------------


def test_exception_after_event_rolls_back_all(app_engine, seeded):
    """A failure raised AFTER the transition event (and the idempotency reservation)
    were written must roll back state, event AND idempotency together — they live in
    the same transaction."""
    case_id = _create_committed_case(app_engine, AUDITOR_1, f"R12-RB-{uuid.uuid4().hex[:8]}")
    idem_key = f"r12-rollback-{uuid.uuid4().hex[:8]}"

    Session = sessionmaker(bind=app_engine)
    with pytest.raises(RuntimeError, match="boom-after-event"):
        with Session() as session:
            with tenant_transaction(session, TENANT):
                resp = CaseService().transition_case(
                    session=session,
                    identity=_identity(AUDITOR_1),
                    case_id=case_id,
                    action="start_review",
                    expected_version=1,
                    idempotency_key=idem_key,
                )
                assert resp.version == 2  # writes are flushed inside the transaction
                raise RuntimeError("boom-after-event")

    with Session() as verify:
        with tenant_transaction(verify, TENANT):
            row = verify.execute(
                select(Case.version, Case.status).where(Case.id == case_id)
            ).one()
            assert row.version == 1, "case version survived the aborted transaction"
            assert row.status == "OPEN", "case status survived the aborted transaction"
            events = verify.execute(
                select(func.count()).select_from(CaseEvent).where(CaseEvent.case_id == case_id)
            ).scalar_one()
            assert events == 1, "transition event survived the aborted transaction"
            ik = verify.execute(
                select(func.count())
                .select_from(IdempotencyKey)
                .where(
                    IdempotencyKey.institution_id == TENANT,
                    IdempotencyKey.key == idem_key,
                )
            ).scalar_one()
            assert ik == 0, "idempotency reservation survived the aborted transaction"


# ---------------------------------------------------------------------------
# Controller-mandated tenant-coverage proof (RLS level)
# ---------------------------------------------------------------------------


def test_case_paths_require_tenant_transaction_context(app_engine, seeded):
    """Proof that the case data plane is only reachable INSIDE tenant_transaction:
    with rows present, an app-role session without the transaction-local tenant
    context reads ZERO rows from cases/case_events/idempotency_keys and cannot
    insert — so any HTTP case path that returns data necessarily ran inside
    tenant_transaction(db, identity.institution_id)."""
    case_id = _create_committed_case(app_engine, AUDITOR_1, f"R12-CTX-{uuid.uuid4().hex[:8]}")

    Session = sessionmaker(bind=app_engine)
    with Session() as bare:
        # The live setting is empty and every institutional table reads as empty.
        setting = bare.execute(text("SELECT current_setting('app.current_institution_id', true)")).scalar()
        assert setting in (None, ""), f"unexpected tenant context on a bare session: {setting!r}"
        assert bare.execute(select(func.count()).select_from(Case)).scalar_one() == 0
        assert bare.execute(select(func.count()).select_from(CaseEvent)).scalar_one() == 0
        assert bare.execute(select(func.count()).select_from(IdempotencyKey)).scalar_one() == 0

        # A blind INSERT without the tenant context is rejected by RLS WITH CHECK:
        # a successful HTTP create therefore proves the create path runs inside
        # tenant_transaction.
        with pytest.raises(DBAPIError) as excinfo:
            bare.add(
                Case(
                    id=f"case_smuggle_{uuid.uuid4().hex[:8]}",
                    case_number="R12-SMUGGLE",
                    institution_id=TENANT,
                    title="insert without tenant context",
                )
            )
            bare.flush()
        assert "row-level security" in str(excinfo.value).lower()
        bare.rollback()

    # ...and inside tenant_transaction the very same rows ARE visible.
    with Session() as ctx:
        with tenant_transaction(ctx, TENANT):
            found = ctx.execute(select(Case.id).where(Case.id == case_id)).scalar_one()
            assert found == case_id
