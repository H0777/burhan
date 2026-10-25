"""
Wallet-challenge persistence integration tests (R10) — real PostgreSQL, synthetic keys only.

These are PostgreSQL-INTEGRATION tests, NOT logic tests. They require a disposable
PostgreSQL 16 test database provisioned with the ops/postgres/init-roles.sql roles and
two environment variables (same contract as test_postgres_rls.py, R11):

  DATABASE_URL            -> least-privilege APP role (ira_aml_app), NOSUPERUSER NOBYPASSRLS.
  MIGRATION_DATABASE_URL  -> migration OWNER role (ira_aml_migrator).

Both must be postgresql:// URLs pointing at the SAME disposable test database.
Without them the module SKIPS. SIWE wallets are Account.create() synthetic keys.

R10 spec points exercised here:
  - challenges persist in the wallet_challenges table (challenge/user/institution/
    domain/chain/nonce/expires/consumed_at) and survive a full connection+pool teardown;
  - consumption is an atomic compare-and-swap: two independent sessions, one winner;
  - challenge validity window is exactly 300 seconds;
  - a challenge is bound to its domain, chain id and subject;
  - a rotated (retired) wallet is rejected against the on-chain generation;
  - every local proof (tenant, subject, domain, chain, signature) fails BEFORE any
    on-chain read happens (a wallet that is not proven locally never triggers a
    RoleManager read).
"""

import os
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.models import Institution
from app.db.session import tenant_transaction
from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletChallengeRequest,
    WalletVerifyRequest,
)
from app.security.wallet_binding import WalletBindingService

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT = "inst_r10_challenges"
OTHER_TENANT = "inst_r10_challenges_other"
DOMAIN = "iraq-aml-audit.cbi.iq"
CHAIN_ID = 31337
SUBJECT = "sub_r10_persistence"


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R10 identity persistence tests require DATABASE_URL (app role) and "
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
    """Bring the module test database to the current alembic head (migration role)."""
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
            "alembic upgrade head failed against the R10 test database "
            f"(exit {result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    with create_engine(pg_urls[1]).connect() as conn:
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    return head


@pytest.fixture(scope="module")
def seeded(migrated_db, owner_engine):
    """Seed the institution(s) once per module (idempotent: the DB may persist)."""
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        for inst_id, name in ((TENANT, "R10 Challenge Test Institution"), (OTHER_TENANT, "R10 Other Institution")):
            if session.get(Institution, inst_id) is None:
                session.add(Institution(id=inst_id, name=name))
        session.commit()
    yield


def _identity(sub: str = SUBJECT, institution: str = TENANT, role: RoleEnum = RoleEnum.AUDITOR) -> Identity:
    # NOTE: the role carried here mimics an untrusted JWT claim; in GREEN the
    # membership (DB) is the only role source for resolution — the binding layer
    # itself only uses institution/sub.
    return Identity(
        sub=sub,
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=institution,
        role=role,
        permissions=[],
    )


def _unique_sub() -> str:
    """Per-test subject: the test database persists across runs, and bindings
    are keyed by (institution, sub) — tests must never share one."""
    return f"sub_{uuid.uuid4().hex[:12]}"


def _service(engine=None, reader=None, domain: str = DOMAIN, chain_id: int = CHAIN_ID):
    """WalletBindingService bound to the given (real PostgreSQL) engine."""
    factory = sessionmaker(bind=engine) if engine is not None else None
    return WalletBindingService(
        domain=domain,
        default_chain_id=chain_id,
        ttl_seconds=300,
        chain_reader=reader,
        session_factory=factory,
    )


class _FakeRoleManagerReader:
    """In-test stand-in for the R02 RoleManager getParticipant(address) read."""

    def __init__(self):
        self.participants = {}
        self.read_count = 0

    def set_participant(self, wallet, participant_id, generation, role, active):
        self.participants[wallet.lower()] = SimpleNamespace(
            participant_id=participant_id,
            generation=generation,
            role=role,
            active=active,
        )

    def get_participant(self, wallet_address):
        self.read_count += 1
        return self.participants.get(wallet_address.lower())


def _new_engine(app_engine):
    """A fresh engine+pool — the stand-in for a new process after a restart."""
    return create_engine(app_engine.url, pool_pre_ping=True)


# ---------------------------------------------------------------------------
# Persistence across process lifetime
# ---------------------------------------------------------------------------


def test_challenge_survives_process_restart(app_engine, seeded):
    """A challenge written through one engine/pool is still consumable after the
    engine, its pool and its sessions are fully disposed and rebuilt (the R10
    requirement that challenges live in PostgreSQL, not in process memory)."""
    sub = _unique_sub()
    reader = _FakeRoleManagerReader()
    engine_a = _new_engine(app_engine)
    service_a = _service(engine=engine_a, reader=reader)
    wallet = Account.create()

    with sessionmaker(bind=engine_a)() as session:
        resp = service_a.create_challenge(
            session, _identity(sub), WalletChallengeRequest(wallet_address=wallet.address, chain_id=CHAIN_ID)
        )
    engine_a.dispose()  # everything the first "process" owned is gone

    reader.set_participant(wallet.address, "0x" + "ab" * 32, 1, "AUDITOR", True)
    engine_b = _new_engine(app_engine)
    service_b = _service(engine=engine_b, reader=reader)
    try:
        sig = wallet.sign_message(encode_defunct(text=resp.message)).signature.hex()
        with sessionmaker(bind=engine_b)() as session:
            binding = service_b.verify_and_bind(
                session, _identity(sub), WalletVerifyRequest(challenge_id=resp.challenge_id, signature=sig)
            )
        assert binding.bound is True
        assert binding.participant_id == "0x" + "ab" * 32
        active = service_b.get_active_binding(TENANT, sub)
        assert active is not None
        assert active.wallet_address.lower() == wallet.address.lower()
        assert active.authorization_generation == 1
    finally:
        engine_b.dispose()


def test_challenge_row_persists_all_bound_fields(app_engine, seeded):
    """The stored challenge row carries challenge/user/institution/domain/chain/
    nonce/expires/consumed_at, the nonce is unique, and consumed_at stays NULL
    until an atomic consumption happens."""
    from app.db.models import WalletChallengeModel

    service = _service(engine=app_engine, reader=None)
    wallet = Account.create()
    with sessionmaker(bind=app_engine)() as session:
        resp = service.create_challenge(
            session, _identity(), WalletChallengeRequest(wallet_address=wallet.address, chain_id=CHAIN_ID)
        )

    now = datetime.now(timezone.utc)
    with sessionmaker(bind=app_engine)() as session:
        with tenant_transaction(session, TENANT):
            row = session.get(WalletChallengeModel, resp.challenge_id)
            assert row is not None, "challenge was not persisted to PostgreSQL"
            assert row.institution_id == TENANT
            assert row.sub == SUBJECT
            assert row.wallet_address.lower() == wallet.address.lower()
            assert row.domain == DOMAIN
            assert row.chain_id == CHAIN_ID
            assert row.nonce == resp.nonce
            assert row.message == resp.message
            assert row.issued_at is not None
            assert row.expires_at is not None
            assert abs((row.expires_at - resp.expires_at).total_seconds()) < 5
            assert row.consumed_at is None

        # Unique challenge nonce: a second row with the same nonce must be refused.
        # (Inside the tenant context, so the RLS WITH CHECK passes and the UNIQUE
        # nonce constraint is what fires.)
        with pytest.raises(IntegrityError):
            with tenant_transaction(session, TENANT):
                session.add(
                    WalletChallengeModel(
                        id=f"wc_{uuid.uuid4().hex[:12]}",
                        institution_id=TENANT,
                        sub=SUBJECT,
                        wallet_address="0x" + "b" * 40,
                        domain=DOMAIN,
                        chain_id=CHAIN_ID,
                        nonce=resp.nonce,  # duplicate
                        message="duplicate nonce attempt",
                        issued_at=now,
                        expires_at=now + timedelta(seconds=300),
                    )
                )
                session.flush()
        session.rollback()


def test_one_active_wallet_per_membership_constraint(app_engine, seeded):
    """The one-active-wallet-per-membership rule is enforced at rest: the
    (institution_id, sub) uniqueness on wallet_bindings refuses a second active
    binding row for the same membership."""
    from app.db.models import WalletBindingModel

    sub = f"sub_one_wallet_{uuid.uuid4().hex[:8]}"
    with sessionmaker(bind=app_engine)() as session:
        with tenant_transaction(session, TENANT):
            session.add(
                WalletBindingModel(
                    id=f"wb_{uuid.uuid4().hex[:12]}",
                    institution_id=TENANT,
                    sub=sub,
                    wallet_address="0x" + "c" * 40,
                    participant_id="0x" + "cd" * 32,
                    role="AUDITOR",
                    authorization_generation=1,
                )
            )
        with pytest.raises(IntegrityError):
            with tenant_transaction(session, TENANT):
                session.add(
                    WalletBindingModel(
                        id=f"wb_{uuid.uuid4().hex[:12]}",
                        institution_id=TENANT,
                        sub=sub,  # same membership
                        wallet_address="0x" + "d" * 40,
                        participant_id="0x" + "cd" * 32,
                        role="AUDITOR",
                        authorization_generation=2,
                    )
                )
                session.flush()
        session.rollback()


# ---------------------------------------------------------------------------
# Atomic single-use consumption
# ---------------------------------------------------------------------------


def test_consume_once_two_sessions(app_engine, seeded):
    """Two independent physical connections race for the same challenge: exactly
    one wins, the loser is rejected with the canonical single-use error, and the
    on-chain reader is never consulted for the losing attempt."""
    sub = _unique_sub()
    reader = _FakeRoleManagerReader()
    engine_1 = _new_engine(app_engine)
    engine_2 = _new_engine(app_engine)
    service = _service(engine=engine_1, reader=reader)
    wallet = Account.create()
    reader.set_participant(wallet.address, "0x" + "ee" * 32, 1, "AUDITOR", True)

    with sessionmaker(bind=engine_1)() as session:
        resp = service.create_challenge(
            session, _identity(sub), WalletChallengeRequest(wallet_address=wallet.address, chain_id=CHAIN_ID)
        )
    sig = wallet.sign_message(encode_defunct(text=resp.message)).signature.hex()

    with sessionmaker(bind=engine_1)() as first:
        binding = service.verify_and_bind(
            first, _identity(sub), WalletVerifyRequest(challenge_id=resp.challenge_id, signature=sig)
        )
    assert binding.bound is True

    with pytest.raises(ValueError, match="Challenge already used or expired"):
        with sessionmaker(bind=engine_2)() as second:
            service.verify_and_bind(
                second, _identity(sub), WalletVerifyRequest(challenge_id=resp.challenge_id, signature=sig)
            )
    assert reader.read_count == 1, "the losing session must not reach the chain"
    engine_1.dispose()
    engine_2.dispose()


def test_repository_consume_challenge_cas_signature(app_engine, seeded):
    """The repository-level compare-and-swap interface: consume_challenge(session,
    challenge_id, institution_id, sub, now) consumes exactly once, records
    consumed_at, and refuses replay, unknown ids and foreign subjects."""
    from app.repositories.wallet_binding_repository import WalletBindingRepository
    from app.security.wallet_binding import ChallengeRecord

    repo = WalletBindingRepository()
    now = datetime.now(timezone.utc)
    record = ChallengeRecord(
        challenge_id=str(uuid.uuid4()),
        institution_id=TENANT,
        sub=SUBJECT,
        wallet_address="0x" + "9" * 40,
        chain_id=CHAIN_ID,
        domain=DOMAIN,
        nonce=uuid.uuid4().hex,
        message="cas probe",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
    )
    Session = sessionmaker(bind=app_engine)
    with Session() as session:
        with tenant_transaction(session, TENANT):
            repo.save_challenge(session, record)

    with Session() as session:
        with tenant_transaction(session, TENANT):
            consumed = repo.consume_challenge(
                session, record.challenge_id, TENANT, SUBJECT, datetime.now(timezone.utc)
            )
            assert consumed.challenge_id == record.challenge_id
            assert consumed.consumed_at is not None

    # Replay loses.
    with Session() as session:
        with tenant_transaction(session, TENANT):
            with pytest.raises(ValueError):
                repo.consume_challenge(session, record.challenge_id, TENANT, SUBJECT, datetime.now(timezone.utc))

    # A foreign subject never consumes another user's challenge.
    other = ChallengeRecord(
        challenge_id=str(uuid.uuid4()),
        institution_id=TENANT,
        sub=SUBJECT,
        wallet_address="0x" + "9" * 40,
        chain_id=CHAIN_ID,
        domain=DOMAIN,
        nonce=uuid.uuid4().hex,
        message="foreign subject probe",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
    )
    with Session() as session:
        with tenant_transaction(session, TENANT):
            repo.save_challenge(session, other)
            with pytest.raises(ValueError):
                repo.consume_challenge(
                    session, other.challenge_id, TENANT, "sub_attacker", datetime.now(timezone.utc)
                )


def test_expired_at_300s(app_engine, seeded):
    """The validity window is exactly 300 seconds: consumable at 299s, expired at
    exactly 300s (inclusive expiry)."""
    from app.repositories.wallet_binding_repository import WalletBindingRepository
    from app.security.wallet_binding import ChallengeRecord

    repo = WalletBindingRepository()
    now = datetime.now(timezone.utc)
    within = ChallengeRecord(
        challenge_id=str(uuid.uuid4()),
        institution_id=TENANT,
        sub=SUBJECT,
        wallet_address="0x" + "7" * 40,
        chain_id=CHAIN_ID,
        domain=DOMAIN,
        nonce=uuid.uuid4().hex,
        message="window 299",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
    )
    boundary = ChallengeRecord(
        challenge_id=str(uuid.uuid4()),
        institution_id=TENANT,
        sub=SUBJECT,
        wallet_address="0x" + "7" * 40,
        chain_id=CHAIN_ID,
        domain=DOMAIN,
        nonce=uuid.uuid4().hex,
        message="window 300",
        issued_at=now,
        expires_at=now + timedelta(seconds=300),
    )
    Session = sessionmaker(bind=app_engine)
    with Session() as session:
        with tenant_transaction(session, TENANT):
            repo.save_challenge(session, within)
            repo.save_challenge(session, boundary)

    with Session() as session:
        with tenant_transaction(session, TENANT):
            consumed = repo.consume_challenge(session, within.challenge_id, TENANT, SUBJECT, now + timedelta(seconds=299))
            assert consumed.consumed_at is not None

    with Session() as session:
        with tenant_transaction(session, TENANT):
            with pytest.raises(ValueError):
                repo.consume_challenge(session, boundary.challenge_id, TENANT, SUBJECT, now + timedelta(seconds=300))


# ---------------------------------------------------------------------------
# Challenge is bound to domain, chain and subject
# ---------------------------------------------------------------------------


def test_wrong_chain_domain_sub_rejected(app_engine, seeded):
    """A challenge issued under (domain, chain, sub) is rejected when consumed
    under a different domain, a different chain id, or a different subject — and
    none of those rejections ever reaches the chain."""
    reader = _FakeRoleManagerReader()
    engine = _new_engine(app_engine)
    issuer = _service(engine=engine, reader=reader)
    wallet = Account.create()

    with sessionmaker(bind=engine)() as session:
        resp = issuer.create_challenge(
            session, _identity(), WalletChallengeRequest(wallet_address=wallet.address, chain_id=CHAIN_ID)
        )
    sig = wallet.sign_message(encode_defunct(text=resp.message)).signature.hex()

    Session = sessionmaker(bind=engine)

    # 1) wrong domain
    rogue_domain = _service(engine=engine, reader=reader, domain="phishing.example.net")
    with pytest.raises(ValueError, match="domain"):
        with Session() as session:
            rogue_domain.verify_and_bind(
                session, _identity(), WalletVerifyRequest(challenge_id=resp.challenge_id, signature=sig)
            )

    # 2) wrong chain id
    rogue_chain = _service(engine=engine, reader=reader, chain_id=999)
    with pytest.raises(ValueError, match="chain"):
        with Session() as session:
            rogue_chain.verify_and_bind(
                session, _identity(), WalletVerifyRequest(challenge_id=resp.challenge_id, signature=sig)
            )

    # 3) wrong subject (same institution): the stored challenge belongs to another user
    with pytest.raises(ValueError, match="another subject"):
        with Session() as session:
            issuer.verify_and_bind(
                session,
                _identity(sub="sub_impersonator"),
                WalletVerifyRequest(challenge_id=resp.challenge_id, signature=sig),
            )

    assert reader.read_count == 0, "domain/chain/subject rejections must not read the chain"
    engine.dispose()


# ---------------------------------------------------------------------------
# Rotation vs. on-chain generation
# ---------------------------------------------------------------------------


def test_rotated_wallet_generation_rejected(app_engine, seeded):
    """After governance rotates the identity to a new wallet, the retired wallet
    fails verification against the on-chain participant record, and the new
    wallet binds with the CURRENT on-chain generation."""
    sub = _unique_sub()
    reader = _FakeRoleManagerReader()
    engine = _new_engine(app_engine)
    service = _service(engine=engine, reader=reader)
    wallet_old = Account.create()
    wallet_new = Account.create()
    pid = "0x" + "ab" * 32

    reader.set_participant(wallet_old.address, pid, 1, "AUDITOR", True)
    with sessionmaker(bind=engine)() as session:
        resp_old = service.create_challenge(
            session, _identity(sub), WalletChallengeRequest(wallet_address=wallet_old.address, chain_id=CHAIN_ID)
        )
    sig_old = wallet_old.sign_message(encode_defunct(text=resp_old.message)).signature.hex()
    with sessionmaker(bind=engine)() as session:
        binding = service.verify_and_bind(
            session, _identity(sub), WalletVerifyRequest(challenge_id=resp_old.challenge_id, signature=sig_old)
        )
    assert binding.authorization_generation == 1
    assert binding.participant_id == pid

    # Governance rotates the identity to wallet_new (generation bumps, old wallet retired).
    reader.set_participant(wallet_old.address, pid, 2, "NONE", False)
    reader.set_participant(wallet_new.address, pid, 2, "AUDITOR", True)

    # A fresh, correctly signed challenge for the RETIRED wallet must be rejected.
    with sessionmaker(bind=engine)() as session:
        resp_stale = service.create_challenge(
            session, _identity(sub), WalletChallengeRequest(wallet_address=wallet_old.address, chain_id=CHAIN_ID)
        )
    sig_stale = wallet_old.sign_message(encode_defunct(text=resp_stale.message)).signature.hex()
    with pytest.raises(ValueError, match="not an active participant"):
        with sessionmaker(bind=engine)() as session:
            service.verify_and_bind(
                session, _identity(sub), WalletVerifyRequest(challenge_id=resp_stale.challenge_id, signature=sig_stale)
            )

    # The new wallet binds with the on-chain generation (2), same participant id.
    with sessionmaker(bind=engine)() as session:
        resp_new = service.create_challenge(
            session, _identity(sub), WalletChallengeRequest(wallet_address=wallet_new.address, chain_id=CHAIN_ID)
        )
    sig_new = wallet_new.sign_message(encode_defunct(text=resp_new.message)).signature.hex()
    with sessionmaker(bind=engine)() as session:
        binding_new = service.verify_and_bind(
            session, _identity(sub), WalletVerifyRequest(challenge_id=resp_new.challenge_id, signature=sig_new)
        )
    assert binding_new.authorization_generation == 2
    assert binding_new.participant_id == pid
    active = service.get_active_binding(TENANT, sub)
    assert active.wallet_address.lower() == wallet_new.address.lower()
    assert active.authorization_generation == 2
    engine.dispose()


# ---------------------------------------------------------------------------
# Local proofs happen BEFORE any chain read
# ---------------------------------------------------------------------------


def test_unproven_wallet_rejected_before_chain_reads(app_engine, seeded):
    """A wallet that fails ANY local proof (signature over the challenge, tenant
    binding of the challenge) is rejected before a single RoleManager read; only
    a fully proven wallet triggers exactly one chain read."""
    reader = _FakeRoleManagerReader()
    engine = _new_engine(app_engine)
    service = _service(engine=engine, reader=reader)
    wallet = Account.create()
    sub = _unique_sub()
    reader.set_participant(wallet.address, "0x" + "f0" * 32, 1, "AUDITOR", True)

    Session = sessionmaker(bind=engine)

    def _issue(institution=TENANT):
        with Session() as session:
            return service.create_challenge(
                session,
                _identity(sub, institution=institution),
                WalletChallengeRequest(wallet_address=wallet.address, chain_id=CHAIN_ID),
            )

    # NOTE: consumption is compare-and-swap FIRST (fail-closed: a failed
    # verification burns the challenge), so each probe below uses its own
    # freshly issued challenge.

    # (a) signature over a DIFFERENT message: valid format, wrong recovery —
    #     the local proof fails and the chain is never read.
    ch_a = _issue()
    wrong_sig = wallet.sign_message(encode_defunct(text="totally different message")).signature.hex()
    with pytest.raises(ValueError, match="Signer address mismatch"):
        with Session() as session:
            service.verify_and_bind(
                session, _identity(sub), WalletVerifyRequest(challenge_id=ch_a.challenge_id, signature=wrong_sig)
            )
    assert reader.read_count == 0

    # (b) a challenge bound to another tenant cannot even be addressed by this
    #     caller's session context — rejected with zero chain reads.
    ch_b = _issue(institution=TENANT)
    with pytest.raises(ValueError):
        with Session() as session:
            service.verify_and_bind(
                session,
                _identity(sub, institution=OTHER_TENANT),
                WalletVerifyRequest(challenge_id=ch_b.challenge_id, signature="0x" + "11" * 65),
            )
    assert reader.read_count == 0

    # (c) the fully proven path reads the chain exactly once.
    ch_c = _issue()
    sig = wallet.sign_message(encode_defunct(text=ch_c.message)).signature.hex()
    with Session() as session:
        binding = service.verify_and_bind(
            session, _identity(sub), WalletVerifyRequest(challenge_id=ch_c.challenge_id, signature=sig)
        )
    assert binding.bound is True
    assert reader.read_count == 1
    engine.dispose()
