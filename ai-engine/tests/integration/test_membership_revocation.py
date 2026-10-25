"""
Institutional membership/revocation integration tests (R10) — real PostgreSQL and
real RSA-signed JWT fixtures (synthetic keys only; no external IdP needed).

Requires the same environment contract as test_postgres_rls.py (R11):
  DATABASE_URL            -> least-privilege APP role (ira_aml_app), NOSUPERUSER NOBYPASSRLS.
  MIGRATION_DATABASE_URL  -> migration OWNER role (ira_aml_migrator).
Without them the module SKIPS.

R10 spec points exercised here:
  - institutional mode NEVER answers without a Bearer token (401) and NEVER falls
    back to the demo identity;
  - institutional startup with OIDC disabled/incomplete must FAIL;
  - tokens missing mandatory claims (exp/aud) are rejected;
  - the JWT role claim can neither create a membership nor influence the resolved
    role — the stored active membership is the only role source;
  - deactivating a membership after a token was issued forbids the NEXT request
    with that very token;
  - when the OIDC provider itself is unreachable, no demo identity ever appears.
"""

import os
import subprocess
import time
import uuid
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.models import Institution, Membership
from app.db.session import set_engine, tenant_transaction
from app.routes.v2.identity import router as identity_router
from app.routes.v2.identity import set_oidc_verifier, set_wallet_service
from app.security.oidc import MockJWKSProvider, OIDCVerifier

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT = "inst_r10_members"
ISSUER = "https://auth.institutional-cbi.iq/oauth2"
AUDIENCE = "iraq-aml-audit-engine"
DEMO_SUB = "usr-dev-demo"


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R10 membership revocation tests require DATABASE_URL (app role) and "
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
            "alembic upgrade head failed against the R10 test database "
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
            session.add(Institution(id=TENANT, name="R10 Membership Test Institution"))
        session.commit()
    yield


def _seed_membership(owner_engine, sub, role="AUDITOR", active=True, institution=TENANT):
    """Insert (or reactivate) a membership as the migration owner under the tenant context."""
    with sessionmaker(bind=owner_engine)() as session:
        with tenant_transaction(session, institution):
            existing = session.execute(
                select(Membership).where(
                    Membership.institution_id == institution, Membership.sub == sub
                )
            ).scalars().first()
            if existing is None:
                session.add(
                    Membership(
                        id=f"mem_{uuid.uuid4().hex[:16]}",
                        institution_id=institution,
                        sub=sub,
                        role=role,
                        is_active=active,
                    )
                )
            else:
                existing.is_active = active
                existing.role = role


def _set_membership_active(owner_engine, sub, active, institution=TENANT):
    with sessionmaker(bind=owner_engine)() as session:
        with tenant_transaction(session, institution):
            mem = session.execute(
                select(Membership).where(
                    Membership.institution_id == institution, Membership.sub == sub
                )
            ).scalars().one()
            mem.is_active = active


def _membership_count(owner_engine, sub, institution=TENANT) -> int:
    with sessionmaker(bind=owner_engine)() as session:
        with tenant_transaction(session, institution):
            return session.execute(
                select(func.count())
                .select_from(Membership)
                .where(Membership.institution_id == institution, Membership.sub == sub)
            ).scalar_one()


# ---------------------------------------------------------------------------
# Fixtures: real RSA keys (synthetic), real signed JWTs, identity-only FastAPI app
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_private, pem_public


@pytest.fixture(scope="module")
def jwks_provider(rsa_keypair):
    pem_private, pem_public = rsa_keypair
    return MockJWKSProvider(
        issuer=ISSUER,
        audience=AUDIENCE,
        private_key_pem=pem_private,
        public_key_pem=pem_public,
        key_id="r10-test-key",
    )


@pytest.fixture
def api(app_engine, jwks_provider, seeded):
    """TestClient over the identity v2 router, wired to the real PostgreSQL app role.

    The full app.main is deliberately NOT imported: the v1 route modules it pulls in
    are uncommitted user edits that exist only in the main workspace (same situation
    documented in R11 §8). The identity router is the surface under test.
    """
    saved_settings = {
        "APP_MODE": getattr(settings, "APP_MODE", "demo"),
        "OIDC_ENABLED": settings.OIDC_ENABLED,
        "OIDC_ISSUER": settings.OIDC_ISSUER,
        "OIDC_AUDIENCE": settings.OIDC_AUDIENCE,
        "OIDC_JWKS_URL": settings.OIDC_JWKS_URL,
        "OIDC_ALGORITHMS": list(getattr(settings, "OIDC_ALGORITHMS", ["RS256"])),
        "OIDC_CLOCK_SKEW_SECONDS": getattr(settings, "OIDC_CLOCK_SKEW_SECONDS", 60),
    }
    set_engine(app_engine)
    # Verifier defaults are the R10-compliant ones (RS256 allowlist, 60s skew);
    # explicit kwargs are pinned by tests/test_identity.py.
    set_oidc_verifier(
        OIDCVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_provider=jwks_provider)
    )
    set_wallet_service(None)  # default DB-backed service

    app = FastAPI()
    app.include_router(identity_router, prefix="/api/v2")
    with TestClient(app) as test_client:
        yield test_client

    set_oidc_verifier(None)
    set_wallet_service(None)
    set_engine(None)
    for key, value in saved_settings.items():
        setattr(settings, key, value)


def _token(jwks_provider, sub, role="AUDITOR", institution=TENANT, **kwargs):
    return jwks_provider.create_signed_token(
        {"sub": sub, "institution_id": institution, "role": role, "permissions": []}, **kwargs
    )


def _me(client, token):
    return client.get("/api/v2/identity/me", headers={"Authorization": f"Bearer {token}"})


# ---------------------------------------------------------------------------
# Institutional mode: no anonymous access, no demo identity
# ---------------------------------------------------------------------------


def test_institutional_no_bearer_401(api):
    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = True
    res = api.get("/api/v2/identity/me")
    assert res.status_code == 401
    assert DEMO_SUB not in res.text

    # Even with the OIDC flag off, institutional mode must never serve the demo identity.
    settings.OIDC_ENABLED = False
    res2 = api.get("/api/v2/identity/me")
    assert res2.status_code == 401
    assert DEMO_SUB not in res2.text


def test_oidc_disabled_startup_fails(api):
    from app.config import validate_startup_config

    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = False
    with pytest.raises(RuntimeError, match="OIDC"):
        validate_startup_config()

    # OIDC enabled but incomplete configuration must also refuse to start.
    settings.OIDC_ENABLED = True
    settings.OIDC_JWKS_URL = ""
    with pytest.raises(RuntimeError, match="OIDC"):
        validate_startup_config()

    # A complete institutional configuration passes.
    settings.OIDC_JWKS_URL = "https://auth.institutional-cbi.iq/oauth2/jwks"
    validate_startup_config()

    # Demo mode with OIDC disabled is a valid, isolated development mode.
    settings.APP_MODE = "demo"
    settings.OIDC_ENABLED = False
    validate_startup_config()


# ---------------------------------------------------------------------------
# Mandatory claims
# ---------------------------------------------------------------------------


def test_missing_exp_or_audience_rejected(api, jwks_provider):
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now - 5,
        "exp": now + 600,
        "sub": f"sub_noclaims_{uuid.uuid4().hex[:8]}",
        "institution_id": TENANT,
        "role": "SUPER_ADMIN",
    }

    without_exp = {k: v for k, v in base.items() if k != "exp"}
    token = jwt.encode(without_exp, jwks_provider.private_key_pem, algorithm="RS256",
                       headers={"kid": jwks_provider.key_id})
    res = _me(api, token)
    assert res.status_code == 401
    assert DEMO_SUB not in res.text

    without_aud = {k: v for k, v in base.items() if k != "aud"}
    token2 = jwt.encode(without_aud, jwks_provider.private_key_pem, algorithm="RS256",
                        headers={"kid": jwks_provider.key_id})
    res2 = _me(api, token2)
    assert res2.status_code == 401
    assert DEMO_SUB not in res2.text


# ---------------------------------------------------------------------------
# Membership is the only role source
# ---------------------------------------------------------------------------


def test_jwt_role_cannot_create_membership(api, owner_engine, jwks_provider):
    sub = f"sub_role_probe_{uuid.uuid4().hex[:8]}"
    token = _token(jwks_provider, sub, role="SUPER_ADMIN")

    # No membership row exists: a SUPER_ADMIN JWT claim grants nothing and
    # must NOT materialize a membership.
    res = _me(api, token)
    assert res.status_code == 403
    assert _membership_count(owner_engine, sub) == 0

    # With a stored membership, its role wins over the JWT role claim.
    _seed_membership(owner_engine, sub, role="AUDITOR")
    res2 = _me(api, token)
    assert res2.status_code == 200
    body = res2.json()
    assert body["role"] == "AUDITOR"
    assert body["sub"] == sub
    assert body["institution_id"] == TENANT


def test_inactive_membership_forbidden(api, owner_engine, jwks_provider):
    sub = f"sub_inactive_{uuid.uuid4().hex[:8]}"
    _seed_membership(owner_engine, sub, role="AUDITOR", active=False)
    token = _token(jwks_provider, sub, role="SUPER_ADMIN")
    res = _me(api, token)
    assert res.status_code == 403


def test_revoked_membership_rejects_issued_token(api, owner_engine, jwks_provider):
    """A token issued while the membership was active must be forbidden on the
    NEXT request after the membership is deactivated — no token TTL grace."""
    sub = f"sub_revoke_{uuid.uuid4().hex[:8]}"
    _seed_membership(owner_engine, sub, role="OPERATOR", active=True)
    token = _token(jwks_provider, sub, role="SUPER_ADMIN")  # JWT claims are irrelevant

    res = _me(api, token)
    assert res.status_code == 200
    assert res.json()["role"] == "OPERATOR"

    _set_membership_active(owner_engine, sub, active=False)

    res2 = _me(api, token)
    assert res2.status_code == 403


# ---------------------------------------------------------------------------
# Provider failure: the demo identity must never surface
# ---------------------------------------------------------------------------


def test_demo_identity_absent_when_oidc_provider_fails(api, jwks_provider):
    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = True
    # JWKS endpoint that refuses connections: the verifier cannot fetch keys.
    set_oidc_verifier(OIDCVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_url="http://127.0.0.1:9/jwks"))
    token = _token(jwks_provider, f"sub_provider_fail_{uuid.uuid4().hex[:8]}")

    res = _me(api, token)
    assert res.status_code == 503, f"provider failure must be 503, got {res.status_code}"
    assert DEMO_SUB not in res.text

    # And the anonymous path in institutional mode never serves the demo identity either.
    res2 = api.get("/api/v2/identity/me")
    assert res2.status_code == 401
    assert DEMO_SUB not in res2.text


# ---------------------------------------------------------------------------
# Response contract: same shape, no secrets
# ---------------------------------------------------------------------------


def test_identity_response_shape_preserved(api, owner_engine, jwks_provider):
    sub = f"sub_shape_{uuid.uuid4().hex[:8]}"
    _seed_membership(owner_engine, sub, role="AUDITOR")
    res = _me(api, _token(jwks_provider, sub, role="SUPER_ADMIN"))
    assert res.status_code == 200
    body = res.json()
    assert set(body.keys()) == {
        "sub",
        "issuer",
        "institution_id",
        "role",
        "permissions",
        "email",
        "participant_id",
        "wallet_address",
        "authorization_generation",
    }
    assert "token" not in body
    assert "challenge" not in body
    assert body["role"] == "AUDITOR"
    assert body["wallet_address"] is None  # no binding yet
