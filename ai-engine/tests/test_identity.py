"""
Unit and route-level tests for R10: Institutional Identity & Wallet Binding.

Covers (logic-level; PostgreSQL enforcement lives in tests/integration/):
  - OIDC JWT verification with allowlisted algorithms, mandatory claims
    (exp/iat/nbf/sub + aud/iss) and a 60 second clock skew;
  - membership-sourced roles via resolve_identity (the JWT role claim is never
    a role source and never creates a membership);
  - single-use SIWE wallet challenge semantics (in-memory double for the
    repository — PostgreSQL persistence is covered by
    tests/integration/test_identity_persistence.py);
  - cross-tenant rejection and authorization generation tracking;
  - the /api/v2 identity routes over an identity-only FastAPI app (the full
    app.main pulls uncommitted v1 user modules — see R11 §8 note).
"""

import time
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db.models import (
    Base,
    Institution,
    Membership,
    WalletBindingModel,
)
from app.db.session import set_engine
from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletChallengeRequest,
    WalletVerifyRequest,
)
from app.security.oidc import OIDCVerifier, MockJWKSProvider
from app.security.wallet_binding import (
    BindingRecord,
    InMemoryWalletBindingRepo,
    WalletBindingService,
)
from app.security.tenant_context import TenantContext

ISSUER = "https://auth.institutional-cbi.iq/oauth2"
AUDIENCE = "iraq-aml-audit-engine"
INSTITUTION = "INST-CBI-IQ-01"


@pytest.fixture
def rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
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


@pytest.fixture
def jwks_provider(rsa_keypair):
    pem_private, pem_public = rsa_keypair
    provider = MockJWKSProvider(
        issuer=ISSUER,
        audience=AUDIENCE,
        private_key_pem=pem_private,
        public_key_pem=pem_public,
        key_id="test-key-1",
    )
    return provider


@pytest.fixture
def oidc_verifier(jwks_provider):
    return OIDCVerifier(
        jwks_provider=jwks_provider,
        algorithms=["RS256"],
        clock_skew_seconds=60,
    )


@pytest.fixture
def wallet_repo():
    return InMemoryWalletBindingRepo()


@pytest.fixture
def wallet_service(wallet_repo):
    return WalletBindingService(
        repository=wallet_repo,
        domain="iraq-aml-audit.cbi.iq",
        default_chain_id=31337,
        ttl_seconds=300,  # 5 minutes
    )


# -------------------------------------------------------------
# 1. OIDC Token Verification & Tenant Extraction
# -------------------------------------------------------------

def test_valid_oidc_token_extracts_verified_claims(oidc_verifier, jwks_provider):
    payload = {
        "sub": "usr-auditor-101",
        "email": "ahmed.auditor@cbi.iq",
        "institution_id": INSTITUTION,
        "role": "AUDITOR",  # role claim passes through unverified; membership decides
        "permissions": ["cases:read", "cases:review", "evidence:write"],
    }
    token = jwks_provider.create_signed_token(payload)

    claims = oidc_verifier.verify_token(token)
    assert claims["sub"] == "usr-auditor-101"
    assert claims["institution_id"] == INSTITUTION
    assert claims["email"] == "ahmed.auditor@cbi.iq"
    # The verifier returns claims only — role decisions are NOT made here.
    assert claims["role"] == "AUDITOR"


def test_token_with_invalid_issuer_rejected(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token(
        {"sub": "attacker-1", "institution_id": "INST-ROGUE"},
        override_issuer="https://rogue-idp.example.com",
    )
    with pytest.raises(ValueError, match="Invalid token issuer"):
        oidc_verifier.verify_token(token)


def test_token_with_invalid_audience_rejected(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token(
        {"sub": "attacker-2", "institution_id": INSTITUTION},
        override_audience="wrong-app-audience",
    )
    with pytest.raises(ValueError, match="Invalid token audience"):
        oidc_verifier.verify_token(token)


def test_expired_token_rejected(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token(
        {"sub": "expired-user", "institution_id": INSTITUTION},
        expires_in_seconds=-90,  # beyond the 60s clock skew
    )
    with pytest.raises(ValueError, match="expired"):
        oidc_verifier.verify_token(token)


def test_token_missing_mandatory_claims_rejected(oidc_verifier, jwks_provider):
    """exp/iat/nbf/sub (and aud) are mandatory: a signed token missing any of
    them is rejected, never half-trusted."""
    now = int(time.time())
    base = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now - 5,
        "exp": now + 600,
        "sub": "usr-mandatory",
        "institution_id": INSTITUTION,
    }
    for missing in ("exp", "iat", "nbf", "sub", "aud"):
        broken = {k: v for k, v in base.items() if k != missing}
        token = jwt.encode(
            broken, jwks_provider.private_key_pem, algorithm="RS256",
            headers={"kid": jwks_provider.key_id},
        )
        with pytest.raises(ValueError, match="missing required claim"):
            oidc_verifier.verify_token(token)


def test_token_algorithm_not_allowlisted_rejected(oidc_verifier):
    """Only allowlisted algorithms are accepted: an HS256 token (even with a
    valid signature over its own secret) is rejected."""
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "iat": now, "nbf": now - 5,
            "exp": now + 600, "sub": "usr-alg-confusion", "institution_id": INSTITUTION,
        },
        "symmetric-attacker-secret",
        algorithm="HS256",
    )
    with pytest.raises(ValueError, match="not allowlisted"):
        oidc_verifier.verify_token(token)


def test_clock_skew_60_seconds_applied(oidc_verifier, jwks_provider):
    """Tokens inside the 60s skew window are accepted; beyond it, rejected."""
    now = int(time.time())
    within_skew = jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "iat": now, "nbf": now - 5,
            "exp": now - 30,  # expired 30s ago: inside the 60s skew
            "sub": "usr-skew", "institution_id": INSTITUTION,
        },
        jwks_provider.private_key_pem, algorithm="RS256",
        headers={"kid": jwks_provider.key_id},
    )
    claims = oidc_verifier.verify_token(within_skew)
    assert claims["sub"] == "usr-skew"

    beyond_skew = jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "iat": now - 3600, "nbf": now - 3600,
            "exp": now - 90,  # expired 90s ago: beyond the 60s skew
            "sub": "usr-skew", "institution_id": INSTITUTION,
        },
        jwks_provider.private_key_pem, algorithm="RS256",
        headers={"kid": jwks_provider.key_id},
    )
    with pytest.raises(ValueError, match="expired"):
        oidc_verifier.verify_token(beyond_skew)


def test_jwt_role_claim_is_never_a_role_source(oidc_verifier, jwks_provider):
    """The verifier hands back claims untouched; it derives NO role/identity
    object. A hostile role claim cannot mint an institutional role here."""
    token = jwks_provider.create_signed_token({
        "sub": "usr-guest",
        "institution_id": INSTITUTION,
        "role": "SUPER_HACKER_ROLE_UNMAPPED",
    })
    claims = oidc_verifier.verify_token(token)
    assert claims["role"] == "SUPER_HACKER_ROLE_UNMAPPED"  # passthrough only


# -------------------------------------------------------------
# 2. Membership-sourced identity resolution (resolve_identity)
# -------------------------------------------------------------


@pytest.fixture
def identity_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    yield factory
    engine.dispose()


def test_resolve_identity_role_comes_from_membership(identity_db, isolated_wallet_service):
    """resolve_identity: role/email come from the stored membership; wallet,
    participant_id and generation come from the stored binding. The JWT role
    claim is ignored completely."""
    from datetime import datetime, timezone as tz

    from app.repositories.institution_repository import resolve_identity

    isolated_wallet_service.repo.save_binding(
        None,
        BindingRecord(
            institution_id=INSTITUTION,
            sub="usr-resolve",
            wallet_address="0x" + "3" * 40,
            participant_id="0x" + "4" * 64,
            role=RoleEnum.AUDITOR,
            authorization_generation=3,
            bound_at=datetime.now(tz.utc),
        ),
    )

    with identity_db() as session:
        session.add(Institution(id=INSTITUTION, name="Central Bank of Iraq"))
        session.add(
            Membership(
                id="mem_resolve", institution_id=INSTITUTION, sub="usr-resolve",
                role="AUDITOR", email="member@cbi.iq", is_active=True,
            )
        )
        session.commit()

        claims = {"sub": "usr-resolve", "iss": ISSUER, "institution_id": INSTITUTION, "role": "SUPER_ADMIN"}
        ident = resolve_identity(session, claims)
        assert ident.role == RoleEnum.AUDITOR
        assert ident.email == "member@cbi.iq"
        assert ident.wallet_address == "0x" + "3" * 40
        assert ident.participant_id == "0x" + "4" * 64
        assert ident.authorization_generation == 3


def test_resolve_identity_without_membership_rejected(identity_db, isolated_wallet_service):
    from app.repositories.institution_repository import MembershipResolutionError, resolve_identity

    with identity_db() as session:
        session.add(Institution(id=INSTITUTION, name="Central Bank of Iraq"))
        session.commit()
        claims = {"sub": "usr-ghost", "iss": ISSUER, "institution_id": INSTITUTION, "role": "SUPER_ADMIN"}
        with pytest.raises(MembershipResolutionError):
            resolve_identity(session, claims)


def test_resolve_identity_inactive_membership_rejected(identity_db, isolated_wallet_service):
    from app.repositories.institution_repository import MembershipResolutionError, resolve_identity

    with identity_db() as session:
        session.add(Institution(id=INSTITUTION, name="Central Bank of Iraq"))
        session.add(
            Membership(
                id="mem_inactive", institution_id=INSTITUTION, sub="usr-inactive",
                role="AUDITOR", is_active=False,
            )
        )
        session.commit()
        claims = {"sub": "usr-inactive", "iss": ISSUER, "institution_id": INSTITUTION, "role": "AUDITOR"}
        with pytest.raises(MembershipResolutionError):
            resolve_identity(session, claims)


def test_resolve_identity_unknown_membership_role_maps_to_none(identity_db, isolated_wallet_service):
    """A membership with a role outside the RBAC enum resolves to NONE (fail-closed)."""
    from app.repositories.institution_repository import resolve_identity

    with identity_db() as session:
        session.add(Institution(id=INSTITUTION, name="Central Bank of Iraq"))
        session.add(
            Membership(
                id="mem_weird", institution_id=INSTITUTION, sub="usr-weird",
                role="ANALYST", is_active=True,
            )
        )
        session.commit()
        ident = resolve_identity(
            session, {"sub": "usr-weird", "iss": ISSUER, "institution_id": INSTITUTION}
        )
        assert ident.role == RoleEnum.NONE
        assert ident.wallet_address is None  # no binding for this subject


# -------------------------------------------------------------
# 3. Wallet Challenge & SIWE Signature Verification (in-memory double)
# -------------------------------------------------------------

def test_wallet_challenge_issuance_and_siwe_verification(wallet_service):
    eth_account = Account.create()
    identity = Identity(
        sub="usr-auditor-1",
        issuer=ISSUER,
        institution_id=INSTITUTION,
        role=RoleEnum.AUDITOR,
        permissions=["cases:review"],
    )

    # 1. Request challenge
    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    challenge = wallet_service.create_challenge(None, identity, req)

    assert challenge.challenge_id is not None
    assert challenge.nonce is not None
    assert eth_account.address in challenge.message
    assert "iraq-aml-audit.cbi.iq" in challenge.message
    assert INSTITUTION in challenge.message

    # 2. Sign SIWE message with Ethereum account
    message_hash = encode_defunct(text=challenge.message)
    signature = eth_account.sign_message(message_hash).signature.hex()

    # 3. Verify challenge and bind wallet
    verify_req = WalletVerifyRequest(
        challenge_id=challenge.challenge_id,
        signature=signature,
    )
    binding = wallet_service.verify_and_bind(None, identity, verify_req)

    assert binding.bound is True
    assert binding.wallet_address.lower() == eth_account.address.lower()
    assert binding.institution_id == INSTITUTION
    assert binding.authorization_generation == 1


def test_challenge_replay_attack_rejected(wallet_service):
    eth_account = Account.create()
    identity = Identity(
        sub="usr-auditor-replay",
        issuer=ISSUER,
        institution_id=INSTITUTION,
        role=RoleEnum.AUDITOR,
        permissions=["cases:review"],
    )

    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    challenge = wallet_service.create_challenge(None, identity, req)
    sig = eth_account.sign_message(encode_defunct(text=challenge.message)).signature.hex()

    # First verification succeeds
    wallet_service.verify_and_bind(
        None,
        identity,
        WalletVerifyRequest(challenge_id=challenge.challenge_id, signature=sig),
    )

    # Replay with same challenge_id MUST fail
    with pytest.raises(ValueError, match="Challenge already used or expired"):
        wallet_service.verify_and_bind(
            None,
            identity,
            WalletVerifyRequest(challenge_id=challenge.challenge_id, signature=sig),
        )


def test_expired_challenge_rejected(wallet_service):
    eth_account = Account.create()
    identity = Identity(
        sub="usr-auditor-timeout",
        issuer=ISSUER,
        institution_id=INSTITUTION,
        role=RoleEnum.AUDITOR,
        permissions=[],
    )

    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    # create challenge with negative TTL
    challenge = wallet_service.create_challenge(None, identity, req, ttl_seconds=-1)
    sig = eth_account.sign_message(encode_defunct(text=challenge.message)).signature.hex()

    with pytest.raises(ValueError, match="Challenge already used or expired"):
        wallet_service.verify_and_bind(
            None,
            identity,
            WalletVerifyRequest(challenge_id=challenge.challenge_id, signature=sig),
        )


# -------------------------------------------------------------
# 4. Cross-Tenant Isolation & Role Invalidation
# -------------------------------------------------------------

def test_cross_tenant_wallet_binding_attempt_rejected(wallet_service):
    """
    A token from Institution A attempting to bind or verify
    against Institution B state must be strictly rejected.
    """
    eth_account = Account.create()

    identity_a = Identity(
        sub="usr-bank-a",
        issuer=ISSUER,
        institution_id="INST-A-COMMERCIAL",
        role=RoleEnum.OPERATOR,
        permissions=[],
    )
    identity_b = Identity(
        sub="usr-bank-b",
        issuer=ISSUER,
        institution_id="INST-B-CENTRAL",
        role=RoleEnum.OPERATOR,
        permissions=[],
    )

    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    challenge_a = wallet_service.create_challenge(None, identity_a, req)
    sig = eth_account.sign_message(encode_defunct(text=challenge_a.message)).signature.hex()

    # User B attempts to verify challenge issued to Institution A
    with pytest.raises(ValueError, match="Tenant mismatch"):
        wallet_service.verify_and_bind(
            None,
            identity_b,
            WalletVerifyRequest(challenge_id=challenge_a.challenge_id, signature=sig),
        )


def test_wallet_rotation_increments_authorization_generation(wallet_service):
    """
    Rotating wallet increments authorization_generation,
    invalidating previous signature validity.
    """
    account_old = Account.create()
    account_new = Account.create()

    identity = Identity(
        sub="usr-auditor-rotating",
        issuer=ISSUER,
        institution_id=INSTITUTION,
        role=RoleEnum.AUDITOR,
        permissions=["cases:review"],
    )

    # 1. Bind first wallet
    c1 = wallet_service.create_challenge(
        None, identity, WalletChallengeRequest(wallet_address=account_old.address, chain_id=31337)
    )
    s1 = account_old.sign_message(encode_defunct(text=c1.message)).signature.hex()
    b1 = wallet_service.verify_and_bind(
        None, identity, WalletVerifyRequest(challenge_id=c1.challenge_id, signature=s1)
    )
    assert b1.authorization_generation == 1
    assert b1.wallet_address.lower() == account_old.address.lower()

    # 2. Rotate to new wallet
    c2 = wallet_service.create_challenge(
        None, identity, WalletChallengeRequest(wallet_address=account_new.address, chain_id=31337)
    )
    s2 = account_new.sign_message(encode_defunct(text=c2.message)).signature.hex()
    b2 = wallet_service.verify_and_bind(
        None, identity, WalletVerifyRequest(challenge_id=c2.challenge_id, signature=s2)
    )

    assert b2.authorization_generation == 2
    assert b2.wallet_address.lower() == account_new.address.lower()

    # Check active binding
    active = wallet_service.get_active_binding(institution_id=INSTITUTION, sub="usr-auditor-rotating")
    assert active.authorization_generation == 2
    assert active.wallet_address.lower() == account_new.address.lower()


def test_tenant_context_middleware_enforcement():
    """
    TenantContext ensures institution_id is immutable per request and
    cannot be overwritten by request headers or body.
    """
    ctx = TenantContext(institution_id="INST-TEST-PRIMARY")
    assert ctx.institution_id == "INST-TEST-PRIMARY"

    # Attempting to assign a mismatched tenant must raise
    with pytest.raises(ValueError, match="Tenant context mismatch"):
        ctx.assert_authorized_for_institution("INST-DIFFERENT")


# -------------------------------------------------------------
# 5. HTTP API Route Tests (identity-only FastAPI app)
#
# app.main is NOT imported here: it pulls the v1 route modules that are
# uncommitted user edits existing only in the main workspace (see R11 §8).
# The identity router is built standalone with the same /api/v2 prefix.
# -------------------------------------------------------------

from app.routes.v2.identity import router as identity_router
from app.routes.v2.identity import set_oidc_verifier, set_wallet_service


@pytest.fixture
def isolated_wallet_service():
    """A session-free in-memory wallet service injected as the singleton, so
    resolve_identity's binding lookup never touches a real database."""
    service = WalletBindingService(
        repository=InMemoryWalletBindingRepo(),
        domain="iraq-aml-audit.cbi.iq",
        default_chain_id=31337,
        ttl_seconds=300,
    )
    set_wallet_service(service)
    yield service
    set_wallet_service(None)


def _identity_app() -> FastAPI:
    app = FastAPI()
    app.include_router(identity_router, prefix="/api/v2")
    return app


@pytest.fixture
def client(oidc_verifier, wallet_service, identity_db):
    """Identity-only app with services injected and an in-memory SQLite DB wired
    as the request-session engine (create_all dev path)."""
    engine = identity_db.kw["bind"]
    with identity_db() as session:
        session.add(Institution(id=INSTITUTION, name="Central Bank of Iraq"))
        for sub, role in (
            ("usr-auditor-fastapi", "AUDITOR"),
            ("usr-auditor-flow", "AUDITOR"),
            ("usr-tenant-a", "AUDITOR"),
            ("usr-tenant-b", "AUDITOR"),
            ("usr-test-schema", "AUDITOR"),
        ):
            session.add(
                Membership(
                    id=f"mem_{sub}", institution_id=INSTITUTION, sub=sub,
                    role=role, is_active=True,
                )
            )
            if sub == "usr-tenant-a":
                session.add(
                    Membership(
                        id="mem_inst_a", institution_id="INST-A-COMMERCIAL", sub=sub,
                        role="AUDITOR", is_active=True,
                    )
                )
                session.add(Institution(id="INST-A-COMMERCIAL", name="A"))
            if sub == "usr-tenant-b":
                session.add(
                    Membership(
                        id="mem_inst_b", institution_id="INST-B-CENTRAL", sub=sub,
                        role="AUDITOR", is_active=True,
                    )
                )
                session.add(Institution(id="INST-B-CENTRAL", name="B"))
        session.commit()

    set_engine(engine)
    set_oidc_verifier(oidc_verifier)
    set_wallet_service(wallet_service)
    with TestClient(_identity_app()) as test_client:
        yield test_client
    set_oidc_verifier(None)
    set_wallet_service(None)
    set_engine(None)


def test_api_identity_me_demo_fallback(client):
    """When APP_MODE is demo, OIDC disabled and no header, returns demo identity."""
    orig = settings.OIDC_ENABLED
    orig_mode = getattr(settings, "APP_MODE", "demo")
    try:
        settings.OIDC_ENABLED = False
        if hasattr(settings, "APP_MODE"):
            settings.APP_MODE = "demo"
        res = client.get("/api/v2/identity/me")
        assert res.status_code == 200
        data = res.json()
        assert data["sub"] == "usr-dev-demo"
        assert data["institution_id"] == settings.INSTITUTION_ID
        assert data["role"] == "SUPER_ADMIN"
    finally:
        settings.OIDC_ENABLED = orig
        if hasattr(settings, "APP_MODE"):
            settings.APP_MODE = orig_mode


def test_api_identity_me_unauthorized_when_oidc_enabled(client):
    """When OIDC_ENABLED is True and no Authorization header, returns 401."""
    orig = settings.OIDC_ENABLED
    try:
        settings.OIDC_ENABLED = True
        res = client.get("/api/v2/identity/me")
        assert res.status_code == 401
        assert "Missing Authorization" in res.json()["detail"]
    finally:
        settings.OIDC_ENABLED = orig


def test_api_identity_me_invalid_token_returns_401(client):
    res = client.get(
        "/api/v2/identity/me",
        headers={"Authorization": "Bearer invalid-garbage-token"}
    )
    assert res.status_code == 401
    assert "Authentication failed" in res.json()["detail"]


def test_api_identity_me_valid_jwt(client, jwks_provider):
    token = jwks_provider.create_signed_token({
        "sub": "usr-auditor-fastapi",
        "email": "fatima.auditor@cbi.iq",
        "institution_id": INSTITUTION,
        "role": "AUDITOR",
        "permissions": ["cases:review"],
    })
    res = client.get(
        "/api/v2/identity/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["sub"] == "usr-auditor-fastapi"
    assert data["institution_id"] == INSTITUTION
    assert data["role"] == "AUDITOR"  # from the stored membership
    assert data["wallet_address"] is None  # not yet bound


def test_api_identity_me_without_membership_forbidden(client, jwks_provider):
    """A perfectly valid JWT for a subject WITHOUT a stored membership is 403 —
    the token cannot create membership."""
    token = jwks_provider.create_signed_token({
        "sub": "usr-no-membership",
        "institution_id": INSTITUTION,
        "role": "SUPER_ADMIN",
    })
    res = client.get(
        "/api/v2/identity/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 403


def test_api_wallet_challenge_and_verify_flow(client, jwks_provider):
    token = jwks_provider.create_signed_token({
        "sub": "usr-auditor-flow",
        "institution_id": INSTITUTION,
        "role": "AUDITOR",
        "permissions": ["cases:review"],
    })
    auth_headers = {"Authorization": f"Bearer {token}"}

    eth_account = Account.create()

    # 1. Request Challenge
    challenge_payload = {
        "wallet_address": eth_account.address,
        "chain_id": 31337,
    }
    res = client.post("/api/v2/wallet/challenge", json=challenge_payload, headers=auth_headers)
    assert res.status_code == 200
    challenge_data = res.json()
    assert "challenge_id" in challenge_data
    assert "nonce" in challenge_data
    assert eth_account.address in challenge_data["message"]

    # 2. Sign SIWE message
    sig = eth_account.sign_message(encode_defunct(text=challenge_data["message"])).signature.hex()

    # 3. Verify Challenge and Bind
    verify_payload = {
        "challenge_id": challenge_data["challenge_id"],
        "signature": sig,
    }
    res_verify = client.post("/api/v2/wallet/verify", json=verify_payload, headers=auth_headers)
    assert res_verify.status_code == 200
    binding_data = res_verify.json()
    assert binding_data["bound"] is True
    assert binding_data["wallet_address"].lower() == eth_account.address.lower()
    assert binding_data["institution_id"] == INSTITUTION
    assert binding_data["authorization_generation"] == 1

    # 4. Subsequent /identity/me now has wallet bound
    res_me = client.get("/api/v2/identity/me", headers=auth_headers)
    assert res_me.status_code == 200
    assert res_me.json()["wallet_address"].lower() == eth_account.address.lower()
    assert res_me.json()["authorization_generation"] == 1

    # 5. Replay fails with 400
    res_replay = client.post("/api/v2/wallet/verify", json=verify_payload, headers=auth_headers)
    assert res_replay.status_code == 400
    assert "Challenge already used or expired" in res_replay.json()["detail"]


def test_api_cross_tenant_wallet_verify_rejected(client, jwks_provider):
    token_a = jwks_provider.create_signed_token({
        "sub": "usr-tenant-a",
        "institution_id": "INST-A-COMMERCIAL",
        "role": "AUDITOR",
    })
    token_b = jwks_provider.create_signed_token({
        "sub": "usr-tenant-b",
        "institution_id": "INST-B-CENTRAL",
        "role": "AUDITOR",
    })

    eth_account = Account.create()

    # User A creates challenge
    res = client.post(
        "/api/v2/wallet/challenge",
        json={"wallet_address": eth_account.address, "chain_id": 31337},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res.status_code == 200
    challenge_data = res.json()
    sig = eth_account.sign_message(encode_defunct(text=challenge_data["message"])).signature.hex()

    # User B attempts to verify User A's challenge
    res_cross = client.post(
        "/api/v2/wallet/verify",
        json={"challenge_id": challenge_data["challenge_id"], "signature": sig},
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_cross.status_code == 400
    assert "Tenant mismatch" in res_cross.json()["detail"]


def test_api_challenge_strict_validation(client, jwks_provider):
    token = jwks_provider.create_signed_token({
        "sub": "usr-test-schema",
        "institution_id": INSTITUTION,
    })
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Extra forbidden field
    res = client.post(
        "/api/v2/wallet/challenge",
        json={"wallet_address": "0x1111111111111111111111111111111111111111", "forbidden_field": True},
        headers=auth_headers,
    )
    assert res.status_code == 422

    # Malformed wallet address
    res = client.post(
        "/api/v2/wallet/challenge",
        json={"wallet_address": "not-an-evm-address"},
        headers=auth_headers,
    )
    assert res.status_code == 422
