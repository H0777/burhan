"""
Unit and Integration tests for T13: Institutional Identity & Wallet Binding
Verifies OIDC JWT verification, tenant context extraction, single-use wallet challenge
and signature verification, cross-tenant rejection, and authorization generation tracking.
"""

import time
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from eth_account import Account
from eth_account.messages import encode_defunct

from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletChallengeRequest,
    WalletVerifyRequest,
)
from app.security.oidc import OIDCVerifier, MockJWKSProvider
from app.security.wallet_binding import WalletBindingService, InMemoryWalletBindingRepo
from app.security.tenant_context import TenantContext


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
        issuer="https://auth.institutional-cbi.iq/oauth2",
        audience="iraq-aml-audit-engine",
        private_key_pem=pem_private,
        public_key_pem=pem_public,
        key_id="test-key-1",
    )
    return provider


@pytest.fixture
def oidc_verifier(jwks_provider):
    return OIDCVerifier(jwks_provider=jwks_provider)


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

def test_valid_oidc_token_extracts_identity(oidc_verifier, jwks_provider):
    payload = {
        "sub": "usr-auditor-101",
        "email": "ahmed.auditor@cbi.iq",
        "institution_id": "INST-CBI-IQ-01",
        "role": "AUDITOR",
        "permissions": ["cases:read", "cases:review", "evidence:write"],
    }
    token = jwks_provider.create_signed_token(payload)
    
    identity = oidc_verifier.verify_token(token)
    assert identity.sub == "usr-auditor-101"
    assert identity.institution_id == "INST-CBI-IQ-01"
    assert identity.role == RoleEnum.AUDITOR
    assert identity.email == "ahmed.auditor@cbi.iq"
    assert "evidence:write" in identity.permissions


def test_token_with_invalid_issuer_rejected(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token(
        {"sub": "attacker-1", "institution_id": "INST-ROGUE"},
        override_issuer="https://rogue-idp.example.com",
    )
    with pytest.raises(ValueError, match="Invalid token issuer"):
        oidc_verifier.verify_token(token)


def test_token_with_invalid_audience_rejected(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token(
        {"sub": "attacker-2", "institution_id": "INST-CBI-IQ-01"},
        override_audience="wrong-app-audience",
    )
    with pytest.raises(ValueError, match="Invalid token audience"):
        oidc_verifier.verify_token(token)


def test_expired_token_rejected(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token(
        {"sub": "expired-user", "institution_id": "INST-CBI-IQ-01"},
        expires_in_seconds=-10,
    )
    with pytest.raises(ValueError, match="Token has expired"):
        oidc_verifier.verify_token(token)


def test_unregistered_claim_role_defaults_to_none(oidc_verifier, jwks_provider):
    token = jwks_provider.create_signed_token({
        "sub": "usr-guest",
        "institution_id": "INST-CBI-IQ-01",
        "role": "SUPER_HACKER_ROLE_UNMAPPED",
    })
    identity = oidc_verifier.verify_token(token)
    assert identity.role == RoleEnum.NONE


# -------------------------------------------------------------
# 2. Wallet Challenge & SIWE Signature Verification
# -------------------------------------------------------------

def test_wallet_challenge_issuance_and_siwe_verification(wallet_service):
    eth_account = Account.create()
    identity = Identity(
        sub="usr-auditor-1",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-CBI-IQ-01",
        role=RoleEnum.AUDITOR,
        permissions=["cases:review"],
    )

    # 1. Request challenge
    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    challenge = wallet_service.create_challenge(identity=identity, request=req)
    
    assert challenge.challenge_id is not None
    assert challenge.nonce is not None
    assert eth_account.address in challenge.message
    assert "iraq-aml-audit.cbi.iq" in challenge.message
    assert "INST-CBI-IQ-01" in challenge.message

    # 2. Sign SIWE message with Ethereum account
    message_hash = encode_defunct(text=challenge.message)
    signature = eth_account.sign_message(message_hash).signature.hex()

    # 3. Verify challenge and bind wallet
    verify_req = WalletVerifyRequest(
        challenge_id=challenge.challenge_id,
        signature=signature,
    )
    binding = wallet_service.verify_and_bind(identity=identity, request=verify_req)

    assert binding.bound is True
    assert binding.wallet_address.lower() == eth_account.address.lower()
    assert binding.institution_id == "INST-CBI-IQ-01"
    assert binding.authorization_generation == 1


def test_challenge_replay_attack_rejected(wallet_service):
    eth_account = Account.create()
    identity = Identity(
        sub="usr-auditor-replay",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-CBI-IQ-01",
        role=RoleEnum.AUDITOR,
        permissions=["cases:review"],
    )

    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    challenge = wallet_service.create_challenge(identity=identity, request=req)
    sig = eth_account.sign_message(encode_defunct(text=challenge.message)).signature.hex()

    # First verification succeeds
    wallet_service.verify_and_bind(
        identity=identity,
        request=WalletVerifyRequest(challenge_id=challenge.challenge_id, signature=sig),
    )

    # Replay with same challenge_id MUST fail
    with pytest.raises(ValueError, match="Challenge already used or expired"):
        wallet_service.verify_and_bind(
            identity=identity,
            request=WalletVerifyRequest(challenge_id=challenge.challenge_id, signature=sig),
        )


def test_expired_challenge_rejected(wallet_service):
    eth_account = Account.create()
    identity = Identity(
        sub="usr-auditor-timeout",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-CBI-IQ-01",
        role=RoleEnum.AUDITOR,
        permissions=[],
    )

    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    # create challenge with negative TTL
    challenge = wallet_service.create_challenge(identity=identity, request=req, ttl_seconds=-1)
    sig = eth_account.sign_message(encode_defunct(text=challenge.message)).signature.hex()

    with pytest.raises(ValueError, match="Challenge already used or expired"):
        wallet_service.verify_and_bind(
            identity=identity,
            request=WalletVerifyRequest(challenge_id=challenge.challenge_id, signature=sig),
        )


# -------------------------------------------------------------
# 3. Cross-Tenant Isolation & Role Invalidation (Review Focus 1 & 2)
# -------------------------------------------------------------

def test_cross_tenant_wallet_binding_attempt_rejected(wallet_service):
    """
    Review Focus 1: Token from Institution A attempting to bind or verify
    against Institution B state must be strictly rejected.
    """
    eth_account = Account.create()
    
    identity_a = Identity(
        sub="usr-bank-a",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-A-COMMERCIAL",
        role=RoleEnum.OPERATOR,
        permissions=[],
    )
    identity_b = Identity(
        sub="usr-bank-b",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-B-CENTRAL",
        role=RoleEnum.OPERATOR,
        permissions=[],
    )

    req = WalletChallengeRequest(wallet_address=eth_account.address, chain_id=31337)
    challenge_a = wallet_service.create_challenge(identity=identity_a, request=req)
    sig = eth_account.sign_message(encode_defunct(text=challenge_a.message)).signature.hex()

    # User B attempts to verify challenge issued to Institution A
    with pytest.raises(ValueError, match="Tenant mismatch"):
        wallet_service.verify_and_bind(
            identity=identity_b,
            request=WalletVerifyRequest(challenge_id=challenge_a.challenge_id, signature=sig),
        )


def test_wallet_rotation_increments_authorization_generation(wallet_service):
    """
    Review Focus 2: Rotating wallet increments authorization_generation,
    invalidating previous signature validity.
    """
    account_old = Account.create()
    account_new = Account.create()

    identity = Identity(
        sub="usr-auditor-rotating",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-CBI-IQ-01",
        role=RoleEnum.AUDITOR,
        permissions=["cases:review"],
    )

    # 1. Bind first wallet
    c1 = wallet_service.create_challenge(identity=identity, request=WalletChallengeRequest(wallet_address=account_old.address, chain_id=31337))
    s1 = account_old.sign_message(encode_defunct(text=c1.message)).signature.hex()
    b1 = wallet_service.verify_and_bind(identity=identity, request=WalletVerifyRequest(challenge_id=c1.challenge_id, signature=s1))
    assert b1.authorization_generation == 1
    assert b1.wallet_address.lower() == account_old.address.lower()

    # 2. Rotate to new wallet
    c2 = wallet_service.create_challenge(identity=identity, request=WalletChallengeRequest(wallet_address=account_new.address, chain_id=31337))
    s2 = account_new.sign_message(encode_defunct(text=c2.message)).signature.hex()
    b2 = wallet_service.verify_and_bind(identity=identity, request=WalletVerifyRequest(challenge_id=c2.challenge_id, signature=s2))
    
    assert b2.authorization_generation == 2
    assert b2.wallet_address.lower() == account_new.address.lower()

    # Check active binding
    active = wallet_service.get_active_binding(institution_id="INST-CBI-IQ-01", sub="usr-auditor-rotating")
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
# 4. HTTP API Route Integration Tests (FastAPI TestClient)
# -------------------------------------------------------------

from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.routes.v2.identity import set_oidc_verifier, set_wallet_service


@pytest.fixture
def client(oidc_verifier, wallet_service):
    # Set injectable services
    set_oidc_verifier(oidc_verifier)
    set_wallet_service(wallet_service)
    with TestClient(app) as test_client:
        yield test_client
    # Cleanup
    set_oidc_verifier(None)
    set_wallet_service(None)


def test_api_identity_me_demo_fallback(client):
    """When OIDC_ENABLED is False and no header, returns demo identity."""
    orig = settings.OIDC_ENABLED
    try:
        settings.OIDC_ENABLED = False
        res = client.get("/api/v2/identity/me")
        assert res.status_code == 200
        data = res.json()
        assert data["sub"] == "usr-dev-demo"
        assert data["institution_id"] == settings.INSTITUTION_ID
        assert data["role"] == "SUPER_ADMIN"
    finally:
        settings.OIDC_ENABLED = orig


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
        "institution_id": "INST-CBI-IQ-01",
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
    assert data["institution_id"] == "INST-CBI-IQ-01"
    assert data["role"] == "AUDITOR"
    assert data["wallet_address"] is None  # not yet bound


def test_api_wallet_challenge_and_verify_flow(client, jwks_provider):
    token = jwks_provider.create_signed_token({
        "sub": "usr-auditor-flow",
        "institution_id": "INST-CBI-IQ-01",
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
    assert binding_data["institution_id"] == "INST-CBI-IQ-01"
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
        "institution_id": "INST-CBI-IQ-01",
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

