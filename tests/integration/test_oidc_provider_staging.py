"""
H05 staging integration — the institutional identity loop against a REAL OIDC
provider (Keycloak, realm "burhan") through the staging nginx origin.

Real HTTP only — NO MOCKS: the PyJWT/OIDC verification contract here mirrors
ai-engine/app/security/oidc.py (RS256 allowlist, iss/aud/exp/iat/nbf/sub,
60s skew) but every token comes from the actual provider running at
KEYCLOAK_ORIGIN, and every API call goes through the nginx origin the browser
uses. The MockJWKSProvider fixture stays confined to ai-engine/tests — it is
NEVER used here (brief H05).

Flow under test (spec section 8 / brief H05):
  discovery -> PKCE Authorization Code login (form POST, cookie session) ->
  code+state callback -> token exchange (code_verifier) -> JWT verified against
  live JWKS -> identity/me through nginx -> SIWE wallet challenge -> EIP-191
  signature -> bind (on-chain RoleManager participant proof) -> identity/me
  carries participant_id + authorization_generation ->
  membership deactivation (operator DB duty) makes the SAME live token 403 on
  the very next request (R10 semantics), then the membership is restored.

Environment contract (module SKIPS without them — the operator secret lives in
gitignored infra/staging/.env, never committed):
  STAGING_OIDC_USER_PASSWORD   required — operator password
  STAGING_OIDC_USERNAME        default "staging-operator"
  H05_STAGING_ORIGIN           default http://127.0.0.1:18080 (nginx)
  H05_KEYCLOAK_ORIGIN          default http://127.0.0.1:18081 (issuer host origin)
  H05_INSTITUTION_ID           default INST-CENTRAL-STAGING
  MIGRATION_DATABASE_URL       enables the revocation test (OWNER role URL to
                               the staging PostgreSQL, e.g.
                               postgresql://ira_aml_migrator:...@127.0.0.1:15432/iraq_aml_staging)

Run:
  node scripts/run-python.js -m pytest -q tests/integration/test_oidc_provider_staging.py -v
"""

import base64
import hashlib
import html as html_module
import os
import re
import secrets
import urllib.parse

import jwt
import pytest
import requests
from jwt import PyJWKClient

STAGING_ORIGIN = os.environ.get("H05_STAGING_ORIGIN", "http://127.0.0.1:18080").rstrip("/")
KEYCLOAK_ORIGIN = os.environ.get("H05_KEYCLOAK_ORIGIN", "http://127.0.0.1:18081").rstrip("/")
ISSUER = f"{KEYCLOAK_ORIGIN}/realms/burhan"
CLIENT_ID = "iraq-aml-frontend"
REDIRECT_URI = f"{STAGING_ORIGIN}/auth/callback"
SCOPE = "openid profile email"
AUDIENCE = "iraq-aml-audit-engine"
INSTITUTION_ID = os.environ.get("H05_INSTITUTION_ID", "INST-CENTRAL-STAGING")
CHAIN_ID = 31337

USERNAME = os.environ.get("STAGING_OIDC_USERNAME", "staging-operator")
PASSWORD = os.environ.get("STAGING_OIDC_USER_PASSWORD", "")

# The institutional operator's wallet: Hardhat dev-network account #5, enrolled
# by the scripts/deploy.js roster bootstrap as "INST-OPERATIONS-01"
# (OPERATOR, generation 1). A PUBLIC deterministic dev-network key — never a
# deployed secret; the on-chain participant proof is the security boundary.
OPERATOR_WALLET_ADDRESS = "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc"
OPERATOR_WALLET_PRIVATE_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"

MIGRATION_DATABASE_URL = os.environ.get("MIGRATION_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not PASSWORD,
    reason="H05 staging tests require STAGING_OIDC_USER_PASSWORD (gitignored infra/staging/.env) "
           "and a running staging stack (nginx 18080, Keycloak 18081, PostgreSQL 15432)",
)

_DISCOVERY_CACHE = {}


def _discovery():
    if not _DISCOVERY_CACHE:
        response = requests.get(f"{ISSUER}/.well-known/openid-configuration", timeout=15)
        assert response.status_code == 200, f"discovery failed: HTTP {response.status_code}"
        _DISCOVERY_CACHE.update(response.json())
    return _DISCOVERY_CACHE


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair():
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _hidden_form_fields(html_text: str) -> dict:
    """Extract every hidden input of the Keycloak login form (execution,
    client_id, tab_id, ...) so the credential POST matches the served form."""
    fields = {}
    for tag in re.findall(r"<input\b[^>]*>", html_text, flags=re.IGNORECASE):
        if 'type="hidden"' not in tag.lower() and "type='hidden'" not in tag.lower():
            continue
        name_match = re.search(r'name="([^"]*)"|name=\'([^\']*)\'', tag)
        value_match = re.search(r'value="([^"]*)"|value=\'([^\']*)\'', tag)
        if name_match:
            name = name_match.group(1) or name_match.group(2)
            value = (value_match.group(1) if value_match else "") or (value_match.group(2) if value_match else "")
            fields[html_module.unescape(name)] = html_module.unescape(value or "")
    return fields


def _walk_redirects(session: requests.Session, response: requests.Response, max_hops: int = 12):
    """Follow 302s manually so the code+state callback URL is captured instead
    of being consumed by nginx serving the SPA."""
    for _ in range(max_hops):
        if response.status_code != 302:
            return response
        location = response.headers["Location"]
        if location.startswith(REDIRECT_URI):
            return location  # the callback itself — stop before nginx
        response = session.get(location, allow_redirects=False, timeout=15)
    pytest.fail("authorization redirect chain did not reach the callback within 12 hops")


@pytest.fixture(scope="module")
def oidc_session():
    """One real browser-equivalent login per module: PKCE Authorization Code
    through the actual Keycloak login form, verified against the live JWKS.
    Returns (access_token, verified_claims)."""
    discovery = _discovery()
    assert discovery["issuer"] == ISSUER
    authorization_endpoint = discovery["authorization_endpoint"]
    token_endpoint = discovery["token_endpoint"]

    state = _b64url(secrets.token_bytes(16))
    nonce = _b64url(secrets.token_bytes(16))
    verifier, challenge = _pkce_pair()

    session = requests.Session()
    first = session.get(
        authorization_endpoint,
        params={
            "client_id": CLIENT_ID,
            "response_type": "code",
            "scope": SCOPE,
            "redirect_uri": REDIRECT_URI,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        allow_redirects=False,
        timeout=15,
    )
    assert first.status_code == 200, f"expected the Keycloak login form, got HTTP {first.status_code}"
    assert "username" in first.text, "login form did not render a username field"

    # Keycloak flags AUTH_SESSION_ID Secure; real browsers honor Secure cookies
    # on the trustworthy loopback origin (http://127.0.0.1 is a secure context),
    # python requests is stricter (RFC 6265 https-only). Relax the flag for this
    # loopback-only session so the non-browser client mirrors browser behavior.
    for cookie in session.cookies:
        cookie.secure = False

    action_match = re.search(r'action="([^"]*)"', first.text)
    assert action_match, "login form has no action"
    action_url = html_module.unescape(action_match.group(1))
    if action_url.startswith("/"):
        action_url = f"{KEYCLOAK_ORIGIN}{action_url}"

    form = _hidden_form_fields(first.text)
    form.update({"username": USERNAME, "password": PASSWORD, "login": "Sign In"})
    posted = session.post(action_url, data=form, allow_redirects=False, timeout=15)

    callback = _walk_redirects(session, posted)
    assert isinstance(callback, str), "login POST never redirected to the callback"
    query = urllib.parse.urlparse(callback).query
    params = urllib.parse.parse_qs(query)
    assert params.get("state", [None])[0] == state, "callback state mismatch (CSRF check)"
    code = params.get("code", [None])[0]
    assert code, "callback carried no authorization code"

    token_response = requests.post(
        token_endpoint,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
        timeout=15,
    )
    assert token_response.status_code == 200, f"token exchange failed: {token_response.text[:200]}"
    token_set = token_response.json()
    access_token = token_set.get("access_token")
    assert access_token, "no access_token in the exchange response"
    assert token_set.get("token_type", "").lower() == "bearer"

    # --- Mirror the engine's verification contract against the LIVE JWKS ------
    discovery_again = _discovery()
    jwks_client = PyJWKClient(discovery_again["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)
    claims = jwt.decode(
        access_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        leeway=60,
        options={"require": ["exp", "iat", "nbf", "sub", "aud", "iss"]},
    )
    assert claims["sub"], "verified token has an empty sub"
    assert claims["institution_id"] == INSTITUTION_ID, (
        f"institution_id claim missing/wrong: {claims.get('institution_id')!r}"
    )
    return access_token, claims


def test_discovery_serves_the_real_provider():
    discovery = _discovery()
    assert discovery["issuer"] == ISSUER
    assert "S256" in discovery.get("code_challenge_methods_supported", []), \
        "PKCE S256 must be advertised"
    jwks = requests.get(discovery["jwks_uri"], timeout=15)
    assert jwks.status_code == 200
    keys = jwks.json()["keys"]
    assert any(k.get("kty") == "RSA" and k.get("alg") == "RS256" and k.get("use") == "sig" for k in keys), \
        "no RSA RS256 signing key published"


def test_full_pkce_login_through_real_provider(oidc_session):
    _, claims = oidc_session
    assert claims["iss"] == ISSUER
    assert AUDIENCE in (claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]])
    assert claims["institution_id"] == INSTITUTION_ID


def test_identity_me_through_nginx_with_the_real_token(oidc_session):
    access_token, claims = oidc_session
    response = requests.get(
        f"{STAGING_ORIGIN}/api/v2/identity/me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    assert response.status_code == 200, f"identity/me failed: {response.text[:200]}"
    identity = response.json()
    assert identity["sub"] == claims["sub"]
    assert identity["issuer"] == ISSUER
    assert identity["institution_id"] == INSTITUTION_ID
    assert identity["role"] == "OPERATOR"
    # On a FRESH staging DB the identity carries NO participant claims before
    # the wallet bind; on a REUSED DB the persisted binding from a previous
    # suite run legitimately resolves for this same (sub, institution). Either
    # way, whenever a participant IS present it must be the operator's wallet.
    if identity["participant_id"] is not None:
        assert identity["wallet_address"].lower() == OPERATOR_WALLET_ADDRESS.lower()
        assert identity["authorization_generation"] >= 1


def test_institutional_posture_no_token_is_401_through_nginx():
    response = requests.get(f"{STAGING_ORIGIN}/api/v2/identity/me", timeout=15)
    assert response.status_code == 401


def test_tampered_token_is_401_not_503(oidc_session):
    """A token whose signature was flipped is an AUTH failure (401) — the
    provider itself is reachable, so it must never surface as 503."""
    access_token, _ = oidc_session
    header, payload, signature = access_token.split(".")
    flipped = bytearray(signature.encode("ascii"))
    flipped[0] = ord("A") if flipped[0] != ord("A") else ord("B")
    tampered = f"{header}.{payload}.{bytes(flipped).decode('ascii')}"
    response = requests.get(
        f"{STAGING_ORIGIN}/api/v2/identity/me",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=15,
    )
    assert response.status_code == 401


def test_wallet_challenge_and_bind_gain_participant_identity(oidc_session):
    from eth_account import Account
    from eth_account.messages import encode_defunct

    access_token, claims = oidc_session
    headers = {"Authorization": f"Bearer {access_token}"}

    challenge_response = requests.post(
        f"{STAGING_ORIGIN}/api/v2/wallet/challenge",
        headers=headers,
        json={"wallet_address": OPERATOR_WALLET_ADDRESS, "chain_id": CHAIN_ID},
        timeout=15,
    )
    assert challenge_response.status_code == 200, f"challenge failed: {challenge_response.text[:300]}"
    challenge = challenge_response.json()
    assert challenge["challenge_id"] and challenge["message"]
    assert OPERATOR_WALLET_ADDRESS in challenge["message"]
    assert f"Chain ID: {CHAIN_ID}" in challenge["message"]

    signature = Account.sign_message(
        encode_defunct(text=challenge["message"]), private_key=OPERATOR_WALLET_PRIVATE_KEY
    ).signature.to_0x_hex()

    verify_response = requests.post(
        f"{STAGING_ORIGIN}/api/v2/wallet/verify",
        headers=headers,
        json={"challenge_id": challenge["challenge_id"], "signature": signature},
        timeout=30,
    )
    assert verify_response.status_code == 200, f"bind failed: {verify_response.text[:300]}"
    binding = verify_response.json()
    assert binding["bound"] is True
    assert binding["wallet_address"].lower() == OPERATOR_WALLET_ADDRESS.lower()
    assert binding["participant_id"].startswith("0x") and len(binding["participant_id"]) == 66
    assert binding["authorization_generation"] >= 1

    me_response = requests.get(f"{STAGING_ORIGIN}/api/v2/identity/me", headers=headers, timeout=15)
    assert me_response.status_code == 200
    identity = me_response.json()
    assert identity["participant_id"] == binding["participant_id"]
    assert identity["authorization_generation"] == binding["authorization_generation"]
    assert identity["wallet_address"].lower() == OPERATOR_WALLET_ADDRESS.lower()


def test_membership_revocation_invalidates_the_same_live_token(oidc_session):
    """R10 through the REAL provider: deactivate the stored membership (operator
    DB duty) and the very next request with the SAME cryptographically valid
    token must get 403 — then restore and get 200 again."""
    if not MIGRATION_DATABASE_URL:
        pytest.skip("MIGRATION_DATABASE_URL not set — revocation test requires the OWNER role URL")

    from sqlalchemy import create_engine, text

    access_token, claims = oidc_session
    headers = {"Authorization": f"Bearer {access_token}"}

    engine = create_engine(MIGRATION_DATABASE_URL, pool_pre_ping=True)
    try:
        def set_membership(active: bool) -> None:
            with engine.begin() as conn:
                # Transaction-local tenant context (FORCE RLS) — same pattern as
                # the RLS suite's owner-role statements.
                conn.execute(
                    text("SELECT set_config('app.current_institution_id', :inst_id, true)"),
                    {"inst_id": INSTITUTION_ID},
                )
                updated = conn.execute(
                    text(
                        "UPDATE memberships SET is_active = :active "
                        "WHERE institution_id = :inst_id AND sub = :sub"
                    ),
                    {"active": active, "inst_id": INSTITUTION_ID, "sub": claims["sub"]},
                ).rowcount
                assert updated == 1, f"membership UPDATE matched {updated} rows"

        set_membership(False)
        try:
            revoked = requests.get(f"{STAGING_ORIGIN}/api/v2/identity/me", headers=headers, timeout=15)
            assert revoked.status_code == 403, (
                f"expected 403 after membership deactivation, got {revoked.status_code}: "
                f"{revoked.text[:200]}"
            )
            assert "membership" in revoked.json().get("detail", "").lower()
        finally:
            set_membership(True)  # leave the staging stack in its working state

        restored = requests.get(f"{STAGING_ORIGIN}/api/v2/identity/me", headers=headers, timeout=15)
        assert restored.status_code == 200, "identity not restored after re-activation"
    finally:
        engine.dispose()
