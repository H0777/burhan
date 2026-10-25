"""
OIDC Token Verification Service (R10).

Verifies signature, issuer, audience, and the MANDATORY claim set (exp, iat,
nbf, sub — plus aud via audience verification) against an allowlist of
algorithms, with a 60 second clock skew. The verifier returns VERIFIED CLAIMS
ONLY: it derives no role and no institutional identity. Roles come exclusively
from the stored membership (resolve_identity), never from a JWT role claim.

Failures are separated into two classes for the HTTP layer:
  - ValueError           -> the token itself is invalid (401)
  - OIDCProviderError    -> the identity provider / JWKS is unavailable (503)
"""

import time
from typing import Any, Dict, List, Optional
import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidTokenError,
    PyJWKClient,
    PyJWKClientError,
)

MANDATORY_CLAIMS = ("exp", "iat", "nbf", "sub")

# Algorithm allowlist default: asymmetric RS256 only. Nothing symmetric or
# "none" is ever accepted unless explicitly allowlisted by configuration.
DEFAULT_ALGORITHMS = ["RS256"]
DEFAULT_CLOCK_SKEW_SECONDS = 60


class OIDCProviderError(Exception):
    """The identity provider (JWKS endpoint) could not be reached or decoded."""


class MockJWKSProvider:
    """
    Test fixture representing an institutional Identity Provider (IdP) with RSA
    keys. SYNTHETIC KEYS ONLY — generated per test run, never deployed secrets.
    """
    def __init__(
        self,
        issuer: str,
        audience: str,
        private_key_pem: bytes,
        public_key_pem: bytes,
        key_id: str = "default-key",
    ):
        self.issuer = issuer
        self.audience = audience
        self.private_key_pem = private_key_pem
        self.public_key_pem = public_key_pem
        self.key_id = key_id

    def create_signed_token(
        self,
        claims: Dict[str, Any],
        expires_in_seconds: int = 3600,
        override_issuer: Optional[str] = None,
        override_audience: Optional[str] = None,
    ) -> str:
        now = int(time.time())
        payload = {
            "iss": override_issuer if override_issuer is not None else self.issuer,
            "aud": override_audience if override_audience is not None else self.audience,
            "iat": now,
            "nbf": now - 5,
            "exp": now + expires_in_seconds,
            **claims,
        }
        headers = {"kid": self.key_id, "alg": "RS256"}
        return jwt.encode(payload, self.private_key_pem, algorithm="RS256", headers=headers)

    def get_public_key(self, kid: Optional[str] = None) -> bytes:
        return self.public_key_pem


class OIDCVerifier:
    """
    Validates JWT tokens against an OIDC Issuer and returns the verified claims.

    - algorithms: allowlist (default ["RS256"]); a token with any other alg is
      rejected before any verification (prevents alg-confusion).
    - clock_skew_seconds: leeway applied to exp/nbf/iat (default 60s per spec).
    - exp/iat/nbf/sub are mandatory; aud is mandatory when audience checking is
      configured (it always is: audience comes from settings).
    """
    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        jwks_url: Optional[str] = None,
        jwks_provider: Optional[MockJWKSProvider] = None,
        algorithms: Optional[List[str]] = None,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ):
        self.jwks_provider = jwks_provider
        self.issuer = issuer or (jwks_provider.issuer if jwks_provider else None)
        self.audience = audience or (jwks_provider.audience if jwks_provider else None)
        self.algorithms = list(algorithms) if algorithms else list(DEFAULT_ALGORITHMS)
        self.clock_skew_seconds = clock_skew_seconds
        self.jwks_client = PyJWKClient(jwks_url) if jwks_url else None

    def _signing_key(self, token: str):
        try:
            if self.jwks_provider:
                return self.jwks_provider.get_public_key()
            if self.jwks_client:
                return self.jwks_client.get_signing_key_from_jwt(token).key
        except PyJWKClientError as exc:
            raise OIDCProviderError(f"Identity provider unreachable: {exc}") from exc
        except jwt.PyJWKError as exc:
            raise OIDCProviderError(f"Identity provider key error: {exc}") from exc
        raise ValueError("No JWKS provider or JWKS URL configured")

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify signature, issuer, audience, mandatory claims and expiration.
        Returns the verified claim set (dict). Raises ValueError for invalid
        tokens and OIDCProviderError when the provider is unavailable.
        """
        # 0. Algorithm allowlist is checked on the unverified header FIRST so a
        #    hostile `alg` never reaches key selection or verification.
        try:
            header = jwt.get_unverified_header(token)
        except InvalidTokenError as exc:
            raise ValueError(f"Invalid token header: {exc}") from exc
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise ValueError(f"Token algorithm {alg!r} is not allowlisted")

        # 1. Retrieve signing key (provider fixture or live JWKS client).
        signing_key = self._signing_key(token)

        # 2. Decode and verify signature + registered claims.
        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.clock_skew_seconds,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "iat", "nbf", "sub", "aud", "iss"],
                },
            )
        except ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidIssuerError:
            raise ValueError("Invalid token issuer")
        except jwt.InvalidAudienceError:
            raise ValueError("Invalid token audience")
        except jwt.MissingRequiredClaimError as exc:
            raise ValueError(f"Token missing required claim: {exc.claim}")
        except InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")

        # 3. Defence in depth: mandatory claims must be present and non-empty
        #    (require would already have caught absence; this also catches
        #    empty-string subs and guarantees the invariant regardless of the
        #    PyJWT version in use).
        for claim in MANDATORY_CLAIMS:
            value = payload.get(claim)
            if value is None or (isinstance(value, str) and not value.strip()):
                raise ValueError(f"Token missing required claim '{claim}'")

        return payload
