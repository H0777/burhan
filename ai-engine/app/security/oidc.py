"""
OIDC Token Verification Service.
Decodes, validates signatures against JWKS, and extracts institutional identity.
"""

import time
from typing import Dict, Any, Optional
import jwt
from jwt import PyJWKClient, InvalidTokenError, ExpiredSignatureError

from app.schemas.identity import Identity, RoleEnum


class MockJWKSProvider:
    """
    Test helper representing an institutional Identity Provider (IdP) with RSA keys.
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
    Validates JWT tokens against an OIDC Issuer.
    Uses standard PyJWT verification (signature, exp, nbf, iss, aud).
    """
    def __init__(
        self,
        issuer: Optional[str] = None,
        audience: Optional[str] = None,
        jwks_url: Optional[str] = None,
        jwks_provider: Optional[MockJWKSProvider] = None,
    ):
        self.jwks_provider = jwks_provider
        self.issuer = issuer or (jwks_provider.issuer if jwks_provider else None)
        self.audience = audience or (jwks_provider.audience if jwks_provider else None)
        self.jwks_client = PyJWKClient(jwks_url) if jwks_url else None

    def verify_token(self, token: str) -> Identity:
        """
        Verify signature, issuer, audience, and expiration.
        Returns Identity object.
        """
        try:
            # 1. Retrieve signing key
            if self.jwks_provider:
                signing_key = self.jwks_provider.get_public_key()
            elif self.jwks_client:
                signing_key = self.jwks_client.get_signing_key_from_jwt(token).key
            else:
                raise ValueError("No JWKS provider or JWKS URL configured")

            # 2. Decode and verify standard claims
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidIssuerError:
            raise ValueError("Invalid token issuer")
        except jwt.InvalidAudienceError:
            raise ValueError("Invalid token audience")
        except InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")

        # 3. Extract and map identity claims
        sub = payload.get("sub")
        if not sub:
            raise ValueError("Token missing 'sub' claim")

        institution_id = payload.get("institution_id")
        if not institution_id:
            raise ValueError("Token missing 'institution_id' claim")

        raw_role = payload.get("role", "NONE").upper()
        try:
            role = RoleEnum(raw_role)
        except ValueError:
            role = RoleEnum.NONE

        permissions = payload.get("permissions", [])
        email = payload.get("email")

        return Identity(
            sub=str(sub),
            issuer=str(payload.get("iss", self.issuer)),
            institution_id=str(institution_id),
            role=role,
            permissions=[str(p) for p in permissions] if isinstance(permissions, list) else [],
            email=str(email) if email else None,
            participant_id=payload.get("participant_id"),
            wallet_address=payload.get("wallet_address"),
            authorization_generation=payload.get("authorization_generation"),
        )
