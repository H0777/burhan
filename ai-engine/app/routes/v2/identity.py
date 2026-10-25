"""
Identity & Institutional Wallet Binding Routes (V2, R10)
Cyber-Forensic Auditing Framework - Specification §7 & T13

R10 semantics:
  - institutional mode NEVER answers without a verified Bearer token (401) and
    NEVER serves the demo identity (the demo dependency is explicit and only
    reachable in demo mode);
  - an unreachable OIDC provider answers 503 — it is never papered over with a
    demo identity or an unverified claim;
  - roles come exclusively from the stored membership (resolve_identity);
  - membership is checked on EVERY request (a membership deactivated after a
    token was issued forbids the very next request with that token);
  - require_on_chain_authorization() verifies generation/role on-chain before
    sensitive writes and answers 503 when the authorization read fails —
    browser-presented claims are never trusted instead.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db
from app.repositories.institution_repository import MembershipResolutionError, resolve_identity
from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletChallengeRequest,
    WalletChallengeResponse,
    WalletVerifyRequest,
    WalletBindingResponse,
)
from app.security.oidc import OIDCProviderError, OIDCVerifier
from app.security.wallet_binding import (
    ChainUnavailableError,
    WalletBindingService,
    get_wallet_service,
    set_wallet_service,  # noqa: F401  (re-exported for tests/routes)
)

router = APIRouter()

# Injectable OIDC verifier hook for tests
_oidc_verifier: Optional[OIDCVerifier] = None


def get_oidc_verifier() -> OIDCVerifier:
    global _oidc_verifier
    if _oidc_verifier is None:
        _oidc_verifier = OIDCVerifier(
            issuer=settings.OIDC_ISSUER,
            audience=settings.OIDC_AUDIENCE,
            jwks_url=settings.OIDC_JWKS_URL if settings.OIDC_JWKS_URL else None,
            algorithms=settings.OIDC_ALGORITHMS,
            clock_skew_seconds=settings.OIDC_CLOCK_SKEW_SECONDS,
        )
    return _oidc_verifier


def set_oidc_verifier(verifier: Optional[OIDCVerifier]) -> None:
    global _oidc_verifier
    _oidc_verifier = verifier


def _demo_identity() -> Identity:
    """The isolated demo identity — reachable ONLY through get_demo_identity in
    demo mode (APP_MODE=demo and OIDC disabled)."""
    return Identity(
        sub="usr-dev-demo",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id=settings.INSTITUTION_ID,
        role=RoleEnum.SUPER_ADMIN,
        permissions=["all"],
        email="developer@demo.local",
        participant_id="0x" + "11" * 32,
        wallet_address="0x" + "22" * 20,
        authorization_generation=1,
    )


async def get_demo_identity() -> Identity:
    """
    Explicit, isolated dependency for the demo identity. Institutional mode
    never wires this in: any missing/invalid token there is a hard 401.
    """
    if settings.APP_MODE.strip().lower() != "demo" or settings.OIDC_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
        )
    return _demo_identity()


async def get_current_identity(
    session: Session = Depends(get_db),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Identity:
    """
    Extracts the Bearer token, verifies it against the OIDC allowlist, and
    resolves the institutional identity from the stored membership + binding.
    Membership is checked on every request.
    """
    if authorization:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header format. Expected 'Bearer <token>'",
            )
        token = parts[1]
        verifier = get_oidc_verifier()
        try:
            claims = verifier.verify_token(token)
        except OIDCProviderError as e:
            # The provider/JWKS is unreachable: this is a service-side failure.
            # NEVER fall back to a demo identity or an unverified claim.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Identity provider unavailable: {e}",
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {e}",
            )

        try:
            return resolve_identity(session, claims)
        except MembershipResolutionError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )

    # No Authorization header: only the isolated demo dependency may answer.
    if settings.APP_MODE.strip().lower() != "demo" or settings.OIDC_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
        )
    return await get_demo_identity()


def require_on_chain_authorization(*allowed_roles: RoleEnum):
    """
    RBAC + on-chain authorization dependency factory for SENSITIVE WRITES
    (consumed by R07/R12 routes): resolves identity AND verifies the wallet's
    generation/role against the on-chain RoleManager.

    - 401/403 from identity resolution and RBAC as usual;
    - 403 when the on-chain participant record contradicts the stored
      binding/membership (rotated, revoked, stale generation);
    - 503 when the authorization (license) read itself fails — never a fallback
      to trusting browser-presented claims.
    """
    def checker(
        identity: Identity = Depends(get_current_identity),
    ) -> Identity:
        if allowed_roles and identity.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{identity.role.value}' not authorized for this resource",
            )
        try:
            get_wallet_service().verify_on_chain_authorization(identity)
        except ChainUnavailableError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"On-chain authorization unavailable: {e}",
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(e),
            )
        return identity

    return checker


def require_roles(*allowed_roles: RoleEnum):
    """
    RBAC dependency factory for route protection (identity resolution still
    checks the active membership on every request).
    """
    def role_checker(identity: Identity = Depends(get_current_identity)) -> Identity:
        if identity.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{identity.role.value}' not authorized for this resource",
            )
        return identity

    return role_checker


@router.get("/identity/me", response_model=Identity, summary="Get current authenticated identity and binding")
async def get_me(identity: Identity = Depends(get_current_identity)):
    """
    Returns the caller's verified institutional identity, RBAC role, and active wallet binding.
    """
    return identity


@router.post("/wallet/challenge", response_model=WalletChallengeResponse, summary="Issue single-use SIWE wallet challenge")
async def issue_wallet_challenge(
    request: WalletChallengeRequest,
    session: Session = Depends(get_db),
    identity: Identity = Depends(get_current_identity),
):
    """
    Issues a single-use EIP-4361 SIWE challenge bound to the user's institution,
    subject, domain and chain, persisted in PostgreSQL.
    """
    try:
        service = get_wallet_service()
        challenge = service.create_challenge(
            session=session,
            identity=identity,
            request=request,
            ttl_seconds=settings.WALLET_CHALLENGE_TTL_SECONDS,
        )
        return challenge
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create wallet challenge: {str(e)}",
        )


@router.post("/wallet/verify", response_model=WalletBindingResponse, summary="Verify SIWE signature and bind EVM wallet")
async def verify_wallet_binding(
    request: WalletVerifyRequest,
    session: Session = Depends(get_db),
    identity: Identity = Depends(get_current_identity),
):
    """
    Verifies an EIP-191 signature over the persisted single-use SIWE challenge
    (atomic compare-and-swap consumption), proves the wallet is an active
    on-chain participant (RoleManager), and establishes or rotates the
    institutional wallet binding with the on-chain authorization generation.
    """
    try:
        service = get_wallet_service()
        binding = service.verify_and_bind(session=session, identity=identity, request=request)
        return binding
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify wallet binding: {str(e)}",
        )
