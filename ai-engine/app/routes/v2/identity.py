"""
Identity & Institutional Wallet Binding Routes (V2)
Cyber-Forensic Auditing Framework - Specification §7 & T13
"""

from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from app.config import settings
from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletChallengeRequest,
    WalletChallengeResponse,
    WalletVerifyRequest,
    WalletBindingResponse,
)
from app.security.oidc import OIDCVerifier
from app.security.wallet_binding import WalletBindingService

router = APIRouter()

# Service singletons / injectable hooks for testing
_oidc_verifier: Optional[OIDCVerifier] = None
_wallet_binding_service: Optional[WalletBindingService] = None


def get_oidc_verifier() -> OIDCVerifier:
    global _oidc_verifier
    if _oidc_verifier is None:
        _oidc_verifier = OIDCVerifier(
            issuer=settings.OIDC_ISSUER,
            audience=settings.OIDC_AUDIENCE,
            jwks_url=settings.OIDC_JWKS_URL if settings.OIDC_JWKS_URL else None,
        )
    return _oidc_verifier


def set_oidc_verifier(verifier: Optional[OIDCVerifier]) -> None:
    global _oidc_verifier
    _oidc_verifier = verifier


def get_wallet_service() -> WalletBindingService:
    global _wallet_binding_service
    if _wallet_binding_service is None:
        _wallet_binding_service = WalletBindingService(
            domain=settings.WALLET_CHALLENGE_DOMAIN,
            default_chain_id=settings.CHAIN_ID,
            ttl_seconds=settings.WALLET_CHALLENGE_TTL_SECONDS,
        )
    return _wallet_binding_service


def set_wallet_service(service: Optional[WalletBindingService]) -> None:
    global _wallet_binding_service
    _wallet_binding_service = service


async def get_current_identity(
    authorization: Optional[str] = Header(None, alias="Authorization")
) -> Identity:
    """
    Extracts Bearer token from Authorization header and verifies institutional identity.
    Falls back to development demo identity only when OIDC_ENABLED is False and no header is provided.
    """
    wallet_svc = get_wallet_service()

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
            identity = verifier.verify_token(token)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: {str(e)}",
            )

        # Enrich with active wallet binding if available
        binding = wallet_svc.get_active_binding(identity.institution_id, identity.sub)
        if binding:
            identity.wallet_address = binding.wallet_address
            identity.authorization_generation = binding.authorization_generation
            identity.participant_id = binding.participant_id
            identity.role = binding.role

        return identity

    # If no Authorization header is provided:
    if settings.OIDC_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
        )

    # Demo fallback mode for local development/testing when OIDC is disabled
    demo_identity = Identity(
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
    binding = wallet_svc.get_active_binding(demo_identity.institution_id, demo_identity.sub)
    if binding:
        demo_identity.wallet_address = binding.wallet_address
        demo_identity.authorization_generation = binding.authorization_generation
        demo_identity.participant_id = binding.participant_id
        demo_identity.role = binding.role

    return demo_identity


def require_roles(*allowed_roles: RoleEnum):
    """
    RBAC dependency factory for route protection.
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
    identity: Identity = Depends(get_current_identity),
):
    """
    Issues a single-use EIP-4361 SIWE challenge bound to the user's institution and subject.
    """
    try:
        service = get_wallet_service()
        challenge = service.create_challenge(
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
    identity: Identity = Depends(get_current_identity),
):
    """
    Verifies an EIP-191 signature over the SIWE challenge and establishes or updates
    institutional wallet binding with an incremented authorization generation.
    """
    try:
        service = get_wallet_service()
        binding = service.verify_and_bind(identity=identity, request=request)
        return binding
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify wallet binding: {str(e)}",
        )
