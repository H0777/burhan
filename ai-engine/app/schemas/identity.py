"""
Identity and Institutional Wallet Binding Schemas (V2).
Enforces strict typing, role enumeration, and SIWE challenge specifications.
"""

from enum import Enum
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator, ConfigDict


class RoleEnum(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    AUDITOR = "AUDITOR"
    OPERATOR = "OPERATOR"
    REGULATOR = "REGULATOR"
    NONE = "NONE"


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sub: str = Field(..., description="Unique OIDC user subject identifier")
    issuer: str = Field(..., description="OIDC Token Issuer URL")
    institution_id: str = Field(..., description="Institutional tenant identifier (e.g. INST-CBI-IQ-01)")
    role: RoleEnum = Field(default=RoleEnum.NONE, description="Assigned institutional RBAC role")
    permissions: List[str] = Field(default_factory=list, description="Explicit RBAC scopes/permissions")
    email: Optional[str] = Field(None, description="Optional user email for audit logs")
    participant_id: Optional[str] = Field(None, description="Opaque 32-byte hex participant ID")
    wallet_address: Optional[str] = Field(None, description="Currently bound active EVM wallet address")
    authorization_generation: Optional[int] = Field(None, description="Authorization generation for vote validation")


class WalletChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    wallet_address: str = Field(..., description="EVM wallet address to bind (0x prefix, 42 chars)")
    chain_id: int = Field(default=31337, description="EVM chain ID where contracts are deployed")

    @field_validator("wallet_address")
    @classmethod
    def validate_evm_address(cls, v: str) -> str:
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError("Invalid EVM wallet address format")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Wallet address must be valid hex")
        return v


class WalletChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(..., description="Unique single-use challenge identifier")
    nonce: str = Field(..., description="Cryptographic alphanumeric nonce")
    message: str = Field(..., description="EIP-4361 compliant sign-in message string")
    expires_at: datetime = Field(..., description="UTC expiration timestamp (5-minute TTL)")


class WalletVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(..., description="Challenge ID returned by challenge endpoint")
    signature: str = Field(..., description="Hex encoded EIP-191 signature (0x-prefixed, 65 bytes)")

    @field_validator("signature")
    @classmethod
    def validate_sig_format(cls, v: str) -> str:
        sig = v.strip()
        if not sig.startswith("0x"):
            sig = f"0x{sig}"
        if len(sig) != 132:  # 0x + 130 hex chars (65 bytes)
            raise ValueError(f"Signature must be 65 bytes (expected 132 chars with 0x prefix, got {len(sig)})")
        try:
            int(sig, 16)
        except ValueError:
            raise ValueError("Signature must be valid hex")
        return sig


class WalletBindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bound: bool = Field(..., description="Whether wallet is bound and authorized")
    wallet_address: str = Field(..., description="EVM address bound to this identity")
    institution_id: str = Field(..., description="Institutional tenant")
    participant_id: str = Field(..., description="Institutional participant identifier")
    role: RoleEnum = Field(..., description="Assigned role")
    authorization_generation: int = Field(..., description="Active authorization generation")

