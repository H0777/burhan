"""
Institutional Wallet Binding and SIWE Verification Service (V2).
Implements single-use challenge issuance, EIP-191/SIWE signature verification,
tenant isolation, and authorization generation increments.
"""

import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
from eth_account import Account
from eth_account.messages import encode_defunct

from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletChallengeRequest,
    WalletChallengeResponse,
    WalletVerifyRequest,
    WalletBindingResponse,
)


class ChallengeRecord:
    def __init__(
        self,
        challenge_id: str,
        institution_id: str,
        sub: str,
        wallet_address: str,
        chain_id: int,
        nonce: str,
        message: str,
        expires_at: datetime,
    ):
        self.challenge_id = challenge_id
        self.institution_id = institution_id
        self.sub = sub
        self.wallet_address = wallet_address.lower()
        self.chain_id = chain_id
        self.nonce = nonce
        self.message = message
        self.expires_at = expires_at
        self.used = False


class BindingRecord:
    def __init__(
        self,
        institution_id: str,
        sub: str,
        wallet_address: str,
        participant_id: str,
        role: RoleEnum,
        authorization_generation: int,
        bound_at: datetime,
    ):
        self.institution_id = institution_id
        self.sub = sub
        self.wallet_address = wallet_address.lower()
        self.participant_id = participant_id
        self.role = role
        self.authorization_generation = authorization_generation
        self.bound_at = bound_at


class InMemoryWalletBindingRepo:
    """
    Initial in-memory fixture repository interface for T13.
    Replaced by PostgreSQL persistent repository in T14.
    """
    def __init__(self):
        self.challenges: Dict[str, ChallengeRecord] = {}
        # key: (institution_id, sub) -> BindingRecord
        self.bindings: Dict[tuple, BindingRecord] = {}

    def save_challenge(self, record: ChallengeRecord) -> None:
        self.challenges[record.challenge_id] = record

    def get_challenge(self, challenge_id: str) -> Optional[ChallengeRecord]:
        return self.challenges.get(challenge_id)

    def mark_challenge_used(self, challenge_id: str) -> None:
        if challenge_id in self.challenges:
            self.challenges[challenge_id].used = True

    def save_binding(self, record: BindingRecord) -> None:
        key = (record.institution_id.lower(), record.sub)
        self.bindings[key] = record

    def get_binding(self, institution_id: str, sub: str) -> Optional[BindingRecord]:
        key = (institution_id.lower(), sub)
        return self.bindings.get(key)


class WalletBindingService:
    def __init__(
        self,
        repository: Optional[InMemoryWalletBindingRepo] = None,
        domain: str = "iraq-aml-audit.cbi.iq",
        default_chain_id: int = 31337,
        ttl_seconds: int = 300,
    ):
        self.repo = repository or InMemoryWalletBindingRepo()
        self.domain = domain
        self.default_chain_id = default_chain_id
        self.ttl_seconds = ttl_seconds

    def create_challenge(
        self,
        identity: Identity,
        request: WalletChallengeRequest,
        ttl_seconds: Optional[int] = None,
    ) -> WalletChallengeResponse:
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl)
        challenge_id = str(uuid.uuid4())
        nonce = secrets.token_hex(16)
        chain_id = request.chain_id or self.default_chain_id

        # Standard EIP-4361 / SIWE Message structure
        message = (
            f"{self.domain} wants you to sign in with your Ethereum account:\n"
            f"{request.wallet_address}\n\n"
            f"Sign-in challenge for Iraq AML Forensics Chain.\n"
            f"Institution: {identity.institution_id}\n"
            f"User Sub: {identity.sub}\n\n"
            f"URI: https://{self.domain}\n"
            f"Version: 1\n"
            f"Chain ID: {chain_id}\n"
            f"Nonce: {nonce}\n"
            f"Issued At: {now.isoformat()}\n"
            f"Expiration Time: {expires_at.isoformat()}"
        )

        record = ChallengeRecord(
            challenge_id=challenge_id,
            institution_id=identity.institution_id,
            sub=identity.sub,
            wallet_address=request.wallet_address,
            chain_id=chain_id,
            nonce=nonce,
            message=message,
            expires_at=expires_at,
        )
        self.repo.save_challenge(record)

        return WalletChallengeResponse(
            challenge_id=challenge_id,
            nonce=nonce,
            message=message,
            expires_at=expires_at,
        )

    def verify_and_bind(
        self,
        identity: Identity,
        request: WalletVerifyRequest,
    ) -> WalletBindingResponse:
        record = self.repo.get_challenge(request.challenge_id)
        now = datetime.now(timezone.utc)

        if not record or record.used or now > record.expires_at:
            raise ValueError("Challenge already used or expired")

        # Review Focus 1: Strict Tenant Isolation
        if record.institution_id.lower() != identity.institution_id.lower():
            raise ValueError(
                f"Tenant mismatch: challenge was issued for institution '{record.institution_id}', "
                f"caller belongs to '{identity.institution_id}'"
            )

        if record.sub != identity.sub:
            raise ValueError("Identity mismatch: challenge was issued for another subject")

        # Recover Ethereum Address from Signature
        try:
            signable_msg = encode_defunct(text=record.message)
            recovered_address = Account.recover_message(signable_msg, signature=request.signature)
        except Exception as e:
            raise ValueError(f"Invalid signature encoding: {str(e)}")

        if recovered_address.lower() != record.wallet_address.lower():
            raise ValueError(
                f"Signer address mismatch: signature produced by '{recovered_address}', "
                f"expected '{record.wallet_address}'"
            )

        # Mark challenge as spent (Single-Use enforcement)
        self.repo.mark_challenge_used(record.challenge_id)

        # Review Focus 2: Authorization Generation Tracking
        existing_binding = self.repo.get_binding(identity.institution_id, identity.sub)
        if existing_binding:
            new_generation = existing_binding.authorization_generation + 1
        else:
            new_generation = 1

        # Derive institutional participant ID (keccak256 or sha256 formatted hex)
        import hashlib
        participant_id = (
            identity.participant_id
            or "0x" + hashlib.sha256(f"{identity.institution_id}:{identity.sub}".encode()).hexdigest()
        )

        binding = BindingRecord(
            institution_id=identity.institution_id,
            sub=identity.sub,
            wallet_address=record.wallet_address,
            participant_id=participant_id,
            role=identity.role,
            authorization_generation=new_generation,
            bound_at=now,
        )
        self.repo.save_binding(binding)

        return WalletBindingResponse(
            bound=True,
            wallet_address=binding.wallet_address,
            institution_id=binding.institution_id,
            participant_id=binding.participant_id,
            role=binding.role,
            authorization_generation=binding.authorization_generation,
        )

    def get_active_binding(self, institution_id: str, sub: str) -> Optional[BindingRecord]:
        return self.repo.get_binding(institution_id, sub)
