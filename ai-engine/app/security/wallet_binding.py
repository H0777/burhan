"""
Institutional Wallet Binding and SIWE Verification Service (V2, R10).

Implements single-use challenge issuance, EIP-191/SIWE signature verification,
tenant isolation, and authorization generation tracking, backed by the
persistent PostgreSQL repository (app.repositories.wallet_binding_repository):

  - challenges are DATABASE rows (they survive process restarts);
  - consumption is an atomic compare-and-swap (two sessions, one winner);
  - every challenge is bound to its user (sub), institution, SIWE domain and
    chain id, and is rejected when consumed under anything else;
  - all LOCAL proofs (tenant, subject, domain, chain, signature) are verified
    BEFORE the single on-chain RoleManager read — a wallet that fails any local
    proof never triggers a chain read;
  - on-chain proof: getParticipant(wallet) must be an ACTIVE participant whose
    participantId matches the membership's binding; a rotated (retired) wallet
    is rejected against the on-chain generation;
  - roles never come from here — the caller passes the membership-resolved
    identity, and the on-chain role must agree with it.

Error classes for the HTTP layer:
  - ValueError               -> rejected request (400/403 upstream)
  - ChainUnavailableError    -> the on-chain authorization read failed (503);
                                browser/JWT claims are NEVER trusted instead.
"""

import hashlib
import secrets
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_session_factory, tenant_transaction
from app.repositories.wallet_binding_repository import (
    BindingRecord,
    ChallengeRecord,  # noqa: F401  (re-exported for compatibility)
    WalletBindingRepository,
)
from app.schemas.identity import (
    Identity,
    RoleEnum,
    WalletBindingResponse,
    WalletChallengeRequest,
    WalletChallengeResponse,
    WalletVerifyRequest,
)

__all__ = [
    "BindingRecord",
    "ChallengeRecord",
    "ChainUnavailableError",
    "InMemoryWalletBindingRepo",
    "ParticipantOnChain",
    "RoleManagerChainReader",
    "WalletBindingService",
    "get_wallet_service",
    "set_wallet_service",
]


class ChainUnavailableError(Exception):
    """The on-chain authorization (license) read failed — never fall back to
    trusting browser-presented claims."""


class ParticipantOnChain:
    """Result of one RoleManager.getParticipant(wallet) read (R02 tuple)."""

    def __init__(self, participant_id: str, generation: int, role: str, active: bool):
        self.participant_id = participant_id
        self.generation = generation
        self.role = role
        self.active = active


def _institutional_mode() -> bool:
    return getattr(settings, "APP_MODE", "demo") == "institutional"


def _default_json_rpc_post(rpc_url: str, method: str, params: list):
    import requests

    response = requests.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=10,
    )
    response.raise_for_status()
    body = response.json()
    if body.get("error"):
        raise ChainUnavailableError(f"RPC error: {body['error']}")
    return body.get("result")


class RoleManagerChainReader:
    """
    Reads getParticipant(address) -> (bytes32 participantId, uint256 generation,
    Role role, bool active) from the R02 RoleManager contract via eth_call.
    The transport is injectable so tests can stub the RPC without a chain.
    """

    ROLE_BY_ID = {
        0: RoleEnum.NONE,
        1: RoleEnum.SUPER_ADMIN,
        2: RoleEnum.AUDITOR,
        3: RoleEnum.OPERATOR,
        4: RoleEnum.REGULATOR,
    }

    def __init__(self, rpc_url: str, contract_address: str, transport=None):
        if not contract_address:
            raise ValueError("RoleManagerChainReader requires the RoleManager contract address")
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self._transport = transport or _default_json_rpc_post

    def _call_get_participant(self, wallet_address: str) -> str:
        from eth_utils import keccak

        selector = keccak(b"getParticipant(address)")[:4].hex()
        addr_hex = wallet_address.lower().replace("0x", "").rjust(64, "0")
        data = "0x" + selector + addr_hex
        return self._transport(
            self.rpc_url,
            "eth_call",
            [{"to": self.contract_address, "data": data}, "latest"],
        )

    def get_participant(self, wallet_address: str) -> Optional[ParticipantOnChain]:
        result_hex = self._call_get_participant(wallet_address)
        if not result_hex or result_hex in ("0x", "0x0"):
            return None
        raw = result_hex[2:]
        if len(raw) < 256:
            raise ChainUnavailableError("Malformed getParticipant ABI payload from RoleManager")
        words = [raw[i * 64:(i + 1) * 64] for i in range(4)]
        participant_id = "0x" + words[0]
        generation = int(words[1], 16)
        role_id = int(words[2], 16)
        active = int(words[3], 16) == 1
        return ParticipantOnChain(
            participant_id=participant_id,
            generation=generation,
            role=self.ROLE_BY_ID.get(role_id, RoleEnum.NONE).value,
            active=active,
        )


class InMemoryWalletBindingRepo:
    """
    Session-free repository double for UNIT tests only (the institutional path
    uses WalletBindingRepository against PostgreSQL — see
    tests/integration/test_identity_persistence.py).
    """

    requires_session = False

    def __init__(self):
        self.challenges = {}
        self.bindings = {}

    def save_challenge(self, session, record: ChallengeRecord) -> None:
        self.challenges[record.challenge_id] = record

    def get_challenge(self, session, challenge_id: str) -> Optional[ChallengeRecord]:
        return self.challenges.get(challenge_id)

    def consume_challenge(self, session, challenge_id: str, institution_id: str, sub: str, now: datetime) -> ChallengeRecord:
        record = self.challenges.get(challenge_id)
        if (
            record is None
            or record.used
            or record.expires_at <= now
            or record.institution_id.lower() != institution_id.lower()
            or record.sub != sub
        ):
            raise ValueError("Challenge already used or expired")
        record.consumed_at = now
        return record

    def save_binding(self, session, record: BindingRecord) -> BindingRecord:
        self.bindings[(record.institution_id.lower(), record.sub)] = record
        return record

    def get_binding(self, session, institution_id: str, sub: str) -> Optional[BindingRecord]:
        return self.bindings.get((institution_id.lower(), sub))

    def wallet_bound_elsewhere(self, session, wallet_address: str, institution_id: str, sub: str) -> bool:
        target = wallet_address.lower()
        for (inst, s), record in self.bindings.items():
            if record.wallet_address.lower() == target and (inst != institution_id.lower() or s != sub):
                return True
        return False


def _build_default_chain_reader() -> Optional[RoleManagerChainReader]:
    address = getattr(settings, "ROLE_MANAGER_ADDRESS", "")
    if not address:
        return None
    return RoleManagerChainReader(rpc_url=settings.BLOCKCHAIN_RPC_URL, contract_address=address)


class WalletBindingService:
    def __init__(
        self,
        repository: Optional[WalletBindingRepository] = None,
        domain: str = "iraq-aml-audit.cbi.iq",
        default_chain_id: int = 31337,
        ttl_seconds: int = 300,
        chain_reader: Optional[RoleManagerChainReader] = None,
        session_factory=None,
    ):
        self.repo = repository if repository is not None else WalletBindingRepository(session_factory=session_factory)
        self.session_factory = session_factory
        self.domain = domain
        self.default_chain_id = default_chain_id
        self.ttl_seconds = ttl_seconds
        self.chain_reader = chain_reader

    # ------------------------------------------------------------------
    # Session / transaction plumbing
    # ------------------------------------------------------------------

    @contextmanager
    def _tenant_session(self, session: Optional[Session], institution_id: str):
        """Yield a session inside the transaction-local tenant context.

        The caller's request session is used when provided; otherwise a short
        session is opened from the configured factory. tenant_transaction sets
        set_config('app.current_institution_id', ..., true) on PostgreSQL
        (RLS-bound) and commits/rolls back the whole unit of work.
        """
        if not self.repo.requires_session:
            yield None
            return
        if session is not None:
            with tenant_transaction(session, institution_id):
                yield session
        else:
            factory = self.session_factory or get_session_factory()
            with factory() as owned:
                with tenant_transaction(owned, institution_id):
                    yield owned

    def _fetch_active_binding(self, session, institution_id: str, sub: str) -> Optional[BindingRecord]:
        with self._tenant_session(session, institution_id) as tx:
            return self.repo.get_binding(tx, institution_id, sub)

    # ------------------------------------------------------------------
    # Challenge issuance
    # ------------------------------------------------------------------

    def create_challenge(
        self,
        session: Optional[Session],
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

        # Standard EIP-4361 / SIWE Message structure — bound to the domain and
        # chain; the exact message text is what the wallet signature commits to.
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
            domain=self.domain,
            nonce=nonce,
            message=message,
            issued_at=now,
            expires_at=expires_at,
        )
        with self._tenant_session(session, identity.institution_id) as tx:
            self.repo.save_challenge(tx, record)

        return WalletChallengeResponse(
            challenge_id=challenge_id,
            nonce=nonce,
            message=message,
            expires_at=expires_at,
        )

    # ------------------------------------------------------------------
    # Verification and binding
    # ------------------------------------------------------------------

    def _check_challenge_binding(self, record: ChallengeRecord, identity: Identity) -> None:
        """All LOCAL (database/config) proofs, in fail-closed order. Runs BEFORE
        the compare-and-swap and long before any chain read."""
        if record.institution_id.lower() != identity.institution_id.lower():
            raise ValueError(
                f"Tenant mismatch: challenge was issued for institution '{record.institution_id}', "
                f"caller belongs to '{identity.institution_id}'"
            )
        if record.sub != identity.sub:
            raise ValueError("Identity mismatch: challenge was issued for another subject")
        if self.domain and record.domain and record.domain != self.domain:
            raise ValueError(
                f"Challenge was issued for domain '{record.domain}', not this service domain '{self.domain}'"
            )
        if record.chain_id != self.default_chain_id:
            raise ValueError(
                f"Challenge was issued for chain id {record.chain_id}, not {self.default_chain_id}"
            )

    def _resolve_on_chain(
        self,
        record: ChallengeRecord,
        identity: Identity,
        existing: Optional[BindingRecord],
    ):
        """The single on-chain RoleManager read — only ever reached after every
        local proof passed. Returns (participant_id, generation)."""
        if self.chain_reader is None:
            if _institutional_mode():
                raise ChainUnavailableError(
                    "RoleManager on-chain reader is not configured; institutional mode "
                    "refuses to bind wallets without an on-chain participant proof"
                )
            # Dev/demo only: no chain configured, derived id and incrementing generation.
            participant_id = (
                identity.participant_id
                or "0x" + hashlib.sha256(f"{identity.institution_id}:{identity.sub}".encode()).hexdigest()
            )
            generation = (existing.authorization_generation + 1) if existing else 1
            return participant_id, generation

        try:
            on_chain = self.chain_reader.get_participant(record.wallet_address)
        except ChainUnavailableError:
            raise
        except Exception as exc:
            raise ChainUnavailableError(f"RoleManager read failed: {exc}") from exc

        if (
            on_chain is None
            or not on_chain.active
            or not on_chain.participant_id
            or on_chain.participant_id in ("0x0", "0x" + "0" * 64)
        ):
            raise ValueError(
                "Wallet is not an active participant on-chain (unknown, rotated, or revoked)"
            )
        participant_id = on_chain.participant_id.lower()
        if existing and existing.participant_id and participant_id != existing.participant_id.lower():
            raise ValueError(
                "Wallet is bound to a different institutional participant identity on-chain"
            )
        chain_role = RoleEnum(str(on_chain.role))
        if chain_role == RoleEnum.NONE:
            raise ValueError(
                "Wallet is not an active participant on-chain (unknown, rotated, or revoked)"
            )
        if identity.role not in (RoleEnum.NONE, chain_role):
            raise ValueError(
                f"On-chain role {chain_role.value} does not match the institutional "
                f"membership role {identity.role.value}"
            )
        return participant_id, int(on_chain.generation)

    def verify_and_bind(
        self,
        session: Optional[Session],
        identity: Identity,
        request: WalletVerifyRequest,
    ) -> WalletBindingResponse:
        now = datetime.now(timezone.utc)

        # --- Transaction 1: local proofs + atomic compare-and-swap consumption.
        # The CAS commits BEFORE signature verification, so a failed proof burns
        # the challenge (fail-closed against signature brute-force).
        with self._tenant_session(session, identity.institution_id) as tx:
            record = self.repo.get_challenge(tx, request.challenge_id)
            if not record:
                raise ValueError("Challenge already used or expired")
            self._check_challenge_binding(record, identity)
            self.repo.consume_challenge(
                tx, record.challenge_id, identity.institution_id, identity.sub, now
            )

        # --- Local signature proof (no DB, no chain).
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

        # --- On-chain participant proof (exactly one read, strictly last).
        existing = self._fetch_active_binding(session, identity.institution_id, identity.sub)
        participant_id, generation = self._resolve_on_chain(record, identity, existing)

        # --- Transaction 2: persist the (single) active binding.
        binding_record = BindingRecord(
            institution_id=identity.institution_id,
            sub=identity.sub,
            wallet_address=record.wallet_address,
            participant_id=participant_id,
            role=identity.role,
            authorization_generation=generation,
            bound_at=now,
        )
        with self._tenant_session(session, identity.institution_id) as tx:
            if self.repo.wallet_bound_elsewhere(tx, record.wallet_address, identity.institution_id, identity.sub):
                raise ValueError(
                    "Wallet already bound to another institutional identity (rotation is governance-only)"
                )
            binding = self.repo.save_binding(tx, binding_record)

        return WalletBindingResponse(
            bound=True,
            wallet_address=binding.wallet_address,
            institution_id=binding.institution_id,
            participant_id=binding.participant_id,
            role=binding.role,
            authorization_generation=binding.authorization_generation,
        )

    # ------------------------------------------------------------------
    # Read-time helpers
    # ------------------------------------------------------------------

    def get_active_binding(self, institution_id: str, sub: str) -> Optional[BindingRecord]:
        """The stored active wallet binding for a membership (interface fixed by
        the R10 brief). Opens its own short tenant session when necessary."""
        return self._fetch_active_binding(None, institution_id, sub)

    def verify_on_chain_authorization(self, identity: Identity) -> ParticipantOnChain:
        """
        Pre-write authorization: verify generation/role on-chain before
        sensitive writes. Raises ChainUnavailableError (-> 503) when the
        authorization read fails and ValueError (-> 403) on any mismatch.
        Browser-presented claims are never trusted instead of this check.
        """
        binding = self.get_active_binding(identity.institution_id, identity.sub)
        if binding is None:
            raise ValueError("No active wallet binding for this identity")
        if self.chain_reader is None:
            raise ChainUnavailableError(
                "RoleManager on-chain reader is not configured; refusing to authorize "
                "sensitive writes from browser-presented claims"
            )
        try:
            on_chain = self.chain_reader.get_participant(binding.wallet_address)
        except ChainUnavailableError:
            raise
        except Exception as exc:
            raise ChainUnavailableError(f"RoleManager read failed: {exc}") from exc

        if (
            on_chain is None
            or not on_chain.active
            or not on_chain.participant_id
            or on_chain.participant_id.lower() != binding.participant_id.lower()
        ):
            raise ValueError(
                "On-chain participant record does not match the stored binding "
                "(rotated, revoked, or unknown wallet)"
            )
        if int(on_chain.generation) != int(binding.authorization_generation):
            raise ValueError(
                "On-chain authorization generation is stale: the participant was rotated "
                f"(on-chain {on_chain.generation}, stored {binding.authorization_generation})"
            )
        chain_role = RoleEnum(str(on_chain.role))
        if identity.role not in (RoleEnum.NONE, chain_role):
            raise ValueError(
                f"On-chain role {chain_role.value} does not match the institutional "
                f"membership role {identity.role.value}"
            )
        return on_chain


# ---------------------------------------------------------------------------
# Service singleton (used by the routes; injectable for tests)
# ---------------------------------------------------------------------------

_wallet_binding_service: Optional[WalletBindingService] = None


def get_wallet_service() -> WalletBindingService:
    global _wallet_binding_service
    if _wallet_binding_service is None:
        _wallet_binding_service = WalletBindingService(
            domain=settings.WALLET_CHALLENGE_DOMAIN,
            default_chain_id=settings.CHAIN_ID,
            ttl_seconds=settings.WALLET_CHALLENGE_TTL_SECONDS,
            chain_reader=_build_default_chain_reader(),
        )
    return _wallet_binding_service


def set_wallet_service(service: Optional[WalletBindingService]) -> None:
    global _wallet_binding_service
    _wallet_binding_service = service
