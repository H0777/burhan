"""
R08 Chain Sender — raw-transaction persistence, nonce discipline, crash-safe
broadcast and reconciliation (spec §7).

Design rules (binding):
  * The signed raw transaction, its tx_hash AND its nonce are persisted in
    chain_submissions and COMMITTED before any broadcast. After a crash the
    worker re-broadcasts the SAME transaction (same nonce, same hash) —
    never a replacement.
  * Nonce allocation is serialized across all workers by a PostgreSQL
    advisory lock keyed per (chain_id, signer_address). The signer address
    is exclusive to the anchoring service.
  * No automatic replacement of a stuck transaction: after 300 seconds
    without a receipt the sender RAISES an alert, marks the submission
    stuck, and PAUSES new sends for that signer — reconciliation continues
    without changing the payload.
  * External nonce consumption (chain pending nonce beyond our persisted
    allocation) pauses the signer for new sends.
  * The private key is provided via credentials (env var or key file) at
    construction, held in memory only, and is NEVER written to the database
    or logs. Only the derived signer address is persisted.

RPC access goes through an "adapter" object (send side). The send-side
adapters live in app/services/evm_rpc_client.py (class JsonRpcSendAdapter)
and the test suite's SimulatedEvmAdapter. R07 owns the verification read
service (anchor reader) in ITS worktree; this module only uses the three
idempotency reads the anchor pipeline itself needs (get_manifest_digest,
get_evidence_by_request_id, get_incident_by_case_reference), which are part
of the send-path idempotency contract (spec §7 "getEvidenceByRequestId
مرجع منع التكرار"), not of evidence verification.

Timing (backoffs, 300s stuck threshold) always flows from an injected clock
— no real sleeps anywhere in this module.
"""

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Dict, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.db.models import ChainSubmission
from app.repositories.outbox_repository import _aware

logger = logging.getLogger("chain_sender")

# Submission lifecycle states (chain_submissions.status)
SIGNED = "SIGNED"                    # raw tx persisted, not yet broadcast
BROADCAST = "BROADCAST"              # sent, no receipt yet
CONFIRMED = "CONFIRMED"              # receipt ok, depth satisfied, block verified
RECEIPT_STATUS_ZERO = "RECEIPT_STATUS_ZERO"
REORGED = "REORGED"

# reconcile() outcomes
class SubmissionState:
    CONFIRMING = "CONFIRMING"          # mined but below confirmation depth
    PENDING = "PENDING"                # not mined yet
    STUCK = "STUCK"                    # > 300s without receipt: alerted, signer paused
    CONFIRMED = CONFIRMED
    RECEIPT_STATUS_ZERO = RECEIPT_STATUS_ZERO
    REORGED = REORGED

STUCK_AFTER_SECONDS = 300  # spec §7: after 300s -> alert + stop new sends


class ChainSenderError(Exception):
    pass


class PayloadConflictError(ChainSenderError):
    """Same (institution, request_id, submission_kind) already persisted with
    a DIFFERENT payload — the request is contradictory and goes DEAD."""


class NonceConsumedExternallyError(ChainSenderError):
    """The chain's pending nonce moved beyond our persisted allocation:
    someone else consumed the signer's nonce. The signer pauses."""


class SignerPausedError(ChainSenderError):
    """New sends refused for this signer (stuck > 300s or external nonce use).
    Reconciliation continues; resuming is an operator action."""


def keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak as _keccak

    k = _keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode("utf-8")).hex()[:8]


def encode_call(signature: str, types: list, args: tuple) -> str:
    import eth_abi

    # eth_abi 5.x wants raw bytes for bytesN — accept "0x..." hex strings.
    normalized = tuple(
        bytes.fromhex(a[2:] if a.startswith("0x") else a)
        if t.startswith("bytes") and isinstance(a, str)
        else a
        for t, a in zip(types, args)
    )
    return selector(signature) + eth_abi.encode(types, normalized).hex()


def case_reference_hash(chain_id: int, contract_address: str, institution_id: str, case_id: str) -> str:
    """Off-chain case reference per ForensicTrail.createIncidentForCase docs:
    keccak256(abi.encode(chainId, contract, institutionRefHash, caseIdHash)).
    Including the institution keeps tenants' references disjoint."""
    import eth_abi

    inst_hash = keccak256(institution_id.encode("utf-8"))
    case_hash = keccak256(case_id.encode("utf-8"))
    encoded = eth_abi.encode(
        ["uint256", "address", "bytes32", "bytes32"],
        [chain_id, contract_address, inst_hash, case_hash],
    )
    return "0x" + keccak256(encoded).hex()


def payload_digest(call: Dict[str, Any]) -> str:
    canonical = json.dumps(call, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SignerCredentials:
    """Anchoring-service signer. The private key comes from the environment
    (ANCHOR_SIGNER_PRIVATE_KEY) or a key file (ANCHOR_SIGNER_KEY_FILE) —
    never from the database — and never reaches logs or persisted rows."""

    ENV_KEY_VAR = "ANCHOR_SIGNER_PRIVATE_KEY"
    ENV_FILE_VAR = "ANCHOR_SIGNER_KEY_FILE"

    def __init__(self, private_key_hex: str):
        from eth_account import Account

        key = private_key_hex.strip()
        if key.startswith("0x"):
            key = key[2:]
        if len(key) != 64:
            raise ValueError("signer private key must be a 32-byte hex value")
        self._account = Account.from_key(key)
        self.address = self._account.address

    @property
    def key_obj(self):
        return self._account

    @classmethod
    def from_environment(cls) -> "SignerCredentials":
        hex_key = os.environ.get(cls.ENV_KEY_VAR, "").strip()
        if hex_key:
            return cls(hex_key)
        path = os.environ.get(cls.ENV_FILE_VAR, "").strip()
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                return cls(fh.read())
        raise ChainSenderError(
            f"anchoring signer not provisioned: set {cls.ENV_KEY_VAR} or {cls.ENV_FILE_VAR}"
        )

    def __repr__(self) -> str:  # never leak the key
        return f"SignerCredentials(address={self.address})"


def advisory_lock_key(chain_id: int, signer_address: str) -> int:
    """Stable signed-64-bit advisory-lock key per (chain, signer)."""
    digest = hashlib.sha256(f"ira-aml-anchor-nonce:{chain_id}:{signer_address.lower()}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@dataclass
class SenderBinding:
    """The registry binding a send uses (same binding the read side uses)."""
    chain_id: int
    contract_address: str
    institution_id: str
    deployment_id: str


class ChainSender:
    """Persists then broadcasts raw transactions with strict nonce discipline.

    Constructor takes a REQUIRED adapter — there is no optional RPC in the
    institutional path (spec §7).
    """

    def __init__(
        self,
        adapter: Any,
        credentials: SignerCredentials,
        clock: Callable,
        gas_limit: int = 400_000,
        required_depth: int = 2,
        stuck_after_seconds: int = STUCK_AFTER_SECONDS,
    ):
        if adapter is None:
            raise ValueError("ChainSender requires an RPC adapter (no optional RPC)")
        if credentials is None:
            raise ValueError("ChainSender requires provisioned signer credentials")
        self.adapter = adapter
        self.credentials = credentials
        self.clock = clock
        self.gas_limit = gas_limit
        self.required_depth = required_depth
        self.stuck_after_seconds = stuck_after_seconds
        self.signer_address = credentials.address
        self._paused_reason: Optional[str] = None

    # -- pause state -------------------------------------------------------

    @property
    def paused(self) -> bool:
        return self._paused_reason is not None

    @property
    def paused_reason(self) -> Optional[str]:
        return self._paused_reason

    def resume(self, reason: str) -> None:
        """Operator action only (tests use it explicitly)."""
        logger.info("signer %s resumed: %s", self.signer_address, reason)
        self._paused_reason = None

    def _pause(self, reason: str) -> None:
        if self._paused_reason is None:
            logger.error("ALERT: signer %s PAUSED for new sends: %s", self.signer_address, reason)
        self._paused_reason = reason

    # -- nonce allocation ---------------------------------------------------

    def _next_nonce(self, session: Session, chain_id: int) -> int:
        """Allocate the next nonce under the per-(chain, signer) PostgreSQL
        advisory lock so all workers serialize; detects external nonce use."""
        session.execute(
            select(func.pg_advisory_xact_lock(advisory_lock_key(chain_id, self.signer_address)))
            if session.get_bind().dialect.name == "postgresql"
            else select(1)
        ).scalar()

        allocated_max = session.execute(
            select(func.max(ChainSubmission.nonce)).where(
                ChainSubmission.chain_id == chain_id,
                ChainSubmission.signer_address == self.signer_address,
            )
        ).scalar_one()

        chain_pending = int(self.adapter.eth_get_transaction_count(self.signer_address, "pending"))
        if allocated_max is None:
            # We have never persisted a submission for this signer, yet the
            # chain already consumed nonces: someone else used the exclusive
            # signer address. Pause instead of allocating on top of it.
            if chain_pending > 0:
                self._pause(
                    f"nonce 0..{chain_pending - 1} consumed externally before any "
                    f"persisted submission (chain pending {chain_pending})"
                )
                raise NonceConsumedExternallyError(self._paused_reason or "nonce consumed externally")
            return 0

        next_nonce = allocated_max + 1
        if chain_pending > allocated_max + 1:
            # A nonce beyond our persisted set was consumed by someone else:
            # the signer address is exclusive to this service, so this is a
            # compromise/misconfiguration — pause new sends.
            self._pause(
                f"nonce {allocated_max + 1}..{chain_pending - 1} consumed externally "
                f"(chain pending {chain_pending}, allocated max {allocated_max})"
            )
            raise NonceConsumedExternallyError(self._paused_reason or "nonce consumed externally")
        return next_nonce

    # -- prepare ----------------------------------------------------------

    def build_call(self, kind: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Encode the two on-chain methods R08 submits (merged R04 ABI)."""
        if kind == "EVIDENCE_ATTESTED":
            data = encode_call(
                "submitEvidenceAttested(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)",
                ["uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
                (
                    int(args["incident_id"]),
                    args["request_id"],
                    args["type_hash"],
                    args["description_hash"],
                    args["file_sha256"],
                    args["manifest_digest"],
                ),
            )
        elif kind == "CASE_INCIDENT":
            data = encode_call(
                "createIncidentForCase(bytes32,bytes32,bytes32)",
                ["bytes32", "bytes32", "bytes32"],
                (
                    args["case_reference_hash"],
                    args["title_hash"],
                    args["severity_hash"],
                ),
            )
        else:
            raise ValueError(f"unsupported submission kind {kind}")
        return {"kind": kind, "to": args["contract_address"], "data": data, "value": 0}

    def prepare_and_persist(
        self,
        session: Session,
        binding: SenderBinding,
        call: Dict[str, Any],
        request_id: str,
        now=None,
    ) -> ChainSubmission:
        """Persist the signed raw tx (nonce included) BEFORE any broadcast.

        Idempotent: an existing row for (institution, request_id, kind) with
        the SAME payload digest is returned unchanged — a crash recovery
        re-broadcasts that exact transaction. A different digest is a
        PayloadConflictError (terminal DEAD). A REORGED or RECEIPT_STATUS_ZERO
        row is replaced IN PLACE with a freshly allocated nonce (the old
        nonce died with the reorged/failed transaction; nothing is re-signed
        silently — the new raw tx is recorded first, as always).
        """
        if self.paused:
            raise SignerPausedError(self._paused_reason or "signer paused")

        digest = payload_digest(call)
        now = _aware(now) if now is not None else self.clock()

        existing = session.execute(
            select(ChainSubmission).where(
                ChainSubmission.institution_id == binding.institution_id,
                ChainSubmission.request_id == request_id,
                ChainSubmission.submission_kind == call["kind"],
            )
        ).scalars().first()

        if existing is not None:
            if existing.payload_digest != digest:
                raise PayloadConflictError(
                    f"request {request_id} already persisted with a different payload "
                    f"({existing.payload_digest} != {digest})"
                )
            if existing.status in (REORGED, RECEIPT_STATUS_ZERO):
                return self._replace_in_place(session, binding, existing, call, request_id, digest, now)
            return existing  # SIGNED/BROADCAST/CONFIRMED: re-broadcast the SAME tx

        return self._insert_new(session, binding, call, request_id, digest, now)

    def _insert_new(
        self, session, binding, call, request_id, digest, now
    ) -> ChainSubmission:
        nonce = self._next_nonce(session, binding.chain_id)
        try:
            row = self._sign_row(binding, call, request_id, digest, nonce, now)
            session.add(row)
            session.flush()
            return row
        except IntegrityError:
            session.rollback()
            existing = session.execute(
                select(ChainSubmission).where(
                    ChainSubmission.institution_id == binding.institution_id,
                    ChainSubmission.request_id == request_id,
                    ChainSubmission.submission_kind == call["kind"],
                )
            ).scalars().first()
            if existing is None:
                raise
            if existing.payload_digest != digest:
                raise PayloadConflictError(
                    f"request {request_id} raced to persistence with a different payload"
                )
            return existing

    def _replace_in_place(
        self, session, binding, existing, call, request_id, digest, now
    ) -> ChainSubmission:
        nonce = self._next_nonce(session, binding.chain_id)
        fresh = self._sign_row(binding, call, request_id, digest, nonce, now)
        existing.nonce = fresh.nonce
        existing.protected_raw_tx = fresh.protected_raw_tx
        existing.tx_hash = fresh.tx_hash
        existing.status = SIGNED
        existing.broadcast_at = None
        existing.stuck_alerted_at = None
        existing.receipt_block_number = None
        existing.receipt_block_hash = None
        existing.receipt_status = None
        existing.created_at = now
        session.flush()
        return existing

    def _sign_row(self, binding, call, request_id, digest, nonce, now) -> ChainSubmission:
        from eth_account import Account

        chain_id = int(self.adapter.eth_chain_id())
        if chain_id != binding.chain_id:
            raise ChainSenderError(
                f"adapter chain id {chain_id} != binding {binding.chain_id}"
            )
        tx = {
            "to": call["to"],
            "data": call["data"],
            "value": call.get("value", 0),
            "nonce": nonce,
            "gas": self.gas_limit,
            "gasPrice": int(self.adapter.eth_gas_price()),
            "chainId": chain_id,
        }
        signed = Account.sign_transaction(tx, self.credentials.key_obj.key)
        raw_hex = signed.raw_transaction.to_0x_hex() if hasattr(signed.raw_transaction, "to_0x_hex") else "0x" + bytes(signed.raw_transaction).hex()
        return ChainSubmission(
            id=f"cs_{uuid.uuid4().hex[:16]}",
            institution_id=binding.institution_id,
            chain_id=binding.chain_id,
            signer_address=self.signer_address,
            nonce=nonce,
            submission_kind=call["kind"],
            request_id=request_id,
            payload_digest=digest,
            protected_raw_tx=raw_hex,
            tx_hash=signed.hash.to_0x_hex() if hasattr(signed.hash, "to_0x_hex") else "0x" + bytes(signed.hash).hex(),
            status=SIGNED,
            created_at=now,
        )

    # -- broadcast ----------------------------------------------------------

    def broadcast(self, submission: ChainSubmission, now=None) -> str:
        """Broadcast the persisted raw transaction. Re-broadcasting the same
        raw tx (crash recovery) is idempotent at the node. The payload is
        never changed here."""
        if self.paused:
            raise SignerPausedError(self._paused_reason or "signer paused")
        now = _aware(now) if now is not None else self.clock()
        returned_hash = self.adapter.eth_send_raw_transaction(submission.protected_raw_tx)
        if str(returned_hash).lower() != submission.tx_hash.lower():
            raise ChainSenderError(
                f"node returned tx hash {returned_hash} for the broadcast of persisted "
                f"{submission.tx_hash} — refusing to continue with an altered transaction"
            )
        if submission.status == SIGNED:
            submission.status = BROADCAST
        submission.broadcast_at = submission.broadcast_at or now
        return submission.tx_hash

    # -- reconcile ----------------------------------------------------------

    def reconcile(self, submission: ChainSubmission, now=None, session: Optional[Session] = None) -> str:
        """Resolve a broadcast submission to a SubmissionState.

        receipt absent   -> PENDING; past stuck_after_seconds -> STUCK with a
                            one-time alert and the signer paused for NEW
                            sends (this reconciliation continues unchanged).
        receipt.status 0 -> RECEIPT_STATUS_ZERO (NOT anchored — the on-chain
                            execution failed; anchor goes FAILED and the
                            retry ladder applies).
        receipt ok       -> verify the receipt's block is canonical; a hash
                            mismatch is REORGED (back to SUBMITTED upstream).
                            Below required depth -> CONFIRMING (slow
                            confirmation consumes no retry).
        full depth + canonical block + matching entry -> CONFIRMED.
        """
        now = _aware(now) if now is not None else self.clock()
        receipt = self.adapter.eth_get_transaction_receipt(submission.tx_hash)

        if receipt is None:
            first_sent = submission.broadcast_at or submission.created_at
            if (now - first_sent).total_seconds() > self.stuck_after_seconds:
                if submission.stuck_alerted_at is None:
                    submission.stuck_alerted_at = now
                    self._pause(
                        f"tx {submission.tx_hash} unconfirmed for more than "
                        f"{self.stuck_after_seconds}s — no automatic replacement; "
                        "operator intervention required"
                    )
                    if session is not None:
                        session.flush()
                return SubmissionState.STUCK
            return SubmissionState.PENDING

        raw_status = receipt.get("status", 0)
        status = int(raw_status, 16) if isinstance(raw_status, str) else int(raw_status)
        if status == 0:
            submission.status = RECEIPT_STATUS_ZERO
            submission.receipt_status = 0
            self._fill_receipt(submission, receipt)
            if session is not None:
                session.flush()
            return SubmissionState.RECEIPT_STATUS_ZERO

        block_number = int(receipt.get("blockNumber", 0), 16) if isinstance(
            receipt.get("blockNumber"), str
        ) else int(receipt.get("blockNumber", 0))
        block = self.adapter.eth_get_block_by_number(block_number)
        if block is None or str(block.get("hash", "")).lower() != str(receipt.get("blockHash", "")).lower():
            submission.status = REORGED
            if session is not None:
                session.flush()
            return SubmissionState.REORGED

        head = int(self.adapter.eth_block_number())
        confirmations = head - block_number + 1
        if confirmations < self.required_depth:
            self._fill_receipt(submission, receipt)
            if session is not None:
                session.flush()
            return SubmissionState.CONFIRMING

        submission.status = CONFIRMED
        submission.receipt_status = 1
        self._fill_receipt(submission, receipt)
        if session is not None:
            session.flush()
        return SubmissionState.CONFIRMED

    def _fill_receipt(self, submission: ChainSubmission, receipt: Dict[str, Any]) -> None:
        bn = receipt.get("blockNumber", 0)
        submission.receipt_block_number = int(bn, 16) if isinstance(bn, str) else int(bn)
        submission.receipt_block_hash = str(receipt.get("blockHash", ""))

    # -- idempotency reads (send-path only; verification reads are R07's) ----

    def manifest_digest_on_chain(self, request_id: str) -> Optional[str]:
        digest = self.adapter.get_manifest_digest(request_id)
        if not digest or digest == "0x" + "0" * 64:
            return None
        return digest

    def evidence_on_chain(self, request_id: str) -> Optional[Dict[str, Any]]:
        rec = self.adapter.get_evidence_by_request_id(request_id)
        if rec and rec.get("exists"):
            return rec
        return None

    def incident_for_case_reference(self, ref_hash: str) -> int:
        return int(self.adapter.get_incident_by_case_reference(ref_hash) or 0)
