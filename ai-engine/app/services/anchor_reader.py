"""
Anchor Reader (R07, spec §5) — pinned-snapshot chain reads for verification.

Responsibilities:
  - take_snapshot(binding): block_number = latest - confirmation_depth + 1,
    then PIN block_hash at that number;
  - every read (eth_call / eth_getCode / eth_getLogs) is executed at the
    pinned block_number — never at "latest";
  - read_incident(binding, incident_id, snapshot): the REAL anchored entries
    with requestIds, manifestDigests and their event positions — no object
    placeholders;
  - writer_authorized_at(binding, writer, event_position): replays the
    EvidenceWriterUpdated history from deployed_at_block ordered by
    (blockNumber, transactionIndex, logIndex) and answers the authorization
    state STRICTLY BEFORE the append event — add-then-revoke inside one block
    keeps the evidence valid, revoke-then-add invalidates it, a grant after
    the submit does not authorize it. End-of-block state is never used.
  - verify_code_hash(binding, snapshot): keccak256(runtime code at the pinned
    block) must equal the binding's expected hash (proven mismatch = invalid;
    missing expected hash = unavailable);
  - recheck_block_hash(snapshot): the pinned block must still resolve to the
    pinned hash right before a result is produced (reorg => snapshot_reorged).

Availability discipline: a network/RPC failure raises RpcUnavailableError and
a missing historical capability raises HistoricalLogsUnavailableError — both
map to `unavailable`, never to a fabricated verdict.

The reader talks to ANY client exposing the low-level surface
(get_block/get_code/get_logs/raw_call) — the production EvmRpcClient
(ai-engine/app/services/evm_rpc_client.py) and test shims both satisfy it.
"""

from typing import Any, Dict, List, Optional

from app.services.chain_registry import DeploymentBinding, CodeHashMismatchError, compute_keccak256

ZERO_BYTES32 = "0x" + "00" * 32


class AnchorReaderError(Exception):
    """Base class — reader-level failures mapped by the verifier."""


class RpcUnavailableError(AnchorReaderError):
    """Network/RPC failure: the verification result is `unavailable`."""


class HistoricalLogsUnavailableError(AnchorReaderError):
    """The writer-grant history cannot be read (missing method/params):
    authorization cannot be proven -> `unavailable` (never fabricated from
    the current allowlist)."""


class CodeHashMissingError(AnchorReaderError):
    """The binding carries no expected code hash: `unavailable`."""


class ContractCodeEmptyError(AnchorReaderError):
    """No bytecode at the bound address at the snapshot block."""


class IncidentNotFoundError(AnchorReaderError):
    """The incident does not exist at the snapshot block."""


class EventPosition:
    """Total order position of a log: (blockNumber, transactionIndex, logIndex)."""

    __slots__ = ("block_number", "transaction_index", "log_index")

    def __init__(self, block_number: int, transaction_index: int, log_index: int):
        self.block_number = int(block_number)
        self.transaction_index = int(transaction_index)
        self.log_index = int(log_index)

    def key(self):
        return (self.block_number, self.transaction_index, self.log_index)

    def __lt__(self, other: "EventPosition") -> bool:
        return self.key() < other.key()

    def __repr__(self):  # pragma: no cover
        return f"EventPosition(block={self.block_number}, tx={self.transaction_index}, log={self.log_index})"


class ChainSnapshot:
    """A pinned chain read point (spec §5): block_number = latest-depth+1 with
    its block_hash fixed at pin time; every verification read happens here."""

    __slots__ = ("id", "chain_id", "block_number", "block_hash", "confirmation_depth")

    def __init__(self, id: Optional[str], chain_id: int, block_number: int, block_hash: str, confirmation_depth: int):
        self.id = id
        self.chain_id = int(chain_id)
        self.block_number = int(block_number)
        self.block_hash = block_hash
        self.confirmation_depth = int(confirmation_depth)

    def __repr__(self):  # pragma: no cover
        return f"ChainSnapshot(#{self.block_number}, {self.block_hash[:18]}.., depth={self.confirmation_depth})"


class AnchoredEntry:
    """One REAL on-chain evidence entry at the snapshot, with its attested
    requestId + manifestDigest and the position of its anchor event."""

    __slots__ = (
        "evidence_id", "incident_id", "submitted_by", "timestamp",
        "evidence_type_hash", "description_hash", "evidence_hash",
        "previous_entry_hash", "entry_hash",
        "request_id", "manifest_digest", "event_position",
    )

    def __init__(
        self,
        evidence_id: str,
        incident_id: str,
        submitted_by: str,
        timestamp: int,
        evidence_type_hash: str,
        description_hash: str,
        evidence_hash: str,
        previous_entry_hash: str,
        entry_hash: str,
        request_id: Optional[str] = None,
        manifest_digest: Optional[str] = None,
        event_position: Optional[EventPosition] = None,
    ):
        self.evidence_id = str(evidence_id)  # uint256 surfaced as decimal STRING
        self.incident_id = str(incident_id)
        self.submitted_by = submitted_by
        self.timestamp = int(timestamp)
        self.evidence_type_hash = evidence_type_hash
        self.description_hash = description_hash
        self.evidence_hash = evidence_hash
        self.previous_entry_hash = previous_entry_hash
        self.entry_hash = entry_hash
        self.request_id = request_id
        self.manifest_digest = manifest_digest
        self.event_position = event_position


class AnchoredIncident:
    """The full incident state at a snapshot: entries in chain order plus
    count/head (uint256 values as decimal strings)."""

    __slots__ = ("incident_id", "entries", "evidence_count", "head_entry_hash", "is_open")

    def __init__(self, incident_id, entries: List[AnchoredEntry], evidence_count: int, head_entry_hash: Optional[str], is_open: bool = True):
        self.incident_id = str(incident_id)
        self.entries = list(entries)
        self.evidence_count = int(evidence_count)
        self.head_entry_hash = head_entry_hash or (entries[-1].entry_hash if entries else ZERO_BYTES32)
        self.is_open = bool(is_open)


def _pos_from_log(log: Dict[str, Any]) -> EventPosition:
    return EventPosition(
        int(log.get("blockNumber", 0)),
        int(log.get("transactionIndex", 0)),
        int(log.get("logIndex", 0)),
    )


class AnchorReader:
    """Per-verification chain reader. `rpc` is any object exposing
    get_block(number), get_code(address, block_number), get_logs(address,
    from_block, to_block) and raw_call(to, data, block_number)."""

    def __init__(self, rpc: Any, registry_binding: Optional[DeploymentBinding] = None):
        self.rpc = rpc
        self.default_binding = registry_binding

    # ------------------------------------------------------------------
    # snapshot acquisition
    # ------------------------------------------------------------------
    def latest_block(self, binding: DeploymentBinding) -> int:
        try:
            head = self.rpc.get_block("latest")
            return int(head["number"])
        except Exception as exc:
            raise RpcUnavailableError(f"latest head unreadable: {type(exc).__name__}: {exc}") from exc

    def take_snapshot(self, binding: DeploymentBinding) -> ChainSnapshot:
        latest = self.latest_block(binding)
        depth = max(1, int(binding.confirmation_depth))
        block_number = latest - depth + 1
        if block_number < 0:
            block_number = 0
        return ChainSnapshot(
            id=None,
            chain_id=binding.chain_id,
            block_number=block_number,
            block_hash=self.block_hash(binding, block_number),
            confirmation_depth=depth,
        )

    def block_hash(self, binding: DeploymentBinding, block_number: int) -> str:
        try:
            block = self.rpc.get_block(block_number)
            return block["hash"]
        except Exception as exc:
            raise RpcUnavailableError(
                f"block {block_number} unreadable: {type(exc).__name__}: {exc}"
            ) from exc

    def recheck_block_hash(self, snapshot: ChainSnapshot) -> bool:
        """True when the pinned block still resolves to the pinned hash.
        Raises RpcUnavailableError on transport failure."""
        return self.block_hash(None, snapshot.block_number) == snapshot.block_hash

    # ------------------------------------------------------------------
    # code hash (at the snapshot block)
    # ------------------------------------------------------------------
    def verify_code_hash(self, binding: DeploymentBinding, snapshot: ChainSnapshot) -> None:
        expected = binding.expected_code_hash("ForensicTrail")
        if not expected:
            raise CodeHashMissingError(
                "deployment binding carries no expected code hash for ForensicTrail"
            )
        address = binding.forensic_trail_address()
        if not address:
            raise CodeHashMissingError("binding has no ForensicTrail address")
        try:
            code = self.rpc.get_code(address, snapshot.block_number)
        except Exception as exc:
            raise RpcUnavailableError(f"eth_getCode failed: {type(exc).__name__}: {exc}") from exc
        if not code or code in ("0x", "0x0"):
            raise ContractCodeEmptyError(f"no bytecode at {address} at block {snapshot.block_number}")
        code_hex = code[2:] if code.startswith("0x") else code
        computed = compute_keccak256(bytes.fromhex(code_hex))
        if computed.lower() != str(expected).lower():
            raise CodeHashMismatchError(
                f"ForensicTrail code hash {computed} != binding {expected} at block {snapshot.block_number}"
            )

    # ------------------------------------------------------------------
    # historical writer authorization (event-ordered)
    # ------------------------------------------------------------------
    def writer_events(self, binding: DeploymentBinding, up_to_block: int) -> List[Dict[str, Any]]:
        """EvidenceWriterUpdated logs from deployed_at_block..up_to_block.
        HistoricalLogsUnavailableError when the capability is missing."""
        address = binding.forensic_trail_address()
        if not getattr(self.rpc, "get_logs", None):
            raise HistoricalLogsUnavailableError("rpc client exposes no get_logs")
        try:
            return self.rpc.get_logs(address, binding.deployed_at_block, up_to_block)
        except AttributeError as exc:
            raise HistoricalLogsUnavailableError(f"get_logs unavailable: {exc}") from exc
        except Exception as exc:
            raise RpcUnavailableError(
                f"writer history unreadable: {type(exc).__name__}: {exc}"
            ) from exc

    def writer_authorized_at(
        self,
        binding: DeploymentBinding,
        writer: str,
        event_position: EventPosition,
    ) -> bool:
        """Authorization state STRICTLY BEFORE event_position, by replaying
        the ordered EvidenceWriterUpdated history. A writer never seen in the
        history falls back to the binding's bootstrap writer set (the initial
        allowlist established at deployment — recorded in the registry, not
        read from current chain state)."""
        events = self.writer_events(binding, event_position.block_number)
        target = writer.lower()
        state: Optional[bool] = None
        seen = False
        for log in events:
            log_writer = str(log.get("writer", log.get("args", {}).get("writer", ""))).lower()
            if log_writer != target:
                continue
            pos = _pos_from_log(log)
            if pos.key() < event_position.key():
                seen = True
                state = bool(log.get("authorized", log.get("args", {}).get("authorized")))
        if not seen:
            return target in binding.bootstrap_writers
        return bool(state)

    # ------------------------------------------------------------------
    # incident reads (all at the pinned block)
    # ------------------------------------------------------------------
    def incident_for_case(self, binding: DeploymentBinding, case_reference_hash: str, snapshot: ChainSnapshot) -> str:
        """getIncidentByCaseReference at the snapshot block; decimal string."""
        from app.services.evm_rpc_client import SIG_GET_INCIDENT_FOR_CASE, _keccak256_selector

        selector = _keccak256_selector(SIG_GET_INCIDENT_FOR_CASE)
        clean = case_reference_hash[2:] if case_reference_hash.startswith("0x") else case_reference_hash
        try:
            raw = self.rpc.raw_call(
                binding.forensic_trail_address(),
                selector + clean.rjust(64, "0"),
                snapshot.block_number,
            )
        except Exception as exc:
            raise RpcUnavailableError(f"case-reference read failed: {type(exc).__name__}: {exc}") from exc
        if raw is None:
            return "0"
        if isinstance(raw, str):
            return str(int(raw, 16))
        return str(int(raw))

    def read_incident(self, binding: DeploymentBinding, incident_id: int, snapshot: ChainSnapshot) -> AnchoredIncident:
        """Read the incident's full entry chain at the pinned block. The RPC
        client returns fully materialized AnchoredEntry objects (decoded from
        getIncident + getEvidenceChain + anchored manifest digests)."""
        try:
            incident = self.rpc.read_incident(binding, incident_id, snapshot)
        except AnchorReaderError:
            raise
        except Exception as exc:
            raise RpcUnavailableError(
                f"incident {incident_id} unreadable at block {snapshot.block_number}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if incident is None:
            raise IncidentNotFoundError(f"incident {incident_id} not found at block {snapshot.block_number}")
        return incident

    def get_manifest_digest(self, binding: DeploymentBinding, request_id: str, snapshot: ChainSnapshot) -> Optional[str]:
        """getManifestDigest(requestId) at the pinned block (None = no
        commitment anchored for this requestId)."""
        from app.services.evm_rpc_client import SIG_GET_MANIFEST_DIGEST, _keccak256_selector

        selector = _keccak256_selector(SIG_GET_MANIFEST_DIGEST)
        clean = request_id[2:] if request_id.startswith("0x") else request_id
        try:
            raw = self.rpc.raw_call(
                binding.forensic_trail_address(),
                selector + clean.rjust(64, "0"),
                snapshot.block_number,
            )
        except Exception as exc:
            raise RpcUnavailableError(f"manifest digest read failed: {type(exc).__name__}: {exc}") from exc
        if raw is None:
            return None
        if isinstance(raw, str):
            hexed = raw[2:] if raw.startswith("0x") else raw
            digest = "0x" + hexed[-64:].rjust(64, "0")
            if digest == ZERO_BYTES32 or int(digest, 16) == 0:
                return None
            return digest
        return str(raw)
