"""
Live EVM RPC Client for Evidence Verification
Interacts with deployed ForensicTrail contract via JSON-RPC.

R07 additions (spec §5): block-tagged reads for the AnchorReader —
eth_call/eth_getCode/eth_getLogs all execute at an EXPLICIT block number
(the pinned snapshot), decoded ABI results for the R04 attested contract
surface, and parsed EvidenceWriterUpdated / EvidenceManifestAnchored /
EvidenceSubmitted logs replayed from the binding's deployed_at_block.
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import httpx
from Crypto.Hash import keccak
import eth_abi


def _keccak256_selector(sig: str) -> str:
    k = keccak.new(digest_bits=256)
    k.update(sig.encode("utf-8"))
    return "0x" + k.hexdigest()[:8]


def _topic(sig: str) -> str:
    k = keccak.new(digest_bits=256)
    k.update(sig.encode("utf-8"))
    return "0x" + k.hexdigest()


TOPIC_EVIDENCE_WRITER_UPDATED = _topic("EvidenceWriterUpdated(address,bool)")
TOPIC_INCIDENT_CREATED = _topic("IncidentCreated(uint256,bytes32,bytes32,address,uint256)")
TOPIC_EVIDENCE_SUBMITTED = _topic(
    "EvidenceSubmitted(uint256,uint256,address,bytes32,bytes32,uint256)"
)
TOPIC_EVIDENCE_MANIFEST_ANCHORED = _topic(
    "EvidenceManifestAnchored(bytes32,uint256,bytes32)"
)

SIG_GET_INCIDENT_FOR_CASE = "getIncidentByCaseReference(bytes32)"
SIG_GET_MANIFEST_DIGEST = "getManifestDigest(bytes32)"
SIG_GET_INCIDENT = "getIncident(uint256)"
SIG_GET_EVIDENCE_CHAIN = "getEvidenceChain(uint256)"

EVIDENCE_TUPLE = (
    "uint256", "uint256", "address", "uint256",
    "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
)


class EvmRpcClient:
    def __init__(self, rpc_url: str = "http://127.0.0.1:8545", manifest_path: Optional[str] = None):
        self.rpc_url = rpc_url
        self.client = httpx.Client(timeout=3.0)
        self.contract_address: Optional[str] = None

        if manifest_path and Path(manifest_path).exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    contracts = data.get("addresses") or data.get("contracts") or {}
                    self.contract_address = contracts.get("ForensicTrail")
            except Exception:
                self.contract_address = None

    def _rpc_call(self, method: str, params: list) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }
        try:
            resp = self.client.post(self.rpc_url, json=payload)
            if resp.status_code != 200:
                raise ConnectionError(f"RPC HTTP error {resp.status_code}: {resp.text}")
            res_json = resp.json()
            if "error" in res_json:
                raise RuntimeError(f"RPC error: {res_json['error']}")
            return res_json.get("result")
        except httpx.RequestError as exc:
            raise ConnectionError(f"RPC connection refused at {self.rpc_url}: {str(exc)}") from exc

    def get_block(self, block_tag: str = "latest") -> Dict[str, Any]:
        if isinstance(block_tag, int):
            block_tag = hex(block_tag)
        result = self._rpc_call("eth_getBlockByNumber", [block_tag, False])
        if not result:
            raise ConnectionError(f"Block not found for tag {block_tag}")
        block_num = int(result.get("number", "0x0"), 16)
        block_hash = result.get("hash", "")
        return {"number": block_num, "hash": block_hash}

    # ------------------------------------------------------------------
    # R07: block-tagged reads for the AnchorReader (spec §5)
    # ------------------------------------------------------------------
    def get_code(self, address: str, block_number: int) -> str:
        return self._rpc_call(
            "eth_getCode", [address, hex(block_number)]
        )

    def eth_get_logs(
        self,
        address: str,
        from_block: int,
        to_block: int,
        topics: Optional[List[Optional[str]]] = None,
    ) -> List[Dict[str, Any]]:
        filter_obj: Dict[str, Any] = {
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "address": address,
        }
        if topics:
            filter_obj["topics"] = topics
        result = self._rpc_call("eth_getLogs", [filter_obj])
        return result or []

    def get_logs(self, address: str, from_block: int, to_block: int) -> List[Dict[str, Any]]:
        """Parsed EvidenceWriterUpdated history (the AnchorReader replay input).
        Ordered by (blockNumber, transactionIndex, logIndex) by the reader."""
        logs = self.eth_get_logs(
            address, from_block, to_block, topics=[TOPIC_EVIDENCE_WRITER_UPDATED]
        )
        parsed = []
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 2:
                continue
            writer = "0x" + topics[1][-40:]
            data = log.get("data", "0x")
            raw = data[2:] if data.startswith("0x") else data
            authorized = bool(int(raw[:64], 16)) if len(raw) >= 64 else False
            parsed.append(
                {
                    "blockNumber": int(log["blockNumber"], 16),
                    "transactionIndex": int(log["transactionIndex"], 16),
                    "logIndex": int(log["logIndex"], 16),
                    "event": "EvidenceWriterUpdated",
                    "writer": writer,
                    "authorized": authorized,
                }
            )
        return parsed

    def raw_call(self, to: str, data: str, block_number: int) -> Any:
        """eth_call at an EXPLICIT block number (the pinned snapshot)."""
        return self._rpc_call(
            "eth_call", [{"to": to, "data": data}, hex(block_number)]
        )

    def _call_bytes32(self, to: str, sig: str, arg_bytes32: str, block_number: int) -> str:
        selector = _keccak256_selector(sig)
        clean = arg_bytes32[2:] if arg_bytes32.startswith("0x") else arg_bytes32
        call_data = selector + clean.rjust(64, "0")
        result = self.raw_call(to, call_data, block_number)
        if not result or result == "0x":
            raise RuntimeError(f"empty eth_call result for {sig}")
        return result

    def get_incident_for_case(self, address: str, case_reference_hash: str, block_number: int) -> int:
        result = self._call_bytes32(address, SIG_GET_INCIDENT_FOR_CASE, case_reference_hash, block_number)
        return int(result, 16)

    def get_manifest_digest(self, address: str, request_id: str, block_number: int) -> Optional[str]:
        result = self._call_bytes32(address, SIG_GET_MANIFEST_DIGEST, request_id, block_number)
        clean = result[2:] if result.startswith("0x") else result
        digest = "0x" + clean[-64:].rjust(64, "0")
        if int(digest, 16) == 0:
            return None
        return digest

    def read_incident(self, binding, incident_id: int, snapshot):
        """Full AnchoredIncident at the pinned block: real entries decoded
        from getEvidenceChain, with requestIds/manifestDigests/event positions
        replayed from the anchored EvidenceManifestAnchored /
        EvidenceSubmitted logs. No object placeholders."""
        from app.services.anchor_reader import AnchoredEntry, AnchoredIncident, EventPosition

        address = binding.forensic_trail_address()
        bn = snapshot.block_number

        incident_raw = self.raw_call(
            address,
            _keccak256_selector(SIG_GET_INCIDENT) + hex(incident_id)[2:].rjust(64, "0"),
            bn,
        )
        if not incident_raw or incident_raw == "0x":
            raise RuntimeError(f"incident {incident_id} not readable at block {bn}")
        inc = eth_abi.decode(
            ["uint256", "bytes32", "bytes32", "address", "uint256", "bool", "uint256"],
            bytes.fromhex(incident_raw[2:]),
        )
        evidence_count = int(inc[6])

        chain_raw = self.raw_call(
            address,
            _keccak256_selector(SIG_GET_EVIDENCE_CHAIN) + hex(incident_id)[2:].rjust(64, "0"),
            bn,
        )
        if not chain_raw or chain_raw == "0x":
            entries = []
        else:
            decoded = eth_abi.decode(
                [f"({EVIDENCE_TUPLE[0]},{EVIDENCE_TUPLE[1]},{EVIDENCE_TUPLE[2]},{EVIDENCE_TUPLE[3]},"
                 f"{EVIDENCE_TUPLE[4]},{EVIDENCE_TUPLE[5]},{EVIDENCE_TUPLE[6]},{EVIDENCE_TUPLE[7]},"
                 f"{EVIDENCE_TUPLE[8]})[]"],
                bytes.fromhex(chain_raw[2:]),
            )
            entries = list(decoded[0]) if decoded else []

        # anchored manifest commitments + append positions (log replay)
        anchored: Dict[int, Dict[str, Any]] = {}
        for log in self.eth_get_logs(
            address,
            max(0, binding.deployed_at_block),
            bn,
            topics=[TOPIC_EVIDENCE_MANIFEST_ANCHORED],
        ):
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            request_id = "0x" + topics[1][-64:]
            evidence_id = int(topics[2], 16)
            data = log.get("data", "0x")
            raw = data[2:] if data.startswith("0x") else data
            digest = "0x" + raw[-64:].rjust(64, "0")
            anchored[evidence_id] = {
                "request_id": request_id,
                "manifest_digest": digest,
                "position": EventPosition(
                    int(log["blockNumber"], 16),
                    int(log["transactionIndex"], 16),
                    int(log["logIndex"], 16),
                ),
            }

        submit_positions: Dict[int, EventPosition] = {}
        for log in self.eth_get_logs(
            address,
            max(0, binding.deployed_at_block),
            bn,
            topics=[TOPIC_EVIDENCE_SUBMITTED],
        ):
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            if int(topics[1], 16) != int(incident_id):
                continue
            evidence_id = int(topics[2], 16)
            submit_positions[evidence_id] = EventPosition(
                int(log["blockNumber"], 16),
                int(log["transactionIndex"], 16),
                int(log["logIndex"], 16),
            )

        real_entries: List[AnchoredEntry] = []
        for e in entries:
            evidence_id = int(e[0])
            commitment = anchored.get(evidence_id)
            real_entries.append(
                AnchoredEntry(
                    evidence_id=str(evidence_id),
                    incident_id=str(int(e[1])),
                    submitted_by=e[2],
                    timestamp=int(e[3]),
                    evidence_type_hash="0x" + e[4].hex(),
                    description_hash="0x" + e[5].hex(),
                    evidence_hash="0x" + e[6].hex(),
                    previous_entry_hash="0x" + e[7].hex(),
                    entry_hash="0x" + e[8].hex(),
                    request_id=commitment["request_id"] if commitment else None,
                    manifest_digest=commitment["manifest_digest"] if commitment else None,
                    event_position=(
                        commitment["position"] if commitment else submit_positions.get(evidence_id)
                    ),
                )
            )

        return AnchoredIncident(
            incident_id=incident_id,
            entries=real_entries,
            evidence_count=evidence_count,
            head_entry_hash=real_entries[-1].entry_hash if real_entries else "0x" + "00" * 32,
            is_open=bool(inc[5]),
        )

    def is_evidence_writer(self, address: str) -> bool:
        if not self.contract_address:
            return True
        selector = _keccak256_selector("isEvidenceWriter(address)")
        # address to 32 bytes
        clean_addr = address.lower().replace("0x", "")
        padded_addr = clean_addr.rjust(64, "0")
        call_data = selector + padded_addr

        try:
            result = self._rpc_call("eth_call", [{"to": self.contract_address, "data": call_data}, "latest"])
            if not result or result == "0x":
                return False
            val = int(result, 16)
            return val == 1
        except Exception:
            return False

    def get_incident(self, incident_id: int) -> Optional[Dict[str, Any]]:
        if not self.contract_address:
            # Fallback if contract address unknown but RPC alive
            return {"id": incident_id, "evidence_count": 1}

        selector = _keccak256_selector("getIncident(uint256)")
        padded_id = hex(incident_id)[2:].rjust(64, "0")
        call_data = selector + padded_id

        try:
            result = self._rpc_call("eth_call", [{"to": self.contract_address, "data": call_data}, "latest"])
            if not result or result == "0x":
                return None
            # Incident struct: uint256 id, bytes32 titleHash, bytes32 severityHash, address reportedBy, uint256 reportedAt, bool isOpen, uint256 evidenceCount
            raw_bytes = bytes.fromhex(result.replace("0x", ""))
            decoded = eth_abi.decode(
                ["uint256", "bytes32", "bytes32", "address", "uint256", "bool", "uint256"],
                raw_bytes
            )
            return {
                "id": decoded[0],
                "titleHash": "0x" + decoded[1].hex(),
                "severityHash": "0x" + decoded[2].hex(),
                "reportedBy": decoded[3],
                "reportedAt": decoded[4],
                "isOpen": decoded[5],
                "evidence_count": decoded[6]
            }
        except Exception:
            return None

    def get_evidence_chain(self, incident_id: int) -> List[Any]:
        if not self.contract_address:
            return []

        # Query incident to know how many entries exist
        inc = self.get_incident(incident_id)
        if not inc:
            return []
        count = inc.get("evidence_count", 0)
        return [object()] * count


class JsonRpcSendAdapter:
    """R08 SEND-SIDE adapter (ChainSender's transport).

    Split contract (R07/R08 parallel work, controller-agreed): R07 owns the
    verification READ service (anchor reader, ITS worktree); this class is
    the send path only — raw-transaction broadcast, nonce/receipt/block
    reads for signing and reconciliation, plus the three send-path
    idempotency reads spec §7 requires BEFORE any re-send
    (getManifestDigest, getEvidenceByRequestId, getIncidentByCaseReference).
    It reuses the same registry binding the read side uses (chain id,
    ForensicTrail address from the deployment manifest).

    It never logs and never persists signer material — the private key
    stays in SignerCredentials (env/key file).
    """

    def __init__(self, rpc_url: str = "http://127.0.0.1:8545", contract_address: Optional[str] = None):
        self.rpc_url = rpc_url
        self.client = httpx.Client(timeout=10.0)
        self.contract_address = contract_address

    def _rpc(self, method: str, params: list) -> Any:
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        resp = self.client.post(self.rpc_url, json=payload)
        if resp.status_code != 200:
            raise ConnectionError(f"RPC HTTP error {resp.status_code}: {resp.text}")
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"RPC error: {body['error']}")
        return body.get("result")

    # -- node ---------------------------------------------------------------

    def eth_chain_id(self) -> int:
        return int(self._rpc("eth_chainId", []), 16)

    def eth_gas_price(self) -> int:
        return int(self._rpc("eth_gasPrice", []), 16)

    def eth_get_transaction_count(self, address: str, tag: str = "pending") -> int:
        return int(self._rpc("eth_getTransactionCount", [address, tag]), 16)

    def eth_block_number(self) -> int:
        return int(self._rpc("eth_blockNumber", []), 16)

    def eth_get_block_by_number(self, number: int) -> Optional[Dict[str, Any]]:
        result = self._rpc("eth_getBlockByNumber", [hex(number), False])
        if not result:
            return None
        return {"number": int(result["number"], 16), "hash": result["hash"]}

    def eth_send_raw_transaction(self, raw_tx_hex: str) -> str:
        return self._rpc("eth_sendRawTransaction", [raw_tx_hex])

    def eth_get_transaction_receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        receipt = self._rpc("eth_getTransactionReceipt", [tx_hash])
        if not receipt:
            return None
        return {
            "status": receipt["status"],
            "blockNumber": receipt["blockNumber"],
            "blockHash": receipt["blockHash"],
            "transactionHash": receipt["transactionHash"],
        }

    # -- send-path idempotency reads (spec §7; verification reads are R07's) --

    def _call(self, data_hex: str) -> Optional[str]:
        if not self.contract_address:
            raise RuntimeError("JsonRpcSendAdapter requires the ForensicTrail binding")
        return self._rpc("eth_call", [{"to": self.contract_address, "data": data_hex}, "latest"])

    def get_manifest_digest(self, request_id: str) -> str:
        selector = _keccak256_selector("getManifestDigest(bytes32)")
        arg = request_id[2:] if request_id.startswith("0x") else request_id
        result = self._call(selector + arg.rjust(64, "0"))
        return "0x" + result[2:].rjust(64, "0") if result and result != "0x" else "0x" + "0" * 64

    def get_incident_by_case_reference(self, ref_hash: str) -> int:
        selector = _keccak256_selector("getIncidentByCaseReference(bytes32)")
        arg = ref_hash[2:] if ref_hash.startswith("0x") else ref_hash
        result = self._call(selector + arg.rjust(64, "0"))
        return int(result, 16) if result else 0

    def get_evidence_by_request_id(self, request_id: str) -> Dict[str, Any]:
        selector = _keccak256_selector("getEvidenceByRequestId(bytes32)")
        arg = request_id[2:] if request_id.startswith("0x") else request_id
        result = self._call(selector + arg.rjust(64, "0"))
        if not result or result == "0x":
            return {"exists": False}
        raw = bytes.fromhex(result[2:])
        decoded = eth_abi.decode(
            ["uint256", "bytes32", "bytes32", "address", "uint256", "bool", "bytes32", "bytes32"],
            raw,
        )
        evidence_id, entry_hash, payload_hash, submitted_by, timestamp, exists, evidence_hash, prev_hash = decoded
        if not exists:
            return {"exists": False}
        return {
            "exists": True,
            "evidence_id": evidence_id,
            "entry_hash": "0x" + entry_hash.hex(),
            "submitted_by": submitted_by,
            "timestamp": timestamp,
            "evidence_hash": "0x" + evidence_hash.hex(),
            "previous_entry_hash": "0x" + prev_hash.hex(),
        }
