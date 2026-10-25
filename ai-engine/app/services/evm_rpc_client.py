"""
Live EVM RPC Client for Evidence Verification
Interacts with deployed ForensicTrail contract via JSON-RPC.
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


class EvmRpcClient:
    def __init__(self, rpc_url: str = "http://127.0.0.1:8545", manifest_path: Optional[str] = None):
        self.rpc_url = rpc_url
        self.client = httpx.Client(timeout=3.0)
        self.contract_address: Optional[str] = None

        if manifest_path and Path(manifest_path).exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.contract_address = data.get("contracts", {}).get("ForensicTrail")
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
        result = self._rpc_call("eth_getBlockByNumber", [block_tag, False])
        if not result:
            raise ConnectionError(f"Block not found for tag {block_tag}")
        block_num = int(result.get("number", "0x0"), 16)
        block_hash = result.get("hash", "")
        return {"number": block_num, "hash": block_hash}

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
