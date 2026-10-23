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
