"""
Blockchain Event Listener & RPC Client (T15)
Cyber-Forensic Auditing Framework - Specification §4, §6 (R09, R11)

Non-blocking httpx JSON-RPC client with bounded backoff, block verification,
and log ingestion capabilities for institutional blockchain indexing.
"""

import json
import time
import logging
from typing import Dict, Any, List, Optional
import httpx

from app.config import settings

logger = logging.getLogger("BlockchainListener")


class RpcRateLimitError(Exception):
    pass


class BlockchainListener:
    """
    JSON-RPC Client for Ethereum / Hardhat node interaction.
    Fetches real-time contract events and queries on-chain forensic records.
    """

    def __init__(self, rpc_url: Optional[str] = None, timeout_seconds: float = 5.0):
        self.rpc_url = rpc_url or settings.BLOCKCHAIN_RPC_URL
        self.timeout_seconds = timeout_seconds
        self._client: Optional[httpx.Client] = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(timeout=self.timeout_seconds)
        return self._client

    def close(self) -> None:
        if self._client and not self._client.is_closed:
            self._client.close()

    def _rpc_call(self, method: str, params: list, retries: int = 3) -> Optional[Any]:
        """
        Low-level JSON-RPC request with bounded exponential backoff for rate limits.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }

        backoff = 0.1
        for attempt in range(retries):
            try:
                resp = self.client.post(self.rpc_url, json=payload)
                if resp.status_code == 429:
                    if attempt == retries - 1:
                        raise RpcRateLimitError(f"RPC Provider rate limited after {retries} retries")
                    time.sleep(backoff)
                    backoff *= 2
                    continue

                if resp.status_code != 200:
                    logger.debug(f"RPC HTTP error {resp.status_code}: {resp.text}")
                    return None

                res_json = resp.json()
                if "error" in res_json:
                    err_msg = str(res_json["error"])
                    if "rate limit" in err_msg.lower() or "too many requests" in err_msg.lower():
                        if attempt == retries - 1:
                            raise RpcRateLimitError(err_msg)
                        time.sleep(backoff)
                        backoff *= 2
                        continue
                    logger.debug(f"RPC error response: {res_json['error']}")
                    return None

                return res_json.get("result")
            except httpx.RequestError as exc:
                logger.debug(f"RPC connection error on {method}: {exc}")
                if attempt == retries - 1:
                    return None
                time.sleep(backoff)
                backoff *= 2

        return None

    def get_block_number(self) -> Optional[int]:
        """Fetch current block height."""
        result = self._rpc_call("eth_blockNumber", [])
        if result:
            return int(result, 16)
        return None

    def get_block_by_number(self, block_number: int | str) -> Optional[Dict[str, Any]]:
        """Fetch block header by block number (int or hex/tag)."""
        tag = hex(block_number) if isinstance(block_number, int) else block_number
        result = self._rpc_call("eth_getBlockByNumber", [tag, False])
        if result and isinstance(result, dict):
            return {
                "number": int(result.get("number", "0x0"), 16),
                "hash": result.get("hash", ""),
                "parent_hash": result.get("parentHash", ""),
                "timestamp": int(result.get("timestamp", "0x0"), 16),
            }
        return None

    def get_block_by_hash(self, block_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch block header by block hash."""
        result = self._rpc_call("eth_getBlockByHash", [block_hash, False])
        if result and isinstance(result, dict):
            return {
                "number": int(result.get("number", "0x0"), 16),
                "hash": result.get("hash", ""),
                "parent_hash": result.get("parentHash", ""),
                "timestamp": int(result.get("timestamp", "0x0"), 16),
            }
        return None

    def get_code(self, contract_address: str, block_tag: str = "latest") -> str:
        """Fetch deployed bytecode at contract address."""
        result = self._rpc_call("eth_getCode", [contract_address, block_tag])
        return result or "0x"

    def is_connected(self) -> bool:
        """Check if local or remote Ethereum node is active."""
        return self.get_block_number() is not None

    def get_contract_logs(
        self,
        contract_address: Optional[str] = None,
        from_block: str = "0x0",
        to_block: str = "latest",
        topics: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch event logs emitted by a specific contract address or addresses.
        """
        filter_params: Dict[str, Any] = {
            "fromBlock": from_block,
            "toBlock": to_block,
        }
        if contract_address:
            filter_params["address"] = contract_address
        if topics:
            filter_params["topics"] = topics

        result = self._rpc_call("eth_getLogs", [filter_params])
        return result or []

    def get_node_health(self) -> Dict[str, Any]:
        """Summary of blockchain connectivity."""
        block = self.get_block_number()
        connected = block is not None
        return {
            "connected": connected,
            "rpc_url": self.rpc_url,
            "current_block": block if connected else None,
            "status": "ONLINE" if connected else "OFFLINE",
        }


# Singleton listener instance
blockchain_listener = BlockchainListener()
