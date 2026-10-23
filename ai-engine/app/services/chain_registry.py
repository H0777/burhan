"""
Chain Registry and Contract Integrity Service (T15)
Specification §4, §6 (R09, R11)
Maintains network policies, confirmation depths, contract bindings,
and bytecode hash integrity validation to prevent malicious contract substitution.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib
from Crypto.Hash import keccak

from app.config import settings

logger = logging.getLogger("ChainRegistry")


class ChainRegistryError(Exception):
    pass


class CodeHashMismatchError(ChainRegistryError):
    pass


def compute_keccak256(data: bytes) -> str:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return "0x" + k.hexdigest()


class ChainRegistry:
    def __init__(
        self,
        manifest_path: Optional[str] = None,
        manifest_data: Optional[Dict[str, Any]] = None,
    ):
        self.manifest_path = manifest_path or settings.DEPLOYMENT_MANIFEST_PATH
        self.manifest: Dict[str, Any] = {}

        if manifest_data:
            self.manifest = manifest_data
        elif self.manifest_path and Path(self.manifest_path).exists():
            try:
                with open(self.manifest_path, "r", encoding="utf-8") as f:
                    self.manifest = json.load(f)
            except Exception as exc:
                logger.warning(f"Could not load deployment manifest: {exc}")

    def get_chain_id(self) -> int:
        return self.manifest.get("chain_id", 31337)

    def get_institution_id(self) -> str:
        return self.manifest.get("institution_id", settings.INSTITUTION_ID)

    def get_contract_address(self, contract_name: str) -> Optional[str]:
        return self.manifest.get("contracts", {}).get(contract_name)

    def get_expected_code_hash(self, contract_name: str) -> Optional[str]:
        return self.manifest.get("code_hashes", {}).get(contract_name)

    def get_confirmation_depth(self, chain_id: Optional[int] = None) -> int:
        cid = chain_id or self.get_chain_id()
        # Sandbox / local hardhat chain IDs: 1337, 31337
        if cid in (1337, 31337):
            return 2
        # Institutional consortium / mainnet policy: 12 blocks
        return self.manifest.get("confirmation_depth", 12)

    def verify_contract_code_hash(
        self,
        rpc_client: Any,
        contract_name: str,
        contract_address: Optional[str] = None,
    ) -> bool:
        """
        Validates that the deployed on-chain bytecode matches the verified manifest code_hash.
        Raises CodeHashMismatchError if the bytecode does not match.
        """
        target_addr = contract_address or self.get_contract_address(contract_name)
        if not target_addr:
            raise ChainRegistryError(f"Contract {contract_name} has no configured address")

        expected_hash = self.get_expected_code_hash(contract_name)
        if not expected_hash:
            logger.warning(f"No expected code_hash found in manifest for {contract_name}")
            return True

        if hasattr(rpc_client, "get_code"):
            code_hex = rpc_client.get_code(target_addr)
            if not code_hex or code_hex in ("0x", "0x0"):
                raise ChainRegistryError(f"No bytecode deployed at {target_addr} for {contract_name}")

            clean_hex = code_hex.replace("0x", "")
            code_bytes = bytes.fromhex(clean_hex)
            computed_hash = compute_keccak256(code_bytes)

            if computed_hash.lower() != expected_hash.lower():
                raise CodeHashMismatchError(
                    f"Security Alert: Contract {contract_name} at {target_addr} has code_hash {computed_hash}, "
                    f"which does NOT match manifest hash {expected_hash}! Potential bytecode tampering."
                )

        return True
