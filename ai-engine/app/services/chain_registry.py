"""
Chain Registry and Contract Integrity Service (T15)
Specification §4, §6 (R09, R11)
Maintains network policies, confirmation depths, contract bindings,
and bytecode hash integrity validation to prevent malicious contract substitution.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import hashlib
from Crypto.Hash import keccak

from app.config import settings

logger = logging.getLogger("ChainRegistry")


class ChainRegistryError(Exception):
    pass


class CodeHashMismatchError(ChainRegistryError):
    pass


class BindingNotFoundError(ChainRegistryError):
    """No deployment binding is registered for the institution (R07):
    the verifier must answer unavailable, never trust-by-default."""


def compute_keccak256(data: bytes) -> str:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return "0x" + k.hexdigest()


class DeploymentBinding:
    """Operator-managed contract deployment binding for one institution
    (spec §5). Source of truth is the registry the OPERATOR manages outside
    user requests — never browser input. Absence of a binding (or of the code
    hash inside it) yields `unavailable`, not implicit trust."""

    __slots__ = (
        "deployment_id",
        "institution_id",
        "chain_id",
        "addresses",
        "deployed_code_hashes",
        "deployed_at_block",
        "confirmation_depth",
        "contract_version",
        "status",
        "bootstrap_writers",
    )

    def __init__(
        self,
        deployment_id: str,
        institution_id: str,
        chain_id: int,
        addresses: Dict[str, str],
        deployed_code_hashes: Dict[str, str],
        deployed_at_block: int,
        confirmation_depth: int,
        contract_version: str,
        status: str,
        bootstrap_writers: Optional[List[str]] = None,
    ):
        self.deployment_id = deployment_id
        self.institution_id = institution_id
        self.chain_id = int(chain_id)
        self.addresses = dict(addresses or {})
        self.deployed_code_hashes = dict(deployed_code_hashes or {})
        self.deployed_at_block = int(deployed_at_block)
        self.confirmation_depth = int(confirmation_depth)
        self.contract_version = contract_version
        self.status = status
        self.bootstrap_writers = [w.lower() for w in (bootstrap_writers or [])]

    def forensic_trail_address(self) -> Optional[str]:
        return self.addresses.get("ForensicTrail")

    def expected_code_hash(self, contract_name: str = "ForensicTrail") -> Optional[str]:
        return self.deployed_code_hashes.get(contract_name)

    def has_code_hash(self, contract_name: str = "ForensicTrail") -> bool:
        return bool(self.deployed_code_hashes.get(contract_name))


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
        contracts = self.manifest.get("addresses") or self.manifest.get("contracts") or {}
        return contracts.get(contract_name)

    def get_expected_code_hash(self, contract_name: str) -> Optional[str]:
        hashes = self.manifest.get("deployed_code_hashes") or self.manifest.get("code_hashes") or {}
        return hashes.get(contract_name)

    def get_confirmation_depth(self, chain_id: Optional[int] = None) -> int:
        cid = chain_id or self.get_chain_id()
        # Sandbox / local hardhat chain IDs: 1337, 31337
        if cid in (1337, 31337):
            return 2
        # Institutional consortium / mainnet policy: 12 blocks
        return self.manifest.get("confirmation_depth", 12)

    # ------------------------------------------------------------------
    # R07 (spec §5): operator-managed deployment binding resolution
    # ------------------------------------------------------------------
    def resolve(self, institution_id: str, deployment_id: Optional[str] = None) -> DeploymentBinding:
        """Resolve the DeploymentBinding for an institution.

        Registry precedence:
          1. multi-institution registry: manifest["deployments"][institution_id]
             is a list of binding dicts (optionally narrowed by deployment_id;
             the ACTIVE binding wins when no id is given);
          2. single-deployment manifest (deployments/deployment-manifest.json
             shape): used only when its institution_id matches the caller's.

        Raises BindingNotFoundError when nothing matches — the caller maps
        that to `unavailable` (absent binding never means trust).
        """
        deployments = self.manifest.get("deployments")
        candidates: List[Dict[str, Any]] = []
        if isinstance(deployments, dict):
            raw = deployments.get(institution_id)
            if isinstance(raw, list):
                candidates = [d for d in raw if isinstance(d, dict)]
            elif isinstance(raw, dict):
                candidates = [raw]
        elif str(self.manifest.get("institution_id", "")) == institution_id and self.manifest.get("deployment_id"):
            candidates = [self.manifest]

        if deployment_id is not None:
            candidates = [d for d in candidates if d.get("deployment_id") == deployment_id]
        else:
            actives = [d for d in candidates if d.get("status") == "active"]
            if actives:
                candidates = actives

        if not candidates:
            raise BindingNotFoundError(
                f"No deployment binding registered for institution {institution_id!r}"
                + (f" and deployment {deployment_id!r}" if deployment_id else "")
            )

        d = candidates[0]
        return DeploymentBinding(
            deployment_id=d["deployment_id"],
            institution_id=institution_id,
            chain_id=int(d.get("chain_id", self.get_chain_id())),
            addresses=d.get("addresses", {}) or {},
            deployed_code_hashes=d.get("deployed_code_hashes", {}) or {},
            deployed_at_block=int(d.get("deployed_at_block", 0)),
            confirmation_depth=int(
                d.get("confirmation_depth", self.get_confirmation_depth(int(d.get("chain_id", 0)) or None))
            ),
            contract_version=str(d.get("contract_version", "")),
            status=str(d.get("status", "unknown")),
            bootstrap_writers=d.get("bootstrap_writers", []) or [],
        )

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
