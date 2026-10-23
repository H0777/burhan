from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
import eth_abi
from eth_hash.auto import keccak

DOMAIN_BYTES = keccak(b"CYBER_AUDIT_EVIDENCE_V2")
DOMAIN = "0x" + DOMAIN_BYTES.hex()
SCHEMA_VERSION = 2

ABI_TYPES = [
    "bytes32",
    "uint16",
    "uint256",
    "address",
    "uint256",
    "uint256",
    "address",
    "uint256",
    "bytes32",
    "bytes32",
    "bytes32",
    "bytes32",
]


class EvidenceV2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=2)
    chain_id: int
    contract_address: str
    incident_id: int
    evidence_id: int
    submitted_by: str
    timestamp: int
    evidence_type_hash: str
    description_hash: str
    evidence_hash: str
    previous_entry_hash: str
    entry_hash: Optional[str] = None


def _to_bytes32(val: str) -> bytes:
    clean = val[2:] if val.startswith("0x") else val
    return bytes.fromhex(clean.zfill(64))


def hash_entry(entry: EvidenceV2) -> str:
    """
    Computes canonical Evidence V2 entry hash via keccak256(abi.encode(...)).
    Conforms strictly to Specification §6.
    """
    values = [
        DOMAIN_BYTES,
        2,
        entry.chain_id,
        entry.contract_address,
        entry.incident_id,
        entry.evidence_id,
        entry.submitted_by,
        entry.timestamp,
        _to_bytes32(entry.evidence_type_hash),
        _to_bytes32(entry.description_hash),
        _to_bytes32(entry.evidence_hash),
        _to_bytes32(entry.previous_entry_hash),
    ]
    encoded = eth_abi.encode(ABI_TYPES, values)
    entry_hash = keccak(encoded)
    return "0x" + entry_hash.hex()
