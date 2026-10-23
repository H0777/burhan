from typing import Optional, List, Dict, Any
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
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int = Field(default=2, alias="schemaVersion")
    chain_id: int = Field(..., alias="chainId")
    contract_address: str = Field(..., alias="contractAddress")
    incident_id: int = Field(..., alias="incidentId")
    evidence_id: int = Field(..., alias="evidenceId")
    submitted_by: str = Field(..., alias="submittedBy")
    timestamp: int
    evidence_type_hash: str = Field(..., alias="evidenceTypeHash")
    description_hash: str = Field(..., alias="descriptionHash")
    evidence_hash: str = Field(..., alias="evidenceHash")
    previous_entry_hash: str = Field(..., alias="previousEntryHash")
    entry_hash: Optional[str] = Field(default=None, alias="entryHash")


class SnapshotInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    block_number: Optional[int] = Field(default=None, alias="blockNumber")
    block_hash: Optional[str] = Field(default=None, alias="blockHash")


class EvidenceVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    case_id: Optional[int] = Field(default=None, alias="caseId")
    incident_id: int = Field(..., alias="incidentId")
    evidence_ids: Optional[List[int]] = Field(default=None, alias="evidenceIds")
    schema_version: int = Field(default=2, alias="schemaVersion")
    chain_id: Optional[int] = Field(default=1337, alias="chainId")
    contract_address: Optional[str] = Field(default=None, alias="contractAddress")
    entries: List[EvidenceV2] = Field(default_factory=list)
    snapshot: Optional[SnapshotInfo] = None


class AnchorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    chain_id: Optional[int] = Field(default=None, alias="chainId")
    contract_address: Optional[str] = Field(default=None, alias="contractAddress")
    count: Optional[int] = None
    head: Optional[str] = None
    block_number: Optional[int] = Field(default=None, alias="blockNumber")
    block_hash: Optional[str] = Field(default=None, alias="blockHash")


class EvidenceVerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: str = Field(..., description="'verified' | 'invalid' | 'unavailable'")
    provenance_status: str = Field(default="unknown")
    checked_entries: List[EvidenceV2] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    block_number: Optional[int] = Field(default=None)
    block_hash: Optional[str] = Field(default=None)
    anchor: Optional[AnchorInfo] = None
    source: Optional[str] = Field(default="registry_trusted_contract")


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
