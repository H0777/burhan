from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
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


# ---------------------------------------------------------------------------
# V3 verification contract (R07, spec §5 — FINAL)
# ---------------------------------------------------------------------------

class VerifyEvidenceRequest(BaseModel):
    """POST /api/v3/evidence/verify body.

    String identifiers reference EvidenceObject rows; the browser NEVER
    supplies entries, chain_id or contract_address (extra="forbid" makes any
    such attempt a 422). On-chain uint256 values are resolved from the
    database/chain and emitted as decimal STRINGS.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    case_id: str = Field(..., alias="caseId")
    evidence_ids: List[str] = Field(..., alias="evidenceIds")
    snapshot_id: Optional[str] = Field(default=None, alias="snapshotId")

    @field_validator("case_id")
    @classmethod
    def _case_required(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("case_id must be a non-empty string")
        return v

    @field_validator("evidence_ids")
    @classmethod
    def _evidence_ids_required(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("evidence_ids must contain at least one evidence identifier")
        seen = set()
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("every evidence id must be a non-empty string")
            if item in seen:
                raise ValueError(f"duplicate evidence id in request: {item}")
            seen.add(item)
        return v


class VerificationResult(BaseModel):
    """Verification outcome — status is strictly tri-state; `unavailable` is
    never mixed with `verified`. Reason codes (stable strings) live in
    `reasons` (e.g. snapshot_reorged, historical_logs_unavailable,
    legacy_unattested, chain_generated_unattested,
    historical_key_time_unproven)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: Literal["verified", "invalid", "unavailable"]
    reasons: List[str] = Field(default_factory=list)
    snapshot_id: Optional[str] = Field(default=None, alias="snapshotId")
    checked_evidence_ids: List[str] = Field(default_factory=list, alias="checkedEvidenceIds")
    deployment_id: Optional[str] = Field(default=None, alias="deploymentId")


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
