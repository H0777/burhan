import { ethers } from "ethers";

export const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("CYBER_AUDIT_EVIDENCE_V2"));
export const SCHEMA_VERSION = 2;

const abiCoder = new ethers.AbiCoder();
const TYPES = [
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
  "bytes32"
];

/**
 * Computes canonical Evidence V2 entry hash
 * @param {Object} entry EvidenceV2 record (accepts camelCase or snake_case)
 * @returns {string} 0x-prefixed 32-byte hex hash string
 */
export function hashEvidence(entry) {
  const chainId = entry.chainId ?? entry.chain_id;
  const contractAddress = entry.contractAddress ?? entry.contract_address;
  const incidentId = entry.incidentId ?? entry.incident_id;
  const evidenceId = entry.evidenceId ?? entry.evidence_id;
  const submittedBy = entry.submittedBy ?? entry.submitted_by;
  const timestamp = entry.timestamp;
  const evidenceTypeHash = entry.evidenceTypeHash ?? entry.evidence_type_hash;
  const descriptionHash = entry.descriptionHash ?? entry.description_hash;
  const evidenceHash = entry.evidenceHash ?? entry.evidence_hash;
  const previousEntryHash = entry.previousEntryHash ?? entry.previous_entry_hash;

  const values = [
    DOMAIN,
    2,
    BigInt(chainId),
    contractAddress,
    BigInt(incidentId),
    BigInt(evidenceId),
    submittedBy,
    BigInt(timestamp),
    evidenceTypeHash,
    descriptionHash,
    evidenceHash,
    previousEntryHash
  ];

  const encoded = abiCoder.encode(TYPES, values);
  return ethers.keccak256(encoded);
}
