// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceHashing
 * @notice Standardized hashing library for digital forensic evidence entries (Evidence V2)
 * @dev Conforms strictly to Three-Track Architecture Specification §6.
 */
library EvidenceHashing {
    bytes32 public constant DOMAIN = keccak256("CYBER_AUDIT_EVIDENCE_V2");
    uint16 public constant SCHEMA_VERSION = 2;

    struct EvidenceV2 {
        uint16 schemaVersion;
        uint256 chainId;
        address contractAddress;
        uint256 incidentId;
        uint256 evidenceId;
        address submittedBy;
        uint256 timestamp;
        bytes32 evidenceTypeHash;
        bytes32 descriptionHash;
        bytes32 evidenceHash;       // SHA-256 hash of off-chain payload/file
        bytes32 previousEntryHash;
    }

    /**
     * @notice Computes the canonical V2 entry hash
     * @dev abi.encode with 12 strict positional parameters as defined in Design Spec §6:
     *      (DOMAIN, 2, chain_id, contract_address, incident_id, evidence_id,
     *       submitted_by, timestamp, evidence_type_hash, description_hash, evidence_hash, previous_entry_hash)
     */
    function hashEntry(EvidenceV2 memory entry) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN,
                uint16(2),
                entry.chainId,
                entry.contractAddress,
                entry.incidentId,
                entry.evidenceId,
                entry.submittedBy,
                entry.timestamp,
                entry.evidenceTypeHash,
                entry.descriptionHash,
                entry.evidenceHash,
                entry.previousEntryHash
            )
        );
    }
}
