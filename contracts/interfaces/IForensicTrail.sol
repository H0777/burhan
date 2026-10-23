// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libraries/EvidenceHashing.sol";

/**
 * @title IForensicTrail
 * @notice Interface for the ForensicTrail contract (V2)
 */
interface IForensicTrail {
    function setEvidenceWriter(address _writer, bool _authorized) external;
    function isEvidenceWriter(address _writer) external view returns (bool);
    function governance() external view returns (address);
    function createIncident(bytes32 _titleHash, bytes32 _severityHash) external returns (uint256);

    /// @notice R03: manifest commitment anchored atomically with an attested
    ///         evidence submission (spec §6)
    event EvidenceManifestAnchored(
        bytes32 indexed requestId,
        uint256 indexed evidenceId,
        bytes32 manifestDigest
    );

    function submitEvidence(
        uint256 _incidentId,
        bytes32 _anchorRequestId,
        bytes32 _evidenceTypeHash,
        bytes32 _descriptionHash,
        bytes32 _fileSha256
    ) external returns (uint256 evidenceId);

    /// @notice R03: attested submission with requestId -> manifestDigest binding
    function submitEvidenceAttested(
        uint256 _incidentId,
        bytes32 _requestId,
        bytes32 _typeHash,
        bytes32 _descriptionHash,
        bytes32 _fileSha256,
        bytes32 _manifestDigest
    ) external returns (uint256 evidenceId);

    /// @notice R03: manifest digest anchored for a requestId (0 = none)
    function getManifestDigest(bytes32 _requestId) external view returns (bytes32);

    /// @notice R03: incident for an institution-wide case reference
    ///         (idempotent per reference; conflicting metadata reverts)
    function createIncidentForCase(
        bytes32 _caseReferenceHash,
        bytes32 _titleHash,
        bytes32 _severityHash
    ) external returns (uint256 incidentId);

    /// @notice R03: incident bound to a case reference (0 = unknown reference)
    function getIncidentByCaseReference(bytes32 _caseReferenceHash) external view returns (uint256);

    function getEvidenceByRequestId(bytes32 _anchorRequestId)
        external
        view
        returns (
            uint256 evidenceId,
            bytes32 entryHash,
            address submittedBy,
            bool exists
        );
    function closeIncident(uint256 _incidentId) external;
    function verifyChainIntegrity(uint256 _incidentId) external view returns (bool);
    function totalIncidents() external view returns (uint256);
    function totalEvidence() external view returns (uint256);
}
