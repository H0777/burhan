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
    function submitEvidence(
        uint256 _incidentId,
        bytes32 _anchorRequestId,
        bytes32 _evidenceTypeHash,
        bytes32 _descriptionHash,
        bytes32 _fileSha256
    ) external returns (uint256 evidenceId);
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
