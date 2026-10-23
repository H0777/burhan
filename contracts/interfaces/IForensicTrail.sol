// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IForensicTrail
 * @notice Interface for the ForensicTrail contract
 */
interface IForensicTrail {
    function setEvidenceWriter(address _writer, bool _authorized) external;
    function isEvidenceWriter(address _writer) external view returns (bool);
    function governance() external view returns (address);
    function createIncident(string calldata _title, string calldata _severity) external returns (uint256);
    function submitEvidence(uint256 _incidentId, string calldata _evidenceType, string calldata _description, bytes32 _evidenceHash) external returns (uint256);
    function closeIncident(uint256 _incidentId) external;
    function verifyChainIntegrity(uint256 _incidentId) external view returns (bool);
    function totalIncidents() external view returns (uint256);
    function totalEvidence() external view returns (uint256);
}

