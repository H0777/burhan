// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IRoleManager
 * @notice Interface for the RoleManager contract
 */
interface IRoleManager {
    enum Role { NONE, SUPER_ADMIN, AUDITOR, OPERATOR, REGULATOR }

    /**
     * R02 participant identity (spec §4): identity comes only from governance
     * enrollment — a fixed institutional bytes32 id with exactly ONE active
     * wallet. Rotation retires the old wallet permanently and strictly
     * increases the identity's authorization generation.
     */
    function enrollParticipant(bytes32 participantId, address wallet, Role role, string calldata reason) external;
    function rotateParticipantWallet(bytes32 participantId, address newWallet, string calldata reason) external;
    function getActiveWallet(bytes32 participantId) external view returns (address);
    function countEligibleParticipants() external view returns (uint256);

    function assignRole(address _target, Role _role, string calldata _reason) external;
    function revokeRole(address _target, string calldata _reason) external;
    function hasRole(address _addr, Role _role) external view returns (bool);
    function getRole(address _addr) external view returns (Role);
    function getRoleChangeCount(address _addr) external view returns (uint256);
    function getAllMembers() external view returns (address[] memory);
    function countByRole(Role _role) external view returns (uint256);
    function countActiveParticipants() external view returns (uint256);
    function hasMinimumRole(address _addr, Role _minRole) external view returns (bool);
    function governance() external view returns (address);
    function getGeneration(address _addr) external view returns (uint256);
    function getParticipant(address _addr) external view returns (bytes32 participantId, uint256 generation, Role role, bool active);
}

