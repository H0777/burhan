// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IRoleManager
 * @notice Interface for the RoleManager contract
 */
interface IRoleManager {
    enum Role { NONE, SUPER_ADMIN, AUDITOR, OPERATOR, REGULATOR }

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

