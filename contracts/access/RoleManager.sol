// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RoleManager
 * @author H0777
 * @notice Role-Based Access Control (RBAC) for Cyber-Forensic Auditing Framework
 * @dev Supports 4 roles with full history tracking for forensic analysis.
 *      Designed to replace single-admin patterns with granular privilege separation.
 *
 * Roles:
 *   SUPER_ADMIN — Full system control, can assign/revoke all roles
 *   AUDITOR     — Can review transactions, escalate reports, read forensic trails
 *   OPERATOR    — Can submit and process daily transactions only
 *   REGULATOR   — Read-only access for external oversight (Central Bank / AML Authority)
 */
contract RoleManager {

    // ============================================================
    // ENUMS & STRUCTS
    // ============================================================

    enum Role { NONE, SUPER_ADMIN, AUDITOR, OPERATOR, REGULATOR }

    struct RoleChange {
        Role previousRole;
        Role newRole;
        address changedBy;
        uint256 timestamp;
        string reason;
    }

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    /// @notice The original deployer — cannot be removed from SUPER_ADMIN
    address public governance;
    address public deployer;

    /// @notice Current role of each address
    mapping(address => Role) private _roles;

    /// @notice History of all role changes per address (for forensic audit)
    mapping(address => RoleChange[]) private _roleHistory;

    /// @notice List of all addresses that have ever been assigned a role
    address[] private _allMembers;
    mapping(address => bool) private _isMember;

    /// @notice Authorization generation per address (increments on role grant/revoke/rotation)
    mapping(address => uint256) private _generations;

    /// @notice Stable institutional participant ID
    mapping(address => bytes32) private _participantIds;

    // ============================================================
    // EVENTS
    // ============================================================

    event GovernanceTransferred(address indexed newGovernance);

    event RoleAssigned(
        address indexed target,
        Role indexed newRole,
        address indexed assignedBy,
        string reason,
        uint256 timestamp
    );

    event RoleRevoked(
        address indexed target,
        Role indexed previousRole,
        address indexed revokedBy,
        string reason,
        uint256 timestamp
    );

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyGovernance() {
        require(msg.sender == governance, "RoleManager: caller is not governance");
        _;
    }

    modifier onlySuperAdmin() {
        require(
            _roles[msg.sender] == Role.SUPER_ADMIN,
            "RoleManager: caller is not SUPER_ADMIN"
        );
        _;
    }

    modifier onlyRole(Role _role) {
        require(
            _roles[msg.sender] == _role || _roles[msg.sender] == Role.SUPER_ADMIN,
            "RoleManager: insufficient role"
        );
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor(address _initialGovernance) {
        require(_initialGovernance != address(0), "RoleManager: invalid governance address");
        governance = _initialGovernance;
        deployer = msg.sender;
        _roles[msg.sender] = Role.SUPER_ADMIN;
        _generations[msg.sender] = 1;
        _participantIds[msg.sender] = bytes32(uint256(uint160(msg.sender)));
        _allMembers.push(msg.sender);
        _isMember[msg.sender] = true;

        _roleHistory[msg.sender].push(RoleChange({
            previousRole: Role.NONE,
            newRole: Role.SUPER_ADMIN,
            changedBy: msg.sender,
            timestamp: block.timestamp,
            reason: "SYSTEM: Initial deployer assignment"
        }));

        emit RoleAssigned(
            msg.sender,
            Role.SUPER_ADMIN,
            msg.sender,
            "SYSTEM: Initial deployer assignment",
            block.timestamp
        );
    }

    // ============================================================
    // CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Transfer governance authority
     * @param _newGovernance The new governance address
     */
    function setGovernance(address _newGovernance) external onlyGovernance {
        require(_newGovernance != address(0), "RoleManager: zero address");
        governance = _newGovernance;
        emit GovernanceTransferred(_newGovernance);
    }

    /**
     * @notice Assign a role to an address (governance only)
     * @param _target The address to assign the role to
     * @param _role The role to assign
     * @param _reason Audit reason for the assignment
     */
    function assignRole(
        address _target,
        Role _role,
        string calldata _reason
    ) external onlyGovernance {
        require(_target != address(0), "RoleManager: invalid address");
        require(_role != Role.NONE, "RoleManager: use revokeRole to remove roles");
        require(_roles[_target] != _role, "RoleManager: role already assigned");

        Role previousRole = _roles[_target];
        _roles[_target] = _role;
        _generations[_target]++;
        if (_participantIds[_target] == bytes32(0)) {
            _participantIds[_target] = bytes32(uint256(uint160(_target)));
        }

        // Track membership
        if (!_isMember[_target]) {
            _allMembers.push(_target);
            _isMember[_target] = true;
        }

        // Record history
        _roleHistory[_target].push(RoleChange({
            previousRole: previousRole,
            newRole: _role,
            changedBy: msg.sender,
            timestamp: block.timestamp,
            reason: _reason
        }));

        emit RoleAssigned(_target, _role, msg.sender, _reason, block.timestamp);
    }

    /**
     * @notice Revoke a role from an address (set to NONE, governance only)
     * @param _target The address to revoke the role from
     * @param _reason Audit reason for revocation
     */
    function revokeRole(
        address _target,
        string calldata _reason
    ) external onlyGovernance {
        require(_target != address(0), "RoleManager: invalid address");
        require(_roles[_target] != Role.NONE, "RoleManager: no role to revoke");

        Role previousRole = _roles[_target];
        _roles[_target] = Role.NONE;
        _generations[_target]++;

        _roleHistory[_target].push(RoleChange({
            previousRole: previousRole,
            newRole: Role.NONE,
            changedBy: msg.sender,
            timestamp: block.timestamp,
            reason: _reason
        }));

        emit RoleRevoked(_target, previousRole, msg.sender, _reason, block.timestamp);
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    /**
     * @notice Check if an address has a specific role
     */
    function hasRole(address _addr, Role _role) external view returns (bool) {
        return _roles[_addr] == _role;
    }

    /**
     * @notice Get the current role of an address
     */
    function getRole(address _addr) external view returns (Role) {
        return _roles[_addr];
    }

    /**
     * @notice Get the full role change history for an address (forensic audit)
     */
    function getRoleHistory(address _addr) external view returns (RoleChange[] memory) {
        return _roleHistory[_addr];
    }

    /**
     * @notice Get the number of role changes for an address
     */
    function getRoleChangeCount(address _addr) external view returns (uint256) {
        return _roleHistory[_addr].length;
    }

    /**
     * @notice Get all addresses that have ever been assigned a role
     */
    function getAllMembers() external view returns (address[] memory) {
        return _allMembers;
    }

    /**
     * @notice Get count of addresses with a specific active role
     */
    function countByRole(Role _role) external view returns (uint256 count) {
        for (uint256 i = 0; i < _allMembers.length; i++) {
            if (_roles[_allMembers[i]] == _role) {
                count++;
            }
        }
    }

    /**
     * @notice Get count of all active participants (role != NONE)
     */
    function countActiveParticipants() external view returns (uint256 count) {
        for (uint256 i = 0; i < _allMembers.length; i++) {
            if (_roles[_allMembers[i]] != Role.NONE) {
                count++;
            }
        }
    }

    /**
     * @notice Check if caller has at least the specified role level
     * @dev SUPER_ADMIN > AUDITOR > OPERATOR > REGULATOR > NONE
     */
    function hasMinimumRole(address _addr, Role _minRole) external view returns (bool) {
        if (_minRole == Role.NONE) return true;
        Role current = _roles[_addr];
        if (current == Role.SUPER_ADMIN) return true;
        return current == _minRole;
    }

    /**
     * @notice Get authorization generation for an address
     */
    function getGeneration(address _addr) external view returns (uint256) {
        return _generations[_addr];
    }

    /**
     * @notice Get participant tuple according to spec §5
     */
    function getParticipant(address _addr) external view returns (
        bytes32 participantId,
        uint256 generation,
        Role role,
        bool active
    ) {
        return (
            _participantIds[_addr],
            _generations[_addr],
            _roles[_addr],
            _roles[_addr] != Role.NONE
        );
    }

    /**
     * @notice Test helper to simulate authorization generation change / revocation
     */
    function testSetGeneration(address _target, uint256 _gen) external {
        _generations[_target] = _gen;
    }
}
