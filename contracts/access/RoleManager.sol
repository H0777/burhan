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
 *
 * Participant identity (R02, spec §4):
 *   A participant is a fixed institutional bytes32 identity with exactly ONE
 *   active wallet. Identity comes only from governance enrollment — assignRole
 *   never mints address-derived identities. Wallet rotation retires the old
 *   wallet permanently: it keeps its historical binding (forensic attribution)
 *   and can never be re-bound to another person. A participant's authorization
 *   generation strictly increases on every grant/revoke/rotation and is carried
 *   in the emitted events. The person↔participantId mapping is held off-chain
 *   in institutional membership records.
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

    struct Participant {
        address wallet;      // current active wallet (exactly one per identity)
        Role role;           // current role of the identity
        uint256 generation;  // identity-scope generation, only increases
        bool enrolled;       // identity exists (enrollment is irreversible)
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

    /// @notice Institutional identity registry: participantId => participant record
    mapping(bytes32 => Participant) private _participants;
    bytes32[] private _allParticipantIds;

    /// @notice Permanent wallet → participantId binding.
    /// @dev Retains rotated-away wallets forever: historical attribution is kept
    ///      and a retired wallet can never be re-bound to another identity.
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
        uint256 timestamp,
        bytes32 participantId,
        uint256 generation
    );

    event RoleRevoked(
        address indexed target,
        Role indexed previousRole,
        address indexed revokedBy,
        string reason,
        uint256 timestamp,
        bytes32 participantId,
        uint256 generation
    );

    event ParticipantEnrolled(
        bytes32 indexed participantId,
        address indexed wallet,
        Role indexed role,
        uint256 generation,
        address enrolledBy,
        string reason,
        uint256 timestamp
    );

    event WalletRotated(
        bytes32 indexed participantId,
        address indexed oldWallet,
        address indexed newWallet,
        uint256 generation,
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
        // Temporary bootstrap role for the deployer (dropped by MultiSigApproval
        // at finalizeBootstrap unless the deployer is explicitly enrolled in the
        // roster). No participantId is minted here: identity comes only from
        // enrollment.
        _roles[msg.sender] = Role.SUPER_ADMIN;
        _generations[msg.sender] = 1;
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
            block.timestamp,
            bytes32(0),
            1
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
     * @notice Enroll an institutional participant with a fixed identity (governance only)
     * @dev The only identity-minting entry point. One active wallet per identity;
     *      ids and wallets must be unique and non-zero.
     * @param _participantId Fixed institutional identity (off-chain roster value)
     * @param _wallet The single active wallet of the participant
     * @param _role The role granted at enrollment (must not be NONE)
     * @param _reason Audit reason for the enrollment
     */
    function enrollParticipant(
        bytes32 _participantId,
        address _wallet,
        Role _role,
        string calldata _reason
    ) external onlyGovernance {
        require(_participantId != bytes32(0), "RoleManager: zero participant id");
        require(_wallet != address(0), "RoleManager: invalid address");
        require(!_participants[_participantId].enrolled, "RoleManager: participant already enrolled");
        require(_participantIds[_wallet] == bytes32(0), "RoleManager: wallet already bound");
        require(_role != Role.NONE, "RoleManager: use revokeRole to remove roles");

        _participants[_participantId] = Participant({
            wallet: _wallet,
            role: _role,
            generation: 1,
            enrolled: true
        });
        _allParticipantIds.push(_participantId);
        _participantIds[_wallet] = _participantId;

        _roles[_wallet] = _role;
        _generations[_wallet] = 1;
        if (!_isMember[_wallet]) {
            _allMembers.push(_wallet);
            _isMember[_wallet] = true;
        }

        _roleHistory[_wallet].push(RoleChange({
            previousRole: Role.NONE,
            newRole: _role,
            changedBy: msg.sender,
            timestamp: block.timestamp,
            reason: _reason
        }));

        emit ParticipantEnrolled(
            _participantId,
            _wallet,
            _role,
            1,
            msg.sender,
            _reason,
            block.timestamp
        );
    }

    /**
     * @notice Rotate the active wallet of a participant (governance only)
     * @dev Retires the old wallet permanently (role cleared, binding kept) and
     *      moves the identity to `newWallet` with a strictly increased generation.
     * @param _participantId Fixed institutional identity
     * @param _newWallet The replacement wallet (must never have been bound)
     * @param _reason Audit reason for the rotation
     */
    function rotateParticipantWallet(
        bytes32 _participantId,
        address _newWallet,
        string calldata _reason
    ) external onlyGovernance {
        require(_participantId != bytes32(0), "RoleManager: zero participant id");
        require(_newWallet != address(0), "RoleManager: invalid address");
        Participant storage participant = _participants[_participantId];
        require(participant.enrolled, "RoleManager: unknown participant");
        require(_newWallet != participant.wallet, "RoleManager: wallet already active");
        require(_participantIds[_newWallet] == bytes32(0), "RoleManager: wallet already bound");

        address oldWallet = participant.wallet;

        participant.generation++;
        participant.wallet = _newWallet;

        // Old wallet: role cleared, historical binding intentionally retained.
        _participantIds[_newWallet] = _participantId;
        _roles[oldWallet] = Role.NONE;
        _roles[_newWallet] = participant.role;
        _generations[_newWallet] = participant.generation;
        if (!_isMember[_newWallet]) {
            _allMembers.push(_newWallet);
            _isMember[_newWallet] = true;
        }

        emit WalletRotated(
            _participantId,
            oldWallet,
            _newWallet,
            participant.generation,
            _reason,
            block.timestamp
        );
    }

    /**
     * @notice Assign a role to an enrolled participant's active wallet (governance only)
     * @dev Identity comes only from enrollment: assigning to an un-enrolled
     *      address or a rotated-away wallet reverts.
     * @param _target The active wallet of an enrolled participant
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

        bytes32 participantId = _participantIds[_target];
        require(participantId != bytes32(0), "RoleManager: target not enrolled");
        Participant storage participant = _participants[participantId];
        require(participant.wallet == _target, "RoleManager: wallet not active for participant");

        Role previousRole = _roles[_target];
        _roles[_target] = _role;
        participant.role = _role;
        participant.generation++;
        _generations[_target] = participant.generation;

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

        emit RoleAssigned(_target, _role, msg.sender, _reason, block.timestamp, participantId, participant.generation);
    }

    /**
     * @notice Revoke a role from an address (set to NONE, governance only)
     * @dev Works for enrolled active wallets and for the temporary deployer role.
     *      Enrollment (identity binding) is never removed — only privileges.
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

        bytes32 participantId = _participantIds[_target];
        if (
            participantId != bytes32(0) &&
            _participants[participantId].enrolled &&
            _participants[participantId].wallet == _target
        ) {
            Participant storage participant = _participants[participantId];
            participant.role = Role.NONE;
            participant.generation = _generations[_target];
        }

        _roleHistory[_target].push(RoleChange({
            previousRole: previousRole,
            newRole: Role.NONE,
            changedBy: msg.sender,
            timestamp: block.timestamp,
            reason: _reason
        }));

        emit RoleRevoked(_target, previousRole, msg.sender, _reason, block.timestamp, participantId, _generations[_target]);
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
     * @notice Count distinct ENROLLED identities eligible to vote in governance
     * @dev Eligible = active SUPER_ADMIN or AUDITOR identity. OPERATOR/REGULATOR
     *      identities and the un-enrolled deployer's temporary role never count.
     */
    function countEligibleParticipants() external view returns (uint256 count) {
        for (uint256 i = 0; i < _allParticipantIds.length; i++) {
            Participant storage participant = _participants[_allParticipantIds[i]];
            if (
                participant.enrolled &&
                participant.role != Role.NONE &&
                (participant.role == Role.SUPER_ADMIN || participant.role == Role.AUDITOR)
            ) {
                count++;
            }
        }
    }

    /**
     * @notice Get the single active wallet of a participant identity
     * @return The active wallet, or address(0) if the identity is unknown or
     *         currently holds no role.
     */
    function getActiveWallet(bytes32 _participantId) external view returns (address) {
        Participant storage participant = _participants[_participantId];
        if (!participant.enrolled || participant.role == Role.NONE) {
            return address(0);
        }
        return participant.wallet;
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
     * @dev Tuple semantics:
     *      - Active wallet of an enrolled identity → its institutional id,
     *        the identity's current generation, its role, active=true.
     *      - Rotated-away wallet → the SAME historical id (attribution kept),
     *        the wallet's stale generation, Role.NONE, active=false.
     *      - Un-enrolled address → id bytes32(0), the address's local
     *        generation, its raw role, active=(role != NONE). This preserves
     *        the pre-R02 shape for unknown addresses (default 0, 0, NONE, false)
     *        and for the temporary deployer role until finalization.
     */
    function getParticipant(address _addr) external view returns (
        bytes32 participantId,
        uint256 generation,
        Role role,
        bool active
    ) {
        participantId = _participantIds[_addr];
        if (participantId != bytes32(0)) {
            Participant storage participant = _participants[participantId];
            if (participant.wallet == _addr) {
                return (
                    participantId,
                    participant.generation,
                    participant.role,
                    participant.role != Role.NONE
                );
            }
            // Retired wallet: historical binding, permanently inactive.
            return (participantId, _generations[_addr], Role.NONE, false);
        }
        return (bytes32(0), _generations[_addr], _roles[_addr], _roles[_addr] != Role.NONE);
    }
}
