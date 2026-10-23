// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./RoleManager.sol";
import "../AuditEngine.sol";
import "../forensics/InsiderActivityLog.sol";
import "../forensics/ForensicTrail.sol";

/**
 * @title MultiSigApproval
 * @author H0777
 * @notice Implements the Four-Eyes Principle for high-risk financial operations
 * @dev Requires multiple authorized signers to approve sensitive actions before execution.
 *      Designed to prevent insider fraud by ensuring no single employee can authorize
 *      critical operations alone.
 *
 * Use Cases:
 *   - Overriding AML warnings on flagged transactions
 *   - Approving transactions above the multi-sig threshold
 *   - Modifying compliance policy parameters
 *   - Elevating or revoking employee roles
 */
contract MultiSigApproval {

    // ============================================================
    // ENUMS & STRUCTS
    // ============================================================

    enum ProposalStatus { PENDING, APPROVED, REJECTED, EXPIRED }

    enum ProposalType {
        OVERRIDE_WARNING,       // Override an AML/compliance warning
        HIGH_VALUE_APPROVAL,    // Approve a high-value transaction
        POLICY_CHANGE,          // Modify compliance thresholds
        ROLE_CHANGE             // Assign or revoke a role
    }

    struct Proposal {
        uint256 id;
        ProposalType proposalType;
        address proposer;
        bytes data;                 // Encoded action data
        string reason;
        uint256 createdAt;
        uint256 expiresAt;
        ProposalStatus status;
        uint256 approvalCount;
        uint256 rejectionCount;
    }

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    address public bootstrapAuthority;
    bool public isBootstrapFinalized;

    RoleManager public roleManager;
    address public auditEngine;
    address public insiderLog;
    address public forensicTrail;

    /// @notice Number of approvals required to execute a proposal
    uint256 public requiredApprovals;

    /// @notice Proposal expiry duration (default 24 hours)
    uint256 public proposalTTL;

    uint256 private _proposalCounter;

    /// @notice All proposals by ID
    mapping(uint256 => Proposal) private _proposals;

    /// @notice Track who has voted on which proposal
    mapping(uint256 => mapping(address => bool)) private _hasVoted;

    /// @notice Track individual votes (true = approve, false = reject)
    mapping(uint256 => mapping(address => bool)) private _votes;

    /// @notice All proposal IDs
    uint256[] private _allProposalIds;

    // ============================================================
    // EVENTS
    // ============================================================

    event BootstrapFinalized(uint256 timestamp);
    event ContractsConfigured(address roleManager, address auditEngine, address insiderLog, address forensicTrail);
    event ParticipantsBootstrapped(uint256 count);

    event ProposalCreated(
        uint256 indexed proposalId,
        ProposalType indexed proposalType,
        address indexed proposer,
        string reason,
        uint256 expiresAt
    );

    event ProposalApproved(
        uint256 indexed proposalId,
        address indexed approver,
        uint256 currentApprovals,
        uint256 requiredApprovals
    );

    event ProposalRejected(
        uint256 indexed proposalId,
        address indexed rejector,
        string reason
    );

    event ProposalExecuted(
        uint256 indexed proposalId,
        address indexed executedBy,
        uint256 timestamp
    );

    event ProposalExpired(
        uint256 indexed proposalId,
        uint256 timestamp
    );

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyBootstrapAuthority() {
        require(msg.sender == bootstrapAuthority && !isBootstrapFinalized, "MultiSig: caller is not bootstrap authority");
        _;
    }

    modifier whenBootstrapFinalized() {
        require(isBootstrapFinalized, "MultiSig: bootstrap not finalized");
        _;
    }

    modifier onlyAuthorized() {
        require(isBootstrapFinalized, "MultiSig: bootstrap not finalized");
        require(address(roleManager) != address(0), "MultiSig: roleManager not set");
        RoleManager.Role role = roleManager.getRole(msg.sender);
        require(
            role == RoleManager.Role.SUPER_ADMIN || role == RoleManager.Role.AUDITOR,
            "MultiSig: caller not authorized to participate"
        );
        _;
    }

    modifier proposalExists(uint256 _proposalId) {
        require(
            _proposalId > 0 && _proposalId <= _proposalCounter,
            "MultiSig: proposal does not exist"
        );
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    /**
     * @param _bootstrapAuthority Temporary authority to configure and bootstrap the system
     * @param _requiredApprovals Minimum approvals needed (must be >= 2)
     * @param _proposalTTLHours Hours before a proposal expires
     */
    constructor(
        address _bootstrapAuthority,
        uint256 _requiredApprovals,
        uint256 _proposalTTLHours
    ) {
        require(_bootstrapAuthority != address(0), "MultiSig: invalid bootstrap authority");
        require(_requiredApprovals >= 2, "MultiSig: need at least 2 approvals");
        require(_proposalTTLHours > 0, "MultiSig: TTL must be positive");

        bootstrapAuthority = _bootstrapAuthority;
        requiredApprovals = _requiredApprovals;
        proposalTTL = _proposalTTLHours * 1 hours;
        isBootstrapFinalized = false;
    }

    // ============================================================
    // BOOTSTRAP FUNCTIONS (SINGLE-USE, REVOKED PERMANENTLY)
    // ============================================================

    /**
     * @notice Link all system contracts during bootstrap phase
     */
    function configureContracts(
        address _roleManager,
        address _auditEngine,
        address _insiderLog,
        address _forensicTrail
    ) external onlyBootstrapAuthority {
        require(address(roleManager) == address(0), "MultiSig: already configured");
        require(
            _roleManager != address(0) &&
            _auditEngine != address(0) &&
            _insiderLog != address(0) &&
            _forensicTrail != address(0),
            "MultiSig: zero address"
        );
        require(_roleManager.code.length > 0, "MultiSig: RoleManager must be a contract");
        require(_auditEngine.code.length > 0, "MultiSig: AuditEngine must be a contract");
        require(_insiderLog.code.length > 0, "MultiSig: InsiderLog must be a contract");
        require(_forensicTrail.code.length > 0, "MultiSig: ForensicTrail must be a contract");

        roleManager = RoleManager(_roleManager);
        auditEngine = _auditEngine;
        insiderLog = _insiderLog;
        forensicTrail = _forensicTrail;

        AuditEngine(_auditEngine).integrateAllContracts(_roleManager, _insiderLog, _forensicTrail, address(this));
        InsiderActivityLog(_insiderLog).setRecorder(_auditEngine, true);
        ForensicTrail(_forensicTrail).setEvidenceWriter(_auditEngine, true);

        emit ContractsConfigured(_roleManager, _auditEngine, _insiderLog, _forensicTrail);
    }

    /**
     * @notice Enroll initial 4+ participants during bootstrap phase
     */
    function bootstrapParticipants(
        address[] calldata _participants,
        uint8[] calldata _roles,
        string[] calldata _reasons
    ) external onlyBootstrapAuthority {
        require(address(roleManager) != address(0), "MultiSig: contracts not configured");
        require(
            _participants.length == _roles.length && _participants.length == _reasons.length,
            "MultiSig: length mismatch"
        );
        require(_participants.length >= 4, "MultiSig: need at least 4 participants");

        for (uint256 i = 0; i < _participants.length; i++) {
            require(_participants[i] != address(0), "MultiSig: zero address participant");
            for (uint256 j = i + 1; j < _participants.length; j++) {
                require(_participants[i] != _participants[j], "MultiSig: duplicate participant");
            }
            roleManager.assignRole(_participants[i], RoleManager.Role(_roles[i]), _reasons[i]);
        }

        emit ParticipantsBootstrapped(_participants.length);
    }

    /**
     * @notice Finalize bootstrap phase and revoke bootstrapAuthority permanently
     */
    function finalizeBootstrap() external onlyBootstrapAuthority {
        require(address(roleManager) != address(0), "MultiSig: contracts not configured");
        require(roleManager.countActiveParticipants() >= 4, "MultiSig: need at least 4 participants");

        require(AuditEngine(auditEngine).isIntegrated(), "MultiSig: audit engine not integrated");
        require(address(AuditEngine(auditEngine).multiSig()) == address(this), "MultiSig: audit engine reference mismatch");
        require(InsiderActivityLog(insiderLog).isRecorder(auditEngine), "MultiSig: audit engine recorder not set");
        require(ForensicTrail(forensicTrail).isEvidenceWriter(auditEngine), "MultiSig: audit engine evidence writer not set");

        isBootstrapFinalized = true;
        bootstrapAuthority = address(0);

        emit BootstrapFinalized(block.timestamp);
    }

    // ============================================================
    // CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Create a new proposal for a sensitive operation
     * @param _type The type of operation being proposed
     * @param _data Encoded data for the operation
     * @param _reason Human-readable justification
     * @return proposalId The ID of the created proposal
     */
    function createProposal(
        ProposalType _type,
        bytes calldata _data,
        string calldata _reason
    ) external onlyAuthorized returns (uint256 proposalId) {
        _proposalCounter++;
        proposalId = _proposalCounter;

        uint256 expiresAt = block.timestamp + proposalTTL;

        _proposals[proposalId] = Proposal({
            id: proposalId,
            proposalType: _type,
            proposer: msg.sender,
            data: _data,
            reason: _reason,
            createdAt: block.timestamp,
            expiresAt: expiresAt,
            status: ProposalStatus.PENDING,
            approvalCount: 0,
            rejectionCount: 0
        });

        _allProposalIds.push(proposalId);

        emit ProposalCreated(proposalId, _type, msg.sender, _reason, expiresAt);
    }

    /**
     * @notice Approve a pending proposal
     * @param _proposalId The ID of the proposal to approve
     */
    function approveProposal(uint256 _proposalId)
        external
        onlyAuthorized
        proposalExists(_proposalId)
    {
        Proposal storage proposal = _proposals[_proposalId];

        require(proposal.status == ProposalStatus.PENDING, "MultiSig: not pending");
        require(block.timestamp < proposal.expiresAt, "MultiSig: proposal expired");
        require(!_hasVoted[_proposalId][msg.sender], "MultiSig: already voted");
        require(msg.sender != proposal.proposer, "MultiSig: proposer cannot self-approve");

        _hasVoted[_proposalId][msg.sender] = true;
        _votes[_proposalId][msg.sender] = true;
        proposal.approvalCount++;

        emit ProposalApproved(
            _proposalId,
            msg.sender,
            proposal.approvalCount,
            requiredApprovals
        );

        // Auto-execute if threshold met
        if (proposal.approvalCount >= requiredApprovals) {
            proposal.status = ProposalStatus.APPROVED;
            emit ProposalExecuted(_proposalId, msg.sender, block.timestamp);
        }
    }

    /**
     * @notice Reject a pending proposal
     * @param _proposalId The ID of the proposal to reject
     * @param _reason Reason for rejection
     */
    function rejectProposal(uint256 _proposalId, string calldata _reason)
        external
        onlyAuthorized
        proposalExists(_proposalId)
    {
        Proposal storage proposal = _proposals[_proposalId];

        require(proposal.status == ProposalStatus.PENDING, "MultiSig: not pending");
        require(!_hasVoted[_proposalId][msg.sender], "MultiSig: already voted");

        _hasVoted[_proposalId][msg.sender] = true;
        _votes[_proposalId][msg.sender] = false;
        proposal.rejectionCount++;
        proposal.status = ProposalStatus.REJECTED;

        emit ProposalRejected(_proposalId, msg.sender, _reason);
    }

    /**
     * @notice Mark an expired proposal (can be called by anyone for cleanup)
     * @param _proposalId The ID of the proposal to expire
     */
    function markExpired(uint256 _proposalId)
        external
        proposalExists(_proposalId)
    {
        Proposal storage proposal = _proposals[_proposalId];
        require(proposal.status == ProposalStatus.PENDING, "MultiSig: not pending");
        require(block.timestamp >= proposal.expiresAt, "MultiSig: not yet expired");

        proposal.status = ProposalStatus.EXPIRED;
        emit ProposalExpired(_proposalId, block.timestamp);
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function getProposal(uint256 _proposalId)
        external
        view
        proposalExists(_proposalId)
        returns (Proposal memory)
    {
        return _proposals[_proposalId];
    }

    function hasVoted(uint256 _proposalId, address _voter)
        external
        view
        returns (bool)
    {
        return _hasVoted[_proposalId][_voter];
    }

    function getVote(uint256 _proposalId, address _voter)
        external
        view
        returns (bool voted, bool approved)
    {
        voted = _hasVoted[_proposalId][_voter];
        approved = _votes[_proposalId][_voter];
    }

    function isApproved(uint256 _proposalId)
        external
        view
        proposalExists(_proposalId)
        returns (bool)
    {
        return _proposals[_proposalId].status == ProposalStatus.APPROVED;
    }

    function totalProposals() external view returns (uint256) {
        return _proposalCounter;
    }

    function getPendingProposals() external view returns (uint256[] memory) {
        uint256 count = 0;
        for (uint256 i = 0; i < _allProposalIds.length; i++) {
            if (_proposals[_allProposalIds[i]].status == ProposalStatus.PENDING &&
                block.timestamp < _proposals[_allProposalIds[i]].expiresAt) {
                count++;
            }
        }

        uint256[] memory pending = new uint256[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < _allProposalIds.length; i++) {
            if (_proposals[_allProposalIds[i]].status == ProposalStatus.PENDING &&
                block.timestamp < _proposals[_allProposalIds[i]].expiresAt) {
                pending[idx++] = _allProposalIds[i];
            }
        }
        return pending;
    }
}
