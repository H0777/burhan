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

    enum ProposalStatus { PENDING, APPROVED, EXECUTED, REJECTED, EXPIRED, CANCELLED }

    enum ProposalType {
        OVERRIDE_WARNING,       // Override an AML/compliance warning
        POLICY_CHANGE,          // Modify compliance thresholds
        EMERGENCY_UNPAUSE,      // Resume operations after emergency pause
        ROLE_CHANGE,            // Assign or revoke a role
        GOVERNANCE_CONFIG       // MultiSig configuration changes
    }

    struct Proposal {
        uint256 id;
        ProposalType proposalType;
        address proposer;
        address target;
        bytes data;                 // Encoded action data
        bytes32 actionHash;
        bytes32 reasonHash;
        string reason;
        uint256 createdAt;
        uint256 notBefore;
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

    /// @notice Track participant IDs to prevent double voting across multiple wallets
    mapping(uint256 => mapping(bytes32 => bool)) private _hasVotedParticipant;

    /// @notice Institutional identity of each proposal's proposer (R02: one person
    ///         holding two wallets of the same identity cannot propose and approve)
    mapping(uint256 => bytes32) private _proposerParticipantIds;

    /// @notice Track approvers per proposal
    mapping(uint256 => address[]) private _proposalApprovers;

    /// @notice Track approver authorization generation at time of voting
    mapping(uint256 => mapping(address => uint256)) private _approverGenerations;

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
        address target,
        bytes32 reasonHash
    );

    event LegacyProposalCreated(
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
        address target
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
     * @notice Enroll initial 4+ institutional participants during bootstrap phase
     * @dev The only bulk-entry point: each entry mints a fixed institutional
     *      identity bound to exactly one active wallet in RoleManager. The whole
     *      enrollment reverts atomically if any entry is invalid (zero id,
     *      duplicate id, duplicate/retired wallet). Ids are fixed off-chain
     *      roster values, never derived from wallet addresses or person names.
     */
    function bootstrapParticipants(
        bytes32[] calldata _participantIds,
        address[] calldata _wallets,
        uint8[] calldata _roles,
        string[] calldata _reasons
    ) external onlyBootstrapAuthority {
        require(address(roleManager) != address(0), "MultiSig: contracts not configured");
        require(
            _participantIds.length == _wallets.length &&
                _wallets.length == _roles.length &&
                _wallets.length == _reasons.length,
            "MultiSig: length mismatch"
        );
        require(_wallets.length >= 4, "MultiSig: need at least 4 participants");

        for (uint256 i = 0; i < _wallets.length; i++) {
            require(_wallets[i] != address(0), "MultiSig: zero address participant");
            for (uint256 j = i + 1; j < _wallets.length; j++) {
                require(_wallets[i] != _wallets[j], "MultiSig: duplicate participant");
            }
            roleManager.enrollParticipant(
                _participantIds[i],
                _wallets[i],
                RoleManager.Role(_roles[i]),
                _reasons[i]
            );
        }

        emit ParticipantsBootstrapped(_wallets.length);
    }

    /**
     * @notice Finalize bootstrap phase and revoke bootstrapAuthority permanently
     * @dev Quorum counts distinct ENROLLED voting identities (SUPER_ADMIN/AUDITOR
     *      only; OPERATOR/REGULATOR and the un-enrolled deployer never count).
     *      Integration completeness and allowlists are verified BEFORE the
     *      authority is erased. The deployer's temporary role is dropped unless
     *      the deployer wallet was explicitly enrolled in the roster.
     */
    function finalizeBootstrap() external onlyBootstrapAuthority {
        require(address(roleManager) != address(0), "MultiSig: contracts not configured");
        require(
            roleManager.countEligibleParticipants() >= 4,
            "MultiSig: need at least 4 eligible participants"
        );

        require(AuditEngine(auditEngine).isIntegrated(), "MultiSig: audit engine not integrated");
        require(address(AuditEngine(auditEngine).multiSig()) == address(this), "MultiSig: audit engine reference mismatch");
        require(InsiderActivityLog(insiderLog).isRecorder(auditEngine), "MultiSig: audit engine recorder not set");
        require(ForensicTrail(forensicTrail).isEvidenceWriter(auditEngine), "MultiSig: audit engine evidence writer not set");

        isBootstrapFinalized = true;
        bootstrapAuthority = address(0);

        // Drop the deployer's temporary bootstrap role unless its wallet is an
        // explicitly enrolled roster participant (identity => explicit trust).
        address deployerWallet = roleManager.deployer();
        (bytes32 deployerId, , , ) = roleManager.getParticipant(deployerWallet);
        if (deployerId == bytes32(0) && roleManager.getRole(deployerWallet) != RoleManager.Role.NONE) {
            roleManager.revokeRole(deployerWallet, "Bootstrap finalized: deployer temporary role dropped");
        }

        emit BootstrapFinalized(block.timestamp);
    }

    // ============================================================
    // CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Create a new typed proposal for atomic execution (V2)
     * @param _type The type of operation being proposed
     * @param _target Target contract to execute callData on
     * @param _data Encoded action calldata for target contract
     * @param _reasonHash Hash of human-readable justification and evidence reference
     * @return proposalId The ID of the created proposal
     */
    function createProposal(
        ProposalType _type,
        address _target,
        bytes calldata _data,
        bytes32 _reasonHash
    ) external onlyAuthorized returns (uint256 proposalId) {
        require(_target != address(0) && _target.code.length > 0, "MultiSig: target must be an active contract");

        // R02: bind the proposal to the proposer's institutional identity, not
        // just the proposing wallet — a rotated second wallet of the same person
        // is still the proposer and can never approve their own proposal.
        (bytes32 proposerId, , , ) = roleManager.getParticipant(msg.sender);
        require(proposerId != bytes32(0), "MultiSig: proposer identity not enrolled");

        _proposalCounter++;
        proposalId = _proposalCounter;
        _proposerParticipantIds[proposalId] = proposerId;

        uint256 expiresAt = block.timestamp + proposalTTL;
        bytes32 actionHash = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                proposalId,
                _type,
                _target,
                keccak256(_data),
                block.timestamp,
                expiresAt
            )
        );

        _proposals[proposalId] = Proposal({
            id: proposalId,
            proposalType: _type,
            proposer: msg.sender,
            target: _target,
            data: _data,
            actionHash: actionHash,
            reasonHash: _reasonHash,
            reason: "",
            createdAt: block.timestamp,
            notBefore: block.timestamp,
            expiresAt: expiresAt,
            status: ProposalStatus.PENDING,
            approvalCount: 0,
            rejectionCount: 0
        });

        _allProposalIds.push(proposalId);

        emit ProposalCreated(proposalId, _type, msg.sender, _target, _reasonHash);
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
        require(msg.sender != proposal.proposer, "MultiSig: proposer cannot approve own proposal");
        require(!_hasVoted[_proposalId][msg.sender], "MultiSig: caller has already voted");

        (bytes32 participantId, uint256 gen, , bool active) = roleManager.getParticipant(msg.sender);
        require(participantId != bytes32(0), "MultiSig: caller identity not enrolled");
        require(active, "MultiSig: participant inactive");
        require(participantId != _proposerParticipantIds[_proposalId], "MultiSig: proposer cannot approve own proposal");
        require(!_hasVotedParticipant[_proposalId][participantId], "MultiSig: participant has already voted");

        // Conflict of interest check on OVERRIDE_WARNING
        if (proposal.proposalType == ProposalType.OVERRIDE_WARNING && proposal.data.length >= 100) {
            bytes memory pdata = proposal.data;
            bytes4 sel;
            assembly {
                sel := mload(add(pdata, 32))
            }
            if (sel == bytes4(keccak256("executeOverrideWarning(uint256,address,address,string)"))) {
                address txSender;
                address txReceiver;
                assembly {
                    txSender := mload(add(pdata, 68))
                    txReceiver := mload(add(pdata, 100))
                }
                require(
                    msg.sender != txSender && msg.sender != txReceiver,
                    "MultiSig: transaction sender/receiver cannot approve override"
                );
            }
        }

        _hasVoted[_proposalId][msg.sender] = true;
        _hasVotedParticipant[_proposalId][participantId] = true;
        _votes[_proposalId][msg.sender] = true;
        _proposalApprovers[_proposalId].push(msg.sender);
        _approverGenerations[_proposalId][msg.sender] = gen;
        proposal.approvalCount++;

        emit ProposalApproved(
            _proposalId,
            msg.sender,
            proposal.approvalCount,
            requiredApprovals
        );

        if (proposal.approvalCount >= requiredApprovals) {
            proposal.status = ProposalStatus.APPROVED;
        }
    }

    /**
     * @notice Atomically execute an approved proposal
     * @param _proposalId The ID of the approved proposal to execute
     */
    function executeProposal(uint256 _proposalId)
        external
        onlyAuthorized
        proposalExists(_proposalId)
        returns (bytes memory)
    {
        Proposal storage proposal = _proposals[_proposalId];
        require(
            proposal.status == ProposalStatus.APPROVED,
            "MultiSig: proposal is not approved or already executed"
        );
        require(block.timestamp < proposal.expiresAt, "MultiSig: proposal expired");

        // Verify voter authorization generations are still fresh
        address[] memory approvers = _proposalApprovers[_proposalId];
        for (uint256 i = 0; i < approvers.length; i++) {
            address approver = approvers[i];
            (, uint256 currentGen, , bool active) = roleManager.getParticipant(approver);
            require(
                active &&
                    currentGen == _approverGenerations[_proposalId][approver] &&
                    roleManager.hasMinimumRole(approver, RoleManager.Role.AUDITOR),
                "MultiSig: approver authorization generation is stale or revoked"
            );
        }

        proposal.status = ProposalStatus.EXECUTED;
        emit ProposalExecuted(_proposalId, msg.sender, proposal.target);

        // Atomic external call to target
        (bool success, bytes memory returnData) = proposal.target.call(proposal.data);
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            } else {
                revert("MultiSig: target execution failed");
            }
        }
        return returnData;
    }

    /**
     * @notice Get all approvers for a proposal
     */
    function getApprovers(uint256 _proposalId)
        external
        view
        proposalExists(_proposalId)
        returns (address[] memory)
    {
        return _proposalApprovers[_proposalId];
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
