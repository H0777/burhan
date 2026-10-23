// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./RoleManager.sol";
import "../AuditEngine.sol";
import "../forensics/InsiderActivityLog.sol";
import "../forensics/ForensicTrail.sol";

/**
 * @title MultiSigApproval
 * @author H0777
 * @notice Four-Eyes governance coordinator for high-risk financial operations
 * @dev Requires multiple authorized signers to approve sensitive actions before execution.
 *      Designed to prevent insider fraud by ensuring no single employee can authorize
 *      critical operations alone.
 *
 * R03 (spec §4, §6, §7) — unified governance and execution-data binding:
 *   - Every proposal type has a CLOSED target+selector table. Targets are only
 *     the contract addresses registered at configure time; action data is
 *     decoded with the exact types and RE-ENCODED, so trailing garbage is
 *     rejected. setGovernance and generic calls are unreachable — governance
 *     can never be migrated through the coordinator.
 *   - actionHash binds chainId, this contract, proposalId, proposalType,
 *     target, keccak256(data), createdAt, notBefore and expiresAt. Only the
 *     bytes stored at creation are ever executed, exactly once.
 *   - Delays: POLICY_CHANGE / ROLE_CHANGE / SYSTEM_CONFIG grants and
 *     setBusinessHours wait TIMELOCK_DELAY (86,400s); OVERRIDE_WARNING,
 *     EMERGENCY_UNPAUSE and SYSTEM_CONFIG revocations (authorized=false) run
 *     at delay 0 — always under two independent approvals. TTL is 259,200s
 *     for every type; execution at now >= expiresAt fails.
 *   - Vote and execution are identity-scoped: the proposer's and every
 *     voter's participant identity AND generation are recorded; execution
 *     re-checks permissions, generations (via each identity's CURRENT active
 *     wallet), quorum, expiry and epoch. A proposer generation change forces
 *     a new proposal.
 *   - Override parties are taken from AuditEngine's own transaction record,
 *     never from proposer-supplied fields; a transaction party (or a
 *     participant identity matching one) can neither propose nor approve the
 *     override of its own warning. Execution is permissionless once all
 *     conditions hold — the executor adds no vote and creates no decision.
 *   - Target execution is atomic: a target revert leaves the proposal
 *     APPROVED (not EXECUTED, not consumed) until it expires.
 */
contract MultiSigApproval {

    // ============================================================
    // ENUMS & STRUCTS
    // ============================================================

    enum ProposalStatus { PENDING, APPROVED, EXECUTED, REJECTED, EXPIRED, CANCELLED }

    enum ProposalType {
        OVERRIDE_WARNING,       // Override an AML/compliance warning
        POLICY_CHANGE,          // Modify compliance thresholds / policy profile
        EMERGENCY_UNPAUSE,      // Resume operations after emergency pause
        ROLE_CHANGE,            // Assign or revoke a role / rotate a wallet
        SYSTEM_CONFIG           // Service authorization & business hours config
    }

    struct Proposal {
        uint256 id;
        ProposalType proposalType;
        address proposer;
        address target;
        bytes data;                 // Encoded action data (the ONLY bytes ever executed)
        bytes32 actionHash;
        string description;
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

    /// @notice Proposal lifetime for EVERY type (spec §7: TTL = 259,200s)
    uint256 public constant PROPOSAL_TTL = 3 days;

    /// @notice Timelock for policy/role changes and service-authorization
    ///         grants (spec §7: 86,400s)
    uint256 public constant TIMELOCK_DELAY = 1 days;

    address public bootstrapAuthority;
    bool public isBootstrapFinalized;

    RoleManager public roleManager;
    address public auditEngine;
    address public insiderLog;
    address public forensicTrail;

    /// @notice Number of approvals required to execute a proposal
    uint256 public requiredApprovals;

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

    /// @notice Proposer authorization generation at creation time — a change
    ///         forces a new proposal (spec §4)
    mapping(uint256 => uint256) private _proposerGenerations;

    /// @notice Track approvers per proposal
    mapping(uint256 => address[]) private _proposalApprovers;

    /// @notice Institutional identity of each recorded voter at vote time (R03)
    mapping(uint256 => mapping(address => bytes32)) private _approverParticipantIds;

    /// @notice Authorization generation of each recorded voter at vote time
    mapping(uint256 => mapping(address => uint256)) private _approverGenerations;

    /// @notice AuditEngine transaction id bound to an OVERRIDE_WARNING proposal
    ///         (decoded from the validated calldata at creation)
    mapping(uint256 => uint256) private _overrideTxIds;

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
        string description
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
     * @dev The proposal TTL is the fixed protocol constant PROPOSAL_TTL
     *      (259,200s) — it is not a deployment parameter (spec §7).
     */
    constructor(
        address _bootstrapAuthority,
        uint256 _requiredApprovals
    ) {
        require(_bootstrapAuthority != address(0), "MultiSig: invalid bootstrap authority");
        require(_requiredApprovals >= 2, "MultiSig: need at least 2 approvals");

        bootstrapAuthority = _bootstrapAuthority;
        requiredApprovals = _requiredApprovals;
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
     * @notice Create a new typed proposal for atomic execution (R03)
     * @dev The (proposalType, target, selector) triple must be on the closed
     *      action table; the calldata is decoded and re-encoded so trailing
     *      garbage is rejected. notBefore follows the per-type delay rules.
     * @param _type The type of operation being proposed
     * @param _target Target contract (must be the registered address for the action)
     * @param _data Encoded action calldata for the target contract
     * @param _description Human-readable justification for the audit record
     * @return proposalId The ID of the created proposal
     */
    function createProposal(
        ProposalType _type,
        address _target,
        bytes calldata _data,
        string calldata _description
    ) external onlyAuthorized returns (uint256 proposalId) {
        // R02/R03: bind the proposal to the proposer's institutional identity.
        (bytes32 proposerId, uint256 proposerGeneration, , ) = roleManager.getParticipant(msg.sender);
        require(proposerId != bytes32(0), "MultiSig: proposer identity not enrolled");

        _proposalCounter++;
        proposalId = _proposalCounter;
        _proposerParticipantIds[proposalId] = proposerId;
        _proposerGenerations[proposalId] = proposerGeneration;

        // Validation + storage live in their own frames (stack pressure).
        _createProposalRecord(proposalId, _type, _target, _data, _description);

        emit ProposalCreated(proposalId, _type, msg.sender, _target, _description);
    }

    /**
     * @dev Validates the action against the closed table and persists the
     *      proposal record (field-by-field: a struct literal overflows the
     *      stack in the legacy pipeline).
     */
    function _createProposalRecord(
        uint256 _proposalId,
        ProposalType _type,
        address _target,
        bytes calldata _data,
        string calldata _description
    ) private {
        (uint256 notBefore, uint256 overrideTxId) = _validateAndSchedule(
            _type,
            _target,
            _data,
            _proposalId
        );
        if (overrideTxId != 0) {
            _overrideTxIds[_proposalId] = overrideTxId;
        }
        _allProposalIds.push(_proposalId);

        Proposal storage proposal = _proposals[_proposalId];
        proposal.id = _proposalId;
        proposal.proposalType = _type;
        proposal.proposer = msg.sender;
        proposal.target = _target;
        proposal.data = _data;
        proposal.description = _description;
        proposal.createdAt = block.timestamp;
        proposal.notBefore = notBefore;
        proposal.expiresAt = block.timestamp + PROPOSAL_TTL;
        proposal.status = ProposalStatus.PENDING;
        proposal.approvalCount = 0;
        proposal.rejectionCount = 0;

        // actionHash binds chainId, governance, proposalId, type, target,
        // data, createdAt, notBefore and expiresAt (spec §4).
        proposal.actionHash = _computeActionHash(
            _proposalId,
            _type,
            _target,
            _data,
            proposal.createdAt,
            notBefore,
            proposal.expiresAt
        );
    }

    /**
     * @dev actionHash = keccak256(abi.encode(chainId, governance, proposalId,
     *      proposalType, target, keccak256(data), createdAt, notBefore,
     *      expiresAt)) — computed in its own frame to keep createProposal's
     *      stack small.
     */
    function _computeActionHash(
        uint256 _proposalId,
        ProposalType _type,
        address _target,
        bytes calldata _data,
        uint256 _createdAt,
        uint256 _notBefore,
        uint256 _expiresAt
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    block.chainid,
                    address(this),
                    _proposalId,
                    _type,
                    _target,
                    keccak256(_data),
                    _createdAt,
                    _notBefore,
                    _expiresAt
                )
            );
    }

    /**
     * @notice Approve a pending proposal
     * @dev Identity-scoped (a rotated second wallet of the same person cannot
     *      vote twice) and conflict-of-interest scoped for overrides (a
     *      transaction party — by wallet OR matching participant identity —
     *      cannot approve the override of its own warning).
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

        (bytes32 participantId, uint256 generation, , bool active) = roleManager.getParticipant(msg.sender);
        require(participantId != bytes32(0), "MultiSig: caller identity not enrolled");
        require(active, "MultiSig: participant inactive");
        require(participantId != _proposerParticipantIds[_proposalId], "MultiSig: proposer cannot approve own proposal");
        require(!_hasVotedParticipant[_proposalId][participantId], "MultiSig: participant has already voted");

        // Conflict of interest on OVERRIDE_WARNING: parties come from the
        // AuditEngine's own transaction record, not from proposal fields.
        if (proposal.proposalType == ProposalType.OVERRIDE_WARNING) {
            AuditEngine.Transaction memory txn = AuditEngine(auditEngine).getTransaction(
                _overrideTxIds[_proposalId]
            );
            require(
                !_identityIsParty(participantId, txn.sender, txn.receiver),
                "MultiSig: transaction sender/receiver cannot approve override"
            );
        }

        _hasVoted[_proposalId][msg.sender] = true;
        _hasVotedParticipant[_proposalId][participantId] = true;
        _votes[_proposalId][msg.sender] = true;
        _proposalApprovers[_proposalId].push(msg.sender);
        _approverParticipantIds[_proposalId][msg.sender] = participantId;
        _approverGenerations[_proposalId][msg.sender] = generation;
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
     * @dev Permissionless: the executor adds no vote and creates no decision —
     *      every authorization condition is re-checked here. The data bytes
     *      stored at creation are the ONLY bytes executed, exactly once. A
     *      target revert bubbles up and leaves the proposal APPROVED (not
     *      EXECUTED, not consumed) so it stays executable until expiry.
     *      Identity re-validation resolves each recorded identity's CURRENT
     *      active wallet and compares its generation against the vote-time
     *      snapshot, so stale authorization can never execute (fail-closed).
     */
    function executeProposal(uint256 _proposalId)
        external
        proposalExists(_proposalId)
        returns (bytes memory)
    {
        Proposal storage proposal = _proposals[_proposalId];
        require(
            proposal.status == ProposalStatus.APPROVED,
            "MultiSig: proposal is not approved or already executed"
        );
        require(block.timestamp >= proposal.notBefore, "MultiSig: timelock active");
        require(block.timestamp < proposal.expiresAt, "MultiSig: proposal expired");
        require(proposal.approvalCount >= requiredApprovals, "MultiSig: quorum not met");

        // Proposer authorization must still be current — a generation change
        // (role rotation, revocation, wallet rotation) forces a new proposal.
        bytes32 proposerId = _proposerParticipantIds[_proposalId];
        address proposerWallet = roleManager.getActiveWallet(proposerId);
        require(
            _isEligibleAtGeneration(proposerWallet, _proposerGenerations[_proposalId]),
            "MultiSig: proposer authorization generation is stale or revoked"
        );

        // Every recorded voter is re-validated by identity via the CURRENT
        // active wallet and the vote-time generation snapshot.
        address[] memory approvers = _proposalApprovers[_proposalId];
        for (uint256 i = 0; i < approvers.length; i++) {
            address wallet = roleManager.getActiveWallet(_approverParticipantIds[_proposalId][approvers[i]]);
            require(
                _isEligibleAtGeneration(wallet, _approverGenerations[_proposalId][approvers[i]]),
                "MultiSig: approver authorization generation is stale or revoked"
            );
        }

        proposal.status = ProposalStatus.EXECUTED;
        emit ProposalExecuted(_proposalId, msg.sender, proposal.target);

        // Atomic external call: the stored bytes only, once.
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
     * @notice Reject a pending proposal (identity-scoped, like approveProposal)
     * @dev A rejection is a vote: the proposer cannot reject their own proposal
     *      and one identity can vote only once.
     */
    function rejectProposal(uint256 _proposalId, string calldata _reason)
        external
        onlyAuthorized
        proposalExists(_proposalId)
    {
        Proposal storage proposal = _proposals[_proposalId];

        require(proposal.status == ProposalStatus.PENDING, "MultiSig: not pending");
        require(block.timestamp < proposal.expiresAt, "MultiSig: proposal expired");

        (bytes32 participantId, , , bool active) = roleManager.getParticipant(msg.sender);
        require(participantId != bytes32(0), "MultiSig: caller identity not enrolled");
        require(active, "MultiSig: participant inactive");
        require(participantId != _proposerParticipantIds[_proposalId], "MultiSig: proposer cannot reject own proposal");
        require(!_hasVotedParticipant[_proposalId][participantId], "MultiSig: participant has already voted");

        _hasVoted[_proposalId][msg.sender] = true;
        _hasVotedParticipant[_proposalId][participantId] = true;
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
    // CLOSED ACTION TABLE (spec §4/§6)
    // ============================================================

    /**
     * @dev Constant-time content equality for the re-encode check (bytes
     *      equality via digest comparison — Solidity has no == for bytes).
     */
    function _exactEncoding(bytes memory _reencoded, bytes memory _original) private pure returns (bool) {
        return keccak256(_reencoded) == keccak256(_original);
    }

    /**
     * @dev Validates the (proposalType, target, selector) triple against the
     *      closed action table and computes notBefore:
     *        OVERRIDE_WARNING, EMERGENCY_UNPAUSE .......... createdAt
     *        POLICY_CHANGE, ROLE_CHANGE ................... createdAt + TIMELOCK_DELAY
     *        SYSTEM_CONFIG setEvidenceWriter/setRecorder .. grant: +TIMELOCK_DELAY,
     *                                                       revocation: createdAt
     *        SYSTEM_CONFIG setBusinessHours ............... createdAt + TIMELOCK_DELAY
     *      Calldata is decoded with the exact types and RE-ENCODED; a mismatch
     *      (malformed encoding or trailing garbage) reverts. Returns the
     *      schedule plus the AuditEngine txId for override proposals.
     */
    function _validateAndSchedule(
        ProposalType _type,
        address _target,
        bytes calldata _data,
        uint256 _proposalId
    ) internal view returns (uint256 notBefore, uint256 overrideTxId) {
        require(_data.length >= 4, "MultiSig: malformed action data");
        bytes4 selector = bytes4(_data[0:4]);
        bytes memory dataMem = _data;

        if (_type == ProposalType.OVERRIDE_WARNING) {
            return
                _validateOverrideAction(
                    _target,
                    selector,
                    _data,
                    dataMem,
                    _proposerParticipantIds[_proposalId]
                );
        }
        if (_type == ProposalType.EMERGENCY_UNPAUSE) {
            return (_validateUnpauseAction(_target, selector, _data, dataMem), 0);
        }
        if (_type == ProposalType.POLICY_CHANGE) {
            return (_validatePolicyAction(_target, selector, _data, dataMem), 0);
        }
        if (_type == ProposalType.ROLE_CHANGE) {
            return (_validateRoleAction(_target, selector, _data, dataMem), 0);
        }
        if (_type == ProposalType.SYSTEM_CONFIG) {
            return (_validateSystemConfigAction(_target, selector, _data, dataMem), 0);
        }

        revert("MultiSig: forbidden proposal type");
    }

    /**
     * @dev OVERRIDE_WARNING -> AuditEngine.executeOverrideWarning only. Parties
     *      are cross-checked against the engine's own transaction record and
     *      the proposer identity must not be a transaction party.
     */
    function _validateOverrideAction(
        address _target,
        bytes4 _selector,
        bytes calldata _data,
        bytes memory _dataMem,
        bytes32 _proposerId
    ) private view returns (uint256 notBefore, uint256 overrideTxId) {
        require(_target == auditEngine, "MultiSig: forbidden target for proposal type");
        require(
            _selector == bytes4(keccak256("executeOverrideWarning(uint256,address,address,string)")),
            "MultiSig: forbidden selector for proposal type"
        );
        (uint256 txId, address txSender, address txReceiver, string memory justification) =
            abi.decode(_data[4:], (uint256, address, address, string));
        require(
            _exactEncoding(abi.encodeWithSelector(_selector, txId, txSender, txReceiver, justification), _dataMem),
            "MultiSig: malformed action data"
        );
        // Override parties come from AuditEngine's own record — never from
        // proposer-supplied fields (an invalid txId reverts here too).
        AuditEngine.Transaction memory txn = AuditEngine(auditEngine).getTransaction(txId);
        require(
            txn.sender == txSender && txn.receiver == txReceiver,
            "AuditEngine: transaction party mismatch"
        );
        require(
            !_identityIsParty(_proposerId, txn.sender, txn.receiver),
            "MultiSig: transaction party cannot propose override"
        );
        return (block.timestamp, txId); // zero delay after quorum
    }

    /**
     * @dev EMERGENCY_UNPAUSE -> AuditEngine.executeEmergencyUnpause only. Delay
     *      0 after quorum; the pauseEpoch binding itself is enforced by the
     *      target at execution time.
     */
    function _validateUnpauseAction(
        address _target,
        bytes4 _selector,
        bytes calldata _data,
        bytes memory _dataMem
    ) private view returns (uint256 notBefore) {
        require(_target == auditEngine, "MultiSig: forbidden target for proposal type");
        require(
            _selector == bytes4(keccak256("executeEmergencyUnpause(uint256)")),
            "MultiSig: forbidden selector for proposal type"
        );
        uint256 expectedEpoch = abi.decode(_data[4:], (uint256));
        require(
            _exactEncoding(abi.encodeWithSelector(_selector, expectedEpoch), _dataMem),
            "MultiSig: malformed action data"
        );
        return block.timestamp;
    }

    /**
     * @dev POLICY_CHANGE -> AuditEngine.executePolicyChange(uint8) or
     *      AuditEngine.executeCustomThresholds(...). Delay 86,400s.
     */
    function _validatePolicyAction(
        address _target,
        bytes4 _selector,
        bytes calldata _data,
        bytes memory _dataMem
    ) private view returns (uint256 notBefore) {
        require(_target == auditEngine, "MultiSig: forbidden target for proposal type");
        if (_selector == bytes4(keccak256("executePolicyChange(uint8)"))) {
            uint8 profile = abi.decode(_data[4:], (uint8));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, profile), _dataMem),
                "MultiSig: malformed action data"
            );
        } else if (
            _selector == bytes4(keccak256("executeCustomThresholds(uint256,uint256,uint256,uint256,uint256)"))
        ) {
            (uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) =
                abi.decode(_data[4:], (uint256, uint256, uint256, uint256, uint256));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, a, b, c, d, e), _dataMem),
                "MultiSig: malformed action data"
            );
        } else {
            revert("MultiSig: forbidden selector for proposal type");
        }
        return block.timestamp + TIMELOCK_DELAY;
    }

    /**
     * @dev ROLE_CHANGE -> RoleManager.assignRole / revokeRole /
     *      rotateParticipantWallet. Delay 86,400s.
     */
    function _validateRoleAction(
        address _target,
        bytes4 _selector,
        bytes calldata _data,
        bytes memory _dataMem
    ) private view returns (uint256 notBefore) {
        require(_target == address(roleManager), "MultiSig: forbidden target for proposal type");
        if (_selector == bytes4(keccak256("assignRole(address,uint8,string)"))) {
            (address target, uint8 role, string memory reason) =
                abi.decode(_data[4:], (address, uint8, string));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, target, role, reason), _dataMem),
                "MultiSig: malformed action data"
            );
        } else if (_selector == bytes4(keccak256("revokeRole(address,string)"))) {
            (address target, string memory reason) = abi.decode(_data[4:], (address, string));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, target, reason), _dataMem),
                "MultiSig: malformed action data"
            );
        } else if (_selector == bytes4(keccak256("rotateParticipantWallet(bytes32,address,string)"))) {
            (bytes32 participantId, address newWallet, string memory reason) =
                abi.decode(_data[4:], (bytes32, address, string));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, participantId, newWallet, reason), _dataMem),
                "MultiSig: malformed action data"
            );
        } else {
            revert("MultiSig: forbidden selector for proposal type");
        }
        return block.timestamp + TIMELOCK_DELAY;
    }

    /**
     * @dev SYSTEM_CONFIG -> ForensicTrail.setEvidenceWriter(address,bool),
     *      InsiderActivityLog.setRecorder(address,bool) (grant +86,400s,
     *      revocation delay 0) or AuditEngine.setBusinessHours(uint8,uint8)
     *      (+86,400s).
     */
    function _validateSystemConfigAction(
        address _target,
        bytes4 _selector,
        bytes calldata _data,
        bytes memory _dataMem
    ) private view returns (uint256 notBefore) {
        if (_selector == bytes4(keccak256("setEvidenceWriter(address,bool)"))) {
            require(_target == forensicTrail, "MultiSig: forbidden target for proposal type");
            (address writer, bool authorized) = abi.decode(_data[4:], (address, bool));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, writer, authorized), _dataMem),
                "MultiSig: malformed action data"
            );
            // Grant waits 24h; revocation takes effect at delay 0 — both
            // under the two independent approvals.
            return authorized ? block.timestamp + TIMELOCK_DELAY : block.timestamp;
        }
        if (_selector == bytes4(keccak256("setRecorder(address,bool)"))) {
            require(_target == insiderLog, "MultiSig: forbidden target for proposal type");
            (address recorder, bool authorized) = abi.decode(_data[4:], (address, bool));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, recorder, authorized), _dataMem),
                "MultiSig: malformed action data"
            );
            return authorized ? block.timestamp + TIMELOCK_DELAY : block.timestamp;
        }
        if (_selector == bytes4(keccak256("setBusinessHours(uint8,uint8)"))) {
            require(_target == auditEngine, "MultiSig: forbidden target for proposal type");
            (uint8 start, uint8 end) = abi.decode(_data[4:], (uint8, uint8));
            require(
                _exactEncoding(abi.encodeWithSelector(_selector, start, end), _dataMem),
                "MultiSig: malformed action data"
            );
            return block.timestamp + TIMELOCK_DELAY;
        }
        revert("MultiSig: forbidden selector for proposal type");
    }

    /**
     * @dev True when `_wallet` is the CURRENT active wallet of an enrolled
     *      identity that is still eligible (SUPER_ADMIN/AUDITOR) and whose
     *      generation still equals the recorded snapshot. Fail-closed: revoked,
     *      rotated or downgraded identities never pass.
     */
    function _isEligibleAtGeneration(address _wallet, uint256 _generation) internal view returns (bool) {
        if (_wallet == address(0)) return false;
        (bytes32 participantId, uint256 generation, RoleManager.Role role, bool active) =
            roleManager.getParticipant(_wallet);
        return
            participantId != bytes32(0) &&
            active &&
            generation == _generation &&
            (role == RoleManager.Role.SUPER_ADMIN || role == RoleManager.Role.AUDITOR);
    }

    /**
     * @dev True when `_participantId` is the institutional identity of either
     *      transaction party (a retired party wallet keeps its identity, so a
     *      rotated wallet of the same person stays blocked).
     */
    function _identityIsParty(
        bytes32 _participantId,
        address _txSender,
        address _txReceiver
    ) internal view returns (bool) {
        if (_participantId == bytes32(0)) return false;
        (bytes32 senderId, , , ) = roleManager.getParticipant(_txSender);
        (bytes32 receiverId, , , ) = roleManager.getParticipant(_txReceiver);
        return _participantId == senderId || _participantId == receiverId;
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
