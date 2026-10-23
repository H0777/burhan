// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ComplianceRules.sol";
import "./interfaces/IAuditEngine.sol";
import "./access/RoleManager.sol";
import "./access/MultiSigApproval.sol";
import "./forensics/InsiderActivityLog.sol";
import "./forensics/ForensicTrail.sol";

/**
 * @title AuditEngine
 * @author H0777
 * @notice Cyber-Forensic Auditing Engine for Detecting Financial Fraud and Insider Threats
 * @dev Core engine integrating:
 *      - RBAC (Role-Based Access Control) via RoleManager
 *      - Insider activity tracking via InsiderActivityLog
 *      - Immutable forensic chain of custody via ForensicTrail
 *      - Four-Eyes Multi-Signature approvals via MultiSigApproval
 *      - Separation of Duties (SoD) enforcement
 *      - Timelock protection on policy updates
 *      - Dual-control emergency circuit breaker (Pause / Unpause)
 *      - Configurable AML/KYC compliance rules
 *
 * Part of the framework:
 * "Integrating Digital Forensics and Financial Accounting:
 *  A Cyber-Auditing System for Mitigating Insider Threat Fraud"
 */
contract AuditEngine is IAuditEngine, ComplianceRules {

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    address public admin;
    address public governance;
    uint256 private _transactionCounter;

    /// @notice External contract references
    RoleManager public roleManager;
    InsiderActivityLog public insiderLog;
    ForensicTrail public forensicTrail;
    MultiSigApproval public multiSig;

    /// @notice Whether external contracts are linked
    bool public isIntegrated;

    event GovernanceTransferred(address indexed newGovernance);
    event AllContractsIntegrated(
        address indexed roleManager,
        address indexed insiderLog,
        address indexed forensicTrail,
        address multiSig
    );

    /// @notice Emergency Circuit Breaker state
    bool public isPaused;
    uint256 public pauseEpoch;

    /// @notice Track consumed proposals to prevent replay
    mapping(uint256 => bool) private _consumedProposals;

    /// @notice MultiSig enforcement flag for all overrides
    bool public enforceMultiSigOverride;

    /// @notice Timelock configuration for policy changes
    uint256 public policyTimelockDelay; // 0 = immediate (testing/default), >0 = enforced delay

    struct PendingPolicyChange {
        PolicyProfile profile;
        uint256 largeThreshold;
        uint256 dailyLimit;
        uint256 maxDaily;
        uint256 maxSingle;
        uint256 kycThreshold;
        uint256 eta;
        bool isCustom;
        bool active;
    }

    PendingPolicyChange public pendingPolicyChange;

    enum AuditStatus { PENDING, CLEARED, FLAGGED, BLOCKED }

    struct Transaction {
        uint256 id;
        address sender;
        address receiver;
        uint256 amount;
        uint256 timestamp;
        bool isFlagged;
        string flagReason;
        AuditStatus status;
    }

    mapping(uint256 => Transaction) private _transactions;
    mapping(address => mapping(uint256 => uint256)) private _dailyVolume;
    mapping(address => mapping(uint256 => uint256)) private _dailyCount;
    mapping(address => bool) private _blacklisted;
    mapping(address => bool) private _kycVerified;
    uint256[] private _allTransactionIds;

    // ============================================================
    // EVENTS
    // ============================================================

    event TransactionSubmitted(uint256 indexed txId, address indexed sender, address indexed receiver, uint256 amount, uint256 timestamp);
    event TransactionFlagged(uint256 indexed txId, address indexed sender, string reason, uint256 timestamp);
    event TransactionCleared(uint256 indexed txId, uint256 timestamp);
    event TransactionBlocked(uint256 indexed txId, address indexed sender, string reason);
    event AddressBlacklisted(address indexed target, string reason);
    event AddressWhitelisted(address indexed target);
    event KYCVerified(address indexed target);
    event KYCRevoked(address indexed target);

    // Forensic & Insider events
    event OverrideAttempted(address indexed operator, uint256 indexed txId, string warningSkipped, uint256 timestamp);
    event PolicyChanged(PolicyProfile indexed newPolicy, address indexed changedBy, uint256 timestamp);
    event ContractsIntegrated(address indexed roleManager, address indexed insiderLog, uint256 timestamp);

    // Advanced Enterprise & Academic events (5 features)
    event EmergencyPaused(address indexed by, string reason, uint256 timestamp);
    event EmergencyUnpaused(address indexed by, uint256 proposalId, uint256 timestamp);
    event PolicyChangeProposed(PolicyProfile indexed profile, uint256 eta, bool isCustom, uint256 timestamp);
    event PolicyChangeExecuted(PolicyProfile indexed profile, uint256 timestamp);
    event PolicyChangeCancelled(uint256 timestamp);
    event AutomatedForensicIncidentCreated(uint256 indexed incidentId, uint256 indexed txId, string severity, uint256 timestamp);
    event MultiSigEnforcementToggled(bool enforced, uint256 timestamp);

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyAdmin() {
        if (isIntegrated) {
            RoleManager.Role role = roleManager.getRole(msg.sender);
            require(
                role == RoleManager.Role.SUPER_ADMIN,
                "AuditEngine: caller is not admin"
            );
        } else {
            require(msg.sender == admin, "AuditEngine: caller is not admin");
        }
        _;
    }

    modifier onlyGovernance() {
        require(
            msg.sender == governance || msg.sender == address(multiSig),
            "AuditEngine: caller is not governance"
        );
        _;
    }

    /**
     * @dev Checks role via RoleManager if integrated, otherwise falls back to admin check
     */
    modifier onlyAuthorized() {
        if (isIntegrated) {
            RoleManager.Role role = roleManager.getRole(msg.sender);
            require(
                role == RoleManager.Role.SUPER_ADMIN ||
                role == RoleManager.Role.AUDITOR,
                "AuditEngine: insufficient role"
            );
        } else {
            require(msg.sender == admin, "AuditEngine: caller is not admin");
        }
        _;
    }

    modifier notBlacklisted(address _addr) {
        require(!_blacklisted[_addr], "AuditEngine: address is blacklisted");
        _;
    }

    modifier validAmount(uint256 _amount) {
        require(_amount > 0, "AuditEngine: amount must be greater than zero");
        require(_amount <= maxSingleTransaction, "AuditEngine: amount exceeds maximum");
        _;
    }

    modifier whenNotPaused() {
        require(!isPaused, "AuditEngine: circuit breaker active - transactions paused");
        _;
    }

    modifier whenPaused() {
        require(isPaused, "AuditEngine: circuit breaker not active");
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor(address _governance) {
        require(_governance != address(0), "AuditEngine: invalid governance address");
        governance = _governance;
        admin = msg.sender;
        _transactionCounter = 0;
        isPaused = false;
        enforceMultiSigOverride = false;
        policyTimelockDelay = 0; // immediate by default for backwards compatibility
    }

    // ============================================================
    // INTEGRATION
    // ============================================================

    /**
     * @notice Link external RoleManager and InsiderActivityLog contracts
     */
    function integrateContracts(
        address _roleManager,
        address _insiderLog
    ) external {
        require(msg.sender == governance || msg.sender == admin, "AuditEngine: unauthorized integration");
        _integrate(_roleManager, _insiderLog, address(0), address(0));
    }

    /**
     * @notice Link all 4 contracts: RoleManager, InsiderLog, ForensicTrail, MultiSigApproval
     */
    function integrateAllContracts(
        address _roleManager,
        address _insiderLog,
        address _forensicTrail,
        address _multiSig
    ) external {
        require(msg.sender == governance || msg.sender == admin, "AuditEngine: unauthorized integration");
        _integrate(_roleManager, _insiderLog, _forensicTrail, _multiSig);
    }

    function _integrate(
        address _roleManager,
        address _insiderLog,
        address _forensicTrail,
        address _multiSig
    ) internal {
        require(!isIntegrated, "AuditEngine: already integrated");
        require(
            _roleManager != address(0) &&
            _insiderLog != address(0),
            "AuditEngine: zero address"
        );
        require(_roleManager.code.length > 0, "AuditEngine: RoleManager must be a contract");
        require(_insiderLog.code.length > 0, "AuditEngine: InsiderLog must be a contract");

        roleManager = RoleManager(_roleManager);
        insiderLog = InsiderActivityLog(_insiderLog);

        if (_forensicTrail != address(0)) {
            require(_forensicTrail.code.length > 0, "AuditEngine: ForensicTrail must be a contract");
            forensicTrail = ForensicTrail(_forensicTrail);
        }
        if (_multiSig != address(0)) {
            require(_multiSig.code.length > 0, "AuditEngine: MultiSig must be a contract");
            multiSig = MultiSigApproval(_multiSig);
        }

        isIntegrated = true;
        emit ContractsIntegrated(_roleManager, _insiderLog, block.timestamp);
        if (_forensicTrail != address(0) && _multiSig != address(0)) {
            emit AllContractsIntegrated(_roleManager, _insiderLog, _forensicTrail, _multiSig);
        }
    }

    // ============================================================
    // CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Submit a financial transaction for automated audit
     * @param _receiver Recipient address
     * @param _amount Transaction amount in wei
     * @return txId The unique transaction ID
     */
    function submitTransaction(
        address _receiver,
        uint256 _amount
    )
        external
        whenNotPaused
        notBlacklisted(msg.sender)
        notBlacklisted(_receiver)
        validAmount(_amount)
        returns (uint256 txId)
    {
        require(_receiver != address(0), "AuditEngine: invalid receiver");
        require(_receiver != msg.sender, "AuditEngine: self-transfer not allowed");

        _transactionCounter++;
        txId = _transactionCounter;

        uint256 today = _getToday();
        _dailyVolume[msg.sender][today] += _amount;
        _dailyCount[msg.sender][today]++;

        Transaction storage txn = _transactions[txId];
        txn.id = txId;
        txn.sender = msg.sender;
        txn.receiver = _receiver;
        txn.amount = _amount;
        txn.timestamp = block.timestamp;
        txn.status = AuditStatus.PENDING;

        _allTransactionIds.push(txId);

        emit TransactionSubmitted(txId, msg.sender, _receiver, _amount, block.timestamp);

        _runAuditEngine(txId, today);

        return txId;
    }

    // ============================================================
    // INTERNAL AUDIT ENGINE & AUTOMATED FORENSICS
    // ============================================================

    function _runAuditEngine(uint256 _txId, uint256 today) internal {
        Transaction storage txn = _transactions[_txId];

        // Rule 1: Large transaction threshold
        if (txn.amount >= largeTransactionThreshold) {
            _flagTransaction(_txId, "LARGE_TRANSACTION: Amount exceeds reporting threshold");

            // Automated Forensic Ingestion for severe large transfer anomaly
            if (txn.amount >= largeTransactionThreshold * 2) {
                _autoRecordForensicIncident(
                    _txId,
                    "CRITICAL_LARGE_TRANSFER",
                    "HIGH",
                    "Transaction amount double large threshold"
                );
            }
            return;
        }

        // Rule 2: Daily volume limit
        if (_dailyVolume[txn.sender][today] >= dailyVolumeLimit) {
            _flagTransaction(_txId, "DAILY_LIMIT_EXCEEDED: Daily volume limit reached");
            return;
        }

        // Rule 3: Suspicious transaction frequency
        if (_dailyCount[txn.sender][today] >= maxDailyTransactions) {
            _flagTransaction(_txId, "SUSPICIOUS_FREQUENCY: Too many transactions in 24 hours");
            return;
        }

        // Rule 4: KYC verification required for high-value transfers
        if (txn.amount >= kycRequiredThreshold && !_kycVerified[txn.sender]) {
            _flagTransaction(_txId, "KYC_REQUIRED: Sender not verified for this amount");
            return;
        }

        // All rules passed - clear transaction
        _clearTransaction(_txId);
    }

    function _flagTransaction(uint256 _txId, string memory _reason) internal {
        Transaction storage txn = _transactions[_txId];
        txn.isFlagged = true;
        txn.flagReason = _reason;
        txn.status = AuditStatus.FLAGGED;
        emit TransactionFlagged(_txId, txn.sender, _reason, block.timestamp);
    }

    function _clearTransaction(uint256 _txId) internal {
        _transactions[_txId].status = AuditStatus.CLEARED;
        emit TransactionCleared(_txId, block.timestamp);
    }

    /**
     * @notice Helper to automatically create an incident in ForensicTrail (Feature 3)
     */
    function _autoRecordForensicIncident(
        uint256 _txId,
        string memory _title,
        string memory _severity,
        string memory _description
    ) internal returns (uint256 incidentId) {
        if (isIntegrated && address(forensicTrail) != address(0)) {
            incidentId = forensicTrail.createIncident(_title, _severity);
            bytes32 evidenceHash = keccak256(abi.encodePacked(_txId, block.timestamp, _description));
            forensicTrail.submitEvidence(incidentId, "AUTOMATED_AUDIT_ALARM", _description, evidenceHash);
            emit AutomatedForensicIncidentCreated(incidentId, _txId, _severity, block.timestamp);
        }
    }

    // ============================================================
    // ADMIN / AUTHORIZED FUNCTIONS & SEPARATION OF DUTIES (SoD)
    // ============================================================

    /**
     * @notice Block a flagged transaction
     * @dev Enforces Separation of Duties: caller cannot be sender or receiver
     */
    function blockTransaction(uint256 _txId) external onlyAuthorized whenNotPaused {
        Transaction storage txn = _transactions[_txId];
        require(txn.status == AuditStatus.FLAGGED, "AuditEngine: can only block flagged transactions");

        // Feature 2: Separation of Duties (SoD)
        require(msg.sender != txn.sender, "AuditEngine: SoD conflict - caller is transaction sender");
        require(msg.sender != txn.receiver, "AuditEngine: SoD conflict - caller is transaction receiver");

        txn.status = AuditStatus.BLOCKED;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.TRANSACTION_APPROVAL,
                _txId,
                txn.sender,
                "Blocked flagged transaction"
            );
        }

        emit TransactionBlocked(_txId, txn.sender, txn.flagReason);
    }

    /**
     * @notice Override a flagged transaction (clear it despite warnings)
     * @dev Enforces SoD and checks MultiSig enforcement flag
     */
    function overrideWarning(uint256 _txId, string calldata _justification) external onlyAuthorized whenNotPaused {
        require(!enforceMultiSigOverride, "AuditEngine: MultiSig approval required for overrides");

        Transaction storage txn = _transactions[_txId];
        require(txn.status == AuditStatus.FLAGGED, "AuditEngine: can only override flagged transactions");

        // Feature 2: Separation of Duties (SoD)
        require(msg.sender != txn.sender, "AuditEngine: SoD conflict - caller is transaction sender");
        require(msg.sender != txn.receiver, "AuditEngine: SoD conflict - caller is transaction receiver");

        string memory previousWarning = txn.flagReason;
        txn.isFlagged = false;
        txn.flagReason = "";
        txn.status = AuditStatus.CLEARED;

        emit OverrideAttempted(msg.sender, _txId, previousWarning, block.timestamp);
        emit TransactionCleared(_txId, block.timestamp);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.TRANSACTION_OVERRIDE,
                _txId,
                txn.receiver,
                _justification
            );
        }
    }

    /**
     * @notice Feature 1: Enforced MultiSig Bridge for overriding warnings
     * @dev Requires an approved proposal in MultiSigApproval
     */
    function overrideWarningWithMultiSig(
        uint256 _txId,
        uint256 _proposalId,
        string calldata _justification
    ) external onlyAuthorized whenNotPaused {
        require(isIntegrated && address(multiSig) != address(0), "AuditEngine: MultiSig not integrated");
        require(multiSig.isApproved(_proposalId), "AuditEngine: proposal not approved by MultiSig");
        require(!_consumedProposals[_proposalId], "AuditEngine: proposal already executed or expired");
        _consumedProposals[_proposalId] = true;

        MultiSigApproval.Proposal memory prop = multiSig.getProposal(_proposalId);
        require(
            prop.proposalType == MultiSigApproval.ProposalType.OVERRIDE_WARNING,
            "AuditEngine: invalid proposal type"
        );

        uint256 targetTxId = abi.decode(prop.data, (uint256));
        require(targetTxId == _txId, "AuditEngine: proposal txId mismatch");

        Transaction storage txn = _transactions[_txId];
        require(txn.status == AuditStatus.FLAGGED, "AuditEngine: can only override flagged transactions");

        // Feature 2: Separation of Duties (SoD)
        require(msg.sender != txn.sender, "AuditEngine: SoD conflict - caller is transaction sender");
        require(msg.sender != txn.receiver, "AuditEngine: SoD conflict - caller is transaction receiver");

        string memory previousWarning = txn.flagReason;
        txn.isFlagged = false;
        txn.flagReason = "";
        txn.status = AuditStatus.CLEARED;

        emit OverrideAttempted(msg.sender, _txId, previousWarning, block.timestamp);
        emit TransactionCleared(_txId, block.timestamp);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.TRANSACTION_OVERRIDE,
                _txId,
                txn.receiver,
                string(abi.encodePacked("MultiSig #", _justification))
            );

            // Log evidence to ForensicTrail if integrated
            if (address(forensicTrail) != address(0)) {
                uint256 incId = forensicTrail.createIncident("MULTISIG_OVERRIDE_AUDIT", "LOW");
                forensicTrail.submitEvidence(
                    incId,
                    "MULTISIG_OVERRIDE_RECORD",
                    _justification,
                    keccak256(abi.encodePacked(_txId, _proposalId, msg.sender, block.timestamp))
                );
            }
        }
    }

    /**
     * @notice Toggle mandatory MultiSig enforcement for all overrides
     */
    function setMultiSigOverrideEnforcement(bool _enforce) external onlyAdmin {
        enforceMultiSigOverride = _enforce;
        emit MultiSigEnforcementToggled(_enforce, block.timestamp);
    }

    function addToBlacklist(address _addr, string calldata _reason) external onlyAuthorized whenNotPaused {
        require(_addr != address(0), "AuditEngine: invalid address");
        require(_addr != admin, "AuditEngine: cannot blacklist admin");
        _blacklisted[_addr] = true;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.BLACKLIST_ACTION,
                0,
                _addr,
                _reason
            );
        }

        emit AddressBlacklisted(_addr, _reason);
    }

    function removeFromBlacklist(address _addr) external onlyAuthorized whenNotPaused {
        _blacklisted[_addr] = false;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.BLACKLIST_ACTION,
                0,
                _addr,
                "Removed from blacklist"
            );
        }

        emit AddressWhitelisted(_addr);
    }

    /**
     * @notice Verify KYC for an address
     * @dev SoD: caller cannot verify their own address
     */
    function verifyKYC(address _addr) external onlyAuthorized whenNotPaused {
        require(_addr != address(0), "AuditEngine: invalid address");
        require(msg.sender != _addr, "AuditEngine: SoD conflict - caller cannot verify self");

        _kycVerified[_addr] = true;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.KYC_ACTION,
                0,
                _addr,
                "KYC verified"
            );
        }

        emit KYCVerified(_addr);
    }

    /**
     * @notice Revoke KYC for an address
     * @dev SoD: caller cannot revoke their own KYC
     */
    function revokeKYC(address _addr) external onlyAuthorized whenNotPaused {
        require(msg.sender != _addr, "AuditEngine: SoD conflict - caller cannot revoke self");
        _kycVerified[_addr] = false;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.KYC_ACTION,
                0,
                _addr,
                "KYC revoked"
            );
        }

        emit KYCRevoked(_addr);
    }

    // ============================================================
    // FEATURE 4: TIMELOCK ON POLICY CHANGES
    // ============================================================

    function setPolicyTimelockDelay(uint256 _delay) external onlyAdmin {
        policyTimelockDelay = _delay;
    }

    function proposePolicyChange(PolicyProfile _policy) external onlyAdmin {
        uint256 eta = block.timestamp + policyTimelockDelay;
        pendingPolicyChange = PendingPolicyChange({
            profile: _policy,
            largeThreshold: 0,
            dailyLimit: 0,
            maxDaily: 0,
            maxSingle: 0,
            kycThreshold: 0,
            eta: eta,
            isCustom: false,
            active: true
        });
        emit PolicyChangeProposed(_policy, eta, false, block.timestamp);
    }

    function proposeCustomThresholds(
        uint256 _largeThreshold,
        uint256 _dailyLimit,
        uint256 _maxDaily,
        uint256 _maxSingle,
        uint256 _kycThreshold
    ) external onlyAdmin {
        uint256 eta = block.timestamp + policyTimelockDelay;
        pendingPolicyChange = PendingPolicyChange({
            profile: PolicyProfile.CUSTOM,
            largeThreshold: _largeThreshold,
            dailyLimit: _dailyLimit,
            maxDaily: _maxDaily,
            maxSingle: _maxSingle,
            kycThreshold: _kycThreshold,
            eta: eta,
            isCustom: true,
            active: true
        });
        emit PolicyChangeProposed(PolicyProfile.CUSTOM, eta, true, block.timestamp);
    }

    function executePolicyChange() external onlyAdmin {
        require(pendingPolicyChange.active, "AuditEngine: no pending policy change");
        require(block.timestamp >= pendingPolicyChange.eta, "AuditEngine: timelock has not expired");

        PolicyProfile applied = pendingPolicyChange.profile;
        if (pendingPolicyChange.isCustom) {
            _setCustomThresholds(
                pendingPolicyChange.largeThreshold,
                pendingPolicyChange.dailyLimit,
                pendingPolicyChange.maxDaily,
                pendingPolicyChange.maxSingle,
                pendingPolicyChange.kycThreshold
            );
        } else {
            _setPolicy(applied);
        }

        pendingPolicyChange.active = false;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "Policy change executed via timelock"
            );
        }

        emit PolicyChangeExecuted(applied, block.timestamp);
    }

    function executePolicyChangeWithMultiSig(uint256 _proposalId) external onlyAdmin {
        require(pendingPolicyChange.active, "AuditEngine: no pending policy change");
        require(isIntegrated && address(multiSig) != address(0), "AuditEngine: MultiSig not integrated");
        require(multiSig.isApproved(_proposalId), "AuditEngine: proposal not approved by MultiSig");

        MultiSigApproval.Proposal memory prop = multiSig.getProposal(_proposalId);
        require(
            prop.proposalType == MultiSigApproval.ProposalType.POLICY_CHANGE,
            "AuditEngine: invalid proposal type"
        );

        PolicyProfile applied = pendingPolicyChange.profile;
        if (pendingPolicyChange.isCustom) {
            _setCustomThresholds(
                pendingPolicyChange.largeThreshold,
                pendingPolicyChange.dailyLimit,
                pendingPolicyChange.maxDaily,
                pendingPolicyChange.maxSingle,
                pendingPolicyChange.kycThreshold
            );
        } else {
            _setPolicy(applied);
        }

        pendingPolicyChange.active = false;

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "Policy change executed via MultiSig bypass"
            );
        }

        emit PolicyChangeExecuted(applied, block.timestamp);
    }

    function cancelPolicyChange() external onlyAdmin {
        require(pendingPolicyChange.active, "AuditEngine: no pending policy change");
        pendingPolicyChange.active = false;
        emit PolicyChangeCancelled(block.timestamp);
    }

    function setPolicy(PolicyProfile _policy) external onlyAdmin {
        require(policyTimelockDelay == 0, "AuditEngine: timelock active - use proposePolicyChange");
        _setPolicy(_policy);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "Compliance policy changed"
            );
        }

        emit PolicyChanged(_policy, msg.sender, block.timestamp);
    }

    function setCustomThresholds(
        uint256 _largeThreshold,
        uint256 _dailyLimit,
        uint256 _maxDaily,
        uint256 _maxSingle,
        uint256 _kycThreshold
    ) external onlyAdmin {
        require(policyTimelockDelay == 0, "AuditEngine: timelock active - use proposeCustomThresholds");
        _setCustomThresholds(_largeThreshold, _dailyLimit, _maxDaily, _maxSingle, _kycThreshold);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "Custom thresholds updated"
            );
        }
    }

    // ============================================================
    // FEATURE 5: DUAL-CONTROL EMERGENCY CIRCUIT BREAKER
    // ============================================================

    /**
     * @notice Emergency Pause: freezes all transactions immediately
     * @dev Can be called by SUPER_ADMIN or AUDITOR
     */
    function emergencyPause(string calldata _reason) external onlyAuthorized whenNotPaused {
        isPaused = true;
        pauseEpoch++;
        emit EmergencyPaused(msg.sender, _reason, block.timestamp);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                string(abi.encodePacked("EMERGENCY PAUSE: ", _reason))
            );

            // Automated forensic trail entry
            if (address(forensicTrail) != address(0)) {
                uint256 incId = forensicTrail.createIncident("EMERGENCY_CIRCUIT_BREAKER", "CRITICAL");
                forensicTrail.submitEvidence(
                    incId,
                    "CIRCUIT_BREAKER_TRIGGERED",
                    _reason,
                    keccak256(abi.encodePacked(msg.sender, block.timestamp, _reason))
                );
            }
        }
    }

    /**
     * @notice Emergency Unpause: resumes transactions
     * @dev Dual-Control: Requires MultiSig approval if integrated, preventing rogue insider unpausing
     */
    function emergencyUnpause(uint256 _proposalId) external onlyAuthorized whenPaused {
        if (isIntegrated && address(multiSig) != address(0)) {
            require(multiSig.isApproved(_proposalId), "AuditEngine: unpause requires MultiSig approval");
            require(!_consumedProposals[_proposalId], "AuditEngine: proposal already executed or expired");
            _consumedProposals[_proposalId] = true;

            MultiSigApproval.Proposal memory prop = multiSig.getProposal(_proposalId);
            require(
                prop.proposalType == MultiSigApproval.ProposalType.POLICY_CHANGE ||
                prop.proposalType == MultiSigApproval.ProposalType.EMERGENCY_UNPAUSE,
                "AuditEngine: invalid unpause proposal type"
            );
        } else {
            require(msg.sender == admin, "AuditEngine: only admin can unpause");
        }

        isPaused = false;
        emit EmergencyUnpaused(msg.sender, _proposalId, block.timestamp);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "EMERGENCY UNPAUSE: Resumed operations"
            );
        }
    }

    /**
     * @notice Atomic execution from MultiSig coordinator to unpause engine
     * @param _expectedEpoch The pauseEpoch for which the unpause proposal was approved
     */
    function executeEmergencyUnpause(uint256 _expectedEpoch) external onlyGovernance whenPaused {
        require(_expectedEpoch == pauseEpoch, "AuditEngine: invalid pause epoch");
        isPaused = false;
        emit EmergencyUnpaused(msg.sender, 0, block.timestamp);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "EMERGENCY UNPAUSE: Resumed via MultiSig Governance"
            );
        }
    }

    /**
     * @notice Atomic execution from MultiSig coordinator to override a warning
     */
    function executeOverrideWarning(
        uint256 _txId,
        address _sender,
        address _receiver,
        string calldata _justification
    ) external onlyGovernance whenNotPaused {
        Transaction storage txn = _transactions[_txId];
        require(txn.status == AuditStatus.FLAGGED, "AuditEngine: can only override flagged transactions");
        require(txn.sender == _sender && txn.receiver == _receiver, "AuditEngine: transaction party mismatch");

        string memory previousWarning = txn.flagReason;
        txn.isFlagged = false;
        txn.flagReason = "";
        txn.status = AuditStatus.CLEARED;

        emit OverrideAttempted(msg.sender, _txId, previousWarning, block.timestamp);
        emit TransactionCleared(_txId, block.timestamp);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.TRANSACTION_OVERRIDE,
                _txId,
                _receiver,
                string(abi.encodePacked("MultiSig Governance: ", _justification))
            );
        }
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    function getTransaction(uint256 _txId) external view returns (Transaction memory) {
        require(_txId > 0 && _txId <= _transactionCounter, "AuditEngine: invalid txId");
        return _transactions[_txId];
    }

    function getFlaggedTransactions() external view returns (uint256[] memory flaggedIds) {
        uint256 count = 0;
        for (uint256 i = 0; i < _allTransactionIds.length; i++) {
            if (_transactions[_allTransactionIds[i]].isFlagged) count++;
        }
        flaggedIds = new uint256[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < _allTransactionIds.length; i++) {
            if (_transactions[_allTransactionIds[i]].isFlagged) {
                flaggedIds[idx++] = _allTransactionIds[i];
            }
        }
    }

    function getDailyVolume(address _addr) external view returns (uint256) {
        return _dailyVolume[_addr][_getToday()];
    }

    function getDailyCount(address _addr) external view returns (uint256) {
        return _dailyCount[_addr][_getToday()];
    }

    function isBlacklisted(address _addr) external view returns (bool) {
        return _blacklisted[_addr];
    }

    function isKYCVerified(address _addr) external view returns (bool) {
        return _kycVerified[_addr];
    }

    function totalTransactions() external view returns (uint256) {
        return _transactionCounter;
    }

    function getAllTransactionIds() external view returns (uint256[] memory) {
        return _allTransactionIds;
    }

    // ============================================================
    // INTERNAL HELPERS
    // ============================================================

    function _getToday() internal view returns (uint256) {
        return block.timestamp / 1 days;
    }
}
