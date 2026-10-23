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
    event AutomatedForensicIncidentCreated(uint256 indexed incidentId, uint256 indexed txId, string severity, uint256 timestamp);

    // ============================================================
    // MODIFIERS
    // ============================================================

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
            incidentId = forensicTrail.createIncident(
                keccak256(bytes(_title)),
                keccak256(bytes(_severity))
            );
            forensicTrail.submitEvidence(
                incidentId,
                keccak256(abi.encodePacked(block.chainid, address(this), _txId, block.timestamp, "AUDIT_ALARM")),
                keccak256("AUTOMATED_AUDIT_ALARM"),
                keccak256(bytes(_description)),
                sha256(abi.encodePacked(_txId, block.timestamp, _description))
            );
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
    // FEATURE 4 (R03): GOVERNANCE-ONLY POLICY EXECUTION
    // ============================================================
    // The parallel admin paths (setPolicyTimelockDelay, proposePolicyChange,
    // proposeCustomThresholds, executePolicyChange(), executePolicyChangeWithMultiSig,
    // cancelPolicyChange, setPolicy, setCustomThresholds) are REMOVED. The
    // decision and its timing live in the MultiSig coordinator alone: a
    // POLICY_CHANGE proposal (86,400s delay) delivers the approved bytes here.
    // These functions do NOT read any parallel proposal inside AuditEngine.

    /**
     * @notice R03: apply a predefined compliance policy profile (governance only)
     * @dev In the integrated system governance is the MultiSig coordinator, so
     *      this is reachable exclusively through an executed POLICY_CHANGE
     *      proposal. No timelock is re-evaluated here — the coordinator's
     *      notBefore already enforced the 86,400s delay.
     */
    function executePolicyChange(PolicyProfile _policy) external onlyGovernance {
        _setPolicy(_policy);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "Policy change executed via governance"
            );
        }

        emit PolicyChanged(_policy, msg.sender, block.timestamp);
    }

    /**
     * @notice R03: apply custom compliance thresholds (governance only)
     * @dev Delivered through an executed POLICY_CHANGE proposal carrying
     *      executeCustomThresholds calldata; threshold validation lives in
     *      ComplianceRules._setCustomThresholds.
     */
    function executeCustomThresholds(
        uint256 _largeThreshold,
        uint256 _dailyLimit,
        uint256 _maxDaily,
        uint256 _maxSingle,
        uint256 _kycThreshold
    ) external onlyGovernance {
        _setCustomThresholds(_largeThreshold, _dailyLimit, _maxDaily, _maxSingle, _kycThreshold);

        if (isIntegrated) {
            insiderLog.logActivity(
                msg.sender,
                InsiderActivityLog.ActivityType.POLICY_CHANGE,
                0,
                address(0),
                "Custom thresholds executed via governance"
            );
        }
    }

    /**
     * @notice R03: configure business hours of the InsiderActivityLog
     *      (governance only; SYSTEM_CONFIG closed action, 86,400s delay)
     * @dev UTC context — the authoritative window lives in InsiderActivityLog;
     *      this wrapper keeps the SYSTEM_CONFIG target on the AuditEngine.
     */
    function setBusinessHours(uint8 _start, uint8 _end) external onlyGovernance {
        require(isIntegrated && address(insiderLog) != address(0), "AuditEngine: InsiderLog not integrated");
        insiderLog.setBusinessHours(_start, _end);
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
                uint256 incId = forensicTrail.createIncident(
                    keccak256("EMERGENCY_CIRCUIT_BREAKER"),
                    keccak256("CRITICAL")
                );
                forensicTrail.submitEvidence(
                    incId,
                    keccak256(abi.encodePacked(block.chainid, address(this), pauseEpoch, block.timestamp, "CIRCUIT_BREAKER")),
                    keccak256("CIRCUIT_BREAKER_TRIGGERED"),
                    keccak256(bytes(_reason)),
                    sha256(abi.encodePacked(msg.sender, block.timestamp, _reason))
                );
            }
        }
    }

    /**
     * @notice Atomic execution from MultiSig coordinator to unpause engine
     * @dev R03: the legacy emergencyUnpause(proposalId) consumer path is REMOVED
     *      (dual control is enforced by the coordinator). The unpause is bound
     *      to the CURRENT pauseEpoch: a stale-epoch replay can never execute.
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
