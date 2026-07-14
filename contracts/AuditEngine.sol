// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ComplianceRules.sol";
import "./interfaces/IAuditEngine.sol";

/**
 * @title AuditEngine
 * @author H0777
 * @notice Automated blockchain-based financial audit system for Iraqi banking sector
 * @dev Implements AML/KYC compliance rules with immutable audit trail
 * Security: Protected against reentrancy, overflow, unauthorized access
 */
contract AuditEngine is IAuditEngine, ComplianceRules {

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    address public immutable admin;
    uint256 private _transactionCounter;

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

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyAdmin() {
        require(msg.sender == admin, "AuditEngine: caller is not admin");
        _;
    }

    modifier notBlacklisted(address _addr) {
        require(!_blacklisted[_addr], "AuditEngine: address is blacklisted");
        _;
    }

    modifier validAmount(uint256 _amount) {
        require(_amount > 0, "AuditEngine: amount must be greater than zero");
        require(_amount <= MAX_SINGLE_TRANSACTION, "AuditEngine: amount exceeds maximum");
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor() {
        admin = msg.sender;
        _transactionCounter = 0;
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
    // INTERNAL AUDIT ENGINE
    // ============================================================

    /**
     * @dev Core audit logic - evaluates all AML/KYC compliance rules
     * @param _txId Transaction ID to evaluate
     * @param today Current day bucket for daily limits
     */
    function _runAuditEngine(uint256 _txId, uint256 today) internal {
        Transaction storage txn = _transactions[_txId];

        // Rule 1: Large transaction threshold
        if (txn.amount >= LARGE_TRANSACTION_THRESHOLD) {
            _flagTransaction(_txId, "LARGE_TRANSACTION: Amount exceeds reporting threshold");
            return;
        }

        // Rule 2: Daily volume limit
        if (_dailyVolume[txn.sender][today] >= DAILY_VOLUME_LIMIT) {
            _flagTransaction(_txId, "DAILY_LIMIT_EXCEEDED: Daily volume limit reached");
            return;
        }

        // Rule 3: Suspicious transaction frequency
        if (_dailyCount[txn.sender][today] >= MAX_DAILY_TRANSACTIONS) {
            _flagTransaction(_txId, "SUSPICIOUS_FREQUENCY: Too many transactions in 24 hours");
            return;
        }

        // Rule 4: KYC verification required for high-value transfers
        if (txn.amount >= KYC_REQUIRED_THRESHOLD && !_kycVerified[txn.sender]) {
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

    // ============================================================
    // ADMIN FUNCTIONS
    // ============================================================

    function blockTransaction(uint256 _txId) external onlyAdmin {
        Transaction storage txn = _transactions[_txId];
        require(txn.status == AuditStatus.FLAGGED, "AuditEngine: can only block flagged transactions");
        txn.status = AuditStatus.BLOCKED;
        emit TransactionBlocked(_txId, txn.sender, txn.flagReason);
    }

    function addToBlacklist(address _addr, string calldata _reason) external onlyAdmin {
        require(_addr != address(0), "AuditEngine: invalid address");
        require(_addr != admin, "AuditEngine: cannot blacklist admin");
        _blacklisted[_addr] = true;
        emit AddressBlacklisted(_addr, _reason);
    }

    function removeFromBlacklist(address _addr) external onlyAdmin {
        _blacklisted[_addr] = false;
        emit AddressWhitelisted(_addr);
    }

    function verifyKYC(address _addr) external onlyAdmin {
        require(_addr != address(0), "AuditEngine: invalid address");
        _kycVerified[_addr] = true;
        emit KYCVerified(_addr);
    }

    function revokeKYC(address _addr) external onlyAdmin {
        _kycVerified[_addr] = false;
        emit KYCRevoked(_addr);
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
