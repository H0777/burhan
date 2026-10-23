// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ComplianceRules
 * @author H0777
 * @notice AML/KYC compliance rules with configurable policy profiles
 * @dev Supports multiple regulatory frameworks:
 *      - IRAQ_CBI:   Central Bank of Iraq guidelines
 *      - GLOBAL_FATF: Financial Action Task Force international standards
 *      - CUSTOM:      User-defined thresholds for any jurisdiction
 *
 * All thresholds are in wei units (1 ether = 1e18 wei)
 */
contract ComplianceRules {

    // ============================================================
    // POLICY PROFILES
    // ============================================================

    enum PolicyProfile { IRAQ_CBI, GLOBAL_FATF, CUSTOM }

    /// @notice Active policy profile
    PolicyProfile public activePolicy;

    // ============================================================
    // CONFIGURABLE THRESHOLDS
    // ============================================================

    /// @notice Large transaction reporting threshold
    uint256 public largeTransactionThreshold;

    /// @notice Maximum daily volume per address
    uint256 public dailyVolumeLimit;

    /// @notice Maximum daily transaction count per address
    uint256 public maxDailyTransactions;

    /// @notice Hard cap on single transaction size
    uint256 public maxSingleTransaction;

    /// @notice KYC verification threshold
    uint256 public kycRequiredThreshold;

    // ============================================================
    // LEGACY CONSTANTS (backward compatibility)
    // ============================================================

    uint256 public constant LARGE_TRANSACTION_THRESHOLD = 10_000 ether;
    uint256 public constant DAILY_VOLUME_LIMIT = 50_000 ether;
    uint256 public constant MAX_DAILY_TRANSACTIONS = 20;
    uint256 public constant MAX_SINGLE_TRANSACTION = 100_000 ether;
    uint256 public constant KYC_REQUIRED_THRESHOLD = 5_000 ether;

    // ============================================================
    // EVENTS
    // ============================================================

    event PolicyUpdated(
        PolicyProfile indexed newPolicy,
        address indexed updatedBy,
        uint256 timestamp
    );

    event ThresholdsUpdated(
        uint256 largeTransactionThreshold,
        uint256 dailyVolumeLimit,
        uint256 maxDailyTransactions,
        uint256 maxSingleTransaction,
        uint256 kycRequiredThreshold,
        address indexed updatedBy,
        uint256 timestamp
    );

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor() {
        // Default to Iraq CBI policy
        _applyIraqCBIPolicy();
        activePolicy = PolicyProfile.IRAQ_CBI;
    }

    // ============================================================
    // POLICY MANAGEMENT
    // ============================================================

    /**
     * @notice Switch to a predefined policy profile
     * @param _policy The policy profile to activate
     */
    function _setPolicy(PolicyProfile _policy) internal {
        if (_policy == PolicyProfile.IRAQ_CBI) {
            _applyIraqCBIPolicy();
        } else if (_policy == PolicyProfile.GLOBAL_FATF) {
            _applyGlobalFATFPolicy();
        }
        // CUSTOM policy retains current values

        activePolicy = _policy;
        emit PolicyUpdated(_policy, msg.sender, block.timestamp);
    }

    /**
     * @notice Set custom thresholds (for CUSTOM policy)
     * @param _largeThreshold Large transaction threshold
     * @param _dailyLimit Daily volume limit
     * @param _maxDaily Maximum daily transactions
     * @param _maxSingle Maximum single transaction
     * @param _kycThreshold KYC required threshold
     */
    function _setCustomThresholds(
        uint256 _largeThreshold,
        uint256 _dailyLimit,
        uint256 _maxDaily,
        uint256 _maxSingle,
        uint256 _kycThreshold
    ) internal {
        require(_largeThreshold > 0, "ComplianceRules: invalid large threshold");
        require(_dailyLimit > _largeThreshold, "ComplianceRules: daily limit must exceed large threshold");
        require(_maxDaily > 0, "ComplianceRules: invalid max daily");
        require(_maxSingle > _largeThreshold, "ComplianceRules: max single must exceed large threshold");
        require(_kycThreshold > 0, "ComplianceRules: invalid KYC threshold");

        largeTransactionThreshold = _largeThreshold;
        dailyVolumeLimit = _dailyLimit;
        maxDailyTransactions = _maxDaily;
        maxSingleTransaction = _maxSingle;
        kycRequiredThreshold = _kycThreshold;

        activePolicy = PolicyProfile.CUSTOM;

        emit ThresholdsUpdated(
            _largeThreshold,
            _dailyLimit,
            _maxDaily,
            _maxSingle,
            _kycThreshold,
            msg.sender,
            block.timestamp
        );
    }

    // ============================================================
    // PREDEFINED POLICIES
    // ============================================================

    /**
     * @dev Iraq Central Bank (CBI) compliance thresholds
     *      Based on Iraqi AML Law No. 39 of 2015
     */
    function _applyIraqCBIPolicy() internal {
        largeTransactionThreshold = 10_000 ether;   // ~$10,000 equivalent
        dailyVolumeLimit = 50_000 ether;             // ~$50,000/day
        maxDailyTransactions = 20;
        maxSingleTransaction = 100_000 ether;        // ~$100,000 hard cap
        kycRequiredThreshold = 5_000 ether;           // ~$5,000 KYC trigger
    }

    /**
     * @dev FATF (Financial Action Task Force) international standards
     *      Generally stricter thresholds for global compliance
     */
    function _applyGlobalFATFPolicy() internal {
        largeTransactionThreshold = 8_000 ether;     // ~$8,000 (lower threshold)
        dailyVolumeLimit = 30_000 ether;             // ~$30,000/day (stricter)
        maxDailyTransactions = 15;                   // Fewer transactions allowed
        maxSingleTransaction = 50_000 ether;         // ~$50,000 hard cap
        kycRequiredThreshold = 3_000 ether;           // ~$3,000 KYC trigger (stricter)
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    /**
     * @notice Get all current active thresholds
     */
    function getActiveThresholds() external view returns (
        uint256 _largeThreshold,
        uint256 _dailyLimit,
        uint256 _maxDaily,
        uint256 _maxSingle,
        uint256 _kycThreshold,
        PolicyProfile _policy
    ) {
        return (
            largeTransactionThreshold,
            dailyVolumeLimit,
            maxDailyTransactions,
            maxSingleTransaction,
            kycRequiredThreshold,
            activePolicy
        );
    }
}
