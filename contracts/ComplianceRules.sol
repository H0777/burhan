// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ComplianceRules
 * @author H0777
 * @notice AML/KYC compliance constants aligned with Iraqi Central Bank guidelines
 * @dev All thresholds are in wei units (1 ether = 1e18 wei)
 * Thresholds represent equivalent values in Iraqi Dinar context
 */
contract ComplianceRules {

    // Large transaction reporting threshold (~$10,000 equivalent)
    // Transactions at or above this amount are flagged for mandatory review
    uint256 public constant LARGE_TRANSACTION_THRESHOLD = 10_000 ether;

    // Maximum daily volume per address (~$50,000 equivalent)
    // Prevents structuring/smurfing attempts to avoid reporting
    uint256 public constant DAILY_VOLUME_LIMIT = 50_000 ether;

    // Maximum daily transaction count per address
    // Unusual frequency is a key AML red flag indicator
    uint256 public constant MAX_DAILY_TRANSACTIONS = 20;

    // Hard cap on single transaction size
    // Acts as a safety valve against input errors and extreme outliers
    uint256 public constant MAX_SINGLE_TRANSACTION = 100_000 ether;

    // KYC verification threshold (~$5,000 equivalent)
    // Transfers above this require sender identity verification
    uint256 public constant KYC_REQUIRED_THRESHOLD = 5_000 ether;
}
