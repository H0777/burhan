// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IAuditEngine
 * @notice Interface for the Smart Audit Engine contract
 */
interface IAuditEngine {
    function submitTransaction(address _receiver, uint256 _amount) external returns (uint256);
    function blockTransaction(uint256 _txId) external;
    function addToBlacklist(address _addr, string calldata _reason) external;
    function removeFromBlacklist(address _addr) external;
    function verifyKYC(address _addr) external;
    function revokeKYC(address _addr) external;
    function getDailyVolume(address _addr) external view returns (uint256);
    function getDailyCount(address _addr) external view returns (uint256);
    function isBlacklisted(address _addr) external view returns (bool);
    function isKYCVerified(address _addr) external view returns (bool);
    function totalTransactions() external view returns (uint256);
    function getAllTransactionIds() external view returns (uint256[] memory);
    function getFlaggedTransactions() external view returns (uint256[] memory);

    // ------------------------------------------------------------
    // R03 governance decision surface (spec §4/§6). These are governance-only:
    // in the integrated system the MultiSig coordinator is the only caller,
    // delivering bytes approved under the closed action table.
    // (executePolicyChange(PolicyProfile) is intentionally NOT declared here:
    // PolicyProfile is owned by ComplianceRules and Solidity interface
    // matching requires identical type declarations.)
    // ------------------------------------------------------------

    /// @notice R03: apply custom compliance thresholds (governance only)
    function executeCustomThresholds(
        uint256 _largeThreshold,
        uint256 _dailyLimit,
        uint256 _maxDaily,
        uint256 _maxSingle,
        uint256 _kycThreshold
    ) external;

    /// @notice R03: override a flagged warning (governance only; the parties
    ///         are verified against the engine's own transaction record)
    function executeOverrideWarning(
        uint256 _txId,
        address _sender,
        address _receiver,
        string calldata _justification
    ) external;

    /// @notice R03: resume operations, bound to the current pauseEpoch
    function executeEmergencyUnpause(uint256 _expectedEpoch) external;

    /// @notice R03: configure InsiderActivityLog business hours (governance only)
    function setBusinessHours(uint8 _start, uint8 _end) external;
}
