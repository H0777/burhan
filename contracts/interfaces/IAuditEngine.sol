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
}
