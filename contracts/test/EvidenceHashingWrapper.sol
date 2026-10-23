// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libraries/EvidenceHashing.sol";

contract EvidenceHashingWrapper {
    function getDomain() external pure returns (bytes32) {
        return EvidenceHashing.DOMAIN;
    }

    function getSchemaVersion() external pure returns (uint16) {
        return EvidenceHashing.SCHEMA_VERSION;
    }

    function hashEntry(EvidenceHashing.EvidenceV2 memory entry) external pure returns (bytes32) {
        return EvidenceHashing.hashEntry(entry);
    }
}
