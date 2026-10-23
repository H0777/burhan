"""
Unit Tests for Smart Contract Scanner & Comment Stripping (T21)
Specification §7 & §9 (R12, R14, R15)
"""

import pytest
from app.services.scanner_service import (
    ContractScannerService,
    strip_solidity_comments,
    MAX_CODE_SIZE_BYTES,
)

scanner = ContractScannerService()


def test_commented_tx_origin_not_flagged():
    """
    Ensures comments referencing tx.origin do NOT cause false positive vulnerability alerts.
    """
    solidity_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureVault {
    address public immutable owner;

    // NOTE: We intentionally avoid tx.origin because it is insecure.
    /* 
       tx.origin could lead to phishing vulnerabilities!
    */
    constructor() {
        owner = msg.sender;
    }

    function withdraw() external {
        require(msg.sender == owner, "Unauthorized");
    }
}
"""
    result = scanner.scan_contract(solidity_code)
    assert result.status == "NO_DETECTED_PATTERNS"
    assert len(result.findings) == 0
    assert any("Absence of detected patterns does NOT certify" in lim for lim in result.limitations)


def test_actual_tx_origin_usage_flagged():
    """
    Ensures executable tx.origin is flagged with the exact line number.
    """
    solidity_code = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    address public owner;

    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Only owner");
        owner = newOwner;
    }
}
"""
    result = scanner.scan_contract(solidity_code)
    assert result.status == "VULNERABILITIES_FOUND"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.vulnerability_type == "TX_ORIGIN_AUTHENTICATION"
    assert finding.severity == "HIGH"
    assert finding.line_number == 8
    assert "tx.origin == owner" in finding.matched_snippet


def test_selfdestruct_critical_severity_flagged():
    """
    Ensures selfdestruct opcode is flagged with CRITICAL severity.
    """
    solidity_code = """pragma solidity ^0.8.20;

contract Killable {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
"""
    result = scanner.scan_contract(solidity_code)
    assert result.status == "VULNERABILITIES_FOUND"
    assert any(f.vulnerability_type == "UNPROTECTED_SELFDESTRUCT" and f.severity == "CRITICAL" for f in result.findings)


def test_oversized_code_rejected():
    """
    Ensures source code exceeding 200 KB is rejected with an explicit error.
    """
    huge_code = "// test\n" * ((MAX_CODE_SIZE_BYTES // 7) + 500)
    with pytest.raises(ValueError) as exc:
        scanner.scan_contract(huge_code)
    assert "exceeds maximum permitted size" in str(exc.value)


def test_empty_code_rejected():
    with pytest.raises(ValueError) as exc:
        scanner.scan_contract("   ")
    assert "cannot be empty" in str(exc.value)
