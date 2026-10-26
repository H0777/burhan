"""
Unit tests for Smart Contract Security Scanner
"""

import pytest
from app.services.gemini_service import gemini_service


def test_clean_secure_contract():
    code = """
    // SPDX-License-Identifier: MIT
    pragma solidity 0.8.20;

    contract SafeBank {
        mapping(address => uint256) public balances;

        event Deposit(address indexed user, uint256 amount);

        function deposit() external payable {
            balances[msg.sender] += msg.value;
            emit Deposit(msg.sender, msg.value);
        }
    }
    """
    result = gemini_service.scan_contract(code, "SafeBank")
    assert result["passed_audit"] is True
    assert result["security_rating"] in ("SECURE", "LOW_RISK")
    assert result["vulnerability_score"] < 30


def test_vulnerable_contract_tx_origin():
    code = """
    pragma solidity ^0.8.0;

    contract Phishable {
        address public owner;
        function withdraw() public {
            require(tx.origin == owner);
            selfdestruct(payable(owner));
        }
    }
    """
    result = gemini_service.scan_contract(code, "Phishable")
    assert result["passed_audit"] is False
    assert result["security_rating"] == "CRITICAL_RISK"
    assert result["vulnerability_score"] >= 60

    finding_ids = [f["id"] for f in result["findings"]]
    assert "SEC-01" in finding_ids  # tx.origin
    assert "SEC-03" in finding_ids  # selfdestruct
