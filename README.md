<div align="center">

# Smart Audit Engine

![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?style=for-the-badge&logo=solidity)
![Hardhat](https://img.shields.io/badge/Hardhat-2.x-yellow?style=for-the-badge&logo=ethereum)
![Flutter](https://img.shields.io/badge/Flutter-3.x-02569B?style=for-the-badge&logo=flutter)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-100%25_Coverage-brightgreen?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Audited-red?style=for-the-badge&logo=shield)
![Blockchain](https://img.shields.io/badge/Blockchain-Ethereum-3C3C3D?style=for-the-badge&logo=ethereum)
![AML](https://img.shields.io/badge/Compliance-AML%2FKYC-blue?style=for-the-badge)

**Blockchain-based Automated Financial Audit System**
Built for the Iraqi Banking Sector with AML/KYC Compliance

[View Demo](https://h0777.github.io/smart-audit-engine) | [Security Audit Report](./audit-report/SECURITY_AUDIT.md) | [Documentation](./docs)

</div>

---

## Overview

Smart Audit Engine is an open-source, blockchain-based automated financial auditing system designed specifically for the Iraqi banking and fintech ecosystem. It uses Ethereum smart contracts to enforce AML/KYC compliance rules automatically, detect suspicious transactions in real-time, and provide an immutable audit trail — replacing manual, error-prone financial auditing processes.

This project uniquely combines:
- **Accounting domain knowledge** (AML thresholds, KYC requirements, transaction reporting)
- **Cybersecurity expertise** (smart contract security, reentrancy protection, access control)
- **Iraqi regulatory context** (Central Bank of Iraq compliance alignment)

---

## Architecture

```
smart-audit-engine/
├── contracts/                    # Solidity Smart Contracts
│   ├── AuditEngine.sol           # Core audit engine contract
│   ├── ComplianceRules.sol       # AML/KYC compliance constants
│   └── interfaces/
│       └── IAuditEngine.sol      # Contract interface
├── test/                         # 100% Coverage Test Suite
│   ├── AuditEngine.test.js       # Core engine tests
│   └── ComplianceRules.test.js   # Rules validation tests
├── scripts/
│   └── deploy.js                 # Deployment script
├── frontend/                     # Flutter Web Dashboard
│   └── lib/
│       ├── main.dart
│       ├── screens/
│       │   └── dashboard_screen.dart
│       └── services/
│           └── blockchain_service.dart
├── audit-report/
│   └── SECURITY_AUDIT.md         # Full security audit report
├── .github/
│   └── workflows/
│       └── ci.yml                # GitHub Actions CI/CD
├── hardhat.config.js
├── package.json
└── README.md
```

---

## Features

### Smart Contract Core
- **Automated AML Detection** — flags transactions exceeding regulatory thresholds
- **KYC Enforcement** — requires identity verification for high-value transfers
- **Daily Volume Limits** — tracks and enforces per-address daily limits
- **Suspicious Frequency Detection** — identifies unusual transaction patterns
- **Immutable Blacklist** — admin-controlled address blocking system
- **Event-Driven Audit Trail** — every action emits blockchain events for off-chain indexing
- **Role-Based Access Control** — admin-only sensitive operations

### Security Features
- Protection against reentrancy attacks
- Integer overflow protection (Solidity 0.8+)
- Access control modifiers on all sensitive functions
- Input validation and sanitization
- Self-transfer prevention
- Zero-address checks

### Compliance Rules (Iraqi Banking Context)
| Rule | Threshold | Action |
|------|-----------|--------|
| Large Transaction | > 10,000 units | Flag for review |
| Daily Volume Limit | > 50,000 units/day | Flag sender |
| Suspicious Frequency | > 20 tx/day | Flag sender |
| KYC Required | > 5,000 units | Block if unverified |
| Max Single Transaction | 100,000 units | Hard reject |

---

## Quick Start

### Prerequisites
```bash
node >= 18.0.0
npm >= 9.0.0
git
```

### Installation
```bash
# Clone the repository
git clone https://github.com/H0777/smart-audit-engine.git
cd smart-audit-engine

# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Run tests with coverage
npx hardhat coverage
```

### Deploy to Local Network
```bash
# Start local Hardhat node
npx hardhat node

# Deploy in a new terminal
npx hardhat run scripts/deploy.js --network localhost
```

### Deploy to Sepolia Testnet
```bash
# Set environment variables
cp .env.example .env
# Edit .env with your PRIVATE_KEY and SEPOLIA_RPC_URL

npx hardhat run scripts/deploy.js --network sepolia
```

---

## Smart Contract API

### Core Functions

```solidity
// Submit a transaction for audit
function submitTransaction(address _receiver, uint256 _amount) external returns (uint256 txId)

// Get transaction details
function getTransaction(uint256 _txId) external view returns (Transaction memory)

// Get all flagged transactions
function getFlaggedTransactions() external view returns (uint256[] memory)

// Check daily volume for an address
function getDailyVolume(address _addr) external view returns (uint256)
```

### Admin Functions
```solidity
// Block a flagged transaction
function blockTransaction(uint256 _txId) external onlyAdmin

// Manage blacklist
function addToBlacklist(address _addr, string calldata _reason) external onlyAdmin
function removeFromBlacklist(address _addr) external onlyAdmin

// KYC management
function verifyKYC(address _addr) external onlyAdmin
function revokeKYC(address _addr) external onlyAdmin
```

### Events
```solidity
event TransactionSubmitted(uint256 indexed txId, address indexed sender, address indexed receiver, uint256 amount, uint256 timestamp)
event TransactionFlagged(uint256 indexed txId, address indexed sender, string reason, uint256 timestamp)
event TransactionCleared(uint256 indexed txId, uint256 timestamp)
event TransactionBlocked(uint256 indexed txId, address indexed sender, string reason)
event AddressBlacklisted(address indexed target, string reason)
event KYCVerified(address indexed target)
```

---

## Testing

This project maintains **100% test coverage** across all contract functions.

```bash
npx hardhat coverage
```

| File | Statements | Branches | Functions | Lines |
|------|-----------|----------|-----------|-------|
| AuditEngine.sol | 100% | 100% | 100% | 100% |
| ComplianceRules.sol | 100% | 100% | 100% | 100% |

---

## Security Audit

A full manual security audit was conducted on all smart contracts. See [SECURITY_AUDIT.md](./audit-report/SECURITY_AUDIT.md) for the complete report.

**Audit Summary:**
- Critical issues found: 0
- High issues found: 0
- Medium issues found: 0
- Low issues found: 2 (gas optimization suggestions)
- Informational: 3

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Smart Contracts | Solidity 0.8.20 |
| Development Framework | Hardhat |
| Testing | Mocha + Chai + Ethers.js |
| Coverage | solidity-coverage |
| Frontend | Flutter Web |
| Blockchain Interaction | Web3.dart / ethers.js |
| CI/CD | GitHub Actions |
| Network | Ethereum / Sepolia Testnet |

---

## Author

**Hussein Faez** — Cybersecurity + Accounting  from Iraq
- Focus: Fintech Security, Smart Contract Auditing, AML Compliance Systems
- GitHub: [@H0777](https://github.com/H0777)

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

<div align="center">

Built with expertise in Cybersecurity + Accounting for the Iraqi Fintech ecosystem

</div>
