<div align="center">

# 🛡️ Iraq AML Cyber-Audit Chain
### Integrating Digital Forensics and Financial Accounting: A Cyber-Auditing System for Mitigating Insider Threat Fraud

[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-363636?style=for-the-badge&logo=solidity)](https://soliditylang.org/)
[![Hardhat](https://img.shields.io/badge/Hardhat-2.22-yellow?style=for-the-badge&logo=ethereum)](https://hardhat.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![React](https://img.shields.io/badge/React-18.x-61DAFB?style=for-the-badge&logo=react)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC?style=for-the-badge&logo=tailwind-css)](https://tailwindcss.com/)
[![Vite](https://img.shields.io/badge/Vite-5.x-646CFF?style=for-the-badge&logo=vite)](https://vitejs.dev/)

[![Tests](https://img.shields.io/badge/Tests-490%2B_Passing-brightgreen?style=for-the-badge)](./test)
[![Coverage](https://img.shields.io/badge/Contract_Coverage-100%25-brightgreen?style=for-the-badge)](./audit-report/SECURITY_AUDIT.md)
[![Security](https://img.shields.io/badge/Security-Audited_%26_Remediated-blue?style=for-the-badge&logo=shield)](./audit-report/SECURITY_AUDIT.md)
[![Compliance](https://img.shields.io/badge/Compliance-CBI_Law_39%2F2015_%26_FATF-gold?style=for-the-badge)](./docs/architecture.md)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](./LICENSE)

**A Hybrid Blockchain & AI-Powered Continuous Audit Ledger for Banking Compliance & Internal Fraud Mitigation**  
*Built for the Iraqi Banking & Fintech Ecosystem (Central Bank of Iraq Compliance)*

[Architecture](./docs/architecture.md) • [Defense Presentation](./docs/defense-presentation.md) • [Security Audit](./audit-report/SECURITY_AUDIT.md) • [Smart Contracts](./contracts) • [AI Engine](./ai-engine) • [Frontend](./frontend)

</div>

---

## 📋 Overview

**Iraq AML Cyber-Audit Chain** is an enterprise-grade, hybrid cyber-auditing and digital forensic platform that bridges the gap between **Financial Forensic Accounting**, **Digital Forensics**, and **Machine Intelligence**.

Traditional financial auditing relies heavily on retrospective periodic sampling, manual spreadsheet reviews, and centralized ERP databases — leaving institutions acutely vulnerable to **authorized insider threats** (e.g., auditors, compliance managers, and privileged operators) who exploit administrative access to override Anti-Money Laundering (AML) controls, manipulate system logs, or collude in illicit transfers.

This platform resolves the insider threat dilemma by enforcing **cryptographic Zero-Trust governance** across three integrated tiers:
1. **On-Chain Cryptographic Consensus (Solidity `^0.8.20`)**: Guarantees deterministic AML/KYC rule enforcement, multi-signature 4-eyes controls, separation of duties, and an append-only, tamper-evident forensic chain of custody.
2. **Off-Chain AI Reasoning Engine (FastAPI & Machine Learning)**: Provides pre-execution fraud scoring (Isolation Forest + heuristics), structuring/smurfing pattern detection, operator behavioral profiling, and AST-based smart contract backdoor audits.
3. **Presentation & Forensic Telemetry (React 18 + Vite + Tailwind CSS)**: High-performance, bilingual (Arabic RTL & English LTR) judicial telemetry console featuring 7 investigative modules and verifiable PDF/print forensic dossiers.

---

## 🏛️ Tri-Tier Architecture

```
+-----------------------------------------------------------------------------------+
|                       TIER 3: PRESENTATION & TELEMETRY LAYER                      |
|     React 18 + Vite + Tailwind CSS 3.4 | Dark Glassmorphic Cyber Interface       |
|     Bilingual (Arabic RTL / English LTR) | 7 Specialized Forensic Modules         |
+-----------------------------------------------------------------------------------+
                                    |               |
                         JSON-RPC   |               | REST / OpenAPI v2
                         WebSockets |               | (Port 8000)
                                    v               v
+-----------------------------------------------------------------------------------+
|                       TIER 2: OFF-CHAIN AI REASONING ENGINE                       |
|  - FastAPI Microservice                      - Isolation Forest Anomaly Detection |
|  - Pre-Execution Anomaly Scoring             - Insider Threat Behavioral Profiler |
|  - Structuring / Smurfing Pattern Engine     - Smart Contract Backdoor Auditor    |
|  - Bilingual Judicial Dossier Generator      - Continuous Blockchain Event Sync   |
+-----------------------------------------------------------------------------------+
                                    |
                           Smart Contract Calls
                           & Event Emission
                                    v
+-----------------------------------------------------------------------------------+
|                  TIER 1: ON-CHAIN IMMUTABLE CRYPTOGRAPHIC CONSENSUS               |
|  RoleManager.sol       MultiSigApproval.sol       AuditEngine.sol                 |
|  - Hierarchical RBAC   - Four-Eyes Principle      - Separation of Duties (SoD)    |
|  - Timelocked Policies - Dual Authorization       - Emergency Circuit Breaker     |
|                                                                                   |
|  ForensicTrail.sol                                InsiderActivityLog.sol          |
|  - Recursive SHA-256 Chain of Custody             - Operator Behavioral Counters  |
|  - Merkle-Anchored Evidence Records               - Collusion & Override Alarms   |
+-----------------------------------------------------------------------------------+
```

---

## ✨ Key Features & Capabilities

### 1. On-Chain Smart Contract Core (`contracts/`)
- **Deterministic AML/KYC Rule Enforcement**: Automatically flags or blocks suspicious transfers based on Central Bank of Iraq (CBI) thresholds and FATF recommendations.
- **Cryptographic Chain of Custody (`ForensicTrail.sol`)**: Maintains a lightweight, recursively hashed header chain of all security and audit events:
  $$	ext{EntryHash}_n = 	ext{keccak256}\Big(n, 	ext{Timestamp}, 	ext{IncidentType}, 	ext{Operator}, 	ext{Actor}, 	ext{EvidenceHash}, 	ext{EntryHash}_{n-1}\Big)$$
  Any off-chain tampering immediately breaks mathematical continuity, detectable via `verifyChainIntegrity()`.
- **Insider Threat Activity Logging (`InsiderActivityLog.sol`)**: Autonomous on-chain accounting of operator behaviors, including after-hours operations (outside 08:00–17:00), repeated AML warning overrides, and beneficiary concentration.
- **Separation of Duties (SoD)**: Cryptographically prohibits transacting parties (sender or receiver) from overriding, clearing, or adjudicating their own transactions.
- **Four-Eyes Principle (`MultiSigApproval.sol`)**: High-risk operations (unpausing after an emergency stop, overriding AML warnings, modifying compliance rules) mandate dual-control multi-signature approval ($M$-of-$N$ quorum, $M \ge 2$) from distinct enrolled identities.
- **Timelocked Governance**: Sensitive policy parameter changes require an enforced timelock period (24 hours / 86,400s) to prevent hasty or unauthorized administrative modifications.

### 2. Off-Chain AI Reasoning Engine (`ai-engine/`)
- **Multi-Factor Fraud Detection**: Combines Machine Learning (Isolation Forest anomaly scores) with financial accounting heuristics:
  - **Structuring / Smurfing**: Flags intentional transaction slicing just below reporting ceilings ($[0.85 	imes 	ext{Limit}, 	ext{Limit})$).
  - **Velocity Spikes**: Tracks 24-hour volume bursts and transaction frequency anomalies.
  - **KYC Verification**: Evaluates sender and counterparty verification states.
- **Insider Threat Behavioral Profiler**: Computes risk coefficients on bank personnel, flagging anomalous access patterns, sub-10-second rapid approvals, and unauthorized override sprees.
- **Solidity Backdoor Auditor**: Analyzes smart contract source code using Abstract Syntax Trees (AST) and security heuristics to detect insider-planted backdoors (e.g., `tx.origin` phishing CWE-287, arbitrary `selfdestruct` CWE-284, reentrancy vulnerabilities CWE-829, unbounded minting).
- **Bilingual Forensic Dossier Generator**: Generates court-admissible forensic reports in Arabic and English, complete with cryptographic Merkle proof hashes, timestamping, and regulatory audit notes.

### 3. Judicial Telemetry & Web Dashboard (`frontend/`)
- **Bilingual Design**: Native Arabic (RTL) and English (LTR) modes tailored for Iraqi banking compliance officers, Central Bank observers, and judicial authorities.
- **7 Investigative Modules**:
  1. `Dashboard`: Real-time transaction flow, AML status breakdown, high-velocity alerts, and key performance indicators.
  2. `Case Workspace`: End-to-end incident lifecycle management and evidence chain tracking.
  3. `Insider Threat Monitor`: Operator threat score matrix, override counters, and simulated collusion detection.
  4. `Forensic Explorer`: Interactive visual chain of custody timeline with live hash verification and tamper-detection simulations.
  5. `AI Risk Scoring Panel`: Real-time pre-execution scoring simulator and structuring detection alerts.
  6. `Smart Contract Auditor`: Automated backdoor scanner with sample contracts and vulnerability breakdowns.
  7. `Governance & MultiSig`: Dual-control proposal submission, 4-eyes voting queue, and RBAC directory.

---

## ⚖️ Regulatory Compliance Matrix

Aligned with **Central Bank of Iraq (CBI) Anti-Money Laundering and Counter-Terrorism Financing Law No. 39 of 2015** and **FATF 40 Recommendations**:

| Compliance Parameter | Rule / Regulatory Reference | Threshold | System Action | Governance Enforcement |
|---|---|---|---|---|
| **Large Transaction (CTR)** | AML Law No. 39 (Art. 12) / FATF Rec. 10 | > 10,000 ETH / IQD Equiv. | Flag for Mandatory Review | Auto-record in `ForensicTrail` |
| **KYC Mandate** | Central Bank of Iraq KYC Regulations | > 5,000 ETH / IQD Equiv. | Block if Unverified | Enforce Verified Identity Status |
| **Daily Velocity Cap** | Structuring & Velocity Monitoring | > 50,000 ETH/day | Flag Account & Freeze Outflow | Require MultiSig Audit Override |
| **Structuring (Smurfing)** | FATF Recommendation 20 (STRs) | 85% - 99.9% of Threshold | Flag as Structuring Anomaly | AI Score Adjustment (+35 pts) |
| **Max Single Transfer** | Absolute Hard Stop | 100,000 ETH / Equiv. | Immediate Hard Revert | Cryptographically Non-Bypassable |
| **Warning Override** | Four-Eyes Control Principle | Operator Override Request | Require MultiSig Approval | $M$-of-$N$ Quorum ($M \ge 2$) |

---

## 📂 Repository Structure

```text
iraq-aml-audit-chain/
├── contracts/                          # Solidity 0.8.20 Smart Contracts
│   ├── AuditEngine.sol                 # Core AML compliance & audit engine
│   ├── ComplianceRules.sol             # Regulatory policy constants & thresholds
│   ├── access/
│   │   ├── RoleManager.sol             # Hierarchical RBAC & identity roster
│   │   └── MultiSigApproval.sol        # Four-Eyes dual-control approval system
│   ├── forensics/
│   │   ├── ForensicTrail.sol           # Immutable hash-linked chain of custody
│   │   └── InsiderActivityLog.sol      # Behavioral operator telemetry
│   ├── libraries/
│   │   └── EvidenceHashing.sol         # Canonical V2 evidence hashing library
│   └── interfaces/                     # Contract interfaces (IAuditEngine, etc.)
├── ai-engine/                          # Python 3.11+ AI Reasoning Microservice
│   ├── app/
│   │   ├── main.py                     # FastAPI application entry point
│   │   ├── models/
│   │   │   ├── fraud_detector.py       # Multi-factor ML & heuristic fraud model
│   │   │   └── insider_analyzer.py     # Operator threat scoring model
│   │   ├── routes/                     # REST API endpoints (v2, v3, forensics)
│   │   └── services/                   # LLM synthesis & event listeners
│   └── tests/                          # 220+ API, ML, and integration tests
├── frontend/                           # React 18 + Vite + Tailwind CSS Console
│   ├── src/
│   │   ├── components/                 # 7 Specialized forensic & audit modules
│   │   ├── hooks/                      # Web3 and state management hooks
│   │   ├── config/                     # Dynamic runtime schema configuration
│   │   └── locales/                    # Bilingual translations (Arabic / English)
│   └── dist/                           # Optimized production build
├── deployments/                        # Verified deployment manifests & schemas
├── scripts/                            # Automation, deployment, and verification
│   ├── deploy.js                       # Hardhat multi-contract orchestrator
│   ├── simulate-fraud-case.js          # Interactive AML attack simulation
│   └── verify-deployment.js            # Deployment integrity verification
├── docs/                               # Technical & Academic Documentation
│   ├── architecture.md                 # In-depth architectural specification
│   └── defense-presentation.md         # Academic defense presentation deck
├── audit-report/                       # Security Audits & Remediation Register
│   └── SECURITY_AUDIT.md               # Formal vulnerability audit report
├── hardhat.config.js                   # Hardhat network & compiler configuration
├── package.json                        # Monorepo dependencies & scripts
└── README.md                           # Master project documentation
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Node.js**: `>= 18.0.0` (LTS recommended)
- **npm**: `>= 9.0.0`
- **Python**: `>= 3.11.0`
- **Git**

### 1. Clone & Install Dependencies

```bash
# Clone repository
git clone https://github.com/H0777/iraq-aml-audit-chain.git
cd iraq-aml-audit-chain

# Install root & contract dependencies
npm install

# Install frontend dependencies
cd frontend && npm install && cd ..

# Install AI engine dependencies
cd ai-engine && pip install -r requirements.txt && cd ..
```

### 2. Compile & Test Smart Contracts

```bash
# Compile Solidity contracts
npx hardhat compile

# Run complete contract test suite (206 passing)
npx hardhat test

# Generate code coverage report (100% coverage)
npx hardhat coverage
```

### 3. Launch Local Blockchain & Deploy

```bash
# Terminal 1: Start local Hardhat EVM node
npx hardhat node

# Terminal 2: Deploy and bootstrap contracts
npm run deploy:local
```

### 4. Run the AI Reasoning Engine

```bash
cd ai-engine
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Launch the Forensic Dashboard

```bash
cd frontend
npm run dev
```
Open your browser at `http://localhost:5173` to access the interactive audit console.

---

## 🧪 Test Suites & Verification Gates

The project enforces strict verification gates across all layers with **over 490 automated tests**:

```bash
# Run full verification suite across all subsystems
npm run verify:all
```

### Test Coverage Summary
| Subsystem | Test Framework | Test Count | Pass Rate | Coverage |
|---|---|---|---|---|
| **Smart Contracts** | Hardhat / Mocha / Chai | **206 Tests** | 100% | **100% Lines & Branches** |
| **AI Engine & API** | PyTest / FastAPI TestClient | **221 Tests** | 100% | High Precision / Parity |
| **Frontend Dashboard** | Vitest / React Testing Library | **65 Tests** | 100% | Component & Auth Validated |
| **Total Verified** | Multi-Layer Integration | **492+ Tests** | **100%** | **Production Grade** |

---

## 🔒 Security Audit & Remediations

The codebase has undergone extensive security reviews and formal verification against typical smart contract vulnerabilities and insider exploit vectors.

**Key Remediations Implemented (F01 - F14):**
- **Zero Backdoor Guarantee (F01/R01)**: Fully eliminated test mutator backdoors from production ABIs and bytecode.
- **Immutable Identity Binding (F02/R02)**: Prevented wallet recycling and duplicate enrollments; guaranteed generation monotonicity.
- **Separation of Duties (F03/R03)**: Strictly blocked actors from voting on or clearing transactions involving their own addresses.
- **Bytecode Budget Enforcement (F04/R04)**: All contracts conform strictly to the EIP-170 code size ceiling ($< 24,576$ bytes).
- **Tamper-Evident Manifest Verification (F05/R09)**: Built standalone offline verification tool for AML dossier manifests.
- **Epoch-Protected Emergency Pause (F11/R14)**: Prevented replay of stale unpause proposals across multiple circuit breaker cycles.

For the complete audit findings, see [SECURITY_AUDIT.md](./audit-report/SECURITY_AUDIT.md).

---

## 👨‍💻 Research & Academic Attribution

**Hussein Faez**  
*Specialization:* Digital Forensics, Cybersecurity & Financial Accounting  
*Country:* Republic of Iraq  
*GitHub:* [@H0777](https://github.com/H0777)  

> **Academic Thesis / Research Project:**  
> *"Integrating Digital Forensics and Financial Accounting: A Cyber-Auditing System for Mitigating Insider Threat Fraud"*  
> Combining distributed ledger technology, machine learning, and forensic accounting principles to protect sovereign and commercial banking infrastructure against authorized insider threats.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.

<div align="center">

**Built with pride for the development and security of the Iraqi Banking Sector 🇮🇶**

</div>
