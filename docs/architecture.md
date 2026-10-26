# System Architecture

## Integrating Digital Forensics and Financial Accounting: A Cyber-Auditing System for Mitigating Insider Threat Fraud

---

### 1. Architectural Philosophy & Dual-Layer Design

This system pioneers a symbiotic integration between **Digital Forensics**, **Financial Forensic Accounting**, and **Machine Intelligence**. Modern financial institutions face sophisticated adversaries from within: authorized insiders (auditors, compliance officers, and system operators) who exploit their credentials to bypass AML limits, rubber-stamp illicit transactions, or manipulate regulatory audit records.

To counter this insider threat vector, the system introduces a **Tri-Tier Hybrid Architecture**:

```
+-----------------------------------------------------------------------------------+
|                            TIER 3: PRESENTATION & TELEMETRY                        |
|   React + Vite Dashboard | 7 Specialized Modules | Bilingual Forensic Dossier    |
+-----------------------------------------------------------------------------------+
                                    |               |
                         JSON-RPC   |               | REST / OpenAPI
                         WebSockets |               | (Port 8000)
                                    v               v
+-----------------------------------------------------------------------------------+
|                        TIER 2: OFF-CHAIN AI REASONING ENGINE                       |
|   - FastAPI Microservice                 - Hybrid ML (Isolation Forest + AST)    |
|   - Pre-Execution Anomaly Scoring        - Insider Threat Behavioral Profiler     |
|   - Structuring / Smurfing Detector      - Gemini 1.5 Flash Forensic Synthesizer  |
|   - Smart Contract Backdoor Auditor      - Continuous EVM Event Listener          |
+-----------------------------------------------------------------------------------+
                                    |
                           Smart Contract Calls
                           & Event Emission
                                    v
+-----------------------------------------------------------------------------------+
|                     TIER 1: ON-CHAIN IMMUTABLE CRYPTOGRAPHIC CONSENSUS             |
|   RoleManager.sol       MultiSigApproval.sol     AuditEngine.sol                  |
|   - Hierarchical RBAC   - Four-Eyes Principle    - Core AML & SoD Controls        |
|   - Timelocked Policies - Dual Authorization     - Emergency Circuit Breaker      |
|                                                                                   |
|   ForensicTrail.sol                              InsiderActivityLog.sol           |
|   - Hash-Linked Chain of Custody                 - Operator Telemetry & Counters  |
|   - SHA-256 Recursive Evidence Proofs            - Override & Collusion Thresholds|
+-----------------------------------------------------------------------------------+
```

---

### 2. Tier 1: On-Chain Cryptographic Consensus

The blockchain layer guarantees **non-repudiation**, **tamper evidence**, and **deterministic policy enforcement**. It is authored in Solidity `^0.8.20` and deployed to Ethereum-compatible EVM networks.

#### 2.1 RoleManager (`contracts/access/RoleManager.sol`)
* **Hierarchical RBAC:** Manages four distinct enterprise roles:
  * `SUPER_ADMIN_ROLE`: High-level governance, role grant/revoke permissions.
  * `AUDITOR_ROLE`: Authorized to flag, review, and request overrides.
  * `OPERATOR_ROLE`: Standard day-to-day transaction processing.
  * `REGULATOR_ROLE`: Read-only judicial and Central Bank observer access.
* **Tamper-Evident History:** Emits `RoleGranted` and `RoleRevoked` events and maintains an append-only role transition ledger to prevent privilege escalation concealment.

#### 2.2 MultiSigApproval (`contracts/access/MultiSigApproval.sol`)
* **Four-Eyes Principle (Dual-Control):** Mandates that no single insider can authorize critical operations (e.g. unpausing the system, overriding repeated warnings, modifying AML limits).
* Requires $M$-of-$N$ cryptographic signatures ($M \ge 2$) before execution.

#### 2.3 ForensicTrail (`contracts/forensics/ForensicTrail.sol`)
* **Court-Admissible Chain of Custody:** Implements a recursive parent-hash linkage pattern akin to a lightweight block header:
  $$\text{EntryHash}_n = \text{keccak256}\Big(n, \text{Timestamp}, \text{IncidentType}, \text{Operator}, \text{Actor}, \text{EvidenceHash}, \text{EntryHash}_{n-1}\Big)$$
* **Chain Integrity Verification:** The `verifyChainIntegrity()` view function algorithmically verifies the integrity of every entry from index 1 to $N$. If any historical record is modified off-chain, the mathematical chain breaks immediately at the exact index.

#### 2.4 InsiderActivityLog (`contracts/forensics/InsiderActivityLog.sol`)
* **Behavioral Operator Metrics:** Automatically tallies insider actions:
  * `warningOverrides`: Number of AML warnings bypassed by this operator.
  * `afterHoursCount`: Number of actions executed outside standard business hours (08:00 - 17:00).
  * `beneficiaryApprovals`: Tracks approval concentration per beneficiary.
* **Autonomous Flagging:** If `warningOverrides > 5`, `afterHoursCount > 3`, or `topBeneficiaryApprovals > 10`, the operator account is permanently flagged on-chain, and an incident is submitted to `ForensicTrail`.

#### 2.5 AuditEngine (`contracts/AuditEngine.sol`)
* **Unified Enforcement Engine:** Integrates all forensic and access components.
* **Separation of Duties (SoD):** Cryptographically prohibits transacting parties (`sender` or `receiver`) from clearing or flagging their own transactions.
* **Timelocked Policy Changes:** AML threshold updates must undergo a 2-day timelock delay unless approved via MultiSig bypass.
* **Dual-Control Circuit Breaker:** Any auditor can pause the engine upon detecting catastrophic fraud (`emergencyPause`), but resuming (`emergencyUnpause`) requires multi-signature validation.

---

### 3. Tier 2: Off-Chain AI Reasoning Engine

Located in `ai-engine/`, built on Python 3.11 and FastAPI, providing sub-millisecond local inference with optional Gemini 1.5 Flash cloud enhancement.

#### 3.1 Pre-Execution Fraud Detector (`app/models/fraud_detector.py`)
* Evaluates transactions before or alongside blockchain submission across 5 heuristic and ML dimensions:
  1. **Threshold Exceedance:** $A \ge \text{Limit}$ ($+40.0$ points).
  2. **Structuring / Smurfing Detection:** $A \in [0.85 \times \text{Limit}, \text{Limit})$ ($+25.0$ to $+40.0$ points).
  3. **KYC Verification Factor:** Unverified sender transacting $> 1.0$ ETH ($+30.0$ points).
  4. **Daily Velocity Exceedance:** Prior Volume $+ A > \text{DailyLimit}$ ($+25.0$ points).
  5. **Off-Hours Factor:** $t \notin [08:00, 17:00)$ ($+15.0$ points).

#### 3.2 Insider Threat Behavioral Profiler (`app/models/insider_analyzer.py`)
* Analyzes aggregated operator actions using behavioral heuristic weights:
  $$\text{ThreatScore} = 5.0 + 35.0 \cdot \mathbb{I}_{[\text{overrides} > 5]} + 30.0 \cdot \mathbb{I}_{[\text{collusion} > 10]} + 20.0 \cdot \mathbb{I}_{[\text{offhours} > 3]} + 15.0 \cdot \mathbb{I}_{[\text{decision\_time} < 10\text{s}]}$$
* Outputs actionable classifications: `LOW`, `ELEVATED`, `HIGH`, `CRITICAL` alongside judicial recommendation codes (`MANDATE_MULTISIG_FREEZE`, `IMMEDIATE_REVOCATION`).

#### 3.3 Smart Contract Backdoor Auditor (`app/services/gemini_service.py`)
* Performs Abstract Syntax Tree (AST) parsing and regex analysis on Solidity source code.
* Detects insider-planted backdoors:
  * Phishing vectors via `tx.origin` (CWE-287).
  * Arbitrary contract destruction via `selfdestruct` (CWE-284).
  * State update post-external call (Reentrancy, CWE-829).
  * Unbounded token minting or zero-address privilege grants.

---

### 4. Tier 3: Presentation & Judicial Telemetry

Built in `frontend/` using React 18, Vite 5, Tailwind CSS, and Recharts.

* **7 Forensic Modules:**
  1. `Dashboard.jsx`: Executive telemetry, AML status distribution, volume trends, live audited transaction feed.
  2. `InsiderMonitor.jsx`: Monitored operator matrix, collusion indicators, real-time threat simulator.
  3. `ForensicExplorer.jsx`: Visual chain of custody explorer, SHA-256 hash timeline, interactive attack/tamper simulation.
  4. `RiskScorePanel.jsx`: Transaction simulator with instant risk scoring, structuring detection alerts, and blockchain broadcast.
  5. `ContractScanner.jsx`: Solidity backdoor auditor with pre-loaded samples and CWE reports.
  6. `ForensicReport.jsx`: Bilingual English / Arabic judicial dossier with print/PDF layout, regulatory stamps, and root hash authentication.
  7. `RoleManagement.jsx`: Four-Eyes MultiSig proposals queue, RBAC directory, Separation of Duties enforcement status.
