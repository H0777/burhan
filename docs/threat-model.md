# Threat Model & Risk Analysis

## Integrating Digital Forensics and Financial Accounting: A Cyber-Auditing System for Mitigating Insider Threat Fraud

---

### 1. Introduction & Scope

Traditional financial auditing systems operate under the perimeter security assumption: threats originate externally, while internal credentials denote trustworthiness. However, modern forensic accounting reveals that **the most damaging financial frauds are executed by authorized insiders** who exploit institutional trust, procedural gaps, and system privileges.

This document formalizes the threat model for the Cyber-Auditing System using the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) and **DREAD** risk scoring.

---

### 2. Threat Actor Taxonomy

| Actor ID | Profile | Motivation | Capabilities | Access Level |
|---|---|---|---|---|
| **TA-01: Rogue Auditor** | Authorized compliance officer or internal auditor | Financial bribery, extortion, embezzlement | Can clear flagged transactions, override AML warnings | `AUDITOR_ROLE` |
| **TA-02: Colluding Operator** | Bank branch teller or payment gateway operator | Organized crime affiliation, personal kickbacks | Routes transfers to specific accounts, batches smurfing | `OPERATOR_ROLE` |
| **TA-03: External Launderer** | Organized syndicate / financial criminal | Evading FATF / CBI scrutiny, laundering narcotics/graft funds | Exploits sub-threshold structuring, split transactions | Public / Customer |
| **TA-04: Malicious Developer** | Compromised contractor or rogue software engineer | Backdoor insertion, systemic fund drainage | Modifies smart contracts, alters access logic | Developer / CI Pipeline |
| **TA-05: Credential Hijacker** | Advanced Persistent Threat (APT) / Phisher | Stolen private keys or session tokens | Executes unauthorized high-volume off-hours actions | Compromised Key |

---

### 3. STRIDE Threat Matrix & Mitigations

```
+--------------------+---------------------------------------+------------------------------------------+
| STRIDE Category    | Specific Threat Scenario               | Cryptographic & AI Mitigation            |
+--------------------+---------------------------------------+------------------------------------------+
| Spoofing           | Attacker impersonates auditor key or  | - Multi-Sig 4-Eyes verification          |
|                    | uses tx.origin phishing hook          | - Contract Scanner AST checks for tx.origin |
+--------------------+---------------------------------------+------------------------------------------+
| Tampering          | Rogue auditor alters historical logs  | - SHA-256 recursive parent-hash chain of |
|                    | to conceal fraudulent clearances      |   custody in ForensicTrail.sol           |
+--------------------+---------------------------------------+------------------------------------------+
| Repudiation        | Operator denies executing illicit     | - Immutable EVM event emission           |
|                    | override or unauthorized clearance    | - Non-repudiable cryptographic signature |
+--------------------+---------------------------------------+------------------------------------------+
| Info Disclosure    | Leaking sensitive transaction trails  | - On-chain data is hashed (keccak256)    |
|                    | or customer PII                       | - Off-chain evidence storage with hashes |
+--------------------+---------------------------------------+------------------------------------------+
| Denial of Service  | Rogue admin locks system or spams     | - Emergency pause requires MultiSig to   |
|                    | bogus transactions to exhaust gas     |   unpause; circuit breaker bounds        |
+--------------------+---------------------------------------+------------------------------------------+
| Elevation of Priv. | Operator self-promotes to Super Admin | - RoleManager strict AccessControl       |
|                    | or clears own transactions            | - Separation of Duties (SoD) constraints |
+--------------------+---------------------------------------+------------------------------------------+
```

---

### 4. In-Depth Attack Vector Analysis

#### Attack Vector 1: Warning Override Flooding (Rubber-Stamping Fraud)
* **Description:** An auditor colludes with a money laundering network. When transactions exceed reporting thresholds (e.g. $\ge 10.0$ ETH), the system emits a compliance warning. The rogue auditor repeatedly overrides these warnings citing bogus justifications (e.g. "verified customer invoice").
* **Mathematical Detection:**
  $$\text{Counter}(\text{operator}) = \sum_{t=1}^{T} \mathbb{I}_{[\text{action}(t) = \text{OVERRIDE}]}$$
  $$\text{Trigger Condition: } \text{Counter}(\text{operator}) > 5$$
* **System Enforcement:**
  1. `InsiderActivityLog.sol` autonomously increments `warningOverrides`.
  2. Upon reaching 6 overrides, `isOperatorFlagged` is set to `true`.
  3. `AuditEngine.sol` blocks single-party override execution: `require(!insiderLog.isOperatorFlagged(msg.sender) || multiSigApproved, "MultiSig required")`.
  4. An unforgeable entry is logged into `ForensicTrail.sol`.

---

#### Attack Vector 2: Structuring & Smurfing (Sub-Threshold Evasion)
* **Description:** Transactors deliberately split large illicit sums into sub-threshold tranches (e.g., transfers of 9.85 ETH, 9.90 ETH, 9.75 ETH) to evade the mandatory 10.0 ETH AML reporting trigger.
* **Mathematical Detection:**
  $$\text{Ratio} = \frac{\text{Amount}}{\text{Threshold}}$$
  $$\text{StructuringScore} = \begin{cases} 
  0.0, & \text{Ratio} < 0.85 \\
  25.0 + 15.0 \times \left(\frac{\text{Ratio} - 0.85}{0.15}\right), & 0.85 \le \text{Ratio} < 1.00 \\
  40.0, & \text{Ratio} \ge 1.00 
  \end{cases}$$
* **System Enforcement:**
  * When $0.85 \le \text{Ratio} < 1.0$, the AI Engine automatically flags `is_structuring_suspected = true`.
  * The transaction risk tier elevates to `HIGH` or `CRITICAL`, triggering automatic compliance officer review and mandatory KYC reverification.

---

#### Attack Vector 3: Separation of Duties (SoD) Bypass
* **Description:** An operator submits a fraudulent transfer from an account they control to a confederate, and then switches roles or uses their auditor privileges to clear the transaction or approve their own KYC status.
* **Cryptographic Constraint:**
  $$\forall \text{tx} = (\text{sender}, \text{receiver}, \text{id}): \quad \text{caller} \neq \text{sender} \;\land\; \text{caller} \neq \text{receiver}$$
* **Code Implementation in `AuditEngine.sol`:**
  ```solidity
  function clearTransaction(uint256 txId) external onlyAuditor {
      Transaction storage transaction = transactions[txId];
      require(msg.sender != transaction.sender, "SoD: Cannot clear own transaction");
      require(msg.sender != transaction.receiver, "SoD: Cannot clear own transaction");
      // ...
  }
  ```

---

#### Attack Vector 4: Smart Contract Backdoor Injection
* **Description:** A rogue developer injects code that appears benign but contains hidden privileges:
  1. `tx.origin == owner`: Allows phishing attacks where an owner interacts with an external DApp, transferring authority.
  2. `selfdestruct(payable(owner))`: Threatens to vaporize contract state and lock escrowed balances.
  3. Checks-Effects-Interactions violation: State updated after external `.call{value: ...}("")`, enabling reentrancy drainage.
* **System Enforcement:**
  * The `ContractScanner` AST parser audits Solidity files, flagging specific CWE identifiers (CWE-287, CWE-284, CWE-829).
  * Contract scoring automatically downgrades contracts to `Grade F` upon detecting `selfdestruct` or `tx.origin`.

---

### 5. DREAD Risk Scoring Summary

| Threat Description | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | DREAD Score (/10) | Risk Rating |
|---|---|---|---|---|---|---|---|
| Warning Override Flooding | 9 | 8 | 8 | 9 | 7 | **8.2** | **CRITICAL** |
| Sub-Threshold Structuring | 8 | 9 | 8 | 8 | 8 | **8.2** | **CRITICAL** |
| Beneficiary Collusion | 9 | 7 | 7 | 8 | 6 | **7.4** | **HIGH** |
| Off-Hours Batch Bursts | 8 | 7 | 8 | 7 | 7 | **7.4** | **HIGH** |
| Historical Log Tampering | 10 | 2 | 3 | 9 | 9 | **6.6** | **HIGH** (Prevented) |
| Smart Contract Backdoors | 10 | 4 | 5 | 10 | 5 | **6.8** | **HIGH** (Prevented) |

---

### 6. Threat Boundary & Implementation Status Taxonomy (A01)

| Threat Scenario | Status | Verification Evidence / Boundary Definition |
|---|:---:|---|
| **Rogue Admin Single-Party Clearance** | **IMPLEMENTED** | MultiSig 4-Eyes Principle with Separation of Duties (`MultiSigApproval.sol`, `case_service.py`). Submitter self-approval reverts. |
| **Historical Forensic Log Mutation** | **IMPLEMENTED** | Parent-hash recursive chaining in `ForensicTrail.sol` and SHA-256 chunked storage in `evidence_store.py`. Tampering reverts with `compromised`. |
| **EVM Proposal Replay Attacks** | **IMPLEMENTED** | Atomic execution state transition to `EXECUTED` blocks second invocation; authorization generation invalidates stale signatures. |
| **Cross-Tenant Data Exposure** | **IMPLEMENTED** | PostgreSQL Row-Level Security (RLS) policies and composite `(institution_id, ...)` foreign keys block cross-tenant read/write. |
| **Client-Side Risk Score Manipulation** | **IMPLEMENTED** | Authoritative server-side feature derivation (`feature_service.py`); client risk inputs rejected in production endpoints. |
| **Transaction Re-Import Race Conditions** | **IMPLEMENTED** | Idempotent conflict detection on `(institution_id, source, external_id)` in `csv_import.py`; conflicting payloads reject with 409. |
| **Physical Node Compromise / 51% Attack** | **OUT-OF-SCOPE** | Framework assumes EVM consortium consensus security (PoA / IBFT 2.0 with authenticated validator nodes). |
| **Off-Chain Cash (Hawala) Transactions** | **UNSUPPORTED** | Purely physical, unrecorded paper currency transactions outside the banking core ledger cannot be mathematically verified. |
| **Zero-Day OS Kernel Exploits** | **UNSUPPORTED** | Defense in depth relies on container isolation, least-privilege Docker daemons, and PostgreSQL OS separation. |

