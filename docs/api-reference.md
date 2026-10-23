# API Reference Manual

## Cyber-Auditing & AI Reasoning Engine API (`v2.0`)

Base URL: `http://localhost:8000` (or `http://ai-engine:8000` in Docker)  
OpenAPI Documentation: `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

---

### 1. System Health

#### `GET /health`
Returns the operational status of the AI Engine and whether ML models are loaded in memory.

* **Response (200 OK):**
```json
{
  "status": "online",
  "service": "Cyber-Auditing AI Engine",
  "version": "2.0.0",
  "model_loaded": true,
  "gemini_enabled": false
}
```

---

### 2. Transaction AML & Fraud Risk Scoring

#### `POST /api/v1/risk/score`
Performs real-time anomaly evaluation on an individual transaction prior to or alongside on-chain broadcast.

* **Request Body:**
```json
{
  "amount": 9.85,
  "daily_volume": 32.0,
  "tx_count_1h": 3,
  "hour_of_day": 23,
  "is_kyc_verified": false,
  "sender": "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
  "receiver": "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
}
```

* **Response (200 OK):**
```json
{
  "anomaly_score": 82.5,
  "risk_tier": "HIGH",
  "is_structuring_suspected": true,
  "flag_reasons": [
    "Structuring suspicion: Amount approaches regulatory limit (10 ETH)",
    "Unverified KYC for high-value transfer",
    "Off-hours transaction activity"
  ],
  "model_type": "Hybrid Isolation Forest & Rule Heuristics"
}
```

---

#### `POST /api/v1/risk/batch`
Evaluates a collection of financial transactions simultaneously for high-throughput batch reconciliation.

* **Request Body:**
```json
{
  "transactions": [
    {
      "tx_id": 1,
      "amount": 2.5,
      "daily_volume": 2.5,
      "tx_count_1h": 1,
      "hour_of_day": 10,
      "is_kyc_verified": true,
      "sender": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      "receiver": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    }
  ]
}
```

* **Response (200 OK):**
```json
{
  "total_analyzed": 1,
  "high_risk_count": 0,
  "results": [
    {
      "tx_id": 1,
      "risk_score": 5.0,
      "risk_tier": "LOW",
      "is_flagged": false,
      "reasons": ["Normal transaction activity"]
    }
  ]
}
```

---

### 3. Insider Threat Telemetry

#### `POST /api/v1/insider/analyze`
Profiles an internal bank operator or auditor based on accumulated actions, overrides, and decision velocities.

* **Request Body:**
```json
{
  "operator_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "total_actions": 48,
  "warning_overrides": 7,
  "after_hours_count": 4,
  "unique_beneficiaries_approved": 3,
  "top_beneficiary_approval_count": 12,
  "avg_decision_time_seconds": 8.5,
  "reversal_rate": 0.12
}
```

* **Response (200 OK):**
```json
{
  "operator_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "threat_score": 88.5,
  "threat_level": "CRITICAL",
  "is_collusion_suspected": true,
  "behavioral_flags": [
    "Excessive warning overrides (7 > limit 5)",
    "Collusion pattern: 12 approvals to a single beneficiary",
    "Repeated after-hours operations (4 times)",
    "Automated or rubber-stamping approval velocity (< 10s decision time)"
  ],
  "recommended_action": "MANDATE_MULTISIG_FREEZE"
}
```

---

#### `GET /api/v1/insider/thresholds`
Returns the current system limits for insider threat indicators.

* **Response (200 OK):**
```json
{
  "max_warning_overrides": 5,
  "max_after_hours_actions": 3,
  "max_beneficiary_repeat": 10,
  "min_decision_time_seconds": 10.0
}
```

---

### 4. Smart Contract Backdoor Auditor

#### `POST /api/v1/contract/scan`
Audits Solidity smart contracts for hidden backdoors, unauthorized privileges, or common CWE vulnerabilities.

* **Request Body:**
```json
{
  "contract_name": "BackdooredVault",
  "source_code": "contract BackdooredVault { address owner; function destroy() public { require(tx.origin == owner); selfdestruct(payable(owner)); } }",
  "solidity_version": "0.8.20"
}
```

* **Response (200 OK):**
```json
{
  "contract_name": "BackdooredVault",
  "security_grade": "F",
  "security_score": 25,
  "total_findings": 2,
  "scan_timestamp": "2026-10-22T19:00:00Z",
  "scanner_engine": "Hybrid AST Pattern & Gemini 1.5 Analysis",
  "findings": [
    {
      "severity": "CRITICAL",
      "vulnerability_type": "Authentication via tx.origin (Phishing Risk)",
      "line_number": 1,
      "snippet": "require(tx.origin == owner)",
      "description": "Using tx.origin for authentication allows phishing attacks.",
      "remediation": "Replace tx.origin with msg.sender and implement RoleManager RBAC.",
      "cwe_id": "CWE-287"
    },
    {
      "severity": "CRITICAL",
      "vulnerability_type": "Self-Destruct Backdoor",
      "line_number": 1,
      "snippet": "selfdestruct(payable(owner))",
      "description": "Contract can be permanently erased, locking user funds.",
      "remediation": "Remove selfdestruct opcode completely.",
      "cwe_id": "CWE-284"
    }
  ]
}
```

---

### 5. Judicial Forensic Reports & Chain Verification

#### `POST /api/v1/forensic/report`
Synthesizes a bilingual forensic dossier suitable for presentation to regulatory bodies or courts of law.

* **Request Body:**
```json
{
  "case_id": "CBI-AML-2026-8841",
  "auditor_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "suspect_addresses": ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"],
  "incident_types": ["INSIDER_EXCESSIVE_OVERRIDE_ALERT", "STRUCTURING"],
  "timeframe_start": "2026-10-15T00:00:00Z",
  "timeframe_end": "2026-10-22T23:59:59Z",
  "evidence_hashes": ["0x4f128e6c73b009e512497678d910a3014a8217bbcc4076356778f249c55d0458"],
  "language": "ar"
}
```

* **Response (200 OK):**
```json
{
  "case_id": "CBI-AML-2026-8841",
  "timestamp": "2026-10-22T19:00:00Z",
  "executive_summary": "تم إعداد هذا التقرير الجنائي الرقمي للتحقيق في أنشطة مالية مشبوهة...",
  "incident_count": 2,
  "risk_classification": "CRITICAL",
  "chain_of_custody_verified": true,
  "findings_breakdown": [
    {
      "category": "Behavioral Anomaly",
      "detail": "تجاوز حدود التحذير بأكثر من 5 مرات متتالية من قبل المشغل",
      "severity": "HIGH"
    }
  ],
  "legal_disclaimer": "الأدلة الرقمية الواردة بهذا التقرير موثقة عبر بصمة تشفيرية متسلسلة غير قابلة للتلاعب."
}
```

---

#### `POST /api/v1/forensic/verify-chain`
Recomputes and validates the parent-hash cryptographic linkage across an entire array of forensic trail entries.

* **Request Body:**
```json
{
  "trail_entries": [
    {
      "index": 0,
      "timestamp": 1776870000,
      "incident_type": "GENESIS_CHAIN_INITIALIZED",
      "operator": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      "actor": "0x0000000000000000000000000000000000000000",
      "evidence_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "previous_entry_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "entry_hash": "0x8f2d5e135b91a783427019cfef940df63a2333be1e433cb8e0724a7374b7c6c4"
    }
  ]
}
```

* **Response (200 OK):**
```json
{
  "is_valid": true,
  "entries_checked": 1,
  "broken_at_index": null,
  "message": "Chain of custody verified successfully"
}
```

---

## 6. Authoritative V2 Institutional APIs (`/api/v2`)

V2 endpoints strictly enforce `extra="forbid"`, minor-unit currency precision (ETH scale=18 wei, IQD scale=3 fils), and 3-state independent verification.

### `GET /api/v2/health/live`
Process liveness probe.
* **Response (200 OK):**
```json
{
  "status": "live",
  "service": "ai-engine",
  "timestamp": "2026-10-23T08:00:00Z"
}
```

### `GET /api/v2/health/ready`
Subsystem readiness probe verifying local ML model and active policy services.
* **Response (200 OK):**
```json
{
  "status": "ready",
  "live": true,
  "ready": true,
  "checks": {
    "ml_engine": true,
    "policy_service": true
  },
  "details": {
    "ml_type": "Hybrid Isolation Forest + Rule Ensemble",
    "active_eth_policy": "IRAQ_CBI"
  }
}
```

### `GET /api/v2/policies/active?asset={ETH|IQD}&institutionId={id}`
Returns the active AML/KYC thresholds in exact integer minor units.
* **Response (200 OK):**
```json
{
  "policy_id": "POLICY-ETH-CBI-V1",
  "version": "IRAQ_CBI",
  "asset": "ETH",
  "currency": "ETH",
  "scale": 18,
  "thresholds": {
    "large_transaction": "10000000000000000000000",
    "daily_volume_limit": "50000000000000000000000",
    "max_daily_transactions": 20,
    "max_single_transaction": "100000000000000000000000",
    "kyc_required_threshold": "5000000000000000000000"
  },
  "effective_at": "2026-01-01T00:00:00Z",
  "source": "on_chain_audit_engine"
}
```

### `POST /api/v2/evidence/verify`
Independently verifies Evidence V2 entries against canonical `keccak256(abi.encode)` rules and on-chain consensus state.
* **Request Body:**
```json
{
  "incidentId": 1,
  "schemaVersion": 2,
  "chainId": 1337,
  "contractAddress": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "entries": [...]
}
```
* **Response (200 OK):**
```json
{
  "status": "verified",
  "provenance_status": "verified_institutional_writer",
  "checked_entries": [...],
  "reasons": [],
  "block_number": 12345,
  "block_hash": "0xabcd1234",
  "anchor": {
    "chain_id": 1337,
    "contract_address": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    "count": 2,
    "head": "0x5519bcb524512d3d9506b16560815ce61f7a9a85192e6114def45ba1346d1830",
    "block_number": 12345,
    "block_hash": "0xabcd1234"
  },
  "source": "registry_trusted_contract"
}
```
Possible statuses: `verified`, `invalid`, `unavailable`.

