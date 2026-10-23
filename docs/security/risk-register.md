# Institutional Risk Register (T24)

> **Document Identifier:** `RISK-REG-V2`  
> **Evaluation Reference:** Specification §4–§11, Requirements R01–R18, Threat Model Alignment  
> **Gate Pre-requisite:** Acceptance Gate G4 (Commercial & Institutional Readiness requires 0 OPEN Critical/High risks)

> **[2026-10-23] superseded_pending_revalidation** — The `VERIFIED_FIXED` statuses below are **historical** results from the pre-remediation review cycle and are not carried forward as evidence of closure. The verified remediation register [../verification/remediation/findings.csv](../verification/remediation/findings.csv) (baseline: [../verification/remediation/baseline-2026-10-23.md](../verification/remediation/baseline-2026-10-23.md)) supersedes this register for tracking: findings F01–F14 are all **OPEN** pending red/green test evidence from a final build. The `F-01..F-07` identifiers below use a different, older numbering scheme and do **not** correspond to `F01–F14`. Historical rows are preserved unchanged.

---

## 1. Risk Register Matrix

| Finding ID | Requirement ID | Severity | Threat / Scenario | Owner | Status | Regression Test | Verification Result | Accepted By |
|---|---|---|---|---|:---:|---|---|---|
| **F-01** | **R09, R14** | **CRITICAL** | Cross-tenant evidence or report read attempt by authenticated operator from another bank | Backend Lead | **VERIFIED_FIXED** | `test_cross_tenant_access_rejection` | Tenant filtering & RLS returns 404 / empty items; zero data leakage | SecOps Lead |
| **F-02** | **R01, R10** | **HIGH** | Separation of duties breach: REGULATOR role attempting state mutations or report creation | Web3/Auth Lead | **VERIFIED_FIXED** | `test_regulator_write_prevention` | RoleChecker strictly rejects with HTTP 403 Forbidden | Compliance Lead |
| **F-03** | **R09, R14** | **HIGH** | Financial PII leakage (Iraqi IBAN, bank account, phone number, EVM wallet) to external cloud AI | AI Lead | **VERIFIED_FIXED** | `test_pii_redaction_defense` | Local regex masking strips identifiers before external egress | Privacy Officer |
| **F-04** | **R16** | **MEDIUM** | Denial of service via oversized Solidity smart contract payload submitted to scanner | Backend Lead | **VERIFIED_FIXED** | `test_contract_scanner_input_bounds` | Size strictly capped at $\le 200\text{ KB}$; rejects with descriptive error | DevOps Lead |
| **F-05** | **R02, R15** | **HIGH** | False security verification claim when regex scanner finds no patterns | Web3 Lead | **VERIFIED_FIXED** | `test_contract_scanner_honest_limitations` | Returns `NO_DETECTED_PATTERNS` + explicit disclaimers; never claims "100% SECURE" | Lead Auditor |
| **F-06** | **R11, R18** | **CRITICAL** | Bit-rot or corrupted database snapshot accepted during disaster recovery restoration | DevOps Lead | **VERIFIED_FIXED** | `test_bit_rot_and_tamper_detection` | SHA-256 manifest validation halts with `BackupCorruptionError` | SecOps Lead |
| **F-07** | **R03, R05** | **HIGH** | Replay or stale signature reuse in MultiSig governance key rotation | Web3 Lead | **VERIFIED_FIXED** | `test_governance_continuity_with_missing_participant` | Incremented authorization generation invalidates stale signatures | Lead Architect |

---

## 2. Gate G4 Risk Acceptance Certification

- **Open Critical Vulnerabilities:** **0**
- **Open High Vulnerabilities:** **0**
- **Accepted Residual Risks:** **0** (All identified risks have automated regression tests in `ai-engine/tests/integration/test_security_findings_regression.py` and `test_recovery_and_backup.py`).

**Formal Sign-off:** Task T24 risk register is fully verified and closed.
