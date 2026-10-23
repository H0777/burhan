# G2 Institutional Platform Gate Acceptance Report — بوابة الاعتماد المؤسسي

**Project:** Iraq AML & Cyber-Forensic Auditing Framework (V2)  
**Verification Date:** 2026-10-23  
**Gate Status:** **PASSED (100% Green, Multi-Tenant Isolation Certified)**  
**Gate Identifier:** `G2: INSTITUTIONAL PLATFORM & MULTI-TENANT ISOLATION`  
**Execution Orchestrator:** `npm run verify:all`  

---

## 1. Executive Summary

The **G2 Institutional Platform Gate** officially certifies **Phase 2 (Tasks T13–T17)** of the three-track roadmap. It establishes multi-tenant isolation, cryptographic institutional identity, WORM evidence vaulting with reorg-resilient blockchain anchoring, Four-Eyes institutional case lifecycle governance, and high-throughput streaming banking transaction ingestion for Central Bank of Iraq (CBI) compliance.

All institutional invariants have been verified against automated tests across smart contracts, database RLS policies, backend API services, and React frontends.

---

## 2. Gate Verification Results Matrix

| Gate Job | Automated Command | Status | Evidence & Metrics |
|---|---|:---:|---|
| **EVM Contracts** | `npm run verify:contracts` | **PASS** | 143 passing tests; zero ABI drift against generated contracts |
| **API & Shared Parity** | `npm run verify:api` | **PASS** | 7 Node currency/hash tests; OpenAPI V2 zero drift; 98 Pytest tests passing |
| **Frontend & Components** | `npm run verify:frontend` | **PASS** | ESLint (0 errors); 23 Vitest tests passing; Vite production bundle built |
| **E2E Integration Flow** | `npm run verify:integration` | **PASS** | 8 Playwright tests passing end-to-end on live node, DB, and FastAPI |
| **Full Sequential Suite** | `npm run verify:all` | **PASS** | Full suite passed with exit code 0 |

---

## 3. Institutional Invariants & Core Deliverables (Tasks T13–T17)

### T13: Institutional Identity, OIDC & EVM Wallet Binding
- **Standard:** EIP-4361 (Sign-In with Ethereum) challenge-response protocol.
- **Invariants:**
  - SIWE challenges are single-use, institution-scoped, and bound to user subject (`sub`).
  - Active wallet binding increments `authorization_generation` to instantly invalidate stale signatures upon role modification or wallet rotation.
  - Multi-tenant tenant context middleware (`tenant_context.py`) strictly propagates institutional boundaries.
- **Verification:** `ai-engine/tests/test_identity.py` (all tests passing).

### T14: Multi-Tenant Schema, Composite FKs & RLS Policies
- **Standard:** PostgreSQL Row-Level Security (RLS) with composite primary/foreign keys `(institution_id, ...)`.
- **Invariants:**
  - Every tenant-scoped table (`cases`, `case_events`, `evidence_objects`, `evidence_anchors`, `transactions`, `import_batches`) includes `institution_id`.
  - Transaction-scoped tenant setting `SET LOCAL app.current_institution_id = :inst_id`.
  - RLS policies block cross-tenant read/write even under shared connection pools.
  - WORM immutability prevents UPDATE/DELETE on finalized evidence and events.
- **Verification:** `ai-engine/tests/integration/test_tenant_storage.py`.

### T15: WORM Evidence Vault & Reorg-Resilient Anchoring
- **Standard:** SHA-256 chunked local/S3-compatible object storage with transactional outbox anchoring.
- **Invariants:**
  - Content-addressed chunking with strict 25 MB payload limit.
  - Outbox worker guarantees at-least-once delivery to EVM `ForensicTrail.submitEvidence`.
  - Chain reorg detection monitors block hashes and confirmations (minimum 12 confirmations), recovering and re-submitting anchors if necessary.
- **Verification:** `ai-engine/tests/integration/test_evidence_store.py`, `test_evidence_delivery.py`, `test_indexer_recovery.py`.

### T16: Institutional Case Lifecycle & Four-Eyes Governance
- **Standard:** 7-stage case workflow: `DRAFT -> UNDER_REVIEW -> EVIDENCE_SEALED -> APPROVED -> CLOSED` (with `REJECTED`, `REOPENED`).
- **Invariants:**
  - **Four-Eyes Principle / SoD:** Submitter cannot approve their own case (`SelfApprovalForbiddenError`).
  - **Optimistic Concurrency:** Case mutations require `expected_version` to prevent concurrent overwrite races (`StaleVersionError`).
  - **Regulator Read-Only:** `REGULATOR` role can view all cases and audit logs but cannot transition state or seal evidence (`RoleForbiddenError`).
  - **Audit Logging:** Every case transition automatically records an immutable `case_events` record with participant identity and timestamp.
  - **Case Workspace UI:** Modern React 18 component (`CaseWorkspace.jsx`) with live stage indicator, state-aware actions, and Arabic localization.
- **Verification:** `ai-engine/tests/integration/test_case_workflow.py`, `frontend/src/components/CaseWorkspace.test.jsx`.

### T17: Reliable Banking Transaction Ingestion & Read Model
- **Standard:** Streaming CSV ingestion for Central Bank of Iraq (CBI) banking transactions with IQD minor-unit scaling (scale 3, fils).
- **Invariants:**
  - Mandatory ISO-8601 UTC timezone parsing (`Z` or `+HH:MM`); missing timezone throws `MISSING_TIMEZONE`.
  - Amount minor units must be non-negative integers; decimal dots rejected.
  - Conflict detection on `(institution_id, source, external_id)`: idempotent skip on identical data; rejection with `CONFLICT_DIFFERENT_DATA` on discrepancy without silent overwrite.
  - Streaming chunked processing capped at 50,000 rows (rejects oversized batches with HTTP 413).
  - Single-query indexed pagination (`GET /api/v2/transactions`) eliminates legacy N-RPC loop.
  - Dashboard banner legal notice ("المصدر المصرفي يثبت ورود سجل فقط، ولا يثبت تسوية نقدية أو دقة إدخال العميل").
- **Verification:** `ai-engine/tests/integration/test_transaction_import.py`, `tests/e2e/trust-flow.spec.js` (Test 1.5).

---

## 4. Acceptance Certification

I hereby certify that **Phase 2: Institutional Platform & Tenant Isolation (Tasks T13–T17)** meets all requirements defined in Specification §4, §5, §7 and passes the **G2 Gate Acceptance Criteria**.

- **Gate Status:** **PASSED**
- **Certified By:** Automated CI Integration Pipeline & Antigravity Agent
- **Target Milestone for Next Phase:** **Phase 3: Academic Track A & Empirical Evaluation (Tasks T18–T22)** targeting Acceptance Gate **G3**.
