# SDD ledger — plan: docs/superpowers/plans/2026-10-22-phase-2-institutional-platform.md

## Pre-flight Interface & Conflict Scan
- T13 -> T14: Identity context (institution_id, sub, participant_id, permissions) from T13 consumed by tenant storage, RLS session context, and evidence broker in T14.
- T13 -> T16: Authenticated investigator identity with SoD roles from T13 consumed by case assignment and transition rules in T16.
- T14 -> T15: PostgreSQL schema, checkpoint table, and chain_events table from T14 consumed by blockchain indexer in T15.
- T14 -> T16: Case repository and immutable case_events tables from T14 consumed by case lifecycle service in T16.
- T15 -> T16/T17: Indexed confirmed on-chain events from T15 consumed by case evidence linkage in T16 and unified transaction queries in T17.
- T16/T17 -> G2: Case workflow and banking CSV connector in T16/T17 verified under two distinct synthetic institutions in G2 gate.
Pre-flight: interfaces aligned with Design Spec §4–8, R08–R11, R14, R18.

Task 13: complete
- OIDC Token Verification & Tenant Context (RS256 signature verification, strict tenant isolation via TenantContext)
- SIWE (EIP-4361) wallet challenge and EIP-191 signature recovery with single-use nonce and 5-min TTL
- Wallet rotation authorization_generation increment (1 -> 2)
- FastAPI V2 endpoints: GET /api/v2/identity/me, POST /api/v2/wallet/challenge, POST /api/v2/wallet/verify
- Frontend AuthProvider (useAuth hook, session storage, challenge signing via Web3 provider, state binding)
- Contract helper getOnChainParticipant in frontend/src/utils/contract.js
- Canonical OpenAPI schema exported with 0 drift (shared/openapi-v2.json)
- Verified with 18 Python tests, 5 Vitest tests, and full verify:all gate suite passing with code 0
Task 14: complete
- Multi-tenant relational schema (SQLAlchemy 2.0 with composite foreign keys on institution_id across 13 scoped tables: institutions, memberships, wallet_bindings, cases, case_events, transactions, policy_versions, assessments, evidence_objects, evidence_anchors, outbox, idempotency_keys, chain_events, checkpoints)
- Transaction-scoped tenant isolation context manager setting `SET LOCAL app.current_institution_id` with dialect adaptivity and PostgreSQL Row-Level Security DDL generation
- Isolated WORM Evidence Store with chunked streaming hash (64KB chunks), 25MB threshold abort without RAM exhaustion, path traversal sanitization (../, null bytes, absolute paths), immutable versioning, and read-time SHA-256 tamper verification
- Multi-tenant Repository Layer: case_repository, evidence_repository, outbox_repository, institution_repository
- EvidenceBroker Service issuing canonical service manifests and atomically persisting EvidenceObject, EvidenceAnchor (PENDING_ANCHOR), and Outbox item within a tenant transaction
- EvidenceAnchorWorker with crash recovery and idempotent replay using contract's getEvidenceByRequestId
- FastAPI V2 evidence endpoints: POST /api/v2/cases/{id}/evidence (multipart upload up to 25MB, Idempotency-Key), GET /api/v2/evidence/{id}, GET /api/v2/evidence/{id}/download
- Docker Compose configuration updated with PostgreSQL 16 service, volume, and healthchecks
- Verified with test_evidence_store.py (5/5), test_tenant_storage.py (6/6), test_evidence_delivery.py (4/4), and full verify:all gate suite passing with code 0
Task 15: complete
- Modernized BlockchainListener with non-blocking httpx JSON-RPC client, connection pooling, and bounded exponential backoff for provider rate limits (429)
- ChainRegistry service enforcing manifest policy, confirmation depths (2 blocks for sandbox 1337/31337, 12 for consortium), and bytecode cryptographic hash verification (detects CodeHashMismatchError)
- BlockchainIndexerWorker with bounded block window batching, atomic checkpoint updates, log ingestion, and real-time lag calculation
- Reorg Recovery: automated detection of checkpoint block hash divergence against on-chain consensus, retroactive fork point backtracking, and marking invalidated events as ORPHANED without deleting audit history
- V2 Health Readiness endpoint updated to display node health, current block, and indexer lag
- Comprehensive Runbook created in `docs/runbooks/indexer-rebuild.md` covering snapshot rebuilding, reorg resolution, and code hash alert procedures
- Verified with test_indexer_recovery.py (6/6 passing) and full verify:all gate suite passing with code 0
Task 16: complete
- Institutional Case Lifecycle Service (`CaseService`) with table-driven state machine (`OPEN` -> `IN_REVIEW` -> `AWAITING_APPROVAL` -> `RESOLVED` -> `CLOSED`, `ESCALATED`)
- Strict Four-Eyes Principle enforcement: self-approval of case resolutions is unconditionally prohibited by inspecting approval request events and rejecting matching `actor_sub`
- Optimistic locking concurrency control (`expected_version`) on all state transitions with HTTP 409 conflict detection
- Read-only protection for `REGULATOR` role: mutation endpoints return 403 Forbidden
- Idempotent request retries via `Idempotency-Key` header with 24-hour expiration and payload hash validation
- Append-only `case_events` ledger recording all actions, state changes, justifications, and assignees
- FastAPI V2 routes (`POST /api/v2/cases`, `GET /api/v2/cases`, `GET /api/v2/cases/{id}`, `POST /api/v2/cases/{id}/transition`, `POST /api/v2/cases/{id}/evidence`)
- Frontend `CaseWorkspace.jsx` component with Arabic/English bilingual layout, persona switcher for Four-Eyes testing, case creation modal, action buttons dynamically enabled per role/status, and immutable event timeline
- Unit and integration tests: Python `test_case_workflow.py` (7/7 passed), Vitest `CaseWorkspace.test.jsx` (5/5 passed), and full `verify:all` passing with code 0
Task 17: complete
- Standard CBI IQD CSV streaming parser (`CsvImportConnector`) supporting up to 50,000 rows with 413 payload rejection
- Strict timezone verification (rejects missing timezone with MISSING_TIMEZONE) and positive integer minor units scale 3 enforcement
- Non-PII standardized row-level validation errors (1-indexed)
- Conflict detection on `(institution_id, source, external_id)`: idempotent skip on identical data; 409 rejection on conflicting data without silent overwriting
- Database model `ImportBatchRecord` added with RLS isolation across institutions
- Single-query indexed pagination endpoint (`GET /api/v2/transactions`) with source, currency, limit, and cursor filters
- Streaming import endpoint (`POST /api/v2/imports/transactions`) with REGULATOR role write-blocking
- Frontend `client.js` methods (`listTransactions`, `importTransactions`), hook `useAuditEngine.js` indexed fetching and `importBankingCSV`, and `Dashboard.jsx` CSV upload and legal disclaimer banner
- Tests: Python `test_transaction_import.py` (8/8 passed), Playwright E2E test `1.5 Banking CSV Ingestion and Read Model Queries` passed in live integration runner
- Full test suite `npm run verify:all` passing with exit code 0

Gate G2: PASSED
- Multi-tenant relational isolation certified under PostgreSQL RLS & composite keys
- EIP-4361 SIWE challenge and EVM wallet binding with authorization generation
- WORM Evidence vault and reorg-resilient indexing worker
- Institutional case lifecycle with strict Four-Eyes governance (no self-approval)
- Streaming banking CSV import and indexed read model
- Verified by docs/verification/g2-institutional.md and docs/gates/g2-institutional-acceptance.md

