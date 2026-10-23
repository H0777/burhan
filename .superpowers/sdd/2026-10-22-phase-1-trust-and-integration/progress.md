# SDD ledger — plan: docs/superpowers/plans/2026-10-22-phase-1-trust-and-integration.md

## Pre-flight Interface & Conflict Scan
- T01 -> T02/T03/T05/T07: Regression tests defined in T01 capture vulnerabilities that T02, T03, T05, T07 will eliminate.
- T02 -> T03: MultiSig bootstrap authority in T02 hands over governance to RoleManager and MultiSig in T03.
- T02/T03 -> T04: ForensicTrail in T04 uses writer allowlists from T02 and requestId dedup from T03/T05.
- T04 -> T05: Shared evidence fixture and hashing in T04 consumed by Python evidence verifier in T05.
- T03 -> T06: On-chain policy updates via MultiSig in T03 consumed by policy service in T06.
- T05/T06 -> T07: Evidence and policy schemas from T05/T06 exported to OpenAPI v2 in T07.
- T03/T04/T06/T07 -> T08: Contract ABIs and OpenAPI client consumed by frontend runtime in T08.
- T03/T08 -> T09: Governance execution ABI and contract client in T08 consumed by RoleManagement UI in T09.
- T02-T09 -> T10: All deployed artifacts and runtime configs packaged in T10.
- T07/T08/T10 -> T11: Linting, build, and unit test gates unified in T11.
- T01-T11 -> T12: Full integration trust flow and G1 verification in T12.
Pre-flight: interfaces aligned with spec §3-8.

Task 1: complete
- Baseline toolchain and Git tree inventory recorded in docs/verification/baseline-2026-10-22.md.
- Smart contract regressions captured in test/security/ObservedRegressions.test.js (3 failing as expected).
- AI/Backend regressions captured in ai-engine/tests/test_observed_regressions.py (altered_content failing as expected, payload mismatch passing 422).
- Zero production code modified in T01.

Task 2: complete (commits 906c918..2cf23dd, tests: npx hardhat test test/security/WriteAuthorization.test.js → 13 passing)
- MultiSig phased bootstrap implemented with single-use bootstrapAuthority.
- EOA contract assignment rejected; zero addresses rejected; double-binding rejected.
- Finalization requires minimum 4 distinct active participants.
- All non-governance write paths and unauthorized logging rejected; recorder and evidence writer allowlists enforced.
Task 3: complete (test suite: test/security/GovernanceExecution.test.js 14 passing; 135 total passing across all suites)
- Structured proposals with typed action integrity, actionHash binding, explicit target and call data implemented.
- Atomic execution via executeProposal with automatic rollback on target failure and replay prevention.
- Separation of Duties (SoD) on warning overrides enforced (warning proposer, sender, and receiver cannot approve).
- Authorization generation tracking in RoleManager and MultiSig to invalidate stale votes when roles change.
- Pause epoch tracking on AuditEngine to prevent stale emergency unpause replays across pause events.
- Legacy suites adapted to V2 typed proposal signatures and atomic execution pattern.
- 135 Hardhat tests passing (100% green).

Task 4: complete (tests: EVM 8 passing, Node/JS 3 passing, Python 3 passing; 143 Hardhat total passing)
- EvidenceHashing library implemented with canonical 12-parameter abi.encode V2 layout according to Design Spec §6.
- Tri-language parity verified across Solidity (EvidenceHashing.sol), Python (app.schemas.evidence.py), and JavaScript (frontend/src/utils/evidenceHash.js).
- Shared fixture suite in shared/fixtures/evidence-v2.json covering initial zero-previous, chained entries, Arabic unicode, large uint256 limits, and 10 single-field perturbation variations.
- ForensicTrail V2 upgraded with hashed incident metadata, canonical V2 entry hashing, and idempotent deduplication via anchorRequestId.
- Duplicate anchorRequestId submissions by the same writer with identical payload return existing evidenceId without re-incrementing or re-emitting.
- Payload or writer mismatches for an existing anchorRequestId strictly revert.
- All 143 Hardhat tests pass across 9 suites.

Task 5: complete (tests: 33/33 Python passing, 143/143 Hardhat passing, 3/3 JS passing)
- Created independent 3-state evidence verifier in ai-engine/app/services/evidence_verifier.py returning strictly "verified", "invalid", or "unavailable".
- Validates canonical keccak256(abi.encode) entry hashes, parent-child continuity, and reconciles with on-chain consensus state and institutional writer allowlists.
- Rejects empty chains, tampered contents, broken links, or count mismatches as "invalid"; cleanly flags RPC failures as "unavailable" without raw tracebacks.
- Identifies legacy unrestricted writers with provenance_status="legacy_unrestricted_submission" and warning flags.
- Created V2 endpoint POST /api/v2/evidence/verify in ai-engine/app/routes/v2/evidence.py matching Specification §7.
- Modified ai-engine/app/services/gemini_service.py to eliminate static claims of cryptographic validity on unanchored or tampered evidence, resolving the T01 baseline regression.
- All 33 Python tests passing, including tests/test_evidence_verifier.py and tests/test_observed_regressions.py.

Task 6: complete (tests: 39/39 Python passing, 143/143 Hardhat passing, 7/7 JS passing)
- Created strict policy schemas in ai-engine/app/schemas/policy.py (PolicyVersion, PolicyThresholds) with exact minor-unit strings.
- Implemented unified policy service in ai-engine/app/services/policy_service.py with Decimal precision (scale=18 wei for ETH, scale=3 fils for IQD).
- Rigorously tested threshold boundaries (threshold - 1, threshold, threshold + 1), huge amounts (> 2^53 up to uint256 max), and strict asset isolation (IQD cannot enter ETH policy and vice versa).
- Implemented GET /api/v2/policies/active in ai-engine/app/routes/v2/policies.py reading authoritative on-chain contract state or regulatory fixtures.
- Updated frontend/src/utils/currency.js with BigInt minor-unit precision parsing and formatting, and clearly disclosed fixed demo rates.
- Clarified ComplianceRules.sol comments on native ETH vs off-chain fiat IQD thresholds.
- All 39 Python tests, 143 Hardhat tests, and 7 Node tests pass (100% green).

Task 7: complete (tests: 44/44 Python passing, 143/143 Hardhat passing, 7/7 JS passing)
- Created common V2 schemas in ai-engine/app/schemas/common.py (APIErrorResponse, LiveHealthResponse, ReadyHealthResponse) with extra="forbid".
- Implemented life-cycle health routes in ai-engine/app/routes/v2/health.py (/api/v2/health/live and /api/v2/health/ready verifying ML engine and policy service).
- Built deterministic OpenAPI v2 exporter in scripts/export-openapi.py generating shared/openapi-v2.json.
- Built schema drift checker in scripts/check-openapi.py and added npm scripts (api:export, api:check, api:generate) in root package.json.
- Created generated TypeScript interface definitions in frontend/src/api/generated/schema.d.ts.
- Created strict fetch API client in frontend/src/api/client.js without silent mock fallbacks.
- Updated frontend/src/utils/aiClient.js checkAIHealth to query real /api/v2/health/ready and inspect actual model readiness.
- Updated docs/api-reference.md with complete V2 API section.
- Verified test suite: 44 Python tests passing, including tests/test_v2_contracts.py verifying 422 extra field rejection.

Task 8: complete (tests: 6/6 Vitest passing, 143/143 Hardhat passing, 44/44 Python passing, 7/7 Node passing)
- Created scripts/export-contracts.js exporting authoritative compiled ABIs to frontend/src/contracts/generated/.
- Created scripts/check-contracts.js checking artifact-to-ABI drift, and added contracts:export and contracts:check npm scripts.
- Implemented frontend/src/config/runtime.js with APP_MODE (demo vs institutional), isInstitutionalMode(), getVerifiedDeployment(), and OperationResult.
- Isolated demo fallback datasets in frontend/src/demo/fixtures.js.
- Upgraded frontend/src/utils/contract.js to import and use generated ABIs, enforce real institutional signers, and prevent simulated wallet fallback when in institutional mode.
- Installed Vitest in frontend with frontend/vitest.config.js, frontend/src/utils/aiClient.test.js, and frontend/src/hooks/useAuditEngine.test.jsx (6 tests passing).
- Validated clean production build: npm --prefix frontend run build succeeded with zero errors.

Task 9: complete (tests: 13/13 Vitest passing, 143/143 Hardhat passing, 44/44 Python passing, 7/7 Node passing)
- Created frontend/src/hooks/useGovernance.js managing proposals and roles via generated ABIs for MultiSigApproval and RoleManager.
- Supports atomic createProposal, approveProposal, executeProposal, rejectProposal returning OperationResult.
- Implemented frontend/src/components/RoleManagement.test.jsx with 7 tests: duplicate vote rejection, APPROVED != EXECUTED enforcement, signature failure handling, expired proposal rejection, account switching role sync, and pre-signing action verification.
- Modified frontend/src/components/RoleManagement.jsx to connect to useGovernance(), render target/actionHash/expiresAt/reason, separate Confirm (2nd Eye) from Execute Action buttons, enforce SoD (proposer cannot self-approve), and show live transaction hashes.
- Modified frontend/src/hooks/useAuditEngine.js to query real RoleManager roles upon connect and account switching, strictly defaulting to NONE in institutional mode without fake SUPER_ADMIN fallback.
- Added DEMO_ROLES and DEMO_PROPOSALS in frontend/src/demo/fixtures.js.
- Verified all tests pass across Vitest (13/13), Hardhat (143/143), Python (44/44), and Node (7/7); frontend production build succeeds with zero errors.
