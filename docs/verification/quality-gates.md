# Quality Gates & Verification Standards (T11)

This document establishes the official quality gates, automated verification commands, and acceptance criteria for the Iraq AML/CFT Cyber-Forensic Audit Chain.

> **[2026-10-23] superseded_pending_revalidation** — Historical gate results referenced by this document (143 passing Hardhat tests, 29 selected passing Python tests, 243 lint warnings) are recorded as **historical** in [remediation/baseline-2026-10-23.md](remediation/baseline-2026-10-23.md) and are **not** evidence of current readiness. The verified remediation register [remediation/findings.csv](remediation/findings.csv) lists F01–F14, all currently **OPEN**. No gate may be cited as passed or closed until its revalidation produces red/green test evidence from a final build with a build id and environment recorded per the remediation design (§3). Thresholds in the matrix below remain the revalidation targets; they are not claims of achievement.

---

## 1. Quality Gates Matrix

| Gate | Scope | Automated Command | Target Threshold |
|---|---|---|---|
| **Gate 1: Contracts** | Solidity 0.8.20 / Hardhat | `npm run verify:contracts` | 100% test pass, zero ABI drift |
| **Gate 2: API & Engine** | FastAPI / Python / OpenAPI | `npm run verify:api` | 100% test pass, zero OpenAPI drift |
| **Gate 3: Frontend** | React 18 / ESLint / Vitest / Vite | `npm run verify:frontend` | 0 lint errors, 100% tests, clean build |
| **Gate 4: Deployment** | Manifest / RPC / Invariants | `npm run deploy:verify` | All 6 bytecodes match, bootstrap revoked |
| **Gate 5: Secrets** | Repository Hygiene | Git index scan | Zero `.env`, `.key`, or `.pem` tracked |

---

## 2. Command Reference

### Gate 1: Contracts & EVM Governance
```bash
# Compiles contracts, checks ABI drift, and runs 143 Hardhat tests
npm run verify:contracts
```
Underlying tasks:
- `npm run contracts:check`: Verifies no drift between compiled artifacts and authoritative ABIs in `frontend/src/contracts/generated/`.
- `npx hardhat test`: Executes all 9 test suites including security regressions, write authorization, atomic governance, and evidence deduplication.

### Gate 2: AI Engine, Policy & API Contract
```bash
# Checks OpenAPI V2 drift, shared hash fixtures, and runs Python test suite
npm run verify:api
```
Underlying tasks:
- `python scripts/check-openapi.py`: Validates that `shared/openapi-v2.json` matches the runtime FastAPI schema.
- `node --test shared/tests/evidence-hash.test.mjs shared/tests/currency.test.mjs`: Tri-language parity verification across EVM, Python, and JavaScript.
- `pytest -q ai-engine/tests`: Executes all 44 unit and contract test cases.

### Gate 3: Frontend Code Quality, Tests & Bundle
```bash
# Runs ESLint v9 flat config, Vitest component/hook tests, and Vite production bundle
npm run verify:frontend
```
Underlying tasks:
- `npm --prefix frontend run lint`: ESLint check with zero errors.
- `npm --prefix frontend test -- --run`: Runs 13 tests covering runtime config, AI client health, and MultiSig governance UI.
- `npm --prefix frontend run build`: Generates production dist bundle without missing dependencies or syntax errors.

### Gate 4: Deployment & Invariant Verification
```bash
# Verifies live deployment against manifest
npm run deploy:verify
```
Checks:
1. RPC connection and chain ID.
2. Bytecode existence and keccak256 hash match against `deployments/deployment-manifest.json`.
3. `isBootstrapFinalized == true`.
4. `bootstrapAuthority == address(0)`.
5. `countActiveParticipants >= 4`.
6. `AuditEngine.isIntegrated == true`.

---

## 3. Secret Hygiene Policy

Under no circumstances should any developer or automated pipeline commit:
- Unencrypted private keys or seed phrases.
- `.env` files containing production credentials.
- Cloud API keys (`GEMINI_API_KEY`).
- Private certificates or `.pem`/`.key` files.

CI runs an automated Git index scan on every push to reject secret leaks immediately.
