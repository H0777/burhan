# Local Environment Startup & Deployment Runbook (T10)

This runbook describes the procedure for deploying, verifying, and running the Iraq AML/CFT Cyber-Forensic Audit Chain in both local bare-metal and Docker Compose environments.

---

## 1. System Architecture & Dual Operating Modes

The system supports two strictly separated modes:
- **`demo` mode**: Rapid visual exploration and mock testing with local Hardhat unlocked signers, pre-seeded synthetic fixtures, and optional ML fallback.
- **`institutional` mode**: Strict production/pilot mode. Hardhat unlocked Signer #0 is prohibited; real Web3/hardware signers and cryptographic deployment verification are strictly enforced. Unauthenticated fallbacks are blocked.

---

## 2. Prerequisites

- **Node.js**: `v20.x` or later (`npm v10+`)
- **Python**: `3.11+` (or `3.14+`)
- **Hardhat**: `2.22.x`
- **Docker & Docker Compose**: Optional for containerized deployment

---

## 3. Bare-Metal Local Startup Procedure

### Step 1: Start the Local EVM Node
In Terminal 1:
```bash
npx hardhat node --hostname 127.0.0.1
```
The node will start with 20 funded test accounts listening on `http://127.0.0.1:8545` (Chain ID `31337`).

### Step 2: Deploy & Bootstrap Contracts
In Terminal 2:
```bash
npx hardhat run scripts/deploy.js --network localhost
```
This script:
1. Deploys `MultiSigApproval`, `RoleManager`, `InsiderActivityLog`, `ForensicTrail`, `ComplianceRules`, and `AuditEngine`.
2. Connects and wires cross-contract permissions.
3. Enrolls the mandatory 4 active participants (Auditor, Operator, Regulator, Admin).
4. Transfers governance to `MultiSigApproval`.
5. Finalizes bootstrap and permanently revokes bootstrap authority (`address(0)`).
6. Computes bytecode keccak256 hashes and saves `deployments/deployment-manifest.json` and `frontend/public/runtime-config.json`.

### Step 3: Cryptographically Verify Deployment
Verify that all contracts match their manifest and that security invariants hold:
```bash
node scripts/verify-deployment.js
```
Expected output:
```
[PASS] Chain ID verified: 31337
[PASS] Bytecode verified for RoleManager
[PASS] Bytecode verified for InsiderActivityLog
[PASS] Bytecode verified for ForensicTrail
[PASS] Bytecode verified for ComplianceRules
[PASS] Bytecode verified for MultiSigApproval
[PASS] Bytecode verified for AuditEngine
[PASS] MultiSigApproval bootstrap finalization verified.
[PASS] Bootstrap authority revocation verified (address(0)).
[PASS] Active participants verified: 5 active signers.
[PASS] AuditEngine integration verified.
[SUCCESS] ALL DEPLOYMENT VERIFICATION CHECKS PASSED!
```

### Step 4: Start the Python FastAPI Engine
In Terminal 3:
```bash
cd ai-engine
# Windows PowerShell:
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Check health:
```bash
curl http://127.0.0.1:8000/api/v2/health/ready
```

### Step 5: Start the Frontend Dashboard
In Terminal 4:
```bash
cd frontend
npm run dev
```
Access the application at `http://localhost:5173`.

---

## 4. Docker Compose Startup Procedure

To run the complete system with isolated networking and reverse proxy:

```bash
docker compose up --build
```

### Container Endpoints:
- **Dashboard UI**: `http://localhost:3005` (proxies `/api` to backend)
- **AI Engine API**: `http://localhost:8005` (direct API access)
- **Hardhat EVM**: `http://localhost:8545` (JSON-RPC)

To verify the containerized deployment:
```bash
node scripts/verify-deployment.js deployments/deployment-manifest.json http://localhost:8545
```

To stop containers cleanly without wiping user data:
```bash
docker compose stop
```

---

## 5. Troubleshooting & Invariant Checks

| Symptom | Root Cause | Remediation |
|---|---|---|
| `MultiSig: bootstrap not finalized` | Deployment was interrupted before step 10 | Re-run `scripts/deploy.js` on fresh node |
| `Chain ID mismatch` | Connected to wrong network (e.g., Mainnet instead of local) | Check `VITE_RPC_URL` in `.env` or `runtime-config.json` |
| `Contract has no deployed bytecode` | Contracts were not deployed to currently running node instance | Re-run `npx hardhat run scripts/deploy.js --network localhost` |
| `Institutional Mode: Unlocked signer #0 is prohibited` | Application set to `institutional` mode without an external wallet | Switch `APP_MODE=demo` or connect MetaMask/Hardware signer |
| `RoleManager: insufficient role` | Account attempting MultiSig action lacks `SUPER_ADMIN` or `AUDITOR` | Switch account in wallet to an authorized auditor/admin signer |
