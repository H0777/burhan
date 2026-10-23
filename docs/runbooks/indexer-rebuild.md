# Runbook: Blockchain Indexer Rebuild & Reorg Recovery

**Operational Guide for Institutional Node Operators & Forensic Auditors**
**Version:** 2.0.0 (Phase 2 Institutional Platform — T15)
**Requirements:** R09, R11

---

## 1. Overview & Architectural Invariants

The Blockchain Indexer continuously synchronizes smart contract events (`ForensicTrail`, `AuditEngine`, `InsiderActivityLog`, `MultiSigApproval`, `RoleManager`) into the relational database with strict multi-tenant isolation.

### Core Security Invariants
1. **Atomic Commits:** Events and checkpoint block headers are always committed within a single database transaction. No partial state is ever persisted.
2. **Deterministic Reorg Recovery:** If an on-chain block hash diverges from the recorded checkpoint block hash, the indexer detects the reorganization, rewinds the checkpoint to the common ancestor, and marks invalidated events as `ORPHANED`.
3. **Audit Immutability (No Silent Deletions):** Orphaned events are never deleted from `chain_events`. Their status is updated to `ORPHANED` to preserve an evidentiary trail of reorganizations for forensic inspection.
4. **Bytecode Hash Verification:** Before indexing any contract address, the indexer validates that the bytecode matches the cryptographic `code_hash` from the approved deployment manifest. Any discrepancy aborts indexing with `CodeHashMismatchError`.

---

## 2. Rebuilding the Indexer from Genesis or Snapshot

When an operator needs to re-index from genesis or a known verified checkpoint snapshot:

### Step 1: Graceful Service Shutdown
Ensure the indexer worker is stopped cleanly to prevent mid-batch processing:
```bash
# In containerized deployments
docker compose stop ai-engine
```

### Step 2: Database Checkpoint Inspection & Reset
Connect to PostgreSQL and inspect current checkpoint state:
```sql
SELECT institution_id, chain_id, contract_address, last_canonical_block_number, last_canonical_block_hash, updated_at
FROM checkpoints
WHERE institution_id = 'INST-CENTRAL-DEMO';
```

To rewind the indexer to a specific verified block (e.g., block 0 for complete rebuild):
```sql
BEGIN;
-- Mark subsequent events as ORPHANED or archive them
UPDATE chain_events
SET status = 'ORPHANED'
WHERE institution_id = 'INST-CENTRAL-DEMO'
  AND block_number > 0;

-- Reset checkpoint to genesis
UPDATE checkpoints
SET last_canonical_block_number = 0,
    last_canonical_block_hash = '0x0000000000000000000000000000000000000000000000000000000000000000',
    updated_at = NOW()
WHERE institution_id = 'INST-CENTRAL-DEMO';
COMMIT;
```

### Step 3: Verify Contract Bytecode Hashes
Ensure the target contracts have not been substituted:
```bash
python -c "
from app.services.chain_registry import ChainRegistry
from app.services.blockchain_listener import blockchain_listener
reg = ChainRegistry()
reg.verify_contract_code_hash(blockchain_listener, 'ForensicTrail')
print('[SUCCESS] Bytecode hashes verified.')
"
```

### Step 4: Resume Indexer & Monitor Sync Lag
Restart the service and monitor indexing progress:
```bash
docker compose start ai-engine
```
Query the readiness endpoint to verify lag reaches `0`:
```bash
curl -s http://localhost:8000/api/v2/health/ready | jq .details
```
Expected output:
```json
{
  "blockchain_status": "ONLINE",
  "current_block": 1450,
  "indexer_lag": 0
}
```

---

## 3. Incident Response: Code Hash Mismatch

If `CodeHashMismatchError` is logged:
1. **Immediate Escalation:** Stop the indexer immediately. This indicates either an unauthorized contract upgrade or malicious contract substitution.
2. **On-Chain Audit:** Compare the bytecode hash at the address using `cast code <address>` or ethers.js against the approved manifest hash in `deployments/deployment-manifest.json`.
3. **Do not update the manifest** without written governance approval signed by 2+ authorized auditors via MultiSig.
