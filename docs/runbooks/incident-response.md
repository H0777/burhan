# Operational Runbook: Incident Response & Compromise Mitigation

> **Document Identifier:** `RUNBOOK-OPS-002`  
> **Requirement Reference:** R11, R14, R18  
> **Classification:** Institutional Pilot Operations

---

## 1. Incident Classification Matrix

| Severity | Event Type | Trigger Criteria | Immediate Action |
|---|---|---|---|
| **SEV-1 (Critical)** | **Cryptographic Compromise** | Backup signature mismatch, bit-rot, or altered evidence file hash | Immediate instance quarantine; freeze outbox queue; trigger DR restore |
| **SEV-2 (High)** | **Participant Key Loss** | Key holder reports lost wallet or stolen device | Invoke MultiSig participant rotation; invalidate authorization generation |
| **SEV-3 (Medium)** | **Blockchain RPC Outage** | EVM node unreachable; indexer lag > 100 blocks | System transitions to `UNAVAILABLE` mode; transactions queue locally without fake anchor claims |
| **SEV-4 (Low)** | **PII Filter Anomaly** | Cloud enrichment payload flagged for unexpected redaction tokens | Inspect local regex mask logs; prevent cloud dispatch |

---

## 2. SEV-1: Bit-Rot / Cryptographic Tamper Response

1. **Isolation:** Halt active worker threads consuming from `outbox`.
2. **Investigation:** Run standalone validation:
   ```bash
   node scripts/run-python.js ops/restore.py --bundle <SUSPECT_BUNDLE> --target-db-url sqlite:///quarantine.db
   ```
3. **Rollback:** Retrieve the last known good WORM backup archive ($< 15\text{ min}$ old).
4. **Restoration:** Execute recovery runbook `RUNBOOK-OPS-001`.

---

## 3. SEV-3: Blockchain RPC Disconnection Response

When the blockchain node disconnects:
1. **Zero Fake Claims Invariant:** The backend API returns HTTP 200 with `status: "unavailable"` and `provenance_status: "unverified_rpc_unreachable"`. Under NO circumstances will the system manufacture mock block numbers or claim consensus.
2. **Local Queueing:** Transactions continue to be recorded in SQLite/PostgreSQL with `status: "RECORDED"`.
3. **Re-connection:** Once JSON-RPC connectivity is restored, indexer reconciles block numbers starting from `CheckpointRecord.last_canonical_block_number`.
