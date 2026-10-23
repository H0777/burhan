# Operational Runbook: Disaster Recovery & System Restoration

> **Document Identifier:** `RUNBOOK-OPS-001`  
> **Requirement Reference:** R11, R16, R18  
> **Target Metrics:** Recovery Point Objective (RPO) $\le 15\text{ minutes}$, Recovery Time Objective (RTO) $\le 2\text{ hours}$

---

## 1. Objectives & Scope

This runbook outlines the operational procedures for recovering the **Cyber-Forensic Auditing Platform** in the event of hardware failure, catastrophic database corruption, data center outage, or node compromise.

### Key Recovery Guarantees
- **RPO $\le 15$ Minutes:** Automated periodic snapshots capture database mutations and evidence files.
- **RTO $\le 2$ Hours:** Fast, automated restoration CLI reconstructs isolated instances from cryptographically signed archives.
- **WORM & Cryptographic Integrity:** All backup bundles contain SHA-256 manifests; bit-rot or tampering causes immediate rejection.
- **Idempotent Outbox Resumption:** Worker tasks resume from the last committed checkpoint without replaying financial anchors or duplicate transactions.

---

## 2. Backup Architecture & Storage Policy

1. **Database Snapshots:** Generated via SQLite `VACUUM INTO` or atomic PostgreSQL point-in-time exports, ensuring zero lock contention.
2. **Evidence Object Store:** Cold-storage replication with SHA-256 validation for every archived forensic dossier, PDF, and JSON artifact.
3. **Checkpoints & Chain State:** Block height, transaction hashes, and smart contract registry cutoffs are embedded in the `backup-manifest.json`.
4. **Secret Boundaries:** Private keys, seed phrases, and operational passwords are NEVER embedded in backups; only opaque cryptographic key references are stored.

---

## 3. Step-by-Step Restoration Procedure

### Step 1: Pre-Restoration Verification & Isolation
Ensure the target server or container environment is strictly isolated from production traffic:
```powershell
# Set target isolated database environment
$TargetDb = "sqlite:///isolated_recovery.db"
$TargetEvidence = "./restored_evidence_store"
```

### Step 2: Integrity & Bit-Rot Verification
Execute the automated restore tool which validates file checksums against `backup-manifest.sha256`:
```powershell
.\ops\restore.ps1 -Bundle "./backups/BKP-20261023-XXXXXX.zip" -TargetDbUrl $TargetDb -TargetEvidenceDir $TargetEvidence
```
If any file has suffered bit-rot or tampering, the CLI will terminate with exit code `2` and an alert:
```
[SECURITY ALERT] Backup corruption or tampering detected: Bit-rot detected in DB snapshot
```

### Step 3: Checkpoint & Worker Outbox Synchronization
Confirm that restored checkpoints match the latest canonical block observed on the local EVM node:
```bash
node scripts/run-python.js -c "
from app.db.session import get_engine
from app.services.backup_service import BackupService
print('Validating checkpoint continuity...')
"
```

### Step 4: Health Probes Verification
Run operational readiness probes before rerouting traffic:
```bash
node scripts/run-python.js -c "
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ops.health.probes import run_all_health_probes

engine = create_engine('sqlite:///isolated_recovery.db')
Session = sessionmaker(bind=engine)
res = run_all_health_probes(Session())
print(res)
assert res['overall_status'] == 'READY'
"
```

---

## 4. Lost Governance Participant Key Rotation

If one participant's hardware wallet is lost or permanently compromised:
1. The remaining 3 active participants convene (Quorum = 3, Proposer + 2 Approvers).
2. Propose `replaceParticipant(lostAddress, newAddress)` via MultiSig.
3. Approver 1 and Approver 2 sign the proposal.
4. Execution updates the participant registry and increments authorization generation, automatically invalidating stale signatures from the lost key.
