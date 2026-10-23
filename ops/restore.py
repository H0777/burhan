#!/usr/bin/env python3
"""
Automated Disaster Recovery Restore CLI (T23)
Specification §4, §7, §8 & Requirement R11, R18

Usage:
  python ops/restore.py --bundle ./backups/BKP-xxx.zip --target-db-url sqlite:///restored.db
"""

import sys
import json
import argparse
from pathlib import Path

# Add ai-engine to sys.path
root_dir = Path(__file__).resolve().parent.parent
ai_engine_dir = root_dir / "ai-engine"
if str(ai_engine_dir) not in sys.path:
    sys.path.insert(0, str(ai_engine_dir))

from app.services.backup_service import BackupService, BackupCorruptionError


def main():
    parser = argparse.ArgumentParser(description="Restore and verify system state from backup bundle")
    parser.add_argument("--bundle", required=True, help="Path to backup zip bundle")
    parser.add_argument("--target-db-url", required=True, help="Destination database URL (must be isolated)")
    parser.add_argument("--target-evidence-dir", default=None, help="Destination directory for restored evidence files")

    args = parser.parse_args()

    service = BackupService()
    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"[ERROR] Bundle not found: {bundle_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[Restore] Verifying bundle integrity and restoring to {args.target_db_url}...")
    try:
        report = service.restore_backup(
            bundle_path=bundle_path,
            target_db_url=args.target_db_url,
            target_evidence_dir=args.target_evidence_dir
        )
        print("[SUCCESS] Restore completed and verified without corruption!")
        print(json.dumps(report, indent=2))
    except BackupCorruptionError as exc:
        print(f"[SECURITY ALERT] Backup corruption or tampering detected: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"[ERROR] Restore failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
