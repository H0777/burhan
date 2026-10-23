#!/usr/bin/env python3
"""
Automated Disaster Recovery Backup CLI (T23)
Specification §4, §7, §8 & Requirement R11, R18

Usage:
  python ops/backup.py --output-dir ./backups --db-url sqlite:///cyber_audit_chain.db
"""

import sys
import argparse
from pathlib import Path

# Add ai-engine to sys.path
root_dir = Path(__file__).resolve().parent.parent
ai_engine_dir = root_dir / "ai-engine"
if str(ai_engine_dir) not in sys.path:
    sys.path.insert(0, str(ai_engine_dir))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.services.backup_service import BackupService


def main():
    parser = argparse.ArgumentParser(description="Create cryptographically signed system backup bundle")
    parser.add_argument("--output-dir", default="./backups", help="Directory where backup bundle will be saved")
    parser.add_argument("--db-url", default="sqlite:///cyber_audit_chain.db", help="Source database URL")
    parser.add_argument("--evidence-dir", default="./evidence_store", help="Path to evidence file storage")
    parser.add_argument("--name", default=None, help="Custom backup bundle identifier")

    args = parser.parse_args()

    engine = create_engine(args.db_url)
    from app.db.models import Base
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    service = BackupService(evidence_dir=args.evidence_dir)
    print(f"[Backup] Initiating snapshot from {args.db_url}...")
    bundle_path = service.create_backup(
        session=session,
        output_dir=args.output_dir,
        backup_name=args.name
    )
    print(f"[SUCCESS] Backup bundle created at: {bundle_path.resolve()}")
    session.close()


if __name__ == "__main__":
    main()
