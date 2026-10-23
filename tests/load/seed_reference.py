#!/usr/bin/env python3
"""
Seed Reference Dataset for Load & Performance Benchmarking (T22)
Specification §7, §8 and Requirement R16.

Generates high-volume reference data for stress testing and query profiling:
- Configurable transaction volume (default 10,000, scalable to 100,000)
- Configurable case & report volume
- Multi-tenant distribution across 2 test institutions (CBI & Rafidain)
- Realistic structuring & high-velocity AML patterns
"""

import sys
import argparse
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add ai-engine to sys.path so app imports work seamlessly
current_dir = Path(__file__).resolve().parent
ai_engine_dir = current_dir.parent.parent / "ai-engine"
if str(ai_engine_dir) not in sys.path:
    sys.path.insert(0, str(ai_engine_dir))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.models import Base, Institution, Membership, Case, CaseEvent, TransactionRecord, ReportRecord
from app.db.session import set_engine


def seed_database(
    database_url: str = "sqlite:///load_benchmark.db",
    num_transactions: int = 10000,
    num_cases: int = 500,
    institution_id: str = "INST-BENCH-001",
    alt_institution_id: str = "INST-BENCH-002",
    batch_size: int = 1000
):
    print(f"[Seed] Initializing database at: {database_url}")
    engine = create_engine(database_url, connect_args={"check_same_thread": False} if "sqlite" in database_url else {})
    set_engine(engine)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # 1. Institutions
    for inst_id, inst_name in [
        (institution_id, "Central Bank Performance Testbed"),
        (alt_institution_id, "Rafidain Institutional Benchmark Node")
    ]:
        existing = session.query(Institution).filter_by(id=inst_id).first()
        if not existing:
            session.add(Institution(id=inst_id, name=inst_name, is_active=True))
    session.commit()

    now = datetime.now(timezone.utc)

    # 2. Cases & Reports
    print(f"[Seed] Seeding {num_cases} forensic cases and immutable reports...")
    t0 = time.perf_counter()
    cases = []
    reports = []
    for i in range(1, num_cases + 1):
        target_inst = institution_id if i % 2 == 1 else alt_institution_id
        case_id = f"CASE-BENCH-{i:06d}"
        cases.append(Case(
            id=case_id,
            case_number=f"CN-BENCH-{i:06d}",
            institution_id=target_inst,
            title=f"Forensic Investigation Scenario #{i:04d}",
            description="High-velocity cross-border settlement scrutiny.",
            severity="HIGH" if i % 4 == 0 else "MEDIUM",
            status="OPEN" if i % 3 != 0 else "CLOSED",
            assigned_to_sub="usr-bench-analyst",
            version=1,
            created_at=now - timedelta(days=i % 30),
            updated_at=now
        ))

        # Add corresponding report
        reports.append(ReportRecord(
            id=f"REP-BENCH-{i:06d}",
            report_id=f"rep-bench-{i:06d}",
            institution_id=target_inst,
            case_id=case_id,
            version=1,
            language="en" if i % 2 == 0 else "ar",
            dossier_hash="0x" + f"{i:064x}",
            integrity_status="VERIFIED" if i % 5 != 0 else "UNANCHORED",
            provenance_status="ANCHORED_CANONICAL",
            markdown_content=f"# Forensic Dossier #{i}\\n\\nAll findings validated against immutable ledger.",
            manifest_json='{"files":[],"total_evidence_bytes":1024}',
            created_by_sub="usr-bench-analyst",
            created_at=now - timedelta(days=i % 30)
        ))

        if len(cases) >= batch_size:
            session.add_all(cases)
            session.add_all(reports)
            session.commit()
            cases.clear()
            reports.clear()

    if cases:
        session.add_all(cases)
        session.add_all(reports)
        session.commit()
    print(f"[Seed] Cases & Reports seeded in {time.perf_counter() - t0:.2f}s.")

    # 3. Transactions
    print(f"[Seed] Seeding {num_transactions} transactions across institutions...")
    t0_tx = time.perf_counter()
    tx_batch = []
    for i in range(1, num_transactions + 1):
        target_inst = institution_id if i % 3 != 0 else alt_institution_id
        is_structuring = (i % 7 == 0)
        amount_minor = 14500000000 if is_structuring else 2500000000  # 14.5M IQD vs 2.5M IQD

        tx_batch.append(TransactionRecord(
            id=f"TX-BENCH-{i:07d}",
            institution_id=target_inst,
            source="IQD_CSV",
            external_id=f"EXT-BENCH-{i:07d}",
            occurred_at=now - timedelta(minutes=(num_transactions - i)),
            sender_ref=f"SND-{(i % 200):04d}",
            receiver_ref=f"RCV-{(i % 300):04d}",
            currency="IQD",
            scale=3,
            amount_minor=amount_minor,
            status="RECORDED",
            risk_score=75 if is_structuring else 15,
            created_at=now - timedelta(minutes=(num_transactions - i))
        ))

        if len(tx_batch) >= batch_size:
            session.add_all(tx_batch)
            session.commit()
            tx_batch.clear()

    if tx_batch:
        session.add_all(tx_batch)
        session.commit()

    t_total = time.perf_counter() - t0_tx
    print(f"[Seed] Transactions completed: {num_transactions} in {t_total:.2f}s ({num_transactions / t_total:.1f} tx/s).")
    session.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed load testing dataset for Iraq AML Audit Chain")
    parser.add_argument("--db-url", default="sqlite:///load_benchmark.db", help="SQLAlchemy database URL")
    parser.add_argument("--transactions", type=int, default=10000, help="Number of transactions to seed")
    parser.add_argument("--cases", type=int, default=500, help="Number of cases to seed")
    parser.add_argument("--institution", default="INST-BENCH-001", help="Primary institution ID")
    parser.add_argument("--batch-size", type=int, default=1000, help="Commit batch size")

    args = parser.parse_args()
    seed_database(
        database_url=args.db_url,
        num_transactions=args.transactions,
        num_cases=args.cases,
        institution_id=args.institution,
        batch_size=args.batch_size
    )
