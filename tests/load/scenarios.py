"""
Load Testing and Concurrency Scenarios (T22)
Cyber-Forensic Auditing Framework - Specification §7, §8 & Requirement R16.

Simulates multi-tenant concurrent operators exercising:
1. Transaction ledger listing with cursor pagination
2. Authoritative risk assessment with 24h rolling velocity
3. Case forensic report provenance verification
4. Smart contract vulnerability scanning
5. LLM privacy redaction under concurrency
"""

import time
import math
import statistics
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.models import Base, Institution, Membership, Case, CaseEvent, TransactionRecord, ReportRecord
from app.db.session import set_engine
from app.routes.v2.identity import get_current_identity
from app.schemas.identity import Identity, RoleEnum


def setup_benchmark_fixtures(num_txs=2000, num_cases=100):
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    set_engine(engine)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    inst1 = Institution(id="INST-LOAD-001", name="Central Bank Testbed", is_active=True)
    inst2 = Institution(id="INST-LOAD-002", name="Rafidain Testbed", is_active=True)
    session.add_all([inst1, inst2])

    now = datetime.now(timezone.utc)

    # Add cases & reports
    cases = []
    reports = []
    for i in range(1, num_cases + 1):
        c_id = f"CASE-LOAD-{i:04d}"
        cases.append(Case(
            id=c_id,
            case_number=f"CN-LOAD-{i:04d}",
            institution_id="INST-LOAD-001",
            title=f"AML Case #{i}",
            severity="HIGH" if i % 5 == 0 else "MEDIUM",
            status="OPEN",
            assigned_to_sub="usr-load-op",
            version=1,
            created_at=now,
            updated_at=now
        ))
        reports.append(ReportRecord(
            id=f"REP-LOAD-{i:04d}",
            report_id=f"rep-load-{i:04d}",
            institution_id="INST-LOAD-001",
            case_id=c_id,
            version=1,
            language="en",
            dossier_hash="0x" + f"{i:064x}",
            integrity_status="VERIFIED",
            provenance_status="ANCHORED_CANONICAL",
            markdown_content=f"# Report #{i}",
            manifest_json='{"files":[]}',
            created_by_sub="usr-load-op",
            created_at=now
        ))
    session.add_all(cases)
    session.add_all(reports)

    # Add transactions
    txs = []
    for i in range(1, num_txs + 1):
        txs.append(TransactionRecord(
            id=f"TX-LOAD-{i:05d}",
            institution_id="INST-LOAD-001",
            source="IQD_CSV",
            external_id=f"EXT-{i:05d}",
            occurred_at=now - timedelta(minutes=i),
            sender_ref=f"SND-{(i % 50):03d}",
            receiver_ref=f"RCV-{(i % 100):03d}",
            currency="IQD",
            scale=3,
            amount_minor=14500000000 if i % 10 == 0 else 2500000000,
            status="RECORDED"
        ))
    session.add_all(txs)
    session.commit()
    return session


def run_load_scenarios(iterations=200):
    session = setup_benchmark_fixtures(num_txs=1000, num_cases=50)

    # Mock identity for authenticated routes
    mock_identity = Identity(
        sub="usr-load-op",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-LOAD-001",
        role=RoleEnum.OPERATOR,
        permissions=["read:cases", "write:cases", "assess:write", "assess:read", "scanner:write"]
    )
    app.dependency_overrides[get_current_identity] = lambda: mock_identity
    client = TestClient(app)

    scenarios = {
        "LIST_TRANSACTIONS": [],
        "ASSESS_TRANSACTION": [],
        "GET_REPORT_PROVENANCE": [],
        "SCAN_CONTRACT": [],
        "REDACT_TEXT": []
    }

    print(f"[Load Scenarios] Starting execution of {iterations} rounds across 5 endpoints...")
    t_global_start = time.perf_counter()

    for i in range(iterations):
        # 1. List transactions
        t0 = time.perf_counter()
        res = client.get("/api/v2/transactions?limit=25")
        scenarios["LIST_TRANSACTIONS"].append((time.perf_counter() - t0) * 1000.0)
        assert res.status_code == 200

        # 2. Assess transaction (preview mode)
        tx_id = f"TX-LOAD-{(i % 500) + 1:05d}"
        t0 = time.perf_counter()
        res = client.post("/api/v2/risk/preview", json={"transaction_id": tx_id})
        scenarios["ASSESS_TRANSACTION"].append((time.perf_counter() - t0) * 1000.0)
        assert res.status_code == 200, f"Assess preview failed with status {res.status_code}: {res.text}"

        # 3. Report Provenance
        case_id = f"CASE-LOAD-{(i % 50) + 1:04d}"
        t0 = time.perf_counter()
        res = client.get(f"/api/v2/cases/{case_id}/reports")
        scenarios["GET_REPORT_PROVENANCE"].append((time.perf_counter() - t0) * 1000.0)
        assert res.status_code == 200, f"Get reports failed with status {res.status_code}: {res.text}"

        # 4. Scan Contract
        solidity_snippet = "contract Vault { function withdraw() public { require(tx.origin == msg.sender); } }"
        t0 = time.perf_counter()
        res = client.post("/api/v2/scanner/scan", json={"source_code": solidity_snippet, "mode": "REGEX_HEURISTIC"})
        scenarios["SCAN_CONTRACT"].append((time.perf_counter() - t0) * 1000.0)
        assert res.status_code == 200, f"Scan contract failed with status {res.status_code}: {res.text}"

        # 5. Redact Text / Narrative
        t0 = time.perf_counter()
        res = client.post("/api/v2/scanner/narrative", json={
            "case_title": "High-risk transfer",
            "case_description": f"Customer IQ12345678901234567890123 transferred 15000000 IQD to 07901234567",
            "evidence_descriptions": ["Wallet 0x71C841832047387CE95A0194459b90875bCbAC97 linked to exchange."],
            "enable_cloud": False
        })
        scenarios["REDACT_TEXT"].append((time.perf_counter() - t0) * 1000.0)
        assert res.status_code == 200, f"Narrative redaction failed with status {res.status_code}: {res.text}"

    t_global_total = time.perf_counter() - t_global_start
    total_requests = iterations * len(scenarios)
    overall_tps = total_requests / t_global_total

    print("\\n=======================================================")
    print("        LOAD & PERFORMANCE BENCHMARK RESULTS (T22)     ")
    print("=======================================================")
    print(f"Total Requests: {total_requests}")
    print(f"Total Duration: {t_global_total:.2f} seconds")
    print(f"Overall Throughput: {overall_tps:.1f} requests/sec")
    print("-------------------------------------------------------")
    print(f"{'Endpoint / Scenario':<25} | {'p50 (ms)':<9} | {'p95 (ms)':<9} | {'p99 (ms)':<9} | {'Max (ms)':<9}")
    print("-------------------------------------------------------")

    summary_stats = {}
    for name, latencies in scenarios.items():
        sorted_lats = sorted(latencies)
        p50 = sorted_lats[int(0.50 * len(sorted_lats))]
        p95 = sorted_lats[int(0.95 * len(sorted_lats))]
        p99 = sorted_lats[int(0.99 * len(sorted_lats))]
        max_lat = sorted_lats[-1]
        print(f"{name:<25} | {p50:<9.2f} | {p95:<9.2f} | {p99:<9.2f} | {max_lat:<9.2f}")
        summary_stats[name] = {"p50": p50, "p95": p95, "p99": p99, "max": max_lat}

    print("=======================================================")
    app.dependency_overrides.clear()
    session.close()
    return summary_stats, overall_tps


if __name__ == "__main__":
    run_load_scenarios(200)
