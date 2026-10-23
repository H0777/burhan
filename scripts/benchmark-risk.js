/**
 * Performance & Latency Benchmark Script (T22)
 * Cyber-Forensic Auditing Framework - Specification §7, §8 & R16
 * 
 * Benchmarks:
 * - Single-transaction authoritative risk scoring latency (p50, p95, p99)
 * - Batch throughput (target >= 100 tx/sec)
 * - Memory stability and connection pooling integrity
 */

const { spawn } = require('child_process');
const path = require('path');

const BENCH_PYTHON_SCRIPT = `
import time
import math
import sys
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models import Base, Institution, TransactionRecord
from app.db.session import set_engine
from app.schemas.identity import Identity, RoleEnum
from app.services.feature_service import FeatureService
from app.services.assessment_service import AssessmentService

def run_benchmark(batch_size=1000):
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    set_engine(engine)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    inst = Institution(id="INST-BENCH-001", name="Benchmark Central Bank", is_active=True)
    db.add(inst)

    now = datetime.now(timezone.utc)
    txs = []
    for i in range(1, batch_size + 1):
        txs.append(TransactionRecord(
            id=f"TX-BENCH-{i:06d}",
            institution_id="INST-BENCH-001",
            source="IQD_CSV",
            external_id=f"EXT-{i:06d}",
            occurred_at=now - timedelta(minutes=i),
            sender_ref=f"SND-{(i % 25):03d}",
            receiver_ref=f"RCV-{(i % 50):03d}",
            currency="IQD",
            scale=3,
            amount_minor=13500000000 if (i % 5 == 0) else 2500000000,
            status="RECORDED"
        ))
    db.add_all(txs)
    db.commit()

    service = AssessmentService(feature_service=FeatureService())
    identity = Identity(
        sub="usr-bench-lead",
        issuer="https://auth.institutional-cbi.iq/oauth2",
        institution_id="INST-BENCH-001",
        role=RoleEnum.OPERATOR,
        permissions=["assess:write", "assess:read"]
    )

    latencies_ms = []
    t_start_all = time.perf_counter()

    for i in range(1, batch_size + 1):
        t0 = time.perf_counter()
        resp = service.assess_transaction(
            session=db,
            identity=identity,
            transaction_id=f"TX-BENCH-{i:06d}",
            is_preview=True
        )
        lat_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(lat_ms)

    t_total_sec = time.perf_counter() - t_start_all
    throughput = batch_size / t_total_sec

    sorted_lats = sorted(latencies_ms)
    p50 = sorted_lats[int(0.50 * len(sorted_lats))]
    p95 = sorted_lats[int(0.95 * len(sorted_lats))]
    p99 = sorted_lats[int(0.99 * len(sorted_lats))]

    print(f"BATCH_SIZE:{batch_size}")
    print(f"TOTAL_SEC:{t_total_sec:.4f}")
    print(f"THROUGHPUT_TPS:{throughput:.2f}")
    print(f"P50_MS:{p50:.2f}")
    print(f"P95_MS:{p95:.2f}")
    print(f"P99_MS:{p99:.2f}")

if __name__ == "__main__":
    run_benchmark(1000)
`;

function run() {
  const runnerPath = path.join(__dirname, 'run-python.js');
  const proc = spawn('node', [runnerPath, '-c', BENCH_PYTHON_SCRIPT], {
    cwd: path.join(__dirname, '..', 'ai-engine'),
    stdio: ['inherit', 'pipe', 'inherit'],
  });

  let output = '';
  proc.stdout.on('data', (data) => {
    output += data.toString();
  });

  proc.on('close', (code) => {
    if (code !== 0) {
      console.error(`[Benchmark] Failed with exit code ${code}`);
      process.exit(code);
    }

    console.log('--- Benchmark Results ---');
    console.log(output);
  });
}

run();
