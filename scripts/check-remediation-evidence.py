#!/usr/bin/env python3
"""Check remediation evidence register consistency (findings.csv).

Planned in R20 but never written; created 2026-10-29 (task H01, DG0).

Honest, minimal logic — no keyword scanning of READMEs (R20 rule):
  1. Parse docs/verification/remediation/findings.csv (10 columns).
  2. For every row with status == VERIFIED_FIXED:
       - build_id must be a non-empty hex-ish SHA (7-40 hex chars);
       - proof_path must be non-empty and exist on disk (relative to repo root).
  3. Exit 0 iff every VERIFIED_FIXED row is valid AND no row is OPEN.
     Any unknown status also fails. Exit 1 otherwise, with a printed table.

Rows still FIXED_PENDING_VALIDATION are reported but do not fail the gate —
their closure is exactly what the validation build must prove.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CSV = REPO_ROOT / "docs" / "verification" / "remediation" / "findings.csv"

KNOWN_STATUSES = {"OPEN", "FIXED_PENDING_VALIDATION", "VERIFIED_FIXED"}
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "csv_path",
        nargs="?",
        default=str(DEFAULT_CSV),
        help="path to findings.csv (default: %(default)s)",
    )
    args = parser.parse_args()
    csv_path = Path(args.csv_path)
    base_dir = csv_path.resolve().parent if csv_path.resolve() != DEFAULT_CSV.resolve() else REPO_ROOT

    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
    except OSError as exc:
        print(f"[remediation:check] cannot read {csv_path}: {exc}")
        return 1

    expected_header = [
        "id", "priority", "status", "evidence_type", "source_paths",
        "task_ids", "red_test", "green_test", "build_id", "proof_path",
    ]
    if not rows or list(rows[0].keys()) != expected_header:
        print("[remediation:check] unexpected CSV header — refusing to judge")
        return 1

    print(f"[remediation:check] {csv_path}")
    header = f"{'id':<5} {'status':<24} {'build_id':<10} {'proof_path':<45} verdict"
    print(header)
    print("-" * len(header))

    failures = []
    open_rows = []
    for row in rows:
        fid = row["id"]
        status = row["status"].strip()
        build_id = row["build_id"].strip()
        proof_path = row["proof_path"].strip()
        verdict = "ok"

        if status not in KNOWN_STATUSES:
            verdict = "FAIL unknown status"
            failures.append(fid)
        elif status == "OPEN":
            verdict = "FAIL still OPEN"
            open_rows.append(fid)
        elif status == "VERIFIED_FIXED":
            problems = []
            if not SHA_RE.match(build_id):
                problems.append("build_id not a hex SHA")
            if not proof_path:
                problems.append("proof_path empty")
            elif not (base_dir / proof_path).exists():
                problems.append("proof_path missing on disk")
            if problems:
                verdict = "FAIL " + "; ".join(problems)
                failures.append(fid)

        print(f"{fid:<5} {status:<24} {build_id or '-':<10} {proof_path or '-':<45} {verdict}")

    total = len(rows)
    verified = sum(1 for r in rows if r["status"].strip() == "VERIFIED_FIXED")
    pending = sum(1 for r in rows if r["status"].strip() == "FIXED_PENDING_VALIDATION")
    print("-" * len(header))
    print(f"rows={total} VERIFIED_FIXED={verified} FIXED_PENDING_VALIDATION={pending} "
          f"OPEN={len(open_rows)} invalid={len(failures)}")

    if failures:
        print("[remediation:check] FAIL — invalid VERIFIED_FIXED rows: "
              + ", ".join(failures))
        return 1
    if open_rows:
        print("[remediation:check] FAIL — OPEN rows remain: " + ", ".join(open_rows))
        return 1
    print("[remediation:check] PASS — register internally consistent "
          f"({verified} VERIFIED_FIXED, {pending} pending validation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
