#!/usr/bin/env python
"""SCA severity gate for pip-audit JSON output (H03 dependency-scan gate).

Policy: the CI job may FAIL only on CRITICAL-severity findings.
pip-audit itself exits non-zero for ANY vulnerability and emits no severity
metadata, so this filter classifies each finding via OSV.dev:

  1. GHSA qualitative rating   -> OSV record ``database_specific.severity``
     (CRITICAL / HIGH / MODERATE / LOW; from GitHub's advisory database).
  2. CVSS v3.1 base score      -> computed from any ``CVSS_V3`` vector on the
     record (>= 9.0 CRITICAL, 7.0-8.9 HIGH, 4.0-6.9 MEDIUM, < 4.0 LOW).
  3. UNKNOWN                   -> no qualitative rating and no CVSS v3 vector
     obtainable for the finding or any of its aliases.

Classification order: any record saying CRITICAL wins; otherwise the highest
qualitative GHSA rating; otherwise the CVSS v3.1 computation; else UNKNOWN.
The pip-audit finding id and all its aliases are queried (GHSA ids first)
because PYSEC records carry no severity of their own.

Fail-open on OSV network errors (finding reported as UNKNOWN, not a gate
failure) so an advisory-service outage cannot break a green build. Input
problems are fail-closed: a missing/corrupt pip-audit report means the gate
cannot attest anything and exits 2.

Exit codes:
  0  pass — no CRITICAL findings (all findings still printed)
  1  FAIL — at least one CRITICAL-severity finding
  2  input error — pip-audit JSON missing or unparseable

Stdlib only. Runs on CPython >= 3.9 (CI: 3.11).
"""

import json
import math
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

OSV_API = "https://api.osv.dev/v1/vulns/"
OSV_TIMEOUT_S = 20
OSV_ATTEMPTS = 2

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}


def fetch_osv(vuln_id):
    """Return the OSV record dict for vuln_id.

    Returns (record, note): (dict, "") on success, or (None, reason) where the
    reason distinguishes a 404 (advisory simply absent from OSV) from a
    network/service failure.
    """
    url = OSV_API + quote(vuln_id, safe="")
    last_error = "unreachable"
    for attempt in range(OSV_ATTEMPTS):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_S) as resp:
                if resp.status != 200:
                    last_error = "HTTP %d" % resp.status
                    continue
                return json.loads(resp.read().decode("utf-8")), ""
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None, "no OSV record"
            last_error = "HTTP %d" % exc.code
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = str(exc) or type(exc).__name__
    return None, last_error


# --- CVSS v3.1 base score (FIRST CVSS v3.1 specification, section 8.2) ---

_CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value):
    """CVSS v3.1 roundup: smallest number with one decimal >= value."""
    return math.ceil(round(value * 10, 6)) / 10.0


def cvss_v3_1_base_score(vector):
    """Compute the base score of a CVSS:3.x vector string, or None if invalid."""
    if not vector.startswith("CVSS:3."):
        return None
    parts = vector.split("/")
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            return None
        key, val = part.split(":", 1)
        metrics[key] = val
    try:
        scope = metrics["S"]
        av = _CVSS_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS_WEIGHTS["AC"][metrics["AC"]]
        pr = _CVSS_WEIGHTS["PR"][scope][metrics["PR"]]
        ui = _CVSS_WEIGHTS["UI"][metrics["UI"]]
        conf = _CVSS_WEIGHTS["CIA"][metrics["C"]]
        integ = _CVSS_WEIGHTS["CIA"][metrics["I"]]
        avail = _CVSS_WEIGHTS["CIA"][metrics["A"]]
    except KeyError:
        return None

    iss_base = min(1.0 - (1.0 - conf) * (1.0 - integ) * (1.0 - avail), 0.915)
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        isc = 6.42 * iss_base
        return _roundup(min(isc + exploitability, 10.0))
    isc = 7.52 * (iss_base - 0.029) - 3.25 * (iss_base - 0.02) ** 15
    return _roundup(min(1.02 * (isc + exploitability), 10.0))


def score_to_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def classify_vuln(vuln_id, aliases):
    """Classify one advisory via OSV; returns (severity, note)."""
    ids_to_try = [vuln_id] + [a for a in aliases if a != vuln_id]
    # GHSA records carry the curated qualitative rating; try them first.
    ids_to_try.sort(key=lambda i: (not i.startswith("GHSA-"), i))

    best_qualitative = None
    best_vector_sev = None
    service_failed = False
    for candidate in ids_to_try:
        record, note = fetch_osv(candidate)
        if record is None:
            if note not in ("no OSV record",):
                service_failed = True
            continue
        db_sev = (record.get("database_specific") or {}).get("severity")
        if db_sev and db_sev.upper() in SEVERITY_ORDER:
            order = SEVERITY_ORDER[db_sev.upper()]
            if best_qualitative is None or order > SEVERITY_ORDER[best_qualitative]:
                best_qualitative = db_sev.upper()
        for sev in record.get("severity") or []:
            if str(sev.get("type", "")).startswith("CVSS_V3"):
                score = cvss_v3_1_base_score(str(sev.get("score", "")))
                mapped = score_to_severity(score)
                if mapped:
                    if best_vector_sev is None or SEVERITY_ORDER[mapped] > SEVERITY_ORDER[best_vector_sev]:
                        best_vector_sev = mapped

    if best_qualitative == "CRITICAL":
        return "CRITICAL", "GHSA qualitative rating"
    if best_qualitative:
        return best_qualitative, "GHSA qualitative rating"
    if best_vector_sev:
        return best_vector_sev, "CVSS v3.1 base score"
    if service_failed:
        return "UNKNOWN", "OSV.dev unreachable (fail-open)"
    return "UNKNOWN", "no severity data in OSV records"


def main(argv):
    if len(argv) != 2:
        print("usage: sca-pip-severity-filter.py <pip-audit-json-output>", file=sys.stderr)
        return 2
    path = argv[1]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        print("SCA GATE ERROR: cannot read pip-audit JSON report at %s: %s" % (path, exc))
        return 2

    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list):
        print("SCA GATE ERROR: pip-audit JSON has no 'dependencies' list — unrecognized format.")
        return 2

    # Dedupe: pip-audit can repeat the same advisory (e.g. per distribution).
    findings = {}
    scanned = 0
    for dep in dependencies:
        scanned += 1
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns") or []:
            vuln_id = vuln.get("id", "?")
            if vuln_id not in findings:
                findings[vuln_id] = {
                    "package": "%s@%s" % (name, version),
                    "aliases": list(vuln.get("aliases") or []),
                    "fix_versions": list(vuln.get("fix_versions") or []),
                }

    print("pip-audit report: %d dependencies audited, %d unique advisories" % (scanned, len(findings)))

    if not findings:
        print("SCA GATE: PASS — no known vulnerabilities in the resolved Python environment.")
        return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        classifications = list(
            pool.map(lambda f: classify_vuln(f[0], f[1]["aliases"]), findings.items())
        )

    criticals = []
    for (vuln_id, info), (severity, note) in zip(findings.items(), classifications):
        fixes = ", ".join(info["fix_versions"]) or "no fix available"
        line = "  [%s] %s — %s (%s; fix: %s)" % (severity, vuln_id, info["package"], note, fixes)
        print(line)
        if severity == "CRITICAL":
            criticals.append((vuln_id, info))
            print("::error title=SCA critical vulnerability::%s — %s — fix versions: %s"
                  % (vuln_id, info["package"], fixes))
        elif severity == "HIGH":
            print("::warning title=SCA high severity (reported, not gating)::%s — %s" % (vuln_id, info["package"]))

    summary = {}
    for severity, _ in classifications:
        summary[severity] = summary.get(severity, 0) + 1
    print("SCA severity summary: " + ", ".join(
        "%s=%d" % (sev, summary[sev]) for sev in sorted(summary, key=lambda s: -SEVERITY_ORDER.get(s, 0))
    ))

    if criticals:
        print("SCA GATE: FAIL — %d CRITICAL-severity vulnerability(ies) require triage:" % len(criticals))
        for vuln_id, info in criticals:
            print("  - %s (%s)" % (vuln_id, info["package"]))
        return 1

    unknowns = summary.get("UNKNOWN", 0)
    print("SCA GATE: PASS — no CRITICAL findings (non-critical findings reported above"
          + ("; %d UNKNOWN-severity advisory(ies) failed open due to missing OSV data" % unknowns if unknowns else "")
          + ").")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
