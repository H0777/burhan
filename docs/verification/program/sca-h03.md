# H03 — SCA Dependency-Security Gate: Closure Record

> **Scope note.** This document closes only the **automatable SCA-gate portion** of H03
> (API pentest + SCA gate). The external API pentest portion is procurement-gated and is
> **not** covered here. Date of record: **2026-10-29**. Local environment: Windows 11,
> Node 24.19.0 / npm 11.17.0, Python 3.14.7 (Hermes toolchain, via `scripts/run-python.js`),
> pip-audit 2.10.1.

---

## 1. What was added

A new CI job `sca-dependency-scan` in [.github/workflows/verify.yml](../../../.github/workflows/verify.yml)
("SCA Dependency Vulnerability Gate (fail on Critical)"), running in parallel with the
existing gates on every push/PR to `main`. It scans three production dependency surfaces:

| Surface | Tool | Command | Fail condition |
|---|---|---|---|
| Root Node (prod: `@openzeppelin/contracts`, `dotenv`) | npm audit | `npm audit --omit=dev --audit-level=critical` | ≥1 CRITICAL |
| Frontend Node (prod: react, ethers, oidc-client-ts, …) | npm audit | `npm audit --omit=dev --audit-level=critical` (in `./frontend`) | ≥1 CRITICAL |
| Python (`ai-engine/requirements.txt`) | pip-audit 2.10.1 | `pip-audit -r ai-engine/requirements.txt --strict --format json` + `scripts/sca-pip-severity-filter.py` | ≥1 CRITICAL |

Commits: `558900b` (filter script), `21d1bf5` (workflow job), this doc.

## 2. Fail policy (exact)

**The job FAILS only on CRITICAL-severity findings. High/Moderate/Low findings are
printed to the job log but do not fail CI.**

- **npm**: `--audit-level=critical` makes npm exit non-zero only when findings at
  `critical` severity exist; the full findings table (all severities) is printed in the
  job log either way. Verified locally: with 2 moderate findings present the command
  still exits 0 while printing them.
- **pip-audit**: exits non-zero for ANY vulnerability (it has no severity filter and its
  JSON output carries no severity metadata), so the raw exit code cannot implement the
  policy. The step therefore captures the exit code, then runs
  [scripts/sca-pip-severity-filter.py](../../../scripts/sca-pip-severity-filter.py),
  which classifies every unique advisory and exits 1 **only** for CRITICAL findings.
  Exit codes: `0` pass, `1` critical(s) found, `2` report missing/corrupt (gate cannot
  attest — treated as a CI health failure, not a vulnerability).

### pip-audit severity classification (honest parsing)

pip-audit emits no severity data, so the filter resolves each advisory (its id plus all
aliases, GHSA ids first) via the **OSV.dev API** (`GET https://api.osv.dev/v1/vulns/{id}`):

1. **GHSA qualitative rating** — `database_specific.severity` (curated by GitHub Advisory DB).
2. **CVSS v3.1 base score** — computed from any `CVSS_V3` vector on the record
   (≥9.0 CRITICAL, 7.0–8.9 HIGH, 4.0–6.9 MEDIUM, <4.0 LOW). Implementation verified
   against published advisory scores: `AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N` → 5.8
   (GitHub: moderate), `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` → 7.4 (GitHub: high),
   `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8.
3. **UNKNOWN** — neither obtainable for the finding or any alias. Reported, not gating.

Classification order: any record rating CRITICAL wins; otherwise the highest qualitative
GHSA rating; otherwise the CVSS computation. Nothing is ignored/suppressed — every
advisory found is printed with its resolved severity and fix versions (`::error`/
`::warning` annotations are emitted for CRITICAL/HIGH respectively).

**Known fail-open modes** (accepted to keep the build green unless a real vulnerability
exists, and logged prominently when they trigger):
- OSV.dev unreachable → affected advisories classified UNKNOWN, gate does not fail.
- pip-audit tool/resolution error (`--strict`) with no output file → the step fails with
  exit 2 (fail-closed on the gate's ability to attest; this is an infrastructure error,
  not a policy failure and not expected to occur on a healthy runner).

## 3. Pinned behaviors

- **pip-audit pinned to 2.10.1** (the exact version validated locally) for a reproducible gate.
- **Full resolution**: `-r requirements.txt` resolves and audits the complete dependency
  closure (71 packages locally, including transitives), not just the 19 direct pins.
  requirements.txt uses `>=` ranges, so resolved versions — and therefore findings —
  drift with each run; the job audits what is resolvable **as of the run date**. This is
  recorded deliberately: it is the same audit an attacker or auditor would reproduce.
- **npm audits run straight off `package-lock.json`** — verified locally (npm 11.17) that
  `npm audit --omit=dev` works with no `node_modules` and no install, for both the root
  and the frontend lockfile. The job therefore needs no `npm ci` (faster CI); npm
  resolves the audit tree from the lockfile alone.
- CI toolchain: Node 24 (`setup-node`, npm cache over both lockfiles), Python 3.11
  (`setup-python`, pip cache keyed on `ai-engine/requirements.txt`).

## 4. Local discovery scan results (2026-10-29, pre-wiring)

Run before wiring the gate (discovery-first), so the fail-on-critical wiring could not
silently redden CI.

### 4.1 Root Node dependencies — `npm audit --omit=dev --json`

```json
"metadata": { "info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0 },
"dependencies": { "prod": 3, "dev": 647, "optional": 32, "peer": 411, "total": 649 }
```

**0 vulnerabilities at every severity.**

### 4.2 Frontend Node dependencies — `npm audit --omit=dev --json` (lockfile-only)

```json
"metadata": { "info": 0, "low": 0, "moderate": 2, "high": 0, "critical": 0, "total": 2 }
```

| Finding | Severity | Range | Advisory |
|---|---|---|---|
| `react-router` (via `react-router-dom` ^6.24) | moderate | 6.0.0 – 7.17.0 | GHSA-wrjc-x8rr-h8h6 (open redirect via backslash in `<Link>`/`useNavigate`, CVE-2025-68470 bypass); GHSA-337j-9hxr-rhxg (constructor injection via `deserializeErrors()` in SSR hydration) |

**0 critical, 0 high, 2 moderate.** The moderates do **not** trip the gate (verified:
`--audit-level=critical` exits 0 while printing them). Fix would require
`react-router-dom@7` (major bump) — **left to H03 triage**, not done here per scope.

### 4.3 Python dependencies — `pip-audit 2.10.1 -r ai-engine/requirements.txt --strict`

Full-resolution audit: **71 dependencies resolved** (19 direct + transitives; e.g.
fastapi 0.162.0, cryptography 50.0.2, sqlalchemy 2.1.6, psycopg 3.3.6, scikit-learn 1.9.1,
pandas 3.1.0, numpy 2.5.4). Result: **"No known vulnerabilities found"**, exit 0,
**0 advisories at every severity**. JSON artifact inspected: `"vulns"` empty across all
71 entries.

### 4.4 Criticals requiring triage

**None.** Zero CRITICAL findings across all three surfaces — the fail-on-critical gate
is wired directly with no suppressions, no `.npmrc` exclusions, and no `--ignore-vuln`
entries. The only outstanding (non-gating) findings are the two **moderate**
`react-router` advisories in §4.2, which are recorded for triage.

## 5. Gate validation performed

- **Workflow YAML**: parsed with js-yaml — all 7 pre-existing jobs intact, new job
  structurally correct (steps, `working-directory`, multi-line run blocks), `concurrency`
  and `verify-integration.needs` untouched.
- **Filter script** (`scripts/sca-pip-severity-filter.py`, stdlib-only, Python ≥3.9):
  tested against six fixture cases — empty report → exit 0; real requests==2.3.0 report
  (6 unique advisories) → all classified via GHSA ratings (5 MODERATE + 1 HIGH), exit 0;
  synthetic CRITICAL fixture (PYSEC-2019-16/GHSA-vfq6-hq5r-27r6, Django CVE-2019-19844)
  → exit 1 with `::error` annotation; unknown-severity advisory → exit 0 logged UNKNOWN;
  corrupt input → exit 2; missing input → exit 2. CVSS v3.1 calculator: 5 vectors
  verified + invalid-metric rejection.
- **npm audit from lockfile without node_modules**: verified for root and frontend
  lockfiles in isolated temp directories (no repo state touched).

## 6. Honest limitations

- The gate audits **production** surfaces only (`--omit=dev` / full pip resolution), per
  the H03 brief. Dev-surface vulnerabilities (build tooling, test runners) are out of scope.
- pip-audit resolution is date-dependent (unpinned `>=` ranges). Two runs may see
  different closures; the CI log records the resolved set via the filter's dependency
  count. A future hardening step (not in this scope) could pin a lockfile for the Python
  surface and audit that instead.
- GHSA ratings are the primary severity source; PYSEC-only advisories with no GHSA/CVE
  alias and no CVSS vector classify as UNKNOWN (reported, non-gating).
- OSV.dev queries are fail-open on service outage (§2), so a prolonged advisory-API
  outage could mask a critical that lands during the outage window. The pip-audit step's
  own log still lists every finding id when any exist.

## 7. H03 triage items handed over (not acted on here)

1. `react-router-dom` ^6.24 → 2 moderate advisories (GHSA-wrjc-x8rr-h8h6,
   GHSA-337j-9hxr-rhxg); fix = major upgrade to react-router-dom@7.18+ (breaking change).
2. Python surface has no lockfile; consider generating one for deterministic audits.
