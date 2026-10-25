# Empirical Evaluation Results (Gate G3) — R18 fail-able activation gate

**Protocol:** `research/protocol.json` (single configuration source) | **Runner config:** `research/experiment-config.json` (thin shim -> `protocol.json`)
**Latest run:** `EXP-AML-42-1792909092` | **Date:** 2026-10-25 06:18:12 UTC | **Seed:** 42 | **Records:** 10,000 (synthetic)
**Config hash:** `0x1f88314ae089032d9b131fc186b424375890458f7a0f468c67ecbf54b5a26762`
**Dataset hash (synthetic):** `0xda30ae6e6b0341566ece6ea9678140a6491a7364747eeff10185fd47f25321c7`
**Split manifest hash:** `0x880a88ceaf262f3dbef52552177e29291efb6649ae38f4bdd4cf40ffe68e447e`

## Decision (AS PRODUCED by the R18 gate — computed, never asserted)

| Field | Value |
|---|---|
| research_status | **INSUFFICIENT_DATA** |
| activation_allowed | **false** |
| `--check-gate` exit code | **2** (insufficient data/environment) |

**Generated claim (from the run manifest `gate_decision`, never a constant string):**

> RESEARCH GATES NOT EVALUATED — INSUFFICIENT_DATA: strict temporal/participant-disjoint
> partitioning left no admissible evaluation splits: validation split has 0 records
> (< minimum 100); validation split lacks a required class (present labels: []).
> The acceptance gates were NOT evaluated and NO model is approved for activation; the
> rules-only baseline remains operative. This negative result is recorded as produced —
> neither a pass nor a model-failure verdict.

**Why exit 2 and not exit 1:** under the honest R17 partition policy the pinned synthetic
corpus yields **no admissible holdout at all** (train participants' later records are
dropped: 7,855 `TRAIN_PARTICIPANT_FUTURE_RECORD`; 1,810 senders cross the validation/test
boundary and enter neither evaluation set; validation split = 0 records). The acceptance
gates were therefore never evaluated — there are no recorded metrics to fail — so the
honest state is INSUFFICIENT_DATA (exit 2). Exit 1 is reserved for FAILED runs with
recorded metrics; the gate arithmetic for that path is pinned by
`research/tests/test_evaluation_gate.py::test_observed_metrics_fail_activation`.

## Partition of the pinned dataset (strict temporal + participant-disjoint, R17 policy)

| Split | Records |
|---|---|
| train (occurred_at <= 2026-01-02T00:00:00Z) | 215 |
| validation (disjoint actors fully inside the window) | **0** |
| test (actors first seen after 2026-01-04T00:00:00Z) | 120 |
| dropped: `TRAIN_PARTICIPANT_FUTURE_RECORD` | 7,855 |
| dropped: `PARTICIPANT_CROSSES_VALIDATION_TEST_BOUNDARY` | 1,810 |

The synthetic generator assigns the 150 senders uniformly across the whole timeline, so
every early sender is a train participant and no participant is eligible for the
validation window. This IS the honest finding — the corpus cannot support the claimed
holdout evaluation, and no random-split fallback exists.

## Historical table (pre-R17 RANDOM split — NOT admissible; recorded for traceability only)

The numbers below come from the pre-R17 random-split regime (leaky subject overlap) and
were promoted to a "SUPPORTED" claim before the strict policy existed. Under the R18 gate
they are **FAILED**, not SUPPORTED: recall 0.7698 is below the 0.85 floor, and the hybrid
FPR of 1.57/1000 (0.157%) is WORSE than the rules baseline FPR of 0.00/1000 (0.000%) — so
no false-positive-reduction claim is possible and ML activation would be denied even
before the recall floor. This exact outcome is pinned by the unit test
`test_observed_metrics_fail_activation`.

| Configuration | Precision | Recall | F1 | PR-AUC (AP) | FPR per 1,000 | p95 (ms) |
|---|---|---|---|---|---|---|
| Rules-Only Baseline | 1.0000 | 0.5396 | 0.7009 | 0.8184 | 0.00 (0.000%) | 0.00 |
| ML-Only (Isolation Forest) | 0.7822 | 0.5683 | 0.6583 | 0.7218 | 34.54 (3.454%) | 21.60 |
| Hybrid Ensemble (Rules + ML) | 0.9907 | 0.7698 | 0.8664 | 0.8188 | 1.57 (0.157%) | 21.60 |

*FPR units: per-1,000 ratio = fraction x 1000; 1.57/1000 == 0.157% (same quantity, two units).
The 77% vs 85% recall shortfall and the 0 -> 1.57/1000 FPR rise are the F13 baseline truths.*

## R18 gate mechanics (what changed)

- Outcome is computed by `evaluate_gate(metrics, baseline, policy)` from
  `acceptance_gates` in `research/protocol.json` — research statuses are
  **PASSED | FAILED | INSUFFICIENT_DATA**; the constant SUPPORTED verdict is retired.
- Protocol floors are hard minima (recall >= 0.85, FPR <= 50/1000, PR-AUC(AP) >= 0.80,
  p95 <= 25 ms); configs that loosen them are rejected (loud `ProtocolConfigError`).
- ML activation additionally requires recall >= baseline, FPR <= baseline, and a strict
  gain in at least one — never "no worse is enough".
- Metrics are computed with tie-grouped average precision (reported as `pr_auc` = AP,
  cross-checked against scikit-learn), honest zero-denominator semantics (a missing class
  refuses the gate instead of dividing silently), confusion matrices, sample sizes, and
  95% Wilson confidence intervals — on a SYNTHETIC corpus (intervals quantify sampling
  noise only, never real-world generalization).
- Every evaluated run is sealed (`evaluation_seal`: labels/predictions hashes, config
  hash, split hash, model hash, evaluation time). Threshold retuning after the seal
  requires a NEW run; `ModelRegistry.activate` binds the default-off engine only to a
  sealed PASSED manifest whose model hash matches the artifact the server loads.
- Default engine state: **rule_based**. No model is currently activated
  (`ModelRegistry.binding_status() == "UNBOUND"`), and `--check-gate` exits 2.

## Environment (recorded, never hardcoded)

Python 3.14.7 (CPython), NumPy 2.5.4, scikit-learn 1.9.1, joblib 1.6.0, Windows 11 (AMD64).

## Run artifacts

- `experiment-manifest.json` — fixed-path mirror of the latest run manifest
  (`EXP-AML-42-1792909092`), regenerated in R18 fix round 1 so no tracked
  artifact contradicts the updated experiment-manifest schema.
- `runs/EXP-AML-42-1792909092/` — R18 full-config run (10,000 records): INSUFFICIENT_DATA
  with `gate_decision` recorded; `--check-gate` exit 2.
- `runs/EXP-AML-42-1792875674/` — R17 short run (1,200 records): INSUFFICIENT_DATA
  (validation 3 / test 6 records).
