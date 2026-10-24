# Empirical Evaluation Run — INSUFFICIENT_DATA

**Protocol:** `research/protocol.json` (protocol_version 1.1.0) | **Run:** `EXP-AML-42-1792875674`
**Config hash:** `0x132bfb1e723b7944524b4c9453758f4ca522e5fe1f427451ef4695596bba57ba`
**Dataset hash (synthetic):** `0x5dae6d2763793387c1e1b1d51f0921d72468e62c316140bf45d608da46975718` (1200 records)

## Outcome: INSUFFICIENT_DATA

Strict temporal + participant-disjoint partitioning (R17 policy) did not leave viable evaluation splits, so the acceptance gates were NOT evaluated and the hybrid ensemble is NOT activated. The rules-only baseline remains the operative detector. No metrics are recorded for this run because no admissible holdout evaluation exists.

**Reason:** validation split has 3 records (< minimum 100); validation split lacks a required class (present labels: [0]); test split has 6 records (< minimum 100)

## Split sizes (rejected split manifest)

| Split | Records |
|---|---|
| train | 215 |
| validation | 3 |
| test | 6 |

## Drop summary

| Drop reason | Count |
|---|---|
| TRAIN_PARTICIPANT_FUTURE_RECORD | 804 |
| PARTICIPANT_CROSSES_VALIDATION_TEST_BOUNDARY | 172 |

This negative result is recorded as produced: it is NOT a model failure verdict and NOT a pass. The synthetic generator assigns senders uniformly across the whole timeline, so under honest temporal/participant separation essentially every sender is a train participant and no participant is eligible for the evaluation windows.

**Environment:** Python 3.14.7, NumPy 2.5.4, scikit-learn 1.9.1, Windows 11
