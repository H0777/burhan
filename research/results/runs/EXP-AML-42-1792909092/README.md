# Empirical Evaluation Run — INSUFFICIENT_DATA

**Protocol:** `research/protocol.json` (protocol_version 1.1.0) | **Run:** `EXP-AML-42-1792909092`
**Config hash:** `0x1f88314ae089032d9b131fc186b424375890458f7a0f468c67ecbf54b5a26762`
**Dataset hash (synthetic):** `0xda30ae6e6b0341566ece6ea9678140a6491a7364747eeff10185fd47f25321c7` (10000 records)

## Outcome: INSUFFICIENT_DATA

Strict temporal + participant-disjoint partitioning (R17 policy) did not leave viable evaluation splits, so the acceptance gates were NOT evaluated and the hybrid ensemble is NOT activated. The rules-only baseline remains the operative detector. No metrics are recorded for this run because no admissible holdout evaluation exists.

**Reason:** validation split has 0 records (< minimum 100); validation split lacks a required class (present labels: [])

## Split sizes (rejected split manifest)

| Split | Records |
|---|---|
| train | 215 |
| validation | 0 |
| test | 120 |

## Drop summary

| Drop reason | Count |
|---|---|
| TRAIN_PARTICIPANT_FUTURE_RECORD | 7855 |
| PARTICIPANT_CROSSES_VALIDATION_TEST_BOUNDARY | 1810 |

This negative result is recorded as produced: it is NOT a model failure verdict and NOT a pass. The synthetic generator assigns senders uniformly across the whole timeline, so under honest temporal/participant separation essentially every sender is a train participant and no participant is eligible for the evaluation windows.

**Environment:** Python 3.14.7, NumPy 2.5.4, scikit-learn 1.9.1, Windows 11
