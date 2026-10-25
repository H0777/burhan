"""R18 metrics tests — honest zero-denominator semantics, tie-grouped
average precision, and 95% confidence intervals.

``compute_eval_metrics`` is the R18 metrics implementation used by the
runner (spec §9). Naming contract: the ``pr_auc`` field IS average
precision (AP) over the precision–recall curve, computed under that name
and never displayed under another metric's name. Zero denominators never
masquerade as success: a missing class is reported explicitly so the gate
can refuse instead of dividing silently.
"""
import random

import pytest

from conftest import impl
from research import run_experiments


def _compute():
    return impl(run_experiments, "compute_eval_metrics")


def _ap():
    return impl(run_experiments, "compute_average_precision")


def _wilson():
    return impl(run_experiments, "wilson_ci95")


# ---------------------------------------------------------------------------
# Known-answer arithmetic
# ---------------------------------------------------------------------------

def test_known_confusion_matrix():
    y_true = [1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
    y_pred = [1, 1, 0, 1, 0, 0, 0, 0, 0, 0]
    scores = [0.9, 0.8, 0.3, 0.7, 0.1, 0.2, 0.05, 0.15, 0.25, 0.35]

    m = _compute()(y_true, y_pred, scores)

    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 6)
    assert m["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["recall"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["f1_score"] == pytest.approx(2 / 3, abs=1e-4)
    assert m["fpr_ratio"] == pytest.approx(1 / 7, abs=1e-6)
    assert m["fpr_per_1000"] == pytest.approx(1000 / 7, abs=1e-2)  # ~142.857
    assert m["n_samples"] == 10
    assert m["n_positives"] == 3
    assert m["n_negatives"] == 7
    assert m["confusion"] == {"tp": 2, "fp": 1, "fn": 1, "tn": 6}


def test_metric_zero_denominator_not_zero_success():
    """A zero denominator never masquerades as a perfect score:
    precision with no positive predictions is 0.0 (not 1.0); recall with no
    actual positives is 0.0 (not 1.0); FPR with no benign records is NOT
    computable (None) — never a fake 0.0 that would read as success."""
    f = _compute()

    m = f([0, 0, 0, 0], [0, 0, 0, 0], [0.1, 0.2, 0.3, 0.4])
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    # FPR here has a valid denominator (4 benign records): 0/4 is a REAL
    # zero, honestly computable — the missing POSITIVE class is flagged so
    # the gate refuses the recall/PR-AUC division instead.
    assert m["fpr_ratio"] == 0.0
    assert m["fpr_per_1000"] == 0.0
    assert m["n_positives"] == 0 and m["has_positives"] is False
    assert m["n_negatives"] == 4 and m["has_negatives"] is True

    m2 = f([1, 1, 1, 1], [1, 1, 1, 1], [0.9, 0.8, 0.7, 0.6])
    assert m2["fpr_ratio"] is None, "no benign records: FPR undefined"
    assert m2["fpr_per_1000"] is None
    assert m2["has_negatives"] is False
    assert m2["recall"] == pytest.approx(1.0)      # defined: tp+fn > 0
    assert m2["precision"] == pytest.approx(1.0)   # defined: tp+fp > 0

    empty = f([], [], [])
    assert empty["n_samples"] == 0
    assert empty["fpr_ratio"] is None
    assert empty["has_positives"] is False and empty["has_negatives"] is False


# ---------------------------------------------------------------------------
# Average precision (PR-AUC/AP): tie grouping and naming
# ---------------------------------------------------------------------------

def test_ties_permutation_invariant():
    """Score ties are grouped into single threshold blocks, so the AP
    (pr_auc) is invariant under any permutation of the input order."""
    y_true = [1, 0, 1, 0, 1, 0, 0, 1]
    scores = [0.9, 0.9, 0.8, 0.8, 0.8, 0.5, 0.5, 0.3]
    y_pred = [1 if s >= 0.75 else 0 for s in scores]

    ap0 = _ap()(y_true, scores)
    m0 = _compute()(y_true, y_pred, scores)

    rng = random.Random(42)
    idx = list(range(len(y_true)))
    for _ in range(50):
        rng.shuffle(idx)
        yt = [y_true[i] for i in idx]
        ys = [scores[i] for i in idx]
        yp = [y_pred[i] for i in idx]
        assert _ap()(yt, ys) == pytest.approx(ap0, rel=1e-12, abs=0)
        assert _compute()(yt, yp, ys) == m0


def test_all_scores_equal():
    """All scores tied: the single threshold block yields AP == prevalence."""
    y_true = [1, 0, 1, 0, 0]
    ap = _ap()(y_true, [0.5] * 5)
    assert ap == pytest.approx(0.4, rel=1e-12)

    m = _compute()(y_true, [0] * 5, [0.5] * 5)
    assert m["pr_auc"] == pytest.approx(0.4, abs=1e-4)


def test_pr_auc_is_average_precision_by_name_and_matches_sklearn():
    """``pr_auc`` is average precision (AP): the pinned implementation is
    cross-checked against scikit-learn's average_precision_score, and the
    value is never presented under another metric's name."""
    from sklearn.metrics import average_precision_score

    cases = [
        ([1, 1, 0, 0], [0.9, 0.8, 0.7, 0.6]),
        ([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.6]),
        ([0, 1, 1, 0, 1], [0.2, 0.4, 0.4, 0.9, 0.4]),
        ([1, 0, 0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]),
        ([1, 0, 1, 1, 0, 0, 1], [0.12, 0.88, 0.55, 0.55, 0.31, 0.02, 0.55]),
    ]
    for y_true, scores in cases:
        expected = average_precision_score(y_true, scores)
        assert _ap()(y_true, scores) == pytest.approx(expected, rel=1e-12)

        m = _compute()(y_true, [1 if s >= 0.5 else 0 for s in scores], scores)
        assert m["pr_auc"] == pytest.approx(expected, abs=2e-4)


# ---------------------------------------------------------------------------
# Reporting artifacts: confusion matrix, 95% CIs, sample sizes
# ---------------------------------------------------------------------------

def test_confidence_intervals_and_sample_sizes_reported():
    y_true = [1] * 40 + [0] * 160
    y_pred = [1] * 30 + [0] * 10 + [1] * 20 + [0] * 140
    scores = [0.9] * 30 + [0.1] * 10 + [0.8] * 20 + [0.2] * 140
    latencies = [0.5 * i for i in range(200)]

    m = _compute()(y_true, y_pred, scores, latencies_ms=latencies)

    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (30, 20, 10, 140)
    assert m["n_samples"] == 200
    assert m["n_positives"] == 40
    assert m["n_negatives"] == 160

    ci = m["ci95"]
    for key, point in (("recall", 0.75), ("precision", 0.6),
                       ("fpr", 20 / 160)):
        lo, hi = ci[key]
        assert 0.0 <= lo <= point <= hi <= 1.0, \
            f"the 95% Wilson interval for {key} must bracket its estimate"

    # Wilson intervals shrink as the sample grows
    lo_small, hi_small = _wilson()(30, 40)
    lo_big, hi_big = _wilson()(300, 400)
    assert (hi_small - lo_small) > (hi_big - lo_big)
    assert _wilson()(0, 0) == [0.0, 1.0]
