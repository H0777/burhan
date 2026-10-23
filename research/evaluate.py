"""
Empirical Evaluation Module
Cyber-Forensic Auditing Framework - Specification §6 & §8 (T19, R12, R13)

Computes standardized academic and regulatory metrics:
- Precision, Recall, F1
- PR-AUC (Precision-Recall Area Under Curve)
- False Positive Rate per 1,000 benign transfers (FPR/1000)
- p95 decision latency
"""

from typing import List, Dict, Any, Tuple
import math


def compute_metrics(
    y_true: List[int],
    y_pred: List[int],
    y_scores: List[float],
    latencies_ms: List[float] = None
) -> Dict[str, float]:
    """
    Computes confusion matrix, PR-AUC, FPR-per-1000, and latency metrics.
    Works independently of scikit-learn for deterministic verification.
    """
    if len(y_true) != len(y_pred) or len(y_true) != len(y_scores):
        raise ValueError("y_true, y_pred, and y_scores must have identical length")

    n = len(y_true)
    if n == 0:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "pr_auc": 0.0,
            "fpr_per_1000": 0.0,
            "latency_p95_ms": 0.0,
        }

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # FPR per 1,000 benign records
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fpr_per_1000 = round(fpr * 1000.0, 3)

    # Compute PR-AUC using trapezoidal approximation on threshold sweeps
    pr_auc = compute_pr_auc(y_true, y_scores)

    # Latency p95
    p95_latency = 0.0
    if latencies_ms and len(latencies_ms) > 0:
        sorted_lat = sorted(latencies_ms)
        idx = int(math.ceil(0.95 * len(sorted_lat))) - 1
        p95_latency = round(sorted_lat[max(0, idx)], 2)

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "pr_auc": round(pr_auc, 4),
        "fpr_per_1000": fpr_per_1000,
        "latency_p95_ms": p95_latency,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total_eval": n,
    }


def compute_pr_auc(y_true: List[int], y_scores: List[float]) -> float:
    """
    Computes Precision-Recall Area Under Curve via discrete trapezoidal integration.
    """
    if sum(y_true) == 0:
        return 0.0

    # Pair scores with labels and sort descending by score
    paired = sorted(zip(y_scores, y_true), key=lambda x: x[0], reverse=True)

    total_positives = sum(y_true)
    accum_tp = 0
    accum_fp = 0

    points: List[Tuple[float, float]] = [(0.0, 1.0)]  # (Recall, Precision) at threshold infinity

    for score, label in paired:
        if label == 1:
            accum_tp += 1
        else:
            accum_fp += 1

        rec = accum_tp / total_positives
        prec = accum_tp / (accum_tp + accum_fp)
        points.append((rec, prec))

    points.append((1.0, accum_tp / (accum_tp + accum_fp)))

    # Trapezoidal integration
    auc = 0.0
    for i in range(1, len(points)):
        r0, p0 = points[i - 1]
        r1, p1 = points[i]
        delta_r = r1 - r0
        if delta_r > 0:
            avg_p = (p0 + p1) / 2.0
            auc += delta_r * avg_p

    return min(1.0, max(0.0, auc))
