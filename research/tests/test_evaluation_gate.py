"""R18 evaluation-gate tests (spec §9) — computed metrics and a fail-able
ML activation gate.

Pins:
- the gate arithmetic: recall floor 0.85 (inclusive), FPR ceiling 50/1000,
  PR-AUC(AP) floor 0.80, p95 latency ceiling 25 ms (all sourced from
  protocol.json ``acceptance_gates`` — never lowered to close the task);
- the additional ML-activation rule: recall >= baseline AND FPR <= baseline
  AND a strict gain in at least one of them. A baseline FPR of 0 forbids
  claiming "false-positive reduction" when FPR rose;
- honest research statuses PASSED / FAILED / INSUFFICIENT_DATA (a missing
  class refuses the gate instead of dividing silently);
- the claim text is GENERATED from the decision — never a constant
  SUPPORTED string;
- FPR display: 1.57 per 1,000 == 0.157%.

RED phase: every test resolves the R18 symbols through the ``impl`` seam and
fails with a clear "not implemented (R18 RED)" message until they land.
"""
import json

import pytest

from conftest import impl
from research import run_experiments


def _evaluate_gate():
    return impl(run_experiments, "evaluate_gate")


def _metrics_cls():
    return impl(run_experiments, "EvaluationMetrics")


def _policy_cls():
    return impl(run_experiments, "EvaluationPolicy")


def _format_fpr():
    return impl(run_experiments, "format_fpr")


# ---------------------------------------------------------------------------
# Fixtures (metric values are the recorded, rounded outputs of the metrics
# computation; the gate consumes the recorded values)
# ---------------------------------------------------------------------------

def make_metrics(**overrides):
    M = _metrics_cls()
    values = dict(
        precision=0.9907,
        recall=0.7698,
        f1_score=0.8664,
        pr_auc=0.8188,
        fpr_ratio=0.00157,
        latency_p95_ms=21.60,
        n_samples=2176,
        n_positives=265,
        n_negatives=1911,
    )
    values.update(overrides)
    return M(**values)


def passing_metrics(**overrides):
    """A candidate that clears every protocol gate with strict margin."""
    base = dict(precision=0.99, recall=0.90, f1_score=0.94, pr_auc=0.90,
                fpr_ratio=0.0, latency_p95_ms=2.0)
    base.update(overrides)
    return make_metrics(**base)


def baseline_metrics(**overrides):
    """Rules-only baseline truth (F13): honest recall, zero FPR."""
    base = dict(precision=1.0, recall=0.5396, f1_score=0.7009, pr_auc=0.8184,
                fpr_ratio=0.0, latency_p95_ms=0.0)
    base.update(overrides)
    return make_metrics(**base)


def default_policy():
    return _policy_cls()()


# ---------------------------------------------------------------------------
# The F13 observed outcome MUST fail the gate
# ---------------------------------------------------------------------------

def test_observed_metrics_fail_activation():
    """recall=0.7698 (< 0.85 floor), FPR=0.00157 with baseline_fpr=0:
    the research verdict is FAILED and ML activation is denied. The decision
    must NOT claim false-positive reduction against a zero-FPR baseline."""
    decision = _evaluate_gate()(
        make_metrics(), baseline_metrics(), default_policy())

    assert decision.research_status == "FAILED"
    assert decision.activation_allowed is False

    reasons = " | ".join(decision.reasons)
    assert "0.7698" in reasons and "0.85" in reasons, \
        "the recall-floor breach must be named with its value"
    assert "1.57" in reasons and "0.157%" in reasons, \
        "FPR must be displayed per 1,000 and as a percentage"
    assert any("worse" in r.lower() and "baseline" in r.lower()
               for r in decision.reasons), \
        "FPR 0.00157 vs baseline_fpr=0 must be named as a worsening"
    assert any("false-positive reduction" in r.lower() and "not" in r.lower()
               for r in decision.reasons), \
        "baseline FPR=0 forbids a false-positive-reduction claim"


def test_recall_085_same_fpr_with_recall_gain_passes():
    """Baseline recall lower, candidate recall exactly 0.85 with the same
    (zero) FPR and the remaining protocol limits met: research PASSED and
    activation ALLOWED (strict gain in recall). Boundaries are inclusive."""
    baseline = baseline_metrics()  # recall 0.5396, fpr 0.0
    candidate = passing_metrics(
        recall=0.85, fpr_ratio=0.0, pr_auc=0.80, latency_p95_ms=25.0)

    decision = _evaluate_gate()(candidate, baseline, default_policy())

    assert decision.research_status == "PASSED"
    assert decision.activation_allowed is True
    assert decision.reasons == []


def test_same_metrics_no_strict_gain_blocks_activation():
    """Candidate identical to the baseline: protocol gates pass, but with no
    strict improvement in recall or FPR the activation is blocked."""
    baseline = baseline_metrics(
        precision=0.99, recall=0.90, f1_score=0.94, pr_auc=0.90,
        latency_p95_ms=2.0)
    candidate = make_metrics(
        precision=0.99, recall=0.90, f1_score=0.94, pr_auc=0.90,
        fpr_ratio=0.0, latency_p95_ms=2.0)

    decision = _evaluate_gate()(candidate, baseline, default_policy())

    assert decision.research_status == "PASSED"
    assert decision.activation_allowed is False
    assert any("strict" in r.lower() for r in decision.reasons), \
        "the no-strict-gain reason must be stated"


def test_fpr_decrease_with_recall_drop_blocks_activation():
    """FPR improves but recall drops below the baseline: activation blocked
    (recall must not decrease), even though the research gates pass."""
    baseline = baseline_metrics(
        precision=0.99, recall=0.90, f1_score=0.94, pr_auc=0.90,
        fpr_ratio=0.002, latency_p95_ms=2.0)
    candidate = passing_metrics(recall=0.85, fpr_ratio=0.001)

    decision = _evaluate_gate()(candidate, baseline, default_policy())

    assert decision.research_status == "PASSED"
    assert decision.activation_allowed is False
    assert any("recall" in r.lower() and "baseline" in r.lower()
               for r in decision.reasons)


# ---------------------------------------------------------------------------
# Display and individual gate components
# ---------------------------------------------------------------------------

def test_fpr_display_per_1000_equals_percent():
    """FPR display: 1.57 per 1,000 == 0.157% (one quantity, two units)."""
    text = _format_fpr()(0.00157)
    assert "1.57/1000" in text
    assert "0.157%" in text

    # the ratio and the per-1000 display are the same quantity
    assert round(0.00157 * 1000, 2) == 1.57
    assert round(0.00157 * 100, 3) == 0.157

    m = make_metrics()
    assert m.fpr_per_1000 == pytest.approx(1.57, abs=1e-9)
    assert _format_fpr()(0.0) == "0.00/1000 (0.000%)"


def test_pr_auc_below_floor_fails_gate():
    """PR-AUC(AP) = 0.79 fails the 0.80 floor; activation denied."""
    decision = _evaluate_gate()(
        passing_metrics(pr_auc=0.79), baseline_metrics(), default_policy())

    assert decision.research_status == "FAILED"
    assert decision.activation_allowed is False
    assert any("pr-auc" in r.lower() or "pr_auc" in r.lower()
               for r in decision.reasons)
    assert any("0.79" in r for r in decision.reasons)


def test_latency_p95_above_ceiling_fails_gate():
    """p95 = 25.01 ms fails the 25 ms ceiling; activation denied."""
    decision = _evaluate_gate()(
        passing_metrics(latency_p95_ms=25.01), baseline_metrics(),
        default_policy())

    assert decision.research_status == "FAILED"
    assert decision.activation_allowed is False
    assert any("latency" in r.lower() for r in decision.reasons)
    assert any("25.01" in r for r in decision.reasons)


# ---------------------------------------------------------------------------
# Honest INSUFFICIENT_DATA: missing class refuses, never silent division
# ---------------------------------------------------------------------------

def test_missing_class_refuses_gate_without_silent_division():
    M = _metrics_cls()
    evaluate = _evaluate_gate()

    no_negatives = M(
        precision=1.0, recall=0.9, f1_score=0.94, pr_auc=0.0,
        fpr_ratio=None, latency_p95_ms=1.0,
        n_samples=100, n_positives=100, n_negatives=0)
    decision = evaluate(no_negatives, baseline_metrics(), default_policy())
    assert decision.research_status == "INSUFFICIENT_DATA"
    assert decision.activation_allowed is False
    joined = " | ".join(decision.reasons).lower()
    assert "missing" in joined or "absent" in joined
    assert "refus" in joined, "the refusal (no silent division) must be stated"

    # a class-missing baseline is equally insufficient (FPR baseline undefined)
    no_positive_baseline = baseline_metrics(
        recall=0.0, fpr_ratio=None, n_positives=0, n_negatives=50)
    d2 = evaluate(passing_metrics(), no_positive_baseline, default_policy())
    assert d2.research_status == "INSUFFICIENT_DATA"
    assert d2.activation_allowed is False


# ---------------------------------------------------------------------------
# Claim text is GENERATED from the decision
# ---------------------------------------------------------------------------

def test_claim_text_is_generated_from_decision_not_constant():
    evaluate = _evaluate_gate()
    failed = evaluate(make_metrics(), baseline_metrics(), default_policy())
    passed = evaluate(
        passing_metrics(recall=0.87), baseline_metrics(), default_policy())
    insufficient = evaluate(
        passing_metrics(n_negatives=0, fpr_ratio=None),
        baseline_metrics(), default_policy())

    claims = {failed.claim, passed.claim, insufficient.claim}
    assert len(claims) == 3, "the claim text varies with the decision"
    for claim in claims:
        assert "SUPPORTED" not in claim, \
            "the claim must never be the constant SUPPORTED string"

    assert "FAILED" in failed.claim
    assert "PASSED" in passed.claim
    assert "INSUFFICIENT_DATA" in insufficient.claim
    assert failed.activation_allowed is False
    assert passed.activation_allowed is True

    # the F13 claim must not assert a false false-positive reduction
    lowered = failed.claim.lower()
    assert "reduction" not in lowered or "not" in lowered


# ---------------------------------------------------------------------------
# Protocol floors are immutable
# ---------------------------------------------------------------------------

def test_policy_floors_cannot_be_lowered():
    P = _policy_cls()
    with pytest.raises(ValueError):
        P(min_recall=0.70)
    with pytest.raises(ValueError):
        P(max_fpr_per_1000=200.0)
    with pytest.raises(ValueError):
        P(min_pr_auc=0.5)
    with pytest.raises(ValueError):
        P(max_latency_p95_ms=100.0)

    p = P()
    assert p.min_recall == 0.85
    assert p.max_fpr_per_1000 == 50.0
    assert p.min_pr_auc == 0.80
    assert p.max_latency_p95_ms == 25.0


def test_from_protocol_rejects_lowered_floors():
    from_protocol = _policy_cls().from_protocol
    base = {
        "acceptance_gates": {
            "min_recall": 0.85, "max_fpr_per_1000": 50.0,
            "min_pr_auc": 0.80, "max_latency_p95_ms": 25.0},
    }

    ok = json.loads(json.dumps(base))
    policy = from_protocol(ok)
    assert policy.min_recall == 0.85

    lowered = json.loads(json.dumps(base))
    lowered["acceptance_gates"]["min_recall"] = 0.70
    with pytest.raises(ValueError):
        from_protocol(lowered)

    loosened = json.loads(json.dumps(base))
    loosened["acceptance_gates"]["max_fpr_per_1000"] = 500.0
    with pytest.raises(ValueError):
        from_protocol(loosened)
