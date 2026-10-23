# Empirical Research Protocol & Experimental Design

**Project:** Iraq AML & Cyber-Forensic Auditing Framework (Track A Academic Evaluation)  
**Version:** 1.0.0  
**Author:** Research & Audit Systems Group  
**Target Milestone:** Gate G3 (Academic & Empirical Evaluation)  

---

## 1. Research Objectives & Hypotheses

The primary research objective is to empirically evaluate whether combining cryptographic multi-signature blockchain auditing with policy-aware server-side machine learning reduces insider fraud latency and financial evasion without introducing unacceptable performance overhead or false positives in Iraqi banking transactions.

### Formal Hypotheses

* **Hypothesis H1 (Governance Evasion Mitigation):**
  $$\mathcal{H}_{1}: \text{A dual-control MultiSig mechanism with dynamic generation tracking reduces replay and insider self-clearance attempts to 0, compared to single-key administrative overrides.}$$
  * *Independent Variable:* Governance Protocol (Single-key vs. MultiSig Four-Eyes with generation tracking).
  * *Dependent Variable:* Replay exploit success rate, self-clearance rate, unauthorized privilege persistence.

* **Hypothesis H2 (Detection Quality & False Positive Control):**
  $$\mathcal{H}_{2}: \text{A hybrid ML model (IsolationForest + GradientBoosting) trained on temporal and customer features achieves a higher PR-AUC and lower False Positive Rate than static rules alone on structured AML evasion.}$$
  * *Baseline:* Static Central Bank of Iraq (CBI) regulatory threshold rules (10,000,000 IQD threshold, 5 daily count, 50,000,000 IQD daily volume).
  * *Metrics:* Precision, Recall, F1-Score, Area Under Precision-Recall Curve (PR-AUC), and False Positive rate per 1,000 transactions.
  * *Acceptance Criterion:* Model is deployed if and only if:
    $$\text{Recall}_{\text{hybrid}} \ge \text{Recall}_{\text{baseline}} \quad \land \quad \text{FPR}_{\text{hybrid}} < \text{FPR}_{\text{baseline}}$$
    If $\mathcal{H}_{2}$ is rejected, static rules remain active and the negative result is published as an academic empirical finding.

* **Hypothesis H3 (Cryptographic WORM Scalability):**
  $$\mathcal{H}_{3}: \text{Off-chain SHA-256 chunked storage anchored via parent-hash chaining into EVM logs bounds transaction latency to } p95 \le 500\text{ms for indexing and queries while maintaining 100\% tamper detection.}$$
  * *Metrics:* Latency p50, p95, p99; storage bytes per incident; on-chain gas expenditure.

---

## 2. Experimental Data Strategy & Leakage Prevention

### 2.1 Dataset Partitioning & Stratification

1. **Subject Isolation:**
   * Customer and employee accounts (`sender_ref`, `receiver_ref`, `operator_address`) in the training set **must never appear** in the validation or test sets.
   * Split ratio: 70% Training, 15% Validation, 15% Test.
2. **Temporal Ordering:**
   * Time-based split boundary: Training data covers earlier chronological window ($t < T_{\text{split}}$); Test data covers future transactions ($t \ge T_{\text{split}}$).
   * Prevents future information leakage into historical model weights.
3. **Deterministic Seeds:**
   * Experiments are seeded with seeds `42`, `43`, and `44`.
   * Splits must yield identical SHA-256 manifest hashes across environments.

### 2.2 Ground Truth & Anomaly Definitions

* Fraud labels are defined using simulated ground truth categories:
  * `STRUCTURING_SMURFING`: Rapid transactions clustered at 85%–99% of reporting threshold.
  * `AFTER_HOURS_BURST`: Multiple high-velocity overrides during non-business hours (UTC 17:00–08:00).
  * `REPEATED_BENEFICIARY_COLLUSION`: Repeated transfers to confederate accounts bypassing KYC limits.
  * `BENIGN`: Standard commercial and payroll transfers adhering to Iraqi banking conventions.

---

## 3. Evaluation Framework & Tooling

Experiments are executed using standard scientific libraries:
* Python 3.11/3.14 with `scikit-learn`, `numpy`, `joblib`.
* Fixed random seeds and pinned dependencies in `requirements.txt`.
* Zero execution of unverified external pickles; all models checked against SHA-256 hashes registered in `research/protocol.json`.

---

## 4. Limitations & Academic Disclosure

1. **Synthetic Data Boundaries:** While transaction distributions emulate Central Bank of Iraq (CBI) payment flows in Iraqi Dinar (IQD scale 3), cash-based informal economies (hawala) cannot be directly verified through digital bank ledgers alone.
2. **Adversarial Adaptation:** Fraudsters may adapt timing intervals once static rules are known; continuous model recalibration and audit logging are required.
3. **Ethical Compliance:** All test identifiers and account numbers are synthetic fixtures (`ACC-BAGHDAD-101`, `TX-IQD-2026-XXXX`); no real customer PII is utilized.
