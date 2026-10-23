# Dataset Card: Iraqi Banking AML & Insider Fraud Benchmark (IQD-AML-2026)

## 1. Dataset Summary

* **Dataset Name:** IQD-AML-2026 Financial Auditing & Insider Fraud Benchmark
* **Curator:** Cyber-Forensic Auditing Framework Research Initiative
* **Domain:** Commercial Banking, Anti-Money Laundering (AML), Combating the Financing of Terrorism (CFT), and Insider Threat Forensics in the Republic of Iraq
* **Languages:** English, Arabic (field metadata and error taxonomies)
* **Release Date:** 2026-10-23
* **Format:** CSV, JSON Lines, Parquet
* **Currency:** Iraqi Dinar (IQD), Minor Unit Scale 3 (1 IQD = 1,000 fils)

---

## 2. Intended Use

* **Primary Use Case:** Benchmarking machine learning models and static compliance rules for detecting smurfing, structured evasion, and insider threat fraud in RTGS and core banking networks.
* **Secondary Use Case:** Evaluating row-level Row-Level Security (RLS) isolation and parent-hash chain of custody integrity in forensic investigation platforms.
* **Out-of-Scope Uses:** Credit scoring, automated loan approval, or identifying real individuals.

---

## 3. Data Structure & Field Dictionary

| Column Name | Type | Description | Unit / Scale |
|---|---|---|---|
| `external_id` | String | Unique transaction reference identifier | e.g. `TX-IQD-2026-0001` |
| `occurred_at` | Timestamp | ISO-8601 UTC timestamp with mandatory offset | e.g. `2026-10-23T08:15:30Z` |
| `sender_ref` | String | Anonymized account / IBAN reference of sender | e.g. `ACC-BAGHDAD-101` |
| `receiver_ref` | String | Anonymized account / IBAN reference of receiver | e.g. `ACC-BASRA-202` |
| `currency` | String | ISO 4217 currency code | `IQD`, `USD`, `ETH` |
| `scale` | Integer | Decimal scale exponent | `3` for IQD, `2` for USD, `18` for ETH |
| `amount_minor` | Integer | Transaction amount in minor units | Non-negative integer (e.g. `15000000000`) |
| `is_fraud` | Integer | Ground truth label (0 = Benign, 1 = Evasion/Fraud) | Binary flag |
| `fraud_category` | String | Specific typology classification | `STRUCTURING`, `INSIDER_OVERRIDE`, `NONE` |

---

## 4. Synthesis Methodology & Anonymization

1. **Synthetic Generation:** No proprietary banking databases were extracted. Data is synthesized using stochastic Poisson-arrival processes calibrated against Central Bank of Iraq (CBI) published reporting statistics.
2. **PII Elimination:** Account references utilize standardized pseudorandom hashes and city prefixes (`BAGHDAD`, `BASRA`, `ERBIL`, `NAJAF`, `MOSUL`).
3. **Reproducibility:** Generator scripts (`scripts/generate_dataset.js`) utilize fixed seeds (`42`, `43`, `44`).
