"""
Model Training & Synthetic Data Generator
Cyber-Forensic Auditing Framework

Generates realistic banking/AML transaction data and trains the offline
Isolation Forest fraud detection model.
"""

import os
import csv
import random
from pathlib import Path


def generate_synthetic_aml_data(output_csv_path: str, num_records: int = 1000):
    """
    Generates a realistic synthetic AML transaction dataset:
    - Normal banking activity (80%)
    - Structuring / Smurfing (8%)
    - After-hours operations (5%)
    - Velocity / burst transfers (4%)
    - Layering / volume ceiling saturation (3%)
    """
    os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)

    headers = [
        "tx_id",
        "amount",
        "sender_daily_volume",
        "sender_daily_count",
        "is_after_hours",
        "threshold_ratio",
        "is_fraud_label"
    ]

    records = []
    random.seed(42)

    for i in range(1, num_records + 1):
        rand_val = random.random()

        if rand_val < 0.80:
            # 1. Normal Transaction (80%)
            amount = round(random.uniform(10.0, 4500.0), 2)
            daily_vol = round(amount + random.uniform(0.0, 15000.0), 2)
            daily_cnt = random.randint(1, 8)
            after_hours = 1 if random.random() < 0.05 else 0
            label = 0

        elif rand_val < 0.88:
            # 2. Structuring / Smurfing (8%) — Just below 10,000 limit
            amount = round(random.uniform(8800.0, 9950.0), 2)
            daily_vol = round(amount + random.uniform(5000.0, 30000.0), 2)
            daily_cnt = random.randint(3, 12)
            after_hours = 1 if random.random() < 0.20 else 0
            label = 1

        elif rand_val < 0.93:
            # 3. After-Hours Anomalies (5%)
            amount = round(random.uniform(3000.0, 18000.0), 2)
            daily_vol = round(amount + random.uniform(10000.0, 40000.0), 2)
            daily_cnt = random.randint(2, 10)
            after_hours = 1
            label = 1

        elif rand_val < 0.97:
            # 4. Rapid Burst Transfers (4%)
            amount = round(random.uniform(1500.0, 7500.0), 2)
            daily_vol = round(amount * random.randint(15, 30), 2)
            daily_cnt = random.randint(21, 35)
            after_hours = random.choice([0, 1])
            label = 1

        else:
            # 5. Massive Volume / Layering (3%)
            amount = round(random.uniform(25000.0, 95000.0), 2)
            daily_vol = round(amount + random.uniform(30000.0, 80000.0), 2)
            daily_cnt = random.randint(1, 5)
            after_hours = random.choice([0, 1])
            label = 1

        threshold_ratio = round(amount / 10000.0, 4)
        records.append([
            i, amount, daily_vol, daily_cnt, after_hours, threshold_ratio, label
        ])

    with open(output_csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(records)

    print(f"Generated {num_records} synthetic transactions -> {output_csv_path}")
    return records


def train_isolation_forest(csv_path: str, output_model_path: str):
    """
    Trains an Isolation Forest anomaly detection model on synthetic AML data
    and persists it to joblib format along with cryptographic metadata.
    """
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)

    try:
        import numpy as np
        import pandas as pd
        import joblib
        from sklearn.ensemble import IsolationForest
        import hashlib
        import json
        from datetime import datetime, timezone

        df = pd.read_csv(csv_path)
        feature_cols = ["amount", "sender_daily_volume", "sender_daily_count", "is_after_hours", "threshold_ratio"]
        X = df[feature_cols].values

        model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        model.fit(X)

        joblib.dump(model, output_model_path)

        # Compute SHA-256 of saved artifact
        sha = hashlib.sha256()
        with open(output_model_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        model_hash = "0x" + sha.hexdigest().lower()

        # Write metadata companion file
        meta = {
            "model_hash": model_hash,
            "feature_schema": feature_cols,
            "training_dataset_hash": "",
            "library_versions": {
                "scikit_learn": "1.9.1",
                "numpy": np.__version__,
                "pandas": pd.__version__,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {"contamination": 0.15},
        }
        with open(output_model_path + ".meta.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        print(f"Model successfully trained and saved -> {output_model_path} (hash: {model_hash})")
        return True
    except ImportError as e:
        raise RuntimeError(f"Scikit-learn / pandas required for training: {e}")


if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    data_file = str(base_dir / "data" / "training_data.csv")
    model_file = str(base_dir / "models" / "pretrained" / "fraud_model.joblib")

    generate_synthetic_aml_data(data_file)
    train_isolation_forest(data_file, model_file)
