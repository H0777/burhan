"""
Local Fraud Detector Model
Cyber-Forensic Auditing Framework

Provides offline, zero-cost machine learning fraud detection using an ensemble of
statistical heuristics and Isolation Forest anomaly scoring.
"""

import os
import math
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from app.models.registry import load_validated_model, ModelStatus


@dataclass
class TransactionFeatures:
    amount: float
    sender_daily_volume: float
    sender_daily_count: int
    is_after_hours: bool
    large_threshold: float = 10000.0
    daily_volume_limit: float = 50000.0
    max_daily_transactions: int = 20
    is_kyc_verified: bool = False
    sender_history_days: int = 30
    rapid_burst_count: int = 0  # Transactions within 10 minutes


class FraudDetector:
    """
    Hybrid Fraud Detection Engine.
    Combines Isolation Forest statistical anomalies with domain-specific AML heuristic rules.
    Operates 100% offline with zero dependencies on external APIs.
    """

    def __init__(self, model_path: Optional[str] = None, expected_hash: Optional[str] = None):
        self.model_path = model_path
        self.expected_hash = expected_hash
        self.ml_model = None
        self.model_status: Optional[ModelStatus] = None
        self._load_or_init_model()

    def _load_or_init_model(self):
        """Attempt to load pretrained scikit-learn model with cryptographic verification."""
        if self.model_path:
            status = load_validated_model(self.model_path, expected_hash=self.expected_hash)
            self.model_status = status
            if status.loaded:
                self.ml_model = status.model
            else:
                self.ml_model = None

    def calculate_risk(self, features: TransactionFeatures) -> Dict[str, Any]:
        """
        Evaluate a transaction and return an in-depth risk dossier.
        """
        risk_score = 0.0
        risk_factors: List[Dict[str, Any]] = []

        # 1. Structuring / Smurfing Detection (Transactions just under reporting threshold)
        if features.large_threshold > 0:
            threshold_ratio = features.amount / features.large_threshold
            if 0.85 <= threshold_ratio < 1.0:
                score_impact = 25.0 + 15.0 * ((threshold_ratio - 0.85) / 0.15)
                risk_score += score_impact
                risk_factors.append({
                    "factor": "STRUCTURING_SUSPICION",
                    "severity": "HIGH",
                    "impact": round(score_impact, 1),
                    "description": (
                        f"Transaction amount ({features.amount:,.2f}) is {threshold_ratio * 100:.1f}% "
                        f"of the reporting limit ({features.large_threshold:,.2f}), indicative of structuring (smurfing)."
                    )
                })

        # 2. Large Amount Threshold Violation
        if features.amount >= features.large_threshold:
            excess_ratio = min(features.amount / features.large_threshold, 3.0)
            score_impact = min(25.0 * excess_ratio, 45.0)
            risk_score += score_impact
            risk_factors.append({
                "factor": "LARGE_VALUE_TRANSFER",
                "severity": "HIGH" if excess_ratio > 1.5 else "MEDIUM",
                "impact": round(score_impact, 1),
                "description": f"Transaction amount exceeds single reporting ceiling of {features.large_threshold:,.2f} ETH."
            })

        # 3. High Value without KYC Verification
        kyc_trigger = features.large_threshold * 0.5
        if features.amount >= kyc_trigger and not features.is_kyc_verified:
            score_impact = 30.0
            risk_score += score_impact
            risk_factors.append({
                "factor": "UNVERIFIED_HIGH_VALUE",
                "severity": "CRITICAL",
                "impact": score_impact,
                "description": "High-value transfer initiated from an address with unverified KYC status."
            })

        # 4. Daily Volume Limit Saturation
        if features.daily_volume_limit > 0:
            vol_ratio = (features.sender_daily_volume + features.amount) / features.daily_volume_limit
            if vol_ratio >= 1.0:
                score_impact = 30.0
                risk_score += score_impact
                risk_factors.append({
                    "factor": "DAILY_VOLUME_EXCEEDED",
                    "severity": "HIGH",
                    "impact": score_impact,
                    "description": f"Cumulative 24-hour volume reaches {vol_ratio * 100:.1f}% of allowable limit."
                })
            elif vol_ratio >= 0.80:
                score_impact = 15.0
                risk_score += score_impact
                risk_factors.append({
                    "factor": "DAILY_VOLUME_WARNING",
                    "severity": "MEDIUM",
                    "impact": score_impact,
                    "description": f"Daily volume approaching threshold ({vol_ratio * 100:.1f}%)."
                })

        # 5. High-Frequency Velocity / Smurfing Burst
        if features.sender_daily_count >= features.max_daily_transactions:
            score_impact = 25.0
            risk_score += score_impact
            risk_factors.append({
                "factor": "HIGH_FREQUENCY_BURST",
                "severity": "HIGH",
                "impact": score_impact,
                "description": f"Daily transaction count ({features.sender_daily_count}) exceeds ceiling."
            })
        elif features.rapid_burst_count >= 3:
            score_impact = 20.0
            risk_score += score_impact
            risk_factors.append({
                "factor": "RAPID_FIRE_BURST",
                "severity": "MEDIUM",
                "impact": score_impact,
                "description": f"Detected {features.rapid_burst_count} sequential transactions in < 10 minute window."
            })

        # 6. Temporal Anomaly: After-Hours Operation
        if features.is_after_hours:
            score_impact = 15.0
            risk_score += score_impact
            risk_factors.append({
                "factor": "AFTER_HOURS_ACTIVITY",
                "severity": "LOW",
                "impact": score_impact,
                "description": "Activity occurred outside standard business hours (8:00 AM - 5:00 PM)."
            })

        # Incorporate ML anomaly score if scikit-learn model is loaded
        if self.ml_model is not None:
            try:
                import numpy as np
                feature_vector = np.array([[
                    features.amount,
                    features.sender_daily_volume,
                    features.sender_daily_count,
                    1 if features.is_after_hours else 0,
                    features.amount / max(features.large_threshold, 1.0)
                ]])
                # Isolation Forest returns -1 for anomaly, 1 for normal
                ml_pred = self.ml_model.predict(feature_vector)[0]
                if ml_pred == -1:
                    risk_score += 20.0
                    risk_factors.append({
                        "factor": "ML_ISOLATION_ANOMALY",
                        "severity": "HIGH",
                        "impact": 20.0,
                        "description": "Statistical isolation forest model flagged vector as high-dimensional outlier."
                    })
            except Exception:
                pass

        # Normalize final score to 0 - 100
        final_score = min(max(round(risk_score, 1), 0.0), 100.0)

        # Categorize risk level
        if final_score >= 75.0:
            risk_level = "CRITICAL"
            recommendation = "BLOCK_AND_ESCALATE"
        elif final_score >= 50.0:
            risk_level = "HIGH"
            recommendation = "REQUIRE_MULTISIG_OVERRIDE"
        elif final_score >= 25.0:
            risk_level = "MEDIUM"
            recommendation = "ENHANCED_DUE_DILIGENCE"
        else:
            risk_level = "LOW"
            recommendation = "AUTO_CLEAR"

        return {
            "fraud_score": final_score,
            "risk_level": risk_level,
            "recommendation": recommendation,
            "risk_factors": risk_factors,
            "evaluation_engine": "Hybrid Isolation & Rule-Matrix v2.0"
        }
