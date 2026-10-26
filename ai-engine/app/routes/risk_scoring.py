"""
Risk Scoring API Route
Cyber-Forensic Auditing Framework
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.models.fraud_detector import FraudDetector, TransactionFeatures
from app.config import settings

router = APIRouter()
detector = FraudDetector(model_path=settings.LOCAL_MODEL_PATH)


class TransactionPayload(BaseModel):
    amount: float = Field(..., gt=0, description="Transaction amount in ETH/wei-unit")
    sender_daily_volume: float = Field(default=0.0, ge=0, description="24h cumulative volume for sender")
    sender_daily_count: int = Field(default=1, ge=0, description="Count of transactions sent today")
    is_after_hours: bool = Field(default=False, description="Whether transaction occurred outside 8am-5pm")
    large_threshold: float = Field(default=10000.0, gt=0, description="Active policy large transaction ceiling")
    daily_volume_limit: float = Field(default=50000.0, gt=0, description="Active policy daily volume limit")
    max_daily_transactions: int = Field(default=20, gt=0, description="Maximum daily transactions allowed")
    is_kyc_verified: bool = Field(default=False, description="Sender KYC verification status")
    rapid_burst_count: int = Field(default=0, ge=0, description="Transactions sent within past 10 minutes")
    sender_address: Optional[str] = Field(default=None, description="Sender Ethereum address")
    receiver_address: Optional[str] = Field(default=None, description="Receiver Ethereum address")


class BatchScoreRequest(BaseModel):
    transactions: List[TransactionPayload]


@router.post("/score", summary="Score a single financial transaction")
async def score_transaction(payload: TransactionPayload):
    """
    Evaluates financial fraud risk, AML structuring likelihood,
    and velocity bursts for a single transaction.
    """
    try:
        features = TransactionFeatures(
            amount=payload.amount,
            sender_daily_volume=payload.sender_daily_volume,
            sender_daily_count=payload.sender_daily_count,
            is_after_hours=payload.is_after_hours,
            large_threshold=payload.large_threshold,
            daily_volume_limit=payload.daily_volume_limit,
            max_daily_transactions=payload.max_daily_transactions,
            is_kyc_verified=payload.is_kyc_verified,
            rapid_burst_count=payload.rapid_burst_count
        )
        result = detector.calculate_risk(features)
        result["sender_address"] = payload.sender_address
        result["receiver_address"] = payload.receiver_address
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Risk scoring error: {str(e)}")


@router.post("/batch", summary="Batch score multiple transactions")
async def batch_score(payload: BatchScoreRequest):
    """
    Processes a list of financial transactions and returns sorted risk evaluations.
    """
    try:
        results = []
        for tx in payload.transactions:
            feat = TransactionFeatures(
                amount=tx.amount,
                sender_daily_volume=tx.sender_daily_volume,
                sender_daily_count=tx.sender_daily_count,
                is_after_hours=tx.is_after_hours,
                large_threshold=tx.large_threshold,
                daily_volume_limit=tx.daily_volume_limit,
                max_daily_transactions=tx.max_daily_transactions,
                is_kyc_verified=tx.is_kyc_verified,
                rapid_burst_count=tx.rapid_burst_count
            )
            res = detector.calculate_risk(feat)
            res["sender_address"] = tx.sender_address
            res["receiver_address"] = tx.receiver_address
            results.append(res)

        # Sort highest risk first
        results.sort(key=lambda x: x["fraud_score"], reverse=True)

        return {
            "total_evaluated": len(results),
            "high_risk_count": sum(1 for r in results if r["risk_level"] in ("HIGH", "CRITICAL")),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch scoring error: {str(e)}")
