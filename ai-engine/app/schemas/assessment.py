"""
Authoritative Risk Scoring & Assessment Schemas (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (T18)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class FeatureSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount_minor: int = Field(..., description="Transaction amount in minor units")
    currency: str = Field(..., description="Currency code (IQD, ETH, USD)")
    scale: int = Field(..., description="Currency decimal scale")
    sender_daily_volume_minor: int = Field(..., description="Cumulative 24h volume for sender prior to transaction")
    sender_daily_count: int = Field(..., description="Cumulative 24h transaction count for sender")
    sender_window_burst_10m: int = Field(..., description="Transaction count by sender in 10-minute window")
    is_after_hours: bool = Field(..., description="Whether transaction occurred outside official banking business hours")
    structuring_ratio: float = Field(..., description="Ratio of amount to reporting threshold")
    large_threshold_minor: int = Field(..., description="Policy large threshold in minor units")
    daily_volume_limit_minor: int = Field(..., description="Policy daily volume ceiling in minor units")
    max_daily_transactions: int = Field(..., description="Policy maximum daily transaction count ceiling")


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transaction_id: str = Field(..., description="Authoritative transaction ID or external reference")
    as_of: Optional[datetime] = Field(default=None, description="Optional historical point-in-time timestamp")


class AssessmentResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    transaction_id: str
    institution_id: str
    as_of: datetime
    policy_id: str
    policy_version: str
    fraud_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str = Field(..., description="Risk category: LOW, MEDIUM, HIGH, CRITICAL")
    structuring_detected: bool
    rules_triggered: List[str]
    feature_snapshot: Dict[str, Any]
    features_hash: str
    engine_version: str
    model_loaded: bool
    source: str
    created_at: datetime


class AssessmentListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: List[AssessmentResponse]
    total: int
