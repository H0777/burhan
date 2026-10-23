"""
Policy Schemas (T06)
Specification §7, §8 (R07)
Strict Pydantic v2 schemas for AML/KYC policies and multi-currency precision.
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class PolicyThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    large_transaction: str = Field(..., description="Large tx reporting threshold in minor units")
    daily_volume_limit: str = Field(..., description="Daily volume limit in minor units")
    max_daily_transactions: int = Field(..., description="Max transactions allowed per day")
    max_single_transaction: str = Field(..., description="Hard single transaction cap in minor units")
    kyc_required_threshold: str = Field(..., description="KYC verification trigger in minor units")


class PolicyVersion(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    policy_id: str = Field(..., description="Unique policy identifier")
    version: str = Field(..., description="Semantic or profile version")
    asset: str = Field(..., description="Asset symbol (ETH, IQD)")
    currency: str = Field(..., description="Currency symbol")
    scale: int = Field(..., description="Decimal scale (18 for ETH wei, 3 for IQD fils)")
    thresholds: PolicyThresholds = Field(..., description="Active threshold configuration in minor units")
    effective_at: str = Field(..., description="Effective ISO UTC timestamp")
    source: str = Field(..., description="Source of policy authority (on_chain_audit_engine, regulatory_fixture)")
    institution_id: Optional[str] = Field(default=None, description="Institutional partition scope")
