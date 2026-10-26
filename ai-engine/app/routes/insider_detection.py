"""
Insider Threat Detection API Route
Cyber-Forensic Auditing Framework
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.models.insider_analyzer import InsiderThreatAnalyzer, OperatorActivityMetrics
from app.config import settings

router = APIRouter()
analyzer = InsiderThreatAnalyzer()


class OperatorMetricsPayload(BaseModel):
    operator_address: str = Field(..., description="Ethereum address of the authorized operator")
    total_actions: int = Field(default=1, ge=0, description="Total operations performed by operator")
    override_count: int = Field(default=0, ge=0, description="Number of compliance overrides performed")
    after_hours_count: int = Field(default=0, ge=0, description="Number of actions outside business hours")
    flag_count: int = Field(default=0, ge=0, description="Contract automated flag count")
    max_beneficiary_approvals: int = Field(default=0, ge=0, description="Max approvals granted to a single beneficiary")
    rapid_approval_count: int = Field(default=0, ge=0, description="Fast approvals in < 5 seconds")
    reversed_decisions_count: int = Field(default=0, ge=0, description="Decisions blocked then cleared")


@router.post("/analyze", summary="Analyze operator behavior for insider threats")
async def analyze_operator(payload: OperatorMetricsPayload):
    """
    Evaluates operator behavioral profile against known insider fraud patterns:
    - Privilege abuse (excessive warning bypass)
    - Conflict of interest (beneficiary concentration)
    - After-hours operations
    - Rubber-stamping decisions
    """
    try:
        metrics = OperatorActivityMetrics(
            operator_address=payload.operator_address,
            total_actions=payload.total_actions,
            override_count=payload.override_count,
            after_hours_count=payload.after_hours_count,
            flag_count=payload.flag_count,
            max_beneficiary_approvals=payload.max_beneficiary_approvals,
            rapid_approval_count=payload.rapid_approval_count,
            reversed_decisions_count=payload.reversed_decisions_count,
            override_threshold=settings.OVERRIDE_ALERT_THRESHOLD,
            after_hours_threshold=settings.AFTER_HOURS_ALERT_THRESHOLD,
            beneficiary_threshold=settings.REPEATED_BENEFICIARY_THRESHOLD,
        )
        return analyzer.analyze(metrics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Insider analysis error: {str(e)}")


@router.get("/thresholds", summary="Get active insider alert thresholds")
async def get_thresholds():
    """Returns current behavioral alert threshold parameters."""
    return {
        "override_alert_threshold": settings.OVERRIDE_ALERT_THRESHOLD,
        "after_hours_alert_threshold": settings.AFTER_HOURS_ALERT_THRESHOLD,
        "repeated_beneficiary_threshold": settings.REPEATED_BENEFICIARY_THRESHOLD,
        "business_hour_window": f"{settings.BUSINESS_HOUR_START:02d}:00 - {settings.BUSINESS_HOUR_END:02d}:00 UTC",
    }
