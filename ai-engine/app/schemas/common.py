"""
Common V2 Schemas
Specification §7 (R06)
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict, Field


class APIErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error explanation")
    request_id: Optional[str] = Field(default=None, description="Correlation identifier")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Detailed diagnostic context")


class LiveHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: str = Field(default="live", description="Liveness state")
    service: str = Field(default="ai-engine", description="Service identifier")
    timestamp: str = Field(..., description="ISO UTC timestamp")


class ReadyHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    status: str = Field(..., description="Readiness state ('ready' | 'degraded')")
    live: bool = Field(default=True, description="Liveness flag")
    ready: bool = Field(..., description="Subsystem readiness flag")
    checks: Dict[str, bool] = Field(..., description="Individual subsystem health status")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata and version indicators")
