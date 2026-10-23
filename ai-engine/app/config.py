"""
Configuration for the AI Engine.
Supports both local-only and API-enhanced modes with institutional runtime integration.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    # Institution and deployment configuration (Specification §7)
    INSTITUTION_ID: str = "INST-CENTRAL-DEMO"
    CHAIN_ID: int = 1337
    DEPLOYMENT_MANIFEST_PATH: str = str(
        Path(__file__).parent.parent.parent / "deployments" / "deployment-manifest.json"
    )

    # Gemini API (optional — system works without it)
    GEMINI_API_KEY: str = ""

    # Local ML model path
    LOCAL_MODEL_PATH: str = str(
        Path(__file__).parent.parent / "models" / "pretrained" / "fraud_model.pkl"
    )

    # Blockchain connection
    BLOCKCHAIN_RPC_URL: str = "http://127.0.0.1:8545"
    CONTRACT_ADDRESS: str = ""

    # CORS origins for frontend (including Compose port 3005)
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:3005",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3005",
    ]

    # Insider threat thresholds
    OVERRIDE_ALERT_THRESHOLD: int = 5
    AFTER_HOURS_ALERT_THRESHOLD: int = 3
    REPEATED_BENEFICIARY_THRESHOLD: int = 10

    # Business hours (UTC)
    BUSINESS_HOUR_START: int = 8
    BUSINESS_HOUR_END: int = 17

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
