"""
Configuration for the AI Engine.
Supports both local-only and API-enhanced modes with institutional runtime integration.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    INSTITUTION_ID: str = "INST-CENTRAL-DEMO"
    CHAIN_ID: int = 1337
    DEPLOYMENT_MANIFEST_PATH: str = str(
        Path(__file__).parent.parent.parent / "deployments" / "deployment-manifest.json"
    )

    # OIDC & Identity configuration (T13, R10)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER: str = "https://auth.institutional-cbi.iq/oauth2"
    OIDC_AUDIENCE: str = "iraq-aml-audit-engine"
    OIDC_JWKS_URL: str = ""
    WALLET_CHALLENGE_DOMAIN: str = "iraq-aml-audit.cbi.iq"
    WALLET_CHALLENGE_TTL_SECONDS: int = 300

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
