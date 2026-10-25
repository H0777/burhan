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

    # Application mode (R10): 'demo' or 'institutional' — explicit, never inferred.
    # Institutional mode requires OIDC (issuer/audience/JWKS) and the on-chain
    # RoleManager address, refuses demo identities and fallback keys/RPC.
    APP_MODE: str = "demo"

    # OIDC & Identity configuration (T13, R10)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER: str = "https://auth.institutional-cbi.iq/oauth2"
    OIDC_AUDIENCE: str = "iraq-aml-audit-engine"
    OIDC_JWKS_URL: str = ""
    OIDC_ALGORITHMS: list[str] = ["RS256"]
    OIDC_CLOCK_SKEW_SECONDS: int = 60
    ROLE_MANAGER_ADDRESS: str = ""
    WALLET_CHALLENGE_DOMAIN: str = "iraq-aml-audit.cbi.iq"
    WALLET_CHALLENGE_TTL_SECONDS: int = 300

    # Gemini API (optional — system works without it)
    GEMINI_API_KEY: str = ""

    # Local ML model configuration (T19)
    LOCAL_MODEL_PATH: str = str(
        Path(__file__).parent.parent / "models" / "pretrained" / "fraud_model.joblib"
    )
    FRAUD_MODEL_PATH: str = str(
        Path(__file__).parent.parent / "models" / "pretrained" / "fraud_model.joblib"
    )
    FRAUD_MODEL_EXPECTED_HASH: str = ""
    ENABLE_ML_INFERENCE: bool = True

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

    # Database & Multi-Tenant Persistence (T14)
    DATABASE_URL: str = "sqlite:///./cyber_audit_chain.db"
    DATABASE_ECHO: bool = False
    
    # Evidence Vault Object Storage (T14)
    EVIDENCE_STORE_PATH: str = str(
        Path(__file__).parent.parent / "data" / "evidence_vault"
    )
    MAX_EVIDENCE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()


def validate_startup_config() -> None:
    """
    Identity startup gate (R10): the application mode must be explicit, and
    institutional mode must be fully provisioned before the API can start.

    Institutional mode FAILS TO START when:
      - OIDC is disabled or its issuer/audience/JWKS endpoint are missing;
      - the on-chain RoleManager address is missing (authorization reads are
        mandatory: generation/role must be verified on-chain before sensitive
        writes, and a failed read answers 503 — never a browser claim).

    Demo mode is an isolated development mode: OIDC off, demo identity, no
    chain requirements.
    """
    mode = settings.APP_MODE.strip().lower()
    if mode not in ("demo", "institutional"):
        raise RuntimeError(
            f"APP_MODE must be 'demo' or 'institutional' (got {settings.APP_MODE!r})"
        )
    if mode == "institutional":
        missing = []
        if not settings.OIDC_ENABLED:
            raise RuntimeError(
                "Institutional mode requires OIDC_ENABLED=true: the demo identity "
                "path is never available in institutional deployments"
            )
        if not settings.OIDC_ISSUER:
            missing.append("OIDC_ISSUER")
        if not settings.OIDC_AUDIENCE:
            missing.append("OIDC_AUDIENCE")
        if not settings.OIDC_JWKS_URL:
            missing.append("OIDC_JWKS_URL")
        if not settings.ROLE_MANAGER_ADDRESS:
            missing.append("ROLE_MANAGER_ADDRESS")
        if missing:
            raise RuntimeError(
                "Institutional mode requires OIDC (issuer/audience/JWKS) and the "
                f"on-chain RoleManager address; missing: {', '.join(missing)}"
            )
