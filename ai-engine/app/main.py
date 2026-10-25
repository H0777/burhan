"""
AI Engine - FastAPI Application
Cyber-Forensic Auditing Framework
Integrating Digital Forensics and Financial Accounting

Main entry point for the AI-driven fraud detection and forensic reporting engine.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.routes import risk_scoring, insider_detection, contract_scanner, forensic_report
from app.routes.v2 import evidence as evidence_v2
from app.routes.v2 import cases as cases_v2
from app.routes.v2 import policies as policies_v2
from app.routes.v2 import health as health_v2
from app.routes.v2 import identity as identity_v2
from app.routes.v2 import transactions as transactions_v2
from app.routes.v2 import risk as risk_v2
from app.routes.v2 import reports as reports_v2
from app.routes.v2 import scanner as scanner_v2
from app.routes.v3 import evidence as evidence_v3
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    print("[AI-Engine] AI Engine starting...")
    print(f"   Mode: {'API + Local' if settings.GEMINI_API_KEY else 'Local Only'}")
    print(f"   Model: {settings.LOCAL_MODEL_PATH}")
    # R10 identity startup gate: APP_MODE must be explicit, and institutional
    # mode requires a fully configured OIDC provider + on-chain RoleManager.
    from app.config import validate_startup_config
    validate_startup_config()
    from app.db.session import init_db
    try:
        init_db()
        print("[AI-Engine] Database schema initialized.")
    except Exception as e:
        print(f"[AI-Engine] Database initialization note: {e}")
    yield
    print("[AI-Engine] AI Engine shutting down...")


app = FastAPI(
    title="Cyber-Forensic AI Engine",
    description=(
        "AI-driven fraud detection and forensic reporting engine. "
        "Supports local ML inference (zero-cost, offline) and optional "
        "Gemini API integration for advanced contract analysis and report generation."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount route modules
app.include_router(risk_scoring.router, prefix="/api/v1/risk", tags=["Risk Scoring"])
app.include_router(insider_detection.router, prefix="/api/v1/insider", tags=["Insider Detection"])
app.include_router(contract_scanner.router, prefix="/api/v1/contract", tags=["Contract Scanner"])
app.include_router(forensic_report.router, prefix="/api/v1/forensic", tags=["Forensic Reports"])
app.include_router(evidence_v2.router, prefix="/api/v2/evidence", tags=["Evidence V2"])
app.include_router(cases_v2.router, prefix="/api/v2/cases", tags=["Cases V2"])
app.include_router(policies_v2.router, prefix="/api/v2/policies", tags=["Policies V2"])
app.include_router(health_v2.router, prefix="/api/v2/health", tags=["Health V2"])
app.include_router(identity_v2.router, prefix="/api/v2", tags=["Identity & Wallet V2"])
app.include_router(transactions_v2.router, prefix="/api/v2/transactions", tags=["Transactions V2"])
app.include_router(transactions_v2.imports_router, prefix="/api/v2/imports", tags=["Imports V2"])
app.include_router(risk_v2.router, prefix="/api/v2/risk", tags=["Risk V2"])
app.include_router(reports_v2.router, prefix="/api/v2", tags=["Reports V2"])
app.include_router(scanner_v2.router, prefix="/api/v2/scanner", tags=["Scanner V2"])
# R07 (spec §5): V3 verification — identifiers only, pinned chain snapshots
app.include_router(evidence_v3.router, prefix="/api/v3/evidence", tags=["Evidence V3"])


@app.get("/api/v1/health", tags=["System"])
async def health_check():
    """Check system health and capabilities."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "capabilities": {
            "local_ml": True,
            "gemini_api": bool(settings.GEMINI_API_KEY),
            "contract_scanning": bool(settings.GEMINI_API_KEY),
            "forensic_reports": True,
        },
        "active_model": settings.LOCAL_MODEL_PATH,
    }
