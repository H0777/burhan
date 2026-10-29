"""
PostgreSQL RLS regression test for the transactions read-model route (H04).

DISCOVERED ON STAGING (H04, E2E trust-flow test 1.5): POST /api/v2/imports/
transactions wrote the batch under tenant_transaction (RLS-correct), but
GET /api/v2/transactions executed its read-model queries WITHOUT the
transaction-local tenant context. On SQLite the WHERE institution_id filter
answered, so the E2E was green; on real PostgreSQL the app role is subject to
FORCE ROW LEVEL SECURITY and the list returned 0 rows. PostgreSQL behavior is
the reference (brief H04): the route now applies apply_tenant_context.

Same environment contract as test_postgres_rls.py (R11):
  - DATABASE_URL            -> least-privilege APP role (ira_aml_app).
  - MIGRATION_DATABASE_URL  -> separate migration OWNER role (ira_aml_migrator).
Without them the module SKIPS. The HTTP chain is the production one: real
identity resolution, real tenant_transaction, real RLS — nothing overridden.
"""

import os
import subprocess
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, text
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.models import Institution, ImportBatchRecord, Membership, TransactionRecord
from app.db.session import set_engine, tenant_transaction
from app.routes.v2.identity import set_oidc_verifier
from app.routes.v2.transactions import router as transactions_router
from app.routes.v2.transactions import imports_router
from app.security.oidc import MockJWKSProvider, OIDCVerifier

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT = "inst_tx_read"
TENANT_OTHER = "inst_tx_other"
OPERATOR_SUB = "sub_tx_operator"
OTHER_SUB = "sub_tx_other_op"

ISSUER = "https://auth.institutional-cbi.iq/oauth2"
AUDIENCE = "iraq-aml-audit-engine"

CSV_FIXTURE = REPO_ROOT / "shared" / "fixtures" / "banking-iqd-demo.csv"


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "H04 transactions read-model RLS tests require DATABASE_URL (app role) "
            f"and MIGRATION_DATABASE_URL (migration owner) pointing at a disposable "
            "PostgreSQL test database"
        )
    return app_url, migration_url


@pytest.fixture(scope="module")
def pg_urls():
    return _require_pg_urls()


@pytest.fixture(scope="module")
def app_engine(pg_urls):
    engine = create_engine(pg_urls[0], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def owner_engine(pg_urls):
    engine = create_engine(pg_urls[1], pool_pre_ping=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def migrated_db(pg_urls):
    result = subprocess.run(
        ["node", str(REPO_ROOT / "scripts" / "run-python.js"), "-m", "alembic", "upgrade", "head"],
        cwd=str(AI_ENGINE_DIR),
        env={**os.environ, "MIGRATION_DATABASE_URL": pg_urls[1]},
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")
    return pg_urls[1]


@pytest.fixture(scope="module")
def seeded(migrated_db, owner_engine):
    """Seed the two tenants + memberships; clear the read tenant's ledger so
    every run starts clean (the test database persists across suite runs)."""
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        for inst_id, name in ((TENANT, "H04 Read-Model RLS Tenant"), (TENANT_OTHER, "H04 Second Tenant")):
            if session.get(Institution, inst_id) is None:
                session.add(Institution(id=inst_id, name=name))
        session.commit()
        for inst_id, sub, role in (
            (TENANT, OPERATOR_SUB, "OPERATOR"),
            (TENANT_OTHER, OTHER_SUB, "OPERATOR"),
        ):
            with tenant_transaction(session, inst_id):
                exists = session.execute(
                    text("SELECT 1 FROM memberships WHERE institution_id = :i AND sub = :s"),
                    {"i": inst_id, "s": sub},
                ).first()
                if not exists:
                    session.add(Membership(
                        id=f"mem_{uuid.uuid4().hex[:16]}",
                        institution_id=inst_id, sub=sub, role=role, is_active=True,
                    ))
        with tenant_transaction(session, TENANT):
            session.execute(delete(TransactionRecord).where(TransactionRecord.institution_id == TENANT))
            session.execute(delete(ImportBatchRecord).where(ImportBatchRecord.institution_id == TENANT))
    yield


@pytest.fixture(scope="module")
def rsa_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_private, pem_public


@pytest.fixture(scope="module")
def jwks_provider(rsa_keypair):
    pem_private, pem_public = rsa_keypair
    return MockJWKSProvider(
        issuer=ISSUER, audience=AUDIENCE,
        private_key_pem=pem_private, public_key_pem=pem_public,
        key_id="h04-tx-read-key",
    )


@pytest.fixture(scope="module")
def api(app_engine, jwks_provider, seeded):
    """TestClient over the REAL transactions v2 routers on the real PostgreSQL
    app role. No overrides of connector, identity or tenant handling."""
    saved_settings = {"APP_MODE": settings.APP_MODE, "OIDC_ENABLED": settings.OIDC_ENABLED}
    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = True
    set_engine(app_engine)
    set_oidc_verifier(OIDCVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_provider=jwks_provider))

    app = FastAPI()
    app.include_router(transactions_router, prefix="/api/v2/transactions")
    app.include_router(imports_router, prefix="/api/v2/imports")
    with TestClient(app) as test_client:
        yield test_client

    set_oidc_verifier(None)
    set_engine(None)
    for key, value in saved_settings.items():
        setattr(settings, key, value)


def _auth(jwks_provider, sub, institution):
    token = jwks_provider.create_signed_token(
        {"sub": sub, "institution_id": institution, "role": "OPERATOR", "permissions": []}
    )
    return {"Authorization": f"Bearer {token}"}


def test_import_then_list_reads_own_rows_under_force_rls(api, jwks_provider):
    """THE regression: import a CSV batch, then list the read model. Before the
    H04 fix the list ran context-less and returned 0 rows on PostgreSQL while
    SQLite answered — observed live as E2E trust-flow test 1.5 failure."""
    csv_bytes = CSV_FIXTURE.read_bytes()

    upload = api.post(
        "/api/v2/imports/transactions",
        files={"file": ("banking-iqd-demo.csv", csv_bytes, "text/csv")},
        headers=_auth(jwks_provider, OPERATOR_SUB, TENANT),
    )
    assert upload.status_code == 201, upload.text
    imported = upload.json()
    assert imported["accepted_rows"] >= 10, imported

    listing = api.get(
        "/api/v2/transactions?limit=100",
        headers=_auth(jwks_provider, OPERATOR_SUB, TENANT),
    )
    assert listing.status_code == 200, listing.text
    body = listing.json()
    # Before the fix: 0 items under FORCE RLS despite a successful import.
    assert body["total"] >= 10, f"read model empty after import: {body}"
    sample = next((tx for tx in body["items"] if tx["external_id"] == "TX-IQD-2026-0001"), None)
    assert sample is not None, "imported transaction missing from read model"
    assert sample["currency"] == "IQD"


def test_other_tenant_cannot_read_imported_rows(api, jwks_provider):
    """Isolation: a second institution's operator reads none of the first
    tenant's imported rows (RLS USING on the read path)."""
    listing = api.get(
        "/api/v2/transactions?limit=100",
        headers=_auth(jwks_provider, OTHER_SUB, TENANT_OTHER),
    )
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 0, f"foreign tenant read {body['total']} rows"
    assert body["items"] == []
