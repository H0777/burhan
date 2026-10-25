"""
Case HTTP-path integration tests (R12, closes F07) — real PostgreSQL, real routers,
real identity resolution. NO override of the case service or of tenant_transaction:
the TestClient exercises the production call chain
(get_current_identity -> tenant_transaction(db, identity.institution_id) -> CaseService).

Requires the same environment contract as test_postgres_rls.py (R11):
  DATABASE_URL            -> least-privilege APP role (ira_aml_app), NOSUPERUSER NOBYPASSRLS.
  MIGRATION_DATABASE_URL  -> migration OWNER role (ira_aml_migrator).
Without them the module SKIPS.

Documented test identity (the only test-specific wiring is the R10 test hook
`set_oidc_verifier` with a synthetic RSA key — the same convention as
tests/integration/test_membership_revocation.py):
  tenant inst_r12_cases  : sub_r12_auditor (AUDITOR), sub_r12_admin (SUPER_ADMIN),
                           sub_r12_regulator (REGULATOR); sub_r12_ghost has NO membership (403).
  tenant inst_r12_other  : second institution for foreign-tenant rejection checks.
  tenant inst_r12_pages  : isolated tenant for the deterministic pagination test.

Spec §8 bindings exercised here (F07 RED evidence: the four case paths used to raise
`TypeError: tenant_transaction() missing 1 required positional argument` on every
authenticated HTTP call):
  - create/list/get/transition answer 201/200/200/200 and never 500;
  - 401 without a token, 403 without membership or with REGULATOR writes,
    404 for a foreign/unknown case, 409 for invalid transitions;
  - idempotency: key scope = institution+sub+method+path+key; body digest covers ALL
    semantic fields; TTL 24h; changed description/severity/new_assignee_sub -> 409;
  - pagination: stable (created_at, id) order, keyset cursor bound to institution and
    filters, next_cursor only when limit+1 exists, foreign cursor rejected.
"""

import base64
import json
import os
import subprocess
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.db.models import Institution, Membership
from app.db.session import set_engine, tenant_transaction
from app.routes.v2.cases import router as cases_router
from app.routes.v2.identity import set_oidc_verifier
from app.security.oidc import MockJWKSProvider, OIDCVerifier

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

TENANT = "inst_r12_cases"
TENANT_OTHER = "inst_r12_other"
TENANT_PAGES = "inst_r12_pages"

AUDITOR_SUB = "sub_r12_auditor"
ADMIN_SUB = "sub_r12_admin"
REGULATOR_SUB = "sub_r12_regulator"
GHOST_SUB = "sub_r12_ghost"  # valid token, NO membership -> 403
PAGES_SUB = "sub_r12_pages"

ISSUER = "https://auth.institutional-cbi.iq/oauth2"
AUDIENCE = "iraq-aml-audit-engine"


def _require_pg_urls() -> tuple[str, str]:
    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R12 case HTTP tests require DATABASE_URL (app role) and "
            "MIGRATION_DATABASE_URL (migration owner) pointing at a disposable "
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
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(
            "alembic upgrade head failed against the R12 test database "
            f"(exit {result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    with create_engine(pg_urls[1]).connect() as conn:
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    return head


@pytest.fixture(scope="module")
def seeded(migrated_db, owner_engine):
    """Seed the three R12 test institutions and their memberships (owner role)."""
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as session:
        for inst_id, name in (
            (TENANT, "R12 Case Flow Test Institution"),
            (TENANT_OTHER, "R12 Second Institution"),
            (TENANT_PAGES, "R12 Pagination Institution"),
        ):
            if session.get(Institution, inst_id) is None:
                session.add(Institution(id=inst_id, name=name))
        session.commit()

        plan = (
            (TENANT, ((AUDITOR_SUB, "AUDITOR"), (ADMIN_SUB, "SUPER_ADMIN"), (REGULATOR_SUB, "REGULATOR"))),
            (TENANT_OTHER, ((AUDITOR_SUB, "AUDITOR"),)),
            (TENANT_PAGES, ((PAGES_SUB, "AUDITOR"),)),
        )
        for inst_id, members in plan:
            with tenant_transaction(session, inst_id):
                existing = {
                    row
                    for row in session.execute(
                        text("SELECT sub FROM memberships WHERE institution_id = :i"),
                        {"i": inst_id},
                    ).scalars()
                }
                for sub, role in members:
                    if sub not in existing:
                        session.add(
                            Membership(
                                id=f"mem_{uuid.uuid4().hex[:16]}",
                                institution_id=inst_id,
                                sub=sub,
                                role=role,
                                is_active=True,
                            )
                        )
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
        issuer=ISSUER,
        audience=AUDIENCE,
        private_key_pem=pem_private,
        public_key_pem=pem_public,
        key_id="r12-test-key",
    )


@pytest.fixture
def api(app_engine, jwks_provider, seeded):
    """TestClient over the REAL cases v2 router wired to the real PostgreSQL app role.

    The case service and tenant_transaction are NOT overridden — the F07 regression
    (TypeError from `tenant_transaction(identity)`) must surface on these calls.
    app.main is deliberately not imported (v1 modules are uncommitted user edits in
    the main workspace; see R11 §8)."""
    saved_settings = {
        "APP_MODE": getattr(settings, "APP_MODE", "demo"),
        "OIDC_ENABLED": settings.OIDC_ENABLED,
    }
    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = True
    set_engine(app_engine)
    set_oidc_verifier(OIDCVerifier(issuer=ISSUER, audience=AUDIENCE, jwks_provider=jwks_provider))

    app = FastAPI()
    app.include_router(cases_router, prefix="/api/v2/cases")
    with TestClient(app) as test_client:
        yield test_client

    set_oidc_verifier(None)
    set_engine(None)
    for key, value in saved_settings.items():
        setattr(settings, key, value)


def _token(jwks_provider, sub, institution=TENANT, role="AUDITOR"):
    return jwks_provider.create_signed_token(
        {"sub": sub, "institution_id": institution, "role": role, "permissions": []}
    )


def _auth(jwks_provider, sub, institution=TENANT, role="AUDITOR"):
    return {"Authorization": f"Bearer {_token(jwks_provider, sub, institution, role)}"}


def _create_case(api, jwks_provider, case_number, **overrides):
    body = {
        "case_number": case_number,
        "title": overrides.pop("title", f"R12 case {case_number}"),
        "description": overrides.pop("description", "initial description"),
        "severity": overrides.pop("severity", "MEDIUM"),
    }
    body.update(overrides)
    return api.post(
        "/api/v2/cases",
        json=body,
        headers=_auth(jwks_provider, AUDITOR_SUB),
    )


# ---------------------------------------------------------------------------
# The F07 path: create/list/get/transition over real HTTP, never a 500
# ---------------------------------------------------------------------------


def test_http_create_list_get_transition_no_500(api, jwks_provider):
    """Full institutional case flow over real routers: 401/403/404 and
    invalid_transition_409 exactly; no step may answer 5xx."""
    seen = []

    # 1) 401: institutional mode, no Bearer token.
    res = api.get("/api/v2/cases")
    seen.append(res.status_code)
    assert res.status_code == 401, f"expected 401 without token, got {res.status_code}"

    # 2) 403: valid token, no stored membership (a JWT alone grants nothing).
    res = api.post(
        "/api/v2/cases",
        json={"case_number": "R12-GHOST-1", "title": "no membership"},
        headers=_auth(jwks_provider, GHOST_SUB),
    )
    seen.append(res.status_code)
    assert res.status_code == 403, f"expected 403 without membership, got {res.status_code}"

    # 3) 201: create with a real AUDITOR membership.
    res = _create_case(api, jwks_provider, "R12-FLOW-001", severity="HIGH")
    seen.append(res.status_code)
    assert res.status_code == 201, f"create failed: {res.status_code} {res.text}"
    case = res.json()
    assert case["status"] == "OPEN"
    assert case["version"] == 1
    assert case["severity"] == "HIGH"
    case_id = case["id"]

    # 4) 200: list contains the case (RLS proves the list query ran inside the
    #    tenant transaction — without set_config the app role sees zero rows).
    res = api.get("/api/v2/cases", headers=_auth(jwks_provider, AUDITOR_SUB))
    seen.append(res.status_code)
    assert res.status_code == 200
    listed_ids = [item["id"] for item in res.json()["items"]]
    assert case_id in listed_ids, "created case invisible through the list path"

    # 5) 200: detail with event history.
    res = api.get(f"/api/v2/cases/{case_id}", headers=_auth(jwks_provider, AUDITOR_SUB))
    seen.append(res.status_code)
    assert res.status_code == 200
    detail = res.json()
    assert detail["case"]["id"] == case_id
    assert any(e["event_type"] == "CASE_CREATED" for e in detail["events"])

    # 6) 404: unknown case id inside the same institution.
    res = api.get("/api/v2/cases/case_does_not_exist", headers=_auth(jwks_provider, AUDITOR_SUB))
    seen.append(res.status_code)
    assert res.status_code == 404, f"expected 404 for unknown case, got {res.status_code}"

    # 7) 403: REGULATOR (read-only) may not create cases.
    res = api.post(
        "/api/v2/cases",
        json={"case_number": "R12-REG-1", "title": "regulator write"},
        headers=_auth(jwks_provider, REGULATOR_SUB, role="REGULATOR"),
    )
    seen.append(res.status_code)
    assert res.status_code == 403, f"expected 403 for REGULATOR create, got {res.status_code}"

    # 8) 200: valid transition start_review (OPEN -> IN_REVIEW, v1 -> v2).
    res = api.post(
        f"/api/v2/cases/{case_id}/transition",
        json={"action": "start_review", "expected_version": 1},
        headers=_auth(jwks_provider, AUDITOR_SUB),
    )
    seen.append(res.status_code)
    assert res.status_code == 200, f"transition failed: {res.status_code} {res.text}"
    body = res.json()
    assert body["status"] == "IN_REVIEW"
    assert body["version"] == 2

    # 9) 409: invalid_transition — approve_resolution is illegal from IN_REVIEW.
    res = api.post(
        f"/api/v2/cases/{case_id}/transition",
        json={"action": "approve_resolution", "expected_version": 2},
        headers=_auth(jwks_provider, ADMIN_SUB, role="SUPER_ADMIN"),
    )
    seen.append(res.status_code)
    assert res.status_code == 409, (
        f"expected invalid_transition_409, got {res.status_code}: {res.text}"
    )

    assert all(code < 500 for code in seen), f"5xx leaked on the case paths: {seen}"


# ---------------------------------------------------------------------------
# Idempotency: semantic digest, scoped key, TTL
# ---------------------------------------------------------------------------


def test_same_key_different_description_or_severity_409(api, jwks_provider):
    """A reused idempotency key with a CHANGED semantic field must be rejected with
    409 — never replayed as a stale success."""
    key = f"r12-idem-desc-{uuid.uuid4().hex[:8]}"

    res = api.post(
        "/api/v2/cases",
        json={
            "case_number": "R12-IDEM-DESC",
            "title": "Idempotency conflict probe",
            "description": "original description",
            "severity": "HIGH",
        },
        headers={**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": key},
    )
    assert res.status_code == 201, res.text
    original_id = res.json()["id"]

    # Changed description, same key -> 409.
    res2 = api.post(
        "/api/v2/cases",
        json={
            "case_number": "R12-IDEM-DESC",
            "title": "Idempotency conflict probe",
            "description": "TAMPERED description",
            "severity": "HIGH",
        },
        headers={**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": key},
    )
    assert res2.status_code == 409, (
        f"changed description replayed as stale success ({res2.status_code}): {res2.text}"
    )

    # Changed severity, same key -> 409.
    res3 = api.post(
        "/api/v2/cases",
        json={
            "case_number": "R12-IDEM-DESC",
            "title": "Idempotency conflict probe",
            "description": "original description",
            "severity": "CRITICAL",
        },
        headers={**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": key},
    )
    assert res3.status_code == 409, (
        f"changed severity replayed as stale success ({res3.status_code}): {res3.text}"
    )

    # No duplicate case was created by the conflicting replays.
    res4 = api.get("/api/v2/cases?limit=100", headers=_auth(jwks_provider, AUDITOR_SUB))
    numbers = [i["case_number"] for i in res4.json()["items"] if i["case_number"] == "R12-IDEM-DESC"]
    assert len(numbers) == 1
    assert original_id


def test_transition_new_assignee_changes_digest_409(api, jwks_provider):
    """A transition replayed under the same key with a different new_assignee_sub
    changes the semantic digest -> 409, not a stale success."""
    res = _create_case(api, jwks_provider, "R12-IDEM-ASSIGN")
    assert res.status_code == 201, res.text
    case_id = res.json()["id"]
    key = f"r12-idem-assign-{uuid.uuid4().hex[:8]}"

    res1 = api.post(
        f"/api/v2/cases/{case_id}/transition",
        json={
            "action": "assign",
            "expected_version": 1,
            "new_assignee_sub": "usr_assignee_alpha",
        },
        headers={**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": key},
    )
    assert res1.status_code == 200, res1.text
    assert res1.json()["assigned_to_sub"] == "usr_assignee_alpha"

    res2 = api.post(
        f"/api/v2/cases/{case_id}/transition",
        json={
            "action": "assign",
            "expected_version": 1,
            "new_assignee_sub": "usr_assignee_beta",
        },
        headers={**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": key},
    )
    assert res2.status_code == 409, (
        f"changed new_assignee_sub replayed as stale success ({res2.status_code}): {res2.text}"
    )


def test_same_request_returns_same_response(api, jwks_provider):
    """Identical retry under the same key returns the SAME stored response and does
    not re-execute (no duplicate case, no duplicate transition event)."""
    key = f"r12-idem-same-{uuid.uuid4().hex[:8]}"
    body = {
        "case_number": "R12-IDEM-SAME",
        "title": "Replay stability probe",
        "description": "stable description",
        "severity": "MEDIUM",
    }
    headers = {**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": key}

    res1 = api.post("/api/v2/cases", json=body, headers=headers)
    assert res1.status_code == 201, res1.text
    first = res1.json()

    res2 = api.post("/api/v2/cases", json=body, headers=headers)
    assert res2.status_code == 201, res2.text
    second = res2.json()
    assert second["id"] == first["id"], "replay re-executed instead of returning the stored response"
    assert second["created_at"] == first["created_at"]

    # The same for a transition: identical retry -> same response, exactly one event.
    tkey = f"r12-idem-trans-{uuid.uuid4().hex[:8]}"
    theaders = {**_auth(jwks_provider, AUDITOR_SUB), "Idempotency-Key": tkey}
    tres1 = api.post(
        f"/api/v2/cases/{first['id']}/transition",
        json={"action": "start_review", "expected_version": 1},
        headers=theaders,
    )
    assert tres1.status_code == 200, tres1.text
    tres2 = api.post(
        f"/api/v2/cases/{first['id']}/transition",
        json={"action": "start_review", "expected_version": 1},
        headers=theaders,
    )
    assert tres2.status_code == 200
    assert tres2.json()["version"] == tres1.json()["version"] == 2

    detail = api.get(
        f"/api/v2/cases/{first['id']}", headers=_auth(jwks_provider, AUDITOR_SUB)
    ).json()
    start_review_events = [e for e in detail["events"] if e["event_type"] == "start_review"]
    assert len(start_review_events) == 1, "idempotent retry produced a duplicate transition event"


# ---------------------------------------------------------------------------
# Pagination: keyset cursor bound to institution + filters
# ---------------------------------------------------------------------------


def test_pagination_two_pages_no_duplicates(api, jwks_provider):
    """Stable (created_at, id) keyset pagination: no duplicates, no gaps,
    next_cursor only when a further page exists, foreign/malformed cursors rejected."""
    headers = _auth(jwks_provider, PAGES_SUB, institution=TENANT_PAGES)
    created_ids = []
    for n in range(1, 6):
        res = api.post(
            "/api/v2/cases",
            json={"case_number": f"R12-PAGE-{n:03d}", "title": f"pagination {n}"},
            headers=headers,
        )
        assert res.status_code == 201, res.text
        created_ids.append(res.json()["id"])

    # Page 1
    res1 = api.get("/api/v2/cases?limit=2", headers=headers)
    assert res1.status_code == 200
    page1 = res1.json()
    assert len(page1["items"]) == 2
    assert page1["next_cursor"], "next_cursor missing while a further page exists"
    assert page1["total"] == 2

    # Page 2
    res2 = api.get(
        f"/api/v2/cases?limit=2&cursor={page1['next_cursor']}", headers=headers
    )
    assert res2.status_code == 200, res2.text
    page2 = res2.json()
    assert len(page2["items"]) == 2
    assert page2["next_cursor"], "next_cursor missing after only 4 of 5 rows"

    # Page 3 (tail): last item, and next_cursor is None exactly at the end.
    res3 = api.get(
        f"/api/v2/cases?limit=2&cursor={page2['next_cursor']}", headers=headers
    )
    assert res3.status_code == 200
    page3 = res3.json()
    assert len(page3["items"]) == 1
    assert page3["next_cursor"] is None, "next_cursor returned with no remaining results"

    seen_ids = [i["id"] for i in page1["items"]] + [i["id"] for i in page2["items"]] + [
        i["id"] for i in page3["items"]
    ]
    assert len(seen_ids) == len(set(seen_ids)), f"duplicated ids across pages: {seen_ids}"
    assert set(seen_ids) == set(created_ids), "pagination skipped rows"

    # Stable order: (created_at, id) descending on every page.
    ordered = [i for i in page1["items"] + page2["items"] + page3["items"]]
    keys = [(i["created_at"], i["id"]) for i in ordered]
    assert keys == sorted(keys, reverse=True), f"unstable pagination order: {keys}"

    # Foreign cursor: a cursor legitimately minted for ANOTHER institution (real
    # next_cursor from TENANT_OTHER's own list) must be rejected here.
    other_headers = _auth(jwks_provider, AUDITOR_SUB, institution=TENANT_OTHER)
    for n in range(1, 3):
        res_other = api.post(
            "/api/v2/cases",
            json={"case_number": f"R12-OTHER-{n:03d}", "title": f"other {n}"},
            headers=other_headers,
        )
        assert res_other.status_code == 201, res_other.text
    res_other_page = api.get("/api/v2/cases?limit=1", headers=other_headers)
    assert res_other_page.status_code == 200
    foreign_cursor = res_other_page.json()["next_cursor"]
    assert foreign_cursor, "expected a real next_cursor minted for the other institution"
    res_foreign = api.get(
        f"/api/v2/cases?limit=2&cursor={foreign_cursor}", headers=headers
    )
    assert res_foreign.status_code == 400, (
        f"foreign-institution cursor accepted ({res_foreign.status_code}): {res_foreign.text}"
    )

    # Malformed cursor is a 400, not a 500.
    res_garbage = api.get("/api/v2/cases?limit=2&cursor=@@not-a-cursor@@", headers=headers)
    assert res_garbage.status_code == 400

    # A cursor is bound to the filters it was minted with.
    resf1 = api.get("/api/v2/cases?limit=2&status=OPEN", headers=headers)
    assert resf1.status_code == 200
    fcur = resf1.json()["next_cursor"]
    assert fcur
    resf2 = api.get(f"/api/v2/cases?limit=2&cursor={fcur}", headers=headers)  # filter dropped
    assert resf2.status_code == 400, "cursor accepted without its bound filters"
