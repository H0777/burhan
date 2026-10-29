"""
H05 staging operator provisioning (one-shot compose service, idempotent).

Operator duty that the engine NEVER performs (R10: a valid token alone grants
nothing; R11: the engine never seeds on PostgreSQL):

  1. Keycloak (realm "burhan"): create-or-update the institutional operator
     user with the institution_id attribute, verify the account and set its
     password. BOTH secrets (bootstrap admin + user password) arrive through
     gitignored infra/staging/.env variables — never committed, never printed.
  2. PostgreSQL memberships: create-or-reactivate the ACTIVE OPERATOR
     membership row for the user's Keycloak subject (the JWT `sub`). Inserted
     with the migration/OWNER role under the transaction-local tenant context
     (FORCE RLS) — the same role/context pattern as the RLS suite.

Every step is an upsert: the whole service is safe to re-run after a stack
recreate. Exit codes: 0 success; 1 configuration/refusal; other failures raise.

The `sub` printed at the end is the membership's stable OIDC subject — it is
NOT a secret (it appears in every issued token anyway).
"""

import json
import os
import sys
import time
import uuid

import requests
from sqlalchemy import create_engine, text

BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://keycloak:8080").rstrip("/")
ADMIN_USERNAME = os.environ.get("KEYCLOAK_ADMIN_USERNAME", "staging-admin")
ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")
REALM = os.environ.get("STAGING_KEYCLOAK_REALM", "burhan")
USERNAME = os.environ.get("STAGING_OIDC_USERNAME", "staging-operator")
USER_PASSWORD = os.environ.get("STAGING_OIDC_USER_PASSWORD", "")
USER_EMAIL = os.environ.get("STAGING_OIDC_USER_EMAIL", f"{USERNAME}@staging.local")
INSTITUTION_ID = os.environ.get("STAGING_INSTITUTION_ID", "INST-CENTRAL-STAGING")
MEMBERSHIP_ROLE = os.environ.get("STAGING_OIDC_MEMBERSHIP_ROLE", "OPERATOR")
MIGRATION_DATABASE_URL = os.environ.get("MIGRATION_DATABASE_URL", "")


def _admin_token() -> str:
    """Bootstrap admin token with patience for first-boot Keycloak."""
    last_error = "unknown"
    for _ in range(90):  # up to ~3 minutes
        try:
            response = requests.post(
                f"{BASE_URL}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": ADMIN_USERNAME,
                    "password": ADMIN_PASSWORD,
                },
                timeout=10,
            )
            if response.status_code == 200:
                return response.json()["access_token"]
            last_error = f"HTTP {response.status_code}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(2)
    raise SystemExit(f"[provisioner] FATAL: admin token unavailable: {last_error}")


def _provision_user(headers: dict) -> str:
    users_url = f"{BASE_URL}/admin/realms/{REALM}/users"
    response = requests.get(
        users_url,
        params={"username": USERNAME, "exact": "true"},
        headers=headers,
        timeout=10,
    )
    response.raise_for_status()
    found = response.json()

    if not found:
        response = requests.post(
            users_url,
            headers=headers,
            timeout=10,
            data=json.dumps(
                {
                    "username": USERNAME,
                    "enabled": True,
                    "email": USER_EMAIL,
                    "emailVerified": True,
                    "firstName": "Staging",
                    "lastName": "Operator",
                    "attributes": {"institution_id": [INSTITUTION_ID]},
                }
            ),
        )
        if response.status_code not in (201, 409):
            raise SystemExit(
                f"[provisioner] FATAL: user create failed: HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )
        response = requests.get(
            users_url,
            params={"username": USERNAME, "exact": "true"},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        found = response.json()
        if not found:
            raise SystemExit("[provisioner] FATAL: user missing after create")

    user = found[0]
    user_id = user["id"]

    # Idempotent attribute/profile upsert (institution_id claim source).
    attributes = dict(user.get("attributes") or {})
    attributes["institution_id"] = [INSTITUTION_ID]
    response = requests.put(
        f"{users_url}/{user_id}",
        headers=headers,
        timeout=10,
        data=json.dumps(
            {
                "firstName": user.get("firstName") or "Staging",
                "lastName": user.get("lastName") or "Operator",
                "email": user.get("email") or USER_EMAIL,
                "emailVerified": True,
                "enabled": True,
                "attributes": attributes,
            }
        ),
    )
    response.raise_for_status()

    # Idempotent password set (secret value never printed).
    response = requests.put(
        f"{users_url}/{user_id}/reset-password",
        headers=headers,
        timeout=10,
        data=json.dumps({"type": "password", "temporary": False, "value": USER_PASSWORD}),
    )
    response.raise_for_status()
    return user_id


def _upsert_membership(sub: str) -> None:
    if not MIGRATION_DATABASE_URL:
        raise SystemExit(
            "[provisioner] FATAL: MIGRATION_DATABASE_URL required — the membership row "
            "is an operator duty; the engine never seeds (R11)"
        )
    engine = create_engine(MIGRATION_DATABASE_URL, pool_pre_ping=True)
    try:
        with engine.begin() as conn:
            # Transaction-local tenant context: memberships sit under FORCE RLS
            # (same pattern as the RLS suite's owner-role inserts).
            conn.execute(
                text("SELECT set_config('app.current_institution_id', :inst_id, true)"),
                {"inst_id": INSTITUTION_ID},
            )
            row = conn.execute(
                text(
                    "SELECT id FROM memberships "
                    "WHERE institution_id = :inst_id AND sub = :sub"
                ),
                {"inst_id": INSTITUTION_ID, "sub": sub},
            ).first()
            if row is None:
                conn.execute(
                    text(
                        "INSERT INTO memberships "
                        "(id, institution_id, sub, role, email, is_active, created_at) "
                        "VALUES (:id, :inst_id, :sub, :role, :email, true, now())"
                    ),
                    {
                        "id": f"mem_{uuid.uuid4().hex[:16]}",
                        "inst_id": INSTITUTION_ID,
                        "sub": sub,
                        "role": MEMBERSHIP_ROLE,
                        "email": USER_EMAIL,
                    },
                )
                print(f"[provisioner] membership created: role={MEMBERSHIP_ROLE} active=true")
            else:
                conn.execute(
                    text(
                        "UPDATE memberships SET is_active = true, role = :role, email = :email "
                        "WHERE id = :id"
                    ),
                    {"role": MEMBERSHIP_ROLE, "email": USER_EMAIL, "id": row[0]},
                )
                print(f"[provisioner] membership re-activated (idempotent re-run): role={MEMBERSHIP_ROLE}")
            # Deactivate stale memberships of this institution: after a Keycloak
            # data-volume wipe the realm is re-imported and the operator's subject
            # changes — no token will ever carry the dead subs again, and an
            # active membership for a subject nobody can authenticate as must not
            # linger (staging hygiene, single-operator realm).
            stale = conn.execute(
                text(
                    "UPDATE memberships SET is_active = false "
                    "WHERE institution_id = :inst_id AND sub <> :sub AND is_active = true"
                ),
                {"inst_id": INSTITUTION_ID, "sub": sub},
            ).rowcount
            if stale:
                print(f"[provisioner] deactivated {stale} stale membership row(s) (dead subs)")
    finally:
        engine.dispose()


def main() -> None:
    if not ADMIN_PASSWORD or not USER_PASSWORD:
        raise SystemExit(
            "[provisioner] FATAL: refusing to run without KEYCLOAK_ADMIN_PASSWORD and "
            "STAGING_OIDC_USER_PASSWORD (set them in gitignored infra/staging/.env)"
        )
    token = _admin_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    user_id = _provision_user(headers)
    print(
        f"[provisioner] keycloak operator ready: realm={REALM} username={USERNAME} "
        f"attributes=institution_id:{INSTITUTION_ID} (password NOT printed)"
    )
    _upsert_membership(user_id)
    print(f"[provisioner] done: sub={user_id}")


if __name__ == "__main__":
    main()
