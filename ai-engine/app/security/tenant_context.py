"""
Institutional Tenant Context (R11).
Ensures institution_id is scoped per request and prevents cross-tenant data leakage.

R11 binding: this is the shared validation type for the institutional tenant
boundary. app.db.session.tenant_transaction validates through TenantContext and
applies the SAME institution id to PostgreSQL row-level security with a
transaction-local `SELECT set_config('app.current_institution_id', :id, true)`
inside one transaction; the id used for authorization checks and the id bound
to RLS must therefore always be the exact same string. Every repository,
route, and worker that touches institutional data must run inside a
tenant_transaction (or an equivalent transaction-local context) — never with a
BYPASSRLS PostgreSQL user.
"""

from typing import Optional


class TenantContext:
    def __init__(self, institution_id: str):
        if not institution_id or not isinstance(institution_id, str):
            raise ValueError("Valid institution_id is required for TenantContext")
        self._institution_id = institution_id.strip()

    @property
    def institution_id(self) -> str:
        return self._institution_id

    def assert_authorized_for_institution(self, target_institution_id: Optional[str]) -> None:
        """
        Enforce strict tenant boundary check.
        Raises ValueError if target_institution_id does not match the authenticated context.
        """
        if not target_institution_id:
            raise ValueError("Target institution_id cannot be empty")
        
        if self._institution_id.lower() != target_institution_id.strip().lower():
            raise ValueError(
                f"Tenant context mismatch: authenticated as '{self._institution_id}', "
                f"cannot access resource of '{target_institution_id}'"
            )

    def __repr__(self) -> str:
        return f"<TenantContext(institution_id='{self._institution_id}')>"
