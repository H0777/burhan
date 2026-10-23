"""
Institutional Tenant Context.
Ensures institution_id is scoped per request and prevents cross-tenant data leakage.
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
