"""
Evidence Verification Route (V3) — R07, spec §5 (FINAL contract).
POST /api/v3/evidence/verify

  - 401 without identity (institutional mode: no demo fallback);
  - 404 for a case/evidence outside the caller's institution — evidence ids
    can never smuggle another case's evidence past case authorization;
  - 422 for malformed requests (empty/duplicate evidence ids, browser-supplied
    entries/chain_id/contract_address, unknown snapshot_id);
  - 200 with an explicit tri-state status: verified | invalid | unavailable
    (never mixed).

String identifiers reference EvidenceObject rows. On-chain uint256 values are
resolved server-side and emitted as decimal STRINGS. The route accepts NO
chain parameters from the browser: the DeploymentBinding comes from the
operator-managed registry (ChainRegistry.resolve).
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db.session import get_db, tenant_transaction
from app.schemas.evidence import VerifyEvidenceRequest, VerificationResult
from app.schemas.identity import Identity
from app.services.anchor_reader import AnchorReader
from app.services.chain_registry import ChainRegistry
from app.services.evidence_verifier import (
    CaseAccessDeniedError,
    EvidenceAccessDeniedError,
    SnapshotNotFoundError,
    ManifestSignatureVerifier,
    verify_case_evidence,
)
from app.services.evidence_store import EvidenceStore
from app.routes.v2.evidence import get_evidence_store
from app.routes.v2.identity import get_current_identity

router = APIRouter()

# Injectable verification context (tests / future composition root)
_ctx = {
    "reader": None,
    "store": None,
    "manifest_verifier": None,
    "trust_registry": None,
    "db_session_factory": None,
    "keys": None,
}


def set_verification_components(reader=None, store=None, manifest_verifier=None,
                                trust_registry=None, db_session_factory=None, keys=None):
    """Inject (or clear) the verification context. Production defaults are
    built lazily from settings when a component is None."""
    _ctx.update(
        reader=reader,
        store=store,
        manifest_verifier=manifest_verifier,
        trust_registry=trust_registry,
        db_session_factory=db_session_factory,
        keys=keys,
    )


def _default_reader() -> Optional[AnchorReader]:
    from app.services.evm_rpc_client import EvmRpcClient

    if not settings.BLOCKCHAIN_RPC_URL:
        return None
    try:
        client = EvmRpcClient(
            rpc_url=settings.BLOCKCHAIN_RPC_URL,
            manifest_path=settings.DEPLOYMENT_MANIFEST_PATH,
        )
        return AnchorReader(rpc=client)
    except Exception:
        return None


@router.post(
    "/verify",
    response_model=VerificationResult,
    summary="Verify case evidence against the pinned chain snapshot (V3)",
)
async def verify_evidence_v3(
    payload: VerifyEvidenceRequest,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
):
    reader = _ctx["reader"] or _default_reader()
    store: EvidenceStore = _ctx["store"] or get_evidence_store()

    if _ctx["manifest_verifier"] is not None:
        verifier = _ctx["manifest_verifier"]
    else:
        from app.security.signing import Verifier

        verifier = ManifestSignatureVerifier(Verifier(), _ctx["trust_registry"])

    session = db
    if _ctx["db_session_factory"] is not None:
        session = _ctx["db_session_factory"]()

    try:
        with tenant_transaction(session, identity.institution_id):
            result = verify_case_evidence(
                session=session,
                identity=identity,
                request=payload,
                reader=reader,
                store=store,
                verifier=verifier,
                chain_registry=ChainRegistry(),
            )
        return result
    except CaseAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except EvidenceAccessDeniedError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except SnapshotNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
