"""
Evidence Anchor Worker (T14, R08)
Specification §5, §7 (R01, R04, R08, R09)

Real anchor worker on top of the leased outbox (claim_batch) and the
ChainSender raw-transaction pipeline:

  claim (FOR UPDATE SKIP LOCKED, 60s lease, owner token)
    -> resolve the case incident via case_incident_mappings (idempotent
       createIncidentForCase; NEVER an incident_id=1 assumption)
    -> dedupe check against the chain (getManifestDigest /
       getEvidenceByRequestId) BEFORE any re-send
    -> ChainSender.prepare_and_persist (signed raw tx + tx_hash + nonce
       COMMITTED before broadcast) -> broadcast -> mark SUBMITTED (not
       final; consumes no retry) -> reconcile to receipt/depth/entry proof
    -> ANCHORED only after receipt success + confirmation depth + canonical
       block + entry/manifest match; then the outbox item COMPLETES under
       its owner token.

Crash safety (spec §7): every DB transition is a short tenant transaction
committed before the next I/O boundary, so a crash at any point leaves a
state the next cycle resumes WITHOUT a second on-chain effect:
  * crash after claim            -> lease expires, item re-claimed, no send
  * crash after signed-tx commit -> re-broadcast the SAME raw tx/nonce
  * crash after broadcast        -> receipt reconciled, no re-send
  * crash after receipt          -> re-reconciled from the persisted tx hash

Timing always comes from an injected clock. There is no optional RPC: the
worker refuses to construct without a ChainSender.
"""

import hashlib
import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Callable, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import CaseIncidentMapping, EvidenceObject, WorkerHeartbeat
from app.repositories import evidence_repository, outbox_repository
from app.services.chain_sender import (
    ChainSender,
    NonceConsumedExternallyError,
    PayloadConflictError,
    SenderBinding,
    SignerPausedError,
    SubmissionState,
    case_reference_hash,
)

logger = logging.getLogger("evidence_anchor_worker")

OUTBOX_EVENT = "ANCHOR_EVIDENCE"


class CrashSimulated(Exception):
    """Raised at an injected crash point (tests only). Mirrors process
    death: never caught here, the session is abandoned exactly as a killed
    process would leave it."""


class EvidenceAnchorWorker:
    def __init__(
        self,
        chain_sender: ChainSender,
        worker_id: Optional[str] = None,
        deployment_id: str = "",
        severity_default: str = "HIGH",
    ):
        # No optional RPC in the institutional constructor.
        if chain_sender is None:
            raise ValueError(
                "EvidenceAnchorWorker requires a provisioned ChainSender — "
                "there is no optional/mock RPC path in the anchor pipeline"
            )
        self.chain_sender = chain_sender
        self.worker_id = worker_id or f"anchor_{uuid.uuid4().hex[:8]}"
        self.deployment_id = deployment_id
        self.severity_default = severity_default

    # ------------------------------------------------------------------
    # cycle
    # ------------------------------------------------------------------

    def process_cycle(
        self,
        session_factory: Callable[[], Session],
        institution_id: str,
        clock: Callable[[], datetime],
        limit: int = 20,
        crash_before: Optional[str] = None,
    ) -> Dict[str, int]:
        """One bounded anchor cycle. `crash_before` is a TEST hook raising
        CrashSimulated at a named boundary ('after_claim',
        'after_prepare_commit', 'after_broadcast', 'after_receipt_before_commit')."""
        stats = {"claimed": 0, "submitted": 0, "anchored": 0, "failed": 0, "dead": 0, "skipped": 0}

        session = session_factory()
        with self._tenant(session, institution_id):
            claimed_rows = outbox_repository.claim_batch(
                session=session,
                institution_id=institution_id,
                worker_id=self.worker_id,
                now=clock(),
                limit=limit,
            )
            # Snapshot before the session closes (attributes expire on commit).
            claimed = [
                {
                    "id": row.id,
                    "event_type": row.event_type,
                    "payload_json": row.payload_json,
                    "lease_token": row.lease_token,
                }
                for row in claimed_rows
            ]
            stats["claimed"] = len(claimed)
            self._heartbeat(session, institution_id, clock, stats)
        session.close()

        for item in claimed:
            if crash_before == "after_claim":
                raise CrashSimulated("after_claim")
            self._process_item(session_factory, item, institution_id, clock, crash_before, stats)
        return stats

    @contextmanager
    def _tenant(self, session: Session, institution_id: str):
        """Short tenant-scoped transaction: RLS context set, work, commit."""
        from app.db.session import tenant_transaction

        with tenant_transaction(session, institution_id):
            yield session

    def _heartbeat(self, session, institution_id, clock, stats) -> None:
        now = clock()
        hb = session.execute(
            select(WorkerHeartbeat).where(
                WorkerHeartbeat.institution_id == institution_id,
                WorkerHeartbeat.worker_id == self.worker_id,
                WorkerHeartbeat.role == "anchor",
            )
        ).scalars().first()
        detail = json.dumps({"stats": stats}, sort_keys=True)
        if hb is None:
            session.add(
                WorkerHeartbeat(
                    id=f"hb_{uuid.uuid4().hex[:16]}",
                    institution_id=institution_id,
                    worker_id=self.worker_id,
                    role="anchor",
                    heartbeat_at=now,
                    detail_json=detail,
                )
            )
        else:
            hb.heartbeat_at = now
            hb.detail_json = detail
        session.flush()

    # ------------------------------------------------------------------
    # per-item pipeline: short committed transactions between I/O boundaries
    # ------------------------------------------------------------------

    def _process_item(self, session_factory, item, institution_id, clock, crash_before, stats):
        if item["event_type"] != OUTBOX_EVENT:
            session = session_factory()
            with self._tenant(session, institution_id):
                outbox_repository.release_claim(session, item["id"], item["lease_token"])
            session.close()
            stats["skipped"] += 1
            return

        payload = json.loads(item["payload_json"])
        token = item["lease_token"]
        outbox_id = item["id"]
        session = session_factory()

        try:
            binding = SenderBinding(
                chain_id=int(payload["chain_id"]),
                contract_address=payload["contract_address"],
                institution_id=institution_id,
                deployment_id=self.deployment_id,
            )
            request_id = payload["anchor_request_id"]

            # -- Phase 1: STORED manifest digest (tenant read) ------------
            with self._tenant(session, institution_id):
                stored = session.execute(
                    select(EvidenceObject).where(
                        EvidenceObject.institution_id == institution_id,
                        EvidenceObject.evidence_id == payload["evidence_id"],
                    )
                ).scalars().first()
                manifest_digest_hex = _strip0x(
                    (stored.manifest_digest if stored else None)
                    or payload.get("manifest_hash")
                )
            if not _is_hash64(manifest_digest_hex):
                self._fail(session, institution_id, outbox_id, token,
                           "stored manifest digest missing/invalid — refusing to anchor",
                           clock, stats, dead=True)
                return

            # -- Phase 2: chain dedupe BEFORE any re-send -----------------
            on_chain_digest = self.chain_sender.manifest_digest_on_chain(request_id)
            if on_chain_digest and on_chain_digest.lower() != "0x" + manifest_digest_hex.lower():
                self._fail(session, institution_id, outbox_id, token,
                           f"request {request_id} already anchored with a different manifest digest",
                           clock, stats, dead=True)
                return
            if on_chain_digest:
                with self._tenant(session, institution_id):
                    self._finish_from_chain(session, institution_id, payload)
                    outbox_repository.complete_claimed(session, outbox_id, token, clock())
                stats["anchored"] += 1
                return

            # -- Phase 3: idempotent case incident ------------------------
            incident_id = self._resolve_incident(session_factory, binding, payload, institution_id, clock)
            if incident_id is None:
                self._fail(session, institution_id, outbox_id, token,
                           "case incident not resolvable yet", clock, stats)
                return

            # -- Phase 4: prepare + persist raw tx, COMMIT, broadcast ------
            call = self.chain_sender.build_call(
                "EVIDENCE_ATTESTED",
                {
                    "contract_address": binding.contract_address,
                    "incident_id": incident_id,
                    "request_id": request_id,
                    "type_hash": "0x" + _sha256_hex("evidence_type"),
                    "description_hash": "0x" + manifest_digest_hex,
                    "file_sha256": payload["file_sha256"],
                    "manifest_digest": "0x" + manifest_digest_hex,
                },
            )
            with self._tenant(session, institution_id):
                submission = self.chain_sender.prepare_and_persist(
                    session, binding, call, request_id=request_id, now=clock()
                )
            # signed raw tx + tx_hash + nonce are now DURABLE (committed).
            if crash_before == "after_prepare_commit":
                session.close()
                raise CrashSimulated("after_prepare_commit")

            if submission.status == "SIGNED":
                self.chain_sender.broadcast(submission, now=clock())  # I/O outside tx
                with self._tenant(session, institution_id):
                    pass  # commits the BROADCAST status + broadcast_at
                stats["submitted"] += 1
                if crash_before == "after_broadcast":
                    session.close()
                    raise CrashSimulated("after_broadcast")

            # SUBMITTED is not final and consumes no retry.
            with self._tenant(session, institution_id):
                outbox_repository.mark_submitted(session, outbox_id, token, clock())

            # -- Phase 5: reconcile to receipt ----------------------------
            with self._tenant(session, institution_id):
                state = self.chain_sender.reconcile(submission, now=clock(), session=session)
            if crash_before == "after_receipt_before_commit" and state == SubmissionState.CONFIRMED:
                session.close()
                raise CrashSimulated("after_receipt_before_commit")

            if state == SubmissionState.CONFIRMED:
                with self._tenant(session, institution_id):
                    self._verify_and_anchor(session, institution_id, payload, submission, manifest_digest_hex)
                    if outbox_repository.complete_claimed(session, outbox_id, token, clock()):
                        stats["anchored"] += 1
                    else:
                        stats["skipped"] += 1  # lease lost; the new owner completes
            elif state == SubmissionState.REORGED:
                with self._tenant(session, institution_id):
                    evidence_repository.update_anchor_status(
                        session=session, institution_id=institution_id,
                        anchor_request_id=request_id, status="REORGED",
                    )
                    outbox_repository.mark_submitted(session, outbox_id, token, clock())
            elif state == SubmissionState.RECEIPT_STATUS_ZERO:
                with self._tenant(session, institution_id):
                    evidence_repository.update_anchor_status(
                        session=session, institution_id=institution_id,
                        anchor_request_id=request_id, status="FAILED",
                        transaction_hash=submission.tx_hash,
                    )
                session.commit()
                self._fail(session, institution_id, outbox_id, token,
                           f"receipt status 0 for tx {submission.tx_hash} — not anchored",
                           clock, stats)
                return
            else:
                # PENDING / CONFIRMING / STUCK: reconciliation continues
                # without a payload change; slow confirmation consumes no
                # retry and STUCK already alerted + paused new sends.
                with self._tenant(session, institution_id):
                    outbox_repository.mark_submitted(session, outbox_id, token, clock())
        except CrashSimulated:
            raise
        except PayloadConflictError as exc:
            self._fail(session, institution_id, outbox_id, token, str(exc), clock, stats, dead=True)
        except (NonceConsumedExternallyError, SignerPausedError) as exc:
            self._fail(session, institution_id, outbox_id, token,
                       f"signer paused: {exc}", clock, stats)
        except Exception as exc:
            logger.error("anchor failure for outbox %s: %s", outbox_id, exc, exc_info=True)
            self._fail(session, institution_id, outbox_id, token, str(exc), clock, stats)
        finally:
            session.close()

    # ------------------------------------------------------------------

    def _resolve_incident(self, session_factory, binding, payload, institution_id, clock) -> Optional[int]:
        """Idempotent case->incident binding: the REAL on-chain incident for
        this (institution, deployment, case) via createIncidentForCase,
        remembered in case_incident_mappings — never an incident_id=1 guess."""
        case_id = payload["case_id"]
        ref_hash = case_reference_hash(binding.chain_id, binding.contract_address, institution_id, case_id)

        session = session_factory()
        try:
            with self._tenant(session, institution_id):
                mapping = session.execute(
                    select(CaseIncidentMapping).where(
                        CaseIncidentMapping.institution_id == institution_id,
                        CaseIncidentMapping.deployment_id == binding.deployment_id,
                        CaseIncidentMapping.case_id == case_id,
                    )
                ).scalars().first()
            if mapping is not None:
                return int(mapping.incident_id)

            existing = self.chain_sender.incident_for_case_reference(ref_hash)
            if existing:
                incident_id = existing
            else:
                call = self.chain_sender.build_call(
                    "CASE_INCIDENT",
                    {
                        "contract_address": binding.contract_address,
                        "case_reference_hash": ref_hash,
                        "title_hash": "0x" + _sha256_hex(f"{institution_id}:{case_id}:title"),
                        "severity_hash": "0x" + _sha256_hex(self.severity_default),
                    },
                )
                request_id = "0x" + _sha256_hex(
                    f"case-incident:{binding.deployment_id}:{institution_id}:{case_id}"
                )
                with self._tenant(session, institution_id):
                    submission = self.chain_sender.prepare_and_persist(
                        session, binding, call, request_id=request_id, now=clock()
                    )
                if submission.status == "SIGNED":
                    self.chain_sender.broadcast(submission, now=clock())
                    with self._tenant(session, institution_id):
                        pass
                with self._tenant(session, institution_id):
                    state = self.chain_sender.reconcile(submission, now=clock(), session=session)
                if state != SubmissionState.CONFIRMED:
                    return None  # the evidence item's retry ladder re-drives this
                incident_id = self.chain_sender.incident_for_case_reference(ref_hash)
                if not incident_id:
                    return None
                with self._tenant(session, institution_id):
                    session.add(
                        CaseIncidentMapping(
                            id=f"cim_{uuid.uuid4().hex[:16]}",
                            institution_id=institution_id,
                            deployment_id=binding.deployment_id,
                            case_id=case_id,
                            case_reference_hash=ref_hash,
                            incident_id=incident_id,
                        )
                    )
            return int(incident_id)
        finally:
            session.close()

    # ------------------------------------------------------------------

    def _verify_and_anchor(self, session, institution_id, payload, submission, manifest_digest_hex) -> None:
        """ANCHORED only after receipt success + depth + canonical block AND
        the on-chain entry matches the stored manifest claim."""
        request_id = payload["anchor_request_id"]
        on_chain = self.chain_sender.evidence_on_chain(request_id)
        if not on_chain:
            raise RuntimeError(
                f"receipt confirmed for {submission.tx_hash} but "
                f"getEvidenceByRequestId({request_id}) is empty"
            )
        digest_on_chain = on_chain.get("manifest_digest") or ""
        if digest_on_chain.lower() != "0x" + manifest_digest_hex.lower():
            raise RuntimeError("on-chain manifest digest does not match the stored manifest digest")
        evidence_repository.update_anchor_status(
            session=session,
            institution_id=institution_id,
            anchor_request_id=request_id,
            status="ANCHORED",
            transaction_hash=submission.tx_hash,
            block_number=submission.receipt_block_number,
            block_hash=submission.receipt_block_hash,
            entry_hash=on_chain.get("entry_hash"),
        )

    def _finish_from_chain(self, session, institution_id, payload) -> None:
        on_chain = self.chain_sender.evidence_on_chain(payload["anchor_request_id"])
        evidence_repository.update_anchor_status(
            session=session,
            institution_id=institution_id,
            anchor_request_id=payload["anchor_request_id"],
            status="ANCHORED",
            transaction_hash=on_chain.get("transaction_hash"),
            block_number=on_chain.get("block_number"),
            entry_hash=on_chain.get("entry_hash"),
        )

    def _fail(self, session, institution_id, outbox_id, token, reason, clock, stats, dead: bool = False) -> None:
        session.rollback()
        result = None
        try:
            with self._tenant(session, institution_id):
                message = f"DEAD (terminal): {reason}" if dead else reason
                result = outbox_repository.fail_claimed(session, outbox_id, token, message, clock())
        except Exception as exc:  # recording a failure must never mask it
            logger.error("failed to record failure for %s: %s", outbox_id, exc)
            return
        if result == "DEAD":
            stats["dead"] += 1
        elif result is None:
            stats["skipped"] += 1
        else:
            stats["failed"] += 1


def _strip0x(value: str) -> str:
    return value[2:] if value and value.startswith("0x") else (value or "")


def _is_hash64(value: str) -> bool:
    return bool(value) and len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
