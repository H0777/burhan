"""
Independent 3-State Evidence Verifier (T05)
Specification §6, §7 (R04, R05, R15)

Evaluates Evidence V2 chains independently against canonical keccak256(abi.encode)
rules and on-chain anchored consensus state. Returns 3 distinct outcomes:
- verified: Cryptographic integrity confirmed and anchored on-chain.
- invalid: Cryptographic mismatch, broken link, or non-matching on-chain state.
- unavailable: RPC node connection failure or required infrastructure unreachable.

R07 (spec §5) adds `verify_case_evidence`: the REAL case-evidence verifier
behind POST /api/v3/evidence/verify. It resolves the operator-managed
DeploymentBinding, pins a ChainSnapshot (latest-depth+1 + block_hash), reads
the anchored incident AT that pin, proves the writer was authorized BEFORE
the append event (ordered block/tx/log replay), verifies the stored Ed25519
service manifest against the on-chain commitment (SHA-256 of the canonical
SIGNED envelope == getManifestDigest), re-hashes the REAL decrypted bytes,
recomputes the canonical V2 entry chain, re-checks the pinned block_hash, and
persists a VerificationSnapshot. Legacy rows without a signed manifest are
classified legacy_unattested and automated AuditEngine traces
chain_generated_unattested — a `verified` verdict is never fabricated.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy.orm import Session
from sqlalchemy import select, text

from app.schemas.evidence import (
    EvidenceV2,
    EvidenceVerificationRequest,
    EvidenceVerificationResult,
    AnchorInfo,
    VerifyEvidenceRequest,
    VerificationResult,
    hash_entry,
)


def verify_evidence(
    request: EvidenceVerificationRequest,
    rpc_client: Optional[object] = None
) -> EvidenceVerificationResult:
    """
    Independently verifies an Evidence V2 collection.
    Recomputes each entry's hash, checks parent-child integrity, and reconciles with on-chain anchor.
    """
    reasons: List[str] = []
    entries = request.entries

    if not entries:
        return EvidenceVerificationResult(
            status="invalid",
            provenance_status="unverified",
            checked_entries=[],
            reasons=["Empty evidence chain provided; verification requires at least one entry."]
        )

    # 1. Internal Cryptographic & Linkage Checks
    for idx, entry in enumerate(entries):
        if entry.incident_id != request.incident_id:
            reasons.append(
                f"Entry {entry.evidence_id} incident_id ({entry.incident_id}) mismatch with request ({request.incident_id})"
            )

        computed = hash_entry(entry)
        if not entry.entry_hash or entry.entry_hash.lower() != computed.lower():
            reasons.append(
                f"Entry {entry.evidence_id} content hash mismatch: expected {computed}, got {entry.entry_hash}"
            )

        if idx > 0:
            pred_hash = entries[idx - 1].entry_hash
            if not entry.previous_entry_hash or entry.previous_entry_hash.lower() != (pred_hash or "").lower():
                reasons.append(
                    f"Broken chain at entry {entry.evidence_id}: previous_entry_hash {entry.previous_entry_hash} does not link to predecessor {pred_hash}"
                )

    if any("mismatch" in r.lower() or "broken" in r.lower() for r in reasons):
        return EvidenceVerificationResult(
            status="invalid",
            provenance_status="compromised",
            checked_entries=entries,
            reasons=reasons
        )

    # 2. On-Chain State / Anchor Reconciliation
    if rpc_client is None:
        return EvidenceVerificationResult(
            status="unavailable",
            provenance_status="unanchored",
            checked_entries=entries,
            reasons=["RPC client unavailable: No active on-chain consensus provider available for verification."]
        )

    try:
        block_info = rpc_client.get_block("latest")
        block_number = block_info.get("number") if block_info else None
        block_hash = block_info.get("hash") if block_info else None

        incident = rpc_client.get_incident(request.incident_id)
        if not incident:
            reasons.append(f"Incident {request.incident_id} does not exist on-chain.")
            return EvidenceVerificationResult(
                status="invalid",
                provenance_status="unanchored",
                checked_entries=entries,
                reasons=reasons,
                block_number=block_number,
                block_hash=block_hash
            )

        on_chain_entries = rpc_client.get_evidence_chain(request.incident_id)
        if len(on_chain_entries) != len(entries):
            reasons.append(
                f"Evidence count mismatch: payload contains {len(entries)} entries, but on-chain incident has {len(on_chain_entries)} entries."
            )
            return EvidenceVerificationResult(
                status="invalid",
                provenance_status="count_mismatch",
                checked_entries=entries,
                reasons=reasons,
                block_number=block_number,
                block_hash=block_hash
            )

        # Check writer authorization
        all_writers_authorized = True
        for e in entries:
            is_auth = rpc_client.is_evidence_writer(e.submitted_by)
            if not is_auth:
                all_writers_authorized = False

        if not all_writers_authorized:
            provenance_status = "legacy_unrestricted_submission"
            reasons.append("Warning: Submission author is not an allowlisted institutional evidence writer.")
        else:
            provenance_status = "verified_institutional_writer"

        anchor = AnchorInfo(
            chain_id=request.chain_id,
            contract_address=request.contract_address,
            count=len(entries),
            head=entries[-1].entry_hash if entries else None,
            block_number=block_number,
            block_hash=block_hash
        )

        return EvidenceVerificationResult(
            status="verified",
            provenance_status=provenance_status,
            checked_entries=entries,
            reasons=reasons,
            block_number=block_number,
            block_hash=block_hash,
            anchor=anchor,
            source="registry_trusted_contract"
        )

    except Exception as exc:
        err_msg = f"RPC node request failed: {type(exc).__name__}: {str(exc)}"
        return EvidenceVerificationResult(
            status="unavailable",
            provenance_status="unknown",
            checked_entries=entries,
            reasons=[err_msg]
        )


# ===========================================================================
# R07 (spec §5) — real case-evidence verification behind /api/v3/evidence/verify
# ===========================================================================

REASON_SNAPSHOT_REORGED = "snapshot_reorged"
REASON_HISTORICAL_LOGS = "historical_logs_unavailable"
REASON_RPC = "rpc_unavailable"
REASON_BINDING = "binding_unavailable"
REASON_CODEHASH_MISSING = "codehash_missing"
REASON_CONTRACT_EMPTY = "contract_code_unavailable"
REASON_CODEHASH_MISMATCH = "codehash_mismatch"
REASON_NOT_ANCHORED = "not_anchored_on_chain"
REASON_LEGACY_UNATTESTED = "legacy_unattested"
REASON_CHAIN_GENERATED_UNATTESTED = "chain_generated_unattested"
REASON_COMMITMENT_MISMATCH = "manifest_commitment_mismatch"
REASON_MANIFEST_INVALID = "manifest_signature_invalid"
REASON_KEY_TIME_UNPROVEN = "historical_key_time_unproven"
REASON_MANIFEST_BINDING = "manifest_binding_mismatch"
REASON_FILE_MISSING = "file_missing"
REASON_FILE_TAMPERED = "file_tampered"
REASON_FILE_HASH = "file_hash_mismatch"
REASON_WRITER = "unauthorized_writer"
REASON_CHAIN_LINK = "entry_chain_broken"
REASON_ANCHOR_RECORD = "anchor_record_missing"


class VerificationServiceError(Exception):
    """Base for HTTP-mappable verification service errors."""


class CaseAccessDeniedError(VerificationServiceError):
    """Case outside the caller's institution (HTTP 404)."""


class EvidenceAccessDeniedError(VerificationServiceError):
    """Evidence outside the requested case/institution (HTTP 404) — evidence
    ids may never smuggle another case's evidence past case authorization."""


class SnapshotNotFoundError(VerificationServiceError):
    """Unknown/dangling snapshot_id in the request (HTTP 422)."""


class ManifestSignatureVerifier:
    """Couples the R05 Verifier with the external trust registry and proves
    manifest signatures; trusted_time comes from the anchored block, never
    from client input."""

    def __init__(self, verifier, registry):
        self._verifier = verifier
        self._registry = registry

    def verify_manifest(self, envelope, trusted_time: Optional[datetime]):
        from app.security.signing import DOMAIN_SERVICE_MANIFEST

        return self._verifier.verify(DOMAIN_SERVICE_MANIFEST, envelope, self._registry, trusted_time)


def _unavailable(reasons, snapshot_id=None, deployment_id=None, checked=None) -> VerificationResult:
    return VerificationResult(
        status="unavailable",
        reasons=list(reasons),
        snapshot_id=snapshot_id,
        checked_evidence_ids=checked or [],
        deployment_id=deployment_id,
    )


def _invalid(reasons, snapshot_id=None, deployment_id=None, checked=None) -> VerificationResult:
    return VerificationResult(
        status="invalid",
        reasons=list(reasons),
        snapshot_id=snapshot_id,
        checked_evidence_ids=checked or [],
        deployment_id=deployment_id,
    )


def _persist_snapshot(session, institution_id, case_id, snapshot, deployment_id,
                      head, count, status, reasons, evidence_ids, existing_id=None) -> str:
    """Insert (or update) the verification_snapshots row. Raw SQL on purpose:
    schema ownership stays with the alembic migration; no ORM model is added."""
    reasons_json = json.dumps(reasons)
    ids_json = json.dumps(evidence_ids)
    if existing_id:
        session.execute(
            text(
                "UPDATE verification_snapshots SET status = :status, reasons_json = :reasons, "
                "evidence_ids_json = :ids, head_entry_hash = :head, evidence_count = :count, "
                "updated_at = now() WHERE id = :id AND institution_id = :inst"
            ),
            {"status": status, "reasons": reasons_json, "ids": ids_json, "head": head,
             "count": count, "id": existing_id, "inst": institution_id},
        )
        session.flush()
        return existing_id
    snap_id = f"vs_{uuid.uuid4().hex[:16]}"
    session.execute(
        text(
            "INSERT INTO verification_snapshots (id, institution_id, case_id, deployment_id, "
            "chain_id, block_number, block_hash, head_entry_hash, evidence_count, status, "
            "reasons_json, evidence_ids_json) VALUES (:id, :inst, :case, :dep, :chain, "
            ":block_number, :block_hash, :head, :count, :status, :reasons, :ids)"
        ),
        {"id": snap_id, "inst": institution_id, "case": case_id, "dep": deployment_id,
         "chain": snapshot.chain_id, "block_number": snapshot.block_number,
         "block_hash": snapshot.block_hash, "head": head, "count": count,
         "status": status, "reasons": reasons_json, "ids": ids_json},
    )
    session.flush()
    return snap_id


def _load_snapshot(session, institution_id, snapshot_id):
    from app.services.anchor_reader import ChainSnapshot

    row = session.execute(
        text(
            "SELECT id, chain_id, block_number, block_hash FROM verification_snapshots "
            "WHERE id = :id AND institution_id = :inst"
        ),
        {"id": snapshot_id, "inst": institution_id},
    ).first()
    if row is None:
        raise SnapshotNotFoundError(f"snapshot {snapshot_id} not found for institution")
    return ChainSnapshot(
        id=row[0], chain_id=row[1], block_number=row[2], block_hash=row[3], confirmation_depth=0
    )


def _case_reference_hash(binding, institution_id: str, case_id: str) -> str:
    """keccak256(abi.encode(chainId, ForensicTrail, keccak256(institutionId),
    keccak256(caseId))) — the off-chain reference the contract registers."""
    import eth_abi
    from eth_hash.auto import keccak

    encoded = eth_abi.encode(
        ["uint256", "address", "bytes32", "bytes32"],
        [
            binding.chain_id,
            binding.forensic_trail_address(),
            keccak(institution_id.encode("utf-8")),
            keccak(case_id.encode("utf-8")),
        ],
    )
    return "0x" + keccak(encoded).hex()


def verify_case_evidence(
    session: Session,
    identity,
    request: VerifyEvidenceRequest,
    reader,
    store,
    verifier,
    chain_registry=None,
) -> VerificationResult:
    """Real case-evidence verification (spec §5). See module docstring."""
    from app.db.models import Case, EvidenceObject, EvidenceAnchor
    from app.services.anchor_reader import (
        RpcUnavailableError,
        HistoricalLogsUnavailableError,
        CodeHashMissingError,
        CodeHashMismatchError,
        ContractCodeEmptyError,
        IncidentNotFoundError,
    )
    from app.services.chain_registry import BindingNotFoundError

    institution_id = identity.institution_id
    checked: List[str] = []
    snapshot = None
    deployment_id: Optional[str] = None

    # ---- 1. tenant-scoped case + evidence authorization (404 at the route)
    case = session.execute(
        select(Case).where(Case.institution_id == institution_id, Case.id == request.case_id)
    ).scalars().first()
    if not case:
        raise CaseAccessDeniedError(
            f"Case {request.case_id} not found for institution {institution_id}"
        )

    evidence_rows = list(
        session.execute(
            select(EvidenceObject).where(
                EvidenceObject.institution_id == institution_id,
                EvidenceObject.case_id == request.case_id,
                EvidenceObject.evidence_id.in_(request.evidence_ids),
            )
        ).scalars().all()
    )
    by_ev = {row.evidence_id: row for row in evidence_rows}
    missing = [ev for ev in request.evidence_ids if ev not in by_ev]
    if missing:
        raise EvidenceAccessDeniedError(
            f"Evidence {missing} not found within case {request.case_id} for institution"
        )

    # ---- 2. deployment binding (absence = unavailable, never trust)
    if chain_registry is None:
        from app.services.chain_registry import ChainRegistry
        chain_registry = ChainRegistry()
    try:
        binding = chain_registry.resolve(institution_id)
    except BindingNotFoundError as exc:
        return _unavailable([f"{REASON_BINDING}: {exc}"], checked=request.evidence_ids)
    deployment_id = binding.deployment_id

    # ---- 3. snapshot: reuse the pinned one or take a new pin
    try:
        if request.snapshot_id:
            snapshot = _load_snapshot(session, institution_id, request.snapshot_id)
        else:
            snapshot = reader.take_snapshot(binding)
    except SnapshotNotFoundError:
        raise
    except RpcUnavailableError as exc:
        return _unavailable([f"{REASON_RPC}: {exc}"], deployment_id=deployment_id,
                            checked=request.evidence_ids)

    def finish_unavailable(reasons, head=None, count=None):
        sid = _persist_snapshot(session, institution_id, request.case_id, snapshot,
                                deployment_id, head, count, "unavailable", reasons,
                                request.evidence_ids, existing_id=snapshot.id)
        return _unavailable(reasons, snapshot_id=sid, deployment_id=deployment_id,
                            checked=request.evidence_ids)

    def finish_invalid(reasons, head=None, count=None):
        sid = _persist_snapshot(session, institution_id, request.case_id, snapshot,
                                deployment_id, head, count, "invalid", reasons,
                                request.evidence_ids, existing_id=snapshot.id)
        return _invalid(reasons, snapshot_id=sid, deployment_id=deployment_id,
                        checked=request.evidence_ids)

    # ---- 4. contract code hash AT the snapshot block
    try:
        reader.verify_code_hash(binding, snapshot)
    except CodeHashMissingError as exc:
        return _unavailable([f"{REASON_CODEHASH_MISSING}: {exc}"], deployment_id=deployment_id,
                            checked=request.evidence_ids)
    except ContractCodeEmptyError as exc:
        return finish_unavailable([f"{REASON_CONTRACT_EMPTY}: {exc}"])
    except CodeHashMismatchError as exc:
        return finish_invalid([f"{REASON_CODEHASH_MISMATCH}: {exc}"])
    except RpcUnavailableError as exc:
        return finish_unavailable([f"{REASON_RPC}: {exc}"])

    # ---- 5. incident resolution at the pin
    try:
        case_ref = _case_reference_hash(binding, institution_id, request.case_id)
        incident_id_str = reader.incident_for_case(binding, case_ref, snapshot)
        if int(incident_id_str) == 0:
            return finish_invalid(
                [f"{REASON_NOT_ANCHORED}: no incident anchored for case {request.case_id}"]
            )
        incident = reader.read_incident(binding, int(incident_id_str), snapshot)
    except RpcUnavailableError as exc:
        return finish_unavailable([f"{REASON_RPC}: {exc}"])
    except IncidentNotFoundError as exc:
        return finish_invalid([f"{REASON_NOT_ANCHORED}: {exc}"])

    head = incident.head_entry_hash
    count = incident.evidence_count

    # ---- 6. canonical entry chain at the pin (links, hashes, count/head)
    chain_reasons: List[str] = []
    prev_hash = "0x" + "00" * 32
    for entry in incident.entries:
        if entry.previous_entry_hash and entry.previous_entry_hash.lower() != prev_hash.lower():
            chain_reasons.append(
                f"{REASON_CHAIN_LINK}: entry {entry.evidence_id} previous_entry_hash mismatch"
            )
        v2 = EvidenceV2(
            schema_version=2,
            chain_id=binding.chain_id,
            contract_address=binding.forensic_trail_address(),
            incident_id=int(entry.incident_id),
            evidence_id=int(entry.evidence_id),
            submitted_by=entry.submitted_by,
            timestamp=entry.timestamp,
            evidence_type_hash=entry.evidence_type_hash,
            description_hash=entry.description_hash,
            evidence_hash=entry.evidence_hash,
            previous_entry_hash=entry.previous_entry_hash or prev_hash,
        )
        computed = hash_entry(v2)
        if not entry.entry_hash or computed.lower() != entry.entry_hash.lower():
            chain_reasons.append(
                f"{REASON_CHAIN_LINK}: entry {entry.evidence_id} hash mismatch"
            )
        prev_hash = entry.entry_hash or computed
    if incident.evidence_count != len(incident.entries):
        chain_reasons.append(
            f"{REASON_CHAIN_LINK}: count {incident.evidence_count} != entries {len(incident.entries)}"
        )
    if chain_reasons:
        return finish_invalid(chain_reasons, head=head, count=count)

    entries_by_request = {e.request_id: e for e in incident.entries if e.request_id}

    # ---- 7. per-evidence checks
    reasons: List[str] = []
    for ev_id in request.evidence_ids:
        checked.append(ev_id)
        row = by_ev[ev_id]

        anchor = session.execute(
            select(EvidenceAnchor).where(
                EvidenceAnchor.institution_id == institution_id,
                EvidenceAnchor.evidence_id == ev_id,
            ).order_by(EvidenceAnchor.created_at.desc())
        ).scalars().first()
        if anchor is None:
            reasons.append(f"{REASON_ANCHOR_RECORD}: {ev_id}")
            continue
        request_id = anchor.anchor_request_id

        entry = entries_by_request.get(request_id)
        if entry is None:
            reasons.append(f"{REASON_NOT_ANCHORED}: {ev_id} (request {request_id} absent at pin)")
            continue

        # stored manifest presence (honest classification, never retro-signed)
        if not row.manifest_envelope_json or not row.manifest_digest:
            reasons.append(f"{REASON_LEGACY_UNATTESTED}: {ev_id}")
            continue

        # on-chain commitment == SHA-256 of the stored canonical SIGNED envelope
        try:
            chain_digest = reader.get_manifest_digest(binding, request_id, snapshot)
        except RpcUnavailableError as exc:
            return finish_unavailable([f"{REASON_RPC}: {exc}"], head=head, count=count)
        if chain_digest is None:
            reasons.append(f"{REASON_CHAIN_GENERATED_UNATTESTED}: {ev_id}")
            continue
        if chain_digest.lower() != ("0x" + row.manifest_digest).lower():
            reasons.append(
                f"{REASON_COMMITMENT_MISMATCH}: {ev_id} stored envelope digest != anchored digest"
            )
            continue

        # Ed25519 signature against the external trust registry; the anchor
        # block time is the PROVEN trusted time (envelope and commitment are
        # in the same transaction).
        try:
            envelope = json.loads(row.manifest_envelope_json)
        except (ValueError, TypeError):
            reasons.append(f"{REASON_MANIFEST_INVALID}: {ev_id} (unparsable envelope)")
            continue
        trusted_time = datetime.fromtimestamp(entry.timestamp, tz=timezone.utc)
        sig = verifier.verify_manifest(envelope, trusted_time)
        if sig.status == "invalid":
            reasons.append(f"{REASON_MANIFEST_INVALID}: {ev_id} ({sig.reason})")
            continue
        if sig.status == "unavailable":
            return finish_unavailable(
                [f"{REASON_KEY_TIME_UNPROVEN}: {ev_id} ({sig.reason})"], head=head, count=count
            )

        body = envelope.get("body", {}) if isinstance(envelope, dict) else {}
        if (
            body.get("institution_id") != institution_id
            or body.get("case_id") != request.case_id
            or body.get("evidence_id") != ev_id
            or int(body.get("object_version", -1)) != int(row.object_version)
        ):
            reasons.append(f"{REASON_MANIFEST_BINDING}: {ev_id}")
            continue

        # REAL bytes through the R06 store (GCM-gated)
        try:
            data, _meta = store.open(institution_id, ev_id, row.object_version)
        except FileNotFoundError:
            reasons.append(f"{REASON_FILE_MISSING}: {ev_id}")
            continue
        except ValueError:
            reasons.append(f"{REASON_FILE_TAMPERED}: {ev_id}")
            continue
        data_sha = hashlib.sha256(data).hexdigest()
        if data_sha.lower() != str(row.sha256_hash).lower():
            reasons.append(f"{REASON_FILE_HASH}: {ev_id}")
            continue

        # writer authorization BEFORE the append event (ordered replay)
        try:
            authorized = reader.writer_authorized_at(
                binding, entry.submitted_by, entry.event_position
            )
        except HistoricalLogsUnavailableError as exc:
            return finish_unavailable(
                [f"{REASON_HISTORICAL_LOGS}: {exc}"], head=head, count=count
            )
        except RpcUnavailableError as exc:
            return finish_unavailable([f"{REASON_RPC}: {exc}"], head=head, count=count)
        if not authorized:
            reasons.append(
                f"{REASON_WRITER}: {ev_id} (writer {entry.submitted_by} not authorized before append)"
            )
            continue

    if reasons:
        return finish_invalid(reasons, head=head, count=count)

    # ---- 8. re-check the pinned block_hash right before the verdict
    try:
        if not reader.recheck_block_hash(snapshot):
            return finish_unavailable([REASON_SNAPSHOT_REORGED], head=head, count=count)
    except RpcUnavailableError as exc:
        return finish_unavailable([f"{REASON_RPC}: {exc}"], head=head, count=count)

    sid = _persist_snapshot(session, institution_id, request.case_id, snapshot, deployment_id,
                            head, count, "verified", [], request.evidence_ids,
                            existing_id=snapshot.id)
    return VerificationResult(
        status="verified",
        reasons=[],
        snapshot_id=sid,
        checked_evidence_ids=request.evidence_ids,
        deployment_id=deployment_id,
    )
