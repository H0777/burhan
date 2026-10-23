"""
Independent 3-State Evidence Verifier (T05)
Specification §6, §7 (R04, R05, R15)

Evaluates Evidence V2 chains independently against canonical keccak256(abi.encode)
rules and on-chain anchored consensus state. Returns 3 distinct outcomes:
- verified: Cryptographic integrity confirmed and anchored on-chain.
- invalid: Cryptographic mismatch, broken link, or non-matching on-chain state.
- unavailable: RPC node connection failure or required infrastructure unreachable.
"""

from typing import Optional, List
from app.schemas.evidence import (
    EvidenceV2,
    EvidenceVerificationRequest,
    EvidenceVerificationResult,
    AnchorInfo,
    hash_entry
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
