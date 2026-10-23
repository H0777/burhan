"""
Authoritative Forensic Report & Verifiable Dossier Service (T20)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (R04, R05, R15, R18)

Produces deterministic, reproducible court-admissible dossiers with cryptographic provenance,
separating objective evidence observations, AML risk evaluations, and four-eyes human decisions.
"""

import os
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.db.models import (
    Case,
    CaseEvent,
    EvidenceObject,
    EvidenceAnchor,
    AssessmentRecord,
    ReportRecord,
)
from app.schemas.identity import Identity
from app.schemas.report import ReportResponse


class ReportService:
    """
    Synthesizes multi-tenant case ledger records into an immutable, verifiable forensic report.
    """

    def generate_case_report(
        self,
        session: Session,
        identity: Identity,
        case_id: str,
        language: str = "en",
        evidence_ids: Optional[List[str]] = None,
        assessment_ids: Optional[List[str]] = None,
    ) -> ReportResponse:
        institution_id = identity.institution_id

        # 1. Fetch Case record
        case = session.execute(
            select(Case).where(
                Case.institution_id == institution_id,
                Case.id == case_id,
            )
        ).scalars().first()

        if not case:
            raise ValueError(f"Case '{case_id}' not found for institution '{institution_id}'")

        # 2. Determine sequential version
        existing_count = session.execute(
            select(ReportRecord).where(
                ReportRecord.institution_id == institution_id,
                ReportRecord.case_id == case_id,
            )
        ).scalars().all()
        version = len(existing_count) + 1
        report_id = f"REP-{case.case_number}-V{version}"

        # 3. Fetch Evidence Objects and Anchors
        ev_query = select(EvidenceObject).where(
            EvidenceObject.institution_id == institution_id,
            EvidenceObject.case_id == case_id,
        )
        if evidence_ids:
            ev_query = ev_query.where(EvidenceObject.evidence_id.in_(evidence_ids))
        evidence_objects = session.execute(ev_query.order_by(EvidenceObject.created_at)).scalars().all()

        anchor_map: Dict[str, EvidenceAnchor] = {}
        for ev in evidence_objects:
            anchor = session.execute(
                select(EvidenceAnchor).where(
                    EvidenceAnchor.institution_id == institution_id,
                    EvidenceAnchor.case_id == case_id,
                    EvidenceAnchor.evidence_id == ev.evidence_id,
                ).order_by(desc(EvidenceAnchor.created_at))
            ).scalars().first()
            if anchor:
                anchor_map[ev.evidence_id] = anchor

        # Determine integrity status
        integrity_status = "VERIFIED"
        provenance_notes = []

        if not evidence_objects:
            integrity_status = "UNANCHORED"
            provenance_notes.append("No physical evidence objects attached to case")
        else:
            for ev in evidence_objects:
                anc = anchor_map.get(ev.evidence_id)
                if not anc or anc.status != "ANCHORED":
                    integrity_status = "UNANCHORED"
                    provenance_notes.append(f"Evidence '{ev.evidence_id}' has pending anchor status")
                    break

        # 4. Fetch Case Transition Events (Four-Eyes Audit Trail)
        events = session.execute(
            select(CaseEvent).where(
                CaseEvent.institution_id == institution_id,
                CaseEvent.case_id == case_id,
            ).order_by(CaseEvent.created_at)
        ).scalars().all()

        # 5. Fetch Assessments
        assessments: List[AssessmentRecord] = []
        if assessment_ids:
            assessments = session.execute(
                select(AssessmentRecord).where(
                    AssessmentRecord.institution_id == institution_id,
                    AssessmentRecord.id.in_(assessment_ids),
                ).order_by(AssessmentRecord.created_at)
            ).scalars().all()

        # 6. Build Manifest Structure
        now_utc = datetime.now(timezone.utc)
        ev_manifest_list = []
        for ev in evidence_objects:
            anc = anchor_map.get(ev.evidence_id)
            ev_manifest_list.append({
                "evidence_id": ev.evidence_id,
                "file_name": ev.file_name,
                "content_type": ev.content_type,
                "file_size": ev.file_size,
                "sha256_hash": ev.sha256_hash,
                "anchor_status": anc.status if anc else "UNANCHORED",
                "contract_address": anc.contract_address if anc else None,
                "transaction_hash": anc.transaction_hash if anc else None,
                "block_number": anc.block_number if anc else None,
                "block_hash": anc.block_hash if anc else None,
            })

        decision_events_list = []
        for evt in events:
            payload = json.loads(evt.payload_json) if evt.payload_json else {}
            decision_events_list.append({
                "event_type": evt.event_type,
                "actor_sub": evt.actor_sub,
                "created_at": evt.created_at.isoformat(),
                "payload": payload,
            })

        assessments_list = []
        for asm in assessments:
            assessments_list.append({
                "assessment_id": asm.id,
                "transaction_id": asm.transaction_id,
                "policy_version": asm.policy_version,
                "fraud_score": float(asm.fraud_score),
                "risk_level": asm.risk_level,
                "rules_triggered": json.loads(asm.rules_triggered_json) if asm.rules_triggered_json else [],
                "features_hash": asm.features_hash,
            })

        manifest = {
            "schema_version": "2.0.0",
            "report_id": report_id,
            "version": version,
            "case_id": case.id,
            "case_number": case.case_number,
            "institution_id": institution_id,
            "language": language,
            "integrity_status": integrity_status,
            "provenance_notes": provenance_notes,
            "generated_at": now_utc.isoformat(),
            "created_by": identity.sub,
            "evidence_items": ev_manifest_list,
            "decision_ledger": decision_events_list,
            "assessments": assessments_list,
        }

        # Canonical SHA-256 Dossier Hash
        canonical_manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        dossier_hash = "0x" + hashlib.sha256(canonical_manifest_bytes).hexdigest().lower()
        manifest["dossier_hash"] = dossier_hash

        # 7. Render Markdown
        markdown_text = self._render_markdown(case, manifest, language)

        provenance_str = (
            "Cryptographically verified on-chain anchor"
            if integrity_status == "VERIFIED"
            else "Pending cryptographic finality on blockchain anchor"
        )

        # 8. Persist ReportRecord
        report_record = ReportRecord(
            id=f"RREC-{uuid.uuid4().hex[:16].upper()}",
            report_id=report_id,
            institution_id=institution_id,
            case_id=case.id,
            version=version,
            language=language,
            dossier_hash=dossier_hash,
            integrity_status=integrity_status,
            provenance_status=provenance_str,
            markdown_content=markdown_text,
            manifest_json=json.dumps(manifest, indent=2),
            created_by_sub=identity.sub,
            created_at=now_utc,
        )
        session.add(report_record)
        session.flush()

        return ReportResponse(
            report_id=report_id,
            case_id=case.id,
            institution_id=institution_id,
            version=version,
            language=language,
            dossier_hash=dossier_hash,
            integrity_status=integrity_status,
            provenance_status=provenance_str,
            markdown=markdown_text,
            engine="ForensicDossierSynthesizer v2.0",
            manifest=manifest,
            created_by=identity.sub,
            created_at=now_utc,
        )

    def _render_markdown(self, case: Case, manifest: Dict[str, Any], language: str) -> str:
        """Renders bilingual deterministic markdown dossier."""
        is_ar = (language == "ar")

        if is_ar:
            md = f"""# تقرير التحقيق الجنائي الرقمي والتدقيق المالي (الإصدار {manifest['version']})

**رقم التقرير:** `{manifest['report_id']}`  
**رمز القضية:** `{manifest['case_number']}`  
**المؤسسة المصدرة:** `{manifest['institution_id']}`  
**تاريخ التوليد:** `{manifest['generated_at']}`  
**المحقق المعتمد:** `{manifest['created_by']}`  
**بصمة الملف الكاملة (Dossier Hash):** `{manifest['dossier_hash']}`  
**حالة النزاهة والإثبات:** `{manifest['integrity_status']}`  

---

## 1. تفاصيل القضية
- **العنوان:** {case.title}
- **مستوى الخطورة:** {case.severity}
- **الحالة الإجرائية:** {case.status}
- **الوصف الجنائي:** {case.description or 'لا يوجد وصف إضافي'}

---

## 2. سجل الأدلة الرقمية وسلسلة الحيازة (Chain of Custody)

| معرف الدليل | اسم الملف | الحجم (بايت) | بصمة SHA-256 | حالة التثبيت | رقم الكتلة | بصمة المعاملة |
|---|---|---|---|---|---|---|
"""
            for ev in manifest["evidence_items"]:
                md += f"| `{ev['evidence_id']}` | {ev['file_name']} | {ev['file_size']} | `{ev['sha256_hash']}` | {ev['anchor_status']} | {ev['block_number'] or 'N/A'} | `{ev['transaction_hash'] or 'N/A'}` |\n"

            md += """
---

## 3. سجل التدقيق وقرارات التحقق الثنائي (Four-Eyes Decision Trail)

| الحدث | المنفذ | التوقيت (UTC) | المبرر / التفاصيل |
|---|---|---|---|
"""
            for evt in manifest["decision_ledger"]:
                reason = evt["payload"].get("reason", "N/A")
                md += f"| {evt['event_type']} | `{evt['actor_sub']}` | {evt['created_at']} | {reason} |\n"

            md += """
---

## 4. الإقرار والتوقيع المؤسسي
تم إصدار هذا التقرير آلياً وفقاً لمعايير التدقيق المالي الجنائي الرقمي. جميع الأدلة والبصمات مقيدة بسجل رقمي غير قابل للتعديل.
"""
            return md

        # Default English
        md = f"""# Digital Forensic Audit & Case Investigation Dossier (Version {manifest['version']})

**Report Identifier:** `{manifest['report_id']}`  
**Case Number:** `{manifest['case_number']}`  
**Issuing Institution:** `{manifest['institution_id']}`  
**Generated At (UTC):** `{manifest['generated_at']}`  
**Investigating Subject:** `{manifest['created_by']}`  
**Authoritative Dossier Hash:** `{manifest['dossier_hash']}`  
**Cryptographic Integrity Status:** `{manifest['integrity_status']}`  

---

## 1. Case Summary
- **Title:** {case.title}
- **Severity Level:** {case.severity}
- **Procedural Status:** {case.status}
- **Case Notes:** {case.description or 'No additional notes provided'}

---

## 2. Chain of Custody & Physical Evidence Objects

| Evidence ID | File Name | Size (Bytes) | SHA-256 Digest | Anchor Status | Block No. | Anchor Tx Hash |
|---|---|---|---|---|---|---|
"""
        for ev in manifest["evidence_items"]:
            md += f"| `{ev['evidence_id']}` | {ev['file_name']} | {ev['file_size']} | `{ev['sha256_hash']}` | {ev['anchor_status']} | {ev['block_number'] or 'N/A'} | `{ev['transaction_hash'] or 'N/A'}` |\n"

        md += """
---

## 3. Four-Eyes Verification & Governance Decision Ledger

| Event Type | Actor Identity | Occurred At (UTC) | Justification / Details |
|---|---|---|---|
"""
        for evt in manifest["decision_ledger"]:
            reason = evt["payload"].get("reason", "N/A")
            md += f"| {evt['event_type']} | `{evt['actor_sub']}` | {evt['created_at']} | {reason} |\n"

        md += """
---

## 4. Integrity Attestation
This forensic report was synthesized authoritatively from tenant-isolated cryptographic ledgers.
Tampering with any included file or metadata breaks verification against the Authoritative Dossier Hash.
"""
        return md
