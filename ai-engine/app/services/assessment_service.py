"""
Authoritative Risk Assessment & AML Evaluation Service (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (T18, R07, R12)

Executes policy-driven compliance rules and fraud detection algorithms against authoritative
server-side feature snapshots, recording immutable audit records for regulatory scrutiny.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.schemas.identity import Identity
from app.schemas.assessment import FeatureSnapshot, AssessmentResponse
from app.db.models import AssessmentRecord, TransactionRecord
from app.services.feature_service import FeatureService


class AssessmentService:
    """
    Evaluates financial transactions against regulatory AML policies and insider anomaly rules.
    """

    def __init__(self, feature_service: Optional[FeatureService] = None):
        self.feature_service = feature_service or FeatureService()

    def assess_transaction(
        self,
        session: Session,
        identity: Identity,
        transaction_id: str,
        as_of: Optional[datetime] = None,
        is_preview: bool = False,
    ) -> AssessmentResponse:
        """
        Performs authoritative or preview evaluation of a transaction.
        """
        institution_id = identity.institution_id

        # 1. Authoritative feature extraction
        snapshot, features_hash, tx, policy = self.feature_service.derive_features(
            session=session,
            institution_id=institution_id,
            transaction_id=transaction_id,
            as_of=as_of,
        )

        # 2. Rule-based evaluation
        rules_triggered: List[str] = []
        score = 5.0  # Baseline low score

        if snapshot.structuring_ratio >= 1.0 or snapshot.amount_minor >= snapshot.large_threshold_minor:
            rules_triggered.append("LARGE_TRANSACTION_EXCEEDED")
            score += 30.0

        if 0.85 <= snapshot.structuring_ratio < 1.00:
            rules_triggered.append("STRUCTURING_SMURFING_SUSPECTED")
            score += 35.0

        if snapshot.sender_daily_volume_minor >= snapshot.daily_volume_limit_minor:
            rules_triggered.append("DAILY_VOLUME_EXCEEDED")
            score += 25.0

        if snapshot.sender_daily_count >= snapshot.max_daily_transactions:
            rules_triggered.append("DAILY_COUNT_EXCEEDED")
            score += 20.0

        if snapshot.sender_window_burst_10m >= 3:
            rules_triggered.append("VELOCITY_BURST_SUSPECTED")
            score += 20.0

        if snapshot.is_after_hours:
            rules_triggered.append("AFTER_HOURS_EXECUTION")
            score += 15.0

        # Cap score at 100.0
        final_score = min(100.0, score)

        # Categorize risk level
        if final_score >= 75.0:
            risk_level = "CRITICAL"
        elif final_score >= 50.0:
            risk_level = "HIGH"
        elif final_score >= 25.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        structuring_detected = "STRUCTURING_SMURFING_SUSPECTED" in rules_triggered
        now_utc = datetime.now(timezone.utc)
        eval_as_of = as_of if as_of is not None else tx.occurred_at
        if eval_as_of.tzinfo is None:
            eval_as_of = eval_as_of.replace(tzinfo=timezone.utc)

        # 3. Handle Simulation / Preview
        if is_preview:
            return AssessmentResponse(
                assessment_id=f"SIM-{uuid.uuid4().hex[:12].upper()}",
                transaction_id=tx.id,
                institution_id=institution_id,
                as_of=eval_as_of,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                fraud_score=round(final_score, 2),
                risk_level=risk_level,
                structuring_detected=structuring_detected,
                rules_triggered=rules_triggered,
                feature_snapshot=snapshot.model_dump(),
                features_hash=features_hash,
                engine_version="2.0.0",
                model_loaded=False,
                source="SIMULATION",
                created_at=now_utc,
            )

        # 4. Handle Persistent Authoritative Assessment
        assessment_id = f"ASM-{uuid.uuid4().hex[:16].upper()}"
        record = AssessmentRecord(
            id=assessment_id,
            institution_id=institution_id,
            transaction_id=tx.id,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            fraud_score=int(final_score),
            risk_level=risk_level,
            structuring_detected=structuring_detected,
            rules_triggered_json=json.dumps(rules_triggered),
            feature_snapshot_json=json.dumps(snapshot.model_dump()),
            features_hash=features_hash,
            engine_version="2.0.0",
            model_loaded=False,
            source="AUTHORITATIVE",
            created_at=now_utc,
        )
        session.add(record)

        # Update denormalized transaction risk score
        tx.risk_score = int(final_score)
        session.flush()

        return AssessmentResponse(
            assessment_id=record.id,
            transaction_id=tx.id,
            institution_id=institution_id,
            as_of=eval_as_of,
            policy_id=record.policy_id,
            policy_version=record.policy_version,
            fraud_score=float(record.fraud_score),
            risk_level=record.risk_level,
            structuring_detected=record.structuring_detected,
            rules_triggered=rules_triggered,
            feature_snapshot=snapshot.model_dump(),
            features_hash=record.features_hash,
            engine_version=record.engine_version,
            model_loaded=record.model_loaded,
            source=record.source,
            created_at=record.created_at,
        )
