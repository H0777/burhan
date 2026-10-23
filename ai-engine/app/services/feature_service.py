"""
Authoritative Server-Side Feature Extraction Service (V2)
Cyber-Forensic Auditing Framework - Specification §7 & §8 (T18, R07, R12)

Derives factual historical and point-in-time features strictly from the authoritative database
and active regulatory policies, rejecting any client-side self-asserted risk inputs.
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, func, and_

from app.config import settings
from app.db.models import TransactionRecord
from app.schemas.assessment import FeatureSnapshot
from app.services.policy_service import get_active_policy


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class FeatureService:
    """
    Computes deterministic, authoritative feature snapshots for transactions.
    """

    def derive_features(
        self,
        session: Session,
        institution_id: str,
        transaction_id: str,
        as_of: Optional[datetime] = None,
    ) -> Tuple[FeatureSnapshot, str, TransactionRecord, object]:
        """
        Derives historical features for a transaction from indexed ledger data.
        Returns:
            Tuple of (FeatureSnapshot, features_hash, TransactionRecord, policy)
        """
        # 1. Authoritative transaction lookup
        tx = session.execute(
            select(TransactionRecord).where(
                TransactionRecord.institution_id == institution_id,
                (TransactionRecord.id == transaction_id) | (TransactionRecord.external_id == transaction_id),
            )
        ).scalars().first()

        if not tx:
            raise ValueError(
                f"Transaction '{transaction_id}' not found for institution '{institution_id}'"
            )

        # 2. Point-in-time reference
        eval_time = as_of if as_of is not None else tx.occurred_at
        if eval_time.tzinfo is None:
            eval_time = eval_time.replace(tzinfo=timezone.utc)

        # 3. Active policy for asset
        policy = get_active_policy(institution_id=institution_id, asset=tx.currency)
        large_threshold_minor = int(policy.thresholds.large_transaction)
        daily_volume_limit_minor = int(policy.thresholds.daily_volume_limit)
        max_daily_transactions = int(policy.thresholds.max_daily_transactions)

        # 4. 24-hour historical window for the same sender
        window_24h_start = eval_time - timedelta(hours=24)
        prior_txs_24h = session.execute(
            select(TransactionRecord).where(
                TransactionRecord.institution_id == institution_id,
                TransactionRecord.sender_ref == tx.sender_ref,
                TransactionRecord.occurred_at >= window_24h_start,
                TransactionRecord.occurred_at <= eval_time,
            )
        ).scalars().all()

        sender_daily_volume_minor = sum(t.amount_minor for t in prior_txs_24h)
        sender_daily_count = len(prior_txs_24h)

        # 5. 10-minute velocity burst window
        window_10m_start = eval_time - timedelta(minutes=10)
        burst_txs = [t for t in prior_txs_24h if _ensure_utc(t.occurred_at) >= window_10m_start]
        sender_window_burst_10m = len(burst_txs)

        # 6. Baghdad Business Hours check (UTC+3; Banking: 08:00 to 17:00 Baghdad Time => 05:00 to 14:00 UTC)
        # Using UTC hour check aligned with settings.BUSINESS_HOUR_START and END
        utc_hour = eval_time.hour
        is_after_hours = bool(
            utc_hour < settings.BUSINESS_HOUR_START or utc_hour >= settings.BUSINESS_HOUR_END
        )

        # 7. Structuring ratio against reporting threshold
        structuring_ratio = (
            round(float(tx.amount_minor) / float(large_threshold_minor), 4)
            if large_threshold_minor > 0
            else 0.0
        )

        # 8. Construct validated FeatureSnapshot
        snapshot = FeatureSnapshot(
            amount_minor=tx.amount_minor,
            currency=tx.currency,
            scale=tx.scale,
            sender_daily_volume_minor=sender_daily_volume_minor,
            sender_daily_count=sender_daily_count,
            sender_window_burst_10m=sender_window_burst_10m,
            is_after_hours=is_after_hours,
            structuring_ratio=structuring_ratio,
            large_threshold_minor=large_threshold_minor,
            daily_volume_limit_minor=daily_volume_limit_minor,
            max_daily_transactions=max_daily_transactions,
        )

        # 9. Canonical JSON serialization and SHA-256 features hash
        canonical_json = json.dumps(snapshot.model_dump(), sort_keys=True, separators=(",", ":"))
        features_hash = "0x" + hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        return snapshot, features_hash, tx, policy
