"""
Unified Policy Service & Currency Precision (T06)
Specification §7, §8 (R07)

Strict decimal and minor-unit arithmetic for financial compliance policies.
Enforces:
- Exact boundary evaluations (threshold - 1, threshold, threshold + 1) in integer minor units.
- Absolute isolation between ETH (scale=18 wei) and IQD (scale=3 fils) policies.
- Elimination of floating point imprecision for amounts up to uint256 max (> 2^53).
"""

from decimal import Decimal, InvalidOperation
from typing import Optional, Dict, Any
from app.schemas.policy import PolicyVersion, PolicyThresholds


# Built-in baseline regulatory policies
DEFAULT_ETH_CBI_POLICY = PolicyVersion(
    policy_id="POLICY-ETH-CBI-V1",
    version="IRAQ_CBI",
    asset="ETH",
    currency="ETH",
    scale=18,
    thresholds=PolicyThresholds(
        large_transaction="10000000000000000000000",   # 10,000 ETH
        daily_volume_limit="50000000000000000000000",  # 50,000 ETH
        max_daily_transactions=20,
        max_single_transaction="100000000000000000000000", # 100,000 ETH
        kyc_required_threshold="5000000000000000000000",   # 5,000 ETH
    ),
    effective_at="2026-01-01T00:00:00Z",
    source="on_chain_audit_engine"
)

DEFAULT_ETH_FATF_POLICY = PolicyVersion(
    policy_id="POLICY-ETH-FATF-V1",
    version="GLOBAL_FATF",
    asset="ETH",
    currency="ETH",
    scale=18,
    thresholds=PolicyThresholds(
        large_transaction="8000000000000000000000",    # 8,000 ETH
        daily_volume_limit="30000000000000000000000",  # 30,000 ETH
        max_daily_transactions=15,
        max_single_transaction="50000000000000000000000",  # 50,000 ETH
        kyc_required_threshold="3000000000000000000000",   # 3,000 ETH
    ),
    effective_at="2026-01-01T00:00:00Z",
    source="on_chain_audit_engine"
)

DEFAULT_IQD_POLICY = PolicyVersion(
    policy_id="DEMO-IQD-1",
    version="DEMO-IQD-1",
    asset="IQD",
    currency="IQD",
    scale=3,
    thresholds=PolicyThresholds(
        large_transaction="15000000000",       # 15,000,000.000 IQD (scale=3)
        daily_volume_limit="75000000000",      # 75,000,000.000 IQD
        max_daily_transactions=20,
        max_single_transaction="150000000000", # 150,000,000.000 IQD
        kyc_required_threshold="7500000000",   # 7,500,000.000 IQD
    ),
    effective_at="2026-01-01T00:00:00Z",
    source="regulatory_policy_store"
)


def to_minor_units(amount: str | Decimal, scale: int) -> str:
    """
    Converts a human-readable decimal amount to exact minor units (wei for ETH, fils for IQD).
    Strictly verifies that decimal places do not exceed scale to prevent truncation.
    """
    try:
        dec = Decimal(str(amount))
    except (InvalidOperation, ValueError):
        raise ValueError(f"Invalid monetary decimal number: {amount}")

    # Check decimal place count
    parts = str(dec).split(".")
    if len(parts) == 2 and len(parts[1]) > scale:
        raise ValueError(f"Amount {amount} has {len(parts[1])} decimal places, exceeding scale {scale}")

    minor = int(dec * (Decimal(10) ** scale))
    return str(minor)


def from_minor_units(amount_minor: int | str, scale: int) -> Decimal:
    """
    Converts integer minor units to an exact Python Decimal without float rounding.
    """
    try:
        minor_int = int(str(amount_minor))
    except ValueError:
        raise ValueError(f"Invalid minor units integer: {amount_minor}")

    return Decimal(minor_int) / (Decimal(10) ** scale)


def format_amount(amount_minor: int | str, scale: int, currency: str) -> str:
    """
    Formats minor units to human-readable string representation with full precision.
    """
    dec = from_minor_units(amount_minor, scale)
    return f"{dec} {currency}"


def get_active_policy(
    institution_id: Optional[str] = None,
    asset: str = "ETH",
    rpc_client: Optional[object] = None
) -> PolicyVersion:
    """
    Retrieves the authoritative active compliance policy for the requested asset.
    Reconciles with on-chain AuditEngine thresholds when RPC provider is available.
    """
    asset_upper = asset.upper()

    if asset_upper == "IQD":
        policy = DEFAULT_IQD_POLICY.model_copy()
        if institution_id:
            policy.institution_id = institution_id
        return policy

    if asset_upper == "ETH":
        if rpc_client is not None:
            # Fetch live on-chain thresholds from AuditEngine contract
            data = rpc_client.get_active_thresholds()
            policy_name = data.get("policy_name", "CUSTOM")
            policy_id = f"POLICY-ETH-{policy_name}-ONCHAIN"

            thresholds = PolicyThresholds(
                large_transaction=str(data["large_threshold"]),
                daily_volume_limit=str(data["daily_limit"]),
                max_daily_transactions=int(data["max_daily_transactions"]),
                max_single_transaction=str(data["max_single_transaction"]),
                kyc_required_threshold=str(data["kyc_threshold"]),
            )

            return PolicyVersion(
                policy_id=policy_id,
                version=policy_name,
                asset="ETH",
                currency="ETH",
                scale=18,
                thresholds=thresholds,
                effective_at="2026-01-01T00:00:00Z",
                source="on_chain_audit_engine",
                institution_id=institution_id
            )

        policy = DEFAULT_ETH_CBI_POLICY.model_copy()
        if institution_id:
            policy.institution_id = institution_id
        return policy

    raise ValueError(f"Unsupported asset for policy evaluation: {asset}")


def evaluate_policy_thresholds(
    amount_minor: str,
    asset: str,
    policy: PolicyVersion
) -> Dict[str, Any]:
    """
    Evaluates an amount in minor units against policy thresholds.
    Performs exact integer arithmetic and enforces strict asset isolation.
    """
    if asset.upper() != policy.asset.upper():
        raise ValueError(
            f"Asset mismatch: Cannot evaluate asset {asset} against policy asset {policy.asset}"
        )

    try:
        amt = int(amount_minor)
    except ValueError:
        raise ValueError(f"Invalid minor units integer: {amount_minor}")

    large_tx = int(policy.thresholds.large_transaction)
    daily_limit = int(policy.thresholds.daily_volume_limit)
    kyc_limit = int(policy.thresholds.kyc_required_threshold)
    max_single = int(policy.thresholds.max_single_transaction)

    return {
        "is_large_transaction": amt >= large_tx,
        "exceeds_daily_volume": amt > daily_limit,
        "requires_kyc": amt >= kyc_limit,
        "exceeds_single_cap": amt > max_single,
        "asset": policy.asset,
        "policy_id": policy.policy_id,
        "scale": policy.scale,
    }
