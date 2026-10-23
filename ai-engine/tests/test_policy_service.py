"""
Policy Service & Currency Precision Tests (T06)
Specification §7, §8 (R07)

Tests:
1. Exact threshold boundary behavior (threshold - 1, threshold, threshold + 1 minor unit).
2. Huge amounts (> 2^53, up to uint256 max) without floating-point precision loss.
3. Strict Decimal & scale validation (ETH scale=18, IQD scale=3; rejection of mismatched/corrupt scales).
4. Asset policy separation (IQD rules never applied to ETH and vice versa).
5. RPC source reading & graceful degradation.
"""

from decimal import Decimal
import pytest
from app.schemas.policy import PolicyVersion, PolicyThresholds
from app.services.policy_service import (
    get_active_policy,
    to_minor_units,
    from_minor_units,
    format_amount,
    evaluate_policy_thresholds
)


class MockAuditEngineClient:
    def __init__(self, active_policy_index=0, raises=False):
        self.active_policy_index = active_policy_index
        self.raises = raises

    def get_active_thresholds(self):
        if self.raises:
            raise ConnectionError("RPC provider timed out")
        if self.active_policy_index == 0:
            # IRAQ_CBI: large = 10,000 ETH, daily = 50,000 ETH, maxDaily = 20, maxSingle = 100,000 ETH, kyc = 5,000 ETH
            return {
                "large_threshold": "10000000000000000000000",
                "daily_limit": "50000000000000000000000",
                "max_daily_transactions": 20,
                "max_single_transaction": "100000000000000000000000",
                "kyc_threshold": "5000000000000000000000",
                "policy_index": 0,
                "policy_name": "IRAQ_CBI"
            }
        else:
            # GLOBAL_FATF: large = 8,000 ETH, daily = 30,000 ETH, maxDaily = 15, maxSingle = 50,000 ETH, kyc = 3,000 ETH
            return {
                "large_threshold": "8000000000000000000000",
                "daily_limit": "30000000000000000000000",
                "max_daily_transactions": 15,
                "max_single_transaction": "50000000000000000000000",
                "kyc_threshold": "3000000000000000000000",
                "policy_index": 1,
                "policy_name": "GLOBAL_FATF"
            }


def test_eth_policy_threshold_boundaries():
    """
    R07: Test exact boundaries: threshold - 1 wei, threshold, threshold + 1 wei.
    10,000 ETH threshold = 10000 * 10^18 wei = 10000000000000000000000 wei.
    """
    policy = get_active_policy(asset="ETH")
    threshold_wei = int(policy.thresholds.large_transaction)
    assert threshold_wei == 10000 * 10**18

    # threshold - 1 wei -> NOT large
    eval_under = evaluate_policy_thresholds(
        amount_minor=str(threshold_wei - 1),
        asset="ETH",
        policy=policy
    )
    assert eval_under["is_large_transaction"] is False
    assert eval_under["requires_kyc"] is True # 9999.999... ETH > 5000 ETH KYC limit

    # exact threshold -> triggers large transaction
    eval_exact = evaluate_policy_thresholds(
        amount_minor=str(threshold_wei),
        asset="ETH",
        policy=policy
    )
    assert eval_exact["is_large_transaction"] is True

    # threshold + 1 wei -> triggers large transaction
    eval_over = evaluate_policy_thresholds(
        amount_minor=str(threshold_wei + 1),
        asset="ETH",
        policy=policy
    )
    assert eval_over["is_large_transaction"] is True


def test_large_amount_exceeding_2_pow_53_no_precision_loss():
    """
    Amounts > 2^53 (9,007,199,254,740,992) must not lose precision or round off.
    e.g. 50,000 ETH = 50000000000000000000000 wei (~5 * 10^22).
    """
    policy = get_active_policy(asset="ETH")
    # 50,000 ETH is daily volume limit
    limit_wei = int(policy.thresholds.daily_volume_limit)
    assert limit_wei > 2**53

    # Exact comparison at 5 * 10^22 + 1
    over_limit = str(limit_wei + 1)
    res = evaluate_policy_thresholds(amount_minor=over_limit, asset="ETH", policy=policy)
    assert res["exceeds_daily_volume"] is True

    exact_limit = str(limit_wei)
    res_exact = evaluate_policy_thresholds(amount_minor=exact_limit, asset="ETH", policy=policy)
    assert res_exact["exceeds_daily_volume"] is False


def test_decimal_conversions_and_scale_validation():
    """
    ETH scale=18, IQD scale=3.
    Conversion between minor units and decimal text.
    """
    # 9.85 ETH = 9850000000000000000 wei
    wei_str = to_minor_units("9.85", scale=18)
    assert wei_str == "9850000000000000000"
    dec_eth = from_minor_units(wei_str, scale=18)
    assert dec_eth == Decimal("9.85")

    # 15,000,000.500 IQD = 15000000500 fils (scale=3)
    fils_str = to_minor_units("15000000.500", scale=3)
    assert fils_str == "15000000500"
    dec_iqd = from_minor_units(fils_str, scale=3)
    assert dec_iqd == Decimal("15000000.500")

    # Reject invalid amount strings
    with pytest.raises(ValueError):
        to_minor_units("INVALID_NUMBER", scale=18)

    with pytest.raises(ValueError):
        to_minor_units("12.3456", scale=3)  # More decimals than scale 3!


def test_asset_policy_isolation():
    """
    R07: IQD policies must never be evaluated against ETH thresholds and vice versa.
    """
    iqd_policy = get_active_policy(asset="IQD")
    assert iqd_policy.asset == "IQD"
    assert iqd_policy.currency == "IQD"
    assert iqd_policy.scale == 3
    assert iqd_policy.policy_id == "DEMO-IQD-1"

    # Evaluating ETH with IQD policy must raise ValueError
    with pytest.raises(ValueError, match="Asset mismatch"):
        evaluate_policy_thresholds(amount_minor="1000000000000000000", asset="ETH", policy=iqd_policy)

    eth_policy = get_active_policy(asset="ETH")
    with pytest.raises(ValueError, match="Asset mismatch"):
        evaluate_policy_thresholds(amount_minor="15000000000", asset="IQD", policy=eth_policy)


def test_rpc_active_threshold_loading():
    """
    Tests live on-chain policy threshold reading via RPC client.
    """
    mock_client = MockAuditEngineClient(active_policy_index=1) # GLOBAL_FATF
    policy = get_active_policy(asset="ETH", rpc_client=mock_client)
    assert policy.version == "GLOBAL_FATF"
    assert policy.thresholds.large_transaction == "8000000000000000000000"

    # Test RPC failure raises or returns default with clear error handling
    mock_failing = MockAuditEngineClient(raises=True)
    with pytest.raises(ConnectionError):
        get_active_policy(asset="ETH", rpc_client=mock_failing)


def test_active_policy_endpoint_http():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routes.v2.policies import set_policy_rpc_provider

    client = TestClient(app)

    # 1. Default ETH policy
    res = client.get("/api/v2/policies/active?asset=ETH")
    assert res.status_code == 200
    data = res.json()
    assert data["asset"] == "ETH"
    assert data["scale"] == 18
    assert data["thresholds"]["large_transaction"] == "10000000000000000000000"

    # 2. IQD policy
    res_iqd = client.get("/api/v2/policies/active?asset=IQD")
    assert res_iqd.status_code == 200
    data_iqd = res_iqd.json()
    assert data_iqd["asset"] == "IQD"
    assert data_iqd["scale"] == 3
    assert data_iqd["policy_id"] == "DEMO-IQD-1"

    # 3. With live RPC provider
    mock_client = MockAuditEngineClient(active_policy_index=1)
    set_policy_rpc_provider(mock_client)
    try:
        res_rpc = client.get("/api/v2/policies/active?asset=ETH")
        assert res_rpc.status_code == 200
        assert res_rpc.json()["version"] == "GLOBAL_FATF"
    finally:
        set_policy_rpc_provider(None)

    # 4. Invalid asset
    res_err = client.get("/api/v2/policies/active?asset=UNSUPPORTED")
    assert res_err.status_code == 400

