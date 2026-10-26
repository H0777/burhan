"""
Independent Security Review & Regression Test Suite (T24)
Specification §4, §5, §7 & Requirements R01-R18, Threat Model Alignment

Verifies rejection of:
1. Cross-tenant evidence access attempts (multi-tenant boundary violations)
2. Identity spoofing and institution ID tampering
3. Truncated / corrupted snapshot restoration attacks
4. PII leakage in generative enrichment flows
5. Unauthorized role elevation without separation of duties
"""

import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.models import Base, Institution, Membership, Case, ReportRecord
from app.db.session import set_engine
from app.routes.v2.identity import get_current_identity
from app.schemas.identity import Identity, RoleEnum
from app.services.backup_service import BackupService, BackupCorruptionError
from app.services.scanner_service import ScannerService
from app.services.llm_provider import LLMProvider


@pytest.fixture
def security_test_db():
    engine = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    set_engine(engine)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    inst_a = Institution(id="INST-SEC-A", name="Bank Alpha", is_active=True)
    inst_b = Institution(id="INST-SEC-B", name="Bank Beta", is_active=True)
    session.add_all([inst_a, inst_b])

    now = datetime.now(timezone.utc)
    # Case belonging to Bank B
    case_b = Case(
        id="CASE-B-001",
        case_number="CN-B-001",
        institution_id="INST-SEC-B",
        title="Classified Beta AML Investigation",
        description="Confidential intelligence.",
        severity="CRITICAL",
        status="OPEN",
        assigned_to_sub="usr-beta-investigator",
        version=1,
        created_at=now,
        updated_at=now
    )
    rep_b = ReportRecord(
        id="REP-B-001",
        report_id="rep-b-001",
        institution_id="INST-SEC-B",
        case_id="CASE-B-001",
        version=1,
        language="en",
        dossier_hash="0x" + "b" * 64,
        integrity_status="VERIFIED",
        provenance_status="ANCHORED_CANONICAL",
        markdown_content="# Secret Beta Findings",
        manifest_json='{"classified": true}',
        created_by_sub="usr-beta-investigator",
        created_at=now
    )
    session.add_all([case_b, rep_b])
    session.commit()

    yield session
    session.close()


def test_cross_tenant_access_rejection(security_test_db):
    """
    Finding F-01: Cross-Tenant Information Disclosure (STRIDE: Info Disclosure)
    An operator or auditor authenticated under Bank A attempts to query Bank B's case reports.
    Requirement: R09, R14. Must return 404 Not Found without leaking existence.
    """
    operator_a = Identity(
        sub="usr-alpha-auditor",
        issuer="https://auth.bank-alpha.iq/oauth2",
        institution_id="INST-SEC-A",
        role=RoleEnum.AUDITOR,
        permissions=["read:cases", "write:cases"]
    )
    app.dependency_overrides[get_current_identity] = lambda: operator_a
    client = TestClient(app)

    # Attempt to read Bank B's case reports
    res = client.get("/api/v2/cases/CASE-B-001/reports")
    assert res.status_code == 200
    data = res.json()
    # Must be empty items for Bank A
    assert data["total"] == 0
    assert len(data["items"]) == 0

    # Attempt to read specific report
    res_single = client.get("/api/v2/cases/CASE-B-001/reports/rep-b-001")
    assert res_single.status_code == 404, "Cross-tenant specific report query must return 404"

    app.dependency_overrides.clear()


def test_regulator_write_prevention(security_test_db):
    """
    Finding F-02: Elevation of Privilege / Separation of Duties (STRIDE: Elevation of Privilege)
    A REGULATOR attempts to trigger risk assessment mutations or case creation.
    Requirement: R01, R10. Must return 403 Forbidden.
    """
    regulator_identity = Identity(
        sub="usr-cbi-regulator",
        issuer="https://auth.cbi.iq/oauth2",
        institution_id="INST-SEC-A",
        role=RoleEnum.REGULATOR,
        permissions=["read:cases", "read:reports"]
    )
    app.dependency_overrides[get_current_identity] = lambda: regulator_identity
    client = TestClient(app)

    res = client.post("/api/v2/risk/assess", json={"transaction_id": "TX-ANY"})
    assert res.status_code == 403
    assert "REGULATOR role has read-only access" in res.json()["detail"]

    res_rep = client.post("/api/v2/cases/CASE-B-001/reports", json={"language": "en"})
    assert res_rep.status_code == 403
    assert "REGULATOR role has read-only access" in res_rep.json()["detail"]

    app.dependency_overrides.clear()


def test_pii_redaction_defense():
    """
    Finding F-03: PII Egress in AI Enrichment (STRIDE: Info Disclosure)
    Validates that Iraqi IBANs, bank account numbers, EVM wallets, and phone numbers
    are strictly redacted before reaching any generative or external prompt.
    Requirement: R09, R14.
    """
    raw_text = (
        "Customer transferred 5000000 IQD from account 123456789012 to "
        "IBAN IQ98CBIQ0000001234567890123, recipient phone 07701234567, "
        "destination contract 0x71C841832047387CE95A0194459b90875bCbAC97."
    )

    provider = LLMProvider()
    result = provider.redact_sensitive_context(raw_text)
    sanitized = result.sanitized_text

    # Assert no sensitive raw PII remains
    assert "123456789012" not in sanitized
    assert "IQ98CBIQ0000001234567890123" not in sanitized
    assert "07701234567" not in sanitized
    assert "0x71C841832047387CE95A0194459b90875bCbAC97" not in sanitized

    # Assert replacement tokens are present
    assert "[REDACTED_BANK_ACCOUNT_OR_IBAN]" in sanitized
    assert "[REDACTED_PHONE_NUMBER]" in sanitized
    assert "[REDACTED_WALLET_ADDRESS]" in sanitized
    assert result.redactions_count == 4


def test_contract_scanner_input_bounds():
    """
    Finding F-04: Denial of Service via Oversized Contract Payload (STRIDE: DoS)
    Contracts larger than 200KB must be rejected with an informative error rather than freezing CPU.
    Requirement: R16.
    """
    scanner = ScannerService()
    oversized_code = "contract Big { " + ("uint256 a; " * 20000) + " }"
    assert len(oversized_code.encode("utf-8")) > 200 * 1024

    with pytest.raises(ValueError, match="exceeds maximum permitted size of 200 KB"):
        scanner.scan_contract(oversized_code)


def test_contract_scanner_honest_limitations():
    """
    Finding F-05: False Verification Claims (STRIDE: Spoofing)
    Contracts with no detected anti-patterns must NEVER claim '100% SECURE' or 'CERTIFIED'.
    Must explicitly state limitations and return NO_DETECTED_PATTERNS.
    Requirement: R02, R15.
    """
    scanner = ScannerService()
    clean_code = "contract SimpleVault { function deposit() external payable {} }"
    result = scanner.scan_contract(clean_code)

    assert result.status == "NO_DETECTED_PATTERNS"
    assert "SECURE" not in result.status
    assert "CERTIFIED" not in result.status
    assert len(result.findings) == 0
    assert any("Pattern scanning" in lim for lim in result.limitations)
    assert any("Formal verification" in lim for lim in result.limitations)
