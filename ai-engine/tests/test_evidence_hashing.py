import json
from pathlib import Path
import pytest

from app.schemas.evidence import EvidenceV2, hash_entry, DOMAIN, SCHEMA_VERSION

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "shared" / "fixtures" / "evidence-v2.json"


@pytest.fixture
def fixtures_data():
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_constants_parity(fixtures_data):
    assert SCHEMA_VERSION == 2
    assert DOMAIN.lower() == fixtures_data["domain"].lower()


def test_fixtures_parity(fixtures_data):
    for fix in fixtures_data["fixtures"]:
        entry = EvidenceV2(
            schema_version=fix.get("schemaVersion", 2),
            chain_id=int(fix["chainId"]),
            contract_address=fix["contractAddress"],
            incident_id=int(fix["incidentId"]),
            evidence_id=int(fix["evidenceId"]),
            submitted_by=fix["submittedBy"],
            timestamp=int(fix["timestamp"]),
            evidence_type_hash=fix["evidenceTypeHash"],
            description_hash=fix["descriptionHash"],
            evidence_hash=fix["evidenceHash"],
            previous_entry_hash=fix["previousEntryHash"],
        )
        computed = hash_entry(entry)
        assert computed.lower() == fix["expectedEntryHash"].lower(), f"Mismatch in {fix['name']}"


def test_field_variations_sensitivity(fixtures_data):
    base_expected = fixtures_data["fixtures"][0]["expectedEntryHash"].lower()
    for var in fixtures_data["variations"]:
        entry = EvidenceV2(
            schema_version=var.get("schemaVersion", 2),
            chain_id=int(var["chainId"]),
            contract_address=var["contractAddress"],
            incident_id=int(var["incidentId"]),
            evidence_id=int(var["evidenceId"]),
            submitted_by=var["submittedBy"],
            timestamp=int(var["timestamp"]),
            evidence_type_hash=var["evidenceTypeHash"],
            description_hash=var["descriptionHash"],
            evidence_hash=var["evidenceHash"],
            previous_entry_hash=var["previousEntryHash"],
        )
        computed = hash_entry(entry).lower()
        assert computed == var["expectedEntryHash"].lower(), f"Mismatch in {var['name']}"
        assert computed != base_expected, f"Variation {var['name']} did not change hash"
