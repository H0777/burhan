import pytest
from app.schemas.evidence import EvidenceV2, EvidenceVerificationRequest, hash_entry
from app.services.evidence_verifier import verify_evidence


class MockRpcClient:
    def __init__(self, incident_exists=True, on_chain_entries=None, is_writer_authorized=True, raises=False, block_number=12345, block_hash="0xabcd1234"):
        self.incident_exists = incident_exists
        self.on_chain_entries = on_chain_entries or []
        self.is_writer_authorized = is_writer_authorized
        self.raises = raises
        self.block_number = block_number
        self.block_hash = block_hash

    def get_incident(self, incident_id):
        if self.raises:
            raise ConnectionError("RPC node connection refused")
        if not self.incident_exists:
            return None
        return {"id": incident_id, "evidence_count": len(self.on_chain_entries)}

    def get_evidence_chain(self, incident_id):
        if self.raises:
            raise ConnectionError("RPC node connection refused")
        return self.on_chain_entries

    def is_evidence_writer(self, address):
        if self.raises:
            raise ConnectionError("RPC node connection refused")
        return self.is_writer_authorized

    def get_block(self, block_tag="latest"):
        if self.raises:
            raise ConnectionError("RPC node connection refused")
        return {"number": self.block_number, "hash": self.block_hash}


def create_sample_entries():
    e1 = EvidenceV2(
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        incident_id=1,
        evidence_id=1,
        submittedBy="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        timestamp=1700000000,
        evidence_type_hash="0x123a5497ddd3854640d2f1e471ce2687cecb761a0d1fd430a84e0a50fc1153e1",
        description_hash="0x61efed381d345eeeb087742eaef3161fbadb38db458121712b9747ff1549383b",
        evidence_hash="0xfc8d7a5c80e91926d9a2169193f7086bd2c410ed8e781f556b1a20160e4ea0b5",
        previous_entry_hash="0x0000000000000000000000000000000000000000000000000000000000000000",
    )
    e1.entry_hash = hash_entry(e1)

    e2 = EvidenceV2(
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        incident_id=1,
        evidence_id=2,
        submittedBy="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        timestamp=1700000060,
        evidence_type_hash="0xb5a5c133e3c9768b2448f8a81a76678cbcf26a6ed103f5882e0dec5c9cb51f05",
        description_hash="0x705635dc41ef1b2fbc16d33b916021299d4cb1d1e1757a42670c7ca0df7faf93",
        evidence_hash="0x5519bcb524512d3d9506b16560815ce61f7a9a85192e6114def45ba1346d1830",
        previous_entry_hash=e1.entry_hash,
    )
    e2.entry_hash = hash_entry(e2)

    return [e1, e2]


def test_verified_valid_chain():
    entries = create_sample_entries()
    rpc = MockRpcClient(incident_exists=True, on_chain_entries=[e.model_dump() for e in entries], is_writer_authorized=True)
    req = EvidenceVerificationRequest(
        incident_id=1,
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        entries=entries,
    )
    result = verify_evidence(req, rpc_client=rpc)
    assert result.status == "verified"
    assert result.provenance_status == "verified_institutional_writer"
    assert len(result.checked_entries) == 2
    assert result.block_number == 12345
    assert result.block_hash == "0xabcd1234"
    assert len(result.reasons) == 0


def test_invalid_altered_content_hash_mismatch():
    entries = create_sample_entries()
    # Alter the entry hash of entry 2 without modifying content
    entries[1].entry_hash = "0x1111111111111111111111111111111111111111111111111111111111111111"
    rpc = MockRpcClient(incident_exists=True, on_chain_entries=[e.model_dump() for e in entries], is_writer_authorized=True)
    req = EvidenceVerificationRequest(
        incident_id=1,
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        entries=entries,
    )
    result = verify_evidence(req, rpc_client=rpc)
    assert result.status == "invalid"
    assert any("hash mismatch" in r.lower() for r in result.reasons)


def test_invalid_broken_chain_previous_entry_hash():
    entries = create_sample_entries()
    # Alter previous_entry_hash to break the chain link
    entries[1].previous_entry_hash = "0x2222222222222222222222222222222222222222222222222222222222222222"
    entries[1].entry_hash = hash_entry(entries[1]) # Recomputed hash is valid for payload, but chain link is broken!
    rpc = MockRpcClient(incident_exists=True, on_chain_entries=[e.model_dump() for e in entries], is_writer_authorized=True)
    req = EvidenceVerificationRequest(
        incident_id=1,
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        entries=entries,
    )
    result = verify_evidence(req, rpc_client=rpc)
    assert result.status == "invalid"
    assert any("broken chain" in r.lower() or "previous_entry_hash" in r.lower() for r in result.reasons)


def test_unavailable_rpc_connection_failure():
    entries = create_sample_entries()
    rpc = MockRpcClient(raises=True)
    req = EvidenceVerificationRequest(
        incident_id=1,
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        entries=entries,
    )
    result = verify_evidence(req, rpc_client=rpc)
    assert result.status == "unavailable"
    assert any("rpc" in r.lower() or "unavailable" in r.lower() for r in result.reasons)
    # Ensure no raw stack traces in reasons
    for r in result.reasons:
        assert "Traceback" not in r


def test_legacy_unrestricted_submission_warning():
    entries = create_sample_entries()
    # Writer is not an institutional allowlisted writer
    rpc = MockRpcClient(incident_exists=True, on_chain_entries=[e.model_dump() for e in entries], is_writer_authorized=False)
    req = EvidenceVerificationRequest(
        incident_id=1,
        schema_version=2,
        chain_id=1337,
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        entries=entries,
    )
    result = verify_evidence(req, rpc_client=rpc)
    assert result.status == "verified"
    assert result.provenance_status == "legacy_unrestricted_submission"
    assert any("unrestricted" in r.lower() or "warning" in r.lower() for r in result.reasons)


def test_v2_verify_endpoint_http():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routes.v2.evidence import set_rpc_provider

    entries = create_sample_entries()
    mock_rpc = MockRpcClient(
        incident_exists=True,
        on_chain_entries=[e.model_dump() for e in entries],
        is_writer_authorized=True,
        block_number=99999,
        block_hash="0x9999ffff"
    )
    set_rpc_provider(mock_rpc)
    try:
        client = TestClient(app)
        payload = {
            "incidentId": 1,
            "schemaVersion": 2,
            "chainId": 1337,
            "contractAddress": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
            "entries": [e.model_dump(by_alias=True) for e in entries]
        }
        res = client.post("/api/v2/evidence/verify", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "verified"
        assert data["provenance_status"] == "verified_institutional_writer"
        assert data["block_number"] == 99999
        assert data["block_hash"] == "0x9999ffff"
        assert len(data["checked_entries"]) == 2
    finally:
        set_rpc_provider(None)

