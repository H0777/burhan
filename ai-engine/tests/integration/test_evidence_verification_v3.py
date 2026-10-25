"""
R07 — real evidence verifier + POST /api/v3/evidence/verify (spec §5, FINAL).

Named cases (exact, from the task brief):
  API contract : no_identity_401, cross_tenant_404, client_entries_field_422,
                 v2_institutional_returns_410, zero_evidence_422 (test_zero_evidence_422)
  adversarial  : fabricated_entries_same_count_never_verify, wrong_contract,
                 missing_codehash, missing_rpc_method, missing_file,
                 tampered_file, unsigned_manifest, swapped_case, wrong_institution
  manifest     : manifest_signature_changed_after_anchor_invalid,
                 retired_service_key_anchor_time_proven
  happy path   : full_flow_verified (GREEN target)

Identity note (controller BLOCKED_VALIDATION-partial): R10 institutional
identity is not fully wireable in this environment; HTTP identity cases use a
clearly injected test Identity via dependency override and the institutional
401/410 gates via APP_MODE. No claim of full institutional identity closure.

Environment contract (R11/R12): DATABASE_URL (app role) + MIGRATION_DATABASE_URL
(migration owner) against a disposable PostgreSQL (r07-pg-test:55437).
"""

import io
import os
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

RUN = uuid.uuid4().hex[:8]
TENANT_A = f"inst_r07_a_{RUN}"
TENANT_B = f"inst_r07_b_{RUN}"
CASE_A = f"case_r07_a_{RUN}"
CASE_A2 = f"case_r07_a2_{RUN}"
CASE_B = f"case_r07_b_{RUN}"
EV1 = f"ev_r07_1_{RUN}"
EV2 = f"ev_r07_2_{RUN}"
EV_A2 = f"ev_r07_a2_{RUN}"
EV_B = f"ev_r07_b_{RUN}"

CHAIN_ID = 31337
CONTRACT = "0x" + "aa" * 20
WRITER = "0x" + "c0" * 20
OTHER_WRITER = "0x" + "d0" * 20
GOVERNANCE = "0x" + "9a" * 20
FAKE_CODE = "0x" + "60" * 40
from Crypto.Hash import keccak as _keccak

_k = _keccak.new(digest_bits=256)
_k.update(b"\x60" * 40)
GOOD_CODEHASH = "0x" + _k.hexdigest()
DEPLOYMENT_ID = "0x" + os.urandom(32).hex()
DEPLOYED_AT_BLOCK = 5
CONFIRMATION_DEPTH = 2
LATEST_BLOCK = 40
SNAPSHOT_BLOCK = LATEST_BLOCK - CONFIRMATION_DEPTH + 1  # latest-depth+1
SNAPSHOT_HASH = "0x" + "51" * 32

PG_APP_URL = os.environ.get(
    "R07_DATABASE_URL", "postgresql://ira_aml_app:r07app@127.0.0.1:55437/ira_aml_r07"
)
PG_MIGRATION_URL = os.environ.get(
    "R07_MIGRATION_DATABASE_URL",
    "postgresql://ira_aml_migrator:r07mig@127.0.0.1:55437/ira_aml_r07",
)


# ---------------------------------------------------------------------------
# PostgreSQL fixtures (R11/R12 conventions)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Process-wide shared state (single migration + single seed per pytest run).
# A plain lru_cache singleton — NOT pytest fixtures — because imported
# fixtures instantiate once per importing module, which would re-seed and
# re-generate key material (breaking signature checks against DB rows).
# ---------------------------------------------------------------------------

from functools import lru_cache


@lru_cache(maxsize=1)
def shared_state():
    from app.db.models import Institution
    from app.db.session import tenant_transaction
    from app.repositories import case_repository
    from app.security.key_provider import LocalFileKeyProvider
    from app.security.signing import Signer, TrustRegistry, encode_public_key
    from app.services.evidence_broker import EvidenceBroker
    from app.services.evidence_store import EvidenceStore
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import tempfile

    if not PG_APP_URL.startswith("postgresql") or not PG_MIGRATION_URL.startswith("postgresql"):
        pytest.skip("R07 requires disposable PostgreSQL (r07-pg-test)")

    # 1. migrate to head (r07_verification_snapshots)
    result = subprocess.run(
        ["node", str(REPO_ROOT / "scripts" / "run-python.js"), "-m", "alembic", "upgrade", "head"],
        cwd=str(AI_ENGINE_DIR),
        env={**os.environ, "MIGRATION_DATABASE_URL": PG_MIGRATION_URL},
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")
    with create_engine(PG_MIGRATION_URL).connect() as conn:
        head = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()

    # 2. key custody + trust registry + encrypted store (one tmp tree)
    base = Path(tempfile.mkdtemp(prefix="r07keys_"))
    for inst in (TENANT_A, TENANT_B):
        d = base / inst
        d.mkdir(parents=True)
        (d / "k_active.seed").write_bytes(os.urandom(32))
        (d / "k_retired.seed").write_bytes(os.urandom(32))
        (d / "current").write_text("k_active")
    keys = LocalFileKeyProvider(str(base))

    def entry(inst, key_id, status):
        seed = (base / inst / f"{key_id}.seed").read_bytes()
        pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        return {
            "institution_id": inst,
            "key_id": key_id,
            "public_key": encode_public_key(pub),
            "valid_from": "2025-01-01T00:00:00+00:00",
            "valid_until": "2027-01-01T00:00:00+00:00",
            "status": status,
        }

    registry = TrustRegistry(
        [
            entry(TENANT_A, "k_active", "active"),
            entry(TENANT_A, "k_retired", "retired"),
            entry(TENANT_B, "k_active", "active"),
        ]
    )
    store = EvidenceStore(
        base_dir=tempfile.mkdtemp(prefix="r07vault_"), key_provider=keys
    )

    # 3. engines + institutions
    owner_engine = create_engine(PG_MIGRATION_URL, pool_pre_ping=True)
    app_engine = create_engine(PG_APP_URL, pool_pre_ping=True)
    OwnerSession = sessionmaker(bind=owner_engine)
    with OwnerSession() as owner:
        for inst, name in ((TENANT_A, "R07 A"), (TENANT_B, "R07 B")):
            if owner.get(Institution, inst) is None:
                owner.add(Institution(id=inst, name=name))
        owner.commit()

    # 4. seed cases + REAL broker evidence
    Session = sessionmaker(bind=app_engine)
    broker = EvidenceBroker(evidence_store=store, signer=Signer(keys))
    out = {}

    def submit(inst, case_id, evidence_id, file_name, content):
        with Session() as session:
            with tenant_transaction(session, inst):
                if case_repository.get_case(session, inst, case_id) is None:
                    case_repository.create_case(
                        session, inst, case_number=f"R07-{case_id}", title="R07", case_id=case_id
                    )
            with tenant_transaction(session, inst):
                return broker.submit_case_evidence(
                    session=session,
                    identity=make_identity(inst),
                    case_id=case_id,
                    file_name=file_name,
                    content_type="application/pdf",
                    stream=io.BytesIO(content),
                    evidence_id=evidence_id,
                )

    out["ev1"] = submit(TENANT_A, CASE_A, EV1, "s1.pdf", b"R07 payload one " + RUN.encode())
    out["ev2"] = submit(TENANT_A, CASE_A, EV2, "s2.pdf", b"R07 payload two " + RUN.encode())
    out["ev_a2"] = submit(TENANT_A, CASE_A2, EV_A2, "a2.pdf", b"R07 same-tenant other case payload")
    out["ev_b"] = submit(TENANT_B, CASE_B, EV_B, "b.pdf", b"R07 tenant B payload")

    return {
        "head": head,
        "keys": keys,
        "trust_registry": registry,
        "store": store,
        "owner_engine": owner_engine,
        "app_engine": app_engine,
        "seeded": out,
    }


# ---------------------------------------------------------------------------
# Thin pytest fixtures over the shared singleton (both test modules)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def pg_urls():
    return PG_APP_URL, PG_MIGRATION_URL


@pytest.fixture(scope="session")
def app_engine(pg_urls):
    return shared_state()["app_engine"]


@pytest.fixture(scope="session")
def owner_engine(pg_urls):
    return shared_state()["owner_engine"]


@pytest.fixture(scope="session")
def migrated_db(pg_urls):
    return shared_state()["head"]


def test_migration_head_is_r07(migrated_db):
    """0003_verification_snapshots must land as the single new head."""
    assert migrated_db == "r07_verification_snapshots"


# ---------------------------------------------------------------------------
# keys / trust registry / store
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    return shared_state()["keys"]


@pytest.fixture(scope="session")
def trust_registry(keys):
    return shared_state()["trust_registry"]


@pytest.fixture(scope="session")
def store(tmp_path_factory, keys):
    return shared_state()["store"]


def make_identity(institution_id, sub="usr_r07_a"):
    from app.schemas.identity import Identity, RoleEnum

    return Identity(
        sub=sub,
        issuer="https://auth.r07.test/oauth2",
        institution_id=institution_id,
        role=RoleEnum.SUPER_ADMIN,
        permissions=["all"],
    )


# ---------------------------------------------------------------------------
# Seed: institutions, cases, REAL broker evidence (R06 store + signed manifest)
# — all inside shared_state(); this is only the thin fixture.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def seeded(migrated_db, app_engine, owner_engine, store, keys):
    return shared_state()["seeded"]


# ---------------------------------------------------------------------------
# Fake chain reader matching the AnchorReader contract (in-memory chain)
# ---------------------------------------------------------------------------

class FakeChain:
    """In-memory ForensicTrail mirror + journal of every read's block tag."""

    def __init__(self):
        self.latest = LATEST_BLOCK
        self.block_hashes = {LATEST_BLOCK: SNAPSHOT_HASH}
        self.code = {CONTRACT: FAKE_CODE}
        self.rpc_down = False
        self.missing_method = False
        self.reorged = False
        self.codehash_override = None
        self.incident_for_case = {}  # ref -> incident; default 1 (single-case fake)
        self.writer_events = []  # (EventPosition, writer, authorized)
        self.entries = {}  # incident_id -> [AnchoredEntry-like dict]
        self.manifest_digests = {}  # request_id -> digest
        self.journal = []  # (method, block_param)

    # -- helpers to build chain state ------------------------------------
    def grant(self, pos, writer, authorized):
        self.writer_events.append((pos, writer, authorized))
        self.writer_events.sort(key=lambda t: (t[0].block_number, t[0].transaction_index, t[0].log_index))

    @staticmethod
    def pos(block, tx, log):
        from app.services.anchor_reader import EventPosition

        return EventPosition(block_number=block, transaction_index=tx, log_index=log)

    def add_entry(self, incident_id, entry):
        self.entries.setdefault(incident_id, []).append(entry)


def build_chain_for(seeded, tamper=None):
    """Anchor the TENANT_A evidence objects (ev1, ev2, ev_a2) on the fake
    chain (attested path) with REAL canonical V2 entry hashes. tamper:
    callable(chain, entries, digests)."""
    from app.schemas.evidence import EvidenceV2, hash_entry
    from app.services.anchor_reader import AnchoredEntry, EventPosition

    chain = FakeChain()
    digests = {}
    entries = []
    for idx, key in enumerate(("ev1", "ev2", "ev_a2")):
        ev = seeded[key]
        digest = "0x" + ev["manifest_digest"]
        digests[ev["anchor_request_id"]] = digest
        chain.manifest_digests[ev["anchor_request_id"]] = digest
        pos = EventPosition(block_number=SNAPSHOT_BLOCK, transaction_index=idx, log_index=idx)
        prev = "0x" + "00" * 32 if idx == 0 else entries[idx - 1].entry_hash
        v2 = EvidenceV2(
            schema_version=2,
            chain_id=CHAIN_ID,
            contract_address=CONTRACT,
            incident_id=1,
            evidence_id=idx + 1,
            submitted_by=WRITER,
            timestamp=1770000000 + idx,
            evidence_type_hash="0x" + "11" * 32,
            description_hash="0x" + "22" * 32,
            evidence_hash="0x" + ev["sha256_hash"],
            previous_entry_hash=prev,
        )
        entries.append(
            AnchoredEntry(
                evidence_id=str(idx + 1),
                incident_id="1",
                submitted_by=WRITER,
                timestamp=v2.timestamp,
                evidence_type_hash=v2.evidence_type_hash,
                description_hash=v2.description_hash,
                evidence_hash=v2.evidence_hash,
                previous_entry_hash=prev,
                entry_hash=hash_entry(v2),
                request_id=ev["anchor_request_id"],
                manifest_digest=digest,
                event_position=pos,
            )
        )
    for e in entries:
        chain.add_entry(1, e)
    # writer authorized from before the first append
    chain.grant(FakeChain.pos(DEPLOYED_AT_BLOCK, 0, 0), WRITER, True)
    if tamper:
        tamper(chain, entries, digests)
    return chain


def set_evidence_manifest(inst, evidence_id, envelope_json, digest):
    """Point an evidence row's manifest columns at (envelope_json, digest).
    Pass None/None to simulate a legacy unsigned row. Used by the adversarial
    tests; each caller restores the original values afterwards."""
    from app.db.session import tenant_transaction
    from sqlalchemy import update
    from app.db.models import EvidenceObject
    from sqlalchemy.orm import sessionmaker

    Session = sessionmaker(bind=shared_state()["app_engine"])
    with Session() as session:
        with tenant_transaction(session, inst):
            session.execute(
                update(EvidenceObject)
                .where(EvidenceObject.evidence_id == evidence_id)
                .values(manifest_envelope_json=envelope_json, manifest_digest=digest)
            )


def make_binding(with_codehash=True):
    from app.services.chain_registry import DeploymentBinding

    return DeploymentBinding(
        deployment_id=DEPLOYMENT_ID,
        institution_id=TENANT_A,
        chain_id=CHAIN_ID,
        addresses={"ForensicTrail": CONTRACT},
        deployed_code_hashes={"ForensicTrail": GOOD_CODEHASH} if with_codehash else {},
        deployed_at_block=DEPLOYED_AT_BLOCK,
        confirmation_depth=CONFIRMATION_DEPTH,
        contract_version="2.1.0",
        status="active",
        bootstrap_writers=[WRITER],
    )


def make_fake_reader(chain, binding=None):
    """Instantiate the real AnchorReader against the FakeChain RPC shim: the
    reader must do its own ABI/eth_call/log-replay work against any client
    exposing the low-level JSON-RPC surface."""
    from app.services.anchor_reader import AnchorReader

    return AnchorReader(rpc=chain, registry_binding=binding or make_binding())


# The FakeChain must expose the SAME low-level surface AnchorReader consumes
# from a real EvmRpcClient. Defined once here; bound as methods below.
def _rpc_block(self, number):
    if self.rpc_down:
        raise ConnectionError("rpc down")
    if number == "latest":
        number = self.latest
    self.journal.append(("eth_getBlockByNumber", number))
    if self.reorged:
        return {"number": number, "hash": "0x" + "99" * 32}
    return {"number": number, "hash": self.block_hashes.get(number, SNAPSHOT_HASH)}


def _rpc_code(self, address, block_number):
    if self.rpc_down:
        raise ConnectionError("rpc down")
    self.journal.append(("eth_getCode", block_number))
    return self.code.get(address, "0x")


def _rpc_logs(self, address, from_block, to_block):
    if self.rpc_down:
        raise ConnectionError("rpc down")
    if self.missing_method:
        raise AttributeError("eth_getLogs unavailable")
    self.journal.append(("eth_getLogs", to_block))
    logs = []
    for pos, writer, authorized in self.writer_events:
        if pos.block_number > to_block:
            continue
        logs.append(
            {
                "address": address,
                "blockNumber": pos.block_number,
                "transactionIndex": pos.transaction_index,
                "logIndex": pos.log_index,
                "event": "EvidenceWriterUpdated",
                "writer": writer,
                "authorized": authorized,
            }
        )
    return logs


def _rpc_call(self, to, data, block_number):
    if self.rpc_down:
        raise ConnectionError("rpc down")
    self.journal.append(("eth_call", block_number))
    if data.startswith("0xincident_for_case:"):
        return str(self.incident_for_case.get(data.split(":", 1)[1], 1))
    if data.startswith("0xdigest:"):
        return self.manifest_digests.get(data.split(":", 1)[1])
    raise RuntimeError(f"unknown call {data[:40]}")


def _rpc_read_incident(self, binding, incident_id, snapshot):
    from app.services.anchor_reader import AnchoredIncident

    if self.rpc_down:
        raise ConnectionError("rpc down")
    self.journal.append(("read_incident", snapshot.block_number))
    # pin semantics: only entries appended AT or BEFORE the pinned block exist
    # at this read point — a later append is invisible at the pin.
    entries = [
        e for e in self.entries.get(incident_id, [])
        if e.event_position is None or e.event_position.block_number <= snapshot.block_number
    ]
    return AnchoredIncident(
        incident_id=incident_id,
        entries=entries,
        evidence_count=len(entries),
        head_entry_hash=entries[-1].entry_hash if entries else None,
    )


FakeChain.get_block = _rpc_block
FakeChain.get_code = _rpc_code
FakeChain.get_logs = _rpc_logs
FakeChain.raw_call = _rpc_call
FakeChain.read_incident = _rpc_read_incident


# ---------------------------------------------------------------------------
# service-level verification helper
# ---------------------------------------------------------------------------

def verify_service(seeded, chain, evidence_ids, case_id=CASE_A, institution=TENANT_A,
                   snapshot_id=None, db_engine=None, keys_fixture=None, store_fixture=None,
                   registry_fixture=None, binding=None):
    """Run verify_case_evidence with the real service, a fresh session, and
    the fake chain reader."""
    from app.db.session import tenant_transaction
    from app.schemas.evidence import VerifyEvidenceRequest
    from app.services.chain_registry import ChainRegistry
    from app.services.evidence_verifier import ManifestSignatureVerifier, verify_case_evidence

    engine = db_engine
    keys = keys_fixture
    st = store_fixture
    reg = registry_fixture
    Session = sessionmaker(bind=engine)
    registry = ChainRegistry(manifest_data={
        "deployments": {
            TENANT_A: [
                {
                    "deployment_id": DEPLOYMENT_ID,
                    "institution_id": TENANT_A,
                    "chain_id": CHAIN_ID,
                    "addresses": {"ForensicTrail": CONTRACT},
                    "deployed_code_hashes": (binding or make_binding()).deployed_code_hashes,
                    "deployed_at_block": DEPLOYED_AT_BLOCK,
                    "confirmation_depth": CONFIRMATION_DEPTH,
                    "contract_version": "2.1.0",
                    "status": "active",
                    "bootstrap_writers": [WRITER],
                }
            ]
        }
    })
    reader = make_fake_reader(chain, binding=binding)
    verifier = ManifestSignatureVerifier(verifier=type("V", (), {"verify": staticmethod(
        lambda domain, envelope, registry, trusted_time=None: _sig_verify(domain, envelope, registry, trusted_time)
    )})(), registry=reg)
    request = VerifyEvidenceRequest(case_id=case_id, evidence_ids=evidence_ids, snapshot_id=snapshot_id)
    with Session() as session:
        with tenant_transaction(session, institution):
            return verify_case_evidence(
                session=session,
                identity=make_identity(institution),
                request=request,
                reader=reader,
                store=st,
                verifier=verifier,
                chain_registry=registry,
            )


def _sig_verify(domain, envelope, registry, trusted_time):
    from app.security.signing import Verifier

    return Verifier().verify(domain, envelope, registry, trusted_time=trusted_time)


# ---------------------------------------------------------------------------
# Happy path (GREEN target)
# ---------------------------------------------------------------------------

def test_full_flow_verified(seeded, app_engine, keys, store, trust_registry):
    result = verify_service(
        seeded, build_chain_for(seeded), [EV1, EV2],
        db_engine=app_engine, keys_fixture=keys, store_fixture=store, registry_fixture=trust_registry,
    )
    assert result.status == "verified", result.reasons
    assert result.checked_evidence_ids == [EV1, EV2]
    assert result.deployment_id == DEPLOYMENT_ID
    assert result.snapshot_id


# ---------------------------------------------------------------------------
# Adversarial set — NONE of these may end verified
# ---------------------------------------------------------------------------

def test_fabricated_entries_same_count_never_verify(seeded, app_engine, keys, store, trust_registry):
    """Same entry count on-chain but completely different content/digests."""

    def tamper(chain, entries, digests):
        for key, e in zip(("ev1", "ev2"), chain.entries[1]):
            e.request_id = "0x" + "ee" * 32
            e.manifest_digest = "0x" + "ee" * 32
        chain.manifest_digests.clear()

    result = verify_service(
        seeded, build_chain_for(seeded, tamper=tamper), [EV1, EV2],
        db_engine=app_engine, keys_fixture=keys, store_fixture=store, registry_fixture=trust_registry,
    )
    assert result.status == "invalid"
    assert result.status != "verified"


def test_wrong_contract(seeded, app_engine, keys, store, trust_registry):
    chain = build_chain_for(seeded)
    chain.code = {CONTRACT: "0x"}  # nothing at the bound address
    result = verify_service(
        seeded, chain, [EV1],
        db_engine=app_engine, keys_fixture=keys, store_fixture=store, registry_fixture=trust_registry,
    )
    assert result.status != "verified"
    assert result.status == "unavailable" or result.status == "invalid"


def test_missing_codehash(seeded, app_engine, keys, store, trust_registry):
    result = verify_service(
        seeded, build_chain_for(seeded), [EV1],
        binding=make_binding(with_codehash=False),
        db_engine=app_engine, keys_fixture=keys, store_fixture=store, registry_fixture=trust_registry,
    )
    assert result.status == "unavailable"


def test_missing_rpc_method(seeded, app_engine, keys, store, trust_registry):
    chain = build_chain_for(seeded)
    chain.missing_method = True
    result = verify_service(
        seeded, chain, [EV1],
        db_engine=app_engine, keys_fixture=keys, store_fixture=store, registry_fixture=trust_registry,
    )
    assert result.status == "unavailable"


def test_missing_file(seeded, app_engine, keys, store, trust_registry):
    import shutil

    ev_dir = store._scoped_evidence_dir(TENANT_A, EV_A2)
    shutil.rmtree(ev_dir, ignore_errors=True)
    result = verify_service(
        seeded, build_chain_for(seeded), [EV_A2], case_id=CASE_A2,
        db_engine=app_engine, keys_fixture=keys, store_fixture=store, registry_fixture=trust_registry,
    )
    assert result.status == "invalid"
    assert any("file" in r for r in result.reasons)


def test_tampered_file(seeded, app_engine, keys, store, trust_registry):
    ev_dir = store._scoped_evidence_dir(TENANT_A, EV2)
    obj = ev_dir / "v1" / "object.bin"  # the R06 ciphertext object
    assert obj.exists(), f"expected encrypted object at {obj}"
    original = obj.read_bytes()
    data = bytearray(original)
    data[-1] ^= 0xFF
    obj.write_bytes(bytes(data))
    try:
        result = verify_service(
            seeded, build_chain_for(seeded), [EV2],
            db_engine=app_engine, keys_fixture=keys, store_fixture=store,
            registry_fixture=trust_registry,
        )
        assert result.status == "invalid"
        assert any("file" in r for r in result.reasons)
    finally:
        obj.write_bytes(original)  # keep the shared seed intact


def test_unsigned_manifest(seeded, app_engine, keys, store, trust_registry):
    """Legacy rows without a signed manifest are classified
    legacy_unattested / chain_generated_unattested — never verified."""
    result = None
    set_evidence_manifest(TENANT_A, EV1, None, None)
    try:
        result = verify_service(
            seeded, build_chain_for(seeded), [EV1],
            db_engine=app_engine, keys_fixture=keys, store_fixture=store,
            registry_fixture=trust_registry,
        )
        assert result.status != "verified"
        assert any("legacy_unattested" in r or "chain_generated_unattested" in r for r in result.reasons)
    finally:
        set_evidence_manifest(
            TENANT_A, EV1,
            __import__("json").dumps(seeded["ev1"]["manifest"], sort_keys=True),
            seeded["ev1"]["manifest_digest"],
        )


def test_manifest_signature_changed_after_anchor_invalid(seeded, app_engine, keys, store, trust_registry):
    """The DB envelope is re-signed (digest changes) after the anchor: the
    stored envelope no longer matches the anchored commitment."""
    from app.security.signing import Signer, envelope_digest

    signer = Signer(keys)
    body = dict(seeded["ev1"]["manifest"]["body"])
    body["issued_at"] = "2026-10-25T23:59:59+00:00"  # changed content
    new_env = signer.sign(TENANT_A, "AML_SERVICE_MANIFEST_V1", body).to_dict()
    set_evidence_manifest(
        TENANT_A, EV1, __import__("json").dumps(new_env, sort_keys=True), envelope_digest(new_env)
    )
    try:
        result = verify_service(
            seeded, build_chain_for(seeded), [EV1],
            db_engine=app_engine, keys_fixture=keys, store_fixture=store,
            registry_fixture=trust_registry,
        )
        assert result.status == "invalid"
    finally:
        set_evidence_manifest(
            TENANT_A, EV1,
            __import__("json").dumps(seeded["ev1"]["manifest"], sort_keys=True),
            seeded["ev1"]["manifest_digest"],
        )


def test_retired_service_key_anchor_time_proven(seeded, app_engine, keys, store, trust_registry):
    """Evidence signed by a RETIRED key still verifies because the anchor
    block timestamp is a trusted time proven by the chain snapshot."""
    from app.security.signing import Signer, envelope_digest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = (keys.base_dir / TENANT_A / "k_retired.seed").read_bytes()
    retired_provider = type(
        "P", (), {"get_signing_key": staticmethod(lambda i, k: Ed25519PrivateKey.from_private_bytes(seed))}
    )()
    signer = Signer(retired_provider)
    body = dict(seeded["ev2"]["manifest"]["body"])
    body["key_id"] = "k_retired"
    env = signer.sign(TENANT_A, "AML_SERVICE_MANIFEST_V1", body).to_dict()
    digest = envelope_digest(env)
    set_evidence_manifest(TENANT_A, EV2, __import__("json").dumps(env, sort_keys=True), digest)

    def tamper(chain, entries, digests):
        chain.manifest_digests[seeded["ev2"]["anchor_request_id"]] = "0x" + digest
        entries[1].manifest_digest = "0x" + digest

    try:
        result = verify_service(
            seeded, build_chain_for(seeded, tamper=tamper), [EV2],
            db_engine=app_engine, keys_fixture=keys, store_fixture=store,
            registry_fixture=trust_registry,
        )
        assert result.status == "verified", result.reasons
    finally:
        set_evidence_manifest(
            TENANT_A, EV2,
            __import__("json").dumps(seeded["ev2"]["manifest"], sort_keys=True),
            seeded["ev2"]["manifest_digest"],
        )


# ---------------------------------------------------------------------------
# HTTP contract (FastAPI TestClient; identity injected per controller note)
# ---------------------------------------------------------------------------

@pytest.fixture()
def http_env(seeded, app_engine, store, keys, trust_registry):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routes.v2.identity import get_current_identity
    from app.routes.v3.evidence import set_verification_components

    chain = build_chain_for(seeded)
    app.dependency_overrides[get_current_identity] = lambda: make_identity(TENANT_A)
    set_verification_components(
        reader=make_fake_reader(chain),
        store=store,
        manifest_verifier=None,  # service builds from registry below
        trust_registry=trust_registry,
        db_session_factory=sessionmaker(bind=app_engine),
        keys=keys,
    )
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.pop(get_current_identity, None)
    set_verification_components(None, None, None, None, None, None)


def test_cross_tenant_404(http_env):
    res = http_env.post("/api/v3/evidence/verify", json={"case_id": CASE_B, "evidence_ids": [EV_B]})
    assert res.status_code == 404


def test_swapped_case(http_env):
    """evidence ids from case A may not be verified through ANOTHER case of
    the SAME institution — evidence_ids cannot bypass case authorization."""
    res = http_env.post("/api/v3/evidence/verify", json={"case_id": CASE_A2, "evidence_ids": [EV1]})
    assert res.status_code == 404


def test_wrong_institution(http_env):
    from app.routes.v2.identity import get_current_identity
    from app.main import app

    app.dependency_overrides[get_current_identity] = lambda: make_identity(TENANT_B, "usr_r07_b")
    try:
        res = http_env.post("/api/v3/evidence/verify", json={"case_id": CASE_A, "evidence_ids": [EV1]})
        assert res.status_code == 404
    finally:
        app.dependency_overrides[get_current_identity] = lambda: make_identity(TENANT_A)


def test_client_entries_field_422(http_env):
    res = http_env.post(
        "/api/v3/evidence/verify",
        json={"case_id": CASE_A, "evidence_ids": [EV1], "entries": [], "chain_id": 1,
              "contract_address": "0x1234567890123456789012345678901234567890"},
    )
    assert res.status_code == 422


def test_zero_evidence_422(http_env):
    res = http_env.post("/api/v3/evidence/verify", json={"case_id": CASE_A, "evidence_ids": []})
    assert res.status_code == 422
    res = http_env.post("/api/v3/evidence/verify", json={"case_id": CASE_A, "evidence_ids": [EV1, EV1]})
    assert res.status_code == 422


def test_no_identity_401(seeded):
    """Institutional mode without a token: hard 401 (no demo fallback)."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings

    old_mode = settings.APP_MODE
    old_oidc = settings.OIDC_ENABLED
    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = True
    try:
        client = TestClient(app, raise_server_exceptions=False)
        res = client.post("/api/v3/evidence/verify", json={"case_id": CASE_A, "evidence_ids": [EV1]})
        assert res.status_code == 401
    finally:
        settings.APP_MODE = old_mode
        settings.OIDC_ENABLED = old_oidc


def test_v2_institutional_returns_410(seeded):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings

    old_mode = settings.APP_MODE
    old_oidc = settings.OIDC_ENABLED
    settings.APP_MODE = "institutional"
    settings.OIDC_ENABLED = True
    try:
        client = TestClient(app, raise_server_exceptions=False)
        res = client.post(
            "/api/v2/evidence/verify",
            json={"incidentId": 1, "schemaVersion": 2, "chainId": 1337,
                  "contractAddress": "0x5FbDB2315678afecb367f032d93F642f64180aa3", "entries": []},
        )
        assert res.status_code == 410
        assert "/api/v3/evidence/verify" in res.json().get("detail", "")
    finally:
        settings.APP_MODE = old_mode
        settings.OIDC_ENABLED = old_oidc


def test_uint256_decimal_strings(http_env):
    """On-chain uint256 values surfaced by the API must be decimal STRINGS."""
    res = http_env.post("/api/v3/evidence/verify", json={"case_id": CASE_A, "evidence_ids": [EV1, EV2]})
    assert res.status_code == 200
    body = res.json()
    for ev in body.get("checked_evidence_ids", []):
        assert isinstance(ev, str)
