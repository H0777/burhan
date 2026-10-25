"""
R08 test helper: a behavior-faithful local EVM simulator + PG harness.

SimulatedEvmAdapter mirrors the send-path semantics the anchor pipeline
depends on (ForensicTrail merged-R04 contract + node behavior):

  * REAL signatures: the ChainSender signs real legacy transactions; the
    simulator recovers the sender from the signature (eth_account) and
    decodes the nonce with a minimal RLP decoder — nonce discipline is
    ENFORCED, not assumed (a wrong nonce raises like a real node).
  * tx hash == keccak256(raw bytes): re-broadcasting the same raw tx is
    idempotent (same hash, mined once).
  * submitEvidenceAttested dedupe by requestId+manifestDigest (conflict
    raises), createIncidentForCase idempotency by case reference hash —
    exactly the merged contract logic.
  * receipts with status/blockNumber/blockHash, auto-mined blocks,
    reorg injection (block hashes above a fork change; receipts keep the
    stale blockHash so canonicality checks catch it), forced status-0
    mining, held receipts (stuck tx), and external nonce bumps.

It is a TEST DOUBLE of the CHAIN, not of the code under test: the worker,
sender, repositories and database are all real (PostgreSQL r08-pg-test).

PGHarness mirrors the R11/R12 environment contract (DATABASE_URL app role +
MIGRATION_DATABASE_URL owner role; skip without them).
"""

import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, Case, EvidenceAnchor, EvidenceObject, Institution, Outbox
from app.db.session import tenant_transaction

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_ENGINE_DIR = Path(__file__).resolve().parents[2]

CHAIN_ID = 31337
CONTRACT = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
DEPLOYMENT_ID = "0x" + "22" * 32


# ---------------------------------------------------------------------------
# minimal RLP decode (legacy transactions only — enough to read the nonce)
# ---------------------------------------------------------------------------

def _rlp_decode(buf: bytes, pos: int = 0):
    prefix = buf[pos]
    if prefix <= 0x7F:
        return buf[pos:pos + 1], pos + 1
    if prefix <= 0xB7:
        length = prefix - 0x80
        start, end = pos + 1, pos + 1 + length
        return buf[start:end], end
    if prefix <= 0xBF:
        length_len = prefix - 0xB7
        length = int.from_bytes(buf[pos + 1:pos + 1 + length_len], "big")
        start, end = pos + 1 + length_len, pos + 1 + length_len + length
        return buf[start:end], end
    if prefix <= 0xF7:
        length = prefix - 0xC0
        end_of_list = pos + 1 + length
        items, cur = [], pos + 1
        while cur < end_of_list:
            item, cur = _rlp_decode(buf, cur)
            items.append(item)
        return items, end_of_list
    length_len = prefix - 0xF7
    length = int.from_bytes(buf[pos + 1:pos + 1 + length_len], "big")
    end_of_list = pos + 1 + length_len + length
    items, cur = [], pos + 1 + length_len
    while cur < end_of_list:
        item, cur = _rlp_decode(buf, cur)
        items.append(item)
    return items, end_of_list


def _keccak(data: bytes) -> bytes:
    from Crypto.Hash import keccak as _keccak

    k = _keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def _sel(sig: str) -> str:
    return _keccak(sig.encode()).hex()[:8]


SEL_CREATE_INCIDENT = _sel("createIncidentForCase(bytes32,bytes32,bytes32)")
SEL_SUBMIT_ATTESTED = _sel(
    "submitEvidenceAttested(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)"
)


class RpcError(Exception):
    pass


class SimulatedEvmAdapter:
    """Send-path RPC + ForensicTrail semantics. Deterministic, auto-mining."""

    def __init__(self, chain_id: int = CHAIN_ID):
        from eth_account import Account

        self._Account = Account
        self.chain_id = chain_id
        self.gas_price = 10 ** 9
        self.executed_nonce: dict[str, int] = {}
        self.txs: dict[str, dict] = {}           # tx_hash -> record
        self.blocks: dict[int, str] = {}          # block number -> hash
        self._next_block = 1
        self.case_ref_incidents: dict[str, int] = {}
        self.case_ref_meta: dict[str, tuple] = {}
        self.incident_counter = 0
        self.manifest_digests: dict[str, str] = {}
        self.manifest_evidence: dict[str, dict] = {}
        self.evidence_counter = 0
        self.broadcast_calls: dict[str, int] = {}  # tx_hash -> eth_sendRaw count
        self.fail_next_tx = False
        self.fail_selector = None  # "EVIDENCE" -> only submitEvidenceAttested reverts
        self.hold_receipts = False
        self.lock = threading.Lock()

    # -- node ---------------------------------------------------------------

    def eth_chain_id(self):
        return self.chain_id

    def eth_gas_price(self):
        return self.gas_price

    def eth_get_transaction_count(self, address, tag):
        return self.executed_nonce.get(address.lower(), 0)

    def eth_block_number(self):
        return self._next_block - 1

    def eth_get_block_by_number(self, number):
        if number not in self.blocks:
            return None
        return {"number": number, "hash": self.blocks[number]}

    def eth_send_raw_transaction(self, raw_hex: str) -> str:
        from eth_account import Account

        raw = bytes.fromhex(raw_hex[2:] if raw_hex.startswith("0x") else raw_hex)
        tx_hash = "0x" + _keccak(raw).hex()
        with self.lock:
            self.broadcast_calls[tx_hash] = self.broadcast_calls.get(tx_hash, 0) + 1
            if tx_hash in self.txs:
                rec = self.txs[tx_hash]
                if not rec.get("reverted"):
                    return tx_hash  # live tx: mempool idempotence, mined once
                # A REORGED tx is re-accepted by a real node (its old copy
                # vanished with the forked block): re-mine it into a new
                # canonical block and re-apply its effects.
                block_number = self._mine()
                receipt = rec["receipt"]
                receipt["blockNumber"] = hex(block_number)
                receipt["blockHash"] = self.blocks[block_number]
                rec["block_number"] = block_number
                rec["reverted"] = False
                if int(receipt["status"], 16) == 1:
                    receipt.pop("effects", None)
                    self._execute(
                        rec["to"], rec["data_hex"], rec["sender"], tx_hash,
                        block_number, receipt,
                    )
                    rec["effects"] = receipt.get("effects", [])
                self.executed_nonce[rec["sender"]] = rec["nonce"] + 1
                return tx_hash

            sender = Account.recover_transaction(raw).lower()
            items, _ = _rlp_decode(raw)
            nonce = int.from_bytes(items[0], "big")
            to = "0x" + items[3].hex()
            data = items[5].hex()

            expected = self.executed_nonce.get(sender, 0)
            if nonce != expected:
                raise RpcError(
                    f"nonce mismatch: tx nonce {nonce}, next for sender is {expected}"
                )

            should_fail = self.fail_next_tx or (
                self.fail_selector == "EVIDENCE" and data.startswith(SEL_SUBMIT_ATTESTED)
            )
            status = 0 if should_fail else 1
            self.fail_next_tx = False
            block_number = self._mine()
            receipt = {
                "status": hex(status),
                "blockNumber": hex(block_number),
                "blockHash": self.blocks[block_number],
                "transactionHash": tx_hash,
                "from": sender,
                "contractAddress": None,
            }
            if status == 1:
                self._execute(to, data, sender, tx_hash, block_number, receipt)
            self.executed_nonce[sender] = nonce + 1
            self.txs[tx_hash] = {
                "sender": sender,
                "nonce": nonce,
                "to": to,
                "data_hex": data,
                "block_number": block_number,
                "receipt": receipt,
                "effects": receipt.get("effects", []),
            }
            return tx_hash

    def eth_get_transaction_receipt(self, tx_hash):
        if self.hold_receipts:
            return None
        rec = self.txs.get(tx_hash)
        return dict(rec["receipt"]) if rec else None

    # -- contract ------------------------------------------------------------

    def _execute(self, to, data_hex, sender, tx_hash, block_number, receipt):
        sel, args_hex = data_hex[:8], data_hex[8:]
        words = [args_hex[i:i + 64] for i in range(0, len(args_hex), 64)]
        effects = receipt.setdefault("effects", [])
        if sel == SEL_CREATE_INCIDENT:
            ref = "0x" + words[0]
            title, severity = "0x" + words[1], "0x" + words[2]
            if ref in self.case_ref_incidents:
                if self.case_ref_meta[ref] != (title, severity):
                    raise RpcError("ForensicTrail: case reference metadata conflict")
                incident_id = self.case_ref_incidents[ref]
            else:
                self.incident_counter += 1
                incident_id = self.incident_counter
                self.case_ref_incidents[ref] = incident_id
                self.case_ref_meta[ref] = (title, severity)
                effects.append(("case_ref", ref))
            receipt["incidentId"] = incident_id
        elif sel == SEL_SUBMIT_ATTESTED:
            request_id = "0x" + words[1]
            manifest = "0x" + words[5]
            if request_id in self.manifest_digests:
                if self.manifest_digests[request_id] != manifest:
                    raise RpcError("ForensicTrail: manifest digest conflict")
                receipt["evidenceId"] = self.manifest_evidence[request_id]["evidence_id"]
                return  # idempotent: no counter change, no new entry
            self.evidence_counter += 1
            evidence_id = self.evidence_counter
            entry_hash = "0x" + _keccak(
                (request_id + str(evidence_id) + manifest).encode()
            ).hex()
            self.manifest_digests[request_id] = manifest
            self.manifest_evidence[request_id] = {
                "evidence_id": evidence_id,
                "entry_hash": entry_hash,
                "block_number": block_number,
                "transaction_hash": tx_hash,
                "manifest_digest": manifest,
            }
            effects.append(("evidence", request_id))
            receipt["evidenceId"] = evidence_id

    def _mine(self) -> int:
        number = self._next_block
        self._next_block += 1
        self.blocks[number] = "0xblk" + f"{number:04d}" + _keccak(
            f"block-{number}".encode()
        ).hex()[:56]
        return number

    # -- send-path idempotency reads (verification reads are R07's) ----------

    def get_manifest_digest(self, request_id):
        return self.manifest_digests.get(request_id, "0x" + "0" * 64)

    def get_evidence_by_request_id(self, request_id):
        rec = self.manifest_evidence.get(request_id)
        if not rec:
            return {"exists": False}
        return {"exists": True, **rec}

    def get_incident_by_case_reference(self, ref_hash):
        return self.case_ref_incidents.get(ref_hash, 0)

    # -- fault injection ------------------------------------------------------

    def bump_nonce(self, address, count=1):
        self.executed_nonce[address.lower()] = (
            self.executed_nonce.get(address.lower(), 0) + count
        )

    def reorg_from(self, block_number):
        """Fork the chain: blocks >= block_number get new hashes and their
        transactions' contract effects REVERT (a real reorg unwinds state).
        Receipts keep the stale blockHash — the observable state a node that
        saw the pre-reorg receipt reports — so canonicality checks catch it.
        Nonces of reverted transactions become allocatable again."""
        with self.lock:
            for number in list(self.blocks):
                if number >= block_number:
                    self.blocks[number] = "0xreorg" + _keccak(
                        f"reorg-{number}".encode()
                    ).hex()[:58]
            for tx_hash, rec in self.txs.items():
                if rec["block_number"] >= block_number and not rec.get("reverted"):
                    rec["reverted"] = True
                    self.executed_nonce[rec["sender"]] = max(
                        0, self.executed_nonce.get(rec["sender"], 1) - 1
                    )
                    for effect in rec.get("effects", []):
                        if effect[0] == "evidence":
                            self.manifest_digests.pop(effect[1], None)
                            self.manifest_evidence.pop(effect[1], None)
                            self.evidence_counter = max(0, self.evidence_counter - 1)
                        elif effect[0] == "case_ref":
                            self.case_ref_incidents.pop(effect[1], None)
                            self.case_ref_meta.pop(effect[1], None)
                            self.incident_counter = max(0, self.incident_counter - 1)

    def stats(self):
        return {
            "incidents": self.incident_counter,
            "evidence": self.evidence_counter,
            "broadcasts": dict(self.broadcast_calls),
        }


# ---------------------------------------------------------------------------
# PostgreSQL harness (R11/R12 environment contract)
# ---------------------------------------------------------------------------

def require_pg_urls() -> tuple[str, str]:
    import os

    app_url = os.environ.get("DATABASE_URL", "")
    migration_url = os.environ.get("MIGRATION_DATABASE_URL", "")
    if not app_url.startswith("postgresql") or not migration_url.startswith("postgresql"):
        pytest.skip(
            "R08 tests require DATABASE_URL (app role) and MIGRATION_DATABASE_URL "
            "(migration owner) pointing at a disposable PostgreSQL (r08-pg-test)"
        )
    return app_url, migration_url


class PGHarness:
    """One migrated database; per-test tenants with a full anchor task."""

    def __init__(self, app_url: str, migration_url: str):
        self.app_engine = create_engine(app_url, pool_pre_ping=True)
        self.owner_engine = create_engine(migration_url, pool_pre_ping=True)
        self.AppSession = sessionmaker(bind=self.app_engine, expire_on_commit=False)
        self.OwnerSession = sessionmaker(bind=self.owner_engine, expire_on_commit=False)

    def migrate(self):
        import os
        import subprocess

        result = subprocess.run(
            ["node", str(REPO_ROOT / "scripts" / "run-python.js"), "-m", "alembic", "upgrade", "head"],
            cwd=str(AI_ENGINE_DIR),
            env={**os.environ, "MIGRATION_DATABASE_URL": self.owner_engine.url.render_as_string(hide_password=False)},
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}"

    def seed_anchor_task(self, institution_id: str | None = None, case_id: str | None = None,
                         manifest_digest: str | None = None) -> dict:
        """Institution + case + evidence object (stored manifest digest) +
        PENDING anchor + PENDING outbox row. Returns identifiers.
        `cases.id` is a GLOBAL primary key (only (institution,id) is the
        tenant composite), so distinct tests/tenants get distinct case ids
        unless the caller forces one."""
        inst = institution_id or f"inst_r08_{uuid.uuid4().hex[:10]}"
        case = case_id or f"case_{uuid.uuid4().hex[:12]}"
        digest = manifest_digest or ("0x" + f"{uuid.uuid4().int % 16**64:064x}")
        request_id = "0x" + f"{(uuid.uuid4().int + 1) % 16**64:064x}"
        evidence_id = f"ev_{uuid.uuid4().hex[:10]}"
        outbox_id = f"out_{uuid.uuid4().hex[:14]}"
        file_sha = "0x" + "ab" * 32

        with self.OwnerSession() as session:
            session.add(Institution(id=inst, name=f"R08 {inst}"))
            session.commit()
            with tenant_transaction(session, inst):
                session.add(Case(id=case, case_number=f"CASE-{inst[-6:]}", title="R08 case",
                                 institution_id=inst, severity="HIGH"))
                session.add(EvidenceObject(
                    id=f"evo_{uuid.uuid4().hex[:12]}", institution_id=inst, case_id=case,
                    evidence_id=evidence_id, object_version=1, file_name="r.bin",
                    content_type="application/octet-stream", file_size=16,
                    sha256_hash="ab" * 32, storage_path="/vault/r.bin", encrypted=False,
                    storage_format="legacy_plaintext_read_only",
                    manifest_digest=digest[2:] if digest.startswith("0x") else digest,
                ))
                session.add(EvidenceAnchor(
                    id=f"anc_{uuid.uuid4().hex[:12]}", institution_id=inst, case_id=case,
                    evidence_id=evidence_id, anchor_request_id=request_id, chain_id=CHAIN_ID,
                    contract_address=CONTRACT, status="PENDING_ANCHOR",
                ))
                session.add(Outbox(
                    id=outbox_id, institution_id=inst, event_type="ANCHOR_EVIDENCE",
                    payload_json=json.dumps({
                        "institution_id": inst, "case_id": case, "evidence_id": evidence_id,
                        "anchor_request_id": request_id, "chain_id": CHAIN_ID,
                        "contract_address": CONTRACT, "file_sha256": file_sha,
                        "manifest_hash": digest,
                    }),
                    status="PENDING", attempts=0,
                ))
            session.commit()
        return {
            "institution_id": inst, "case_id": case, "evidence_id": evidence_id,
            "outbox_id": outbox_id, "anchor_request_id": request_id,
            "manifest_digest": digest, "file_sha256": file_sha,
        }

    def query(self, sql: str, params: dict | None = None, tenant: str | None = None):
        """Owner-role statement inside the tenant context (FORCEd RLS honest
        read). SELECTs return rows; other statements return None."""
        with self.OwnerSession() as session:
            if tenant:
                with tenant_transaction(session, tenant):
                    result = session.execute(text(sql), params or {})
                    return result.all() if result.returns_rows else None
            result = session.execute(text(sql), params or {})
            return result.all() if result.returns_rows else None

    def close(self):
        self.app_engine.dispose()
        self.owner_engine.dispose()


class FakeClock:
    def __init__(self, start: datetime | None = None):
        self.now = start or datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def make_sender(adapter, clock, gas_limit=400_000):
    from eth_account import Account

    from app.services.chain_sender import ChainSender, SignerCredentials

    account = Account.create()
    sender = ChainSender(
        adapter=adapter,
        credentials=SignerCredentials(account.key.hex()),
        clock=clock,
        gas_limit=gas_limit,
        required_depth=1,
    )
    return sender, account
