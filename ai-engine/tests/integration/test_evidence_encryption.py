"""
Evidence encryption tests (R06) — spec §6.

AES-256-GCM at rest with a random per-object DEK wrapped by the institution
key (key_id); AAD binds institution + evidence + version; no plaintext DEK at
rest; GCM tag gate before any plaintext release; open_verified_stream for
large/verified reads; key rotation; cross-institution key refusal; legacy
objects stay legacy_plaintext_read_only with no silent conversion.
"""

import base64
import io
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from app.security.key_provider import LocalFileKeyProvider
from app.services.evidence_store import EvidenceStore

MAX_SIZE = 25 * 1024 * 1024

SEEDS = {}


def _make_key_dir(root: Path) -> LocalFileKeyProvider:
    """Two institutions; inst_a holds k1 and k2 (for rotation), inst_b holds
    only its own key. Returns a provider over the key dir."""
    base = root / "keys"
    layout = {
        "inst_a": {"keys": ["k1", "k2"], "current": "k1"},
        "inst_b": {"keys": ["k1"], "current": "k1"},
    }
    for inst, spec in layout.items():
        d = base / inst
        d.mkdir(parents=True)
        for key_id in spec["keys"]:
            seed = os.urandom(32)
            SEEDS[(inst, key_id)] = seed
            (d / f"{key_id}.seed").write_bytes(seed)
        (d / "current").write_text(spec["current"], encoding="utf-8")
    return LocalFileKeyProvider(base)


@pytest.fixture
def key_env(tmp_path):
    provider = _make_key_dir(tmp_path)
    vault = tmp_path / "vault"
    store = EvidenceStore(base_dir=str(vault), max_size_bytes=MAX_SIZE, key_provider=provider)
    return {"provider": provider, "vault": vault, "store": store, "tmp": tmp_path}


def _version_dir(vault: Path, inst: str, ev: str, version: int) -> Path:
    return vault / inst / ev / f"v{version}"


def test_encrypted_at_rest_plaintext_and_dek_absent(key_env):
    """The object on disk is ciphertext (never the plaintext); metadata carries
    only a WRAPPED dek; GCM nonce and auth tag are present; the plaintext DEK
    appears nowhere at rest."""
    store = key_env["store"]
    vault = key_env["vault"]
    content = b"TOP SECRET investigation file \xe2\x9c\x93" * 128

    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "secret.bin"},
        institution_id="inst_a",
        evidence_id="ev-enc-1",
        object_version=1,
    )

    vdir = _version_dir(vault, "inst_a", "ev-enc-1", 1)
    meta = json.loads((vdir / "meta.json").read_text(encoding="utf-8"))

    assert meta["storage_format"] == "aes256gcm_v1"
    assert meta["encryption_key_id"] == "k1"
    wrapped = meta["wrapped_dek"]
    assert wrapped["algorithm"] == "X25519-HKDF-SHA256-AES256GCM-V1"
    assert len(base64.b64decode(wrapped["ciphertext"], validate=True)) == 32 + 16
    assert len(base64.b64decode(meta["nonce"], validate=True)) == 12
    assert len(base64.b64decode(meta["auth_tag"], validate=True)) == 16

    # No forbidden plaintext-DEK style keys anywhere in metadata.
    flat = json.dumps(meta).lower()
    for forbidden in ('"dek"', '"data_key"', '"plaintext_key"'):
        assert forbidden not in flat, f"plaintext DEK field {forbidden} present in metadata"

    # The plaintext never appears in ANY file under the vault — including
    # the .tmp directory used by open_verified_stream (fix round 1).
    blob = b"".join(p.read_bytes() for p in vault.rglob("*") if p.is_file())
    assert content not in blob, "plaintext found at rest"

    # Ciphertext object file differs from plaintext.
    ct = (vdir / "object.bin").read_bytes()
    assert ct != content

    # A DEK that cannot be unwrapped without the institution key: delete the
    # key material and decryption must fail closed.
    (key_env["tmp"] / "keys" / "inst_a" / "k1.seed").unlink()
    with pytest.raises(Exception):
        store.open(institution_id="inst_a", evidence_id="ev-enc-1", object_version=1)


def test_tampered_ciphertext_or_tag_invalid(key_env):
    """Flipping any ciphertext byte, or the auth tag, or the nonce refuses
    decryption — no plaintext release."""
    store = key_env["store"]
    vault = key_env["vault"]
    content = b"integrity critical bytes" * 100
    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "tamper.bin"},
        institution_id="inst_a",
        evidence_id="ev-tamper-2",
        object_version=1,
    )
    vdir = _version_dir(vault, "inst_a", "ev-tamper-2", 1)
    obj = vdir / "object.bin"

    original = obj.read_bytes()

    # 1. ciphertext byte flip
    flipped = bytearray(original)
    flipped[0] ^= 0x01
    obj.write_bytes(bytes(flipped))
    with pytest.raises(ValueError, match="Integrity Compromised|GCM|auth"):
        store.open(institution_id="inst_a", evidence_id="ev-tamper-2", object_version=1)
    obj.write_bytes(original)

    # 2. auth tag flip
    meta = json.loads((vdir / "meta.json").read_text(encoding="utf-8"))
    tag = bytearray(base64.b64decode(meta["auth_tag"]))
    tag[0] ^= 0xFF
    meta2 = dict(meta, auth_tag=base64.b64encode(bytes(tag)).decode("ascii"))
    (vdir / "meta.json").write_text(json.dumps(meta2), encoding="utf-8")
    with pytest.raises(ValueError, match="Integrity Compromised|GCM|auth"):
        store.open(institution_id="inst_a", evidence_id="ev-tamper-2", object_version=1)

    # 3. nonce flip
    meta3 = dict(meta, nonce=base64.b64encode(b"\x00" * 12).decode("ascii"))
    (vdir / "meta.json").write_text(json.dumps(meta3), encoding="utf-8")
    with pytest.raises(ValueError, match="Integrity Compromised|GCM|auth"):
        store.open(institution_id="inst_a", evidence_id="ev-tamper-2", object_version=1)


def test_aad_binds_institution_evidence_and_version(key_env):
    """The GCM AAD binds all three dimensions: moving the object to another
    evidence id, or decrypting with a different version/institution context,
    fails the tag."""
    from app.services.encrypted_object import decrypt_bytes

    store = key_env["store"]
    vault = key_env["vault"]
    provider = key_env["provider"]
    content = b"aad-bound bytes" * 32
    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "bound.bin"},
        institution_id="inst_a",
        evidence_id="ev-aad",
        object_version=7,
    )

    vdir = _version_dir(vault, "inst_a", "ev-aad", 7)
    meta = json.loads((vdir / "meta.json").read_text(encoding="utf-8"))
    ct = (vdir / "object.bin").read_bytes()

    kwargs = dict(
        nonce=base64.b64decode(meta["nonce"]),
        auth_tag=base64.b64decode(meta["auth_tag"]),
        wrapped_dek=meta["wrapped_dek"],
        key_provider=provider,
    )

    # correct binding decrypts
    assert decrypt_bytes(ct, institution_id="inst_a", evidence_id="ev-aad", object_version=7, **kwargs) == content

    # flip evidence
    with pytest.raises(Exception):
        decrypt_bytes(ct, institution_id="inst_a", evidence_id="ev-AAD-OTHER", object_version=7, **kwargs)

    # flip version
    with pytest.raises(Exception):
        decrypt_bytes(ct, institution_id="inst_a", evidence_id="ev-aad", object_version=8, **kwargs)

    # flip institution
    with pytest.raises(Exception):
        decrypt_bytes(ct, institution_id="inst_a_other", evidence_id="ev-aad", object_version=7, **kwargs)

    # store-level: moving the published folder to another evidence id refuses
    ev_b = vault / "inst_a" / "ev-aad-stolen"
    shutil.copytree(vdir, ev_b / "v7")
    with pytest.raises(ValueError, match="Integrity Compromised|GCM|auth"):
        store.open(institution_id="inst_a", evidence_id="ev-aad-stolen", object_version=7)


def test_key_rotation_v2_new_key_v1_old_key_readable(key_env):
    """Rotation: v2 is written under the NEW key; v1 stays readable under the
    retained OLD key; each version records the key id that wrapped it."""
    store = key_env["store"]
    vault = key_env["vault"]
    tmp = key_env["tmp"]
    provider = key_env["provider"]

    v1_content = b"written under k1"
    store.put(
        stream_or_bytes=io.BytesIO(v1_content),
        metadata={"file_name": "rotation.bin"},
        institution_id="inst_a",
        evidence_id="ev-rot",
        object_version=1,
    )

    # rotate: current pointer moves to k2
    (tmp / "keys" / "inst_a" / "current").write_text("k2", encoding="utf-8")

    v2_content = b"written under k2 after rotation"
    store.put(
        stream_or_bytes=io.BytesIO(v2_content),
        metadata={"file_name": "rotation.bin"},
        institution_id="inst_a",
        evidence_id="ev-rot",
        object_version=2,
    )

    meta1 = json.loads(
        (_version_dir(vault, "inst_a", "ev-rot", 1) / "meta.json").read_text(encoding="utf-8")
    )
    meta2 = json.loads(
        (_version_dir(vault, "inst_a", "ev-rot", 2) / "meta.json").read_text(encoding="utf-8")
    )
    assert meta1["encryption_key_id"] == "k1"
    assert meta2["encryption_key_id"] == "k2"
    assert meta1["wrapped_dek"]["ciphertext"] != meta2["wrapped_dek"]["ciphertext"]

    # v1 still decrypts with the retained old key; v2 with the new key.
    data1, _ = store.open(institution_id="inst_a", evidence_id="ev-rot", object_version=1)
    data2, _ = store.open(institution_id="inst_a", evidence_id="ev-rot", object_version=2)
    assert data1 == v1_content
    assert data2 == v2_content


def test_second_institution_key_refused(key_env):
    """A second institution's key cannot unwrap or decrypt the object."""
    from app.services.encrypted_object import decrypt_bytes

    store = key_env["store"]
    vault = key_env["vault"]
    provider = key_env["provider"]
    content = b"inst a private evidence" * 16
    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "private.bin"},
        institution_id="inst_a",
        evidence_id="ev-cross",
        object_version=1,
    )

    vdir = _version_dir(vault, "inst_a", "ev-cross", 1)
    meta = json.loads((vdir / "meta.json").read_text(encoding="utf-8"))
    ct = (vdir / "object.bin").read_bytes()

    with pytest.raises(Exception):
        decrypt_bytes(
            ct,
            institution_id="inst_b",
            evidence_id="ev-cross",
            object_version=1,
            nonce=base64.b64decode(meta["nonce"]),
            auth_tag=base64.b64decode(meta["auth_tag"]),
            wrapped_dek=meta["wrapped_dek"],
            key_provider=provider,
        )


def test_open_verified_stream_gates_plaintext_on_tag(key_env):
    """open_verified_stream releases plaintext only after GCM tag success; on
    tampering no readable plaintext stream is produced."""
    store = key_env["store"]
    vault = key_env["vault"]
    content = b"stream me after verification" * 1000
    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "stream.bin"},
        institution_id="inst_a",
        evidence_id="ev-stream",
        object_version=1,
    )

    fh = store.open_verified_stream(institution_id="inst_a", evidence_id="ev-stream", object_version=1)
    try:
        data = fh.read()
        assert data == content
    finally:
        fh.close()

    # tamper -> no stream
    vdir = _version_dir(vault, "inst_a", "ev-stream", 1)
    obj = vdir / "object.bin"
    original = obj.read_bytes()
    tampered = bytearray(original)
    tampered[len(tampered) // 2] ^= 0x02
    obj.write_bytes(bytes(tampered))
    with pytest.raises(ValueError, match="Integrity Compromised|GCM|auth"):
        store.open_verified_stream(institution_id="inst_a", evidence_id="ev-stream", object_version=1)


def test_verified_stream_leaves_no_plaintext_residue(key_env):
    """Fix round 1: the verified-plaintext temp file is DELETE-ON-CLOSE. After
    the stream is fully consumed (explicit close or context exit) the vault —
    .tmp included — holds no plaintext and no residue files; an abandoned
    handle is unlinked by the finalizer backstop."""
    import gc

    store = key_env["store"]
    content = b"verified stream residue check" * 512
    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "residue.bin"},
        institution_id="inst_a",
        evidence_id="ev-residue",
        object_version=1,
    )
    tmp_dir = key_env["vault"] / ".tmp"

    # 1. explicit close
    fh = store.open_verified_stream(institution_id="inst_a", evidence_id="ev-residue", object_version=1)
    assert fh.read() == content
    fh.close()
    residue = list(tmp_dir.iterdir()) if tmp_dir.exists() else []
    assert residue == [], f"plaintext temp residue after close: {residue}"

    # 2. context-manager exit
    with store.open_verified_stream(
        institution_id="inst_a", evidence_id="ev-residue", object_version=1
    ) as fh2:
        assert fh2.read(10) == content[:10]
    residue = list(tmp_dir.iterdir()) if tmp_dir.exists() else []
    assert residue == [], f"plaintext temp residue after context exit: {residue}"

    # 3. finalizer backstop: handle abandoned without close()
    fh3 = store.open_verified_stream(institution_id="inst_a", evidence_id="ev-residue", object_version=1)
    pending = list(tmp_dir.iterdir())
    assert len(pending) == 1, f"expected exactly one open temp file, got {pending}"
    del fh3
    gc.collect()
    residue = list(tmp_dir.iterdir()) if tmp_dir.exists() else []
    assert residue == [], f"finalizer left plaintext residue: {residue}"

    # 4. whole-vault scan (including .tmp): plaintext nowhere at rest
    blob = b"".join(p.read_bytes() for p in key_env["vault"].rglob("*") if p.is_file())
    assert content not in blob, "verified plaintext persisted somewhere in the vault"


def test_legacy_object_stays_legacy_plaintext_read_only(tmp_path):
    """Legacy (pre-R06) flat plaintext objects keep working read-only: no
    silent conversion, no retroactive encryption or signing."""
    vault = tmp_path / "legacy_vault"
    vault.mkdir(parents=True)
    inst, ev = "inst_legacy", "ev-old-1"
    legacy_dir = vault / inst / ev
    legacy_dir.mkdir(parents=True)
    legacy_content = b"legacy plaintext bytes from before R06"
    (legacy_dir / "v1_legacy_report.txt").write_bytes(legacy_content)
    legacy_meta = {
        "evidence_id": ev,
        "object_version": 1,
        "institution_id": inst,
        "file_name": "legacy_report.txt",
        "content_type": "text/plain",
        "file_size": len(legacy_content),
        "sha256_hash": __import__("hashlib").sha256(legacy_content).hexdigest(),
        "created_at": "2025-01-01T00:00:00+00:00",
        "metadata": {"file_name": "legacy_report.txt"},
    }
    (legacy_dir / "v1_meta.json").write_text(json.dumps(legacy_meta), encoding="utf-8")

    provider = _make_key_dir(tmp_path)
    store = EvidenceStore(base_dir=str(vault), max_size_bytes=MAX_SIZE, key_provider=provider)

    data, meta = store.open(institution_id=inst, evidence_id=ev, object_version=1)
    assert data == legacy_content
    assert meta["storage_format"] == "legacy_plaintext_read_only"

    # The original file is untouched — still plaintext, same bytes, no marker.
    assert (legacy_dir / "v1_legacy_report.txt").read_bytes() == legacy_content
    assert not (legacy_dir / "v1").exists()
    markers = list(legacy_dir.rglob("*COMMITTED*"))
    assert markers == [], f"retroactive publish marker on legacy object: {markers}"


def test_later_encrypted_copy_preserves_original_hash_and_provenance(key_env):
    """An encrypted copy of a legacy object records the original hash and a
    migration record; the original stays legacy plaintext; provenance level is
    unchanged (the copy says so explicitly)."""
    vault = key_env["vault"]
    provider = key_env["provider"]
    legacy_store = EvidenceStore(base_dir=str(vault), max_size_bytes=MAX_SIZE, key_provider=None)

    inst, ev = "inst_a", "ev-migrate"
    legacy_content = b"legacy bytes to be migrated"
    legacy_store.put(
        stream_or_bytes=io.BytesIO(legacy_content),
        metadata={"file_name": "legacy.txt"},
        institution_id=inst,
        evidence_id=ev,
        object_version=1,
    )

    import hashlib

    original_sha = hashlib.sha256(legacy_content).hexdigest()

    migrated = legacy_store.migrate_to_encrypted(
        institution_id=inst, evidence_id=ev, legacy_version=1, key_provider=provider
    )
    assert migrated.object_version == 2

    # v2 is encrypted: it decrypts only through a provider-backed store.
    encrypted_store = key_env["store"]
    data2, meta2 = encrypted_store.open(institution_id=inst, evidence_id=ev, object_version=2)
    assert data2 == legacy_content
    assert meta2["storage_format"] == "aes256gcm_v1"
    assert meta2["migration"]["migrated_from_version"] == 1
    assert meta2["migration"]["original_sha256"] == original_sha
    assert meta2["migration"]["original_storage_format"] == "legacy_plaintext_read_only"

    # Fail-closed: a store without key material refuses the encrypted copy —
    # proof there is no plaintext DEK at rest to fall back on.
    with pytest.raises(Exception):
        legacy_store.open(institution_id=inst, evidence_id=ev, object_version=2)

    # v1 unchanged: still legacy plaintext on disk, same hash.
    v1_data, v1_meta = legacy_store.open(institution_id=inst, evidence_id=ev, object_version=1)
    assert v1_data == legacy_content
    assert v1_meta["storage_format"] == "legacy_plaintext_read_only"
    assert v1_meta["sha256_hash"] == original_sha
