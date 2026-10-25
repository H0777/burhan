"""
Evidence store immutability tests (R06) — spec §6.

No-replace atomic version publishing, staging isolation, crash behavior,
path containment (relative_to, siblings, symlinks), size boundary at
25*1024*1024 bytes, and Windows/Arabic display-name handling.

These tests are written against the R06 EvidenceStore contract:
  - EvidenceStore(base_dir, max_size_bytes, key_provider=None)
  - published versions live in <base>/<inst>/<evid>/v<n>/ with a completion
    marker; a version without its completion marker is not readable.
"""

import hashlib
import io
import json
import os
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.services.evidence_store import EvidenceStore


MAX_SIZE = 25 * 1024 * 1024  # the spec §6 limit, bytes


@pytest.fixture
def vault():
    tmp = tempfile.mkdtemp(prefix="r06_immutability_")
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def store(vault):
    return EvidenceStore(base_dir=str(vault), max_size_bytes=MAX_SIZE)


def _version_dir(vault: Path, institution_id: str, evidence_id: str, version: int) -> Path:
    return vault / institution_id / evidence_id / f"v{version}"


def test_same_version_two_writers_only_one_success(store, vault):
    """Two independent writers racing on the same (institution, evidence,
    version): exactly one publish succeeds; the final bytes belong to the
    winner only; staging never crosses between writers."""
    inst, ev = "INST-RACE", "ev-race-1"
    winner_content = b"WRITER-A canonical immutable bytes" * 64
    loser_content = b"WRITER-B bytes that must never persist"

    errors = []
    successes = []

    def writer(content: bytes, label: str):
        s = EvidenceStore(base_dir=str(vault), max_size_bytes=MAX_SIZE)
        try:
            stored = s.put(
                stream_or_bytes=io.BytesIO(content),
                metadata={"file_name": f"{label}.bin", "content_type": "application/octet-stream"},
                institution_id=inst,
                evidence_id=ev,
                object_version=1,
            )
            successes.append((label, stored, content))
        except Exception as exc:  # noqa: BLE001 - the loser raises by design
            errors.append((label, exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(writer, winner_content, "A"), pool.submit(writer, loser_content, "B")]
        for fut in futures:
            fut.result()

    # Exactly one success, one failure.
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}"
    assert len(errors) == 1, f"expected exactly one loser, got {len(errors)}"

    winner_label, _stored, winner_bytes = successes[0]

    # Final bytes belong to the winner only.
    data, meta = store.open(institution_id=inst, evidence_id=ev, object_version=1)
    assert data == winner_bytes
    assert meta["file_name"] == f"{winner_label}.bin"

    # The published version dir carries exactly one object and one metadata.
    vdir = _version_dir(vault, inst, ev, 1)
    assert vdir.is_dir()
    object_files = [p.name for p in vdir.iterdir() if p.name.startswith("object")]
    assert object_files == ["object.bin"], f"unexpected object files: {object_files}"

    # No staging residue from either writer inside the evidence directory.
    residues = [p.name for p in (vault / inst / ev).iterdir() if p.name.startswith(".staging")]
    assert residues == [], f"staging files leaked: {residues}"


def test_crash_before_publish_leaves_no_readable_object(store, vault, monkeypatch):
    """A crash between staged write and publish leaves no readable object and
    no published version directory."""
    inst, ev = "INST-CRASH", "ev-crash-1"

    def explode(self, *args, **kwargs):
        raise RuntimeError("simulated crash before publish")

    monkeypatch.setattr(EvidenceStore, "_publish_version", explode)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.put(
            stream_or_bytes=io.BytesIO(b"content that must never become readable"),
            metadata={"file_name": "crash.bin"},
            institution_id=inst,
            evidence_id=ev,
            object_version=1,
        )

    # No published version directory at all.
    assert not _version_dir(vault, inst, ev, 1).exists()

    # open() refuses: nothing readable was published.
    with pytest.raises(FileNotFoundError):
        store.open(institution_id=inst, evidence_id=ev, object_version=1)

    # No completion marker anywhere in the evidence directory.
    ev_dir = vault / inst / ev
    if ev_dir.exists():
        markers = list(ev_dir.rglob("*COMMITTED*"))
        assert markers == [], f"completion marker found after crash: {markers}"


def test_missing_metadata_not_accepted(store, vault):
    """A published version directory without its metadata record is refused —
    an object without metadata is not evidence."""
    inst, ev = "INST-META", "ev-meta-1"
    store.put(
        stream_or_bytes=b"legitimate bytes",
        metadata={"file_name": "ok.bin"},
        institution_id=inst,
        evidence_id=ev,
        object_version=1,
    )

    vdir = _version_dir(vault, inst, ev, 1)
    assert vdir.is_dir()

    # Attacker (or partial write) removes the metadata file.
    meta_file = vdir / "meta.json"
    assert meta_file.exists()
    meta_file.unlink()

    with pytest.raises(ValueError, match="missing required metadata"):
        store.open(institution_id=inst, evidence_id=ev, object_version=1)

    # Same refusal when metadata exists but a required field was stripped.
    store.put(
        stream_or_bytes=b"second version",
        metadata={"file_name": "ok2.bin"},
        institution_id=inst,
        evidence_id=ev,
        object_version=2,
    )
    vdir2 = _version_dir(vault, inst, ev, 2)
    loaded = json.loads((vdir2 / "meta.json").read_text(encoding="utf-8"))
    for key in ("file_size", "sha256_hash", "created_at", "institution_id", "object_version"):
        loaded.pop(key, None)
    (vdir2 / "meta.json").write_text(json.dumps(loaded), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required metadata"):
        store.open(institution_id=inst, evidence_id=ev, object_version=2)


def test_evidence_size_boundary_25mib_accepted_plus_one_rejected(store, vault):
    """25*1024*1024 bytes is accepted; +1 byte is rejected with no final file
    left behind."""
    inst = "INST-SIZE"
    exact = b"\xa5" * MAX_SIZE

    stored = store.put(
        stream_or_bytes=io.BytesIO(exact),
        metadata={"file_name": "exact_25mib.bin"},
        institution_id=inst,
        evidence_id="ev-size-ok",
        object_version=1,
    )
    assert stored.size == MAX_SIZE
    data, meta = store.open(institution_id=inst, evidence_id="ev-size-ok", object_version=1)
    assert len(data) == MAX_SIZE
    assert data[:8] == b"\xa5" * 8

    one_over = b"\xa5" * (MAX_SIZE + 1)
    with pytest.raises(ValueError, match="maximum allowed"):
        store.put(
            stream_or_bytes=io.BytesIO(one_over),
            metadata={"file_name": "over_25mib.bin"},
            institution_id=inst,
            evidence_id="ev-size-over",
            object_version=1,
        )

    # No final file left for the rejected object.
    ev_dir = vault / inst / "ev-size-over"
    assert not _version_dir(vault, inst, "ev-size-over", 1).exists()
    if ev_dir.exists():
        leftovers = [p.name for p in ev_dir.rglob("*") if not p.name.startswith(".staging")]
        assert leftovers == [], f"final artifacts left after rejection: {leftovers}"
        staging = list(ev_dir.rglob(".staging*"))
        assert staging == [], f"staging leaked after rejection: {staging}"


def test_Windows_unicode_display_name(store, vault):
    """An Arabic display name is preserved for presentation while the on-disk
    internal id stays ASCII-safe (Windows path safety)."""
    inst, ev = "INST-AR", "ev-arabic-1"
    arabic_name = "تقرير_تحقيق_رقم_٤٢.pdf"
    content = b"arabic-named forensic report bytes"

    stored = store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": arabic_name, "content_type": "application/pdf"},
        institution_id=inst,
        evidence_id=ev,
        object_version=1,
    )

    # Internal id is ASCII-safe.
    assert stored.file_name.isascii(), f"internal file name not ASCII: {stored.file_name!r}"
    internal_path = Path(stored.storage_path)
    assert internal_path.name.isascii()
    assert internal_path.exists()

    # Display name preserved exactly.
    data, meta = store.open(institution_id=inst, evidence_id=ev, object_version=1)
    assert data == content
    assert meta["display_name"] == arabic_name
    assert meta["metadata"]["file_name"] == arabic_name


def test_path_prefix_sibling(store, vault):
    """A sibling directory (shared prefix) is never reachable through path
    confusion; containment uses relative_to, not string prefixes."""
    inst, ev = "BANK_A", "ev-sib-1"
    content = b"bank A private evidence"

    store.put(
        stream_or_bytes=io.BytesIO(content),
        metadata={"file_name": "a.bin"},
        institution_id=inst,
        evidence_id=ev,
        object_version=1,
    )

    # Sibling institution with a shared string prefix cannot read A's object.
    with pytest.raises(FileNotFoundError):
        store.open(institution_id="BANK_A_ARCHIVE", evidence_id=ev, object_version=1)
    with pytest.raises(FileNotFoundError):
        store.open(institution_id="BANK_A", evidence_id="ev-sib-1-sibling", object_version=1)

    # Direct containment check: a sibling of the vault root is rejected.
    sibling = vault.parent / (vault.name + "_sibling")
    with pytest.raises(ValueError, match="escapes|outside|root"):
        store.validate_within_root(sibling)


def test_symlink_escape(store, vault):
    """A symlink (or Windows junction — the privilege-free equivalent) inside
    the store pointing outside the root is rejected on write and read paths."""
    outside = Path(tempfile.mkdtemp(prefix="r06_outside_"))
    try:
        inst, ev = "INST-SYM", "ev-sym-1"
        link_path = vault / inst
        created = False
        try:
            os.symlink(outside, link_path, target_is_directory=True)
            created = True
        except (OSError, NotImplementedError):
            # WinError 1314 (no SeCreateSymbolicLinkPrivilege): fall back to a
            # junction, which needs no privilege and escapes identically.
            import _winapi

            _winapi.CreateJunction(str(outside), str(link_path))
            created = True
        assert created, "neither symlink nor junction could be created"

        # Write path refuses to traverse the link.
        with pytest.raises(ValueError, match="symlink"):
            store.put(
                stream_or_bytes=b"escape attempt",
                metadata={"file_name": "escape.bin"},
                institution_id=inst,
                evidence_id=ev,
                object_version=1,
            )

        # Read path refuses as well: stage a plausible-looking target outside
        # then attempt an open through the link.
        (outside / ev).mkdir(parents=True, exist_ok=True)
        with pytest.raises(ValueError, match="symlink"):
            store.open(institution_id=inst, evidence_id=ev, object_version=1)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
        # Remove the junction itself (a directory unlink; do not follow it).
        link_path = vault / "INST-SYM"
        if link_path.exists():
            try:
                os.rmdir(str(link_path))
            except OSError:
                pass


def test_metadata_filename_traversal(store, vault):
    """Traversal payloads inside metadata['file_name'] are rejected, not
    sanitized silently."""
    inst, ev = "INST-TRAV", "ev-trav-1"
    bad_names = [
        "../evil.txt",
        "..\\evil.exe",
        "sub/dir/payload.bin",
        "..",
        "....//....//etc/passwd",
    ]
    for name in bad_names:
        with pytest.raises(ValueError, match="file_name|traversal"):
            store.put(
                stream_or_bytes=b"x",
                metadata={"file_name": name},
                institution_id=inst,
                evidence_id=f"ev-trav-{abs(hash(name)) % 1000}",
                object_version=1,
            )

    # Nothing was persisted for any rejected name.
    ev_root = vault / inst
    if ev_root.exists():
        assert list(ev_root.iterdir()) == [], f"unexpected artifacts: {list(ev_root.iterdir())}"


# ---------------------------------------------------------------------------
# R06 fix round 1: leaf-file containment on UNRESOLVED components
# ---------------------------------------------------------------------------


def _create_dir_link(link: Path, target: Path) -> None:
    """Create a directory symlink where the host allows it, else a junction
    (the privilege-free Windows equivalent)."""
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        import _winapi

        _winapi.CreateJunction(str(target), str(link))


def _remove_dir_link(link: Path) -> None:
    if link.exists() or link.is_symlink() or link.is_junction():
        try:
            os.rmdir(str(link))
        except OSError:
            pass


def test_symlink_scan_walks_unresolved_components(store, vault):
    """The unresolved-component walk fires on a link component BEFORE
    resolution — the old scan operated on already-resolved paths, where
    resolve() had eliminated the links, and could never fire."""
    outside = Path(tempfile.mkdtemp(prefix="r06_scan_outside_"))
    try:
        link = vault / "JUNC"
        _create_dir_link(link, outside)
        deep_target = link / "ev" / "v1" / "object.bin"
        with pytest.raises(ValueError, match="symlink"):
            store._check_no_symlinks(deep_target)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
        _remove_dir_link(vault / "JUNC")


def test_version_dir_link_escape_rejected(store, vault):
    """Regression guard (runs everywhere): a published version directory
    swapped for a link to an attacker directory containing a COMPLETE version
    (marker + valid metadata + object) is rejected before any read."""
    inst, ev = "INST-VDIR", "ev-vdir-1"
    outside = Path(tempfile.mkdtemp(prefix="r06_vdir_outside_"))
    try:
        content = b"attacker-supplied bytes"
        (outside / "object.bin").write_bytes(content)
        attacker_meta = {
            "evidence_id": ev,
            "object_version": 1,
            "institution_id": inst,
            "file_name": "x.bin",
            "display_name": "x.bin",
            "content_type": "application/octet-stream",
            "file_size": len(content),
            "sha256_hash": hashlib.sha256(content).hexdigest(),
            "created_at": "2026-01-01T00:00:00+00:00",
            "storage_format": "legacy_plaintext_read_only",
            "metadata": {"file_name": "x.bin"},
        }
        (outside / "meta.json").write_text(json.dumps(attacker_meta), encoding="utf-8")
        (outside / "COMMITTED.marker").write_text("x", encoding="utf-8")

        (vault / inst).mkdir(parents=True, exist_ok=True)
        _create_dir_link(vault / inst / ev, outside)

        with pytest.raises(ValueError, match="symlink"):
            store.open(institution_id=inst, evidence_id=ev, object_version=1)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
        _remove_dir_link(vault / inst / ev)


def test_leaf_file_symlink_rejected(store, vault):
    """A file symlink planted at meta.json (and at object.bin) of a
    legacy-format published version is rejected BEFORE any read — no
    arbitrary-file-read through the store API.

    Discriminating assertions: pre-fix, the store followed the link (meta
    read succeeded, then failed later on hash mismatch with a DIFFERENT
    message; the outside file was read). Post-fix, the link is detected on
    the unresolved component before any read.

    Skips only where the host cannot create file symlinks (Windows without
    SeCreateSymbolicLinkPrivilege); the junction tests above cover link
    rejection privilege-free there.
    """
    outside = Path(tempfile.mkdtemp(prefix="r06_leaf_outside_"))
    try:
        inst, ev = "INST-LEAF", "ev-leaf-1"
        content = b"honest legacy plaintext bytes"
        store.put(
            stream_or_bytes=io.BytesIO(content),
            metadata={"file_name": "honest.txt"},
            institution_id=inst,
            evidence_id=ev,
            object_version=1,
        )
        vdir = vault / inst / ev / "v1"

        attacker_content = b"ATTACKER ARBITRARY FILE CONTENT"
        attacker_meta = {
            "evidence_id": ev,
            "object_version": 1,
            "institution_id": inst,
            "file_name": "honest.txt",
            "content_type": "text/plain",
            "file_size": len(attacker_content),
            "sha256_hash": hashlib.sha256(attacker_content).hexdigest(),
            "created_at": "2026-01-01T00:00:00+00:00",
            "metadata": {"file_name": "honest.txt"},
        }
        (outside / "attacker_meta.json").write_text(json.dumps(attacker_meta), encoding="utf-8")
        (outside / "attacker_object.bin").write_bytes(attacker_content)

        # 1. meta.json leaf: unlink the honest metadata, link to attacker's.
        real_meta = (vdir / "meta.json").read_bytes()
        (vdir / "meta.json").unlink()
        try:
            os.symlink(outside / "attacker_meta.json", vdir / "meta.json")
        except (OSError, NotImplementedError):
            pytest.skip(
                "file symlink creation unavailable on this host "
                "(no SeCreateSymbolicLinkPrivilege); junction tests cover link rejection"
            )
        with pytest.raises(ValueError, match="symlink"):
            store.open(institution_id=inst, evidence_id=ev, object_version=1)

        # restore honest metadata
        (vdir / "meta.json").unlink()
        (vdir / "meta.json").write_bytes(real_meta)

        # 2. object.bin leaf: honest metadata inside, object links OUTSIDE.
        (vdir / "object.bin").unlink()
        os.symlink(outside / "attacker_object.bin", vdir / "object.bin")
        with pytest.raises(ValueError, match="symlink"):
            store.open(institution_id=inst, evidence_id=ev, object_version=1)
    finally:
        shutil.rmtree(outside, ignore_errors=True)
