"""R18 integration tests — the model registry is bound to the evaluation
decision (spec §9).

A model may only be activated from a sealed, PASSED run manifest whose
model hash matches the artifact the server will load. A failed gate keeps
the engine rule_based. Thresholds cannot be retuned after the evaluation
seal: the seal covers the labels/predictions hashes, the config hash and
the evaluation time, so any reopening with changed thresholds is refused
and requires a NEW run — never an independent re-test on already-seen data.
"""
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
for _p in (str(ROOT),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from research import run_experiments  # noqa: E402  (seal/fixture builder)
from app.models.registry import (  # noqa: E402
    ModelActivationError,
    ModelRegistry,
    compute_file_sha256,
)
from app.services.assessment_service import AssessmentService  # noqa: E402

ARTIFACT_BYTES = (
    b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x12"
    b"isolation_forest_r18_fixture_payload"
)
OTHER_ARTIFACT_BYTES = b"not-the-evaluated-artifact-payload"


def _sha(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def build_manifest_doc(server_artifact: Path, **overrides) -> dict:
    """A valid PASSED run manifest whose model hash matches the artifact
    deployed at the server path. Built with the research seal builder so the
    seal format has a single source."""
    model_hash = compute_file_sha256(str(server_artifact))
    config_hash = "0x" + "c" * 64
    split_hash = "0x" + "5" * 64
    seal = run_experiments.build_evaluation_seal(
        run_id="EXP-AML-42-TEST",
        labels=[1, 0, 1, 0],
        predictions=[1, 0, 0, 0],
        config_hash=config_hash,
        split_hash=split_hash,
        model_hash=model_hash,
    )
    doc = {
        "experiment_id": "EXP-AML-42-TEST",
        "protocol_version": "1.1.0",
        "model_id": "hybrid_ensemble",
        "outcome": "PASSED",
        "model_hash": model_hash,
        "split_hash": split_hash,
        "config_hash": config_hash,
        "model_artifact_path": "ai-engine/models/pretrained/fraud_model.joblib",
        "gate_decision": {
            "research_status": "PASSED",
            "activation_allowed": True,
            "reasons": [],
            "claim": ("Research gates PASSED ... ACTIVATION APPROVED "
                      "(generated from the decision)"),
        },
        "evaluation_seal": seal,
    }
    doc.update(overrides)
    return doc


@pytest.fixture
def env(tmp_path):
    server_artifact = tmp_path / "fraud_model.joblib"
    server_artifact.write_bytes(ARTIFACT_BYTES)
    binding_path = tmp_path / "active_model.json"
    manifest_path = tmp_path / "run-manifest.json"
    manifest_path.write_text(
        json.dumps(build_manifest_doc(server_artifact), indent=2),
        encoding="utf-8")
    return SimpleNamespace(
        tmp=tmp_path,
        artifact=server_artifact,
        binding_path=binding_path,
        manifest_path=manifest_path,
    )


def _registry(env) -> ModelRegistry:
    return ModelRegistry(server_model_path=str(env.artifact),
                         binding_path=str(env.binding_path))


def _write_manifest(env, doc: dict) -> Path:
    env.manifest_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return env.manifest_path


# ---------------------------------------------------------------------------
# Gate must be PASSED + sealed + hash-matched, or activation is refused
# ---------------------------------------------------------------------------

def test_invalid_manifest_or_hash_blocks_activation(env):
    registry = _registry(env)

    # a) missing gate decision
    doc = build_manifest_doc(env.artifact)
    del doc["gate_decision"]
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # b) missing split fingerprint
    doc = build_manifest_doc(env.artifact)
    del doc["split_hash"]
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # c) research outcome FAILED
    doc = build_manifest_doc(env.artifact)
    doc["outcome"] = "FAILED"
    doc["gate_decision"] = {
        "research_status": "FAILED", "activation_allowed": False,
        "reasons": ["recall 0.7698 below the 0.85 floor"],
        "claim": "Research gates FAILED ..."}
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # d) decision recorded but activation not allowed
    doc = build_manifest_doc(env.artifact)
    doc["gate_decision"]["activation_allowed"] = False
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # e) tampered seal content (seal hash no longer reproduces)
    doc = build_manifest_doc(env.artifact)
    doc["evaluation_seal"]["labels_sha256"] = _sha(b"tampered-labels")
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # f) model hash mismatch against the artifact the server will load
    env.artifact.write_bytes(OTHER_ARTIFACT_BYTES)
    doc = build_manifest_doc(env.artifact)  # manifest now matches OTHER bytes
    doc["model_hash"] = _sha(ARTIFACT_BYTES)
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # g) evaluated artifact not deployed at the server path at all
    doc = build_manifest_doc(env.artifact)
    env.artifact.unlink()
    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", _write_manifest(env, doc))

    # h) wrong model_id requested
    env.artifact.write_bytes(ARTIFACT_BYTES)
    doc = build_manifest_doc(env.artifact)
    with pytest.raises(ModelActivationError):
        registry.activate("other_model", _write_manifest(env, doc))

    # no invalid attempt may leave an activation binding behind
    assert not env.binding_path.exists()


def test_failed_gate_keeps_rule_based(env):
    doc = build_manifest_doc(env.artifact)
    doc["outcome"] = "FAILED"
    doc["gate_decision"] = {
        "research_status": "FAILED",
        "activation_allowed": False,
        "reasons": [
            "recall 0.7698 is below the 0.85 floor",
            "FPR 1.57/1000 (0.157%) is worse than the baseline 0.00/1000 "
            "(0.000%); false-positive reduction may NOT be claimed",
        ],
        "claim": "Research gates FAILED ... ML activation DENIED ...",
    }
    doc["gate_decision"] = dict(doc["gate_decision"])
    path = _write_manifest(env, doc)
    registry = _registry(env)

    with pytest.raises(ModelActivationError):
        registry.activate("hybrid_ensemble", path)

    # the engine stays rule_based by default — no binding, no hybrid
    assert not env.binding_path.exists()
    mode, binding = registry.resolve_engine()
    assert mode == "rule_based"
    assert binding is None
    assert registry.binding_status() == "UNBOUND"

    # an operator-requested hybrid without a gated model fails clearly
    with pytest.raises(ModelActivationError):
        registry.resolve_engine(requested_mode="hybrid")


def test_threshold_cannot_be_retuned_after_seal(env):
    registry = _registry(env)
    path = env.manifest_path  # valid PASSED manifest written by the fixture

    binding = registry.activate("hybrid_ensemble", path)
    assert binding.model_id == "hybrid_ensemble"
    assert binding.model_hash == compute_file_sha256(str(env.artifact))
    assert registry.binding_status() == "ACTIVE"
    assert env.binding_path.exists()
    persisted = json.loads(env.binding_path.read_text(encoding="utf-8"))
    assert persisted["research_status"] == "PASSED"
    assert persisted["activation_allowed"] is True
    assert persisted["config_hash"].startswith("0x")

    mode, bound = registry.resolve_engine()
    assert mode == "hybrid" and bound is not None

    # re-activating the SAME sealed manifest is idempotent (same evaluation)
    registry.activate("hybrid_ensemble", path)
    assert registry.binding_status() == "ACTIVE"

    # swapping the deployed artifact breaks the binding: the seal pins the
    # exact bytes the server must load
    env.artifact.write_bytes(OTHER_ARTIFACT_BYTES)
    with pytest.raises(ModelActivationError):
        registry.resolve_engine(requested_mode="hybrid")
    assert registry.binding_status() == "BROKEN"
    env.artifact.write_bytes(ARTIFACT_BYTES)
    assert registry.binding_status() == "ACTIVE"

    # retuning thresholds after the seal: the manifest's config hash changes
    # but the seal does not — activation is refused and requires a NEW run
    retuned = json.loads(path.read_text(encoding="utf-8"))
    retuned["config_hash"] = "0x" + "d" * 64
    _write_manifest(env, retuned)

    with pytest.raises(ModelActivationError) as err:
        registry.activate("hybrid_ensemble", path)
    assert "new run" in str(err.value).lower()

    # the stale binding no longer reproduces against the tampered manifest:
    # reopening the evaluation becomes a NEW run, never an independent
    # re-test on the already-seen test data
    assert registry.binding_status() == "BROKEN"
    with pytest.raises(ModelActivationError):
        registry.resolve_engine(requested_mode="hybrid")


def test_assessment_service_defaults_rule_based_and_refuses_undeclared_hybrid(env):
    # default: rule_based, no binding
    default_registry = ModelRegistry(
        server_model_path=str(env.artifact),
        binding_path=str(env.tmp / "binding-default.json"))
    service = AssessmentService(model_registry=default_registry)
    mode, binding = service.resolve_engine_mode()
    assert mode == "rule_based"
    assert binding is None

    # once a sealed PASSED run is activated, an explicit hybrid request
    # resolves against the binding
    active_registry = ModelRegistry(
        server_model_path=str(env.artifact),
        binding_path=str(env.tmp / "binding-active.json"))
    active_registry.activate("hybrid_ensemble", env.manifest_path)
    hybrid_service = AssessmentService(
        model_registry=active_registry, requested_engine="hybrid")
    mode2, binding2 = hybrid_service.resolve_engine_mode()
    assert mode2 == "hybrid"
    assert binding2 is not None
    assert binding2.model_id == "hybrid_ensemble"

    # operator-requested hybrid with a NON-gated model fails the request
    # clearly (no undeclared fallback to rules-only)
    refusing_service = AssessmentService(
        model_registry=ModelRegistry(
            server_model_path=str(env.artifact),
            binding_path=str(env.tmp / "binding-none.json")),
        requested_engine="hybrid")
    with pytest.raises(ModelActivationError):
        refusing_service.resolve_engine_mode()
