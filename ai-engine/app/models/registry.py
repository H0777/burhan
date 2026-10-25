"""
Model Registry & Integrity-Verified Artifact Loading
Cyber-Forensic Auditing Framework - Specification §6, §7 (T19, R12, R13, R18)

Enforces:
1. Cryptographic SHA-256 artifact verification prior to deserialization (tamper rejection).
2. Explicit rejection of text markers, dummy placeholders, or user-uploaded pickles.
3. Feature schema and ordering immutability.
4. Truthful ModelStatus reporting for readiness checks (no silent fake fallbacks).
5. R18: the registry is BOUND TO THE EVALUATION DECISION — a model can only
   be activated from a sealed, PASSED run manifest (research/evaluate_gate
   decision recorded by the runner) whose model hash matches the artifact
   the server will load. The default engine is rule_based; an
   operator-requested hybrid without a valid binding fails clearly (no
   undeclared fallback). The evaluation seal covers the evaluated
   labels/predictions hashes, the config hash and the evaluation time, so
   thresholds cannot be retuned after the seal: reopening requires a NEW
   research run, never an independent re-test on already-seen data.
"""

import os
import json
import hashlib
from dataclasses import dataclass, fields as dataclass_fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import joblib

FEATURE_SCHEMA_V2 = [
    "amount_minor",
    "sender_daily_volume_minor",
    "sender_daily_count",
    "sender_window_burst_10m",
    "is_after_hours",
    "structuring_ratio",
]

ACTIVATION_BINDING_SCHEMA_VERSION = "model-activation/1"
RESEARCH_STATUS_PASSED = "PASSED"

# Field names of the evaluation seal produced by research/run_experiments.py
# (build_evaluation_seal). Validation mirrors the research-side
# canonicalization so the seal has one format and two independent checkers.
_SEAL_REQUIRED_KEYS = (
    "schema_version", "run_id", "labels_sha256", "predictions_sha256",
    "config_hash", "split_hash", "model_hash", "evaluated_at", "seal_hash",
)


def _canonical_json_bytes(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest().lower()


def _sha256_file_bytes(path: Path) -> str:
    return _sha256_hex(path.read_bytes())


@dataclass
class ModelArtifactMetadata:
    model_hash: str
    feature_schema: List[str]
    training_dataset_hash: str
    library_versions: Dict[str, str]
    created_at: str
    metrics: Dict[str, float]


@dataclass
class ModelStatus:
    loaded: bool
    model: Optional[Any] = None
    model_hash: Optional[str] = None
    feature_schema: Optional[List[str]] = None
    metadata: Optional[ModelArtifactMetadata] = None
    error_reason: Optional[str] = None


def compute_file_sha256(filepath: str) -> str:
    """Computes exact lowercase hex SHA-256 of a file with '0x' prefix."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return "0x" + sha.hexdigest().lower()


def load_validated_model(
    model_path: str,
    expected_hash: Optional[str] = None,
    metadata_path: Optional[str] = None,
    enforce_schema: bool = True,
) -> ModelStatus:
    """
    Safely verifies and loads a pre-trained scikit-learn model artifact.
    Rejects tampered, corrupt, placeholder, or mismatched models.
    """
    if not model_path or not os.path.exists(model_path):
        return ModelStatus(
            loaded=False,
            error_reason=f"Model artifact not found at path: {model_path}",
        )

    # 1. Reject dummy placeholder text files immediately
    try:
        with open(model_path, "rb") as f:
            header = f.read(64)
            if b"OFFLINE_HEURISTIC" in header or b"PLACEHOLDER" in header or b"DUMMY" in header:
                return ModelStatus(
                    loaded=False,
                    error_reason="Rejected placeholder marker text: expected binary serialized scikit-learn artifact",
                )
    except Exception as exc:
        return ModelStatus(
            loaded=False,
            error_reason=f"Failed reading model header: {str(exc)}",
        )

    # 2. Check SHA-256 integrity if expected_hash provided
    actual_hash = compute_file_sha256(model_path)
    if expected_hash:
        expected_clean = expected_hash.strip().lower()
        if not expected_clean.startswith("0x"):
            expected_clean = "0x" + expected_clean

        if actual_hash != expected_clean:
            return ModelStatus(
                loaded=False,
                model_hash=actual_hash,
                error_reason=(
                    f"Cryptographic hash mismatch (tampering detected): "
                    f"expected {expected_clean}, got {actual_hash}"
                ),
            )

    # 3. Load companion metadata if available
    meta: Optional[ModelArtifactMetadata] = None
    target_meta_path = metadata_path or (model_path + ".meta.json")
    if os.path.exists(target_meta_path):
        try:
            with open(target_meta_path, "r", encoding="utf-8") as f:
                raw_meta = json.load(f)
                meta = ModelArtifactMetadata(
                    model_hash=raw_meta.get("model_hash", actual_hash),
                    feature_schema=raw_meta.get("feature_schema", FEATURE_SCHEMA_V2),
                    training_dataset_hash=raw_meta.get("training_dataset_hash", ""),
                    library_versions=raw_meta.get("library_versions", {}),
                    created_at=raw_meta.get("created_at", ""),
                    metrics=raw_meta.get("metrics", {}),
                )
                if enforce_schema and meta.feature_schema != FEATURE_SCHEMA_V2:
                    return ModelStatus(
                        loaded=False,
                        model_hash=actual_hash,
                        error_reason=(
                            f"Feature schema mismatch in metadata: expected {FEATURE_SCHEMA_V2}, "
                            f"got {meta.feature_schema}"
                        ),
                    )
        except Exception as exc:
            return ModelStatus(
                loaded=False,
                model_hash=actual_hash,
                error_reason=f"Failed parsing artifact metadata: {str(exc)}",
            )

    # 4. Deserialize model using joblib safely
    try:
        loaded_model = joblib.load(model_path)
    except Exception as exc:
        return ModelStatus(
            loaded=False,
            model_hash=actual_hash,
            error_reason=f"Deserialization failure (corrupted artifact): {str(exc)}",
        )

    # 5. Check if loaded object is a valid estimator
    if not hasattr(loaded_model, "predict"):
        return ModelStatus(
            loaded=False,
            model_hash=actual_hash,
            error_reason="Loaded object does not implement predict() estimator interface",
        )

    return ModelStatus(
        loaded=True,
        model=loaded_model,
        model_hash=actual_hash,
        feature_schema=meta.feature_schema if meta else FEATURE_SCHEMA_V2,
        metadata=meta,
        error_reason=None,
    )


# ---------------------------------------------------------------------------
# R18: activation binding — the registry is bound to the evaluation decision
# ---------------------------------------------------------------------------

class ModelActivationError(RuntimeError):
    """Activation of the gated model was requested but the recorded research
    decision, seal or artifact chain does not authorize it. Fail-closed:
    there is never an undeclared fallback to a model that was not evaluated."""


@dataclass
class ActivationBinding:
    """The sealed activation record binding a model id to a PASSED,
    sealed research run whose artifact the server will load."""
    model_id: str
    model_hash: str
    split_hash: str
    config_hash: str
    run_id: str
    research_status: str
    activation_allowed: bool
    sealed_at: str
    activated_at: str
    run_manifest_path: str
    run_manifest_sha256: str
    seal_hash: str

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": ACTIVATION_BINDING_SCHEMA_VERSION,
            "model_id": self.model_id,
            "model_hash": self.model_hash,
            "split_hash": self.split_hash,
            "config_hash": self.config_hash,
            "run_id": self.run_id,
            "research_status": self.research_status,
            "activation_allowed": self.activation_allowed,
            "sealed_at": self.sealed_at,
            "activated_at": self.activated_at,
            "run_manifest_path": self.run_manifest_path,
            "run_manifest_sha256": self.run_manifest_sha256,
            "seal_hash": self.seal_hash,
        }


def _verify_seal_structure(seal: Any) -> List[str]:
    """Validation-side mirror of research verify_evaluation_seal: recompute
    the seal hash over the canonical body and check the schema version."""
    problems: List[str] = []
    if not isinstance(seal, dict):
        return ["run manifest carries no evaluation seal"]
    missing = [k for k in _SEAL_REQUIRED_KEYS if k not in seal]
    if missing:
        problems.append(f"evaluation seal is missing {missing}")
        return problems
    body = {k: seal[k] for k in _SEAL_REQUIRED_KEYS if k != "seal_hash"}
    if _sha256_hex(_canonical_json_bytes(body)) != seal["seal_hash"]:
        problems.append(
            "evaluation seal hash does not reproduce (the seal was tampered "
            "with or fields changed after evaluation)")
    return problems


def _verify_run_manifest_authorization(
        manifest: Any) -> Tuple[List[str], Optional[str]]:
    """Checks that a run manifest records a PASSED gate decision that allows
    activation, with an intact evaluation seal and all fingerprints present.
    Returns (problems, model_hash)."""
    problems: List[str] = []
    if not isinstance(manifest, dict):
        return ["run manifest is not a JSON object"], None
    required = ("experiment_id", "model_id", "outcome", "gate_decision",
                "evaluation_seal", "model_hash", "split_hash", "config_hash")
    missing = [k for k in required if k not in manifest]
    if missing:
        problems.append(f"run manifest is missing {missing}")
        return problems, None

    gate = manifest["gate_decision"]
    if not isinstance(gate, dict):
        problems.append("gate_decision must be an object")
    else:
        status = gate.get("research_status")
        if status != RESEARCH_STATUS_PASSED:
            problems.append(
                f"research decision is {status!r}, not PASSED — activation "
                f"requires a PASSED gate (a FAILED or INSUFFICIENT_DATA run "
                f"keeps the engine rule_based)")
        if gate.get("activation_allowed") is not True:
            problems.append("the recorded gate decision does not allow "
                            "activation")
        if not isinstance(gate.get("reasons"), list):
            problems.append("gate_decision.reasons must be a list")

    if manifest["outcome"] != RESEARCH_STATUS_PASSED:
        problems.append(
            f"run outcome is {manifest['outcome']!r}, not PASSED")

    for key in ("model_hash", "split_hash", "config_hash"):
        value = manifest[key]
        if not isinstance(value, str) or not value.startswith("0x"):
            problems.append(f"run manifest {key} is not a fingerprint")

    problems.extend(_verify_seal_structure(manifest["evaluation_seal"]))
    seal = manifest["evaluation_seal"]
    if isinstance(seal, dict) and not problems:
        # the seal must pin exactly the manifest's fingerprints
        for manifest_key in ("config_hash", "split_hash", "model_hash"):
            if seal.get(manifest_key) != manifest[manifest_key]:
                problems.append(
                    f"evaluation seal {manifest_key} does not match the run "
                    f"manifest {manifest_key} (thresholds/config were "
                    f"changed after the seal; a NEW run is required)")
        if seal.get("run_id") != manifest["experiment_id"]:
            problems.append("evaluation seal run_id does not match the run "
                            "manifest experiment_id")
    return problems, manifest.get("model_hash")


class ModelRegistry:
    """Binds loadable model artifacts to the research evaluation decision.

    The default server artifact path is the one the engine loads
    (``app/models/pretrained/fraud_model.joblib``). ``activate`` refuses
    anything but a sealed, PASSED run manifest whose model hash matches the
    deployed artifact. The default engine mode is rule_based; an
    operator-requested hybrid without a valid binding fails loudly (no
    undeclared fallback), and a binding that no longer reproduces (artifact
    swapped, manifest retuned) is broken until a NEW sealed run is bound.
    """

    def __init__(self,
                 server_model_path: Optional[str] = None,
                 binding_path: Optional[str] = None) -> None:
        pretrained_dir = Path(__file__).resolve().parent / "pretrained"
        self.server_model_path = (
            Path(server_model_path) if server_model_path
            else pretrained_dir / "fraud_model.joblib")
        self.binding_path = (
            Path(binding_path) if binding_path
            else pretrained_dir / "active_model.json")

    # -- activation ---------------------------------------------------------

    def activate(self, model_id: str, run_manifest_path) -> ActivationBinding:
        """Activate ``model_id`` from a sealed PASSED run manifest.

        Requires: the manifest to record research_status PASSED with
        activation_allowed, an intact evaluation seal pinning the manifest's
        config/split/model fingerprints, and the evaluated artifact (by
        SHA-256) deployed at the server path the engine will load. Writes
        the activation binding; refuses (ModelActivationError) otherwise and
        never leaves a partial binding behind.
        """
        path = Path(run_manifest_path)
        if not path.exists():
            raise ModelActivationError(
                f"activation refused: run manifest not found: {path}")
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ModelActivationError(
                f"activation refused: run manifest {path} is not valid "
                f"JSON: {exc}") from exc

        problems, model_hash = _verify_run_manifest_authorization(manifest)
        if problems:
            raise ModelActivationError(
                "activation refused: " + "; ".join(problems))
        assert model_hash is not None

        if model_id != manifest["model_id"]:
            raise ModelActivationError(
                f"activation refused: requested model_id {model_id!r} != "
                f"evaluated model {manifest['model_id']!r}")

        if not self.server_model_path.exists():
            raise ModelActivationError(
                f"activation refused: the evaluated artifact is not deployed "
                f"at the server path {self.server_model_path}; deploy the "
                f"evaluated model (hash {model_hash}) before activation — "
                f"the registry binds only the artifact the server will load")
        actual_hash = compute_file_sha256(str(self.server_model_path))
        if actual_hash != model_hash:
            raise ModelActivationError(
                f"activation refused: server artifact hash {actual_hash} "
                f"does not match the evaluated model hash {model_hash}")

        seal = manifest["evaluation_seal"]
        binding = ActivationBinding(
            model_id=model_id,
            model_hash=model_hash,
            split_hash=manifest["split_hash"],
            config_hash=manifest["config_hash"],
            run_id=manifest["experiment_id"],
            research_status=RESEARCH_STATUS_PASSED,
            activation_allowed=True,
            sealed_at=seal["evaluated_at"],
            activated_at=datetime.now(timezone.utc).isoformat(),
            run_manifest_path=str(path.resolve()),
            run_manifest_sha256=_sha256_file_bytes(path),
            seal_hash=seal["seal_hash"],
        )
        self.binding_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.binding_path.with_suffix(".json.tmp")
        tmp_path.write_text(
            json.dumps(binding.to_json_dict(), indent=2), encoding="utf-8")
        os.replace(str(tmp_path), str(self.binding_path))
        return binding

    # -- binding state ------------------------------------------------------

    def _load_binding(self) -> Optional[ActivationBinding]:
        if not self.binding_path.exists():
            return None
        try:
            raw = json.loads(self.binding_path.read_text(encoding="utf-8"))
            known = {f.name for f in dataclass_fields(ActivationBinding)}
            return ActivationBinding(
                **{k: v for k, v in raw.items() if k in known})
        except (OSError, ValueError, TypeError):
            return None

    def _binding_problems(self, binding: ActivationBinding) -> List[str]:
        """Re-verify the whole binding chain at read time: manifest file
        unchanged since activation, decision still PASSED/allowed, seal
        intact, artifact hash still the sealed one."""
        problems: List[str] = []
        manifest_path = Path(binding.run_manifest_path)
        if not manifest_path.exists():
            problems.append(
                f"bound run manifest is missing: {manifest_path}")
        else:
            if _sha256_file_bytes(manifest_path) != binding.run_manifest_sha256:
                problems.append(
                    "the bound run manifest file changed after activation — "
                    "reopening the evaluation requires a NEW run, never a "
                    "re-test on the already-seen data")
            try:
                manifest = json.loads(
                    manifest_path.read_text(encoding="utf-8"))
                auth_problems, _ = _verify_run_manifest_authorization(manifest)
                problems.extend(auth_problems)
            except (OSError, ValueError) as exc:
                problems.append(f"bound run manifest is unreadable: {exc}")
        if not self.server_model_path.exists():
            problems.append(
                f"the sealed artifact is missing from the server path "
                f"{self.server_model_path}")
        elif compute_file_sha256(str(self.server_model_path)) \
                != binding.model_hash:
            problems.append(
                "the artifact at the server path no longer matches the "
                "sealed model hash (artifact was swapped after activation)")
        return problems

    def binding_status(self) -> str:
        """Truthful readiness surface: UNBOUND (no binding), ACTIVE (binding
        fully reproduces), or BROKEN (binding exists but fails to
        reproduce). Never raises."""
        binding = self._load_binding()
        if binding is None:
            return "UNBOUND"
        return "ACTIVE" if not self._binding_problems(binding) else "BROKEN"

    def active_binding(self) -> Optional[ActivationBinding]:
        """The activation binding when it fully reproduces, else None."""
        binding = self._load_binding()
        if binding is not None and not self._binding_problems(binding):
            return binding
        return None

    def resolve_engine(self,
                       requested_mode: str = "auto"
                       ) -> Tuple[str, Optional[ActivationBinding]]:
        """Resolve the evaluation engine against the activation binding.

        - ``rule_based``: always rule_based (never consults the model);
        - ``auto`` (default): hybrid only with a fully valid binding,
          otherwise the declared rule_based default;
        - ``hybrid``: requires a valid binding — without one, or with a
          broken one, raises ModelActivationError (an operator-requested
          hybrid with a non-gated model fails clearly; no undeclared
          fallback).
        """
        if requested_mode not in ("auto", "rule_based", "hybrid"):
            raise ValueError(
                f"unknown engine mode {requested_mode!r}; expected "
                f"auto|rule_based|hybrid")
        if requested_mode == "rule_based":
            return "rule_based", None

        binding = self._load_binding()
        if binding is None:
            if requested_mode == "hybrid":
                raise ModelActivationError(
                    "hybrid engine requested but the model registry has no "
                    f"activation binding (expected at "
                    f"{self.binding_path}); activate a gated model via "
                    "ModelRegistry.activate(model_id, run_manifest_path) or "
                    "request engine='rule_based' explicitly — no undeclared "
                    "fallback")
            return "rule_based", None

        problems = self._binding_problems(binding)
        if problems:
            raise ModelActivationError(
                f"activation binding at {self.binding_path} is broken: "
                + "; ".join(problems)
                + ". Re-activation requires a NEW sealed PASSED research run "
                "(never an independent re-test on already-seen data), or "
                "remove the stale binding to stay rule_based")
        return "hybrid", binding
