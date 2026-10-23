#!/usr/bin/env python3
"""
OpenAPI Schema Exporter (T07)
Specification §7 (R06)
Exports canonical deterministic OpenAPI JSON for V2 APIs to shared/openapi-v2.json.
"""

import os
import sys
import json
from pathlib import Path

# Add ai-engine to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
AI_ENGINE_DIR = ROOT_DIR / "ai-engine"
sys.path.insert(0, str(AI_ENGINE_DIR))

from app.main import app


def export_openapi(target_path: Path):
    full_spec = app.openapi()

    # Filter paths for V2 only to keep shared contract strictly focused on V2
    v2_paths = {k: v for k, v in full_spec.get("paths", {}).items() if k.startswith("/api/v2")}

    # Also keep schemas referenced by V2 paths
    components = full_spec.get("components", {})
    schemas = components.get("schemas", {})

    v2_spec = {
        "openapi": full_spec.get("openapi", "3.1.0"),
        "info": {
            "title": "Cyber-Forensic Auditing Framework - V2 API",
            "version": "2.0.0",
            "description": "Authoritative contract for institutional evidence verification, policy resolution, and lifecycle readiness."
        },
        "paths": dict(sorted(v2_paths.items())),
        "components": {
            "schemas": dict(sorted(schemas.items()))
        }
    }

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(v2_spec, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")

    print(f"[SUCCESS] Exported canonical OpenAPI V2 schema to {target_path}")


if __name__ == "__main__":
    target = ROOT_DIR / "shared" / "openapi-v2.json"
    export_openapi(target)
