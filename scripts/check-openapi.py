#!/usr/bin/env python3
"""
OpenAPI Schema Drift Checker (T07)
Specification §7 (R06)
Verifies that shared/openapi-v2.json is fully up-to-date with current FastAPI models.
"""

import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
AI_ENGINE_DIR = ROOT_DIR / "ai-engine"
sys.path.insert(0, str(AI_ENGINE_DIR))

from app.main import app


def check_openapi(target_path: Path) -> bool:
    if not target_path.exists():
        print(f"[ERROR] OpenAPI schema file does not exist: {target_path}")
        return False

    full_spec = app.openapi()
    v2_paths = {k: v for k, v in full_spec.get("paths", {}).items() if k.startswith("/api/v2")}
    schemas = full_spec.get("components", {}).get("schemas", {})

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

    generated_str = json.dumps(v2_spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with open(target_path, "r", encoding="utf-8") as f:
        existing_str = f.read()

    if generated_str != existing_str:
        print("[ERROR] OpenAPI V2 schema drift detected! Run 'npm run api:export' to synchronize.")
        return False

    print("[SUCCESS] OpenAPI V2 schema is up to date (no drift detected).")
    return True


if __name__ == "__main__":
    target = ROOT_DIR / "shared" / "openapi-v2.json"
    if not check_openapi(target):
        sys.exit(1)
    sys.exit(0)
