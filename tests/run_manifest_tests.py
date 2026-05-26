#!/usr/bin/env python3
"""Validate sample collection manifests without third-party JSON Schema deps."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "tests" / "sample_manifests"
SCHEMA = ROOT / "tests" / "manifest.schema.json"
REQUIRED = {"schema_version", "script", "script_version", "platform", "collected_at", "redacted", "zip_requested", "files"}
PLATFORMS = {"windows", "linux", "macos"}
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def validate_manifest(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = []

    missing = sorted(REQUIRED - set(data))
    if missing:
        errors.append(f"missing required keys {missing}")

    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if data.get("platform") not in PLATFORMS:
        errors.append(f"invalid platform {data.get('platform')!r}")
    if not SEMVER.match(str(data.get("script_version", ""))):
        errors.append(f"invalid script_version {data.get('script_version')!r}")
    if not isinstance(data.get("redacted"), bool):
        errors.append("redacted must be boolean")
    if not isinstance(data.get("zip_requested"), bool):
        errors.append("zip_requested must be boolean")

    warnings = data.get("warnings", [])
    if warnings is not None and not isinstance(warnings, list):
        errors.append("warnings must be an array when present")
    warnings_count = data.get("warnings_count")
    if warnings_count is not None:
        if not isinstance(warnings_count, int) or warnings_count < 0:
            errors.append("warnings_count must be a non-negative integer")
        elif isinstance(warnings, list) and warnings_count != len(warnings):
            errors.append("warnings_count must match warnings length")

    files = data.get("files")
    if not isinstance(files, list):
        errors.append("files must be an array")
    else:
        for index, file_info in enumerate(files):
            if not isinstance(file_info, dict):
                errors.append(f"files[{index}] must be an object")
                continue
            for key in ("path", "bytes", "sha256"):
                if key not in file_info:
                    errors.append(f"files[{index}] missing {key}")
            if not isinstance(file_info.get("path"), str) or not file_info.get("path"):
                errors.append(f"files[{index}].path must be non-empty")
            if not isinstance(file_info.get("bytes"), int) or file_info.get("bytes", -1) < 0:
                errors.append(f"files[{index}].bytes must be non-negative integer")
            sha = file_info.get("sha256")
            if sha not in (None, "") and not SHA256.match(str(sha)):
                errors.append(f"files[{index}].sha256 must be a lowercase sha256 hex digest")

    return errors


def main() -> int:
    json.loads(SCHEMA.read_text(encoding="utf-8"))
    samples = sorted(SAMPLES.glob("*.json"))
    if not samples:
        print("No sample manifests found.", file=sys.stderr)
        return 2

    failures = {}
    for sample in samples:
        errors = validate_manifest(sample)
        if errors:
            failures[sample.name] = errors

    if failures:
        for name, errors in failures.items():
            print(f"[FAIL] {name}")
            for error in errors:
                print(f"  - {error}")
        return 1

    print(f"[OK] {len(samples)} manifest samples passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
