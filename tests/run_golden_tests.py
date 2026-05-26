#!/usr/bin/env python3
"""Golden tests for crash-log-analyzer's triage script."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".agents" / "skills" / "crash-log-analyzer" / "scripts" / "classify_crash_log.py"
GOLDEN = ROOT / "tests" / "golden"
ALLOWED_EXPECT_KEYS = {
    "exit_classification",
    "platforms",
    "domains",
    "references",
    "exception_codes",
    "signals_or_statuses",
    "key_fields",
    "confidence",
    "fault_context",
}
ALLOWED_CLASSIFICATIONS = {
    "normal exit",
    "crash",
    "forced kill",
    "hang",
    "hang followed by forced kill",
    "shutdown/restart",
    "requested stop",
    "unknown",
}


def load_classifier():
    namespace = runpy.run_path(str(SCRIPT))
    return namespace["make_summary"]


def names(items):
    return [item["name"] for item in items]


def check_contains(label, actual, expected):
    missing = [item for item in expected if item not in actual]
    if missing:
        return [f"{label}: missing {missing}; actual={actual}"]
    return []


def check_key_fields(actual_fields, expected_fields):
    errors = []
    for key, expected_values in expected_fields.items():
        actual_values = actual_fields.get(key, [])
        missing = [value for value in expected_values if value not in actual_values]
        if missing:
            errors.append(f"key_fields.{key}: missing {missing}; actual={actual_values}")
    return errors


def check_fault_context(actual_context, expected_context):
    errors = []
    for key, expected_value in expected_context.items():
        actual_value = actual_context.get(key)
        if actual_value != expected_value:
            errors.append(f"fault_context.{key}: expected {expected_value!r}, got {actual_value!r}")
    return errors


def run_case(make_summary, input_path):
    expected_path = input_path.with_suffix(".expect.json")
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    summary = make_summary(input_path.read_text(encoding="utf-8"), 25)

    errors = []
    unexpected_keys = sorted(set(expected) - ALLOWED_EXPECT_KEYS)
    if unexpected_keys:
        errors.append(f"expect schema: unexpected keys {unexpected_keys}")

    expected_classification = expected.get("exit_classification")
    if expected_classification and expected_classification not in ALLOWED_CLASSIFICATIONS:
        errors.append(f"expect schema: invalid exit_classification {expected_classification!r}")
    actual_classification = summary["exit"]["classification"]
    if expected_classification and actual_classification != expected_classification:
        errors.append(f"exit_classification: expected {expected_classification!r}, got {actual_classification!r}")

    errors.extend(check_contains("platforms", names(summary["platforms"]), expected.get("platforms", [])))
    errors.extend(check_contains("domains", names(summary["domains"]), expected.get("domains", [])))
    errors.extend(check_contains("references", summary["recommended_references"], expected.get("references", [])))

    expected_codes = expected.get("exception_codes", [])
    actual_codes = [item["code"].lower() for item in summary["exception_codes"]]
    errors.extend(check_contains("exception_codes", actual_codes, [code.lower() for code in expected_codes]))

    expected_signals = expected.get("signals_or_statuses", [])
    actual_signals = [item["signal"].lower() for item in summary["signals_or_statuses"]]
    errors.extend(check_contains("signals_or_statuses", actual_signals, [signal.lower() for signal in expected_signals]))

    errors.extend(check_key_fields(summary.get("key_fields", {}), expected.get("key_fields", {})))
    expected_confidence = expected.get("confidence")
    if expected_confidence and summary["exit"].get("confidence") != expected_confidence:
        errors.append(f"confidence: expected {expected_confidence!r}, got {summary['exit'].get('confidence')!r}")

    errors.extend(check_fault_context(summary.get("fault_context", {}), expected.get("fault_context", {})))
    return errors


def main() -> int:
    make_summary = load_classifier()
    inputs = sorted(GOLDEN.glob("*.txt"))
    if not inputs:
        print("No golden test inputs found.", file=sys.stderr)
        return 2

    failures = {}
    for input_path in inputs:
        errors = run_case(make_summary, input_path)
        if errors:
            failures[input_path.name] = errors

    if failures:
        for case, errors in failures.items():
            print(f"[FAIL] {case}")
            for error in errors:
                print(f"  - {error}")
        return 1

    print(f"[OK] {len(inputs)} golden tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
