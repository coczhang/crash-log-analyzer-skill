#!/usr/bin/env python3
"""Run repository validation that does not require platform-specific tools."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILES = [
    ROOT / ".agents" / "skills" / "crash-log-analyzer" / "scripts" / "classify_crash_log.py",
    ROOT / ".agents" / "skills" / "crash-log-analyzer" / "scripts" / "redact_text.py",
    ROOT / "tests" / "run_golden_tests.py",
    ROOT / "tests" / "run_manifest_tests.py",
    ROOT / "tests" / "test_redaction.py",
    ROOT / "tests" / "validate_skill.py",
    ROOT / "tests" / "run_all.py",
]
COMMANDS = [
    [sys.executable, "-B", "tests/validate_skill.py"],
    [sys.executable, "-B", "tests/run_golden_tests.py"],
    [sys.executable, "-B", "tests/run_manifest_tests.py"],
    [sys.executable, "-B", "tests/test_redaction.py"],
]


def check_python_syntax() -> int:
    for path in PYTHON_FILES:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    print(f"[OK] {len(PYTHON_FILES)} Python files parsed")
    return 0


def run_command(command: list[str]) -> int:
    completed = subprocess.run(command, cwd=ROOT)
    return completed.returncode


def main() -> int:
    check_python_syntax()
    for command in COMMANDS:
        rc = run_command(command)
        if rc != 0:
            return rc
    print("[OK] repository validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
