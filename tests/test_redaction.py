#!/usr/bin/env python3
"""Regression tests for text redaction."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".agents" / "skills" / "crash-log-analyzer" / "scripts" / "redact_text.py"


def main() -> int:
    redact_text = runpy.run_path(str(SCRIPT))["redact_text"]
    source = "\n".join(
        [
            r"user=jane@example.com",
            r"ip=192.168.1.42",
            r"token=abc1234567890xyz",
            r"Authorization: Bearer eyJhbGciOiJ.fake-token",
            r"jwt=eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkw.signature987654321",
            r"license_key=LIC-1234-5678-SECRET",
            r"tenant_id=tenant-abc-123",
            r"user=ACME-DOMAIN\camerauser",
            r"ipv6=2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            r"path=C:\Users\alice\AppData\Local\Crash",
            r"home=/home/bob/.cache/app",
            r"hostname=prod-camera-17",
            r"customer=acme-camera-lab",
        ]
    )
    redacted = redact_text(source, ["ACME-CAMERA-LAB"])
    forbidden = [
        "jane@example.com",
        "192.168.1.42",
        "abc1234567890xyz",
        "eyJhbGciOiJ.fake-token",
        "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkw.signature987654321",
        "LIC-1234-5678-SECRET",
        "tenant-abc-123",
        r"ACME-DOMAIN\camerauser",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        r"C:\Users\alice",
        "/home/bob",
        "prod-camera-17",
        "acme-camera-lab",
    ]
    leaked = [value for value in forbidden if value in redacted]
    if leaked:
        print(f"[FAIL] leaked values: {leaked}", file=sys.stderr)
        print(redacted, file=sys.stderr)
        return 1

    required_markers = [
        "EMAIL_REDACTED",
        "IP_REDACTED",
        "IPV6_REDACTED",
        "JWT_REDACTED",
        "WINDOWS_ACCOUNT_REDACTED",
        "REDACTED",
        "USERPROFILE_REDACTED",
        "USER_HOME_REDACTED",
        "HOST_REDACTED",
        "TERM_REDACTED",
    ]
    missing = [marker for marker in required_markers if marker not in redacted]
    if missing:
        print(f"[FAIL] missing redaction markers: {missing}", file=sys.stderr)
        print(redacted, file=sys.stderr)
        return 1

    print("[OK] redaction tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
