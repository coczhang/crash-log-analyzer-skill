#!/usr/bin/env python3
"""Redact common secrets and identifiers from crash-analysis text artifacts."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable


REDACTIONS = [
    (re.compile(r"(?i)\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), "EMAIL_REDACTED"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP_REDACTED"),
    (re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b"), "IPV6_REDACTED"),
    (re.compile(r"(?i)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "JWT_REDACTED"),
    (re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|license[_-]?key|serial|tenant[_-]?id|client[_-]?id)\s*[:=]\s*(?:(?:bearer|basic)\s+)?[^\r\n,;]+"), r"\1=REDACTED"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 REDACTED"),
    (re.compile(r"(?i)\b[A-Za-z]:\\Users\\[^\\\r\n\t ]+"), r"USERPROFILE_REDACTED"),
    (re.compile(r"(?i)(?<![:\\])\b(?![A-Z0-9_.-]*REDACTED\b)[A-Z0-9_.-]+\\(?![A-Z0-9_.-]*REDACTED\b)[A-Z0-9_.-]+\b"), "WINDOWS_ACCOUNT_REDACTED"),
    (re.compile(r"/(?:Users|home)/[^/\s]+"), r"/USER_HOME_REDACTED"),
    (re.compile(r"(?i)\b(host|hostname|computername|machine)\s*[:=]\s*([A-Za-z0-9_.-]+)"), r"\1=HOST_REDACTED"),
]


def redact_text(text: str, extra_terms: Iterable[str] = ()) -> str:
    redacted = text
    for pattern, replacement in REDACTIONS:
        redacted = pattern.sub(replacement, redacted)

    for term in extra_terms:
        if term:
            redacted = re.sub(re.escape(term), "TERM_REDACTED", redacted, flags=re.IGNORECASE)
    return redacted


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Redact sensitive values from crash-analysis text.")
    parser.add_argument("paths", nargs="*", help="Files to redact. Reads stdin when omitted.")
    parser.add_argument("--in-place", action="store_true", help="Rewrite files in place.")
    parser.add_argument("--term", action="append", default=[], help="Additional literal term to replace with TERM_REDACTED.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.paths:
        sys.stdout.write(redact_text(sys.stdin.read(), args.term))
        return 0

    for raw_path in args.paths:
        path = Path(raw_path)
        text = path.read_text(encoding="utf-8", errors="replace")
        redacted = redact_text(text, args.term)
        if args.in_place:
            path.write_text(redacted, encoding="utf-8")
        else:
            sys.stdout.write(redacted)
            if not redacted.endswith("\n"):
                sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
