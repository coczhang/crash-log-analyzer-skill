#!/usr/bin/env python3
"""Self-contained metadata checks for the skill package."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".agents" / "skills" / "crash-log-analyzer" / "SKILL.md"
OPENAI_YAML = ROOT / ".agents" / "skills" / "crash-log-analyzer" / "agents" / "openai.yaml"


def parse_frontmatter(text: str) -> dict[str, str]:
    match = re.match(r"^---\n(.*?)\n---", text, flags=re.DOTALL)
    if not match:
        raise ValueError("SKILL.md frontmatter is missing or malformed")
    values = {}
    for raw in match.group(1).splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def main() -> int:
    errors = []
    skill_text = SKILL.read_text(encoding="utf-8")
    try:
        frontmatter = parse_frontmatter(skill_text)
    except ValueError as exc:
        errors.append(str(exc))
        frontmatter = {}

    name = frontmatter.get("name", "")
    description = frontmatter.get("description", "")
    if name != "crash-log-analyzer":
        errors.append(f"unexpected skill name: {name!r}")
    if not re.fullmatch(r"[a-z0-9-]{1,64}", name):
        errors.append("skill name must be lower hyphen-case and <=64 chars")
    if not description:
        errors.append("description is required")
    if len(description) > 1024:
        errors.append("description exceeds 1024 characters")
    for required in ("references/quality-gate.md", "scripts/classify_crash_log.py", "scripts/redact_text.py"):
        if required not in skill_text:
            errors.append(f"SKILL.md does not mention {required}")

    openai_text = OPENAI_YAML.read_text(encoding="utf-8")
    short_match = re.search(r'short_description:\s*"([^"]+)"', openai_text)
    if not short_match:
        errors.append("openai.yaml short_description missing")
    elif not 25 <= len(short_match.group(1)) <= 64:
        errors.append("openai.yaml short_description must be 25-64 chars")
    if "$crash-log-analyzer" not in openai_text:
        errors.append("openai.yaml default_prompt must mention $crash-log-analyzer")

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    print("[OK] skill metadata checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
