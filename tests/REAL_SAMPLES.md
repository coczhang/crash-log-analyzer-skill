# Real Crash Sample Intake

Use this guide when converting a real production incident into a regression case for `tests/golden`.

## File Pair

Each case uses two files:

```text
tests/golden/<case-name>.txt
tests/golden/<case-name>.expect.json
```

Use lowercase hyphenated or underscored names. Prefer names that include platform and failure class, for example:

```text
windows-event1000-qt-access-violation.txt
linux-systemd-oom-kill.txt
macos-dyld-library-validation.txt
watchdog-heartbeat-timeout-hard-kill.txt
```

## Required Redaction

Before committing a real sample, redact:

- Customer, user, host, tenant, device, and project names.
- User profile paths and home directories.
- Public or private IP addresses unless the IP itself is the failure signal.
- Email addresses, tokens, passwords, API keys, license keys, and session IDs.
- Proprietary source file paths when not needed to preserve the stack meaning.

Preserve:

- Exception codes, signal names, Event IDs, exit codes, fault offsets, module names, library names, function names, frame order, timestamps relative to the incident, build IDs, and UUIDs needed for symbolication.
- Watchdog sequence and timing.
- Thread IDs if they are needed for reasoning.

Use the bundled text redactor for first-pass cleanup:

```text
python .agents/skills/crash-log-analyzer/scripts/redact_text.py raw-log.txt
python .agents/skills/crash-log-analyzer/scripts/redact_text.py --in-place tests/golden/<case>.txt --term CustomerName
```

Do a manual review after automated redaction. Dump/core files may contain memory-resident secrets and should not be committed.

## Expected JSON

Validate expected files against the shape in `tests/golden/schema.json`.

Minimal example:

```json
{
  "exit_classification": "crash",
  "platforms": ["windows"],
  "domains": ["qt"],
  "references": ["references/windows.md", "references/qt-cpp.md"],
  "exception_codes": ["0xc0000005"],
  "key_fields": {
    "windows_event_id": ["1000"]
  }
}
```

## Review Checklist

- The expected classification is based on artifact evidence, not memory of the incident.
- The sample is small enough to review but still contains the decisive evidence.
- The sample does not leak secrets or customer identifiers.
- The expected references match the workflow a human analyst should follow.
- A prior classifier bug would fail this case.

Run:

```text
python -B tests/run_golden_tests.py
```
