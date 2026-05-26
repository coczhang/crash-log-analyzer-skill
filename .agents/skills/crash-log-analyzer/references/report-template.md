# Crash Analysis Report Templates

Use this when the user asks for a formal report, RCA, customer-facing summary, or when the case has multiple logs/platform clues.

## Internal Engineering RCA

- Incident:
- Affected versions/builds:
- Platform/environment:
- User impact:
- Exit classification:
- Most likely root cause:
- Confidence:

### Timeline

| Time | Source | Event |
| --- | --- | --- |
| | | |

### Evidence

- Log excerpts:
- Dump/core/crash-report facts:
- Stack/thread facts:
- Watchdog/service facts:
- Code facts:

### Root Cause Hypotheses

1. High probability:
   - Supports:
   - Disproves:
   - Verification:
2. Medium probability:
   - Supports:
   - Disproves:
   - Verification:
3. Low probability:
   - Supports:
   - Disproves:
   - Verification:

### Verification Plan

- Reproduction:
- Debugger/symbol steps:
- Instrumentation:
- Stress or sanitizer tests:
- Deployment/environment checks:

### Fix Plan

- Immediate mitigation:
- Minimal code fix:
- Rollout/rollback plan:
- Regression tests:

### Prevention

- Dump/core collection:
- Symbol management:
- Structured logs:
- Watchdog improvements:
- Thread/lifetime rules:
- CI/stress/sanitizer coverage:

## Customer or Management Summary

Keep this short and avoid uncertain implementation details.

- What happened:
- Who/what was affected:
- Current status:
- Likely cause:
- Mitigation already taken:
- Next verification step:
- Expected follow-up:

## Executive Rules

- State uncertainty plainly: "The evidence currently supports..." instead of "The root cause is..." when symbols/dumps are missing.
- Do not blame Qt, FFmpeg, GPU drivers, or the OS unless the evidence rules out app-side lifetime, threading, ABI, and deployment issues.
- Separate immediate mitigation from permanent fix.
- Include exact artifact names used for the conclusion.
