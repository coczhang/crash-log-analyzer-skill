# Crash Analysis Quality Gate

Use this before finalizing any crash analysis, RCA, customer summary, or fix recommendation.

## Minimum Passing Bar

The answer must include:

- A clear exit classification: normal exit, crash, forced kill, hang, hang followed by forced kill, shutdown/restart, requested stop, or unknown.
- Concrete evidence from the provided artifact. Quote short identifiers, fields, frames, codes, or timestamps; do not invent missing facts.
- Confidence level with a reason.
- Ranked hypotheses with disconfirming evidence for each meaningful hypothesis.
- Verification steps that can increase or decrease confidence.
- Minimal safe mitigation before invasive refactors.
- Missing artifacts listed only when they change the next diagnostic step.

## Hard Fails

Do not finalize if the answer:

- Claims a root cause without tying it to specific evidence.
- Blames Qt, FFmpeg, GPU drivers, CRT, libc, dyld, systemd, or the OS just because the top frame is there.
- Confuses crash, watchdog kill, OOM kill, hang, normal exit, service stop, and OS shutdown.
- Treats optimized or unsymbolicated release stacks as exact source truth.
- Recommends broad refactors before verification and minimal mitigation.
- Omits confidence or verification steps.
- Ignores the first app-owned frame when one is present.
- Ignores watchdog timeline fields when the question is about normal exit vs killed vs crashed.

## Evidence Ladder

Prefer stronger evidence first:

1. Full dump/core/crash report with symbols and thread stacks.
2. OS crash artifact with exception/signal/termination reason and fault module.
3. Watchdog timeline with PID, start time, heartbeat, kill action, and exit status.
4. Application logs with timestamps and thread IDs.
5. User report or symptom description.

If only weak evidence is available, say so and keep hypotheses narrow.

## Classification Checks

- Crash: requires OS exception/signal/core/minidump/crash report or equivalent runtime abort evidence.
- Forced kill: requires SIGKILL, TerminateProcess, taskkill, OOM killer, watchdog hard kill, admin kill, or container hard-stop evidence.
- Hang: requires liveness plus missed heartbeat, stalled event loop, blocked thread dump, or watchdog timeout.
- Normal exit: requires expected exit code/status plus an explicit expected shutdown path or service stop context.
- Unknown: use when the artifact lacks decisive crash/kill/hang/normal evidence.

## Fix Recommendation Gate

Before suggesting code changes, answer:

- Which object, buffer, thread, or module is implicated?
- Is the implicated frame app-owned or library-owned?
- What smaller logging/assertion/symbol step would validate the hypothesis?
- What is the lowest-risk mitigation?
- What regression or stress test would catch recurrence?

## Confidence Labels

- High: multiple independent artifacts agree, symbols identify app-owned code, and alternatives are unlikely.
- Medium: evidence points to a narrow area, but symbols, full stacks, or reproduction are incomplete.
- Low: evidence only supports a broad class of failures.
- Unknown: classification or root cause cannot be responsibly narrowed from the provided data.
