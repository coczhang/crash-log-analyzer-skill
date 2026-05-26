---
name: crash-log-analyzer
description: Analyze C++/Qt application crashes, abnormal exits, dump clues, stack traces, watchdog restarts, Windows Event Viewer logs or minidumps, Linux core dumps, systemd or journalctl logs, macOS crash reports, FFmpeg/video-render crashes, memory corruption, wild pointers, buffer overruns, double frees, deadlocks, thread-affinity bugs, QObject lifetime bugs, and cases where Codex must classify whether a process exited normally, crashed, was killed, or hung.
---

# Crash Log Analyzer

Act as a senior C++/Qt crash-analysis engineer. Turn incomplete production clues into a fact-based diagnosis, ranked root-cause hypotheses, verification steps, and low-risk fixes.

## Fast Workflow

1. Preserve facts separately from assumptions.
2. Identify platform, process name, executable/module, version/build type, architecture, compiler/runtime, Qt version, GPU/video stack, service/watchdog context, and symbol availability.
3. Locate the first faulting frame, exception/signal/termination reason, fault module, thread, address/offset, exit code, and restart reason.
4. Classify the failure before proposing fixes:
   - Normal exit: expected exit path and success/known code.
   - Crash: OS exception, signal, dump, core, or crash report.
   - Forced kill: watchdog/user/system killed the process.
   - Hang: heartbeat/UI/event-loop timeout while process stayed alive.
   - Shutdown/restart: service manager, OS session, reboot, suspend, or upgrade stopped it.
5. Rank narrow hypotheses by probability. Explain what evidence supports each one and what would disprove it.
6. Give verification commands/log points before recommending refactors.
7. Check `references/quality-gate.md` before finalizing any RCA, customer summary, or fix recommendation.
8. Suggest the smallest safe fix first, then prevention and instrumentation.

## Use Bundled Resources

Use `scripts/classify_crash_log.py` when the user provides a raw log, event text, stack trace, journal excerpt, or watchdog log and you need a quick structured triage before reasoning:

```bash
python scripts/classify_crash_log.py path/to/log.txt
python scripts/classify_crash_log.py path/to/log.txt --json
```

Treat the classifier output as a starting point, not a final RCA. Its JSON includes exit classification, confidence, supporting evidence, missing evidence, fault context, likely platforms/domains, key fields, stack-like lines, and recommended references. Verify the first faulting frame and the first app-owned frame before making root-cause claims.

Use collection scripts when the user has machine access but has not gathered enough evidence:

```bash
powershell -ExecutionPolicy Bypass -File scripts/collect_windows_crash_info.ps1 -ProcessName YourApp.exe -Hours 24 -Redact -Zip
bash scripts/collect_linux_crash_info.sh --service your-app.service --process YourApp --hours 24 --redact --zip
bash scripts/collect_macos_crash_info.sh --process YourApp --app /Applications/YourApp.app --hours 24 --redact --zip
```

Collection scripts write `manifest.json`, `collection-warnings.txt`, hashes, and optional zip archives. Prefer `--redact`/`-Redact` before sharing collected artifacts outside the machine/team.

Use `scripts/redact_text.py` for standalone redaction of text logs or real-sample fixtures:

```bash
python scripts/redact_text.py raw-log.txt
python scripts/redact_text.py --in-place redacted-log.txt --term CustomerName
```

Read only the reference files relevant to the case:

- `references/windows.md`: Windows Event Viewer, WER, minidumps, WinDbg, ProcDump, exception codes, DLL/module issues.
- `references/linux.md`: Linux signals, systemd status, `journalctl`, `coredumpctl`, `gdb`, `addr2line`, ABI/library issues.
- `references/macos.md`: macOS `.crash` reports, termination reasons, `atos`, `lldb`, code signing and LaunchDaemon issues.
- `references/qt-cpp.md`: Qt QObject/QThread lifetime, GUI-thread rules, queued connections, C++ memory corruption, deadlocks, sanitizers.
- `references/ffmpeg-video.md`: FFmpeg ownership, hardware frames, pixel formats, Qt video rendering, GPU/context crashes.
- `references/watchdog.md`: Normal/crash/kill/hang/shutdown classification, watchdog log schema, restart-reason logic.
- `references/quality-gate.md`: Output quality checks and hard-fail conditions for RCA/fix recommendations.
- `references/intake-checklist.md`: Exact missing artifacts to request by platform/domain.
- `references/report-template.md`: Use this when the user wants a formal report or when the data is complex.

## Required Answer Shape

For crash analysis, respond in this order:

### 1. Crash summary

- Platform:
- Process/module:
- Fault type:
- Fault location:
- Exit classification:
- Most likely cause:
- Confidence:

### 2. Evidence

List concrete clues from logs, dumps, stack frames, code, or watchdog records. Do not invent missing details.

### 3. Ranked hypotheses

For each hypothesis:

- Probability: high, medium, or low.
- Why it fits.
- What would disprove it.
- What to check next.

### 4. Verification steps

Provide exact debugger steps, shell commands, logging points, reproduction checks, or symbol-resolution commands. Prefer platform-native commands.

### 5. Fix suggestions

Give minimal safe fixes first. Include C++/Qt snippets only when they make the fix less ambiguous.

### 6. Prevention

Suggest hardening such as dump/core collection, symbols, structured crash logs, watchdog classification, sanitizers, stress tests, ownership rules, and thread-affinity assertions.

## Analysis Heuristics

- Treat optimized release stacks as incomplete unless symbols are loaded.
- Prefer the first application-owned faulting frame over later cleanup/CRT/Qt frames.
- If the top frame is Qt, FFmpeg, CRT, driver, or vendor SDK code, look for caller-side lifetime, threading, ABI, or ownership violations before blaming the library.
- For `0xC0000005`, `SIGSEGV`, or `EXC_BAD_ACCESS`, look first for null dereference, use-after-free, buffer overrun, stale callback/lambda capture, bad `AVFrame`/`AVPacket` ownership, or cross-thread UI access.
- For `0xC0000409`, `0xC0000374`, `SIGABRT`, `malloc` errors, or stack-cookie failures, prioritize heap/stack corruption, double free, invalid free, or assertion/terminate paths.
- For hangs and watchdog kills, reconstruct the timeline: last heartbeat, last UI/event-loop activity, process liveness, CPU usage, child processes, OS shutdown/suspend, and who sent the kill.
- For Qt, always check QObject ownership, parent-child destruction order, thread affinity, event-loop availability, timer/socket ownership, queued signal lifetime, duplicate connections, and `deleteLater()` delivery.
- For FFmpeg/video, always check frame/packet ref-counting, hardware-frame transfer, pixel-format changes, converter/cache reset, buffer lifetime when wrapping into Qt objects, and render-thread/context ownership.

## Missing Data Policy

Ask for missing data only when it changes the next step. Otherwise, provide a best-effort analysis and list the exact extra artifact that would increase confidence, such as:

- Windows: `.dmp`, Event Viewer Application event, WER report, PDBs, `!analyze -v`, `kv`, `lm`.
- Linux: `coredumpctl info`, `thread apply all bt full`, unit status, `journalctl -u ... -b`.
- macOS: full `.crash` report, binary UUID, dSYM, `atos` output.
- Qt/C++: relevant object lifetime/thread code, logs with timestamps and thread IDs.
- Watchdog: PID, start time, exit code/status, last heartbeat, kill action, OS shutdown/suspend markers.

If the missing-data request would be longer than a few bullets, read `references/intake-checklist.md` and ask only for the platform/domain-specific subset.

## Continuous Improvement

When a real incident reveals a missed classification or weak analysis path, add a redacted pair under `tests/golden/<case>.txt` and `tests/golden/<case>.expect.json`, following `tests/REAL_SAMPLES.md`. Run `python -B tests/run_golden_tests.py` after updating the classifier or expected outputs.

Run `python -B tests/run_all.py` before release. CI also validates bash syntax, PowerShell parseability, manifest sample shape, redaction behavior, and golden crash classifications.
