# Watchdog Exit Classification

Read this when the user asks whether a process exited normally, crashed, was killed, or hung; when logs include heartbeat timeout, service restart, supervisor restart, PID reuse, forced kill, or abnormal exit without a stack trace.

## Required Timeline

Build a single timeline with absolute timestamps:

- Watchdog start and app start.
- PID and process start time.
- Last heartbeat time and heartbeat source thread/process.
- Last app log event.
- Exit notification time.
- Exit code/status/signal/exception.
- Kill request time and kill method.
- OS shutdown, suspend/resume, user logout, update, service stop, or deployment markers.
- Restart time and restart reason.

## Classification Matrix

| Evidence | Classification |
| --- | --- |
| Exit code 0 or expected app-specific code, no timeout, no OS exception | Normal exit |
| Windows exception, Linux signal/core, macOS `.crash`, minidump/core dump | Crash |
| Watchdog sends SIGTERM/SIGKILL/TerminateProcess after missed heartbeat | Hang followed by forced kill |
| Process still alive while heartbeat stopped | Hang |
| `SIGKILL`, exit 137, TerminateProcess, taskkill, OOM killer, admin kill | Forced kill |
| `SIGTERM`, exit 143, service stop during deployment/shutdown | Requested stop, usually normal/service-managed |
| OS reboot/shutdown/session ending before exit | Shutdown/restart, not app crash unless crash evidence exists |
| PID disappears without exit code and no OS crash artifact | Unknown abnormal exit; need supervisor/OS evidence |

## Robust Watchdog Log Schema

Log these fields for every monitored process:

```json
{
  "event": "process_exit",
  "pid": 1234,
  "process_start_time": "2026-05-26T10:00:00.000Z",
  "exit_time": "2026-05-26T10:05:10.000Z",
  "exit_code": 0,
  "exit_status": "SUCCESS",
  "last_heartbeat_time": "2026-05-26T10:05:08.000Z",
  "last_app_event": "shutdown_requested",
  "watchdog_action": "none",
  "os_shutdown_detected": false,
  "restart_reason": "normal_exit"
}
```

Also log `kill_requested`, `kill_grace_period_expired`, `heartbeat_timeout`, `process_still_alive`, `process_missing`, and `restart_started` as separate events.

## Decision Logic

Use this priority order:

1. If there is OS crash evidence, classify as crash.
2. Else if watchdog killed after a heartbeat timeout, classify as hang followed by forced kill.
3. Else if OOM/admin/supervisor hard kill evidence exists, classify as forced kill.
4. Else if OS shutdown/suspend/deployment stop overlaps the exit, classify as shutdown/restart or requested stop.
5. Else if exit code/status is expected and app logged an explicit shutdown path, classify as normal exit.
6. Else classify as unknown abnormal exit and list the missing evidence.

## Common Pitfalls

- PID reuse can make the watchdog attribute an exit to the wrong process. Always compare PID plus process start time.
- A heartbeat written from a worker thread can keep reporting alive while the GUI thread is deadlocked. Decide what the heartbeat proves.
- A heartbeat written from the GUI thread can stop during heavy rendering without full process death.
- A watchdog kill can mask the original hang cause. Preserve thread dumps before hard kill when possible.
- Service managers may report only the final kill status. Correlate earlier timeout and crash records.

## Recommended Pre-Kill Capture

- Windows: create full dump with ProcDump or `MiniDumpWriteDump` before `TerminateProcess`.
- Linux: `gcore <pid>` or `coredumpctl`/`systemd-coredump`; capture `pstack` or `gdb thread apply all bt`.
- macOS: `sample <pid> 10`, `spindump`, or `lldb` attach backtrace when allowed.

