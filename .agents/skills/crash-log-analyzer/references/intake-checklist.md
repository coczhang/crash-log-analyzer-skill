# Crash Analysis Intake Checklist

Use this when user-provided evidence is incomplete. Ask only for artifacts that change the next diagnostic step.

## Universal Minimum

- App name, version/build, commit if known.
- Platform, OS version, architecture, deployment type.
- Exact local time and timezone of incident.
- Whether the app was foreground UI, background service, daemon, or child process.
- Last known user action or service action.
- Logs covering at least 5 minutes before and after the exit.
- Whether symbols/unstripped binaries are available.

## Windows

Ask for:

- Event Viewer Application events `1000` and `1001`.
- WER report text and dump path if present.
- Full dump or minidump.
- Matching PDBs for the app and plugins.
- Output from WinDbg: `!analyze -v`, `kv`, `~* kp`, `lm`, `lmvm <faulting-module>`.
- `collect_windows_crash_info.ps1` output when the user can run scripts.

Ask only if relevant:

- ProcDump configuration if dumps are missing.
- Service account, working directory, and environment if the process is a Windows service.
- GPU driver version and display sleep/RDP/session-switch history for render crashes.

## Linux

Ask for:

- `systemctl status <service> --no-pager`.
- `systemctl show <service> -p Result -p ExecMainCode -p ExecMainStatus -p Restart -p NRestarts`.
- `journalctl -u <service> -b --no-pager` around the incident.
- `coredumpctl info` and `coredumpctl gdb` output.
- In GDB: `bt full`, `info threads`, `thread apply all bt full`.
- Executable/shared-library build IDs.
- `collect_linux_crash_info.sh` output when the user can run scripts.

Ask only if relevant:

- Container runtime exit status and host OOM logs for exit `137` or `SIGKILL`.
- X11/Wayland/GPU driver details for GUI/video failures.
- Unstripped binaries or debug packages when stack frames are only addresses.

## macOS

Ask for:

- Full `.crash` or `.ips` report including Binary Images.
- dSYM UUID and binary UUID from `dwarfdump --uuid`.
- `atos` output for unsymbolicated app frames.
- `log show --predicate 'process == "AppName"' --last 1h`.
- `collect_macos_crash_info.sh` output when the user can run scripts.

Ask only if relevant:

- `codesign --verify --deep --strict --verbose=4` output for CODESIGNING termination.
- `spctl`, entitlements, quarantine, and `@rpath` details for DYLD/library issues.
- LaunchAgent/LaunchDaemon plist, user account, and permissions for service-style apps.

## Qt/C++

Ask for:

- Code around the first app-owned stack frame.
- QObject ownership and parent-child relationships for involved objects.
- Thread-affinity logs: current thread, `obj->thread()`, event-loop state.
- Connection setup code, especially lambdas, queued connections, and repeated setup.
- Shutdown sequence for QThread, workers, timers, sockets, widgets, and render resources.

## FFmpeg/Video

Ask for:

- FFmpeg version/build configuration and matching runtime DLLs/shared objects.
- Decoder/encoder, pixel format, width/height, hardware acceleration type.
- Ownership handoff for `AVFrame`, `AVPacket`, `AVBufferRef`, and wrapped Qt video/image buffers.
- Logs for hardware-frame transfer failures and stream parameter changes.
- Render thread/context ownership and teardown order.

## Watchdog

Ask for:

- PID plus process start time.
- Last heartbeat time and heartbeat source thread/process.
- Last app log event.
- Exit code/status/signal/exception.
- Watchdog kill request and grace-period expiry.
- OS shutdown, suspend/resume, deployment, update, or service-stop markers.
- Restart reason.
