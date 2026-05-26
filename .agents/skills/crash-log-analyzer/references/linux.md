# Linux Crash Analysis

Read this for Linux core dumps, `systemd` service exits, `journalctl` excerpts, `dmesg` segfault lines, container exits, Linux watchdog restarts, or ELF/shared-library issues.

## Evidence to Collect

- Signal, exit status, core-dump status, PID, executable path, working directory, command line, service unit, cgroup/container ID.
- Kernel line from `dmesg` or journal: fault address, IP, SP, error code, mapped object.
- Core metadata: build ID, executable build, library build IDs, stripped/unstripped binary availability.
- Runtime facts: distro, glibc/libstdc++ version, Qt platform plugin, X11/Wayland, GPU driver, FFmpeg build, container base image.

## systemd and Journal Commands

```bash
systemctl status your-service --no-pager
journalctl -u your-service -b --no-pager
journalctl -u your-service --since "2026-05-26 10:00" --until "2026-05-26 10:30" --no-pager
journalctl -k -b --no-pager
coredumpctl list your-app
coredumpctl info <PID-or-COREDUMP>
coredumpctl gdb <PID-or-COREDUMP>
```

Check restart policy and status:

```bash
systemctl show your-service -p Restart -p RestartSec -p NRestarts -p ExecMainStatus -p ExecMainCode -p Result
```

## GDB Workflow

```bash
gdb ./YourApp core
set pagination off
info files
info sharedlibrary
bt full
info threads
thread apply all bt full
frame 0
info registers
disassemble /m
```

Resolve addresses without a core:

```bash
addr2line -f -C -e ./YourApp 0xADDRESS
eu-addr2line -f -C -e ./YourApp 0xADDRESS
readelf -n ./YourApp | grep -A4 'Build ID'
```

## Signal Triage

| Signal/status | Meaning | First checks |
| --- | --- | --- |
| `SIGSEGV` / 11 | Invalid memory access | null/stale pointer, out-of-bounds, use-after-free, bad mapped buffer |
| `SIGABRT` / 6 | Process aborted itself | assert, `std::terminate`, glibc malloc check, Qt fatal message |
| `SIGBUS` / 7 | Bus error | mmap truncation, alignment, device/shared-memory issue |
| `SIGILL` / 4 | Illegal instruction | CPU feature mismatch, corrupt binary, wrong container host |
| `SIGKILL` / 9 | Forced kill | OOM killer, watchdog kill, user/admin kill, container runtime |
| `SIGTERM` / 15 | Requested termination | service stop, deployment, shutdown, watchdog graceful phase |
| exit `0/SUCCESS` | Normal exit | expected service stop unless watchdog says heartbeat failure |
| exit `137` | Usually SIGKILL | OOM, container kill, watchdog hard kill |
| exit `143` | Usually SIGTERM | controlled stop or watchdog graceful kill |

## OOM and Kill Evidence

```bash
journalctl -k -b | grep -i -E 'killed process|out of memory|oom'
dmesg -T | grep -i -E 'killed process|out of memory|oom'
```

If OOM killed, classify as forced kill, not application crash, unless earlier logs show an app exception.

## Interpretation Rules

- `systemd` `Result=signal` or `status=11/SEGV` is a crash. `status=9/KILL` is a forced kill. `status=0/SUCCESS` is normal unless the supervisor killed after a hang and masked the status.
- A core whose top frame is `raise`, `abort`, `__assert_fail`, `malloc_printerr`, or `std::terminate` points to an intentional abort path; inspect the caller and logs immediately before abort.
- A segfault inside `libQt`, `libav*`, Mesa, NVIDIA, or a vendor SDK often means caller-side lifetime/threading/ABI misuse. Inspect the first application frame.
- In containers, compare the host GPU driver, container runtime libraries, glibc/libstdc++, Qt plugin paths, and mounted codec/GPU devices.
- For stripped binaries, ask for unstripped binaries or debug packages with matching build IDs before claiming exact source lines.

