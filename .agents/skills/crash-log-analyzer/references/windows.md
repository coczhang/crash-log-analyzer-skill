# Windows Crash Analysis

Read this when the artifact is an Event Viewer Application event, WER report, minidump/full dump, WinDbg output, Windows service crash, exception code, DLL fault module, or Windows watchdog restart.

## Evidence to Collect

- Event Viewer fields: faulting application, application version, faulting module, module version, exception code, fault offset, process ID, start time, application path, module path, report ID.
- WER fields: `AppName`, `AppVersion`, `AppPath`, `ExceptionCode`, `FaultingModule`, `FaultingModulePath`, `Bucket`, `Cab Id`, dump path.
- Dump type: minidump, full dump, heap dump. Note whether private memory is present.
- Build facts: x86/x64/arm64, compiler, CRT, Qt version, FFmpeg build, GPU driver, app commit/version, PDB availability.
- Service facts: account, working directory, environment variables, desktop/session isolation, restart policy.

## Exception Code Triage

| Code | Meaning | First checks |
| --- | --- | --- |
| `0xC0000005` | Access violation | null/stale pointer, use-after-free, out-of-bounds, bad function pointer, cross-thread UI or video buffer lifetime |
| `0xC0000409` | Stack buffer overrun / fail-fast | stack corruption, invalid parameter, security cookie, deliberate `RaiseFailFastException` |
| `0xC0000374` | Heap corruption | double free, invalid free, buffer overrun before crash, mixed allocators/CRT |
| `0x80000003` | Breakpoint | debug break, assertion, `__debugbreak`, unexpected breakpoint in release |
| `0xE06D7363` | C++ exception | unhandled C++ exception; inspect exception object and throw site |
| `0xC000001D` | Illegal instruction | CPU feature mismatch, corrupt code, wrong binary for machine |
| `0xC00000FD` | Stack overflow | recursion, huge stack allocation, signal recursion, logging recursion |

## Dump Capture

Use ProcDump for production-safe capture:

```bat
procdump -ma -e -x dumps YourApp.exe
procdump -ma -i C:\dumps
procdump -ma -h YourApp.exe C:\dumps
procdump -ma -t YourApp.exe C:\dumps
```

Use Windows Error Reporting local dumps when ProcDump cannot run:

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\YourApp.exe" /v DumpFolder /t REG_EXPAND_SZ /d C:\dumps /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\YourApp.exe" /v DumpType /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\YourApp.exe" /v DumpCount /t REG_DWORD /d 10 /f
```

## WinDbg Workflow

```text
windbg -z your.dmp
.symfix
.sympath+ C:\path\to\pdbs
.reload /f
!analyze -v
kv
~* kp
lm
lmvm YourModule
!peb
!teb
```

For heap corruption:

```text
!heap -s
!heap -flt s <size>
!address <address>
```

For C++ exceptions:

```text
!analyze -v
.exr -1
.cxr <context>
kv
```

## Interpretation Rules

- If the fault module is `Qt*.dll`, `avcodec*.dll`, `avutil*.dll`, `KERNELBASE.dll`, `ucrtbase.dll`, `ntdll.dll`, or a GPU/vendor DLL, inspect the first app-owned caller and object/buffer ownership. The library is often only where corruption is detected.
- Fault offset without symbols is not enough for root cause. Ask for matching PDBs and module timestamp/size.
- If the crash happens at startup, check missing DLLs, wrong architecture, VC runtime, plugin paths, Qt platform plugin, permissions, service working directory, and blocked GPU/codec DLLs.
- If the crash happens during shutdown, check object destruction order, thread stop order, `QThread::wait()`, pending queued signals, FFmpeg packet/frame teardown, and static destruction.
- If Event Viewer only reports `Application Error` plus WER, treat it as a crash until an explicit normal exit or watchdog kill record disproves it.

## Qt and Video Windows Notes

- QWidget and most rendering APIs must stay on the GUI/render thread.
- GPU reset, display sleep/wake, RDP session switch, and driver upgrades can invalidate contexts. Look for `DXGI_ERROR_DEVICE_REMOVED`, OpenGL context loss, or D3D errors before the crash.
- Confirm all DLLs are from the same deployment set. Mixed FFmpeg/Qt plugin DLLs can crash far from the load point.

