# macOS Crash Analysis

Read this for `.crash` reports, Console crash logs, LaunchAgent/LaunchDaemon failures, `EXC_*` exceptions, `atos` symbolication, notarization/runtime issues, or architecture mismatch on macOS.

## Evidence to Collect

- Header: process, path, identifier, version, code type, parent process, user ID, OS version, report version, incident ID.
- Exception fields: `Exception Type`, `Exception Codes`, `Exception Subtype`, `Termination Reason`, crashed thread.
- Thread backtrace for the crashed thread and any dispatch/worker threads.
- Binary images: executable UUID, dSYM UUID, framework paths, architecture, load addresses.
- Deployment facts: app bundle layout, hardened runtime, entitlements, quarantine, LaunchDaemon account, working directory.

## Useful Commands

Show recent app logs:

```bash
log show --predicate 'process == "YourApp"' --last 1h
log show --predicate 'subsystem CONTAINS "com.yourcompany"' --last 1h
```

Symbolicate addresses:

```bash
dwarfdump --uuid YourApp.app/Contents/MacOS/YourApp
dwarfdump --uuid YourApp.app.dSYM
atos -o YourApp.app/Contents/MacOS/YourApp -arch arm64 -l 0xLOAD_ADDRESS 0xCRASH_ADDRESS
```

Debug a core if available:

```bash
lldb -c corefile
bt all
image list
```

Check signing/runtime:

```bash
codesign --verify --deep --strict --verbose=4 YourApp.app
codesign -d --entitlements :- YourApp.app
spctl --assess --verbose=4 YourApp.app
xattr -l YourApp.app
```

## Exception Triage

| Field | Meaning | First checks |
| --- | --- | --- |
| `EXC_BAD_ACCESS / KERN_INVALID_ADDRESS` | Invalid memory access | stale pointer, null, use-after-free, bad buffer |
| `EXC_CRASH / SIGABRT` | Process aborted | assertion, `abort`, `std::terminate`, Qt fatal log |
| `EXC_GUARD` | Guarded resource violation | file descriptor, vnode, libdispatch misuse |
| `EXC_BAD_INSTRUCTION` | Illegal instruction/trap | Swift/ObjC trap, CPU mismatch, explicit trap |
| `Namespace CODESIGNING` | Runtime/signing kill | invalid signature, hardened runtime, library validation |
| `Namespace DYLD` | Loader failure | missing framework/dylib, bad rpath, architecture mismatch |

## Interpretation Rules

- Use the crashed thread, not only thread 0. Thread 0 may be idle if a worker crashed.
- Unsymbolicated frames are only addresses until matched with binary UUID and dSYM UUID.
- `arm64` vs `x86_64` mismatches can appear as loader failures, plugin failures, or illegal instructions under Rosetta.
- For LaunchAgents/Daemons, check account permissions, current working directory, environment variables, file access, and GUI/session restrictions.
- For Qt apps, verify bundle plugin paths, `@rpath`, `qt.conf`, platform plugins, and whether GUI APIs are used only in the main thread.

