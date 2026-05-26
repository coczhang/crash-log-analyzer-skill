#!/usr/bin/env python3
"""Quick triage for crash logs, stack traces, and watchdog records.

The script intentionally stays heuristic. It extracts likely platform, fault
signals/codes, modules, stack-like lines, and recommended reference files so an
agent can start with structured facts instead of rereading noisy logs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List


EXCEPTION_CODES = {
    "0xc0000005": "Windows access violation",
    "0xc0000409": "Windows fail-fast / stack buffer overrun",
    "0xc0000374": "Windows heap corruption",
    "0x80000003": "Windows breakpoint",
    "0xe06d7363": "Unhandled C++ exception",
    "0xc000001d": "Illegal instruction",
    "0xc00000fd": "Stack overflow",
}

SIGNALS = {
    "sigsegv": "Linux/macOS segmentation fault",
    "sigabrt": "Abort/assert/terminate",
    "sigbus": "Bus error",
    "sigill": "Illegal instruction",
    "sigkill": "Forced kill",
    "sigterm": "Requested termination",
    "segmentation fault": "Segmentation fault",
    "core dumped": "Core dump generated",
}

PLATFORM_PATTERNS = {
    "windows": [
        r"faulting application",
        r"faulting module",
        r"\bfaulting_ip\b",
        r"\bstack_text\b",
        r"\bevent id:\s*100[01]\b",
        r"\bfault bucket\b",
        r"exception code",
        r"exception offset",
        r"\bwer\b",
        r"\bappcrash\b",
        r"\.dmp\b",
        r"\bntdll\.dll\b",
        r"\bkernelbase\.dll\b",
        r"0xc000[0-9a-f]+",
    ],
    "linux": [
        r"\bsig(segv|abrt|bus|ill|kill|term)\b",
        r"\bsystemd\b",
        r"\bjournalctl\b",
        r"\bcoredumpctl\b",
        r"\baddresssanitizer\b",
        r"\bcore dumped\b",
        r"\bsegfault at\b",
        r"\bstatus=\d+/",
        r"\bkilled process\b",
        r"\blibc\.so\b",
    ],
    "macos": [
        r"incident identifier",
        r"exception type:\s*exc_",
        r"termination reason:",
        r"namespace\s+(codesigning|dyld|signal)",
        r"crashed thread:",
        r"binary images:",
        r"code type:",
        r"\.crash\b",
        r"\bdyld\b",
    ],
}

DOMAIN_PATTERNS = {
    "qt": [r"\bqobject\b", r"\bqthread", r"\bqwidget\b", r"\bqapplication\b", r"\bqtcore\b", r"\bqtgui\b", r"\bqtwidgets\b"],
    "ffmpeg_video": [r"\bavframe\b", r"\bavpacket\b", r"\bavcodec\b", r"\blibavcodec\b", r"\bavformat\b", r"\blibavformat\b", r"\bavutil\b", r"\blibavutil\b", r"\bswscontext\b", r"\bffmpeg\b", r"\bqvideoframe\b", r"\bavhwframe\b", r"\bhw_frames_ctx\b", r"\bd3d11va\b", r"\bvaapi\b", r"\bcuda\b"],
    "watchdog": [r"\bwatchdog\b", r"\bheartbeat\b", r"\btimeout\b", r"\brestart reason\b", r"\blast heartbeat\b"],
    "threading": [r"\bdeadlock\b", r"\bmutex\b", r"\bthread\b", r"\bblockingqueuedconnection\b", r"\bjoin\b", r"\bwait\("],
    "memory": [r"use-after-free", r"use after free", r"heap-use-after-free", r"stack-use-after", r"addresssanitizer", r"ubsan", r"double free", r"heap corruption", r"invalid free", r"buffer overrun", r"access violation", r"bad access"],
}

FIELD_PATTERNS = {
    "windows_event_id": [r"\bEvent ID:\s*(\d+)"],
    "wer_bucket": [r"\bFault bucket\s+([^,\r\n]+)"],
    "faulting_application_name": [r"\bFaulting application name:\s*([^,\r\n]+)", r"\bApplication Name:\s*([^,\r\n]+)"],
    "faulting_module_name": [r"\bFaulting module name:\s*([^,\r\n]+)", r"\bFault Module Name:\s*([^,\r\n]+)"],
    "fault_offset": [r"\bFault offset:\s*([^\s,\r\n]+)"],
    "faulting_ip": [r"\bFAULTING_IP:\s*([^\r\n]+)"],
    "exception_code": [r"\bException Code:\s*([^\s,\r\n]+)", r"\bEXCEPTION_CODE:\s*\([^)]+\)\s*([^\s,\r\n]+)"],
    "exception_offset": [r"\bException Offset:\s*([^\s,\r\n]+)"],
    "report_id": [r"\bReport Id:\s*([0-9a-fA-F-]+)"],
    "faulting_process_id": [r"\bFaulting process id:\s*([^\s,\r\n]+)"],
    "faulting_thread_id": [r"\bFaulting thread id:\s*([^\s,\r\n]+)"],
    "systemd_result": [r"\bResult=([A-Za-z0-9_-]+)", r"\bFailed with result '([^']+)'"],
    "exec_main_status": [r"\bExecMainStatus=(\d+)"],
    "exit_code": [r"\bexit[_ -]?code\s*[:=]\s*(\d+)", r"\bexited with code\s+(\d+)"],
    "pid": [r"\bpid[=:]\s*(\d+)", r"\bprocess\s+(\d+)\s+\("],
    "last_heartbeat_time": [r"\blast_heartbeat_time[=:]\s*([0-9T:.-]+Z?)"],
    "restart_reason": [r"\brestart_reason[=:]\s*([A-Za-z0-9_-]+)"],
    "crashed_thread": [r"\bCrashed Thread:\s*([^\r\n]+)"],
    "termination_namespace": [r"\bTermination Reason:\s*Namespace\s+([A-Z_]+)"],
    "termination_code": [r"\bTermination Reason:\s*Namespace\s+[A-Z_]+,\s*Code\s+([^\s,\r\n]+)"],
    "binary_uuid": [r"<([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})>"],
}

LIBRARY_FRAME_HINTS = (
    " qt",
    "qtcore",
    "qtgui",
    "qtwidgets",
    "qobject",
    "qthread",
    "qwidget",
    "libav",
    "avcodec",
    "avformat",
    "avutil",
    "swscale",
    "ffmpeg",
    "ntdll",
    "kernelbase",
    "kernel32",
    "ucrtbase",
    "msvcp",
    "vcruntime",
    "libc.",
    "libpthread",
    "pthread",
    "dyld",
    "libsystem",
    "corefoundation",
    "foundation",
    "appkit",
    "objc",
    "asan",
    "ubsan",
)


def read_input(path: str | None) -> str:
    if path:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    return sys.stdin.read()


def count_patterns(text_lower: str, patterns: Iterable[str]) -> int:
    return sum(len(re.findall(pattern, text_lower, flags=re.IGNORECASE)) for pattern in patterns)


def detect_platforms(text: str) -> List[Dict[str, object]]:
    lower = text.lower()
    scored = []
    for platform, patterns in PLATFORM_PATTERNS.items():
        score = count_patterns(lower, patterns)
        if score:
            scored.append({"name": platform, "score": score})
    if any(item["name"] == "macos" and int(item["score"]) >= 3 for item in scored):
        scored = [item for item in scored if not (item["name"] == "linux" and int(item["score"]) <= 1)]
    if ("watchdog" in lower or "heartbeat" in lower) and not has_linux_specific_context(lower):
        scored = [item for item in scored if not (item["name"] == "linux" and int(item["score"]) <= 2)]
    scored.sort(key=lambda item: (-int(item["score"]), str(item["name"])))
    return scored


def has_linux_specific_context(text_lower: str) -> bool:
    linux_specific_patterns = [
        r"\bsystemd\b",
        r"\bjournalctl\b",
        r"\bcoredumpctl\b",
        r"\bcore dumped\b",
        r"\bsegfault at\b",
        r"\bstatus=\d+/",
        r"\bkilled process\b",
        r"\bout of memory\b",
        r"\boom\b",
        r"\blibc\.so\b",
    ]
    return any(re.search(pattern, text_lower, flags=re.IGNORECASE) for pattern in linux_specific_patterns)


def detect_domains(text: str) -> List[Dict[str, object]]:
    lower = text.lower()
    scored = []
    for domain, patterns in DOMAIN_PATTERNS.items():
        score = count_patterns(lower, patterns)
        if score:
            scored.append({"name": domain, "score": score})
    scored.sort(key=lambda item: (-int(item["score"]), str(item["name"])))
    return scored


def unique_in_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        normalized = value.strip()
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            result.append(normalized)
    return result


def extract_exception_codes(text: str) -> List[Dict[str, str]]:
    codes = []
    for line in text.splitlines():
        line_codes = re.findall(r"\b(?:0x)?[cCeE][0-9a-fA-F]{7,15}\b|0x[0-9a-fA-F]{8,16}", line)
        if not line_codes:
            continue
        lower_line = line.lower()
        for code in line_codes:
            lower_code = normalize_status_code(code)
            if lower_code in EXCEPTION_CODES or "exception" in lower_line or "status" in lower_line:
                codes.append(lower_code)
    codes = unique_in_order(codes)
    result = []
    for code in codes:
        result.append({"code": code, "meaning": EXCEPTION_CODES.get(code.lower(), "Unknown exception/status code")})
    return result


def normalize_status_code(code: str) -> str:
    normalized = code.strip().lower()
    if not normalized.startswith("0x"):
        normalized = f"0x{normalized}"
    return normalized


def extract_signals(text: str) -> List[Dict[str, str]]:
    lower = text.lower()
    found = []
    for signal, meaning in SIGNALS.items():
        if signal in lower:
            found.append({"signal": signal.upper() if signal.startswith("sig") else signal, "meaning": meaning})

    status_matches = re.findall(r"status=(\d+)/([A-Z]+)|exit(?:ed)?(?: with)?(?: code)?\s*[:=]?\s*(\d+)|exit[_ -]?code\s*[:=]\s*(\d+)", text, flags=re.IGNORECASE)
    for numeric, named, exit_code, explicit_exit_code in status_matches:
        exit_value = exit_code or explicit_exit_code
        if numeric and named:
            found.append({"signal": f"status={numeric}/{named.upper()}", "meaning": status_meaning(numeric, named)})
        elif exit_value:
            found.append({"signal": f"exit={exit_value}", "meaning": exit_code_meaning(exit_value)})
    return unique_signal_dicts(found)


def unique_signal_dicts(values: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    result = []
    for item in values:
        key = item["signal"].lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def status_meaning(numeric: str, named: str) -> str:
    name = named.upper()
    if name in {"SEGV", "ABRT", "BUS", "ILL"}:
        return "Crash signal"
    if name == "KILL":
        return "Forced kill"
    if name == "TERM":
        return "Requested termination"
    if numeric == "0" or name == "SUCCESS":
        return "Normal success status"
    return "Process status"


def exit_code_meaning(code: str) -> str:
    mapping = {
        "0": "Normal success status",
        "6": "SIGABRT on Unix-like systems",
        "9": "SIGKILL on Unix-like systems",
        "11": "SIGSEGV on Unix-like systems",
        "15": "SIGTERM on Unix-like systems",
        "134": "Often SIGABRT in shells/containers",
        "137": "Often SIGKILL in shells/containers",
        "139": "Often SIGSEGV in shells/containers",
        "143": "Often SIGTERM in shells/containers",
    }
    return mapping.get(code, "Application-specific or platform-specific exit code")


def extract_modules(text: str) -> List[str]:
    patterns = [
        r"Faulting module name:\s*([^,\r\n]+)",
        r"Faulting module path:\s*([^\r\n]+)",
        r"\b([A-Za-z0-9_.+-]+\.(?:dll|exe|so(?:\.\d+)*|dylib|framework))\b",
        r"\bin\s+([A-Za-z0-9_:+.-]+![A-Za-z0-9_:$~<>.-]+)",
    ]
    modules = []
    for pattern in patterns:
        modules.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    return unique_in_order(modules)[:20]


def extract_process_names(text: str) -> List[str]:
    patterns = [
        r"Faulting application name:\s*([^,\r\n]+)",
        r"Process:\s*([^\[\r\n]+)",
        r"Command Line:\s*([^\r\n]+)",
        r"Executable:\s*([^\r\n]+)",
        r"Process Name:\s*([^\r\n]+)",
    ]
    names = []
    for pattern in patterns:
        names.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    return unique_in_order(names)[:10]


def extract_key_fields(text: str) -> Dict[str, List[str]]:
    fields: Dict[str, List[str]] = {}
    for name, patterns in FIELD_PATTERNS.items():
        values = []
        for pattern in patterns:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                if isinstance(match, tuple):
                    values.extend(part for part in match if part)
                else:
                    values.append(match)
        if values:
            fields[name] = unique_in_order(clean_field_value(value) for value in values)[:10]
    return fields


def clean_field_value(value: str) -> str:
    cleaned = value.strip().strip(",")
    if re.fullmatch(r"[cCeE][0-9a-fA-F]{7}", cleaned):
        return normalize_status_code(cleaned)
    return cleaned


def extract_stack_lines(text: str, limit: int) -> List[str]:
    stack_patterns = [
        r"^\s*#\d+\s+.*$",
        r"^\s*[0-9a-fA-F]{2}\s+[0-9a-f`]+\s+.*$",
        r"^\s*\d+\s+[0-9a-f`]+\s+[0-9a-f`]+\s+.*$",
        r"^\s*[0-9a-fA-F]{8,16}\s+.*$",
        r"^\s*at\s+[\w.$:<>\-]+\s*\(.*$",
        r"^\s*\d+\s+\S+\s+.*$",
        r"^\s*\d+\s+[\w:~<>.$-]+\s*\(.*$",
        r"^\s*Thread\s+\d+.*$",
        r"^\s*Crashed Thread:.*$",
    ]
    lines = []
    for line in text.splitlines():
        if any(re.search(pattern, line) for pattern in stack_patterns):
            lines.append(line.rstrip())
        if len(lines) >= limit:
            break
    return lines


def classify_exit(text: str, exception_codes: List[Dict[str, str]], signals: List[Dict[str, str]], domains: List[Dict[str, object]]) -> Dict[str, object]:
    lower = text.lower()
    signal_text = " ".join(item["signal"].lower() + " " + item["meaning"].lower() for item in signals)
    domain_names = {str(item["name"]) for item in domains}
    crash_signal_tokens = ("sigsegv", "sigabrt", "sigbus", "sigill", "segmentation fault", "status=11/segv", "status=6/abrt")
    has_crash_signal = "crash signal" in signal_text or any(token in signal_text for token in crash_signal_tokens)
    has_macos_exception = "exception type:" in lower and "exc_" in lower
    has_macos_runtime_termination = "termination reason:" in lower and ("namespace codesigning" in lower or "namespace dyld" in lower)
    has_sanitizer_crash = "addresssanitizer" in lower and ("error:" in lower or "aborting" in lower)
    has_shutdown_marker = any(marker in lower for marker in ("system shutdown", "os_shutdown", "shutdown/restart", "reboot.target", "rebooting", "shutting down", "poweroff.target", "restart_reason=system_shutdown"))

    if exception_codes or has_crash_signal or "core dump" in signal_text or has_macos_exception or has_macos_runtime_termination or has_sanitizer_crash:
        return {"classification": "crash", "reason": "OS exception, crash signal, core dump, or crash-report evidence was detected."}

    if "oom" in lower or "out of memory" in lower or "killed process" in lower:
        return {"classification": "forced kill", "reason": "OOM or kernel kill evidence was detected."}

    if has_shutdown_marker:
        return {"classification": "shutdown/restart", "reason": "OS or service-manager shutdown/restart evidence was detected without direct crash evidence."}

    if "sigkill" in signal_text or "status=9/kill" in signal_text or "exit=137" in signal_text or "terminateprocess" in lower:
        if "watchdog" in domain_names or "heartbeat" in lower:
            return {"classification": "hang followed by forced kill", "reason": "Watchdog/heartbeat evidence appears with a hard kill."}
        return {"classification": "forced kill", "reason": "Hard-kill evidence was detected."}

    if "heartbeat" in lower and ("timeout" in lower or "missed" in lower or "expired" in lower):
        return {"classification": "hang", "reason": "Heartbeat timeout evidence was detected without direct crash evidence."}

    if "sigterm" in signal_text or "status=15/term" in signal_text or "exit=143" in signal_text:
        return {"classification": "requested stop", "reason": "SIGTERM or equivalent controlled-stop status was detected."}

    if "exit=0" in signal_text or "status=0/success" in signal_text or "exited with code 0" in lower or "deactivated successfully" in lower:
        return {"classification": "normal exit", "reason": "Success exit status was detected and no crash evidence was found."}

    return {"classification": "unknown", "reason": "No decisive crash, kill, hang, or normal-exit evidence was detected."}


def extract_fault_context(key_fields: Dict[str, List[str]], exception_codes: List[Dict[str, str]], modules: List[str], frames: List[str]) -> Dict[str, str]:
    context: Dict[str, str] = {}
    first_values = {
        "process": key_fields.get("faulting_application_name", []),
        "faulting_module": key_fields.get("faulting_module_name", []) or modules,
        "fault_offset": key_fields.get("fault_offset", []) or key_fields.get("exception_offset", []),
        "faulting_ip": key_fields.get("faulting_ip", []),
        "exception_code": key_fields.get("exception_code", []) or [item["code"] for item in exception_codes],
        "faulting_thread": key_fields.get("faulting_thread_id", []) or key_fields.get("crashed_thread", []),
    }
    for name, values in first_values.items():
        if values:
            context[name] = values[0]

    for frame in frames:
        if is_stack_frame(frame):
            context.setdefault("first_faulting_frame", frame.strip())
            break
    for frame in frames:
        if is_probably_app_frame(frame):
            context.setdefault("first_app_frame", frame.strip())
            break
    return context


def is_stack_frame(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped and not stripped.lower().startswith(("thread ", "crashed thread:")))


def is_probably_app_frame(line: str) -> bool:
    lower = f" {line.lower()}"
    if any(hint in lower for hint in LIBRARY_FRAME_HINTS):
        return False
    module_match = re.search(r"\b([A-Za-z_][\w.+-]*)!", line)
    if module_match:
        module = module_match.group(1).lower()
        return not module.endswith((".dll", ".so", ".dylib"))
    return "::" in line or bool(re.search(r"\bin\s+[A-Za-z_][\w:<>~.-]+\s*(?:\+|\()", line))


def build_evidence_summary(
    key_fields: Dict[str, List[str]],
    exception_codes: List[Dict[str, str]],
    signals: List[Dict[str, str]],
    fault_context: Dict[str, str],
    interesting_lines: List[str],
) -> List[str]:
    evidence = []
    for item in exception_codes:
        evidence.append(f"exception_code={item['code']} ({item['meaning']})")
    for item in signals:
        evidence.append(f"signal_or_status={item['signal']} ({item['meaning']})")
    for key in ("windows_event_id", "systemd_result", "exec_main_status", "exit_code", "restart_reason", "last_heartbeat_time", "termination_namespace", "termination_code"):
        for value in key_fields.get(key, []):
            evidence.append(f"{key}={value}")
    for key in ("faulting_module", "fault_offset", "faulting_ip", "first_faulting_frame", "first_app_frame"):
        if key in fault_context:
            evidence.append(f"{key}={fault_context[key]}")
    evidence.extend(interesting_lines[:5])
    return unique_in_order(evidence)[:20]


def estimate_confidence(classification: str, evidence: List[str], fault_context: Dict[str, str], frames: List[str]) -> str:
    if classification == "unknown":
        return "unknown"
    strong_tokens = ("exception_code=", "signal_or_status=", "windows_event_id=", "systemd_result=", "termination_namespace=", "restart_reason=")
    strong_count = sum(1 for item in evidence if item.startswith(strong_tokens))
    if strong_count >= 2 and (fault_context or frames):
        return "high"
    if strong_count >= 1 or evidence:
        return "medium"
    return "low"


def build_missing_evidence(classification: str, platforms: List[Dict[str, object]], frames: List[str], fault_context: Dict[str, str]) -> List[str]:
    missing = []
    platform_names = {str(item["name"]) for item in platforms}
    if classification == "crash":
        if "windows" in platform_names:
            missing.append("full dump or minidump with matching PDBs")
        if "linux" in platform_names:
            missing.append("core file with thread apply all bt full and build IDs")
        if "macos" in platform_names:
            missing.append("full .crash/.ips report with Binary Images and matching dSYM UUIDs")
        if not frames:
            missing.append("symbolized thread stack")
        if "first_app_frame" not in fault_context:
            missing.append("first application-owned frame")
    elif classification in {"hang", "hang followed by forced kill"}:
        missing.extend(["pre-kill thread dump", "last heartbeat and watchdog kill timeline with PID start time"])
    elif classification in {"forced kill", "requested stop", "shutdown/restart"}:
        missing.append("process start time correlated with PID and service-manager/OS shutdown markers")
    elif classification == "normal exit":
        missing.append("application log showing the expected shutdown path")
    return unique_in_order(missing)


def build_collection_hints(platforms: List[Dict[str, object]], domains: List[Dict[str, object]], classification: str) -> List[str]:
    platform_names = {str(item["name"]) for item in platforms}
    domain_names = {str(item["name"]) for item in domains}
    hints = []

    if "windows" in platform_names:
        hints.extend([
            "Collect Event Viewer Application events 1000 and 1001 around the crash time.",
            "Capture a full dump with ProcDump or WER LocalDumps and keep matching PDBs.",
            "Run WinDbg commands: !analyze -v, kv, ~* kp, lm, and lmvm on the faulting module.",
        ])
    if "linux" in platform_names:
        hints.extend([
            "Collect systemctl status, systemctl show Result/ExecMainStatus, journalctl -u for the boot, and coredumpctl info.",
            "Open the core with gdb and run bt full, info threads, and thread apply all bt full.",
            "Record executable and shared-library build IDs for symbol matching.",
        ])
    if "macos" in platform_names:
        hints.extend([
            "Collect the full .crash report including Binary Images and the crashed thread.",
            "Verify dSYM UUIDs with dwarfdump and symbolize addresses with atos.",
            "For CODESIGNING or DYLD termination, capture codesign verification, entitlements, quarantine, and @rpath details.",
        ])
    if "watchdog" in domain_names or classification in {"forced kill", "hang", "hang followed by forced kill", "shutdown/restart", "requested stop", "unknown"}:
        hints.extend([
            "Correlate PID with process start time to avoid PID reuse mistakes.",
            "Capture last heartbeat, last app event, watchdog kill request, grace-period expiry, exit status, and OS shutdown/suspend markers.",
            "If a hang is suspected, capture thread dumps before the hard kill.",
        ])
    if "qt" in domain_names or "threading" in domain_names:
        hints.extend([
            "Add Qt logs with timestamps, thread IDs, QObject addresses, destroyed signals, and thread-affinity assertions.",
            "Inspect queued connections, deleteLater delivery, QThread shutdown order, and cross-thread UI calls.",
        ])
    if "ffmpeg_video" in domain_names:
        hints.extend([
            "Log AVFrame/AVPacket ownership handoff, pixel format, dimensions, hardware-frame transfer return codes, and render-thread context ownership.",
            "Check whether converter/device/frame pools reset on stream parameter or GPU-context changes.",
        ])
    if "memory" in domain_names:
        hints.extend([
            "Use ASan/UBSan, page heap, Application Verifier, or allocator diagnostics to catch corruption closer to the write site.",
        ])

    return unique_in_order(hints)


def recommend_references(platforms: List[Dict[str, object]], domains: List[Dict[str, object]], classification: str) -> List[str]:
    refs = []
    platform_map = {
        "windows": "references/windows.md",
        "linux": "references/linux.md",
        "macos": "references/macos.md",
    }
    domain_map = {
        "qt": "references/qt-cpp.md",
        "threading": "references/qt-cpp.md",
        "memory": "references/qt-cpp.md",
        "ffmpeg_video": "references/ffmpeg-video.md",
        "watchdog": "references/watchdog.md",
    }
    for item in platforms:
        ref = platform_map.get(str(item["name"]))
        if ref:
            refs.append(ref)
    for item in domains:
        ref = domain_map.get(str(item["name"]))
        if ref:
            refs.append(ref)
    if classification in {"forced kill", "hang", "hang followed by forced kill", "shutdown/restart", "requested stop", "unknown"}:
        refs.append("references/watchdog.md")
    refs.append("references/report-template.md")
    return unique_in_order(refs)


def extract_interesting_lines(text: str, limit: int) -> List[str]:
    keywords = [
        "faulting",
        "exception",
        "termination reason",
        "crashed thread",
        "sigsegv",
        "sigabrt",
        "sigkill",
        "core dumped",
        "segfault",
        "status=",
        "main process exited",
        "watchdog",
        "heartbeat",
        "timeout",
        "oom",
        "killed process",
        "assert",
        "abort",
    ]
    lines = []
    for line in text.splitlines():
        lower = line.lower()
        if any(keyword in lower for keyword in keywords):
            lines.append(line.strip())
        if len(lines) >= limit:
            break
    return lines


def make_summary(text: str, stack_limit: int) -> Dict[str, object]:
    platforms = detect_platforms(text)
    domains = detect_domains(text)
    exception_codes = extract_exception_codes(text)
    signals = extract_signals(text)
    exit_info = classify_exit(text, exception_codes, signals, domains)
    frames = extract_stack_lines(text, stack_limit)
    modules = extract_modules(text)
    processes = extract_process_names(text)
    classification = str(exit_info["classification"])
    references = recommend_references(platforms, domains, classification)
    key_fields = extract_key_fields(text)
    collection_hints = build_collection_hints(platforms, domains, classification)
    fault_context = extract_fault_context(key_fields, exception_codes, modules, frames)
    interesting_lines = extract_interesting_lines(text, 20)
    evidence = build_evidence_summary(key_fields, exception_codes, signals, fault_context, interesting_lines)
    exit_info["confidence"] = estimate_confidence(classification, evidence, fault_context, frames)
    exit_info["supporting_evidence"] = evidence
    exit_info["missing_evidence"] = build_missing_evidence(classification, platforms, frames, fault_context)
    line_count = len(text.splitlines())
    word_counter = Counter(re.findall(r"[A-Za-z_][A-Za-z0-9_:+.-]{2,}", text))

    return {
        "line_count": line_count,
        "platforms": platforms,
        "domains": domains,
        "processes": processes,
        "exception_codes": exception_codes,
        "signals_or_statuses": signals,
        "modules": modules,
        "key_fields": key_fields,
        "exit": exit_info,
        "fault_context": fault_context,
        "stack_like_lines": frames,
        "interesting_lines": interesting_lines,
        "recommended_references": references,
        "collection_hints": collection_hints,
        "frequent_tokens": [token for token, _ in word_counter.most_common(12)],
    }


def format_score_items(items: List[Dict[str, object]]) -> str:
    if not items:
        return "- none detected"
    return "\n".join(f"- {item['name']} (score {item['score']})" for item in items)


def format_dict_items(items: List[Dict[str, str]], key_name: str) -> str:
    if not items:
        return "- none detected"
    return "\n".join(f"- {item[key_name]}: {item['meaning']}" for item in items)


def format_list(items: List[str]) -> str:
    if not items:
        return "- none detected"
    return "\n".join(f"- {item}" for item in items)


def format_key_fields(fields: Dict[str, List[str]]) -> str:
    if not fields:
        return "- none detected"
    lines = []
    for key in sorted(fields):
        lines.append(f"- {key}: {', '.join(fields[key])}")
    return "\n".join(lines)


def format_simple_dict(fields: Dict[str, str]) -> str:
    if not fields:
        return "- none detected"
    return "\n".join(f"- {key}: {fields[key]}" for key in sorted(fields))


def format_markdown(summary: Dict[str, object]) -> str:
    exit_info = summary["exit"]
    assert isinstance(exit_info, dict)
    lines: List[str] = [
        "# Crash Log Triage",
        "",
        f"- Lines scanned: {summary['line_count']}",
        f"- Exit classification: {exit_info['classification']}",
        f"- Classification reason: {exit_info['reason']}",
        f"- Confidence: {exit_info['confidence']}",
        "",
        "## Supporting Evidence",
        format_list(exit_info["supporting_evidence"]),  # type: ignore[arg-type]
        "",
        "## Missing Evidence",
        format_list(exit_info["missing_evidence"]),  # type: ignore[arg-type]
        "",
        "## Likely Platforms",
        format_score_items(summary["platforms"]),  # type: ignore[arg-type]
        "",
        "## Detected Domains",
        format_score_items(summary["domains"]),  # type: ignore[arg-type]
        "",
        "## Processes",
        format_list(summary["processes"]),  # type: ignore[arg-type]
        "",
        "## Exception Codes",
        format_dict_items(summary["exception_codes"], "code"),  # type: ignore[arg-type]
        "",
        "## Signals or Exit Statuses",
        format_dict_items(summary["signals_or_statuses"], "signal"),  # type: ignore[arg-type]
        "",
        "## Modules",
        format_list(summary["modules"]),  # type: ignore[arg-type]
        "",
        "## Key Fields",
        format_key_fields(summary["key_fields"]),  # type: ignore[arg-type]
        "",
        "## Fault Context",
        format_simple_dict(summary["fault_context"]),  # type: ignore[arg-type]
        "",
        "## Stack-Like Lines",
        format_list(summary["stack_like_lines"]),  # type: ignore[arg-type]
        "",
        "## Interesting Lines",
        format_list(summary["interesting_lines"]),  # type: ignore[arg-type]
        "",
        "## Recommended References",
        format_list(summary["recommended_references"]),  # type: ignore[arg-type]
        "",
        "## Collection Hints",
        format_list(summary["collection_hints"]),  # type: ignore[arg-type]
    ]
    return "\n".join(lines) + "\n"


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify and summarize crash-log text.")
    parser.add_argument("path", nargs="?", help="Log file path. Reads stdin when omitted.")
    parser.add_argument("--json", action="store_true", help="Write machine-readable JSON.")
    parser.add_argument("--stack-limit", type=int, default=25, help="Maximum stack-like lines to include.")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    text = read_input(args.path)
    if not text.strip():
        print("No input text provided.", file=sys.stderr)
        return 2

    summary = make_summary(text, max(0, args.stack_limit))
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(format_markdown(summary), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
