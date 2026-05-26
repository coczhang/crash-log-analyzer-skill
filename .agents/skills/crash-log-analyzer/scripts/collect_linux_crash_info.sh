#!/usr/bin/env bash
set -uo pipefail

VERSION="1.1.0"
SERVICE=""
PROCESS=""
HOURS="24"
OUTDIR=""
REDACT=0
ZIP=0

usage() {
  echo "Usage: $0 [--service name.service] [--process process-name] [--hours 24] [--out dir] [--redact] [--zip] [--version]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --service) SERVICE="${2:-}"; shift 2 ;;
    --process) PROCESS="${2:-}"; shift 2 ;;
    --hours) HOURS="${2:-24}"; shift 2 ;;
    --out) OUTDIR="${2:-}"; shift 2 ;;
    --redact) REDACT=1; shift ;;
    --zip) ZIP=1; shift ;;
    --version) echo "$VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$OUTDIR" ]; then
  OUTDIR="crash-info-linux-$(date +%Y%m%d-%H%M%S)"
fi

mkdir -p "$OUTDIR"
WARNINGS_FILE="$OUTDIR/collection-warnings.txt"
: > "$WARNINGS_FILE"

warn() {
  echo "$*" >> "$WARNINGS_FILE"
  echo "warning: $*" >&2
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

hash_file() {
  if have_cmd sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif have_cmd shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo ""
  fi
}

redact_file() {
  file="$1"
  case "$file" in
    *manifest.json|*.zip|*.dmp|*.dump|*.core) return ;;
  esac
  tmp="${file}.redact.$$"
  if sed -E \
    -e 's#/(Users|home)/[^/[:space:]]+#/\1/USER_REDACTED#g' \
    -e 's#([0-9]{1,3}\.){3}[0-9]{1,3}#IP_REDACTED#g' \
    -e 's#[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}#EMAIL_REDACTED#g' \
    -e 's#([Pp]assword|[Pp]asswd|[Tt]oken|[Ss]ecret|[Aa]pi[_-]?[Kk]ey|[Aa]uthorization)[[:space:]]*[:=][[:space:]]*(([Bb]earer|[Bb]asic)[[:space:]]+)?[^[:space:],;]+#\1=REDACTED#g' \
    "$file" > "$tmp"; then
    mv "$tmp" "$file"
  else
    rm -f "$tmp"
    warn "Could not redact $file"
  fi
}

write_manifest() {
  manifest="$OUTDIR/manifest.json"
  warning_count="$(wc -l < "$WARNINGS_FILE" | tr -d ' ')"
  {
    echo "{"
    echo "  \"schema_version\": 1,"
    echo "  \"script\": \"collect_linux_crash_info.sh\","
    echo "  \"script_version\": \"$(json_escape "$VERSION")\","
    echo "  \"platform\": \"linux\","
    echo "  \"collected_at\": \"$(json_escape "$(date -u +%Y-%m-%dT%H:%M:%SZ)")\","
    echo "  \"service\": \"$(json_escape "$SERVICE")\","
    echo "  \"process\": \"$(json_escape "$PROCESS")\","
    echo "  \"hours\": \"$(json_escape "$HOURS")\","
    echo "  \"redacted\": $([ "$REDACT" -eq 1 ] && echo true || echo false),"
    echo "  \"zip_requested\": $([ "$ZIP" -eq 1 ] && echo true || echo false),"
    echo "  \"warnings\": ["
    first_warning=1
    while IFS= read -r warning; do
      [ -n "$warning" ] || continue
      if [ "$first_warning" -eq 0 ]; then
        echo ","
      fi
      first_warning=0
      printf '    "%s"' "$(json_escape "$warning")"
    done < "$WARNINGS_FILE"
    echo
    echo "  ],"
    echo "  \"warnings_file\": \"collection-warnings.txt\","
    echo "  \"warnings_count\": $warning_count,"
    echo "  \"files\": ["
    first=1
    while IFS= read -r file; do
      [ -f "$file" ] || continue
      rel="${file#$OUTDIR/}"
      [ "$rel" = "manifest.json" ] && continue
      size="$(wc -c < "$file" | tr -d ' ')"
      sha="$(hash_file "$file")"
      if [ "$first" -eq 0 ]; then
        echo ","
      fi
      first=0
      printf '    {"path": "%s", "bytes": %s, "sha256": "%s"}' "$(json_escape "$rel")" "$size" "$(json_escape "$sha")"
    done < <(find "$OUTDIR" -type f | sort)
    echo
    echo "  ]"
    echo "}"
  } > "$manifest"
}

create_zip() {
  zip_path="$OUTDIR.zip"
  rm -f "$zip_path"
  if have_cmd zip; then
    (cd "$(dirname "$OUTDIR")" && zip -qr "$(basename "$zip_path")" "$(basename "$OUTDIR")") || warn "zip command failed"
  elif have_cmd python3; then
    if ! python3 - "$OUTDIR" "$zip_path" <<'PY'
import os
import sys
import zipfile

source, target = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
    for root, _, files in os.walk(source):
        for name in files:
            path = os.path.join(root, name)
            archive.write(path, os.path.relpath(path, os.path.dirname(source)))
PY
    then
      warn "python3 zip creation failed"
    fi
  else
    warn "Cannot create zip: neither zip nor python3 is available"
  fi
}

for cmd in journalctl coredumpctl dmesg pgrep uname; do
  have_cmd "$cmd" || warn "Missing command: $cmd"
done
if [ -n "$SERVICE" ]; then
  have_cmd systemctl || warn "Missing command: systemctl"
fi

{
  echo "collected_at=$(date --iso-8601=seconds 2>/dev/null || date)"
  echo "script_version=$VERSION"
  echo "host=$(hostname 2>/dev/null || true)"
  echo "service=$SERVICE"
  echo "process=$PROCESS"
  echo "hours=$HOURS"
  echo "redacted=$REDACT"
  uname -a 2>/dev/null || true
} > "$OUTDIR/summary.txt"

if [ -n "$SERVICE" ]; then
  systemctl status "$SERVICE" --no-pager > "$OUTDIR/systemctl-status.txt" 2>&1 || warn "systemctl status failed for $SERVICE"
  systemctl show "$SERVICE" \
    -p Id -p Names -p ActiveState -p SubState -p Result -p ExecMainPID -p ExecMainCode -p ExecMainStatus -p Restart -p NRestarts \
    > "$OUTDIR/systemctl-show.txt" 2>&1 || warn "systemctl show failed for $SERVICE"
  journalctl -u "$SERVICE" --since "$HOURS hours ago" --no-pager > "$OUTDIR/journal-service.txt" 2>&1 || warn "journalctl service query failed for $SERVICE"
fi

journalctl --since "$HOURS hours ago" --no-pager > "$OUTDIR/journal-window.txt" 2>&1 || warn "journalctl window query failed"
journalctl -k --since "$HOURS hours ago" --no-pager > "$OUTDIR/journal-kernel.txt" 2>&1 || warn "journalctl kernel query failed"
dmesg -T > "$OUTDIR/dmesg.txt" 2>&1 || warn "dmesg query failed; root or CAP_SYSLOG may be required"

if [ -n "$PROCESS" ]; then
  coredumpctl list "$PROCESS" > "$OUTDIR/coredump-list.txt" 2>&1 || warn "coredumpctl list failed for $PROCESS"
  pgrep -a "$PROCESS" > "$OUTDIR/pgrep.txt" 2>&1 || warn "pgrep found no matching process or failed for $PROCESS"
else
  coredumpctl list > "$OUTDIR/coredump-list.txt" 2>&1 || warn "coredumpctl list failed"
fi

grep -i -E "segfault|core dump|coredump|killed process|out of memory|oom|sigsegv|sigabrt|sigkill|sigterm" \
  "$OUTDIR/journal-window.txt" "$OUTDIR/journal-kernel.txt" "$OUTDIR/dmesg.txt" \
  > "$OUTDIR/crash-keywords.txt" 2>/dev/null || true

if [ "$REDACT" -eq 1 ]; then
  while IFS= read -r file; do
    [ -f "$file" ] && redact_file "$file"
  done < <(find "$OUTDIR" -type f)
fi

write_manifest

if [ "$ZIP" -eq 1 ]; then
  create_zip
  write_manifest
fi

echo "Crash collection written to $OUTDIR"
if [ "$ZIP" -eq 1 ] && [ -f "$OUTDIR.zip" ]; then
  echo "Zip written to $OUTDIR.zip"
fi
