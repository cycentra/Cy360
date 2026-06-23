#!/bin/bash
# CyCentra 360 — On-Demand Endpoint Scan Active Response
# Runs ClamAV (if installed) or a lightweight find-based heuristic scan.
# Portal-triggered via Wazuh API (no automatic AR block in ossec.conf).
# "delete" is a no-op — scans cannot be cancelled mid-flight, just ignored.
# Output is written to the AR log and a per-scan report file.

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
SCAN_REPORT_DIR="/var/ossec/logs/cy360-scan-reports"

_log() {
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') scan-endpoint: $*" >> "$LOG_FILE"
}

read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")

if [[ "$COMMAND" == "delete" ]]; then
    _log "delete command received — no-op for scan-endpoint"
    exit 0
fi

_log "on-demand scan triggered on $(hostname)"
mkdir -p "$SCAN_REPORT_DIR"
REPORT="${SCAN_REPORT_DIR}/scan-$(date -u '+%Y%m%dT%H%M%SZ').log"

# ── Target directories — volatile/writable locations most likely to hold malware
SCAN_TARGETS=(
    /tmp
    /var/tmp
    /dev/shm
    /home
    /root
)

# ── ClamAV scan (preferred) ───────────────────────────────────────────────────
if command -v clamscan &>/dev/null; then
    _log "ClamAV found — running clamscan"
    {
        echo "=== CyCentra 360 On-Demand ClamAV Scan ==="
        echo "Host:   $(hostname)"
        echo "Start:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "Paths:  ${SCAN_TARGETS[*]}"
        echo "=========================================="
    } >> "$REPORT"

    clamscan \
        --recursive \
        --infected \
        --no-summary \
        --max-filesize=100M \
        --max-scansize=500M \
        "${SCAN_TARGETS[@]}" >> "$REPORT" 2>&1 || true

    INFECTED=$(grep -c "FOUND$" "$REPORT" 2>/dev/null || echo 0)
    _log "ClamAV scan complete — infected files: $INFECTED — report: $REPORT"

    if [[ "$INFECTED" -gt 0 ]]; then
        _log "ALERT: $INFECTED infected file(s) found on $(hostname) — review $REPORT"
        # Emit a synthetic Wazuh event for the portal to surface
        echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') cy360-scan: ClamAV found $INFECTED infected file(s) on $(hostname). Report: $REPORT" \
            >> /var/ossec/logs/active-responses.log
    fi
    exit 0
fi

# ── Heuristic fallback: find suspicious executables in volatile paths ─────────
_log "ClamAV not available — running heuristic find-based scan"
{
    echo "=== CyCentra 360 On-Demand Heuristic Scan ==="
    echo "Host:   $(hostname)"
    echo "Start:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Note:   ClamAV not installed — heuristic mode only"
    echo "=============================================="
} >> "$REPORT"

# Find setuid/setgid files in scan targets
_log "checking for setuid/setgid in volatile paths"
find "${SCAN_TARGETS[@]}" -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
    | while read -r f; do echo "SETUID/SETGID: $f"; done >> "$REPORT"

# Find ELF executables without owning packages (world-writable dirs, /tmp, etc.)
_log "checking for executable scripts and ELFs in writable paths"
find "${SCAN_TARGETS[@]}" -xdev -type f \( -perm -0111 -o -name "*.sh" -o -name "*.py" -o -name "*.elf" \) 2>/dev/null \
    | head -500 \
    | while read -r f; do echo "EXEC: $f"; done >> "$REPORT"

# Find recently modified files (last 24 h) — potential dropper activity
_log "checking for files modified in last 24h"
find "${SCAN_TARGETS[@]}" -xdev -type f -mmin -1440 2>/dev/null \
    | head -200 \
    | while read -r f; do echo "RECENT: $f"; done >> "$REPORT"

echo "End:    $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$REPORT"
_log "heuristic scan complete — report: $REPORT"

exit 0
