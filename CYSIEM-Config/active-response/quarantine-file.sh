#!/bin/bash
# CyCentra 360 — File Quarantine Active Response
# Moves the matching file to /var/ossec/quarantine/ and kills owning processes.
# Triggered by: rule 101003 (MISP hash blacklist match from FIM/syscheck event)
# "delete" command: logs restoration request but does NOT restore automatically
#                   (restoration requires analyst review via portal).
# Wazuh 4.x AR: receives JSON on stdin; command field is "add" or "delete".

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/quarantine"

_log() {
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') quarantine-file: $*" >> "$LOG_FILE"
}

# ── Parse Wazuh JSON from stdin ──────────────────────────────────────────────
read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")

# Try multiple field paths where a file path may live in a MISP/FIM correlated alert
FILE_PATH=$(echo "$INPUT" | python3 - 2>/dev/null <<'PYEOF'
import sys, json
d = json.load(sys.stdin)
params = d.get("parameters", {})
alert  = params.get("alert", {})
# Preference order: syscheck.path, data.path, data.syscheck.path, data.file
for key_chain in (
    ["syscheck", "path"],
    ["data", "path"],
    ["data", "syscheck", "path"],
    ["data", "file"],
):
    node = alert
    for k in key_chain:
        node = node.get(k, {}) if isinstance(node, dict) else {}
    if isinstance(node, str) and node:
        print(node)
        sys.exit(0)
sys.exit(1)
PYEOF
) || FILE_PATH=""

_log "command=$COMMAND file=${FILE_PATH:-<not-found-in-alert>}"

if [[ "$COMMAND" == "delete" ]]; then
    _log "RESTORE request received for '${FILE_PATH}' — manual analyst action required via CyCentra portal"
    exit 0
fi

# ── Validate file path before acting ────────────────────────────────────────
if [[ -z "$FILE_PATH" ]]; then
    _log "ERROR: no file path in alert JSON — cannot quarantine (check alert field mapping)"
    exit 1
fi

if [[ ! -e "$FILE_PATH" ]]; then
    _log "WARN: '$FILE_PATH' does not exist on this host — already removed or path mismatch"
    exit 0
fi

# Safety guard: never quarantine Wazuh agent files or system binaries
case "$FILE_PATH" in
    /var/ossec/*|/usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
        _log "ERROR: refusing to quarantine protected path '$FILE_PATH'"
        exit 1
        ;;
esac

# ── Create quarantine directory with tight permissions ───────────────────────
mkdir -p "$QUARANTINE_DIR"
chmod 700 "$QUARANTINE_DIR"
chown root:root "$QUARANTINE_DIR"

# ── Kill processes with open handles on the file ─────────────────────────────
if command -v fuser &>/dev/null; then
    fuser -k "$FILE_PATH" 2>/dev/null && _log "killed process(es) holding '$FILE_PATH'" || true
fi

# ── Move file to quarantine — preserve original name + timestamp suffix ──────
BASENAME=$(basename "$FILE_PATH")
DEST="$QUARANTINE_DIR/${BASENAME}.$(date -u '+%Y%m%dT%H%M%SZ')"
if mv -- "$FILE_PATH" "$DEST"; then
    chmod 000 "$DEST"
    _log "QUARANTINED '$FILE_PATH' → '$DEST'"
    # Write metadata sidecar for analyst review
    cat > "${DEST}.meta" << META
source_path=$FILE_PATH
quarantined=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
trigger=rule-101003-misp-hash
host=$(hostname)
META
else
    _log "ERROR: failed to move '$FILE_PATH' to quarantine"
    exit 1
fi

exit 0
