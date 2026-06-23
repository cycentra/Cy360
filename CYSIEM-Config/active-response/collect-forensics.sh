#!/bin/bash
# CyCentra 360 — Forensic Collection Active Response
# Captures volatile artifacts for post-incident analysis. Non-destructive — read-only.
# Output: /var/ossec/logs/cy360-forensics/HOSTNAME-YYYYMMDDTHHMMSSZ.tar.gz
# Triggered by: policy engine (manual). "delete" is a no-op.
# Wazuh 4.x AR: receives JSON on stdin; command field is "add" or "delete".

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
FORENSICS_DIR="/var/ossec/logs/cy360-forensics"
MAX_REPORTS=20   # rotate when more than this many exist

_log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') collect-forensics: $*" >> "$LOG_FILE"; }

read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")

if [[ "$COMMAND" == "delete" ]]; then
    _log "delete command received — no-op for collect-forensics"
    exit 0
fi

HOST=$(hostname)
TS=$(date -u '+%Y%m%dT%H%M%SZ')
WORKDIR=$(mktemp -d)
REPORT_NAME="${HOST}-${TS}"

_log "forensic collection started on $HOST — workdir $WORKDIR"
mkdir -p "$FORENSICS_DIR"

# ── Running processes ─────────────────────────────────────────────────────────
{
    echo "=== PROCESSES (ps auxf) ==="
    ps auxf 2>/dev/null || ps aux 2>/dev/null || echo "ps unavailable"
    echo ""
    echo "=== PROCESS TREE (pstree) ==="
    pstree -p 2>/dev/null || echo "pstree unavailable"
} > "$WORKDIR/processes.txt" 2>/dev/null

# ── Network connections ───────────────────────────────────────────────────────
{
    echo "=== LISTENING SOCKETS (ss -tulnp) ==="
    ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || echo "ss/netstat unavailable"
    echo ""
    echo "=== ALL CONNECTIONS (ss -anp) ==="
    ss -anp 2>/dev/null || netstat -anp 2>/dev/null || echo "unavailable"
    echo ""
    echo "=== ROUTING TABLE ==="
    ip route show 2>/dev/null || route -n 2>/dev/null || echo "unavailable"
    echo ""
    echo "=== ARP TABLE ==="
    arp -a 2>/dev/null || ip neigh 2>/dev/null || echo "unavailable"
} > "$WORKDIR/network.txt" 2>/dev/null

# ── Open files (top consumers + suspicious paths) ────────────────────────────
{
    echo "=== OPEN FILES IN /tmp /var/tmp /dev/shm ==="
    lsof /tmp /var/tmp /dev/shm 2>/dev/null | head -200 || \
        find /tmp /var/tmp /dev/shm -maxdepth 3 -type f 2>/dev/null | head -200
} > "$WORKDIR/open_files.txt" 2>/dev/null

# ── Cron jobs ─────────────────────────────────────────────────────────────────
{
    echo "=== /etc/crontab ==="
    cat /etc/crontab 2>/dev/null || echo "not found"
    echo ""
    echo "=== /etc/cron.d/ ==="
    ls -la /etc/cron.d/ 2>/dev/null && cat /etc/cron.d/* 2>/dev/null || echo "empty"
    echo ""
    echo "=== /var/spool/cron/ (all users) ==="
    find /var/spool/cron -type f 2>/dev/null | while read -r f; do
        echo "--- $f ---"; cat "$f" 2>/dev/null
    done
    echo ""
    echo "=== systemd timers ==="
    systemctl list-timers --all 2>/dev/null || echo "systemd unavailable"
} > "$WORKDIR/cron_jobs.txt" 2>/dev/null

# ── Persistence: startup / autorun ───────────────────────────────────────────
{
    echo "=== Enabled systemd services ==="
    systemctl list-unit-files --state=enabled 2>/dev/null | head -100 || echo "unavailable"
    echo ""
    echo "=== /etc/rc.local ==="
    cat /etc/rc.local 2>/dev/null || echo "not found"
    echo ""
    echo "=== /etc/init.d/ scripts ==="
    ls /etc/init.d/ 2>/dev/null || echo "empty"
    echo ""
    echo "=== ~/.bashrc / ~/.profile (root) ==="
    cat /root/.bashrc /root/.profile 2>/dev/null || echo "not found"
    echo ""
    echo "=== SSH authorized_keys (root) ==="
    cat /root/.ssh/authorized_keys 2>/dev/null || echo "not found"
} > "$WORKDIR/persistence.txt" 2>/dev/null

# ── Loaded kernel modules ─────────────────────────────────────────────────────
{
    echo "=== Loaded modules (lsmod) ==="
    lsmod 2>/dev/null || echo "lsmod unavailable"
} > "$WORKDIR/kernel_modules.txt" 2>/dev/null

# ── Recently modified files (last 24h) ───────────────────────────────────────
{
    echo "=== Files modified in last 24h (excl. /proc /sys /dev /run) ==="
    find / -xdev -not \( -path '/proc/*' -o -path '/sys/*' \
        -o -path '/dev/*' -o -path '/run/*' \) \
        -type f -mmin -1440 2>/dev/null | sort | head -500
} > "$WORKDIR/recent_files.txt" 2>/dev/null

# ── Environment & users ───────────────────────────────────────────────────────
{
    echo "=== Logged-in users (who) ==="
    who 2>/dev/null || echo "unavailable"
    echo ""
    echo "=== Last logins (last -n 30) ==="
    last -n 30 2>/dev/null || echo "unavailable"
    echo ""
    echo "=== Shadow accounts (locked/unlocked) ==="
    awk -F: '$2 !~ /^!/ && $2 != "*" { print $1 " UNLOCKED" }' /etc/shadow 2>/dev/null || echo "unavailable"
    echo ""
    echo "=== Sudoers ==="
    cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' || echo "unavailable"
} > "$WORKDIR/users_sessions.txt" 2>/dev/null

# ── System info ───────────────────────────────────────────────────────────────
{
    echo "=== Hostname / OS ==="
    uname -a; cat /etc/os-release 2>/dev/null
    echo ""
    echo "=== Uptime ==="
    uptime
    echo ""
    echo "=== Memory ==="
    free -h 2>/dev/null || echo "unavailable"
    echo ""
    echo "=== Disk ==="
    df -h 2>/dev/null
    echo ""
    echo "=== Collection timestamp ==="
    date -u
} > "$WORKDIR/system_info.txt" 2>/dev/null

# ── Package into tar.gz ───────────────────────────────────────────────────────
ARCHIVE="$FORENSICS_DIR/${REPORT_NAME}.tar.gz"
tar -czf "$ARCHIVE" -C "$(dirname "$WORKDIR")" "$(basename "$WORKDIR")" 2>/dev/null
chmod 600 "$ARCHIVE"
rm -rf "$WORKDIR"

_log "forensic archive created: $ARCHIVE ($(du -sh "$ARCHIVE" 2>/dev/null | cut -f1))"

# Rotate old reports
_count=$(find "$FORENSICS_DIR" -name "*.tar.gz" | wc -l)
if [[ "$_count" -gt "$MAX_REPORTS" ]]; then
    find "$FORENSICS_DIR" -name "*.tar.gz" -printf '%T+ %p\n' 2>/dev/null \
        | sort | head -$((_count - MAX_REPORTS)) | awk '{print $2}' | xargs rm -f
    _log "rotated old forensic archives (kept newest $MAX_REPORTS)"
fi

exit 0
