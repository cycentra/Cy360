#!/bin/bash
# CyCentra 360 — WiFi/Wireless Blocking Active Response
# Linux: uses nmcli (NetworkManager) or rfkill.
# macOS: uses networksetup to disable Airport.
# Portal-triggered ONLY — no automatic AR block in ossec.conf.
# "delete" re-enables WiFi.
# Wazuh 4.x AR: receives JSON on stdin; command field is "add" or "delete".

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_FILE="/var/ossec/var/run/cy360-wifi-block.lock"

_log() {
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') block-wifi: $*" >> "$LOG_FILE"
}

read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")

_log "command=$COMMAND host=$(hostname) os=$(uname -s)"

# ── Linux WiFi block ──────────────────────────────────────────────────────────
_linux_block() {
    if [[ -f "$LOCK_FILE" ]]; then
        _log "WiFi already blocked (lock present) — skipping duplicate"
        return
    fi

    local blocked=0

    # Method 1: NetworkManager (most common on modern distros)
    if command -v nmcli &>/dev/null; then
        nmcli radio wifi off 2>/dev/null && _log "nmcli: WiFi radio disabled" && ((blocked++)) || true
    fi

    # Method 2: rfkill (kernel-level, works without NetworkManager)
    if command -v rfkill &>/dev/null; then
        rfkill block wifi 2>/dev/null && _log "rfkill: WiFi blocked" && ((blocked++)) || true
    fi

    if [[ "$blocked" -eq 0 ]]; then
        _log "ERROR: neither nmcli nor rfkill available — cannot block WiFi on $(hostname)"
        exit 1
    fi

    echo "$(date +%s)" > "$LOCK_FILE"
    _log "WiFi BLOCKED on $(hostname)"
}

_linux_unblock() {
    local unblocked=0

    if command -v rfkill &>/dev/null; then
        rfkill unblock wifi 2>/dev/null && _log "rfkill: WiFi unblocked" && ((unblocked++)) || true
    fi

    if command -v nmcli &>/dev/null; then
        nmcli radio wifi on 2>/dev/null && _log "nmcli: WiFi radio enabled" && ((unblocked++)) || true
    fi

    if [[ "$unblocked" -eq 0 ]]; then
        _log "WARN: could not unblock WiFi — nmcli and rfkill both unavailable"
    fi

    rm -f "$LOCK_FILE"
    _log "WiFi UNBLOCKED on $(hostname)"
}

# ── macOS WiFi block ──────────────────────────────────────────────────────────
_macos_block() {
    if [[ -f "$LOCK_FILE" ]]; then
        _log "WiFi already blocked (lock present) — skipping duplicate"
        return
    fi

    # Detect the airport network interface name (typically en0 or en1)
    local iface
    iface=$(networksetup -listallhardwareports 2>/dev/null \
        | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -1 || echo "en0")

    if networksetup -setairportpower "$iface" off 2>/dev/null; then
        _log "networksetup: AirPort ($iface) powered off"
    else
        _log "WARN: networksetup setairportpower failed on $iface — may need MDM policy"
    fi

    echo "$(date +%s)" > "$LOCK_FILE"
    _log "WiFi BLOCKED on macOS $(hostname)"
}

_macos_unblock() {
    local iface
    iface=$(networksetup -listallhardwareports 2>/dev/null \
        | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -1 || echo "en0")

    if networksetup -setairportpower "$iface" on 2>/dev/null; then
        _log "networksetup: AirPort ($iface) powered on"
    else
        _log "WARN: networksetup setairportpower on failed on $iface"
    fi

    rm -f "$LOCK_FILE"
    _log "WiFi UNBLOCKED on macOS $(hostname)"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
OS=$(uname -s)
case "$COMMAND" in
  add)
    case "$OS" in
      Linux)  _linux_block   ;;
      Darwin) _macos_block   ;;
      *)      _log "ERROR: unsupported OS '$OS'"; exit 1 ;;
    esac
    ;;
  delete)
    case "$OS" in
      Linux)  _linux_unblock   ;;
      Darwin) _macos_unblock   ;;
      *)      _log "ERROR: unsupported OS '$OS'"; exit 1 ;;
    esac
    ;;
  *)
    _log "unknown command '$COMMAND' — defaulting to block"
    case "$OS" in
      Linux)  _linux_block   ;;
      Darwin) _macos_block   ;;
    esac
    ;;
esac

exit 0
