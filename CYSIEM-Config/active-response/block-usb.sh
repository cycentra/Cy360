#!/bin/bash
# CyCentra 360 — USB Storage Blocking Active Response
# Linux: blacklists usb-storage via modprobe.d + unloads the module immediately.
# macOS: disables the IOUSBMassStorageClass kext (requires SIP partial disable or MDM).
# Triggered by: rules 100910 (Windows/Linux built-in), 100911 (Sysmon EventID 6, USBSTOR)
# timeout=0 (permanent) — "delete" re-enables USB storage.
# Wazuh 4.x AR: receives JSON on stdin; command field is "add" or "delete".

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
MODPROBE_CONF="/etc/modprobe.d/cy360-block-usb.conf"
LOCK_FILE="/var/ossec/var/run/cy360-usb-block.lock"

_log() {
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') block-usb: $*" >> "$LOG_FILE"
}

read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")

_log "command=$COMMAND host=$(hostname) os=$(uname -s)"

# ── Linux USB block ───────────────────────────────────────────────────────────
_linux_block() {
    if [[ -f "$LOCK_FILE" ]]; then
        _log "USB already blocked (lock present) — skipping duplicate"
        return
    fi

    # Write modprobe blacklist so block survives reboot
    cat > "$MODPROBE_CONF" << 'CONF'
# CyCentra 360 — USB storage blocked by active-response
blacklist usb-storage
install usb-storage /bin/true
CONF
    chmod 644 "$MODPROBE_CONF"

    # Update initramfs on Ubuntu/Debian for persistence across reboots
    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u -k all 2>/dev/null || true
    fi

    # Unload module if currently loaded
    if lsmod 2>/dev/null | grep -q "^usb_storage"; then
        modprobe -r usb-storage 2>/dev/null && _log "usb-storage module unloaded" || \
            _log "WARN: could not unload usb-storage (device in use?)"
    else
        _log "usb-storage module not loaded — blacklist written"
    fi

    echo "$(date +%s)" > "$LOCK_FILE"
    _log "USB storage BLOCKED on $(hostname)"
}

_linux_unblock() {
    rm -f "$MODPROBE_CONF"
    rm -f "$LOCK_FILE"

    if command -v update-initramfs &>/dev/null; then
        update-initramfs -u -k all 2>/dev/null || true
    fi

    # Reload the module so USB works immediately without reboot
    modprobe usb-storage 2>/dev/null && _log "usb-storage module re-loaded" || \
        _log "WARN: modprobe usb-storage failed — may need reboot"

    _log "USB storage UNBLOCKED on $(hostname)"
}

# ── macOS USB block ────────────────────────────────────────────────────────────
# Requires: `sudo kextutil -b com.apple.driver.usb.AppleUSBHostComposite`
# or MDM-managed System Extension management. Without SIP partial disable,
# kextutil will fail silently — log and notify for manual MDM policy push.
_macos_block() {
    if [[ -f "$LOCK_FILE" ]]; then
        _log "USB already blocked (lock present) — skipping duplicate"
        return
    fi

    if command -v kextutil &>/dev/null; then
        kextutil -b com.apple.iokit.IOUSBMassStorageClass 2>/dev/null && \
            _log "IOUSBMassStorageClass kext blocked via kextutil" || \
            _log "WARN: kextutil failed (SIP may block this) — manual MDM USB profile required"
    else
        _log "WARN: kextutil not found on macOS — push USB restriction via MDM (Jamf/ABM)"
    fi

    echo "$(date +%s)" > "$LOCK_FILE"
    _log "USB block attempted on macOS $(hostname) — verify via MDM or manual inspection"
}

_macos_unblock() {
    if command -v kextload &>/dev/null; then
        kextload /System/Library/Extensions/IOUSBMassStorageClass.kext 2>/dev/null && \
            _log "IOUSBMassStorageClass kext re-loaded" || \
            _log "WARN: kextload failed — may need reboot or MDM profile removal"
    fi
    rm -f "$LOCK_FILE"
    _log "USB unblock attempted on macOS $(hostname)"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
OS=$(uname -s)
case "$COMMAND" in
  add)
    case "$OS" in
      Linux)  _linux_block   ;;
      Darwin) _macos_block   ;;
      *)      _log "ERROR: unsupported OS '$OS'"
              exit 1 ;;
    esac
    ;;
  delete)
    case "$OS" in
      Linux)  _linux_unblock   ;;
      Darwin) _macos_unblock   ;;
      *)      _log "ERROR: unsupported OS '$OS'"
              exit 1 ;;
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
