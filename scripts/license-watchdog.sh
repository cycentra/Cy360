#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CyCentra 360 — License Watchdog
# Runs daily via systemd timer.  Stops all platform services when the
# license (or demo period) has expired.
# ─────────────────────────────────────────────────────────────────────────────

LOG="/var/log/cycentra/license-watchdog.log"
SERVICES=(cycentra-backend cysiemstack-engine cysiem-to-redis)

_log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")  $*" | tee -a "$LOG"; }

mkdir -p "$(dirname "$LOG")"

_log "License watchdog running..."

source /opt/cycentra/license-check.sh 2>&1 | tee -a "$LOG"
_CODE=$?

if [[ $_CODE -eq 2 ]]; then
    _log "LICENSE EXPIRED — stopping all CyCentra services"
    for svc in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc"; then
            systemctl stop "$svc"
            _log "Stopped: $svc"
        fi
    done
    # Write a lockfile so services won't auto-restart
    echo "EXPIRED $(date -u +%Y-%m-%dT%H:%M:%SZ)" > /opt/cycentra/.license_expired
    _log "Services stopped. Renew license at https://cycentra.com"
elif [[ $_CODE -eq 0 || $_CODE -eq 1 ]]; then
    # Remove any stale lockfile if license was renewed
    rm -f /opt/cycentra/.license_expired
    _log "License OK (type=${CYCENTRA_LICENSE_TYPE}, days_remaining=${CYCENTRA_DAYS_REMAINING})"
fi
