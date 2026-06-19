#!/bin/bash
# CyCentra 360 — Host Isolation Active Response
# Drops all inbound/outbound traffic; whitelists Wazuh manager port 1514 (TCP+UDP).
# Triggered by: anti-tamper/fileless-malware rules 101000-101001 (local)
#               and MISP absolute match rules 101002-101003 (global/all).
# Wazuh 4.x active-response: receives JSON on stdin; command field is "add" or "delete".

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_FILE="/var/ossec/var/run/cy360-isolation.lock"
CHAIN="CY360_ISOLATION"

_log() {
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') isolate-host: $*" >> "$LOG_FILE"
}

# ── Parse Wazuh 4.x JSON from stdin ─────────────────────────────────────────
read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")
MANAGER_IP=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); \
     print(d.get('parameters',{}).get('alert',{}).get('manager',{}).get('name',''))" \
    2>/dev/null || echo "")

# Fall back: parse manager address from ossec.conf
if [[ -z "$MANAGER_IP" ]]; then
    MANAGER_IP=$(grep -oPm1 '(?<=<address>)[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null \
        | head -1 || echo "")
fi

_log "command=$COMMAND manager=${MANAGER_IP:-<unknown>}"

# ── Require iptables or nft ───────────────────────────────────────────────────
if ! command -v iptables &>/dev/null && ! command -v nft &>/dev/null; then
    _log "ERROR: neither iptables nor nft found — cannot isolate host"
    exit 1
fi

# ── iptables engine ───────────────────────────────────────────────────────────
_apply_iptables() {
    iptables -N "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN"

    # Loopback always allowed
    iptables -A "$CHAIN" -i lo -j ACCEPT
    iptables -A "$CHAIN" -o lo -j ACCEPT

    # Whitelist Wazuh manager port 1514 (TCP + UDP) both directions
    if [[ -n "$MANAGER_IP" ]]; then
        iptables -A "$CHAIN" -d "$MANAGER_IP" -p tcp --dport 1514 -j ACCEPT
        iptables -A "$CHAIN" -d "$MANAGER_IP" -p udp --dport 1514 -j ACCEPT
        iptables -A "$CHAIN" -s "$MANAGER_IP" -p tcp --sport 1514 -j ACCEPT
        iptables -A "$CHAIN" -s "$MANAGER_IP" -p udp --sport 1514 -j ACCEPT
    fi

    # Allow established Wazuh sessions so in-flight manager comms are not cut
    iptables -A "$CHAIN" -m state --state ESTABLISHED,RELATED -p tcp --sport 1514 -j ACCEPT
    iptables -A "$CHAIN" -m state --state ESTABLISHED,RELATED -p tcp --dport 1514 -j ACCEPT

    # Drop everything else
    iptables -A "$CHAIN" -j DROP

    # Hook chain into INPUT and OUTPUT (idempotent check-before-insert)
    iptables -C INPUT  -j "$CHAIN" 2>/dev/null || iptables -I INPUT  1 -j "$CHAIN"
    iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"

    _log "iptables isolation APPLIED"
}

_remove_iptables() {
    iptables -D INPUT  -j "$CHAIN" 2>/dev/null || true
    iptables -D OUTPUT -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    _log "iptables isolation REMOVED"
}

# ── nftables engine (fallback when iptables absent) ──────────────────────────
_apply_nftables() {
    nft add table inet cy360_isolation 2>/dev/null || true
    nft add chain inet cy360_isolation input \
        '{ type filter hook input priority -100; policy drop; }' 2>/dev/null || true
    nft add chain inet cy360_isolation output \
        '{ type filter hook output priority -100; policy drop; }' 2>/dev/null || true
    nft flush chain inet cy360_isolation input  2>/dev/null || true
    nft flush chain inet cy360_isolation output 2>/dev/null || true

    # Loopback
    nft add rule inet cy360_isolation input  iif lo accept
    nft add rule inet cy360_isolation output oif lo accept

    # Wazuh manager port 1514
    if [[ -n "$MANAGER_IP" ]]; then
        nft add rule inet cy360_isolation output ip daddr "$MANAGER_IP" tcp dport 1514 accept
        nft add rule inet cy360_isolation output ip daddr "$MANAGER_IP" udp dport 1514 accept
        nft add rule inet cy360_isolation input  ip saddr "$MANAGER_IP" tcp sport 1514 accept
        nft add rule inet cy360_isolation input  ip saddr "$MANAGER_IP" udp sport 1514 accept
    fi

    _log "nftables isolation APPLIED"
}

_remove_nftables() {
    nft delete table inet cy360_isolation 2>/dev/null || true
    _log "nftables isolation REMOVED"
}

# ── State engine ──────────────────────────────────────────────────────────────
_apply_isolation() {
    if [[ -f "$LOCK_FILE" ]]; then
        _log "isolation already active (lock present) — skipping duplicate apply"
        return
    fi
    if command -v iptables &>/dev/null; then
        _apply_iptables
    else
        _apply_nftables
    fi
    echo "$(date +%s)" > "$LOCK_FILE"
    _log "lock written to $LOCK_FILE"
}

_remove_isolation() {
    if command -v iptables &>/dev/null; then
        _remove_iptables
    else
        _remove_nftables
    fi
    rm -f "$LOCK_FILE"
    _log "lock removed"
}

case "$COMMAND" in
  add)    _apply_isolation  ;;
  delete) _remove_isolation ;;
  *)
    _log "unknown command '$COMMAND' — defaulting to add"
    _apply_isolation
    ;;
esac

exit 0
