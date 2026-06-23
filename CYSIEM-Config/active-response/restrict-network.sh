#!/bin/bash
# CyCentra 360 — Restrict Network Active Response
# Partial isolation: blocks internet-bound traffic while preserving LAN connectivity.
# Useful when full isolation (isolate-host.sh) is too aggressive — keeps endpoint
# reachable for internal remediation tools while cutting off C2 egress.
# Triggered by: policy engine (manual or auto). No ossec.conf auto AR block by default.
# Wazuh 4.x AR: receives JSON on stdin; command field is "add" or "delete".

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_FILE="/var/ossec/var/run/cy360-net-restrict.lock"
CHAIN="CY360_NET_RESTRICT"

_log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') restrict-network: $*" >> "$LOG_FILE"; }

read -r INPUT
COMMAND=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('command','add'))" 2>/dev/null || echo "add")
MANAGER_IP=$(echo "$INPUT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); \
     print(d.get('parameters',{}).get('alert',{}).get('manager',{}).get('name',''))" \
    2>/dev/null || echo "")
[[ -z "$MANAGER_IP" ]] && MANAGER_IP=$(grep -oPm1 '(?<=<address>)[^<]+' \
    /var/ossec/etc/ossec.conf 2>/dev/null | head -1 || echo "")

_log "command=$COMMAND manager=${MANAGER_IP:-<unknown>}"

if ! command -v iptables &>/dev/null && ! command -v nft &>/dev/null; then
    _log "ERROR: neither iptables nor nft found"; exit 1
fi

# ── iptables: allow LAN, block internet ───────────────────────────────────────
_apply_iptables() {
    iptables -N "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN"

    # Always allow loopback
    iptables -A "$CHAIN" -i lo -j ACCEPT
    iptables -A "$CHAIN" -o lo -j ACCEPT

    # Allow Wazuh manager comms
    if [[ -n "$MANAGER_IP" ]]; then
        iptables -A "$CHAIN" -d "$MANAGER_IP" -p tcp --dport 1514 -j ACCEPT
        iptables -A "$CHAIN" -d "$MANAGER_IP" -p udp --dport 1514 -j ACCEPT
        iptables -A "$CHAIN" -s "$MANAGER_IP" -p tcp --sport 1514 -j ACCEPT
        iptables -A "$CHAIN" -s "$MANAGER_IP" -p udp --sport 1514 -j ACCEPT
    fi

    # Allow established sessions (in-flight TCP so SSH over LAN still works)
    iptables -A "$CHAIN" -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow all RFC1918 private LAN traffic
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        iptables -A "$CHAIN" -d "$net" -j ACCEPT
        iptables -A "$CHAIN" -s "$net" -j ACCEPT
    done

    # Allow DNS to LAN resolvers (common: .1 or .2 on the subnet)
    iptables -A "$CHAIN" -p udp --dport 53 -j ACCEPT
    iptables -A "$CHAIN" -p tcp --dport 53 -j ACCEPT

    # Block everything else (internet)
    iptables -A "$CHAIN" -j DROP

    iptables -C INPUT  -j "$CHAIN" 2>/dev/null || iptables -I INPUT  1 -j "$CHAIN"
    iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"
    iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"
    _log "iptables internet restriction APPLIED (LAN preserved)"
}

_remove_iptables() {
    iptables -D INPUT   -j "$CHAIN" 2>/dev/null || true
    iptables -D OUTPUT  -j "$CHAIN" 2>/dev/null || true
    iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    _log "iptables internet restriction REMOVED"
}

# ── nftables fallback ─────────────────────────────────────────────────────────
_apply_nftables() {
    nft add table inet cy360_restrict 2>/dev/null || true
    nft add chain inet cy360_restrict input  '{ type filter hook input priority -50; policy accept; }' 2>/dev/null || true
    nft add chain inet cy360_restrict output '{ type filter hook output priority -50; policy accept; }' 2>/dev/null || true
    nft flush chain inet cy360_restrict input  2>/dev/null || true
    nft flush chain inet cy360_restrict output 2>/dev/null || true

    nft add rule inet cy360_restrict input  iif lo accept
    nft add rule inet cy360_restrict output oif lo accept
    nft add rule inet cy360_restrict input  ip saddr {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16} accept
    nft add rule inet cy360_restrict output ip daddr {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16} accept
    nft add rule inet cy360_restrict input  ct state established,related accept
    nft add rule inet cy360_restrict output ct state established,related accept
    nft add rule inet cy360_restrict output ip daddr != {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16} drop
    _log "nftables internet restriction APPLIED"
}

_remove_nftables() {
    nft delete table inet cy360_restrict 2>/dev/null || true
    _log "nftables internet restriction REMOVED"
}

_apply() {
    [[ -f "$LOCK_FILE" ]] && { _log "already restricted (lock present)"; return; }
    command -v iptables &>/dev/null && _apply_iptables || _apply_nftables
    echo "$(date +%s)" > "$LOCK_FILE"
    _log "network restriction ACTIVE on $(hostname)"
}

_remove() {
    command -v iptables &>/dev/null && _remove_iptables || _remove_nftables
    rm -f "$LOCK_FILE"
    _log "network restriction LIFTED on $(hostname)"
}

case "$COMMAND" in
  add)    _apply  ;;
  delete) _remove ;;
  *)      _log "unknown command '$COMMAND' — defaulting to restrict"; _apply ;;
esac
exit 0
