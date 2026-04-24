#!/usr/bin/env bash
# CyCentra360 — Wazuh Agent Configuration Deployer
# Deploys or updates /var/ossec/etc/shared/default/agent.conf
#
# Usage:
#   sudo bash scripts/deploy_agent_config.sh [--conf /path/to/agent.conf] [--reload]
#
# Options:
#   --conf <path>   Path to agent.conf to deploy (default: CYSIEM-Config/agent_config/agent.conf
#                   relative to this script's repo root, or the installed copy at
#                   /tmp/cycentra-config/agent_config/agent.conf)
#   --reload        Reload wazuh-manager after deployment (default: prompted interactively)
#
# What it does:
#   1. Validates the source agent.conf exists
#   2. Backs up the existing /var/ossec/etc/shared/default/agent.conf
#   3. Copies the new agent.conf with correct ownership (root:wazuh, 660)
#   4. Optionally reloads wazuh-manager

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}  ▸ ${NC}$*"; }
success() { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()    { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
error()   { echo -e "${RED}  ✗ ${NC}$*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash scripts/deploy_agent_config.sh"
[[ -d "/var/ossec" ]] || error "Wazuh is not installed (/var/ossec not found)"

# ── Parse args ────────────────────────────────────────────────────────────────
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/.." && pwd)"

CONF_SRC=""
DO_RELOAD=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --conf)    CONF_SRC="$2"; shift 2 ;;
        --conf=*)  CONF_SRC="${1#*=}"; shift ;;
        --reload)  DO_RELOAD="yes"; shift ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

# Resolve source file: explicit arg → repo CYSIEM-Config → installed temp copy
if [[ -z "$CONF_SRC" ]]; then
    if [[ -f "$_REPO_ROOT/CYSIEM-Config/agent_config/agent.conf" ]]; then
        CONF_SRC="$_REPO_ROOT/CYSIEM-Config/agent_config/agent.conf"
    elif [[ -f "/tmp/cycentra-config/agent_config/agent.conf" ]]; then
        CONF_SRC="/tmp/cycentra-config/agent_config/agent.conf"
    else
        error "agent.conf not found. Specify with --conf /path/to/agent.conf"
    fi
fi

[[ -f "$CONF_SRC" ]] || error "Source file not found: $CONF_SRC"

DEST_DIR="/var/ossec/etc/shared/default"
DEST="$DEST_DIR/agent.conf"

echo -e "\n${BOLD}  CyCentra 360 — Agent Config Deployer${NC}\n"
info "Source : $CONF_SRC"
info "Target : $DEST"
echo ""

# ── Backup existing config ────────────────────────────────────────────────────
if [[ -f "$DEST" ]]; then
    BACKUP="${DEST}.backup-$(date +%Y%m%d-%H%M%S)"
    cp "$DEST" "$BACKUP"
    success "Existing agent.conf backed up → $BACKUP"
fi

# ── Deploy ────────────────────────────────────────────────────────────────────
mkdir -p "$DEST_DIR"
cp "$CONF_SRC" "$DEST"
chmod 660 "$DEST"
chown root:wazuh "$DEST"
success "agent.conf deployed to $DEST"

# ── Reload prompt / flag ──────────────────────────────────────────────────────
if [[ -z "$DO_RELOAD" && -t 0 ]]; then
    echo -ne "  ${BOLD}Reload wazuh-manager now?${NC} [Y/n]: "
    read -r _ans
    [[ -z "$_ans" || "$_ans" =~ ^[Yy] ]] && DO_RELOAD="yes"
fi

if [[ "$DO_RELOAD" == "yes" ]]; then
    if /var/ossec/bin/wazuh-analysisd -t 2>/dev/null; then
        systemctl reload wazuh-manager 2>/dev/null \
            || systemctl restart wazuh-manager 2>/dev/null
        success "wazuh-manager reloaded — agents will receive updated config on next check-in"
    else
        warn "Wazuh config validation failed — fix errors before reloading"
        warn "Check: /var/ossec/bin/wazuh-analysisd -t"
        exit 1
    fi
else
    info "Reload skipped. Run when ready: systemctl reload wazuh-manager"
fi

echo ""
success "Done. Agents will pull the new agent.conf on their next remoted check-in (up to ~5 min)."
echo ""
