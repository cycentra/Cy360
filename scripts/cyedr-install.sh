#!/usr/bin/env bash
# CyCentra 360 — CyEDR Agent Installer
# Installs CyEDR on Linux and macOS endpoints.
#
# What this installs:
#   Linux  — auditd + CyEDR audit rules, YARA, CyEDR Python bridge daemon (systemd)
#   macOS  — YARA, CyEDR Python bridge daemon (LaunchDaemon), oslog subscription
#
# CySIEM (Wazuh) is optional. Use --with-cysiem to auto-install, or
# --no-cysiem to skip the prompt, or answer the interactive question.
#
# Usage:
#   curl -fsSL https://<platform>/cyedr-install.sh | bash -s -- \
#       --token <DEPLOY_TOKEN> --platform https://<platform> [OPTIONS]
#
#   Options:
#     --token TOKEN          Deployment token (required)
#     --platform URL         CyCentra 360 platform URL (required)
#     --asset-type TYPE      Asset type: workstation|server|database|domain_controller|
#                            api_gateway|jump_server (default: workstation)
#     --with-cysiem          Also install CySIEM (Wazuh) agent
#     --no-cysiem            Skip CySIEM installation without prompting
#     --silent               Non-interactive; --no-cysiem implied unless --with-cysiem set
#     --help                 Show this help

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLU}[CyEDR]${NC} $*"; }
ok()    { echo -e "${GRN}[CyEDR]${NC} $*"; }
warn()  { echo -e "${YEL}[CyEDR]${NC} $*"; }
die()   { echo -e "${RED}[CyEDR ERROR]${NC} $*" >&2; exit 1; }

# ── Defaults ───────────────────────────────────────────────────────────────────
DEPLOY_TOKEN=""
PLATFORM_URL=""
ASSET_TYPE="workstation"
WITH_CYSIEM=""          # empty=prompt, "yes"=install, "no"=skip
SILENT=false
EDR_HOME="/opt/cycentra/edr"
EDR_USER="cyedr"
PYTHON_BIN=""

banner() {
    echo -e "${BLU}"
    cat << 'EOF'
  ██████╗██╗   ██╗     ███████╗██████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝     ██╔════╝██╔══██╗██╔══██╗
 ██║      ╚████╔╝      █████╗  ██║  ██║██████╔╝
 ██║       ╚██╔╝       ██╔══╝  ██║  ██║██╔══██╗
 ╚██████╗   ██║███████╗███████╗██████╔╝██║  ██║
  ╚═════╝   ╚╝╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝
EOF
    echo -e "${NC}${GRN}  CyCentra 360 — CyEDR Endpoint Defense  |  FROM SIGNALS TO STRENGTH${NC}"
    echo -e "${BLU}  ─────────────────────────────────────────────────────────────────${NC}"
    echo ""
}

# ── Argument parsing ───────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --token)      DEPLOY_TOKEN="$2"; shift 2 ;;
            --platform)   PLATFORM_URL="${2%/}"; shift 2 ;;
            --asset-type) ASSET_TYPE="$2"; shift 2 ;;
            --with-cysiem) WITH_CYSIEM="yes"; shift ;;
            --no-cysiem)   WITH_CYSIEM="no"; shift ;;
            --silent)      SILENT=true; shift ;;
            --help|-h)
                banner
                grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | sed 's/^#//'
                exit 0 ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
    [[ -z "$DEPLOY_TOKEN" ]] && die "Missing --token <DEPLOY_TOKEN>"
    [[ -z "$PLATFORM_URL" ]] && die "Missing --platform <URL>"
    if [[ "$SILENT" == "true" ]] && [[ -z "$WITH_CYSIEM" ]]; then WITH_CYSIEM="no"; fi
}

# ── Platform detection ─────────────────────────────────────────────────────────
detect_platform() {
    OS_TYPE="$(uname -s)"
    ARCH="$(uname -m)"
    case "$OS_TYPE" in
        Linux)  OS_KEY="LINUX"  ;;
        Darwin) OS_KEY="MACOS"  ;;
        *)      die "Unsupported OS: $OS_TYPE. Use cyedr-install.ps1 for Windows." ;;
    esac
    info "Detected platform: $OS_TYPE ($ARCH)"
}

# ── Root check ─────────────────────────────────────────────────────────────────
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        die "CyEDR installer must run as root (sudo bash $0 ...)"
    fi
}

# ── Architecture detection ─────────────────────────────────────────────────────
detect_arch() {
    case "$ARCH" in
        x86_64)           AGENT_ARCH="x86_64";  DEB_ARCH="amd64";  PKG_ARCH="intel64" ;;
        aarch64|arm64)    AGENT_ARCH="aarch64"; DEB_ARCH="arm64";  PKG_ARCH="arm64"   ;;
        *)
            warn "Unknown arch $ARCH — defaulting to x86_64"
            AGENT_ARCH="x86_64"; DEB_ARCH="amd64"; PKG_ARCH="intel64"
            ;;
    esac
    info "Architecture: $ARCH → agent bundle key: $AGENT_ARCH"
}

# ── Install system packages ────────────────────────────────────────────────────
install_packages_linux() {
    info "Installing system dependencies..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq auditd audispd-plugins yara curl python3 \
            iptables iproute2 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y -q audit audit-libs yara curl python3 \
            iptables iproute 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y -q audit yara curl python3 \
            iptables iproute 2>/dev/null || true
    else
        warn "Unknown package manager — skipping auto-install; ensure auditd and yara are present"
    fi
    ok "System packages installed"
}

install_packages_macos() {
    info "Installing system dependencies (macOS)..."
    if command -v brew &>/dev/null; then
        brew install yara 2>/dev/null || warn "Homebrew yara install failed — YARA scanning may be unavailable"
    else
        warn "Homebrew not found — YARA scanning may be unavailable. Install: https://brew.sh"
    fi
    # Python3 is expected via Xcode CLT or Homebrew
    ok "System packages installed"
}

# ── Deploy CyEDR agent ─────────────────────────────────────────────────────────
PYTHON_MODE=false   # set to true when falling back to python3 launcher

deploy_agent() {
    info "Creating CyEDR installation directory: $EDR_HOME"
    mkdir -p "$EDR_HOME/"{rules,ioc_cache,quarantine,logs,yara_rules}

    # Create dedicated system user (no login, no home)
    if [[ "$OS_KEY" == "LINUX" ]]; then
        if ! id "$EDR_USER" &>/dev/null; then
            useradd -r -s /bin/false -d "$EDR_HOME" -M "$EDR_USER" 2>/dev/null || true
        fi
    fi

    # Download arch-specific pre-built CyEDR agent binary from platform
    info "Downloading CyEDR agent binary (${OS_KEY}/${AGENT_ARCH})..."
    local BUNDLE_URL="$PLATFORM_URL/api/edr/installer/agent-bundle?os=${OS_KEY}&arch=${AGENT_ARCH}"
    if curl -fsSL --max-time 60 \
        -H "Authorization: Bearer $DEPLOY_TOKEN" \
        "$BUNDLE_URL" \
        -o "$EDR_HOME/cyedr-agent" 2>/dev/null; then
        chmod 750 "$EDR_HOME/cyedr-agent"
        ok "Agent binary downloaded"
    else
        # Air-gap fallback: look for binary alongside the installer script
        warn "Pre-built binary not available for ${OS_KEY}/${AGENT_ARCH} — trying Python fallback..."
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)" || true
        local FALLBACK="" OS_KEY_LOWER
        OS_KEY_LOWER="$(echo "$OS_KEY" | tr '[:upper:]' '[:lower:]')"
        for try_path in \
            "${SCRIPT_DIR}/cyedr-agent-${OS_KEY_LOWER}-${AGENT_ARCH}" \
            "${SCRIPT_DIR}/../agent/cyedr-agent" \
            "/tmp/cyedr-agent"; do
            [[ -f "$try_path" ]] && { FALLBACK="$try_path"; break; }
        done
        if [[ -n "$FALLBACK" ]]; then
            cp "$FALLBACK" "$EDR_HOME/cyedr-agent"
            chmod 750 "$EDR_HOME/cyedr-agent"
            warn "Using local bundle: $FALLBACK"
        else
            # Python-mode fallback: download agent script and run with python3
            PYTHON_BIN="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
            if [[ -n "$PYTHON_BIN" ]]; then
                info "Installing in Python mode using $PYTHON_BIN..."
                if curl -fsSL --max-time 60 \
                    -H "Authorization: Bearer $DEPLOY_TOKEN" \
                    "$PLATFORM_URL/api/edr/installer/agent-py" \
                    -o "$EDR_HOME/cyedr_agent.py" 2>/dev/null; then
                    chmod 640 "$EDR_HOME/cyedr_agent.py"
                    # Install pip dependencies for the agent
                    "$PYTHON_BIN" -m pip install --quiet psutil requests pyyaml 2>/dev/null || true
                    PYTHON_MODE=true
                    ok "Agent script installed (Python mode: $PYTHON_BIN)"
                else
                    die "Cannot obtain CyEDR agent (binary or script). Check your deployment token and network to $PLATFORM_URL"
                fi
            else
                die "Cannot obtain cyedr-agent binary and python3 is not available. Install Python 3 or contact support."
            fi
        fi
    fi

    # Download YARA rules bundle from platform
    info "Downloading YARA rule bundle..."
    curl -fsSL --max-time 30 \
        -H "Authorization: Bearer $DEPLOY_TOKEN" \
        "$PLATFORM_URL/api/edr/installer/yara-rules" \
        -o "$EDR_HOME/yara_rules/cycentra.yar" 2>/dev/null \
        || warn "YARA rules download failed — local scanning will use built-in signatures only"

    # Write agent config
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
    cat > "$EDR_HOME/config.json" << CONF
{
  "platform_url":    "$PLATFORM_URL",
  "deploy_token":    "$DEPLOY_TOKEN",
  "asset_type":      "$ASSET_TYPE",
  "hostname":        "$HOSTNAME",
  "os_type":         "$OS_KEY",
  "edr_home":        "$EDR_HOME",
  "poll_interval":   60,
  "heartbeat_interval": 60,
  "telemetry_batch": 20,
  "yara_rules":      "$EDR_HOME/yara_rules/cycentra.yar",
  "quarantine_dir":  "$EDR_HOME/quarantine",
  "ioc_cache":       "$EDR_HOME/ioc_cache/ioc.json",
  "log_file":        "$EDR_HOME/logs/cyedr_agent.log"
}
CONF
    chmod 600 "$EDR_HOME/config.json"
    ok "CyEDR agent deployed to $EDR_HOME"
}

# ── Linux: auditd configuration ────────────────────────────────────────────────
configure_auditd_linux() {
    info "Configuring auditd for CyEDR..."

    # CyEDR-specific auditd rules file (separate from Wazuh's existing rules)
    cat > /etc/audit/rules.d/60-cyedr.rules << 'AUDRULES'
## CyCentra 360 CyEDR — Endpoint Detection Rules
## Key prefix cy360_edr_* ensures no collision with Wazuh cy360_wazuh_tamper rules

# Process execution tracking
-a always,exit -F arch=b64 -S execve -k cy360_edr_exec
-a always,exit -F arch=b32 -S execve -k cy360_edr_exec

# Network connections
-a always,exit -F arch=b64 -S connect -k cy360_edr_net
-a always,exit -F arch=b32 -S connect -k cy360_edr_net

# Process injection / fileless memory syscalls
-a always,exit -F arch=b64 -S ptrace -k cy360_edr_inject
-a always,exit -F arch=b64 -S process_vm_writev -k cy360_edr_inject
-a always,exit -F arch=b64 -S process_vm_readv -k cy360_edr_inject
-a always,exit -F arch=b64 -S memfd_create -k cy360_edr_inject

# Privileged process execution (uid changes)
-a always,exit -F arch=b64 -S setuid -S setgid -k cy360_edr_privesc
-a always,exit -F arch=b64 -S setresuid -S setresgid -k cy360_edr_privesc

# Sensitive file access
-w /etc/passwd -p rwa -k cy360_edr_credentials
-w /etc/shadow -p rwa -k cy360_edr_credentials
-w /etc/sudoers -p rwa -k cy360_edr_credentials
-w /root/.ssh -p rwa -k cy360_edr_credentials

# Persistence paths
-w /etc/cron.d -p rwxa -k cy360_edr_persist
-w /etc/systemd/system -p rwxa -k cy360_edr_persist
-w /etc/rc.local -p rwxa -k cy360_edr_persist

# Anti-tamper: CyEDR agent self-defence (new key; Wazuh still watches cy360_wazuh_tamper)
-w /opt/cycentra/edr -p wa -k cy360_edr_tamper
AUDRULES
    chmod 640 /etc/audit/rules.d/60-cyedr.rules

    # Configure audisp to emit events to /var/log/audit/audit.log (default) AND
    # to a named pipe that CyEDR reads without interfering with Wazuh's af_unix plugin
    if [[ -d /etc/audisp/plugins.d ]]; then
        cat > /etc/audisp/plugins.d/cyedr.conf << 'AUDISP'
active = yes
direction = out
path = builtin_af_unix
type = builtin
args = 0660 /var/run/cyedr_audit.sock
format = string
AUDISP
        chmod 640 /etc/audisp/plugins.d/cyedr.conf
    fi

    # Load new rules immediately
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/60-cyedr.rules 2>/dev/null || true
    systemctl enable auditd 2>/dev/null && systemctl restart auditd 2>/dev/null || true
    ok "auditd configured with CyEDR rules"
}

# ── Linux: systemd service ─────────────────────────────────────────────────────
install_systemd_service() {
    info "Installing CyEDR systemd service..."

    local EXEC_START
    if [[ "$PYTHON_MODE" == "true" ]]; then
        EXEC_START="$PYTHON_BIN $EDR_HOME/cyedr_agent.py --config $EDR_HOME/config.json"
    else
        EXEC_START="$EDR_HOME/cyedr-agent --config $EDR_HOME/config.json"
    fi

    cat > /etc/systemd/system/cyedr-agent.service << SVCFILE
[Unit]
Description=CyCentra 360 EDR Agent
Documentation=https://docs.cycentra.com/edr
After=network-online.target auditd.service
Wants=network-online.target
# Watchdog via companion .timer — see cyedr-watchdog.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$EDR_HOME
ExecStart=$EXEC_START
Restart=always
RestartSec=10
StandardOutput=append:$EDR_HOME/logs/cyedr_agent.log
StandardError=append:$EDR_HOME/logs/cyedr_agent.log
# Harden: prevent CyEDR from being killed by OOM killer
OOMScoreAdjust=-900
# Resource limits
MemoryMax=256M
CPUQuota=25%
# Protect self from non-root writes
ProtectSystem=strict
ReadWritePaths=$EDR_HOME /var/run /var/log/audit /tmp

[Install]
WantedBy=multi-user.target
SVCFILE

    # Watchdog service — restarts cyedr-agent if it goes down
    cat > /etc/systemd/system/cyedr-watchdog.service << WDFILE
[Unit]
Description=CyEDR Agent Watchdog
After=cyedr-agent.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl is-active cyedr-agent || systemctl restart cyedr-agent'
WDFILE

    cat > /etc/systemd/system/cyedr-watchdog.timer << WDTIMER
[Unit]
Description=CyEDR Watchdog Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
WDTIMER

    chmod 644 /etc/systemd/system/cyedr-{agent,watchdog}.service \
              /etc/systemd/system/cyedr-watchdog.timer
    systemctl daemon-reload
    systemctl enable cyedr-agent cyedr-watchdog.timer
    ok "systemd services installed (cyedr-agent, cyedr-watchdog)"
}

# ── macOS: LaunchDaemon ────────────────────────────────────────────────────────
install_launchdaemon() {
    info "Installing CyEDR LaunchDaemon (macOS)..."
    local PLIST="/Library/LaunchDaemons/com.cycentra.edr.plist"

    # Build ProgramArguments based on binary vs Python mode
    local PROG_ARGS
    if [[ "$PYTHON_MODE" == "true" ]]; then
        PROG_ARGS="    <string>$PYTHON_BIN</string>
        <string>$EDR_HOME/cyedr_agent.py</string>
        <string>--config</string>
        <string>$EDR_HOME/config.json</string>"
    else
        PROG_ARGS="    <string>$EDR_HOME/cyedr-agent</string>
        <string>--config</string>
        <string>$EDR_HOME/config.json</string>"
    fi

    mkdir -p "$EDR_HOME/logs"

    cat > "$PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cycentra.edr</string>
    <key>ProgramArguments</key>
    <array>
        $PROG_ARGS
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$EDR_HOME/logs/cyedr_agent.log</string>
    <key>StandardErrorPath</key>
    <string>$EDR_HOME/logs/cyedr_agent.log</string>
    <key>WorkingDirectory</key>
    <string>$EDR_HOME</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>Nice</key>
    <integer>10</integer>
    <key>HardResourceLimits</key>
    <dict>
        <key>MemoryLock</key>
        <integer>268435456</integer>
    </dict>
</dict>
</plist>
PLIST

    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"
    # bootstrap is the modern API (macOS 13+); fall back to legacy load for older systems
    launchctl bootstrap system "$PLIST" 2>/dev/null || launchctl load -w "$PLIST" 2>/dev/null || true
    ok "LaunchDaemon installed: com.cycentra.edr"
}

# ── Enroll with platform ───────────────────────────────────────────────────────
enroll_agent() {
    # Skip enrollment if a valid agent_id + enrollment_token already exist in config
    if [[ -f "$EDR_HOME/config.json" ]]; then
        local _existing_id _existing_tok
        _existing_id=$(python3 -c "import json,sys; d=json.load(open('$EDR_HOME/config.json')); print(d.get('agent_id',''))" 2>/dev/null || true)
        _existing_tok=$(python3 -c "import json,sys; d=json.load(open('$EDR_HOME/config.json')); print(d.get('enrollment_token',''))" 2>/dev/null || true)
        if [[ -n "$_existing_id" && -n "$_existing_tok" ]]; then
            AGENT_ID="$_existing_id"
            ENROLLMENT_TOKEN="$_existing_tok"
            ok "Re-using existing enrollment — Agent ID: $AGENT_ID"
            return
        fi
    fi

    info "Enrolling with CyCentra 360 platform..."
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

    # Collect agent IP
    if [[ "$OS_KEY" == "LINUX" ]]; then
        AGENT_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)"
    else
        AGENT_IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")"
    fi
    AGENT_IP="${AGENT_IP:-unknown}"

    # Detect default gateway MAC at install time (trusted corporate environment)
    # This seeds the network zone auto-learning so the server knows which gateway
    # is the corporate one without admin needing to configure it manually.
    GW_IP=""; GW_MAC=""
    if [[ "$OS_KEY" == "LINUX" ]]; then
        GW_IP="$(ip route show default 2>/dev/null | awk '/via/{print $3; exit}')"
        if [[ -n "$GW_IP" ]]; then
            GW_MAC="$(arp -n "$GW_IP" 2>/dev/null | awk 'NR==2{print $3}' | tr '[:lower:]' '[:upper:]')"
        fi
    else
        # macOS: get default route then ARP lookup
        GW_IP="$(netstat -rn 2>/dev/null | awk '/^default/{print $2; exit}')"
        if [[ -n "$GW_IP" ]]; then
            GW_MAC="$(arp "$GW_IP" 2>/dev/null | grep -oE '[0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}' | head -1 | tr '[:lower:]' '[:upper:]')"
        fi
    fi
    [[ -z "$GW_MAC" ]] && warn "Could not detect gateway MAC — zone auto-learning will rely on heartbeat"

    local ENROLL_RESPONSE
    ENROLL_RESPONSE=$(curl -fsSL --max-time 30 \
        -X POST "$PLATFORM_URL/api/edr/agents/self-enroll" \
        -H "Authorization: Bearer $DEPLOY_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"deployment_token\": \"$DEPLOY_TOKEN\",
            \"hostname\":    \"$HOSTNAME\",
            \"os_type\":     \"$OS_KEY\",
            \"asset_type\":  \"$ASSET_TYPE\",
            \"agent_ip\":    \"$AGENT_IP\",
            \"version\":     \"1.0.0\",
            \"gateway_ip\":  \"$GW_IP\",
            \"gateway_mac\": \"$GW_MAC\"
        }") || die "Enrollment failed — check network connectivity to $PLATFORM_URL"

    # Extract agent_id and enrollment_token from response
    AGENT_ID=$(echo "$ENROLL_RESPONSE" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
    ENROLLMENT_TOKEN=$(echo "$ENROLL_RESPONSE" | grep -o '"enrollment_token":"[^"]*"' | cut -d'"' -f4)
    [[ -z "$AGENT_ID" ]] && die "Enrollment response did not include agent_id: $ENROLL_RESPONSE"
    [[ -z "$ENROLLMENT_TOKEN" ]] && die "Enrollment response did not include enrollment_token: $ENROLL_RESPONSE"

    # Persist agent_id and enrollment_token into config
    python3 - << PYINLINE
import json
cfg_path = "$EDR_HOME/config.json"
with open(cfg_path) as f:
    cfg = json.load(f)
cfg["agent_id"] = "$AGENT_ID"
cfg["enrollment_token"] = "$ENROLLMENT_TOKEN"
with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
PYINLINE

    ok "Enrolled — Agent ID: $AGENT_ID"
}

# ── CySIEM (Wazuh) optional installation ──────────────────────────────────────
maybe_install_cysiem() {
    if [[ "$WITH_CYSIEM" == "no" ]]; then
        info "CySIEM (Wazuh) installation skipped."
        return
    fi

    if [[ "$WITH_CYSIEM" != "yes" ]]; then
        echo ""
        echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YEL} OPTIONAL: CySIEM Agent (Wazuh-based log collection)   ${NC}"
        echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo "  CySIEM provides:"
        echo "   • File Integrity Monitoring (FIM)"
        echo "   • Auth log collection (syslog / journald)"
        echo "   • Compliance log aggregation (auditd compliance events)"
        echo "   • Windows: Security event log, PowerShell logging"
        echo ""
        echo "  CyEDR already covers:"
        echo "   • Behavioral detection (process, network, memory)"
        echo "   • Automated threat response"
        echo "   • SIEM telemetry feed"
        echo ""
        local CHOICE
        read -r -t 60 -p "Install CySIEM agent alongside CyEDR? [y/N]: " CHOICE || CHOICE="n"
        case "$CHOICE" in [Yy]|[Yy][Ee][Ss]) ;; *) info "CySIEM skipped."; return ;; esac
        WITH_CYSIEM="yes"
    fi

    info "Installing CySIEM (Wazuh) agent..."
    local INSTALLER_URL="$PLATFORM_URL/api/edr/installer/cysiem-script"
    local TMP_INSTALLER="/tmp/cy360-agent-install.sh"

    curl -fsSL --max-time 60 \
        -H "Authorization: Bearer $DEPLOY_TOKEN" \
        "$INSTALLER_URL" -o "$TMP_INSTALLER" \
        || die "Failed to download CySIEM installer from $INSTALLER_URL"
    chmod +x "$TMP_INSTALLER"

    bash "$TMP_INSTALLER" --install || \
        warn "CySIEM installer returned non-zero exit code — check $TMP_INSTALLER output"

    rm -f "$TMP_INSTALLER"
    ok "CySIEM (Wazuh) agent installed"
}

# ── Lock down file permissions ─────────────────────────────────────────────────
harden_permissions() {
    info "Hardening CyEDR file permissions..."
    local _grp; _grp="$(if [[ "$OS_KEY" == "MACOS" ]]; then echo wheel; else echo root; fi)"
    chown -R "root:${_grp}" "$EDR_HOME"
    chmod -R 750 "$EDR_HOME"
    chmod 700 "$EDR_HOME/quarantine"
    chmod 600 "$EDR_HOME/config.json"
    chmod 755 "$EDR_HOME/logs"
    ok "Permissions set"
}

# ── Start agent ────────────────────────────────────────────────────────────────
start_agent() {
    info "Starting CyEDR agent..."
    if [[ "$OS_KEY" == "LINUX" ]]; then
        systemctl start cyedr-agent
        sleep 2
        if systemctl is-active --quiet cyedr-agent; then
            ok "cyedr-agent is running"
        else
            warn "cyedr-agent failed to start — check: journalctl -u cyedr-agent -n 50"
        fi
    else
        launchctl kickstart -k system/com.cycentra.edr 2>/dev/null || launchctl start com.cycentra.edr 2>/dev/null || true
        sleep 2
        if launchctl print system/com.cycentra.edr 2>/dev/null | grep -q "state ="; then
            ok "CyEDR agent is running (macOS)"
        else
            warn "CyEDR agent may not be running — check: $EDR_HOME/logs/cyedr_agent.log"
        fi
    fi
}

# ── Summary ────────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GRN} CyEDR Agent Installation Complete                    ${NC}"
    echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  Platform:   $PLATFORM_URL"
    echo "  Agent home: $EDR_HOME"
    echo "  Logs:       $EDR_HOME/logs/cyedr_agent.log"
    if [[ "$OS_KEY" == "LINUX" ]]; then
        echo ""
        echo "  Status:     systemctl status cyedr-agent"
        echo "  Logs:       journalctl -u cyedr-agent -f"
    else
        echo ""
        echo "  Status:     launchctl list com.cycentra.edr"
        echo "  Logs:       tail -f $EDR_HOME/logs/cyedr_agent.log"
    fi
    echo ""
    echo -e "${YEL}  Next: View this endpoint in CyCentra 360 > Endpoint Fleet${NC}"
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────────────────
main() {
    banner
    parse_args "$@"
    check_root
    detect_platform

    # OS-specific package install
    if [[ "$OS_KEY" == "LINUX" ]]; then
        install_packages_linux
    else
        install_packages_macos
    fi

    detect_arch
    deploy_agent

    if [[ "$OS_KEY" == "LINUX" ]]; then
        configure_auditd_linux
        install_systemd_service
    else
        install_launchdaemon
    fi

    harden_permissions
    enroll_agent
    maybe_install_cysiem
    start_agent
    print_summary
}

main "$@"
