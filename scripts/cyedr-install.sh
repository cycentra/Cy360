#!/usr/bin/env bash
# CyCentra 360 — CyEDR Agent Installer
# Installs CyEDR on Linux and macOS endpoints.
#
# What this installs:
#   Linux  — auditd + CyEDR audit rules, YARA, CyEDR Python bridge daemon (systemd)
#   macOS  — YARA, CyEDR Python bridge daemon (LaunchDaemon), oslog subscription
#
# A system-tray/menu-bar icon (cyedr-tray) is installed by default on
# workstation asset types — shows CyEDR is running, offers an on-demand scan,
# and a password-gated Stop/Exit (admin password set in Cy360 -> EDR Policies
# -> Tamper Protection). Use --no-tray to skip it, or --with-tray to force it
# on non-workstation asset types.
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
#     --with-tray            Install the system-tray app even on non-workstation asset types
#     --no-tray              Skip installing the system-tray app
#     --silent               Non-interactive
#     --help                 Show this help

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[0;34m'; DIM='\033[2m'; NC='\033[0m'
info()  { echo -e "${BLU}[CyEDR]${NC} $*"; }
ok()    { echo -e "${GRN}[CyEDR]${NC} $*"; }
warn()  { echo -e "${YEL}[CyEDR]${NC} $*"; }
die()   { echo -e "${RED}[CyEDR ERROR]${NC} $*" >&2; exit 1; }

# Safety net: any command that fails without an explicit `|| true`/`|| warn`
# guard would otherwise kill the script under `set -e` with zero CyEDR-branded
# output (e.g. apt-get update failing because unattended-upgrades holds the
# dpkg lock on a freshly booted host) — that reads as "the installer just
# silently stopped". This guarantees a visible error with line + command.
trap 'echo -e "${RED}[CyEDR ERROR]${NC} Installer aborted at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR

# ── Defaults ───────────────────────────────────────────────────────────────────
DEPLOY_TOKEN=""
PLATFORM_URL=""
ASSET_TYPE="workstation"
WITH_TRAY=""            # empty=default (workstation only), "yes"=force install, "no"=skip
SILENT=false
EDR_HOME="/opt/cycentra/edr"
EDR_USER="cyedr"
PYTHON_BIN=""
TRAY_HOME="/opt/cycentra/edr-tray"   # separate from EDR_HOME (root-only 750) — the tray
                                      # binary must be world-executable for any local user

# Kept in sync with agent/cyedr_agent.py's AGENT_VERSION by git-push.sh on every
# release (same mechanism that already syncs cycentra-setup.sh's header line and
# backend/pyproject.toml) — never bump this by hand.
CYEDR_AGENT_VERSION="1.0.238"

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
    # CyEDR Agent Build != platform release version by design — the agent
    # script's own version only bumps when agent/tray code changes, not on
    # every platform release (syncing the two caused a self-update restart
    # loop in the past, see AGENT_VERSION comment in agent/cyedr_agent.py).
    # Platform version is echoed separately in print_summary() once
    # PLATFORM_URL is known, so the two numbers are never shown looking like
    # a single "version" that should match.
    echo -e "${DIM}  CyEDR Agent Build: v${CYEDR_AGENT_VERSION}${NC}"
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
            --with-tray)   WITH_TRAY="yes"; shift ;;
            --no-tray)     WITH_TRAY="no"; shift ;;
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
    # `[[ cond ]] && die ...` as the LAST statement in a function is a classic
    # `set -e` trap: when cond is false (the normal, valid-args case), the `&&`
    # list's exit status is 1, that becomes parse_args's own return status, and
    # since main() calls `parse_args "$@"` as a bare statement, `set -e` treats
    # the whole script as having failed a command and aborts immediately —
    # silently, because die()/the ERR trap never actually ran. This is exactly
    # what made the installer print the banner and then exit with no message.
    return 0
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
        # Debian / Ubuntu / Raspberry Pi OS / Kali (all arches)
        # Non-fatal: a fresh boot's unattended-upgrades often holds the dpkg
        # lock for the first few minutes, which would otherwise abort the
        # entire install here under set -e before the agent is even deployed.
        apt-get update -qq 2>/dev/null || warn "apt-get update failed (dpkg lock or unreachable mirror?) — continuing with existing package lists"
        apt-get install -y -qq auditd audispd-plugins yara curl \
            python3 python3-pip python3-venv \
            python3-requests python3-psutil python3-yaml \
            iptables iproute2 nmap snmp 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        # RHEL 8/9, CentOS Stream 8/9, Fedora, Rocky Linux, AlmaLinux, Amazon Linux 2023
        # python3-venv is NOT a separate package on RPM distros — venv is built into python3
        dnf install -y -q audit yara curl \
            python3 python3-pip \
            python3-requests python3-psutil python3-pyyaml \
            iptables iproute nmap net-snmp-utils 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        # RHEL 7, CentOS 7, Amazon Linux 2 (legacy)
        yum install -y -q audit audit-libs yara curl \
            python3 python3-pip \
            python3-requests python3-psutil python3-pyyaml \
            iptables iproute nmap net-snmp-utils 2>/dev/null || true
    elif command -v apk &>/dev/null; then
        # Alpine Linux (all arches) — package names differ from Debian/RPM
        apk add --quiet python3 py3-pip \
            py3-requests py3-psutil py3-yaml \
            nmap net-snmp-tools 2>/dev/null || true
        # Note: auditd and yara are not in Alpine standard repos
    else
        warn "Unknown package manager — skipping auto-install; ensure auditd, yara, nmap, and snmpwalk are present"
    fi
    ok "System packages installed"
}

install_packages_macos() {
    info "Installing system dependencies (macOS)..."
    # When run as `sudo bash`, root's PATH excludes Homebrew directories.
    # Probe known Homebrew prefix locations explicitly before falling back to PATH.
    local BREW_BIN=""
    for _try in \
        /opt/homebrew/bin/brew \
        /usr/local/bin/brew \
        "$(command -v brew 2>/dev/null)"; do
        [[ -x "$_try" ]] && { BREW_BIN="$_try"; break; }
    done

    if [[ -n "$BREW_BIN" ]]; then
        # Homebrew refuses to run as root. When invoked via `sudo bash`, delegate
        # the install back to the original user via SUDO_USER.
        local _BREW_USER="${SUDO_USER:-}"
        local _brew_install
        if [[ -n "$_BREW_USER" && "$_BREW_USER" != "root" ]]; then
            _brew_install="HOMEBREW_NO_AUTO_UPDATE=1 sudo -u $_BREW_USER $BREW_BIN install"
        else
            _brew_install="HOMEBREW_NO_AUTO_UPDATE=1 $BREW_BIN install"
        fi
        eval "$_brew_install yara" 2>/dev/null \
            || warn "Homebrew yara install failed — YARA scanning may be unavailable"
        eval "$_brew_install nmap" 2>/dev/null \
            || warn "Homebrew nmap install failed — Network Probe subnet scan may be unavailable"
        eval "$_brew_install net-snmp" 2>/dev/null \
            || warn "Homebrew net-snmp install failed — SNMP probe scan may be unavailable"
    else
        warn "Homebrew not found — YARA, nmap, and snmpwalk may be unavailable. Install: https://brew.sh"
    fi
    # Python3 is expected via Xcode CLT or Homebrew
    ok "System packages installed"
}

# Resolve the absolute path to the yara binary after package install.
# LaunchDaemons/systemd services run with a stripped PATH that excludes
# Homebrew and /usr/local/bin, so we must embed the absolute path in config.json.
resolve_yara_binary() {
    local bin
    for bin in \
        "$(command -v yara 2>/dev/null)" \
        /opt/homebrew/bin/yara \
        /usr/local/bin/yara \
        /usr/bin/yara \
        /bin/yara; do
        [[ -x "$bin" ]] && { echo "$bin"; return 0; }
    done
    echo "yara"   # fallback: keep as name, agent will try absolute paths at runtime
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
                    # Install pip dependencies into root's Python path so they are
                    # accessible when the agent runs as root under LaunchDaemon/systemd.
                    # sudo preserves the invoking user's HOME, so pip would normally
                    # install into the user's ~/Library — root can't see those packages.
                    # We force HOME to root's real home directory to fix this.
                    local _root_home
                    _root_home="$(eval echo ~root 2>/dev/null)" || _root_home="/root"
                    [[ -z "$_root_home" || "$_root_home" == "~root" ]] && _root_home="/root"
                    info "Installing Python dependencies for CyEDR agent..."

                    # Fast-path: system packages already installed by install_packages_linux()
                    # (python3-requests / python3-psutil / python3-yaml on apt distros,
                    #  python3-requests / python3-psutil / python3-pyyaml on dnf/yum distros)
                    if env HOME="$_root_home" "$PYTHON_BIN" -c "import requests, psutil, yaml" 2>/dev/null; then
                        ok "Python dependencies already available (system packages)"
                    else
                        # 1. Retry with system package manager (handles partial installs)
                        if command -v apt-get &>/dev/null; then
                            apt-get install -y -qq python3-requests python3-psutil python3-yaml 2>/dev/null || true
                        elif command -v dnf &>/dev/null; then
                            dnf install -y -q python3-requests python3-psutil python3-pyyaml 2>/dev/null || true
                        elif command -v yum &>/dev/null; then
                            yum install -y -q python3-requests python3-psutil python3-pyyaml 2>/dev/null || true
                        elif command -v apk &>/dev/null; then
                            apk add --quiet py3-requests py3-psutil py3-yaml 2>/dev/null || true
                        fi

                        # 2. pip with --break-system-packages (works on Debian/Ubuntu with pip>=23)
                        if ! env HOME="$_root_home" "$PYTHON_BIN" -c "import requests, psutil, yaml" 2>/dev/null; then
                            if "$PYTHON_BIN" -m pip install --help 2>&1 | grep -q 'break-system-packages'; then
                                env HOME="$_root_home" "$PYTHON_BIN" -m pip install --quiet \
                                    --break-system-packages psutil requests pyyaml 2>/dev/null || true
                            else
                                env HOME="$_root_home" "$PYTHON_BIN" -m pip install --quiet \
                                    psutil requests pyyaml 2>/dev/null || true
                            fi
                        fi

                        # 3. venv fallback — always works even when system pip is locked down
                        if ! env HOME="$_root_home" "$PYTHON_BIN" -c "import requests, psutil, yaml" 2>/dev/null; then
                            info "Trying venv fallback for Python dependencies..."
                            if "$PYTHON_BIN" -m venv "$EDR_HOME/venv" 2>/dev/null; then
                                "$EDR_HOME/venv/bin/pip" install --quiet psutil requests pyyaml 2>/dev/null || true
                                # Point PYTHON_BIN at the venv interpreter for the rest of setup
                                PYTHON_BIN="$EDR_HOME/venv/bin/python3"
                            fi
                        fi

                        # Final check
                        if ! env HOME="$_root_home" "$PYTHON_BIN" -c "import requests, psutil, yaml" 2>/dev/null; then
                            if command -v apt-get &>/dev/null; then
                                die "Python dependencies could not be installed. Try: apt-get install python3-requests python3-psutil python3-yaml"
                            elif command -v dnf &>/dev/null; then
                                die "Python dependencies could not be installed. Try: dnf install python3-requests python3-psutil python3-pyyaml"
                            elif command -v yum &>/dev/null; then
                                die "Python dependencies could not be installed. Try: yum install python3-requests python3-psutil python3-pyyaml"
                            elif command -v apk &>/dev/null; then
                                die "Python dependencies could not be installed. Try: apk add py3-requests py3-psutil py3-yaml"
                            else
                                die "Python dependencies could not be installed. Run: $PYTHON_BIN -m pip install requests psutil pyyaml"
                            fi
                        fi
                        ok "Python dependencies installed"
                    fi

                    # watchdog is optional (File Integrity Monitoring only) — best-effort,
                    # never blocks agent setup. No apt/dnf/yum system package is reliably
                    # available across distros for it, so pip is the only path attempted.
                    if ! env HOME="$_root_home" "$PYTHON_BIN" -c "import watchdog" 2>/dev/null; then
                        if "$PYTHON_BIN" -m pip install --help 2>&1 | grep -q 'break-system-packages'; then
                            env HOME="$_root_home" "$PYTHON_BIN" -m pip install --quiet \
                                --break-system-packages watchdog 2>/dev/null || true
                        else
                            env HOME="$_root_home" "$PYTHON_BIN" -m pip install --quiet watchdog 2>/dev/null || true
                        fi
                    fi
                    if env HOME="$_root_home" "$PYTHON_BIN" -c "import watchdog" 2>/dev/null; then
                        ok "watchdog installed (File Integrity Monitoring enabled)"
                    else
                        warn "watchdog could not be installed — File Integrity Monitoring will be disabled on this host"
                    fi

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
    YARA_BIN="$(resolve_yara_binary)"
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
  "yara_binary":     "$YARA_BIN",
  "yara_rules":      "$EDR_HOME/yara_rules/cycentra.yar",
  "quarantine_dir":  "$EDR_HOME/quarantine",
  "ioc_cache":       "$EDR_HOME/ioc_cache/ioc.json",
  "log_file":        "$EDR_HOME/logs/cyedr_agent.log"
}
CONF

    # agent_id/enrollment_token are intentionally left unset here — enroll_agent()
    # always re-enrolls fresh below and writes the current, valid token. Carrying
    # a stale token forward across reinstalls previously left agents permanently
    # broken with no way to recover short of manually editing config.json.
    chmod 600 "$EDR_HOME/config.json"
    ok "CyEDR agent deployed to $EDR_HOME"
}

# ── Decide whether to install the system-tray app ──────────────────────────────
want_tray() {
    [[ "$WITH_TRAY" == "no" ]] && return 1
    [[ "$WITH_TRAY" == "yes" ]] && return 0
    [[ "$ASSET_TYPE" == "workstation" ]] && return 0
    return 1   # default: skip on headless server/database/DC/etc. asset types
}

# ── Deploy CyEDR system-tray binary ─────────────────────────────────────────────
# Separate download, separate directory from EDR_HOME on purpose: EDR_HOME is
# locked to root-only traversal (750) by harden_permissions() below because
# config.json inside it holds the enrollment token — the tray binary and its
# IPC token/socket must be reachable by any locally logged-in user, so they
# live in their own world-traversable directory instead of loosening EDR_HOME.
deploy_tray() {
    info "Downloading CyEDR system-tray binary (${OS_KEY}/${AGENT_ARCH})..."
    mkdir -p "$TRAY_HOME"
    local TRAY_ARCH="$AGENT_ARCH"
    [[ "$OS_KEY" == "MACOS" ]] && TRAY_ARCH="$PKG_ARCH"
    local TRAY_URL="$PLATFORM_URL/api/edr/installer/tray-bundle?os=${OS_KEY}&arch=${TRAY_ARCH}"
    if curl -fsSL --max-time 60 \
        -H "Authorization: Bearer $DEPLOY_TOKEN" \
        "$TRAY_URL" \
        -o "$TRAY_HOME/cyedr-tray" 2>/dev/null; then
        chown root:root "$TRAY_HOME/cyedr-tray" 2>/dev/null || true
        chmod 755 "$TRAY_HOME/cyedr-tray"
        chmod 755 "$TRAY_HOME"
        ok "System-tray binary installed to $TRAY_HOME"
        return 0
    fi
    warn "Tray binary not available for ${OS_KEY}/${TRAY_ARCH} — skipping tray install " \
         "(run agent-packages/build-edr-packages.sh on the platform server, or pass --no-tray to silence this)"
    return 1
}

# ── Linux: XDG autostart for the tray (any desktop session, any user) ──────────
install_tray_autostart_linux() {
    mkdir -p /etc/xdg/autostart
    cat > /etc/xdg/autostart/cyedr-tray.desktop << DESKTOP
[Desktop Entry]
Type=Application
Name=CyEDR
Comment=CyCentra 360 endpoint protection status
Exec=$TRAY_HOME/cyedr-tray
Icon=security-high
Terminal=false
X-GNOME-Autostart-enabled=true
NoDisplay=false
DESKTOP
    chmod 644 /etc/xdg/autostart/cyedr-tray.desktop
    ok "Tray autostart registered (XDG autostart — starts for any user's desktop session)"
}

# ── macOS: system-wide LaunchAgent for the tray (any GUI login session) ────────
install_tray_launchagent_macos() {
    local PLIST="/Library/LaunchAgents/com.cycentra.edrtray.plist"
    cat > "$PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cycentra.edrtray</string>
    <key>ProgramArguments</key>
    <array>
        <string>$TRAY_HOME/cyedr-tray</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST
    chown root:wheel "$PLIST"
    chmod 644 "$PLIST"
    # /Library/LaunchAgents plists auto-load for every user at their next GUI
    # login with no further action. Best-effort: also load it immediately for
    # whichever user is in the current console session, if any.
    local console_user
    console_user="$(stat -f%Su /dev/console 2>/dev/null || true)"
    if [[ -n "$console_user" && "$console_user" != "root" ]]; then
        local console_uid
        console_uid="$(id -u "$console_user" 2>/dev/null || true)"
        if [[ -n "$console_uid" ]]; then
            launchctl asuser "$console_uid" launchctl bootstrap "gui/$console_uid" "$PLIST" 2>/dev/null || true
        fi
    fi
    ok "Tray LaunchAgent installed: com.cycentra.edrtray (system-wide, any GUI login)"
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

    # Watchdog service — restarts cyedr-agent if it goes down, UNLESS the stop
    # was tray-authorized (marker at $EDR_HOME/.tray_stopped — see
    # IPCListener._do_stop() in cyedr_agent.py). Without this check, an admin-
    # password-gated "Stop/Exit CyEDR" from the tray would silently get
    # reverted within 5 minutes, making that password gate meaningless on
    # Linux specifically (macOS/Windows have no equivalent watchdog to fight).
    cat > /etc/systemd/system/cyedr-watchdog.service << WDFILE
[Unit]
Description=CyEDR Agent Watchdog
After=cyedr-agent.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl is-active --quiet cyedr-agent || { [ -f $EDR_HOME/.tray_stopped ] && exit 0; systemctl restart cyedr-agent; }'
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
    # Always re-enroll, even on reinstall. self_enroll_agent() on the server matches
    # the existing row by hardware_uuid/hostname and UPDATEs it rather than inserting
    # a duplicate, so this is safe — and it guarantees the agent always ends up with
    # the current, valid enrollment_token instead of silently carrying a stale one
    # forward across reinstalls.
    info "Enrolling with CyCentra 360 platform..."
    HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

    # Collect stable hardware UUID for deduplication across reinstalls
    HW_UUID=""
    if [[ "$OS_KEY" == "MACOS" ]]; then
        HW_UUID="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | grep -o '"IOPlatformUUID" = "[^"]*"' | grep -oE '[0-9A-F-]{36}' | head -1)"
    elif [[ "$OS_KEY" == "LINUX" ]]; then
        HW_UUID="$(cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null || cat /sys/class/dmi/id/product_uuid 2>/dev/null | head -1)"
        HW_UUID="${HW_UUID^^}"  # uppercase
    fi
    [[ -z "$HW_UUID" ]] && warn "Could not detect hardware UUID — hostname will be used for deduplication"

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
            \"hostname\":      \"$HOSTNAME\",
            \"os_type\":       \"$OS_KEY\",
            \"asset_type\":    \"$ASSET_TYPE\",
            \"agent_ip\":      \"$AGENT_IP\",
            \"version\":       \"1.0.0\",
            \"hardware_uuid\": \"$HW_UUID\",
            \"gateway_ip\":    \"$GW_IP\",
            \"gateway_mac\":   \"$GW_MAC\"
        }") || die "Enrollment failed — check network connectivity to $PLATFORM_URL"

    # Extract agent_id and enrollment_token from response
    AGENT_ID=$(echo "$ENROLL_RESPONSE" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
    ENROLLMENT_TOKEN=$(echo "$ENROLL_RESPONSE" | grep -o '"enrollment_token":"[^"]*"' | cut -d'"' -f4)
    [[ -z "$AGENT_ID" ]] && die "Enrollment response did not include agent_id: $ENROLL_RESPONSE"
    [[ -z "$ENROLLMENT_TOKEN" ]] && die "Enrollment response did not include enrollment_token: $ENROLL_RESPONSE"

    # Persist agent_id, enrollment_token, and hardware_uuid into config
    python3 - << PYINLINE
import json
cfg_path = "$EDR_HOME/config.json"
with open(cfg_path) as f:
    cfg = json.load(f)
cfg["agent_id"]         = "$AGENT_ID"
cfg["enrollment_token"] = "$ENROLLMENT_TOKEN"
if "$HW_UUID":
    cfg["hardware_uuid"] = "$HW_UUID"
with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
PYINLINE

    ok "Enrolled — Agent ID: $AGENT_ID"
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
        # restart, not start: on a reinstall over an already-running agent, `start`
        # is a systemd no-op on an active unit — daemon-reload picks up the new
        # ExecStart (python3 mode, new binary, etc.) but the OLD process keeps
        # running untouched until something actually restarts it. `restart`
        # behaves identically to `start` when the unit isn't running yet, so this
        # is safe for both fresh installs and reinstalls.
        systemctl restart cyedr-agent
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
    # Best-effort — shown side by side, clearly labeled, so nobody mistakes
    # the agent build number for a platform-version mismatch (they're
    # intentionally different counters, see banner()/AGENT_VERSION comment
    # in agent/cyedr_agent.py). Never fails the install if unreachable.
    _PLATFORM_VER=$(curl -fsSL --max-time 10 "$PLATFORM_URL/api/system/version" 2>/dev/null \
        | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
        | sed -E 's/.*"([^"]+)"$/\1/')
    echo "  Platform version:   ${_PLATFORM_VER:-unknown}"
    echo "  CyEDR Agent Build:  v${CYEDR_AGENT_VERSION}  (independent counter — only bumps when agent/tray code changes)"
    echo "  Agent home: $EDR_HOME"
    echo "  Logs:       $EDR_HOME/logs/cyedr_agent.log"
    if [[ "$OS_KEY" == "LINUX" ]]; then
        echo ""
        echo "  Status:     systemctl status cyedr-agent"
        echo "  Logs:       journalctl -u cyedr-agent -f"
        echo "  Restart if stopped (tray Stop/Exit, or a crash):"
        echo "              sudo systemctl start cyedr-agent"
    else
        echo ""
        echo "  Status:     sudo launchctl list com.cycentra.edr"
        echo "  Logs:       tail -f $EDR_HOME/logs/cyedr_agent.log"
        # Printed here permanently, not only inside the tray's dialogs — by
        # the time someone needs this, the tray may be showing the
        # unreachable/red state and this may be the only place it's written
        # down (the agent's own log stops updating once it's stopped).
        echo "  Restart if stopped: use \"Start CyEDR...\" in the tray menu"
        echo "              (asks for the CyEDR admin password, then macOS's own"
        echo "               admin authentication) — or from Terminal:"
        echo "              sudo launchctl bootstrap system /Library/LaunchDaemons/com.cycentra.edr.plist"
        echo "              (if that errors 'already bootstrapped', use instead:"
        echo "               sudo launchctl kickstart -k system/com.cycentra.edr)"
    fi
    if [[ -x "$TRAY_HOME/cyedr-tray" ]]; then
        echo ""
        echo "  Tray:       $TRAY_HOME/cyedr-tray (starts automatically at next login)"
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

    if want_tray && deploy_tray; then
        if [[ "$OS_KEY" == "LINUX" ]]; then
            install_tray_autostart_linux
        else
            install_tray_launchagent_macos
        fi
    fi

    harden_permissions
    enroll_agent
    start_agent
    print_summary
}

main "$@"
