#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — Setup & Update Wizard v1.0.73 — 2026-04-06 21:31 UTC
#
# FRESH INSTALL (runs everything — infra + app):
#   sudo bash cycentra-setup.sh
#
# UPDATE EXISTING SERVER (skips infra, only updates app packages):
#   sudo bash cycentra-setup.sh --update
#
# PIN A SPECIFIC VERSION:
#   CYCENTRA_VERSION=v1.2.0 sudo bash cycentra-setup.sh
#   CYCENTRA_VERSION=v1.2.0 sudo bash cycentra-setup.sh --update
#
# AIR-GAPPED / LOCAL BUNDLE:
#   CYCENTRA_RELEASE_URL=/path/to/bundle.tar.gz sudo bash cycentra-setup.sh
#
# What this script pulls from where:
#   apt repos          → PostgreSQL 16, Redis, nginx, certbot, python3
#   packages.wazuh.com → Wazuh manager + indexer + dashboard
#   GitHub Releases    → cycentra-release.tar.gz (portal, SQL, config, manifest)
#   GitHub Packages    → cycentra-backend wheel (Flask + engine combined)
#   Let's Encrypt      → SSL certificates via certbot
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Parse flags ───────────────────────────────────────────────────────────────
MODE="full"
for arg in "$@"; do
    case "$arg" in
        --update) MODE="update" ;;
        --infra)  MODE="infra"  ;;
    esac
done

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}  ▸ ${NC}$*"; }
success() { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()    { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
error()   { echo -e "${RED}  ✗ ${NC}$*"; }
divider() { echo -e "${DIM}  ────────────────────────────────────────────────${NC}"; }

ask() {
    local varname=$1 prompt=$2 default=${3:-}
    local disp=""; [[ -n "$default" ]] && disp=" ${DIM}[${default}]${NC}"
    echo -ne "  ${WHITE}${prompt}${NC}${disp}: "
    read -r value
    [[ -z "$value" && -n "$default" ]] && value="$default"
    eval "$varname='$value'"
}
ask_secret() {
    local varname=$1 prompt=$2
    echo -ne "  ${WHITE}${prompt}${NC} ${DIM}[auto-generate]${NC}: "
    read -rs value; echo
    [[ -z "$value" ]] && value=$(openssl rand -hex 16) && info "Generated: ${DIM}${value}${NC}"
    eval "$varname='$value'"
}
ask_yn() {
    local prompt=$1 default=${2:-y}
    local opts="Y/n"; [[ "$default" == "n" ]] && opts="y/N"
    echo -ne "  ${WHITE}${prompt}${NC} ${DIM}[${opts}]${NC}: "
    read -r value; [[ -z "$value" ]] && value="$default"
    [[ "$value" =~ ^[Yy] ]] && return 0 || return 1
}

gen_secret() { openssl rand -hex 24; }
gen_pass()   { openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20; }
_port_up()   { ss -tlnp 2>/dev/null | grep -q ":${1} "; }

# Published version of this script — updated automatically by git-push.sh on each release.
# Used by --update mode to skip re-installation when the server is already on the latest version.
_SCRIPT_VERSION="v1.0.99"

# Mask GIT auth tokens in URLs before printing to output
_mask_url() { echo "$1" | sed 's|pkg\.github\.com/.*/|pkg.github.com/[TOKEN]/|g'; }

step=0
_LAST_STEP="(initializing)"

# ── Error trap — fires on any unexpected non-zero exit (set -euo pipefail) ──────
trap '
    ec=$?
    echo ""
    echo -e "\n${RED}${BOLD}  ✗ FATAL: Setup aborted during STEP ${step} \"${_LAST_STEP}\"${NC}"
    echo -e "  ${RED}  Failed command : ${BASH_COMMAND}${NC}"
    echo -e "  ${RED}  Exit code      : ${ec}  |  Line: ${BASH_LINENO[0]}${NC}"
    echo -e "  ${DIM}  Fix the issue above, then re-run: sudo bash cycentra-setup.sh${NC}"
    echo ""
' ERR

step_header() {
    step=$((step+1))
    _LAST_STEP="$1"
    echo -e "\n${BOLD}${CYAN}  ── STEP ${step}: $1${NC}"
    divider
}

[[ $EUID -ne 0 ]] && { error "Run as root: sudo bash cycentra-setup.sh"; exit 1; }

ERRORS=()

# ── Banner ────────────────────────────────────────────────────────────────────
[[ -t 1 ]] && clear; echo ""
echo -e "${CYAN}${BOLD}"
echo "  ██████╗██╗   ██╗ ██████╗███████╗███╗   ██╗████████╗██████╗  █████╗ "
echo "  ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗"
echo "  ██║      ╚████╔╝ ██║     █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║"
echo "  ██║       ╚██╔╝  ██║     ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║"
echo "  ╚██████╗   ██║   ╚██████╗███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║"
echo "   ╚═════╝   ╚═╝    ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}360° Security Operations Platform${NC}"
echo -e "  ${DIM}Setup & Update Wizard — v1.0.73 — 2026-04-06 21:31 UTC${NC}"
echo ""; divider

if [[ "$MODE" == "update" ]]; then
    echo -e "  ${YELLOW}MODE: UPDATE${NC} — skipping infrastructure, updating packages only"
elif [[ "$MODE" == "infra" ]]; then
    echo -e "  ${YELLOW}MODE: INFRA ONLY${NC} — installing infrastructure only"
else
    echo -e "  ${DIM}MODE: FULL INSTALL${NC} — infrastructure + application"
fi
divider; echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# INFRASTRUCTURE BLOCK — skipped when MODE=update
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$MODE" != "update" ]]; then

# ── Step 1: System packages ───────────────────────────────────────────────────
step_header "SYSTEM DEPENDENCIES"
apt-get update -y -qq
apt-get install -y -qq \
    curl wget gnupg lsb-release ca-certificates jq \
    python3 python3-pip \
    nmap whois rsync git openssl \
    nginx certbot python3-certbot-nginx \
    2>/dev/null
success "System packages installed"

# ── Docker install ─────────────────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1 && docker --version | grep -q "2[4-9]\.\|[3-9][0-9]\."; then
    success "Docker already installed — $(docker --version)"
else
    info "Installing Docker ..."
    for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
        apt-get remove -y "$pkg" 2>/dev/null || true
    done
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y -qq
    apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    success "Docker installed — $(docker --version)"
fi

# ── Step 2: PostgreSQL 16 ─────────────────────────────────────────────────────
step_header "POSTGRESQL 16"

if ! dpkg -l postgresql-16 2>/dev/null | grep -q "^ii"; then
    info "Adding PostgreSQL 16 apt repository ..."
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
    echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list
    apt-get update -y -qq
    apt-get install -y -qq postgresql-16
    systemctl enable postgresql
    systemctl start postgresql
    success "PostgreSQL 16 installed"
else
    success "PostgreSQL 16 already installed"
fi

# Bind to :5433 to avoid conflict with CyIRIS Docker postgres on :5432
# Try 5433 first (idempotent re-runs), then fall back to 5432 (fresh install)
PG_CONF=$(sudo -u postgres psql -p 5433 -t -c "SHOW config_file;" 2>/dev/null | tr -d ' \n' \
       || sudo -u postgres psql -p 5432 -t -c "SHOW config_file;" 2>/dev/null | tr -d ' \n' \
       || echo "")
if [[ -n "$PG_CONF" && -f "$PG_CONF" ]]; then
    _pg_changed=false
    if grep -q "^port = 5432" "$PG_CONF" 2>/dev/null; then
        info "Reconfiguring PostgreSQL from :5432 to :5433 ..."
        sed -i "s/^port = 5432/port = 5433/" "$PG_CONF"
        _pg_changed=true
    fi
    # Ensure PostgreSQL listens on TCP (asyncpg requires host=127.0.0.1)
    if ! grep -q "^listen_addresses = 'localhost'" "$PG_CONF" 2>/dev/null; then
        if grep -q "^#*listen_addresses" "$PG_CONF" 2>/dev/null; then
            sed -i "s/^#*listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF"
        else
            echo "listen_addresses = 'localhost'" >> "$PG_CONF"
        fi
        _pg_changed=true
    fi
    if [[ "$_pg_changed" == true ]]; then
        systemctl restart postgresql
        success "PostgreSQL configured: port 5433, TCP on localhost"
    fi
fi

# Preserve or generate correlation DB password
_EXISTING_CORR=$(grep "^POSTGRES_PASSWORD=" /opt/cycentra/cysiemstack.env 2>/dev/null \
    | cut -d= -f2 || true)
CORR_DB_PASS="${_EXISTING_CORR:-$(gen_pass)}"
[[ -n "$_EXISTING_CORR" ]] \
    && info "Preserving existing correlation DB password" \
    || info "Generated new correlation DB password"

# Create user + database (idempotent)
sudo -u postgres psql -p 5433 -tc \
    "SELECT 1 FROM pg_roles WHERE rolname='corruser';" 2>/dev/null \
    | grep -q 1 \
    || sudo -u postgres psql -p 5433 \
       -c "CREATE USER corruser WITH PASSWORD '${CORR_DB_PASS}';" 2>/dev/null || true

sudo -u postgres psql -p 5433 -tc \
    "SELECT 1 FROM pg_database WHERE datname='correlation';" 2>/dev/null \
    | grep -q 1 \
    || sudo -u postgres psql -p 5433 \
       -c "CREATE DATABASE correlation OWNER corruser;" 2>/dev/null || true

sudo -u postgres psql -p 5433 \
    -c "GRANT ALL PRIVILEGES ON DATABASE correlation TO corruser;" 2>/dev/null || true
sudo -u postgres psql -p 5433 \
    -c "ALTER USER corruser WITH PASSWORD '${CORR_DB_PASS}';" 2>/dev/null || true

success "PostgreSQL: correlation DB ready on :5433"

# ── Step 3: Redis ─────────────────────────────────────────────────────────────
step_header "REDIS"

if ! dpkg -l redis-server 2>/dev/null | grep -q "^ii"; then
    apt-get install -y -qq redis-server
    success "Redis installed"
else
    success "Redis already installed"
fi

cat > /etc/redis/redis.conf << 'REDISEOF'
bind 127.0.0.1
port 6379
daemonize yes
supervised systemd
loglevel notice
logfile /var/log/redis/redis-server.log
dir /var/lib/redis
appendonly yes
appendfilename "appendonly.aof"
maxmemory 256mb
maxmemory-policy allkeys-lru
REDISEOF

systemctl enable redis-server
systemctl restart redis-server
sleep 2
redis-cli ping 2>/dev/null | grep -q "PONG" \
    && success "Redis running on :6379" \
    || { error "Redis failed to start"; ERRORS+=("Redis failed"); }

fi  # end INFRA block

# ═══════════════════════════════════════════════════════════════════════════════
# APP BLOCK — runs in all modes
# ═══════════════════════════════════════════════════════════════════════════════

# Ensure jq is present for all modes
command -v jq >/dev/null 2>&1 || apt-get install -y -qq jq

# In update mode read CORR_DB_PASS from existing env
if [[ "$MODE" == "update" ]]; then
    # Try standalone POSTGRES_PASSWORD= line first (written by v1.0.61+)
    CORR_DB_PASS=$(grep "^POSTGRES_PASSWORD=" /opt/cycentra/cysiemstack.env 2>/dev/null \
        | sed 's/^POSTGRES_PASSWORD=//' | tr -d '"' || true)
    # Fallback: extract from DATABASE_URL (installs prior to v1.0.61 had no standalone key)
    if [[ -z "$CORR_DB_PASS" ]]; then
        CORR_DB_PASS=$(grep "^DATABASE_URL=" /opt/cycentra/cysiemstack.env 2>/dev/null \
            | sed 's|.*://[^:]*:\([^@]*\)@.*|\1|' || true)
        [[ -n "$CORR_DB_PASS" ]] && info "Correlation DB password recovered from DATABASE_URL"
    fi
    if [[ -z "$CORR_DB_PASS" ]]; then
        warn "POSTGRES_PASSWORD not found in /opt/cycentra/cysiemstack.env — generating a new one"
        warn "If the correlation DB already exists, update POSTGRES_PASSWORD in cysiemstack.env manually"
        CORR_DB_PASS=$(gen_pass)
    fi
fi

# ── Step 4: CySIEM install (full install only) ───────────────────────────────
_CYSIEM_FRESH=false
_CYSIEM_ADMIN_PASS=""
_CYSIEM_WUI_PASS=""

if [[ "$MODE" == "full" ]]; then

    step_header "CySIEM INSTALLATION"

    if dpkg -l 2>/dev/null | grep -q wazuh-manager; then
        success "CySIEM already installed — ensuring services running"
        systemctl start wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
    else
        info "Running CySIEM all-in-one installer (this takes 5–10 minutes) ..."
        cd ~
        curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
        bash wazuh-install.sh -a
        success "CySIEM installed"
        _CYSIEM_FRESH=true
        # Capture generated credentials from passwords file (non-fatal — Step 4.2 auto-detects from dashboard config)
        _cysiem_pwfile=$(tar -xOf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null || echo "")
        _CYSIEM_ADMIN_PASS=$(echo "$_cysiem_pwfile" | grep -A 1 "^username: admin$"   | grep "^password:" | awk '{print $2}' || true)
        _CYSIEM_WUI_PASS=$(echo  "$_cysiem_pwfile" | grep -A 1 "^username: wazuh-wui$" | grep "^password:" | awk '{print $2}' || true)
        # Fallback: Wazuh 4.x installer prints credentials in stdout summary — capture if tar extract above found nothing
        if [[ -z "$_CYSIEM_ADMIN_PASS" ]]; then
            _CYSIEM_ADMIN_PASS=$(grep -oP '(?<=Password: )\S+' ~/wazuh-install-files.tar 2>/dev/null | head -1 || true)
        fi
        cd ~
    fi

fi  # end CySIEM install block


# ── Step 4.1: CySIEM Dashboard configuration ─────────────────────────────────
WAZUH_YML="/etc/wazuh-dashboard/opensearch_dashboards.yml"
if [[ -f "$WAZUH_YML" ]]; then

    step_header "CySIEM DASHBOARD CONFIGURATION"

    cp "$WAZUH_YML" "${WAZUH_YML}.backup-$(date +%Y%m%d)" 2>/dev/null || true
    grep -q "^server.host:" "$WAZUH_YML" \
        && sed -i 's|^server.host:.*|server.host: "127.0.0.1"|' "$WAZUH_YML" \
        || echo 'server.host: "127.0.0.1"' >> "$WAZUH_YML"
    grep -q "^server.port:" "$WAZUH_YML" \
        && sed -i 's|^server.port:.*|server.port: 5601|' "$WAZUH_YML" \
        || echo 'server.port: 5601' >> "$WAZUH_YML"
    systemctl restart wazuh-dashboard 2>/dev/null || true
    success "CySIEM Dashboard configured: host=127.0.0.1, port=5601"

fi

# ── Step 4.2: Auto-detect CySIEM API password ─────────────────────────────────
# Read the wazuh-wui password from the dashboard config file.
# Works for both fresh installs and existing installs; runs in all modes.
if [[ -f "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml" ]]; then
    step_header "CySIEM API PASSWORD DETECTION"
    _detected=$(grep -v '^#' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml 2>/dev/null \
        | grep -oP '(?<=password: ")[^"]+' | head -1)
    if [[ -n "$_detected" ]]; then
        _CYSIEM_WUI_PASS="$_detected"
        success "CySIEM API password auto-detected from dashboard config"
        # Patch cysiemstack.env immediately — handles update mode (step 10 is skipped)
        if [[ -f "/opt/cycentra/cysiemstack.env" ]]; then
            if grep -q "^WAZUH_API_PASSWORD=" /opt/cycentra/cysiemstack.env; then
                sed -i "s|^WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=${_detected}|" /opt/cycentra/cysiemstack.env
            else
                echo "WAZUH_API_PASSWORD=${_detected}" >> /opt/cycentra/cysiemstack.env
            fi
            success "WAZUH_API_PASSWORD updated in cysiemstack.env"
        fi
    else
        warn "CySIEM API password not found — update WAZUH_API_PASSWORD in /opt/cycentra/cysiemstack.env manually"
    fi
fi

# ── CySIEM → Redis bridge ─────────────────────────────────────────────────────
# Deployed AFTER CySIEM is installed so alerts.json exists when the service starts.
# Runs in all modes (full/infra/update): rewrites the watcher script and restarts.
# NOTE: Filebeat 7.x (Wazuh-distributed) crashes on kernel 6.x (seccomp SIGABRT);
#       this pure-Python watcher replaces it with no kernel-compatibility issues.
step_header "CySIEM → REDIS BRIDGE (Python watcher)"

# Install redis-py if not already present
python3 -c "import redis" 2>/dev/null \
    || PIP_ROOT_USER_ACTION=ignore pip3 install --break-system-packages --quiet redis

# Ensure deploy directory exists
mkdir -p /opt/cycentra

# Write the watcher script
cat > /opt/cycentra/cysiem_to_redis.py << 'PYEOF'
#!/usr/bin/env python3
"""CySIEM alerts.json → Redis bridge — tails alerts and pushes NDJSON lines to Redis."""
import json
import logging
import os
import time
from pathlib import Path

import redis

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
REDIS_HOST  = "127.0.0.1"
REDIS_PORT  = 6379
REDIS_KEY   = "cysiemstack:alerts:raw"
MAX_LIST    = 200_000   # cap Redis list to avoid unbounded memory growth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("cysiem_to_redis")


def tail_forever() -> None:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    r.ping()

    path = Path(ALERTS_FILE)
    log.info("watching %s  →  redis:%d/%s", ALERTS_FILE, REDIS_PORT, REDIS_KEY)

    # Open in raw unbuffered binary mode so OS-level appends are immediately
    # visible — Python text-mode buffering can silently stall on tailed files.
    with open(path, "rb", buffering=0) as fb:
        fb.seek(0, 2)                         # start at EOF — no history replay
        inode  = os.stat(path).st_ino
        buf    = b""
        pushed = 0

        while True:
            chunk = fb.read(65536)
            if chunk:
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        json.loads(line)      # validate before pushing
                        pipe = r.pipeline()
                        pipe.lpush(REDIS_KEY, line)
                        pipe.ltrim(REDIS_KEY, 0, MAX_LIST - 1)
                        pipe.execute()
                        pushed += 1
                        if pushed % 100 == 0:
                            log.info("pushed %d alerts total", pushed)
                    except json.JSONDecodeError as exc:
                        log.warning("invalid JSON — skipped: %s", exc)
                    except redis.RedisError as exc:
                        log.error("redis error: %s", exc)
                        raise  # let outer loop reconnect
            else:
                # detect CySIEM daily log rotation
                try:
                    if os.stat(path).st_ino != inode:
                        log.info("log rotation detected — reopening %s", path)
                        buf = b""
                        fb.close()
                        fb = open(path, "rb", buffering=0)
                        inode = os.stat(path).st_ino
                except FileNotFoundError:
                    pass
                time.sleep(0.05)


if __name__ == "__main__":
    while True:
        try:
            tail_forever()
        except Exception as exc:
            log.error("fatal: %s — retrying in 5 s", exc)
            time.sleep(5)
PYEOF
chmod 750 /opt/cycentra/cysiem_to_redis.py

# Write the systemd unit
cat > /etc/systemd/system/cysiem-to-redis.service << 'UNITEOF'
[Unit]
Description=CySIEM alerts.json → Redis bridge
After=network.target redis.service wazuh-manager.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/cycentra/cysiem_to_redis.py
Restart=always
RestartSec=5
StandardOutput=append:/opt/cycentra/engine.log
StandardError=append:/opt/cycentra/engine.log

[Install]
WantedBy=multi-user.target
UNITEOF

# Remove Filebeat if installed — it crashes on kernel 6.x (seccomp pthread issue)
if dpkg -l filebeat &>/dev/null 2>&1; then
    systemctl disable --now filebeat 2>/dev/null || true
    apt-get purge -y filebeat 2>/dev/null || true
    rm -rf /etc/filebeat /var/lib/filebeat /var/log/filebeat
    success "Filebeat removed (replaced by cysiem-to-redis)"
fi

# Ensure CySIEM alerts log is readable (may not exist yet if CySIEM not generating alerts)
if [[ -f /var/ossec/logs/alerts/alerts.json ]]; then
    chmod o+r /var/ossec/logs/alerts/alerts.json 2>/dev/null || true
    chmod o+x /var/ossec/logs/alerts/ 2>/dev/null || true
    success "CySIEM alerts.json readable"
else
    warn "CySIEM alerts.json not found — watcher will retry once CySIEM generates alerts"
fi

systemctl daemon-reload
systemctl enable cysiem-to-redis
systemctl restart cysiem-to-redis
sleep 2
systemctl is-active cysiem-to-redis >/dev/null 2>&1 \
    && success "cysiem-to-redis running — tailing CySIEM alerts → Redis :6379" \
    || { warn "cysiem-to-redis failed — check: journalctl -u cysiem-to-redis -n 20"; \
         ERRORS+=("cysiem-to-redis failed"); }

# ── Download release bundle ───────────────────────────────────────────────────
step_header "DOWNLOAD RELEASE BUNDLE"

GH_TOKEN="${GH_TOKEN:-}"
if [[ -z "$GH_TOKEN" ]]; then
    error "GH_TOKEN is not set. Run with: GH_TOKEN=your_token sudo -E bash cycentra-setup.sh"
    exit 1
fi

GH_ORG="cycentra"
GH_REPO="cycentra360"
GH_BASE="https://maven.pkg.github.com/${GH_ORG}/${GH_REPO}"
CYCENTRA_VERSION="${CYCENTRA_VERSION:-latest}"

if [[ "$CYCENTRA_VERSION" == "latest" ]]; then
    _latest_tag=$(curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${GH_ORG}/${GH_REPO}/releases/latest" \
        | jq -r '.tag_name')
    [[ -z "$_latest_tag" || "$_latest_tag" == "null" ]] && \
        { error "Could not resolve latest release from GitHub API"; exit 1; }
    CYCENTRA_VERSION="$_latest_tag"
    info "Latest release resolved: ${CYCENTRA_VERSION}"
fi

GH_VER="${CYCENTRA_VERSION#v}"
CYCENTRA_RELEASE_URL="${CYCENTRA_RELEASE_URL:-${GH_BASE}/cycentra/bundle/${GH_VER}/bundle-${GH_VER}.tar.gz}"

# ── Version pre-check (update mode only) ─────────────────────────────────────
# Compare the installed version against the latest published version resolved
# from GitHub Releases API (CYCENTRA_VERSION).  Using _SCRIPT_VERSION here
# would always match because the running script IS the installed one.
if [[ "$MODE" == "update" && "${FORCE_UPDATE:-0}" != "1" ]]; then
    _installed_ver=$(cat /opt/cycentra/version 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ -n "$_installed_ver" && "$_installed_ver" == "$CYCENTRA_VERSION" ]]; then
        echo ""
        success "Already at the latest version: ${CYCENTRA_VERSION}"
        info    "Nothing to update. Run with FORCE_UPDATE=1 to re-apply the current version."
        exit 0
    elif [[ -n "$_installed_ver" ]]; then
        info "Update available: ${_installed_ver} → ${CYCENTRA_VERSION}"
    fi
fi

BUNDLE_DIR="/tmp/cycentra-release"
rm -rf "$BUNDLE_DIR" /tmp/cycentra-release.tar.gz

info "Downloading: $(_mask_url "${CYCENTRA_RELEASE_URL}")"
if [[ "$CYCENTRA_RELEASE_URL" == http* ]]; then
    curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        "$CYCENTRA_RELEASE_URL" -o /tmp/cycentra-release.tar.gz \
        && success "Bundle downloaded" \
        || { error "Download failed. Check GH_TOKEN and version."; exit 1; }
    tar -xzf /tmp/cycentra-release.tar.gz -C /tmp/
else
    tar -xzf "$CYCENTRA_RELEASE_URL" -C /tmp/
fi

MANIFEST="$BUNDLE_DIR/manifest.json"
[[ ! -f "$MANIFEST" ]] && { error "manifest.json not found in bundle"; exit 1; }

BUNDLE_VERSION=$(jq -r '.version'    "$MANIFEST")
PKG_VER=$(jq        -r '.ver_number' "$MANIFEST")
PKG_NAME="cycentra-backend"
WHEEL_URL="${GH_BASE}/cycentra/backend/${PKG_VER}/cycentra_backend-${PKG_VER}-py3-none-any.whl"

success "Bundle version  : ${BUNDLE_VERSION}"
info    "Package         : ${PKG_NAME}==${PKG_VER}"

# Write version file (always — so System Settings page can read it)
mkdir -p /opt/cycentra
echo "${BUNDLE_VERSION}" > /opt/cycentra/version
success "Version file written: /opt/cycentra/version → ${BUNDLE_VERSION}"

# Write RELEASE_NOTES.md for System Settings page — shipped inside the release bundle
_RN_DEST="/opt/cycentra/RELEASE_NOTES.md"
mkdir -p /opt/cycentra

if [[ -f "$BUNDLE_DIR/RELEASE_NOTES.md" ]]; then
    cp "$BUNDLE_DIR/RELEASE_NOTES.md" "$_RN_DEST"
    success "RELEASE_NOTES.md deployed to ${_RN_DEST}"
else
    warn "RELEASE_NOTES.md not found in bundle — Settings tab release history may be outdated"
fi

# Copy this script to /opt/cycentra/ so the portal can invoke it for --update
_SELF="$(realpath "$0")"
cp "$_SELF" /opt/cycentra/cycentra-setup.sh
chmod 750  /opt/cycentra/cycentra-setup.sh
success "Setup script deployed to /opt/cycentra/cycentra-setup.sh"
# ── Step 6-9: Interactive config (full install only) ─────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "CLIENT INFORMATION"
    ask CLIENT_NAME  "Client / Organisation name" "cycentra"
    ask CLIENT_EMAIL "Primary admin email"        "admin@${CLIENT_NAME,,}.com"
    ask BASE_DOMAIN  "Base domain"                "${CLIENT_NAME,,}.com"
    echo ""
    info "Subdomains: cy360 · cyscan · cysiem · cyiris · cysoar · cymind  (all on .${BASE_DOMAIN})"
    echo ""
    if ! ask_yn "Are all subdomains pointing at this server in DNS?"; then
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        warn "Add DNS A records: cy360 cyscan cysiem cyiris cysoar → ${SERVER_IP}"
        ask_yn "Continue anyway? (SSL will fail if DNS not ready)" "n" || exit 0
    fi

    INSTALL_CYSIEM=true; INSTALL_CYIRIS=true; INSTALL_CYSOAR=true
    success "CySIEM selected"; success "CyIRIS selected"; success "CySOAR selected"

    step_header "OAUTH / SSO CONFIGURATION"
    echo -e "  ${DIM}Portal login via Google or Microsoft.${NC}"; echo ""
    PS3="  Choose provider: "
    select OAUTH_PROVIDER in "Google" "Microsoft Azure AD" "Skip"; do
        case $REPLY in
            1) OAUTH_PROVIDER="google";    break;;
            2) OAUTH_PROVIDER="microsoft"; break;;
            3) OAUTH_PROVIDER="skip";      break;;
        esac
    done
    OAUTH_CLIENT_ID=""; OAUTH_CLIENT_SECRET=""
    if [[ "$OAUTH_PROVIDER" != "skip" ]]; then
        [[ "$OAUTH_PROVIDER" == "google" ]] \
            && info "Redirect URI: https://cyscan.${BASE_DOMAIN}/auth/google/callback" \
            || info "Redirect URI: https://cyscan.${BASE_DOMAIN}/auth/microsoft/callback"
        echo ""
        ask OAUTH_CLIENT_ID "OAuth Client ID" ""
        ask_secret OAUTH_CLIENT_SECRET "OAuth Client Secret"
    else
        warn "OAuth skipped — configure later in /opt/cycentra/.env"
    fi

    # AI provider is configured after install via the portal's AI Settings page.
    AI_PROVIDER="none"; AI_API_KEY=""; AI_MODEL=""

    step_header "SMTP CONFIGURATION (OPTIONAL)"
    SMTP_HOST=""; SMTP_PORT=""; SMTP_USER=""; SMTP_PASS=""; SUPPORT_EMAIL=""
    if ask_yn "Configure SMTP for support emails?" "n"; then
        ask SMTP_HOST     "SMTP hostname"          "smtp.gmail.com"
        ask SMTP_PORT     "SMTP port"              "587"
        ask SMTP_USER     "SMTP username"          ""
        ask_secret SMTP_PASS "SMTP password"
        ask SUPPORT_EMAIL "Support destination"    "support@${BASE_DOMAIN}"
        success "SMTP configured → ${SUPPORT_EMAIL}"
    fi

    step_header "GENERATING SECRETS"
    _env="/opt/cycentra/.env"
    _get() { grep -m1 "^${1}=" "$_env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true; }
    if [[ -f "$_env" ]]; then
        info "Existing .env found — preserving session secrets"
        FLASK_SECRET=$(_get SECRET_KEY);   [[ -z "$FLASK_SECRET"   ]] && FLASK_SECRET=$(gen_secret)
        JWT_SECRET=$(_get JWT_SECRET);     [[ -z "$JWT_SECRET"     ]] && JWT_SECRET=$(gen_secret)
        IRIS_SECRET=$(_get IRIS_SECRET);   [[ -z "$IRIS_SECRET"    ]] && IRIS_SECRET=$(gen_secret)
        IRIS_DB_PASS=$(_get IRIS_DB_PASS); [[ -z "$IRIS_DB_PASS"   ]] && IRIS_DB_PASS=$(gen_pass)
        NODERED_SECRET=$(_get NODE_RED_CREDENTIAL_SECRET)
        [[ -z "$NODERED_SECRET" ]] && NODERED_SECRET=$(gen_secret)
    else
        FLASK_SECRET=$(gen_secret); JWT_SECRET=$(gen_secret)
        IRIS_SECRET=$(gen_secret);  IRIS_DB_PASS=$(gen_pass)
        NODERED_SECRET=$(gen_secret)
    fi
    ADMIN_API_KEY=$(gen_secret)
    CYIRIS_OIDC_SECRET=$(gen_secret)
    CYSOAR_OIDC_SECRET=$(gen_secret)
    success "All secrets ready"

    step_header "REVIEW & CONFIRM"
    echo -e "  ${DIM}Client  :${NC} ${WHITE}${CLIENT_NAME}${NC}"
    echo -e "  ${DIM}Email   :${NC} ${WHITE}${CLIENT_EMAIL}${NC}"
    echo -e "  ${DIM}Domain  :${NC} ${WHITE}${BASE_DOMAIN}${NC}"
    echo -e "  ${DIM}OAuth   :${NC} ${WHITE}${OAUTH_PROVIDER}${NC}"
    echo -e "  ${DIM}AI      :${NC} ${WHITE}${AI_PROVIDER}${NC}"
    echo -e "  ${DIM}SMTP    :${NC} ${WHITE}${SMTP_HOST:-not configured}${NC}"
    echo -e "  ${DIM}Version :${NC} ${WHITE}${BUNDLE_VERSION}${NC}"
    echo ""
    ask_yn "Proceed with full installation?" || exit 0

else
    # Update mode — read existing config from .env
    info "Update mode — reading configuration from /opt/cycentra/.env ..."
    [[ ! -f /opt/cycentra/.env ]] && {
        error "/opt/cycentra/.env not found. Run full install first."
        exit 1
    }
    set -a; source /opt/cycentra/.env; set +a
    CLIENT_NAME="${CLIENT_NAME:-cycentra}"
    CLIENT_EMAIL="${CLIENT_EMAIL:-admin@cycentra.com}"
    BASE_DOMAIN="${BASE_DOMAIN:-cycentra.com}"
    INSTALL_CYSIEM=true; INSTALL_CYIRIS=true; INSTALL_CYSOAR=true
    success "Loaded existing configuration (domain: ${BASE_DOMAIN})"
fi

# ── Step 10: Write .env files (full install only) ─────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "WRITING CONFIGURATION FILES"
    mkdir -p /opt/cycentra && chmod 700 /opt/cycentra

    cat > /opt/cycentra/.env << ENVEOF
# CyCentra 360 — generated by setup wizard v7.1
# Version: ${BUNDLE_VERSION} | Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

BASE_DOMAIN=${BASE_DOMAIN}
CLIENT_NAME=${CLIENT_NAME}
SECRET_KEY=${FLASK_SECRET}
JWT_SECRET=${JWT_SECRET}
ADMIN_API_KEY=${ADMIN_API_KEY}
FRONTEND_URL=https://cy360.${BASE_DOMAIN}
BASE_URL=https://cyscan.${BASE_DOMAIN}
OAUTH_PROVIDER=${OAUTH_PROVIDER:-skip}
ENVEOF

    [[ "${OAUTH_PROVIDER:-skip}" == "google" ]] && cat >> /opt/cycentra/.env << ENVEOF
GOOGLE_CLIENT_ID=${OAUTH_CLIENT_ID}
GOOGLE_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
ENVEOF

    [[ "${OAUTH_PROVIDER:-skip}" == "microsoft" ]] && cat >> /opt/cycentra/.env << ENVEOF
MICROSOFT_CLIENT_ID=${OAUTH_CLIENT_ID}
MICROSOFT_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
ENVEOF

    cat >> /opt/cycentra/.env << ENVEOF

CYIRIS_OIDC_SECRET=${CYIRIS_OIDC_SECRET}
CYSOAR_OIDC_SECRET=${CYSOAR_OIDC_SECRET}
USE_CUSTOM_IMAGES=no

IRIS_SECRET=${IRIS_SECRET}
IRIS_DB_PASS=${IRIS_DB_PASS}
IRIS_ADM_EMAIL=${CLIENT_EMAIL}
IRIS_ADM_PASSWORD=CyIRIS@CHANGE
CYCENTRA_PORTAL_URL=https://cy360.${BASE_DOMAIN}
IRIS_SECRET_KEY=${IRIS_SECRET}
POSTGRES_PASSWORD=${IRIS_DB_PASS}
NODE_RED_CREDENTIAL_SECRET=${NODERED_SECRET}

AI_PROVIDER=${AI_PROVIDER:-none}
AI_API_KEY=${AI_API_KEY:-}
AI_MODEL=${AI_MODEL:-}

SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-}
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SUPPORT_EMAIL=${SUPPORT_EMAIL:-support@cycentra.com}

SIEM_ENGINE_URL=http://127.0.0.1:8100
SIEM_LLM_ENABLED=true
SIEM_MISP_ENABLED=false

# GitHub token — used by the portal backend to download updates/upgrades without
# requiring the customer to enter it in the UI.  Set via GH_TOKEN env var at install time.
GH_TOKEN=${GH_TOKEN:-}

# ── Cloud CyMISP (Cycentra-managed MISP at misp.cycentra.com) ─────────────────
# When a customer selects "Cloud CyMISP" in System Settings > Integrations, the
# backend uses these credentials automatically.  CLOUD_MISP_API_KEY must be set
# to the vendor-issued API key for this installation.
CLOUD_MISP_URL=https://misp.cycentra.com
CLOUD_MISP_API_KEY=${CLOUD_MISP_API_KEY:-}
ENVEOF
    chmod 600 /opt/cycentra/.env
   # mkdir -p /root/cy-asm && cp /opt/cycentra/.env /root/cy-asm/.env
   # success "Main .env written → /opt/cycentra/.env"

    _LLM_FLAG="false"
    [[ "${AI_PROVIDER:-none}" != "none" ]] && _LLM_FLAG="true"

    # Use auto-detected password if available, otherwise preserve existing, or placeholder
    _WAZUH_PASS="${_CYSIEM_WUI_PASS:-$(grep "^WAZUH_API_PASSWORD=" /opt/cycentra/cysiemstack.env 2>/dev/null | cut -d= -f2)}"
    _WAZUH_PASS="${_WAZUH_PASS:-CHANGE_ME_after_cysiem_install}"

    cat > /opt/cycentra/cysiemstack.env << SIEMEOF
# CySIEMStack environment — auto-generated by setup.sh
# WAZUH_API_PASSWORD is auto-detected from CySIEM dashboard config

DATABASE_URL=postgresql+asyncpg://corruser:${CORR_DB_PASS}@127.0.0.1:5433/correlation
REDIS_URL=redis://127.0.0.1:6379/0
REDIS_ALERT_KEY=cysiemstack:alerts:raw

WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=${_WAZUH_PASS}

# LLM provider and credentials are read from /opt/cycentra/ai_settings.json
# Configure via the AI Settings page in the portal — no keys needed here.
LLM_ENABLED=${_LLM_FLAG}

CORRELATION_WINDOW_MINUTES=15
UEBA_BASELINE_DAYS=30
RISK_DECAY_HOURS=24
INCIDENT_ID_PREFIX=INC
LOG_LEVEL=INFO
UEBA_ML_SHADOW_MODE=true
UEBA_ML_MIN_TRAIN_DAYS=7
UEBA_ML_MODEL_DIR=/opt/cycentra/ml_models
MISP_ENABLED=false
# Standalone key so --update mode can read the password without parsing DATABASE_URL
POSTGRES_PASSWORD=${CORR_DB_PASS}
SIEMEOF
    chmod 600 /opt/cycentra/cysiemstack.env
    success "cysiemstack.env written → /opt/cycentra/cysiemstack.env"

    # Create ML model persistence directory
    mkdir -p /opt/cycentra/ml_models
    chmod 755 /opt/cycentra/ml_models
    success "ML model directory created → /opt/cycentra/ml_models"

fi  # end full env block

# ── Step 11: Deploy portal static files ──────────────────────────────────────
step_header "DEPLOYING PORTAL"

PORTAL_DIR="/var/www/cycentra360"
mkdir -p "$PORTAL_DIR"
if [[ -d "$BUNDLE_DIR/portal/dist" ]]; then
    rsync -a --delete "$BUNDLE_DIR/portal/dist/" "$PORTAL_DIR/"
    success "Portal deployed → ${PORTAL_DIR} ($(find $PORTAL_DIR -type f | wc -l) files)"
else
    warn "portal/dist not in bundle"; ERRORS+=("Portal dist missing")
fi

# Deploy branding and config assets from bundle
BRANDING_DIR="/opt/cycentra-branding"
mkdir -p "$BRANDING_DIR" /tmp/cycentra-config
[[ -d "$BUNDLE_DIR/scripts"       ]] && cp -r "$BUNDLE_DIR/scripts/."       "$BRANDING_DIR/scripts/"
[[ -d "$BUNDLE_DIR/assets"        ]] && cp -r "$BUNDLE_DIR/assets/."        "$BRANDING_DIR/assets/"
[[ -d "$BUNDLE_DIR/CYSIEM-Config" ]] && cp -r "$BUNDLE_DIR/CYSIEM-Config/." "/tmp/cycentra-config/"

mkdir -p /var/log/cycentra/cy-asm/scans
mkdir -p /var/log/cycentra/cy-asm/logs
mkdir -p /var/log/cycentra/cy-asm/reports
chmod -R 755 /var/log/cycentra/cy-asm
success "ASM log directories created"

# ── Step 12: Install cycentra-backend package (Flask + engine combined) ───────
step_header "INSTALLING CYCENTRA-BACKEND PACKAGE"

info "Installing ${PKG_NAME}==${PKG_VER} into system Python ..."
info "Wheel: $(_mask_url "${WHEEL_URL}")"

# Download wheel from GitHub Packages then install locally.
# pip requires the filename to match the wheel naming convention; use the real WHL name.
# --break-system-packages required on Ubuntu 24.04 (PEP 668 externally-managed env)
# PIP_ROOT_USER_ACTION=ignore suppresses the "running as root" advisory — intentional here.
_WHL_FILE="/tmp/cycentra_backend-${PKG_VER}-py3-none-any.whl"
curl -fsSL \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    "${WHEEL_URL}" \
    -o "${_WHL_FILE}" \
    || { error "Wheel download failed — check GH_TOKEN and version"; exit 1; }

PIP_ROOT_USER_ACTION=ignore pip3 install \
    --extra-index-url https://pypi.org/simple/ \
    "${_WHL_FILE}" \
    --upgrade \
    --break-system-packages \
    --ignore-installed \
    -q \
    && success "Installed: ${PKG_NAME}==${PKG_VER}" \
    || { error "Package install failed — check wheel download and dependencies"; \
         ERRORS+=("pip install failed"); }

# Locate installed files for systemd service definitions
PYTHON_BIN=$(which python3)
SITE_PKG=$(python3 -c "import site; print(site.getsitepackages()[0])")
info "Site-packages: ${SITE_PKG}"

FLASK_APP="${SITE_PKG}/app.py"
ENGINE_DIR="${SITE_PKG}/cysiemstack/correlation_engine"

[[ -f "$FLASK_APP" ]] \
    && success "Flask entry point: ${FLASK_APP}" \
    || { error "app.py not found in ${SITE_PKG}"; ERRORS+=("app.py missing after install"); }

[[ -d "$ENGINE_DIR" ]] \
    && success "Engine found: ${ENGINE_DIR}" \
    || warn "Engine directory not found at ${ENGINE_DIR} — check package structure"

# ── Step 13: DB schema + migrations ──────────────────────────────────────────
step_header "DATABASE SCHEMA & MIGRATIONS"

if [[ -f "$BUNDLE_DIR/db/init.sql" ]]; then
    info "Applying init.sql ..."
    PGPASSWORD="$CORR_DB_PASS" psql -h 127.0.0.1 -p 5433 \
        -U corruser -d correlation \
        -f "$BUNDLE_DIR/db/init.sql" -v ON_ERROR_STOP=0 -q 2>/dev/null || true
    success "init.sql applied"
else
    # Fallback: use the init.sql shipped with the installed package
    _PKG_INIT=$(find "$SITE_PKG" -path "*/cysiemstack/postgres/init.sql" 2>/dev/null | head -1 || true)
    if [[ -n "$_PKG_INIT" ]]; then
        info "Applying init.sql from installed package ..."
        PGPASSWORD="$CORR_DB_PASS" psql -h 127.0.0.1 -p 5433 \
            -U corruser -d correlation \
            -f "$_PKG_INIT" -v ON_ERROR_STOP=0 -q 2>/dev/null || true
        success "init.sql applied (from ${_PKG_INIT})"
    else
        warn "No init.sql found — database schema may not be initialised"
        ERRORS+=("init.sql missing")
    fi
fi

if [[ -d "$BUNDLE_DIR/db/migrations" ]]; then
    for sql in "$BUNDLE_DIR/db/migrations/"*.sql; do
        [[ -f "$sql" ]] || continue
        info "Migration: $(basename $sql) ..."
        PGPASSWORD="$CORR_DB_PASS" psql -h 127.0.0.1 -p 5433 \
            -U corruser -d correlation \
            -f "$sql" -v ON_ERROR_STOP=0 -q 2>/dev/null \
            && success "$(basename $sql) applied" \
            || warn    "$(basename $sql) had warnings (may already be applied)"
    done
fi

# Also apply any migrations shipped inside the installed Python package.
# These cover upgrades where the bundle didn't include a db/migrations/ directory.
# All migration SQL files are idempotent (ADD COLUMN IF NOT EXISTS), so re-runs are safe.
_pkg_migrations=$(find "${SITE_PKG:-/usr/local/lib/python3.12/dist-packages}" \
    -path "*/cysiemstack/postgres/migrations/*.sql" 2>/dev/null | sort || true)
if [[ -n "$_pkg_migrations" ]]; then
    while IFS= read -r sql; do
        [[ -f "$sql" ]] || continue
        info "Package migration: $(basename $sql) ..."
        PGPASSWORD="$CORR_DB_PASS" psql -h 127.0.0.1 -p 5433 \
            -U corruser -d correlation \
            -f "$sql" -v ON_ERROR_STOP=0 -q 2>/dev/null \
            && success "$(basename $sql) applied" \
            || warn    "$(basename $sql) had warnings (may already be applied)"
    done <<< "$_pkg_migrations"
fi

# ── Step 14: Systemd services ─────────────────────────────────────────────────
step_header "SYSTEMD SERVICES"

UVICORN_BIN=$(which uvicorn 2>/dev/null || echo "${PYTHON_BIN} -m uvicorn")

cat > /etc/systemd/system/cycentra-backend.service << UNITEOF
[Unit]
Description=CyCentra 360 Flask Backend
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=${SITE_PKG}
EnvironmentFile=/opt/cycentra/.env
ExecStart=${PYTHON_BIN} ${FLASK_APP}
Restart=always
RestartSec=5
StandardOutput=append:/opt/cycentra/flask.log
StandardError=append:/opt/cycentra/flask.log

[Install]
WantedBy=multi-user.target
UNITEOF

cat > /etc/systemd/system/cysiemstack-engine.service << UNITEOF
[Unit]
Description=CyCentra 360 CySIEMStack Correlation Engine
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=${ENGINE_DIR}
EnvironmentFile=/opt/cycentra/cysiemstack.env
ExecStart=${UVICORN_BIN} main:app --host 127.0.0.1 --port 8100 --workers 1 --log-level info
Restart=always
RestartSec=5
StandardOutput=append:/opt/cycentra/engine.log
StandardError=append:/opt/cycentra/engine.log

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable cycentra-backend cysiemstack-engine

# Start Flask backend
pkill -f "python3.*app.py" 2>/dev/null || true
sleep 1
systemctl restart cycentra-backend
sleep 4
curl -s --max-time 5 http://127.0.0.1:5252/health 2>/dev/null | grep -q "ok" \
    && success "Flask backend healthy :5252" \
    || { warn "Flask not responding — check: journalctl -u cycentra-backend -n 30"; \
         ERRORS+=("Flask unhealthy"); }

# Start correlation engine
systemctl restart cysiemstack-engine
ENGINE_UP=false
for i in $(seq 1 12); do
    curl -sf http://127.0.0.1:8100/health >/dev/null 2>&1 \
        && { success "CySIEMStack engine healthy :8100"; ENGINE_UP=true; break; }
    sleep 5
done
[[ "$ENGINE_UP" == false ]] && \
    { warn "Engine timed out — last 30 lines of engine.log:"
      echo ""
      tail -30 /opt/cycentra/engine.log 2>/dev/null | while IFS= read -r line; do echo -e "  ${DIM}${line}${NC}"; done
      echo ""
      warn "To investigate: journalctl -u cysiemstack-engine -n 30"
      ERRORS+=("Engine not responding"); }

# ── Step 15: nginx vhosts (full install only) ─────────────────────────────────
# ── Step 15: nginx vhosts (full install only) ─────────────────────────────────
# NOTE v7.2: CyIRIS and CySOAR nginx config removed from here.
# They are now managed dynamically by routes.py on module install/uninstall:
#   CyIRIS  → adds cyiris.DOMAIN server block + certbot expand on install
#   CySOAR  → injects location CySOAR into portal server on install
#   CyMISP  → was already routes.py-managed (unchanged)
# Only permanent core services remain here: cy360, cyscan, cysiem.
if [[ "$MODE" == "full" ]]; then

    step_header "NGINX VHOST CONFIGURATION"

    SSL_CONF="/etc/nginx/sites-available/cycentra-modules"
    SSL_CONF_BACKUP="${SSL_CONF}.ssl-pending"

    cat > "$SSL_CONF" << NGINXEOF
# CyCentra 360 nginx — generated by setup wizard v7.2 — ${BASE_DOMAIN}
# Module nginx blocks (cyiris, cysoar, cymisp) are managed by routes.py.

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# ── Portal (cy360) ───────────────────────────────────────────────────────────
server { listen 80; server_name cy360.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cy360.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    root /var/www/cycentra360; index index.html;
    location /     { try_files \$uri \$uri/ /index.html; }
    location /assets/  { expires 1y; add_header Cache-Control "public, immutable"; }
    location = /index.html { add_header Cache-Control "no-cache, no-store, must-revalidate"; }
    location /api/  { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_read_timeout 180s; }
    location /auth/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }
    location /oidc/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }
    # location cysoar is injected here by routes.py when CySOAR is installed via portal
}

# ── Backend / OIDC IdP (cyscan) ──────────────────────────────────────────────
server { listen 80; server_name cyscan.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cyscan.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    set \$cors_origin "";
    if (\$http_origin ~* "^https://(cy360|cysiem|cyiris|cysoar)\.${BASE_DOMAIN}\$") { set \$cors_origin \$http_origin; }
    add_header Access-Control-Allow-Origin      \$cors_origin always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Allow-Methods     "GET, POST, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers     "Content-Type, Authorization, X-CyCentra-AdminKey" always;
    if (\$request_method = OPTIONS) { return 204; }
    location / {
        proxy_pass http://127.0.0.1:5252;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
    }
}

# ── CySIEM / Wazuh Dashboard (cysiem) ────────────────────────────────────────
server { listen 80; server_name cysiem.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cysiem.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "" always;
    add_header Content-Security-Policy "frame-ancestors 'self' https://cy360.${BASE_DOMAIN}" always;
    location / {
        proxy_pass https://127.0.0.1:5601;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120;
        proxy_buffering off;
        proxy_cookie_flags ~ samesite=none secure;
    }
}
# cyiris.DOMAIN server block is added by routes.py when CyIRIS is installed via portal
# cymisp.DOMAIN server block is added by routes.py when CyMISP is installed via portal

# ── CyMind AI (cymind / cyq) ─────────────────────────────────────────────────
server { listen 80; server_name cymind.${BASE_DOMAIN} cyq.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cymind.${BASE_DOMAIN} cyq.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    client_max_body_size 500M;

    # ── SSE streaming (chat/stream, model pull) — no buffering ────
    location ~ ^/api/v1/(chat/stream|models/.*/pull) {
        proxy_pass         http://127.0.0.1:${CYMIND_PORT:-8080};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Connection        "";
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
        chunked_transfer_encoding on;
    }

    # ── All API requests ──────────────────────────────────────────
    location /api/ {
        proxy_pass         http://127.0.0.1:${CYMIND_PORT:-8080};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Connection        "";
        proxy_read_timeout 300s;
    }

    # ── Frontend SPA ──────────────────────────────────────────────
    location / {
        proxy_pass         http://127.0.0.1:${CYMIND_PORT:-8080};
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }
}
NGINXEOF

    cp "$SSL_CONF" "$SSL_CONF_BACKUP"

fi  # end full nginx block

# ── Step 16: SSL certificates (full install only) ─────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "SSL CERTIFICATES"

    # HTTP-only stub so nginx starts for ACME challenge
    cat > "$SSL_CONF" << 'STUBEOF'
server {
    listen 80;
    server_name _;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "setup-in-progress"; add_header Content-Type text/plain; }
}
STUBEOF

    mkdir -p /var/www/html
    ln -sf /etc/nginx/sites-available/cycentra-modules \
           /etc/nginx/sites-enabled/cycentra-modules 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t 2>/dev/null \
        && { systemctl reload nginx 2>/dev/null || systemctl start nginx; \
             success "nginx started (HTTP stub for certbot)"; } \
        || { error "nginx config invalid"; ERRORS+=("nginx failed"); }

    if [[ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]]; then
        curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf \
            -o /etc/letsencrypt/options-ssl-nginx.conf 2>/dev/null || true
    fi

    if [[ ! -f /etc/letsencrypt/ssl-dhparams.pem ]]; then
        info "Generating ssl-dhparams.pem in background (~30s) ..."
        openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 2>/dev/null &
        DHPARAM_PID=$!
    fi

    certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        -m "$CLIENT_EMAIL" -d cy360.${BASE_DOMAIN} -d cyscan.${BASE_DOMAIN} 2>/dev/null \
        && success "SSL cert obtained (cy360, cyscan)" \
        || warn "Certbot failed for base domains — DNS may not be ready yet"

    certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        -m "$CLIENT_EMAIL" -d cysiem.${BASE_DOMAIN} 2>/dev/null \
        && success "CySIEM SSL cert obtained" || warn "Certbot failed for cysiem"
    # NOTE: cyiris.DOMAIN cert is obtained by routes.py via certbot --expand when CyIRIS is installed.
    # NOTE: cymisp.DOMAIN cert is obtained by routes.py via certbot --expand when CyMISP is installed.

    [[ -n "${DHPARAM_PID:-}" ]] && wait "$DHPARAM_PID" 2>/dev/null || true

    # Restore full SSL nginx config now that certs exist
    cp "$SSL_CONF_BACKUP" "$SSL_CONF"
    nginx -t 2>/dev/null \
        && systemctl reload nginx && success "nginx reloaded with full SSL config" \
        || { warn "nginx SSL config pending — re-run after DNS resolves"; \
             ERRORS+=("nginx SSL pending"); }
             
fi  # end SSL block

# ── Step 18: Wazuh rules, decoders, ossec.conf ────────────────────────────────
if [[ -d "/var/ossec" ]]; then

    step_header "WAZUH RULES & CONFIG"

    CONFIG_SRC="/tmp/cycentra-config"
    [[ -d "$CONFIG_SRC/rules" ]] && \
        cp "$CONFIG_SRC/rules/"*.xml /var/ossec/etc/rules/ 2>/dev/null || true
    [[ -d "$CONFIG_SRC/decoders" ]] && \
        cp "$CONFIG_SRC/decoders/"*.xml /var/ossec/etc/decoders/ 2>/dev/null || true

    if [[ -f "$CONFIG_SRC/integrations/custom-llm.py" ]]; then
        cp "$CONFIG_SRC/integrations/custom-llm.py" /var/ossec/integrations/
        chmod 750 /var/ossec/integrations/custom-llm.py
        chown root:wazuh /var/ossec/integrations/custom-llm.py
        success "custom-llm.py deployed"
    fi

    if [[ -f "$CONFIG_SRC/conf/ossec.conf" ]]; then
        cp "$CONFIG_SRC/conf/ossec.conf" /var/ossec/etc/ossec.conf
        chmod 660 /var/ossec/etc/ossec.conf
        chown root:wazuh /var/ossec/etc/ossec.conf
        success "ossec.conf deployed"
    fi

    /var/ossec/bin/wazuh-analysisd -t 2>/dev/null \
        && success "CySIEM rules valid" \
        || { warn "wazuh-analysisd -t reported errors"; ERRORS+=("CySIEM rules invalid"); }

    systemctl restart wazuh-manager && success "wazuh-manager restarted"

fi  # end Wazuh config block

# ── Step 20: Platform branding (whitelabel) ───────────────────────────────────
step_header "PLATFORM BRANDING (WHITELABEL)"

for script in apply-favicons apply-logos enable-multitenancy apply-custom-branding apply-plugin-branding; do
    SPATH="$BRANDING_DIR/scripts/${script}.sh"
    if [[ -f "$SPATH" ]]; then
        bash "$SPATH" \
            && success "${script}.sh applied" \
            || warn "${script}.sh returned non-zero — check output above"
    else
        info "${script}.sh not in bundle — skipping"
    fi
done

# ── Step 21: Inject domain into portal index.html ────────────────────────────
step_header "PORTAL DOMAIN INJECTION"

PORTAL_INDEX="$PORTAL_DIR/index.html"
if [[ -f "$PORTAL_INDEX" ]]; then
    sed -i '/window\.__CYCENTRA_DOMAIN__/d' "$PORTAL_INDEX"
    sed -i '/window\.__CYCENTRA_CLIENT__/d'  "$PORTAL_INDEX"
    sed -i "s|</head>|<script>window.__CYCENTRA_DOMAIN__='${BASE_DOMAIN}';window.__CYCENTRA_CLIENT__='${CLIENT_NAME}';</script></head>|" "$PORTAL_INDEX"
    success "Domain injected into portal → ${BASE_DOMAIN}"
else
    warn "portal/index.html not found — re-run after portal is deployed"
    ERRORS+=("Portal index.html missing")
fi

# ── Step 22: RBAC + config.json ───────────────────────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "RBAC & CONFIG"

    # Only create rbac.json if it does not already exist
    if [[ ! -f /opt/cycentra/rbac.json ]]; then
        info "rbac.json not found. Initializing with admin: ${CLIENT_EMAIL}"
        cat > /opt/cycentra/rbac.json << RBACEOF
{ "${CLIENT_EMAIL}": { "role": "admin" } }
RBACEOF
        success "rbac.json initialized"
    else
        success "Existing rbac.json detected — preserving user permissions"
    fi

    # config.json should always be updated to reflect current version/domain
    cat > "$PORTAL_DIR/config.json" << CFGJSON
{
  "base_domain": "${BASE_DOMAIN}",
  "client_name": "${CLIENT_NAME}",
  "version":     "${BUNDLE_VERSION}",
  "portal_url":  "https://cy360.${BASE_DOMAIN}",
  "cyscan_url":  "https://cyscan.${BASE_DOMAIN}",
  "generated":   "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
CFGJSON

    success "Portal config.json updated"

fi

# Ensure log directory and auth log exist with correct permissions
mkdir -p /var/log/cycentra && touch /var/log/cycentra/auth.log
chmod 644 /var/log/cycentra/auth.log

# ── Step 23: Cron jobs ────────────────────────────────────────────────────────
step_header "CRON JOBS"

WORDLIST=$(find "$SITE_PKG" -name "update_wordlist.py" 2>/dev/null | head -1 || true)
if [[ -n "$WORDLIST" ]]; then
    # Use a tempfile to avoid bash pipeline operator-precedence pitfalls with
    # set -euo pipefail (|| has lower precedence than |, causing grep to exit 1
    # on empty input and aborting the script).
    _tmpcron=$(mktemp)
    { crontab -l 2>/dev/null || true; } | grep -v "update_wordlist" > "$_tmpcron" || true
    echo "0 0 * * * ${PYTHON_BIN} ${WORDLIST} >> /opt/cycentra/cron.log 2>&1" >> "$_tmpcron"
    crontab "$_tmpcron"
    rm -f "$_tmpcron"
    success "Cron: ASM wordlist update registered (daily midnight)"
else
    info "update_wordlist.py not found — cron job skipped"
fi

# ── Step 24: Health checks ────────────────────────────────────────────────────
step_header "HEALTH CHECKS"

chk() {
    local label=$1 url=$2
    local code; code=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] \
        && success "${label}: HTTP ${code}" \
        || warn    "${label}: HTTP ${code} — ${url}"
}

echo ""; info "── Internal ports ──"
_port_up 5252 && success "Flask backend   :5252 UP" || warn "Flask backend   :5252 DOWN"
_port_up 8100 && success "SIEM engine     :8100 UP" || warn "SIEM engine     :8100 DOWN"
_port_up 5433 && success "PostgreSQL      :5433 UP" || warn "PostgreSQL      :5433 DOWN"
_port_up 6379 && success "Redis           :6379 UP" || warn "Redis           :6379 DOWN"
_port_up 5601 && success "CySIEM Dashboard :5601 UP" || warn "CySIEM Dashboard :5601 DOWN (install via portal)"
_port_up 4433 && success "CyIRIS          :4433 UP" || warn "CyIRIS          :4433 DOWN (install via portal)"
_port_up 1880 && success "CySOAR          :1880 UP" || warn "CySOAR          :1880 DOWN (install via portal)"

echo ""; info "── Systemd services ──"
for svc in cycentra-backend cysiemstack-engine postgresql redis-server nginx cysiem-to-redis; do
    systemctl is-active "$svc" >/dev/null 2>&1 \
        && success "${svc} active" \
        || warn    "${svc} inactive"
done

echo ""; info "── Internal HTTP ──"
chk "Flask /health"  "http://127.0.0.1:5252/health"
chk "Engine /health" "http://127.0.0.1:8100/health"

if [[ "$MODE" == "full" ]]; then
    echo ""; info "── External HTTPS ──"
    chk "Portal"  "https://cy360.${BASE_DOMAIN}"
    chk "Backend" "https://cyscan.${BASE_DOMAIN}/health"
    chk "CySIEM"  "https://cysiem.${BASE_DOMAIN}"
    chk "CyIRIS"  "https://cyiris.${BASE_DOMAIN}/api/v2/ping"
fi

# ── Step 25: Cleanup ──────────────────────────────────────────────────────────
step_header "CLEANUP"

rm -rf "$BUNDLE_DIR" /tmp/cycentra-release.tar.gz /tmp/cycentra-config
rm -f ~/wazuh-install.sh ~/wazuh-install-files* 2>/dev/null || true
success "Staging files removed"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""; divider
echo -e "\n  ${BOLD}${WHITE}CyCentra 360 — ${MODE^^} Complete${NC}\n"
divider; echo ""
echo -e "  ${CYAN}Version        ${NC}  ${BUNDLE_VERSION}"
if [[ "$MODE" == "full" ]]; then
    echo -e "  ${CYAN}Portal         ${NC}  https://cy360.${BASE_DOMAIN}"
    echo -e "  ${CYAN}Backend API    ${NC}  https://cyscan.${BASE_DOMAIN}"
    echo -e "  ${CYAN}CySIEM         ${NC}  https://cysiem.${BASE_DOMAIN}"
    echo -e "  ${CYAN}CyIRIS         ${NC}  https://cyiris.${BASE_DOMAIN}"
    echo -e "  ${CYAN}CySOAR         ${NC}  https://cysoar.${BASE_DOMAIN}"
fi
echo ""
echo -e "  ${BOLD}Flask service  :${NC}  systemctl status cycentra-backend"
echo -e "  ${BOLD}Engine service :${NC}  systemctl status cysiemstack-engine"
echo -e "  ${BOLD}Flask log      :${NC}  /opt/cycentra/flask.log"
echo -e "  ${BOLD}Engine log     :${NC}  /opt/cycentra/engine.log"
echo -e "  ${BOLD}Main env       :${NC}  /opt/cycentra/.env"
echo -e "  ${BOLD}SIEM env       :${NC}  /opt/cycentra/cysiemstack.env"
echo -e "  ${BOLD}nginx config   :${NC}  /etc/nginx/sites-available/cycentra-modules"
echo ""

if [[ "$MODE" == "full" ]]; then
    echo -e "  ${BOLD}Admin API key  :${NC}  ${WHITE}${ADMIN_API_KEY}${NC}"
    echo -e "  ${BOLD}CyIRIS secret  :${NC}  ${WHITE}${CYIRIS_OIDC_SECRET}${NC}"
    echo -e "  ${BOLD}CySOAR secret  :${NC}  ${WHITE}${CYSOAR_OIDC_SECRET}${NC}"
    echo ""
fi

if [[ "${_CYSIEM_FRESH:-false}" == "true" ]]; then
    echo -e "  ${BOLD}${CYAN}── CySIEM Initial Credentials ──${NC}"
    echo -e "  ${CYAN}Dashboard URL  ${NC}  https://cysiem.${BASE_DOMAIN}"
    if [[ -n "${_CYSIEM_ADMIN_PASS:-}" ]]; then
        echo -e "  ${BOLD}Admin login    :${NC}  ${WHITE}admin / ${_CYSIEM_ADMIN_PASS}${NC}"
    else
        echo -e "  ${DIM}Admin password : See ~/wazuh-install-files.tar → wazuh-passwords.txt${NC}"
    fi
    if [[ -n "${_CYSIEM_WUI_PASS:-}" ]]; then
        echo -e "  ${BOLD}API user (wui) :${NC}  ${WHITE}wazuh-wui / ${_CYSIEM_WUI_PASS}${NC}"
    else
        echo -e "  ${DIM}API password   : Stored in /opt/cycentra/cysiemstack.env${NC}"
    fi
    echo ""
fi

echo -e "  ${BOLD}${YELLOW}Next steps:${NC}"
echo -e "  ${DIM}1. Verify WAZUH_API_PASSWORD in /opt/cycentra/cysiemstack.env (auto-detected if CySIEM is installed)${NC}"
echo -e "  ${DIM}   then: systemctl restart cysiemstack-engine${NC}"
echo -e "  ${DIM}2. Verify alerts flowing: redis-cli -p 6379 llen cysiemstack:alerts:raw${NC}"
echo -e "  ${DIM}   (cysiem-to-redis tails CySIEM alerts → Redis — check: journalctl -u cysiem-to-redis -n 20)${NC}"
echo -e "  ${DIM}3. Check engine log: tail -f /opt/cycentra/engine.log${NC}"
echo -e "  ${DIM}4. Install CyIRIS / CySOAR via portal${NC}"
echo -e "  ${DIM}5. To update: sudo bash cycentra-setup.sh --update${NC}"
echo ""

# Save summary file
cat > /root/cycentra-setup-summary.txt << SUMEOF
CyCentra 360 Setup Summary v7.1
Generated : $(date)
Version   : ${BUNDLE_VERSION}
Mode      : ${MODE}
═══════════════════════════════════
Client : ${CLIENT_NAME}
Domain : ${BASE_DOMAIN}
Email  : ${CLIENT_EMAIL:-n/a}

URLs:
  Portal:   https://cy360.${BASE_DOMAIN}
  Backend:  https://cyscan.${BASE_DOMAIN}
  CySIEM:   https://cysiem.${BASE_DOMAIN}
  CyIRIS:   https://cyiris.${BASE_DOMAIN}
  CySOAR:   https://cysoar.${BASE_DOMAIN}

Services:
  Flask backend  : systemctl status cycentra-backend
  SIEM engine    : systemctl status cysiemstack-engine
  PostgreSQL     : systemctl status postgresql   (port 5433)
  Redis          : systemctl status redis-server (port 6379)
  nginx          : systemctl status nginx
  CySIEM         : systemctl status wazuh-manager

Paths:
  Flask log    : /opt/cycentra/flask.log
  Engine log   : /opt/cycentra/engine.log
  Main env     : /opt/cycentra/.env
  SIEM env     : /opt/cycentra/cysiemstack.env
  RBAC         : /opt/cycentra/rbac.json
  Portal files : /var/www/cycentra360
  nginx config : /etc/nginx/sites-available/cycentra-modules
  Branding     : /opt/cycentra-branding

Next steps:
  1. Verify WAZUH_API_PASSWORD in /opt/cycentra/cysiemstack.env (auto-detected if CySIEM is installed)
     then: systemctl restart cysiemstack-engine
  2. Verify alerts flowing: redis-cli -p 6379 llen cysiemstack:alerts:raw
     (cysiem-to-redis service tails CySIEM alerts → Redis)
  3. Check engine log: tail -f /opt/cycentra/engine.log
  4. Install CyIRIS/CySOAR via portal
  5. Update: sudo bash cycentra-setup.sh --update
SUMEOF

success "Summary saved → /root/cycentra-setup-summary.txt"

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo ""
    warn "${#ERRORS[@]} item(s) need attention:"
    for e in "${ERRORS[@]}"; do echo -e "  ${YELLOW}⚠${NC} $e"; done
fi

echo ""; divider
echo -e "  ${DIM}Re-run anytime: sudo bash cycentra-setup.sh${NC}"
echo -e "  ${DIM}Update only:    sudo bash cycentra-setup.sh --update${NC}"
echo ""