#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 -- Setup & Update Wizard v1.0.230 -- 2026-04-20 14:35 UTC
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



# ── Colours & helpers (defined early — used by license check below) ───────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}  ▸ ${NC}$*"; }
success() { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()    { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
error()   { echo -e "${RED}  ✗ ${NC}$*"; }
divider() { echo -e "${DIM}  ────────────────────────────────────────────────${NC}"; }

gen_secret() { openssl rand -hex 24; }
gen_pass()   { openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20; }
_port_up()   { ss -tlnp 2>/dev/null | grep -q ":${1} "; }

# ── Parse flags ───────────────────────────────────────────────────────────────
MODE="full"
for arg in "$@"; do
    case "$arg" in
        --update) MODE="update" ;;
        --infra)  MODE="infra"  ;;
    esac
done


# ── License check (full install only — updates are always allowed) ────────────
# Validator is embedded as a heredoc — single-file installer, no external
# license_validator.py required alongside the script or binary.
_LIC_FILE="/opt/cycentra/cycentra.lic"
# Also accept a .lic placed alongside this script (for licensed one-file installs)
[[ ! -f "$_LIC_FILE" ]] && \
    _LIC_FILE_LOCAL="${_SCRIPT_DIR:-$(dirname "${BASH_SOURCE[0]:-$0}")}/cycentra.lic" && \
    [[ -f "$_LIC_FILE_LOCAL" ]] && _LIC_FILE="$_LIC_FILE_LOCAL"

# ── Certbot environment: set during fresh install prompt (Step 1a below) ─────
CERTBOT_ENV="--staging"   # safe default; overridden to "" for PROD during fresh install

if [[ "$MODE" == "full" ]]; then
    # Write embedded validator to a secure temp file
    _VALIDATOR_DEST="/tmp/cycentra_license_validator_$$.py"
    cat > "$_VALIDATOR_DEST" << 'CYCENTRA_VALIDATOR_EOF'
#!/usr/bin/env python3
import base64, json, os, subprocess, sys, tempfile
from datetime import date
from pathlib import Path

CYCENTRA_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3PWTGpjM9/RTMTA4FMmj
coYBxAEtckGxiv/Vf9vtZHbZBsoqaZk+Fx30DeiHCD2x0P//xkLxb/+yhY4vGsx5
cYEJpUHCxlskxFaBlBOQmZGIqgq6BHicfEnAiRCmmX6GznmCNPzqIIgXXtTOVILz
ez/oTDQkfNp5z3qrHK9XAqleqHehyJR3genS9XAPB8sNey6RfjYPa4FZixm4O7DI
i0nQeWeGjhPeZLaWo+BIGeMzCZQZpLOg4HBvsdNQZ9Jp4ktHnPKAFqyLzI+4BctE
o6cG5hWtmCcvUXWwzB+5YTPmMDp28kRNNOyMLo9DPsS6LHcW5R96uEXsyE8G1lZo
oQIDAQAB
-----END PUBLIC KEY-----
"""
DEMO_MAX_DAYS = 15
DEMO_STATE    = Path("/opt/cycentra/.demo_start")
LICENSE_PATH  = Path("/opt/cycentra/cycentra.lic")

def _verify_signature(payload_str, sig_b64):
    try: sig_bytes = base64.b64decode(sig_b64)
    except Exception: return False
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
        kf.write(CYCENTRA_PUBLIC_KEY); kf_path = kf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sf:
        sf.write(sig_bytes); sf_path = sf.name
    try:
        p = subprocess.run(["openssl","dgst","-sha256","-verify",kf_path,"-signature",sf_path],
                           input=payload_str.encode(), capture_output=True)
        return p.returncode == 0
    except FileNotFoundError: return False
    finally: os.unlink(kf_path); os.unlink(sf_path)

def _parse_lic_file(path):
    try: text = path.read_text()
    except Exception: return None, None
    try:
        pb64 = text.split("-----BEGIN CYCENTRA LICENSE-----")[1].split("-----END CYCENTRA LICENSE-----")[0].strip()
        sb64 = text.split("-----BEGIN CYCENTRA SIGNATURE-----")[1].split("-----END CYCENTRA SIGNATURE-----")[0].strip()
        ps   = base64.b64decode(pb64).decode()
        return json.loads(ps), sb64, ps
    except Exception: return None, None, None

def _days_remaining(exp): return (date.fromisoformat(exp) - date.today()).days

def _demo_days_remaining():
    if not DEMO_STATE.exists():
        DEMO_STATE.parent.mkdir(parents=True, exist_ok=True)
        DEMO_STATE.write_text(date.today().isoformat())
        return DEMO_MAX_DAYS
    return max(0, DEMO_MAX_DAYS - (date.today() - date.fromisoformat(DEMO_STATE.read_text().strip())).days)

def validate(lic_path=LICENSE_PATH):
    p = Path(lic_path)
    if not p.exists():
        d = _demo_days_remaining()
        if d <= 0:
            return {"valid":False,"type":"demo","days_remaining":0,"features":[],"customer":"Demo",
                    "message":"Demo period expired. Purchase a license at cycentra.com"}
        return {"valid":True,"type":"demo","days_remaining":d,"features":["cysiem"],
                "customer":"Demo","message":f"Demo mode — {d} day(s) remaining"}
    r = _parse_lic_file(p)
    if len(r) == 2:
        return {"valid":False,"type":"none","days_remaining":0,"features":[],"customer":"unknown",
                "message":"License file is corrupt or unreadable"}
    payload, sig_b64, payload_str = r
    if payload is None:
        return {"valid":False,"type":"none","days_remaining":0,"features":[],"customer":"unknown",
                "message":"License file could not be parsed"}
    if not _verify_signature(payload_str, sig_b64):
        return {"valid":False,"type":"none","days_remaining":0,"features":[],
                "customer":payload.get("customer","unknown"),
                "message":"License signature is invalid — file may have been tampered"}
    days = _days_remaining(payload["expires"])
    if days < 0:
        return {"valid":False,"type":payload["type"],"days_remaining":0,
                "features":payload.get("features",[]),"customer":payload["customer"],
                "message":f"License expired on {payload['expires']}"}
    return {"valid":True,"type":payload["type"],"days_remaining":days,
            "features":payload.get("features",[]),"customer":payload["customer"],
            "message":f"License valid — {days} day(s) remaining (expires {payload['expires']})"}

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--license", default=str(LICENSE_PATH))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    lic = Path(args.license)
    result = validate(lic)
    if not args.quiet: print(json.dumps(result, indent=2))
    # Exit codes: 0=full, 1=demo, 2=expired, 3=tampered/invalid, 4=no license (auto-demo)
    if not lic.exists(): sys.exit(4)
    if result.get("valid"):
        sys.exit(0 if result.get("type") == "full" else 1)
    sys.exit(2 if result.get("days_remaining", 1) <= 0 else 3)
CYCENTRA_VALIDATOR_EOF
    chmod 600 "$_VALIDATOR_DEST"

    set +e
    _LIC_JSON=$(python3 "$_VALIDATOR_DEST" --license "$_LIC_FILE" 2>/dev/null)
    _LIC_CODE=$?
    set -e
    _LIC_TYPE=$(echo "$_LIC_JSON"  | python3 -c "import sys,json;print(json.load(sys.stdin).get('type','none'))" 2>/dev/null || echo "none")
    _LIC_DAYS=$(echo "$_LIC_JSON"  | python3 -c "import sys,json;print(json.load(sys.stdin).get('days_remaining',0))" 2>/dev/null || echo "0")
    _LIC_MSG=$(echo "$_LIC_JSON"   | python3 -c "import sys,json;print(json.load(sys.stdin).get('message',''))" 2>/dev/null || echo "")
    _LIC_CUST=$(echo "$_LIC_JSON"  | python3 -c "import sys,json;print(json.load(sys.stdin).get('customer',''))" 2>/dev/null || echo "")
    rm -f "$_VALIDATOR_DEST"

    case $_LIC_CODE in
        0) success "License: FULL — ${_LIC_CUST} — ${_LIC_DAYS} day(s) remaining"
           CYCENTRA_DEMO_MODE=0 ;;
        1) warn "License: DEMO — ${_LIC_DAYS} day(s) remaining"
           warn "Full platform features will be limited. Place cycentra.lic in the installer"
           warn "directory to activate a full license."
           CYCENTRA_DEMO_MODE=1 ;;
        2) error "License EXPIRED — ${_LIC_MSG}"
           error "Purchase or renew at https://cycentra.com"
           exit 1 ;;
        3) error "License INVALID — ${_LIC_MSG}"
           error "The license file may have been tampered. Contact support@cycentra.com"
           exit 1 ;;
        4|*)
           warn "No license found — installing 15-day demo"
           warn "Place cycentra.lic alongside this script to install the full platform."
           CYCENTRA_DEMO_MODE=1 ;;
    esac
    export CYCENTRA_DEMO_MODE
    export CYCENTRA_LICENSE_TYPE="${_LIC_TYPE}"
fi

# ── ask / ask_secret / ask_yn helpers (interactive fallbacks) ────────────────
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

# Published version of this script — updated automatically by git-push.sh on each release.
# Used by --update mode to skip re-installation when the server is already on the latest version.
_SCRIPT_VERSION="v1.0.230"

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
echo -e "  ${DIM}Setup & Update Wizard — ${_SCRIPT_VERSION} — $(date -u +"%Y-%m-%d %H:%M UTC")${NC}"
echo ""; divider

if [[ "$MODE" == "update" ]]; then
    echo -e "  ${YELLOW}MODE: UPDATE${NC} — skipping infrastructure, updating packages only"
elif [[ "$MODE" == "infra" ]]; then
    echo -e "  ${YELLOW}MODE: INFRA ONLY${NC} — installing infrastructure only"
else
    echo -e "  ${DIM}MODE: FULL INSTALL${NC} — infrastructure + application"
fi
divider; echo ""

# ── Step 1: Prompt for base domain ──────────────────────────────────────────
if [[ "$MODE" == "full" && ! -f "/opt/cycentra/.env" ]]; then
    step_header "BASE DOMAIN CONFIGURATION"
    read -p "Enter your base domain name [cycentra.com]: " USER_DOMAIN
    BASE_DOMAIN="${USER_DOMAIN:-cycentra.com}"
fi

# ── Step 1a: Prompt for environment type (fresh install only) ────────────────
if [[ "$MODE" == "full" && ! -f "/opt/cycentra/.env" ]]; then
    step_header "ENVIRONMENT TYPE"
    echo "  Select environment type:"
    echo "    [1] PROD     — request a real Let's Encrypt certificate"
    echo "    [2] STAGING  — use Let's Encrypt staging (no browser-trusted cert)"
    read -p "  Choice [1/2, default=2]: " _ENV_CHOICE
    if [[ "$_ENV_CHOICE" == "1" ]]; then
        CERTBOT_ENV=""
        info "PROD selected — using Let's Encrypt production environment for certbot."
    else
        CERTBOT_ENV="--staging"
        info "STAGING selected — using Let's Encrypt staging environment for certbot."
    fi
fi


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

# ── pip3 compatibility: --break-system-packages (pip >= 23.x / Python 3.11+) ─
# Older distros (Ubuntu 20.04, pip 21.x) reject this flag with "no such option".
# Detect support once and store in _PIP_BSP for reuse everywhere.
_PIP_BSP=""
pip3 install --break-system-packages --dry-run pip 2>&1 | grep -q "no such option" || _PIP_BSP="--break-system-packages"

# ── Python reporting prerequisites ────────────────────────────────────────────
_PY_REPORT_PKGS=(reportlab matplotlib numpy pillow)
declare -A _PY_IMPORT_MAP=([reportlab]=reportlab [matplotlib]=matplotlib [numpy]=numpy [pillow]=PIL)
_PY_MISSING=()
for _pkg in "${_PY_REPORT_PKGS[@]}"; do
    _import="${_PY_IMPORT_MAP[$_pkg]:-${_pkg,,}}"
    python3 -c "import $_import" 2>/dev/null || _PY_MISSING+=("$_pkg")
done
if [[ ${#_PY_MISSING[@]} -eq 0 ]]; then
    success "Python reporting packages already installed — skipping"
else
    info "Installing Python reporting packages: ${_PY_MISSING[*]} ..."
    PIP_ROOT_USER_ACTION=ignore pip3 install "${_PY_MISSING[@]}" \
        ${_PIP_BSP} -q \
        && success "Installed: ${_PY_MISSING[*]}" \
        || { error "Failed to install Python reporting packages"; ERRORS+=("pip reporting prereqs failed"); }
fi

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

# ── Step 4: Nuclei (ProjectDiscovery — not in standard apt repos) ─────────────
step_header "NUCLEI SCANNER"

if command -v nuclei >/dev/null 2>&1; then
    success "Nuclei already installed — $(nuclei -version 2>&1 | head -1)"
else
    info "Installing Nuclei from ProjectDiscovery releases..."
    apt-get install -y -qq unzip 2>/dev/null || true

    _NUCLEI_URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | python3 -c "import sys,json; assets=json.load(sys.stdin)['assets']; print(next(a['browser_download_url'] for a in assets if 'linux_amd64.zip' in a['name']))" \
        2>/dev/null)

    if [[ -z "$_NUCLEI_URL" ]]; then
        warn "Could not resolve Nuclei download URL — skipping. Install manually later."
    else
        curl -fsSL "$_NUCLEI_URL" -o /tmp/nuclei_linux_amd64.zip
        unzip -o /tmp/nuclei_linux_amd64.zip nuclei -d /usr/local/bin/ 2>/dev/null
        chmod +x /usr/local/bin/nuclei
        rm -f /tmp/nuclei_linux_amd64.zip

        if command -v nuclei >/dev/null 2>&1; then
            nuclei -update-templates -silent 2>/dev/null || true
            success "Nuclei installed — $(nuclei -version 2>&1 | head -1)"
        else
            warn "Nuclei binary install failed — ASM Nuclei scanner will be skipped at runtime"
        fi
    fi
fi

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
_CYSIEM_KS_PASS=""

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
        _CYSIEM_ADMIN_PASS=$(echo "$_cysiem_pwfile" | grep -A 1 "^username: admin$"      | grep "^password:" | awk '{print $2}' || true)
        _CYSIEM_WUI_PASS=$(echo  "$_cysiem_pwfile" | grep -A 1 "^username: wazuh-wui$"   | grep "^password:" | awk '{print $2}' || true)
        _CYSIEM_KS_PASS=$(echo   "$_cysiem_pwfile" | grep -A 1 "^username: kibanaserver$" | grep "^password:" | awk '{print $2}' || true)
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

    # ── Ensure kibanaserver service-account credentials are active ────────────
    # Wazuh installer generates a random kibanaserver password but may leave the
    # credential lines commented in opensearch_dashboards.yml.  Dashboard cannot
    # reach OpenSearch without them → every request returns 401 regardless of
    # proxy auth config.
    # Priority: (1) uncomment existing real password, (2) inject from installer
    # tar, (3) fall-back to checking if tar is available from a previous install.
    _ks_line_user=$(grep -E "^#?\s*opensearch\.username:" "$WAZUH_YML" | head -1)
    _ks_line_pass=$(grep -E "^#?\s*opensearch\.password:" "$WAZUH_YML" | head -1)
    _ks_pass_val=$(echo "$_ks_line_pass" | awk '{print $NF}' | tr -d '"')
    if [[ -n "$_ks_line_user" && -n "$_ks_pass_val" && "$_ks_pass_val" != "kibanaserver" ]]; then
        # Lines exist with a real (non-placeholder) password — uncomment if needed
        sed -i 's|^#\s*\(opensearch\.username:\)|\1|' "$WAZUH_YML" || true
        sed -i 's|^#\s*\(opensearch\.password:\)|\1|' "$WAZUH_YML" || true
        success "CySIEM Dashboard: kibanaserver credentials uncommented"
    else
        # Try to obtain the real password: installer variable, then fall back to tar
        if [[ -z "$_CYSIEM_KS_PASS" && -f ~/wazuh-install-files.tar ]]; then
            _pwfile2=$(tar -xOf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt 2>/dev/null || true)
            _CYSIEM_KS_PASS=$(echo "$_pwfile2" | grep -A 1 "^username: kibanaserver$" | grep "^password:" | awk '{print $2}' || true)
        fi
        if [[ -n "$_CYSIEM_KS_PASS" ]]; then
            # Remove any existing (commented or not) username/password lines and rewrite
            sed -i '/^#\?\s*opensearch\.username:/d; /^#\?\s*opensearch\.password:/d' "$WAZUH_YML" || true
            printf 'opensearch.username: kibanaserver\nopensearch.password: "%s"\n' "$_CYSIEM_KS_PASS" >> "$WAZUH_YML"
            success "CySIEM Dashboard: kibanaserver credentials set from installer"
        else
            warn "kibanaserver password unknown — opensearch.username/password may be missing from opensearch_dashboards.yml. Dashboard→OpenSearch auth will fail if so."
        fi
    fi

    systemctl restart wazuh-dashboard 2>/dev/null || true
    success "CySIEM Dashboard configured: host=127.0.0.1, port=5601"

fi

# ── Step 4.3: CySIEM proxy auth (IAP mode) ───────────────────────────────────
# Wazuh Dashboard is gated by oauth2-proxy (auth_request in nginx).
# Dashboard auth.type is set to "proxy" — it trusts X-Proxy-User from nginx.
# This replaces the old OIDC + securityadmin.sh approach entirely.
# Configured after .env is written (step 4.3b below).
_WAZUH_DASH_YML="/etc/wazuh-dashboard/opensearch_dashboards.yml"

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
    || PIP_ROOT_USER_ACTION=ignore pip3 install ${_PIP_BSP} --quiet redis

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
[[ -z "$GH_TOKEN" ]] && { error "GH_TOKEN is not set. Export it before running: export GH_TOKEN=<token>"; exit 1; }
GH_ORG="cycentra"
GH_REPO="cycentra360"

# ── Detect local bundle (running from inside an already-extracted tarball) ────
# When the server runs:  tar -xzf bundle.tar.gz && sudo bash cycentra-setup.sh
# manifest.json will be in the same directory as this script.  In that case
# we skip the download entirely — GH_TOKEN is not required.
#
# Use BASH_SOURCE[0] — more reliable than $0 when invoked as:
#   sudo bash cycentra-setup.sh          (relative path, $0 = 'cycentra-setup.sh')
#   sudo bash /tmp/.../cycentra-setup.sh  (absolute path)
#   sudo -E bash ...                      (with preserved env)
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
BUNDLE_DIR="/tmp/cycentra-release"

if [[ -f "$_SCRIPT_DIR/manifest.json" ]]; then
    info "Local bundle detected — skipping download"
    BUNDLE_DIR="$_SCRIPT_DIR"
    # Resolve version from local bundle for the update-mode pre-check below
    CYCENTRA_VERSION=$(cat "$_SCRIPT_DIR/VERSION" 2>/dev/null || jq -r '.version' "$_SCRIPT_DIR/manifest.json" 2>/dev/null || echo "unknown")
    _RELEASE_JSON=""
else
    # ── Remote download path: requires GH_TOKEN ───────────────────────────────
    if [[ -z "$GH_TOKEN" ]]; then
        error "GH_TOKEN is not set and could not be resolved. Ensure it is exported or set in the environment."
        exit 1
    fi

    # Step 1: resolve latest release metadata (single API call — no maven)
    info "Fetching latest release metadata from GitHub..."
    _RELEASE_JSON=$(curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${GH_ORG}/${GH_REPO}/releases/latest")

    CYCENTRA_VERSION=$(echo "$_RELEASE_JSON" | jq -r '.tag_name')
    [[ -z "$CYCENTRA_VERSION" || "$CYCENTRA_VERSION" == "null" ]] && \
        { error "Could not resolve latest release from GitHub API — check GH_TOKEN (needs repo scope)"; exit 1; }
    info "Latest release: ${CYCENTRA_VERSION}"

    # Step 2: find bundle asset URL from release metadata
    _bundle_asset_url=$(echo "$_RELEASE_JSON" | \
        jq -r '.assets[] | select(.name | contains("cycentra-release")) | .url' | head -1)
    [[ -z "$_bundle_asset_url" || "$_bundle_asset_url" == "null" ]] && \
        { error "Bundle asset not found in release ${CYCENTRA_VERSION} — check CI published correctly"; exit 1; }

    # Step 3: download via asset API URL (required for private repos — direct URL returns 404)
    rm -rf "$BUNDLE_DIR" /tmp/cycentra-release.tar.gz
    info "Downloading release bundle..."
    curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/octet-stream" \
        "$_bundle_asset_url" \
        -o /tmp/cycentra-release.tar.gz \
        && success "Bundle downloaded" \
        || { error "Bundle download failed — check GH_TOKEN permissions"; exit 1; }
    tar -xzf /tmp/cycentra-release.tar.gz -C /tmp/
fi

# ── Version pre-check (update mode only) ─────────────────────────────────────
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

MANIFEST="$BUNDLE_DIR/manifest.json"
[[ ! -f "$MANIFEST" ]] && { error "manifest.json not found in bundle at ${BUNDLE_DIR}"; exit 1; }

BUNDLE_VERSION=$(jq -r '.version'    "$MANIFEST")
PKG_VER=$(jq        -r '.ver_number' "$MANIFEST")
PKG_NAME="cycentra-backend"

# Wheel asset URL — resolved from the same release metadata (no maven required).
# Falls back to empty; the download step below handles missing asset gracefully.
if [[ -n "${_RELEASE_JSON:-}" ]]; then
    WHEEL_URL=$(echo "$_RELEASE_JSON" | \
        jq -r --arg ver "$PKG_VER" \
        '.assets[] | select(.name | test("cycentra.backend.*\\.whl")) | .url' | head -1)
else
    WHEEL_URL=""
fi

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
_SETUP_DEST="/opt/cycentra/cycentra-setup.sh"
if [[ "$_SELF" != "$_SETUP_DEST" ]]; then
    cp "$_SELF" "$_SETUP_DEST"
    chmod 750  "$_SETUP_DEST"
    success "Setup script deployed to $_SETUP_DEST"
else
    success "Setup script already at $_SETUP_DEST — no copy needed"
fi

# Deploy license validator + watchdog scripts
_SCRIPT_BASE="$(dirname "$(realpath "${BASH_SOURCE[0]:-$0}")")"
if [[ -f "$_SCRIPT_BASE/license_validator.py" ]]; then
    cp "$_SCRIPT_BASE/license_validator.py" /opt/cycentra/license_validator.py
    chmod 755 /opt/cycentra/license_validator.py
    success "License validator deployed → /opt/cycentra/license_validator.py"
elif [[ -f "$BUNDLE_DIR/license_validator.py" ]]; then
    cp "$BUNDLE_DIR/license_validator.py" /opt/cycentra/license_validator.py
    chmod 755 /opt/cycentra/license_validator.py
    success "License validator deployed from bundle"
else
    warn "license_validator.py not found — license enforcement disabled"
fi

# If a license file is present alongside the installer, copy it in
if [[ -f "$_SCRIPT_BASE/cycentra.lic" && ! -f /opt/cycentra/cycentra.lic ]]; then
    cp "$_SCRIPT_BASE/cycentra.lic" /opt/cycentra/cycentra.lic
    chmod 600 /opt/cycentra/cycentra.lic
    success "License file installed → /opt/cycentra/cycentra.lic"
fi
# ── Step 6-9: Interactive config (full install only) ─────────────────────────

if [[ "$MODE" == "full" ]]; then
    # Use BASE_DOMAIN from earlier prompt or .env
    if [[ ! -f "/opt/cycentra/.env" ]]; then
        BASE_DOMAIN="${BASE_DOMAIN:-cycentra.com}"
    else
        source /opt/cycentra/.env
        BASE_DOMAIN="${BASE_DOMAIN:-cycentra.com}"
    fi
    
    # ── No interactive prompts — all config is set via environment variables or
    # ── edited in /opt/cycentra/.env post-install.
    CLIENT_NAME="${CLIENT_NAME:-cycentra}"
    CLIENT_EMAIL="${CLIENT_EMAIL:-admin@cycentra.com}"
    BASE_DOMAIN="${BASE_DOMAIN:-cycentra.com}"
    OAUTH_PROVIDER="${OAUTH_PROVIDER:-google}"
    # ── OAuth credentials — loaded from Azure Key Vault at runtime.
    # Written as empty here; the app fetches them from Key Vault on startup
    # (AZURE_KEYVAULT_URL must be set in .env pointing to your vault).
    GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID:-}"
    GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET:-}"
    MICROSOFT_CLIENT_ID="${MICROSOFT_CLIENT_ID:-}"
    MICROSOFT_CLIENT_SECRET="${MICROSOFT_CLIENT_SECRET:-}"
    AI_PROVIDER="none"; AI_API_KEY=""; AI_MODEL=""
    SMTP_HOST=""; SMTP_PORT=""; SMTP_USER=""; SMTP_PASS=""; SUPPORT_EMAIL="support@${BASE_DOMAIN}"
    INSTALL_CYSIEM=true; INSTALL_CYIRIS=true; INSTALL_CYSOAR=true

    info "Domain : ${BASE_DOMAIN}  |  OAuth: ${OAUTH_PROVIDER}"
    info "Post-install → edit /opt/cycentra/.env and restart: systemctl restart cycentra"

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
    CYSIEM_OIDC_SECRET=$(gen_secret)
    # oauth2-proxy: client secret (used by CyCentra OIDC) + 32-byte cookie secret
    OAUTH2PROXY_SECRET=$(gen_secret)
    OAUTH2PROXY_COOKIE_SECRET=$(openssl rand -base64 32 | tr -d '\n' | head -c 32)
    success "All secrets ready"

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

    # ── Patch .env for update mode ────────────────────────────────────────────
    # SAFE: only removes specific dead/orphaned vars by name, and only appends
    # vars that are missing entirely.  Customer custom entries ARE preserved.
    # The full .env is NEVER rewritten in update mode — only surgical edits.
    step_header "PATCHING /opt/cycentra/.env"
    _env="/opt/cycentra/.env"

    # Remove dead / orphaned variables
    for _dead in USE_CUSTOM_IMAGES SIEM_LLM_ENABLED SIEM_MISP_ENABLED \
                 AI_PROVIDER AI_API_KEY AI_MODEL; do
        if grep -q "^${_dead}=" "$_env" 2>/dev/null; then
            sed -i "/^${_dead}=/d" "$_env"
            info "Removed orphaned var: ${_dead}"
        fi
    done

    # Add CLOUD_MISP_* if missing (introduced in v1.0.X)
    if ! grep -q "^CLOUD_MISP_URL=" "$_env" 2>/dev/null; then
        cat >> "$_env" << PATCHEOF

# ── Cloud CyMISP (Cycentra-managed MISP at cymisp.cycentra.com) ────────────────
CLOUD_MISP_URL=${CLOUD_MISP_URL:-}
CLOUD_MISP_API_KEY=${CLOUD_MISP_API_KEY:-}
AZURE_KEYVAULT_URL=${AZURE_KEYVAULT_URL:-}
PATCHEOF
        info "Added CLOUD_MISP_* to .env"
    fi

    # Add CLOUD_IRIS_* if missing (introduced in v1.0.X)
    if ! grep -q "^CLOUD_IRIS_URL=" "$_env" 2>/dev/null; then
        cat >> "$_env" << PATCHEOF

# ── Cloud CyIRIS (Cycentra-managed DFIR IRIS at cyiris.cycentra.com) ──────────
CLOUD_IRIS_URL=https://cyiris.cycentra.com
CLOUD_IRIS_API_KEY=${CLOUD_IRIS_API_KEY:-}
CLOUD_IRIS_CUSTOMER_ID=${CLOUD_IRIS_CUSTOMER_ID:-1}
PATCHEOF
        info "Added CLOUD_IRIS_* to .env"
    fi

    # Add CYSIEM_OIDC_SECRET if missing (SSO v1 — introduced with full OIDC)
    if ! grep -q "^CYSIEM_OIDC_SECRET=" "$_env" 2>/dev/null; then
        echo "CYSIEM_OIDC_SECRET=$(openssl rand -hex 32)" >> "$_env"
        info "Added CYSIEM_OIDC_SECRET to .env"
    fi

    # Add IAP oauth2-proxy secrets if missing (introduced with IAP switch)
    if ! grep -q "^OAUTH2PROXY_SECRET=" "$_env" 2>/dev/null; then
        _new_oauth2_secret=$(openssl rand -hex 32)
        _new_cookie_secret=$(openssl rand -base64 32 | tr -d '\n' | head -c 32)
        cat >> "$_env" << PATCHEOF

# ── IAP oauth2-proxy secrets ───────────────────────────────────────────────────
OAUTH2PROXY_SECRET=${_new_oauth2_secret}
OAUTH2PROXY_COOKIE_SECRET=${_new_cookie_secret}
PATCHEOF
        info "Added OAUTH2PROXY_SECRET + OAUTH2PROXY_COOKIE_SECRET to .env"
        # Export into current session so the IAP setup step below can use them
        OAUTH2PROXY_SECRET="$_new_oauth2_secret"
        OAUTH2PROXY_COOKIE_SECRET="$_new_cookie_secret"
    fi

    chmod 600 "$_env"
    success ".env patched"
fi

# ── Step 10: Write .env files (full install only) ─────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "WRITING CONFIGURATION FILES"
    mkdir -p /opt/cycentra && chmod 700 /opt/cycentra

    # Reset demo clock on every fresh full install — prevents a stale .demo_start
    # from a previous installation on the same server from immediately expiring the demo.
    chattr -i /opt/cycentra/.demo_start 2>/dev/null || true
    date -u +"%Y-%m-%d" > /opt/cycentra/.demo_start
    chattr +i /opt/cycentra/.demo_start 2>/dev/null || true
    chattr -i /opt/cycentra/.license_expired 2>/dev/null || true
    rm -f /opt/cycentra/.license_expired
    info "Demo clock reset to today ($(cat /opt/cycentra/.demo_start))"

    cat > /opt/cycentra/.env << ENVEOF
# CyCentra 360 — generated by setup wizard v7.1
# Version: ${BUNDLE_VERSION} | Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

BASE_DOMAIN=${BASE_DOMAIN}
CLIENT_NAME=${CLIENT_NAME}
SECRET_KEY=${FLASK_SECRET}
JWT_SECRET=${JWT_SECRET}
ADMIN_API_KEY=${ADMIN_API_KEY}
FRONTEND_URL=https://cysoc.${BASE_DOMAIN}
BASE_URL=https://cyasm.${BASE_DOMAIN}
OAUTH_PROVIDER=${OAUTH_PROVIDER}
ENVEOF

    # Always write all OAuth credentials so admins can switch provider by
    # editing a single OAUTH_PROVIDER line in /opt/cycentra/.env
    cat >> /opt/cycentra/.env << ENVEOF
# OAuth — Google SSO
GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}

# OAuth — Microsoft Azure AD
MICROSOFT_CLIENT_ID=${MICROSOFT_CLIENT_ID}
MICROSOFT_CLIENT_SECRET=${MICROSOFT_CLIENT_SECRET}
ENVEOF

    cat >> /opt/cycentra/.env << ENVEOF

CYIRIS_OIDC_SECRET=${CYIRIS_OIDC_SECRET}
CYSOAR_OIDC_SECRET=${CYSOAR_OIDC_SECRET}
CYSIEM_OIDC_SECRET=${CYSIEM_OIDC_SECRET}

# ── IAP oauth2-proxy ────────────────────────────────────────────────────────────
# oauth2-proxy uses OIDC against cyasm.DOMAIN. It is the single SSO gate for
# cyiris, cysoar, and cysiem subdomains via nginx auth_request.
OAUTH2PROXY_SECRET=${OAUTH2PROXY_SECRET}
OAUTH2PROXY_COOKIE_SECRET=${OAUTH2PROXY_COOKIE_SECRET}

IRIS_SECRET=${IRIS_SECRET}
IRIS_DB_PASS=${IRIS_DB_PASS}
IRIS_ADM_EMAIL=${CLIENT_EMAIL}
IRIS_ADM_PASSWORD=${IRIS_ADM_PASSWORD:-}
CYCENTRA_PORTAL_URL=https://cysoc.${BASE_DOMAIN}
IRIS_SECRET_KEY=${IRIS_SECRET}
POSTGRES_PASSWORD=${IRIS_DB_PASS}
NODE_RED_CREDENTIAL_SECRET=${NODERED_SECRET}

SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-}
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SUPPORT_EMAIL=${SUPPORT_EMAIL:-support@cycentra.com}

SIEM_ENGINE_URL=http://127.0.0.1:8100

# GitHub token — used by the portal backend to download updates/upgrades without
# requiring the customer to enter it in the UI.  Set via GH_TOKEN env var at install time.
GH_TOKEN=${GH_TOKEN:-}

# ── Cloud CyMISP (Cycentra-managed MISP at cymisp.cycentra.com) ────────────────
# When a customer selects "Cloud CyMISP" in System Settings > Integrations, the
# backend uses these credentials automatically.  CLOUD_MISP_API_KEY must be set
# to the vendor-issued API key for this installation.
CLOUD_MISP_URL=${CLOUD_MISP_URL:-}
CLOUD_MISP_API_KEY=${CLOUD_MISP_API_KEY:-}

# ── Cloud CyIRIS (Cycentra-managed DFIR IRIS at cyiris.cycentra.com) ──────────
# When a customer selects "Cloud CyIRIS" in System Settings > Integrations, the
# backend uses these credentials automatically.  CLOUD_IRIS_API_KEY must be set
# to the vendor-issued API key for this installation.
CLOUD_IRIS_URL=${CLOUD_IRIS_URL:-}
CLOUD_IRIS_API_KEY=${CLOUD_IRIS_API_KEY:-}
CLOUD_IRIS_CUSTOMER_ID=${CLOUD_IRIS_CUSTOMER_ID:-1}

# ── Azure Key Vault — set to your vault URL to enable secret bootstrap ─────────
# The app fetches GOOGLE_CLIENT_ID/SECRET, MICROSOFT_CLIENT_ID/SECRET,
# MAXMIND_KEY, GH_TOKEN, IRIS_ADM_PASSWORD, CLOUD_MISP_*, CLOUD_IRIS_*
# from Key Vault at startup when this is set.
# Auth: Managed Identity (Azure VM) or AZURE_CLIENT_ID/SECRET/TENANT_ID env vars.
AZURE_KEYVAULT_URL=${AZURE_KEYVAULT_URL:-}
ENVEOF
    # MAXMIND_KEY pulled from Key Vault at runtime — not written here
    echo "MAXMIND_KEY=${MAXMIND_KEY:-}" >> /opt/cycentra/.env
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
INCIDENT_MAX_AGE_MINUTES=30
UEBA_BASELINE_DAYS=30
RISK_DECAY_HOURS=24
INCIDENT_ID_PREFIX=INC
LOG_LEVEL=INFO
UEBA_ML_SHADOW_MODE=true
UEBA_ML_MIN_TRAIN_DAYS=7
UEBA_ML_MODEL_DIR=/opt/cycentra/ml_models
MISP_ENABLED=false
# Security MCP bridge — exposes 11 SIEM/Wazuh tools to AI clients at /mcp/sse
# Set to false to disable the bridge without uninstalling the mcp package.
MCP_ENABLED=true
# Standalone key so --update mode can read the password without parsing DATABASE_URL
POSTGRES_PASSWORD=${CORR_DB_PASS}
# Azure Key Vault — engine fetches WAZUH_API_PASSWORD from KV when set
AZURE_KEYVAULT_URL=${AZURE_KEYVAULT_URL:-}
SIEMEOF
    chmod 600 /opt/cycentra/cysiemstack.env
    success "cysiemstack.env written → /opt/cycentra/cysiemstack.env"

    # Create ML model persistence directory
    mkdir -p /opt/cycentra/ml_models
    chmod 755 /opt/cycentra/ml_models
    success "ML model directory created → /opt/cycentra/ml_models"

fi  # end full env block

# ── Step 4.3b: IAP Gateway — oauth2-proxy + Wazuh proxy auth ─────────────────
# Runs in all modes (full / update). Idempotent.
# oauth2-proxy: single OIDC gate for cyiris, cysoar, cysiem subdomains.
# Wazuh: switches Dashboard to proxy auth mode (reads X-Proxy-User from nginx).
# OpenSearch Security also needs proxy_auth_domain enabled and rolesmapping updated
# (all_access backend role → all_access OpenSearch role) for Dashboard proxy auth to
# work end-to-end.  Both are applied below via REST API (primary) and
# securityadmin.sh (fallback).

step_header "IAP GATEWAY (oauth2-proxy)"

# Load vars from .env if not already in memory (update mode)
[[ -z "${BASE_DOMAIN:-}" ]] && \
    BASE_DOMAIN=$(grep "^BASE_DOMAIN=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)
BASE_DOMAIN="${BASE_DOMAIN:-cycentra.com}"
[[ -z "${OAUTH2PROXY_SECRET:-}" ]] && \
    OAUTH2PROXY_SECRET=$(grep "^OAUTH2PROXY_SECRET=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)
[[ -z "${OAUTH2PROXY_COOKIE_SECRET:-}" ]] && \
    OAUTH2PROXY_COOKIE_SECRET=$(grep "^OAUTH2PROXY_COOKIE_SECRET=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)

if [[ -z "$OAUTH2PROXY_SECRET" || -z "$OAUTH2PROXY_COOKIE_SECRET" ]]; then
    warn "oauth2-proxy secrets missing in .env — IAP setup skipped; re-run --update"
else
    # ── Pull and start oauth2-proxy container ───────────────────────────────────
    # Runs on 127.0.0.1:4180. nginx uses it as an internal auth_request backend.
    # Cookie domain .BASE_DOMAIN means ONE login covers all subdomains.
    _OAUTH2_PROXY_IMAGE="quay.io/oauth2-proxy/oauth2-proxy:latest"

    if docker ps -q --filter "name=cy-proxy" 2>/dev/null | grep -q .; then
        info "cy-proxy container already running — checking config..."
        # Compare cookie domain to detect domain change; recreate if needed
        _running_domain=$(docker inspect cy-proxy 2>/dev/null \
            | python3 -c "import sys,json; e=json.load(sys.stdin)[0]['Config']['Env']; \
              print(next((x.split('=',1)[1] for x in e if x.startswith('OAUTH2_PROXY_COOKIE_DOMAINS=')),'')" 2>/dev/null || true)
        if [[ "$_running_domain" == ".${BASE_DOMAIN}" ]]; then
            info "cy-proxy already configured for .${BASE_DOMAIN} — no restart needed"
        else
            info "cy-proxy domain changed — recreating container"
            docker rm -f cy-proxy 2>/dev/null || true
        fi
    fi

    if ! docker ps -q --filter "name=cy-proxy" 2>/dev/null | grep -q .; then
        docker pull "$_OAUTH2_PROXY_IMAGE" 2>/dev/null || \
            warn "oauth2-proxy pull failed — using cached image if available"

        docker run -d \
            --name cy-proxy \
            --restart unless-stopped \
            --network host \
            -e OAUTH2_PROXY_PROVIDER=oidc \
            -e OAUTH2_PROXY_OIDC_ISSUER_URL="https://cyasm.${BASE_DOMAIN}/oidc" \
            -e OAUTH2_PROXY_CLIENT_ID=oauth2proxy \
            -e OAUTH2_PROXY_CLIENT_SECRET="${OAUTH2PROXY_SECRET}" \
            -e OAUTH2_PROXY_REDIRECT_URL="https://cysoc.${BASE_DOMAIN}/oauth2/callback" \
            -e OAUTH2_PROXY_HTTP_ADDRESS="127.0.0.1:4180" \
            -e OAUTH2_PROXY_COOKIE_SECRET="${OAUTH2PROXY_COOKIE_SECRET}" \
            -e OAUTH2_PROXY_COOKIE_DOMAINS=".${BASE_DOMAIN}" \
            -e OAUTH2_PROXY_WHITELIST_DOMAINS=".${BASE_DOMAIN}" \
            -e OAUTH2_PROXY_EMAIL_DOMAINS="*" \
            -e OAUTH2_PROXY_SCOPE="openid email profile" \
            -e OAUTH2_PROXY_SET_XAUTHREQUEST=true \
            -e OAUTH2_PROXY_PASS_ACCESS_TOKEN=false \
            -e OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER=false \
            -e OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true \
            -e OAUTH2_PROXY_SKIP_JWT_BEARER_TOKENS=false \
            -e OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY=true \
            -e OAUTH2_PROXY_COOKIE_SECURE=true \
            -e OAUTH2_PROXY_COOKIE_SAMESITE=lax \
            -e OAUTH2_PROXY_SESSION_STORE_TYPE=cookie \
            -e OAUTH2_PROXY_UPSTREAMS="http://127.0.0.1:5252" \
            "$_OAUTH2_PROXY_IMAGE" \
        && success "cy-proxy (oauth2-proxy) started on 127.0.0.1:4180" \
        || { warn "oauth2-proxy container failed to start — check: docker logs cy-proxy"; \
             ERRORS+=("oauth2-proxy failed to start"); }
    fi

    # ── Wazuh Dashboard: switch to proxy auth mode ──────────────────────────────
    # Remove all OIDC settings, add proxy auth.
    # NOTE: proxy mode still requires two OpenSearch Security changes:
    #   1. proxy_auth_domain http_enabled: true  (applied via securityadmin.sh)
    #   2. all_access rolesmapping entry          (applied via REST API or securityadmin.sh)
    # Both are attempted below; see "OpenSearch Security" section.
    if [[ -f "$_WAZUH_DASH_YML" ]]; then
        step_header "CySIEM PROXY AUTH"
        cp "$_WAZUH_DASH_YML" "${_WAZUH_DASH_YML}.pre-iap-$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

        # Use Python to rewrite cleanly — avoids null bytes from shell heredocs,
        # idempotent (strips old proxy/OIDC lines before re-adding).
        python3 - "$_WAZUH_DASH_YML" << 'WAZUH_PY_EOF'
import sys
path = sys.argv[1]
with open(path, "rb") as f:
    raw = f.read().replace(b"\x00", b"")
text = raw.decode("utf-8")
remove_prefixes = [
    "opensearch_security.auth.type",
    "opensearch_security.proxycache.",
    "opensearch_security.openid.",
    "opensearch.requestHeadersAllowlist",
    "# CyCentra 360 IAP proxy auth",
    "# Authentication gate:",
    "# Wazuh trusts",
]
cleaned = "\n".join(
    line for line in text.splitlines()
    if not any(line.strip().startswith(p) for p in remove_prefixes)
).rstrip() + "\n"
cleaned += (
    "# CyCentra 360 IAP proxy auth — written by cycentra-setup.sh\n"
    "opensearch_security.auth.type: proxy\n"
    "opensearch_security.proxycache.user_header: \"x-proxy-user\"\n"
    "opensearch_security.proxycache.roles_header: \"x-proxy-roles\"\n"
    "opensearch.requestHeadersAllowlist: [\"securitytenant\",\"Authorization\",\"x-proxy-user\",\"x-proxy-roles\"]\n"
)
with open(path, "w") as f:
    f.write(cleaned)
print("Wazuh proxy auth config written")
WAZUH_PY_EOF

        # ── OpenSearch Security: enable proxy_auth_domain ────────────────────────
        # The Dashboard proxy auth requires OpenSearch to accept proxy headers.
        # Enable http_enabled under proxy_auth_domain in the security config and
        # apply via the REST API (primary) or securityadmin.sh (fallback).
        _OS_SEC_CFG="/etc/wazuh-indexer/opensearch-security/config.yml"
        _CY_SEC_LOG="/var/log/cycentra/securityadmin.log"
        mkdir -p /var/log/cycentra 2>/dev/null || true
        if [[ -f "$_OS_SEC_CFG" ]]; then
            # Patch config.yml on disk: enable proxy_auth_domain.http_enabled.
            # Bugs in the previous state-machine:
            #   1. Exit condition "indent <= 4" never fired for blocks at indent 6
            #      (siblings were not detected, other domains got patched too).
            #   2. Script always printed "enabled" even when the block was absent
            #      (file written back unchanged, securityadmin then uploaded a
            #      config that still had http_enabled: false — silent no-op).
            # Fixed: use indent-relative exit; create the block if absent; exit 1
            # when no change was made so the caller can report a real warning.
            python3 - "$_OS_SEC_CFG" << 'OS_SEC_PY_EOF'
import sys
path = sys.argv[1]
with open(path, "r") as f:
    text = f.read()
lines = text.splitlines()
out = []
in_proxy_domain   = False
proxy_dom_indent  = -1
found             = False
patched           = False
for line in lines:
    stripped = line.lstrip()
    indent   = len(line) - len(stripped)
    if stripped.startswith("proxy_auth_domain:"):
        in_proxy_domain  = True
        proxy_dom_indent = indent
        found            = True
        out.append(line)
        continue
    if in_proxy_domain:
        # Exit when we reach a sibling key (same indent) or a parent (shallower).
        # This replaces the previous "indent <= 4" heuristic which never fired
        # for blocks indented at 6+ spaces and caused unintended side-effects on
        # sibling auth domains (e.g. jwt_auth_domain, ldap).
        if stripped and not stripped.startswith("#") and indent <= proxy_dom_indent:
            in_proxy_domain = False
            # fall through to normal append below
        elif stripped.startswith("http_enabled:") and not patched:
            out.append(line.replace("http_enabled: false", "http_enabled: true"))
            patched = True
            continue
    out.append(line)
# If the block was absent altogether, inject it just before
# basic_internal_auth_domain so the indentation matches the rest of authc.
if not found:
    new_lines = []
    for line in out:
        if line.lstrip().startswith("basic_internal_auth_domain:") and not patched:
            base_indent = " " * (len(line) - len(line.lstrip()))
            child_indent = base_indent + "  "
            new_lines += [
                base_indent + "proxy_auth_domain:",
                child_indent + 'description: "CyCentra 360 IAP proxy authentication"',
                child_indent + "http_enabled: true",
                child_indent + "transport_enabled: false",
                child_indent + "order: 1",
                child_indent + "http_authenticator:",
                child_indent + "  type: proxy",
                child_indent + "  challenge: false",
                child_indent + "  config:",
                child_indent + '    user_header: "x-proxy-user"',
                child_indent + '    roles_header: "x-proxy-roles"',
                child_indent + "authentication_backend:",
                child_indent + "  type: noop",
            ]
            patched = True
        new_lines.append(line)
    out = new_lines
with open(path, "w") as f:
    f.write("\n".join(out) + "\n")
if patched:
    print("OpenSearch proxy_auth_domain patched in config.yml")
    sys.exit(0)
else:
    print("WARNING: proxy_auth_domain not found and basic_internal_auth_domain "
          "anchor missing — config.yml not modified", file=sys.stderr)
    sys.exit(1)
OS_SEC_PY_EOF
            _cfg_py_rc=$?

            # ── Apply OpenSearch Security changes for proxy auth ──────────────────
            # Two changes are required:
            #   1. proxy_auth_domain http_enabled: true  — allows Dashboard to forward
            #      proxy headers to OpenSearch Security for user authentication.
            #   2. all_access rolesmapping               — maps the "all_access" backend
            #      role (sent by nginx as X-Proxy-Roles) to the all_access OpenSearch role.
            # Without both, the Wazuh Dashboard shows the native login screen for ALL
            # proxy-authenticated users instead of logging them in automatically.
            #
            # Strategy: wait for the indexer to be ready, then try:
            #   (a) REST API securityconfig GET+PATCH+PUT (primary — no JVM required)
            #   (b) securityadmin.sh with the on-disk config.yml (fallback)
            _SEC_ADMIN="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
            _CERT_DIR="/etc/wazuh-indexer/certs"

            if [[ -f "${_CERT_DIR}/admin.pem" ]]; then
                # ── 1. Wait for OpenSearch indexer (up to 90 s) ──────────────────────
                # securityadmin.sh silently fails when the indexer hasn't finished
                # starting.  A readiness check prevents the silent failure that leaves
                # proxy_auth_domain disabled and causes the login-screen loop.
                info "Waiting for OpenSearch indexer to be ready (up to 90 s)..."
                _INDEXER_READY=false
                for _idx_n in $(seq 1 18); do
                    _idx_code=$(curl -sk -o /dev/null -w '%{http_code}' \
                        --cert "${_CERT_DIR}/admin.pem" \
                        --key  "${_CERT_DIR}/admin-key.pem" \
                        "https://127.0.0.1:9200/_cluster/health" 2>/dev/null || true)
                    # Accept only 2xx — 3xx redirects indicate misconfiguration
                    if [[ "$_idx_code" =~ ^2 ]]; then
                        _INDEXER_READY=true
                        success "OpenSearch indexer ready (HTTP ${_idx_code})"
                        break
                    fi
                    sleep 5
                done

                if [[ "$_INDEXER_READY" != "true" ]]; then
                    warn "OpenSearch indexer not reachable after 90 s — security config skipped; re-run --update once Wazuh is healthy"
                else
                    # ── 2a. Enable proxy_auth_domain via REST API (primary) ───────────
                    # GET the live security config, patch proxy_auth_domain.http_enabled
                    # in Python, then PUT it back.  This is more reliable than
                    # securityadmin.sh (no JVM dependency, no "cd /" requirement, no
                    # Java heap / timeout issues).  Falls back to securityadmin.sh when
                    # the endpoint returns a non-200 or the PUT is rejected.
                    _CONFIG_APPLIED=false
                    _cfg_get_code=$(curl -sk -o /tmp/_cy_sec_cfg.json -w '%{http_code}' \
                        --cert "${_CERT_DIR}/admin.pem" \
                        --key  "${_CERT_DIR}/admin-key.pem" \
                        "https://127.0.0.1:9200/_plugins/_security/api/securityconfig" \
                        2>/dev/null || true)
                    if [[ "$_cfg_get_code" == "200" && -s /tmp/_cy_sec_cfg.json ]]; then
                        python3 - /tmp/_cy_sec_cfg.json /tmp/_cy_sec_patch.json << 'SEC_REST_PY'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
try:
    with open(src) as f:
        raw = json.load(f)
    dynamic = raw.get("config", {}).get("dynamic", {})
    authc   = dynamic.setdefault("authc", {})
    if "proxy_auth_domain" not in authc:
        authc["proxy_auth_domain"] = {
            "http_enabled": True,
            "transport_enabled": False,
            "order": 1,
            "http_authenticator": {
                "type": "proxy",
                "challenge": False,
                "config": {
                    "user_header": "x-proxy-user",
                    "roles_header": "x-proxy-roles",
                },
            },
            "authentication_backend": {"type": "noop"},
        }
        print("proxy_auth_domain block created via REST patch")
    else:
        authc["proxy_auth_domain"]["http_enabled"] = True
        print("proxy_auth_domain http_enabled set via REST patch")
    with open(dst, "w") as f:
        json.dump({"dynamic": dynamic}, f)
    sys.exit(0)
except Exception as exc:
    print(f"REST patch error: {exc}", file=sys.stderr)
    sys.exit(1)
SEC_REST_PY
                        if [[ $? -eq 0 && -s /tmp/_cy_sec_patch.json ]]; then
                            _cfg_put_code=$(curl -sk -o /dev/null -w '%{http_code}' \
                                --cert "${_CERT_DIR}/admin.pem" \
                                --key  "${_CERT_DIR}/admin-key.pem" \
                                -X PUT \
                                "https://127.0.0.1:9200/_plugins/_security/api/securityconfig/config" \
                                -H "Content-Type: application/json" \
                                -d @/tmp/_cy_sec_patch.json \
                                2>/dev/null || true)
                            if [[ "$_cfg_put_code" =~ ^(200|201)$ ]]; then
                                _CONFIG_APPLIED=true
                                success "OpenSearch proxy_auth_domain enabled via REST API"
                            else
                                info "REST API securityconfig PUT returned ${_cfg_put_code} — trying securityadmin fallback"
                            fi
                            rm -f /tmp/_cy_sec_patch.json
                        fi
                        rm -f /tmp/_cy_sec_cfg.json
                    else
                        info "GET securityconfig returned ${_cfg_get_code} — trying securityadmin fallback"
                        rm -f /tmp/_cy_sec_cfg.json
                    fi

                    # ── 2b. Enable proxy_auth_domain via securityadmin.sh (fallback) ──
                    # Stderr is written to $_CY_SEC_LOG instead of /dev/null so any
                    # JVM or YAML errors are visible for post-install diagnosis.
                    if [[ "$_CONFIG_APPLIED" != "true" ]]; then
                        if [[ -x "$_SEC_ADMIN" && "$_cfg_py_rc" -eq 0 ]]; then
                            export JAVA_HOME=/usr/share/wazuh-indexer/jdk
                            cd /
                            "$_SEC_ADMIN" \
                                -f "$_OS_SEC_CFG" -t config \
                                -icl -nhnv \
                                -cacert "${_CERT_DIR}/root-ca.pem" \
                                -cert   "${_CERT_DIR}/admin.pem" \
                                -key    "${_CERT_DIR}/admin-key.pem" \
                                -h 127.0.0.1 2>>"$_CY_SEC_LOG" \
                                && { _CONFIG_APPLIED=true; \
                                     success "OpenSearch proxy_auth_domain applied via securityadmin"; } \
                                || warn "securityadmin.sh failed for config.yml — see ${_CY_SEC_LOG} for details"
                        elif [[ ! -x "$_SEC_ADMIN" ]]; then
                            warn "securityadmin.sh not found — proxy_auth_domain config skipped"
                        else
                            warn "config.yml patch failed (Python exit ${_cfg_py_rc}) — securityadmin skipped; check ${_OS_SEC_CFG}"
                        fi
                    fi

                    [[ "$_CONFIG_APPLIED" != "true" ]] && \
                        warn "proxy_auth_domain NOT enabled in OpenSearch — Wazuh SSO will show a login screen; re-run --update to retry"

                    # ── 3. Apply rolesmapping: REST API (primary) or securityadmin (fallback) ─
                    # The REST API PUT per-role endpoint is preferred: it patches only the
                    # target roles without wiping the full rolesmapping, requires no JVM,
                    # and uses the same admin certs via mTLS.
                    # CRITICAL roles:
                    #   all_access   — backend_roles ["admin","all_access"] lets nginx
                    #                  X-Proxy-Roles: all_access grant full Dashboard access.
                    #   kibana_server — maps kibanaserver service account (Dashboard→OpenSearch).
                    _RM_APPLIED=false

                    _rm_aa_code=$(curl -sk -o /dev/null -w '%{http_code}' \
                        --cert "${_CERT_DIR}/admin.pem" \
                        --key  "${_CERT_DIR}/admin-key.pem" \
                        -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/all_access" \
                        -H 'Content-Type: application/json' \
                        -d '{"backend_roles":["admin","all_access"],"hosts":[],"users":[]}' \
                        2>/dev/null || true)
                    _rm_ks_code=$(curl -sk -o /dev/null -w '%{http_code}' \
                        --cert "${_CERT_DIR}/admin.pem" \
                        --key  "${_CERT_DIR}/admin-key.pem" \
                        -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/kibana_server" \
                        -H 'Content-Type: application/json' \
                        -d '{"backend_roles":[],"hosts":[],"users":["kibanaserver"]}' \
                        2>/dev/null || true)

                    if [[ "$_rm_aa_code" =~ ^(200|201)$ && "$_rm_ks_code" =~ ^(200|201)$ ]]; then
                        # REST API returns 200 when updating an existing mapping,
                        # 201 when creating a new one — both are success.
                        _RM_APPLIED=true
                        success "OpenSearch rolesmapping applied via REST API (all_access + kibana_server)"
                    else
                        warn "REST API rolesmapping returned ${_rm_aa_code}/${_rm_ks_code} — trying securityadmin fallback"
                    fi

                    # Fallback: securityadmin.sh -t rolesmapping (replaces entire mapping —
                    # must include all critical entries to avoid wiping kibana_server)
                    if [[ "$_RM_APPLIED" != "true" && -x "$_SEC_ADMIN" ]]; then
                        cat > /tmp/_cy_rolesmapping.yml << 'CY_ROLES_EOF'
_meta:
  type: "rolesmapping"
  config_version: 2

all_access:
  reserved: false
  hidden: false
  backend_roles:
  - "admin"
  - "all_access"
  hosts: []
  users: []
  and_backend_roles: []

kibana_server:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "kibanaserver"
  and_backend_roles: []

kibana_user:
  reserved: false
  hidden: false
  backend_roles:
  - "kibanauser"
  hosts: []
  users: []
  and_backend_roles: []

wazuh_ui_user:
  reserved: false
  backend_roles:
  - "wazuh_ui_user"
  users: []

wazuh_ui_admin:
  reserved: false
  backend_roles:
  - "wazuh_ui_admin"
  users: []

own_index:
  reserved: false
  users:
  - "*"
  and_backend_roles: []
CY_ROLES_EOF
                        "$_SEC_ADMIN" \
                            -f /tmp/_cy_rolesmapping.yml -t rolesmapping \
                            -icl -nhnv \
                            -cacert "${_CERT_DIR}/root-ca.pem" \
                            -cert   "${_CERT_DIR}/admin.pem" \
                            -key    "${_CERT_DIR}/admin-key.pem" \
                            -h 127.0.0.1 2>/dev/null \
                            && { _RM_APPLIED=true; \
                                 success "OpenSearch rolesmapping applied via securityadmin (all_access + kibana_server)"; } \
                            || warn "rolesmapping apply failed — Wazuh SSO users may lack access; re-run --update"
                        rm -f /tmp/_cy_rolesmapping.yml
                    fi

                    [[ "$_RM_APPLIED" != "true" ]] && \
                        warn "OpenSearch rolesmapping not applied — X-Proxy-Roles: all_access will not grant Dashboard access until rolesmapping is updated"
                fi
            else
                warn "admin.pem not found at ${_CERT_DIR} — OpenSearch security config skipped"
            fi
        fi

        systemctl restart wazuh-dashboard 2>/dev/null || true
        success "CySIEM Dashboard: proxy auth configured (X-Proxy-User from nginx)"
    else
        info "Wazuh not installed — CySIEM proxy auth will run when Wazuh is deployed"
    fi

    # ── Patch running nginx cysiem block: all_access role (idempotent) ────────
    # Earlier installs wrote X-Proxy-Roles admin which has no OpenSearch roles_mapping
    # entry by default.  all_access is the built-in backend role pre-mapped to the
    # all_access security role in every vanilla OpenSearch installation.
    _NGINX_MOD="/etc/nginx/sites-available/cycentra-modules"
    if [[ -f "$_NGINX_MOD" ]] && grep -q 'X-Proxy-Roles admin' "$_NGINX_MOD" 2>/dev/null; then
        sed -i 's/X-Proxy-Roles admin;/X-Proxy-Roles all_access;/g' "$_NGINX_MOD" || true
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
            success "nginx cysiem: X-Proxy-Roles patched to all_access" || \
            warn "nginx reload failed after X-Proxy-Roles patch — check: nginx -t"
    fi
fi  # end IAP setup

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

# Deploy config assets from bundle
mkdir -p /tmp/cycentra-config
[[ -d "$BUNDLE_DIR/CYSIEM-Config" ]] && cp -r "$BUNDLE_DIR/CYSIEM-Config/." "/tmp/cycentra-config/"

mkdir -p /var/log/cycentra/cy-asm/scans
mkdir -p /var/log/cycentra/cy-asm/logs
mkdir -p /var/log/cycentra/cy-asm/reports
chmod -R 755 /var/log/cycentra/cy-asm
success "ASM log directories created"

# ── Step 12: Install cycentra-backend package (Flask + engine combined) ───────
step_header "INSTALLING CYCENTRA-BACKEND PACKAGE"

info "Installing ${PKG_NAME}==${PKG_VER} into system Python ..."

# Download wheel — use the release asset URL resolved earlier if available,
# otherwise fall back to the local bundle directory (pre-packaged wheel).
_WHL_FILE="/tmp/cycentra_backend-${PKG_VER}-py3-none-any.whl"

if [[ -n "${WHEEL_URL:-}" && "$WHEEL_URL" != "null" ]]; then
    info "Downloading wheel from GitHub Release asset..."
    curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/octet-stream" \
        "${WHEEL_URL}" \
        -o "${_WHL_FILE}" \
        && success "Wheel downloaded" \
        || { error "Wheel download failed — check GH_TOKEN permissions"; exit 1; }
elif _local_whl=$(ls "$BUNDLE_DIR"/*.whl 2>/dev/null | head -1) && [[ -n "$_local_whl" ]]; then
    _WHL_FILE="$_local_whl"
    info "Using wheel from local bundle: ${_WHL_FILE}"
else
    # Fallback: local bundle has no wheel (old bundle) — resolve from GitHub Releases API.
    # This handles bundles built before CI started packaging the wheel inside the tarball.
    if [[ -z "$GH_TOKEN" ]]; then
        error "Wheel not in bundle and GH_TOKEN not set — cannot download wheel."
        error "Re-run with: GH_TOKEN=your_token sudo -E bash cycentra-setup.sh"
        exit 1
    fi
    info "Wheel not in bundle — fetching from GitHub Releases API (bundle pre-dates wheel packaging)..."
    _whl_release_json=$(curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${GH_ORG}/${GH_REPO}/releases/latest")
    _whl_asset_url=$(echo "$_whl_release_json" | \
        jq -r '.assets[] | select(.name | test("\\.whl$")) | .url' | head -1)
    if [[ -z "$_whl_asset_url" || "$_whl_asset_url" == "null" ]]; then
        error "Wheel asset not found in latest GitHub Release — check CI published the .whl"
        exit 1
    fi
    curl -fsSL \
        -H "Authorization: Bearer ${GH_TOKEN}" \
        -H "Accept: application/octet-stream" \
        "$_whl_asset_url" \
        -o "${_WHL_FILE}" \
        && success "Wheel downloaded from latest release" \
        || { error "Wheel download failed — check GH_TOKEN permissions"; exit 1; }
fi

PIP_ROOT_USER_ACTION=ignore pip3 install \
    --extra-index-url https://pypi.org/simple/ \
    "${_WHL_FILE}" \
    --upgrade \
    ${_PIP_BSP} \
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

# ── License watchdog timer (checks + enforces expiry daily) ──────────────────
cat > /opt/cycentra/license-watchdog.sh << 'WATCHEOF'
#!/bin/bash
LOG="/var/log/cycentra/license-watchdog.log"
SERVICES=(cycentra-backend cysiemstack-engine cysiem-to-redis)
_log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")  $*" | tee -a "$LOG"; }
mkdir -p "$(dirname "$LOG")"
# Guard: a missing validator makes python3 exit 2 ("can't open file"), which
# the watchdog below would misread as "license expired" and stop all services.
if [[ ! -f /opt/cycentra/license_validator.py ]]; then
    _log "WARNING: /opt/cycentra/license_validator.py not found — skipping license check"
    _log "Re-run: sudo bash /opt/cycentra/cycentra-setup.sh --update to redeploy"
    exit 0
fi
_LIC_JSON=$(python3 /opt/cycentra/license_validator.py --license /opt/cycentra/cycentra.lic 2>/dev/null)
_CODE=$?
_TYPE=$(echo "$_LIC_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin).get('type','none'))" 2>/dev/null)
_DAYS=$(echo "$_LIC_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin).get('days_remaining',0))" 2>/dev/null)
_MSG=$(echo "$_LIC_JSON"  | python3 -c "import sys,json;print(json.load(sys.stdin).get('message',''))" 2>/dev/null)
if [[ $_CODE -eq 2 ]]; then
    _log "LICENSE EXPIRED — stopping all CyCentra services"
    for svc in "${SERVICES[@]}"; do
        systemctl is-active --quiet "$svc" && systemctl stop "$svc" && _log "Stopped: $svc"
    done
    chattr -i /opt/cycentra/.license_expired 2>/dev/null || true
    echo "EXPIRED $(date -u)" > /opt/cycentra/.license_expired
    chattr +i /opt/cycentra/.license_expired 2>/dev/null || true
    _log "Renew at https://cycentra.com"
elif [[ $_CODE -eq 0 || $_CODE -eq 1 ]]; then
    chattr -i /opt/cycentra/.license_expired 2>/dev/null || true
    rm -f /opt/cycentra/.license_expired
    _log "License OK — type=${_TYPE} days_remaining=${_DAYS}"
    if [[ $_DAYS -le 7 && $_DAYS -gt 0 ]]; then
        _log "WARNING: license expires in ${_DAYS} day(s)"
    fi
fi
WATCHEOF
chmod 750 /opt/cycentra/license-watchdog.sh

cat > /etc/systemd/system/cycentra-license-check.service << 'LICUNITEOF'
[Unit]
Description=CyCentra 360 License Watchdog
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash /opt/cycentra/license-watchdog.sh
StandardOutput=journal
StandardError=journal
LICUNITEOF

cat > /etc/systemd/system/cycentra-license-check.timer << 'LICTIMEREOF'
[Unit]
Description=CyCentra 360 License Watchdog — daily check

[Timer]
OnBootSec=2min
OnUnitActiveSec=24h

[Install]
WantedBy=timers.target
LICTIMEREOF

# Patch cycentra-backend and cysiemstack-engine to refuse start if license expired
for _SVC_FILE in /etc/systemd/system/cycentra-backend.service \
                 /etc/systemd/system/cysiemstack-engine.service; do
    if [[ -f "$_SVC_FILE" ]] && ! grep -q "license-check" "$_SVC_FILE"; then
        sed -i '/^\[Service\]/a ExecStartPre=/bin/bash -c "[ ! -f /opt/cycentra/.license_expired ] || { echo LICENSE_EXPIRED; exit 1; }"' \
            "$_SVC_FILE"
    fi
done

systemctl daemon-reload
systemctl enable cycentra-backend cysiemstack-engine cycentra-license-check.timer
systemctl start  cycentra-license-check.timer
success "License watchdog timer enabled (daily)"

# Clear any stale .license_expired sentinel before restarting the backend.
# During --update the full-install cleanup path is skipped, so a sentinel left
# from a previous expiry event would block the restart.  The daily watchdog
# will re-enforce expiry on its next run if the license is genuinely expired.
chattr -i /opt/cycentra/.license_expired 2>/dev/null || true
rm -f /opt/cycentra/.license_expired

# Start Flask backend
pkill -f "python3.*app.py" 2>/dev/null || true
sleep 1
systemctl restart cycentra-backend
sleep 4
curl -s --max-time 5 http://127.0.0.1:5252/health 2>/dev/null | grep -q "ok" \
    && success "Flask backend healthy :5252" \
    || { warn "Flask not responding — check: journalctl -u cycentra-backend -n 30"; \
         ERRORS+=("Flask unhealthy"); }

# Start correlation engine (MCP bridge runs inside this same process at /mcp/sse)
systemctl restart cysiemstack-engine
ENGINE_UP=false
for i in $(seq 1 12); do
    curl -sf http://127.0.0.1:8100/health >/dev/null 2>&1 \
        && { success "CySIEMStack engine healthy :8100 (MCP bridge at /mcp/sse)"; ENGINE_UP=true; break; }
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
# Only permanent core services remain here: cysoc, cyasm, cysiem.
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

# ── Portal (cysoc) ───────────────────────────────────────────────────────────
server { listen 80; server_name cysoc.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cysoc.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/privkey.pem;
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
    # ── IAP: oauth2-proxy sign-in / callback / sign-out ─────────────────────
    location /oauth2/ {
        proxy_pass       http://127.0.0.1:4180;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Auth-Request-Redirect \$request_uri;
    }
    # Internal auth-check endpoint used by auth_request in other server blocks
    location = /oauth2/auth {
        internal;
        proxy_pass              http://127.0.0.1:4180;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URI \$request_uri;
        proxy_set_header        X-Scheme \$scheme;
    }
    location @error401 { return 302 https://cysoc.${BASE_DOMAIN}/oauth2/sign_in?rd=https://\$host\$request_uri; }
    # location /cysoar/ is injected here by routes.py when CySOAR is installed via portal
}

# ── Backend / OIDC IdP (cyasm) ──────────────────────────────────────────────
server { listen 80; server_name cyasm.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cyasm.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    set \$cors_origin "";
    if (\$http_origin ~* "^https://(cysoc|cysiem|cyiris|cysoar)\.${BASE_DOMAIN}\$") { set \$cors_origin \$http_origin; }
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
    add_header Content-Security-Policy "frame-ancestors 'self' https://cysoc.${BASE_DOMAIN}" always;
    # IAP gate — only authenticated CyCentra users reach Wazuh Dashboard
    auth_request     /oauth2/auth;
    error_page 401 = @error401;
    auth_request_set \$proxy_user  \$upstream_http_x_auth_request_email;
    location @error401 { return 302 https://cysoc.${BASE_DOMAIN}/oauth2/sign_in?rd=https://\$host\$request_uri; }
    location = /oauth2/auth {
        internal;
        proxy_pass              http://127.0.0.1:4180;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URI \$request_uri;
        proxy_set_header        X-Scheme \$scheme;
    }
    location / {
        proxy_pass https://127.0.0.1:5601;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        # Pass authenticated identity to Wazuh Dashboard (proxy auth mode)
        proxy_set_header X-Proxy-User  \$proxy_user;
        proxy_set_header X-Proxy-Roles all_access;
        proxy_read_timeout 120;
        proxy_buffering off;
        proxy_cookie_flags ~ samesite=none secure;
    }
}
# cyiris.DOMAIN server block is added by routes.py when CyIRIS is installed via portal
# cymisp.DOMAIN server block is added by routes.py when CyMISP is installed via portal
# cymind.DOMAIN server block is added by cymind/install.sh when CyMind is installed
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

    # Remove any other site configs in sites-enabled that may reference non-existent
    # cert files from a previous partial install — they would cause nginx -t to fail
    # even though our stub config is valid.
    for _stale_site in /etc/nginx/sites-enabled/*; do
        [[ "$_stale_site" == "/etc/nginx/sites-enabled/cycentra-modules" ]] && continue
        [[ -e "$_stale_site" ]] && { rm -f "$_stale_site"; info "Removed stale nginx site: $_stale_site"; }
    done

    # Also clear any conf.d configs that may have a conflicting default_server on port 80.
    # These are not managed by sites-enabled and can intercept ACME challenges.
    for _stale_conf in /etc/nginx/conf.d/*.conf; do
        [[ -e "$_stale_conf" ]] && { mv "$_stale_conf" "${_stale_conf}.certbot-bak"; info "Temporarily moved conflicting conf.d: $_stale_conf"; }
    done

    nginx -t 2>/dev/null \
        && { systemctl reload nginx 2>/dev/null || systemctl start nginx; \
             success "nginx started (HTTP stub for certbot)"; } \
        || { error "nginx config invalid — run: nginx -t"; ERRORS+=("nginx failed"); }

    # Wait for nginx workers to fully reload before certbot tries the ACME challenge.
    # systemctl reload returns as soon as SIGHUP is sent — workers take a moment.
    sleep 3

    # Verify nginx is actually serving the ACME path before invoking certbot.
    if ! curl -s --max-time 5 "http://127.0.0.1/.well-known/acme-challenge/test" -o /dev/null; then
        warn "nginx not responding on port 80 — ACME challenge will likely fail"
    fi

    # Ensure options-ssl-nginx.conf exists — try download, fall back to local minimal copy.
    if [[ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]]; then
        mkdir -p /etc/letsencrypt
        curl -s --max-time 15 \
            https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf \
            -o /etc/letsencrypt/options-ssl-nginx.conf 2>/dev/null || true
        if [[ ! -s /etc/letsencrypt/options-ssl-nginx.conf ]]; then
            cat > /etc/letsencrypt/options-ssl-nginx.conf << 'SSLOPTEOF'
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
SSLOPTEOF
            info "options-ssl-nginx.conf: used local fallback (curl unavailable)"
        fi
    fi

    if [[ ! -f /etc/letsencrypt/ssl-dhparams.pem ]]; then
        info "Generating ssl-dhparams.pem in background (~30s) ..."
        openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 2>/dev/null &
        DHPARAM_PID=$!
    fi

    # ── helper: run certbot only when needed ─────────────────────────────────
    # If a valid (non-expired, >30 days remaining) LE cert already exists for the
    # primary domain, skip certbot entirely.  This avoids hitting the LE rate limit
    # (5 certs per exact set of identifiers per 168h) on repeated setup runs, which
    # is common during initial testing / fresh installs on the same server.
    # Returns 0 if certbot was skipped (cert already fine), 1 if certbot ran.
    _certbot_if_needed() {
        local primary_domain="$1"; shift   # e.g. cysoc.cycentra.com
        local log_file="$1";       shift   # temp log path
        local -a cb_args=("$@")            # remaining args passed to certbot

        local live_cert="/etc/letsencrypt/live/${primary_domain}/fullchain.pem"

        # Check cert exists AND has >30 days remaining validity.
        if [[ -f "$live_cert" ]] && \
           openssl x509 -checkend 2592000 -noout -in "$live_cert" 2>/dev/null; then
            success "SSL cert for ${primary_domain} already valid — skipping certbot"
            return 0
        fi

        certbot certonly $CERTBOT_ENV --webroot -w /var/www/html --non-interactive --agree-tos \
            --preferred-challenges http-01 --keep-until-expiring \
            "${cb_args[@]}" \
            >"$log_file" 2>&1
        local rc=$?
        if [[ $rc -eq 0 ]]; then
            return 0
        fi

        # Detect rate-limit specifically and surface the retry-after time.
        if grep -q "too many certificates" "$log_file" 2>/dev/null; then
            local retry_after
            retry_after=$(grep -oE "retry after [0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+ UTC" \
                "$log_file" 2>/dev/null | head -1)
            warn "Certbot hit Let's Encrypt rate limit (5 certs/7 days for this exact domain set)"
            [[ -n "$retry_after" ]] && warn "  → ${retry_after}"
            warn "  → Tip: use --staging flag on test runs to avoid consuming rate-limit quota"
            # If an older cert exists (even if expired), reuse it rather than self-signed.
            if [[ -f "$live_cert" ]]; then
                warn "  → Reusing existing (possibly expired) LE cert from previous run"
                return 0
            fi
        else
            warn "Certbot failed for ${primary_domain} — details:"
            grep -E "Error|error|WARN|failed|challenge|refused|Timeout|rate.limit|DNS|problem|detail" \
                "$log_file" 2>/dev/null | head -10 | sed 's/^/    /'
        fi
        rm -f "$log_file"
        return 1
    }

    # ── certbot: cysoc + cyasm ───────────────────────────────────────────────
    _CB_LOG_BASE="/tmp/certbot-cysoc-$$.log"
    _certbot_if_needed "cysoc.${BASE_DOMAIN}" "$_CB_LOG_BASE" \
        -m "$CLIENT_EMAIL" -d cysoc.${BASE_DOMAIN} -d cyasm.${BASE_DOMAIN} \
        && success "SSL cert ready (cysoc, cyasm)" \
        || true   # self-signed fallback below handles missing cert

    # ── certbot: cysiem ───────────────────────────────────────────────────────
    _CB_LOG_SIEM="/tmp/certbot-cysiem-$$.log"
    _certbot_if_needed "cysiem.${BASE_DOMAIN}" "$_CB_LOG_SIEM" \
        -m "$CLIENT_EMAIL" -d cysiem.${BASE_DOMAIN} \
        && success "SSL cert ready (cysiem)" \
        || true
    # NOTE: cyiris/cymisp certs are obtained by routes.py (certbot --nginx -d cyiris.DOMAIN)
    # when those modules are installed via the portal. No cert is needed here
    # because no cyiris/cymisp nginx block exists until the module is installed.

    [[ -n "${DHPARAM_PID:-}" ]] && wait "$DHPARAM_PID" 2>/dev/null || true

    # Restore any conf.d configs that were temporarily moved aside for certbot.
    for _bak_conf in /etc/nginx/conf.d/*.certbot-bak; do
        [[ -e "$_bak_conf" ]] && mv "$_bak_conf" "${_bak_conf%.certbot-bak}"
    done

    # ── Self-signed fallback ──────────────────────────────────────────────────
    # If certbot could not obtain a cert (DNS not propagated, port 80 blocked,
    # rate limit, etc.) generate a self-signed cert so nginx can start with SSL
    # and the portal / backend remain reachable.  When setup is re-run after DNS
    # resolves, certbot will obtain real certs and overwrite the live/ symlinks.
    _BASE_CERT="/etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/fullchain.pem"
    _SIEM_CERT="/etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/fullchain.pem"
    _SELFSIGNED_DIR="/etc/ssl/cycentra/selfsigned"

    if [[ ! -f "$_BASE_CERT" ]]; then
        info "Generating self-signed cert for cysoc/cyasm (temporary — browser will show security warning)..."
        mkdir -p "$_SELFSIGNED_DIR" "/etc/letsencrypt/live/cysoc.${BASE_DOMAIN}"
        openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout "$_SELFSIGNED_DIR/cysoc-privkey.pem" \
            -out    "$_SELFSIGNED_DIR/cysoc-fullchain.pem" \
            -days 90 \
            -subj "/CN=cysoc.${BASE_DOMAIN}/O=CyCentra/C=US" \
            -addext "subjectAltName=DNS:cysoc.${BASE_DOMAIN},DNS:cyasm.${BASE_DOMAIN}" \
            2>/dev/null \
            && { ln -sf "$_SELFSIGNED_DIR/cysoc-fullchain.pem" \
                        "/etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/fullchain.pem"
                 ln -sf "$_SELFSIGNED_DIR/cysoc-privkey.pem" \
                        "/etc/letsencrypt/live/cysoc.${BASE_DOMAIN}/privkey.pem"
                 warn "Self-signed cert installed for cysoc/cyasm — re-run setup after DNS resolves to replace with Let's Encrypt"; } \
            || warn "Self-signed cert generation failed for cysoc/cyasm"
    fi

    if [[ ! -f "$_SIEM_CERT" ]]; then
        info "Generating self-signed cert for cysiem (temporary)..."
        mkdir -p "$_SELFSIGNED_DIR" "/etc/letsencrypt/live/cysiem.${BASE_DOMAIN}"
        openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout "$_SELFSIGNED_DIR/cysiem-privkey.pem" \
            -out    "$_SELFSIGNED_DIR/cysiem-fullchain.pem" \
            -days 90 \
            -subj "/CN=cysiem.${BASE_DOMAIN}/O=CyCentra/C=US" \
            2>/dev/null \
            && { ln -sf "$_SELFSIGNED_DIR/cysiem-fullchain.pem" \
                        "/etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/fullchain.pem"
                 ln -sf "$_SELFSIGNED_DIR/cysiem-privkey.pem" \
                        "/etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/privkey.pem"
                 warn "Self-signed cert installed for cysiem — re-run setup to replace with Let's Encrypt"; } \
            || warn "Self-signed cert generation failed for cysiem"
    fi

    # Restore full SSL nginx config now that certs exist (real or self-signed).
    if [[ -f "$_BASE_CERT" && -f "$_SIEM_CERT" ]]; then
        cp "$SSL_CONF_BACKUP" "$SSL_CONF"

        # Detect whether any cert in live/ is self-signed (issuer == subject).
        # If so, strip the HSTS header from the nginx config.
        # HSTS with a self-signed cert causes Chrome to block the site with no
        # bypass option once it has cached the HSTS policy from a prior real cert.
        # The header is restored automatically on the next run when a real LE cert
        # is in place and the server block is regenerated.
        _is_selfsigned=false
        if openssl x509 -noout -in "$_BASE_CERT" 2>/dev/null | true; then
            _issuer=$(openssl x509 -noout -issuer  -in "$_BASE_CERT" 2>/dev/null)
            _subject=$(openssl x509 -noout -subject -in "$_BASE_CERT" 2>/dev/null)
            [[ "$_issuer" == "$_subject" ]] && _is_selfsigned=true
        fi

        if [[ "$_is_selfsigned" == "true" ]]; then
            # Replace HSTS header with max-age=0 so browsers clear any cached policy.
            sed -i 's/add_header Strict-Transport-Security "[^"]*" always;/add_header Strict-Transport-Security "max-age=0" always;/g' "$SSL_CONF"
            warn "Self-signed cert active — HSTS set to max-age=0 to prevent browser lockout"
            warn "  → Re-run setup after LE rate limit expires to restore full HSTS"
        fi

        nginx -t 2>/dev/null \
            && systemctl reload nginx && success "nginx reloaded with full SSL config" \
            || { warn "nginx SSL config invalid — check /etc/nginx/sites-available/cycentra-modules"; \
                 ERRORS+=("nginx SSL pending"); }
    else
        warn "nginx SSL config NOT restored — HTTP stub remains active"
        ERRORS+=("nginx SSL pending")
    fi

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
            success "SaaS auth decoders patched — removed invalid <type>json</type> lines"
        else
            success "SaaS auth decoders already present"
        fi
    fi
        step_header "INFRASTRUCTURE PREREQUISITES"

        # ── 19.1 geoip2 Python library ────────────────────────────────────────────
        if ! python3 -c "import geoip2" 2>/dev/null; then
                info "Installing geoip2 Python library..."
                PIP_ROOT_USER_ACTION=ignore pip3 install geoip2 ${_PIP_BSP} -q \
                        && success "geoip2 installed" \
                        || warn "geoip2 install failed — GeoIP enrichment will be disabled"
        else
                success "geoip2 already installed"
        fi

        # ── 19.2 GeoLite2-City.mmdb download (requires MAXMIND_KEY in .env) ──────
        GEOIP_DIR="/opt/cycentra/geoip"
        mkdir -p "$GEOIP_DIR"
        GEOLITE_DB="$GEOIP_DIR/GeoLite2-City.mmdb"
        if [[ ! -f "$GEOLITE_DB" ]]; then
                MAXMIND_KEY="$(grep "^MAXMIND_KEY=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2)"
                if [[ -n "$MAXMIND_KEY" ]]; then
                        info "Downloading GeoLite2-City.mmdb..."
                        GEOURL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_KEY}&suffix=tar.gz"
                        TMP_GEO=$(mktemp /tmp/geolite2_XXXXXX.tar.gz)
                        curl -sL "$GEOURL" -o "$TMP_GEO" \
                            && tar -xzf "$TMP_GEO" -C "$GEOIP_DIR" --strip-components=1 --wildcards "*.mmdb" 2>/dev/null || true
                        find "$GEOIP_DIR" -name "*.mmdb" ! -name "GeoLite2-City.mmdb" -exec mv {} "$GEOLITE_DB" \; 2>/dev/null || true
                        rm -f "$TMP_GEO"
                        [[ -f "$GEOLITE_DB" ]] \
                                && success "GeoLite2-City.mmdb downloaded" \
                                || warn "GeoLite2 download failed — check MAXMIND_KEY in /opt/cycentra/.env"
                else
                        warn "MAXMIND_KEY not in /opt/cycentra/.env — GeoLite2 DB skipped"
                        warn "Add MAXMIND_KEY=<your_key> to .env and re-run to enable GeoIP enrichment"
                        warn "Free signup: https://www.maxmind.com/en/geolite2/signup"
                fi
        else
                success "GeoLite2-City.mmdb already present"
        fi

    # end infra prerequisites block
    # ── 19.8 Reload Wazuh after config/decoder changes ────────────────────────
    /var/ossec/bin/wazuh-analysisd -t 2>/dev/null \
        && { systemctl reload wazuh-manager 2>/dev/null || systemctl restart wazuh-manager 2>/dev/null; \
             success "wazuh-manager reloaded with new decoders/rules"; } \
        || warn "Wazuh config validation failed — fix errors before reloading"

    info "Post-install manual steps for cloud telemetry:"
    info "  1. Edit /var/ossec/etc/ossec.conf — replace PLACEHOLDER_ values in cloud wodles,"
    info "     then change <disabled>yes</disabled> → <disabled>no</disabled>"
    info "  2. GeoIP: add MAXMIND_KEY=<key> to /opt/cycentra/.env and re-run --update"
    info "     Free signup: https://www.maxmind.com/en/geolite2/signup"
    info "  3. Sysmon: copy /opt/cycentra/sysmon/ to Windows endpoints + run deploy_sysmon.ps1"
    info "  4. Audit policy: run apply_audit_policy.ps1 on Domain Controllers"

    # end infra prerequisites block

# ── Step 20: Platform branding (cylogo) ──────────────────────────────────────
step_header "PLATFORM BRANDING (CYLOGO)"

_CYLOGO_DIR="/usr/local/lib/python3.12/dist-packages/cy_asm/modules/cylogo"

for script in apply-favicons apply-logos enable-multitenancy apply-custom-branding apply-plugin-branding; do
    _SPATH="$_CYLOGO_DIR/${script}.sh"
    if [[ -f "$_SPATH" ]]; then
        chmod +x "$_SPATH"
        bash "$_SPATH" \
            && success "${script}.sh applied" \
            || warn "${script}.sh returned non-zero — check output above"
    else
        warn "${script}.sh not found at ${_SPATH} — skipping"
    fi
done

systemctl restart wazuh-dashboard.service 

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
  "portal_url":  "https://cysoc.${BASE_DOMAIN}",
  "cyasm_url":   "https://cyasm.${BASE_DOMAIN}",
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
curl -sk --max-time 5 "http://127.0.0.1:5252/oidc/.well-known/openid-configuration" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); assert '/oidc' in d.get('issuer',''), 'bad issuer'" 2>/dev/null \
    && success "OIDC IdP discovery  UP  (issuer OK)" \
    || warn    "OIDC IdP discovery  DOWN or issuer mismatch — check cycentra-backend"

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
    chk "Portal"  "https://cysoc.${BASE_DOMAIN}"
    chk "Backend" "https://cyasm.${BASE_DOMAIN}/health"
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
    echo -e "  ${CYAN}Portal         ${NC}  https://cysoc.${BASE_DOMAIN}"
    echo -e "  ${CYAN}Backend API    ${NC}  https://cyasm.${BASE_DOMAIN}"
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
echo -e "  ${DIM}4. Security MCP bridge available at http://127.0.0.1:8100/mcp/sse (inside cysiemstack-engine)${NC}"
echo -e "  ${DIM}5. Install CyIRIS / CySOAR via portal${NC}"
echo -e "  ${DIM}6. To update: sudo bash cycentra-setup.sh --update${NC}"
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
  Portal:   https://cysoc.${BASE_DOMAIN}
  Backend:  https://cyasm.${BASE_DOMAIN}
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
  Branding     : $BUNDLE_DIR/backend/blueprints/cylogo

Next steps:
  1. Verify WAZUH_API_PASSWORD in /opt/cycentra/cysiemstack.env (auto-detected if CySIEM is installed)
     then: systemctl restart cysiemstack-engine
  2. Verify alerts flowing: redis-cli -p 6379 llen cysiemstack:alerts:raw
     (cysiem-to-redis service tails CySIEM alerts → Redis)
  3. Check engine log: tail -f /opt/cycentra/engine.log
  4. Security MCP bridge: http://127.0.0.1:8100/mcp/sse (inside cysiemstack-engine)
  5. Install CyIRIS/CySOAR via portal
  6. Update: sudo bash cycentra-setup.sh --update
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