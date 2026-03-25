#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — Setup & Update Wizard v7.0
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
#   Cloudsmith         → cycentra-backend wheel, cysiemstack-engine wheel
#   Let's Encrypt      → SSL certificates (via certbot)
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
skip()    { echo -e "${DIM}  ↷ SKIP (--update mode): $*${NC}"; }

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

step=0
step_header() {
    step=$((step+1))
    echo -e "\n${BOLD}${CYAN}  ── $1${NC}"
    divider
}

[[ $EUID -ne 0 ]] && { error "Run as root: sudo bash cycentra-setup.sh"; exit 1; }

ERRORS=()

# ── Banner ────────────────────────────────────────────────────────────────────
clear; echo ""
echo -e "${CYAN}${BOLD}"
echo "  ██████╗██╗   ██╗ ██████╗███████╗███╗   ██╗████████╗██████╗  █████╗ "
echo "  ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗"
echo "  ██║      ╚████╔╝ ██║     █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║"
echo "  ██║       ╚██╔╝  ██║     ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║"
echo "  ╚██████╗   ██║   ╚██████╗███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║"
echo "   ╚═════╝   ╚═╝    ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}360° Security Operations Platform${NC}"
echo -e "  ${DIM}Setup Wizard v7.0${NC}"
echo ""; divider

if [[ "$MODE" == "update" ]]; then
    echo -e "  ${YELLOW}MODE: UPDATE${NC} — skipping infrastructure, updating packages only"
elif [[ "$MODE" == "infra" ]]; then
    echo -e "  ${YELLOW}MODE: INFRA ONLY${NC} — installing infrastructure, skipping app packages"
else
    echo -e "  ${DIM}MODE: FULL INSTALL${NC} — infrastructure + application"
fi
divider; echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# INFRA BLOCK — skipped when running --update
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$MODE" != "update" ]]; then

# ── System packages ───────────────────────────────────────────────────────────
step_header "SYSTEM DEPENDENCIES"
apt-get update -y -qq
apt-get install -y -qq \
    curl wget gnupg lsb-release ca-certificates jq \
    python3.12-venv python3-pip \
    nmap whois rsync git openssl \
    nginx certbot python3-certbot-nginx \
    2>/dev/null
success "System packages installed"

# ── PostgreSQL 16 ─────────────────────────────────────────────────────────────
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

# Bind to port 5433 to avoid conflict with CyIRIS Docker postgres on :5432
PG_CONF=$(sudo -u postgres psql -t -c "SHOW config_file;" 2>/dev/null | tr -d ' ' || echo "")
if [[ -n "$PG_CONF" && -f "$PG_CONF" ]]; then
    if grep -q "^port = 5432" "$PG_CONF" 2>/dev/null; then
        info "Reconfiguring PostgreSQL from :5432 to :5433 ..."
        sed -i "s/^port = 5432/port = 5433/" "$PG_CONF"
        systemctl restart postgresql
        success "PostgreSQL now on :5433"
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

# ── Redis ─────────────────────────────────────────────────────────────────────
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

# ── jq must be present for all modes ─────────────────────────────────────────
command -v jq >/dev/null 2>&1 || apt-get install -y -qq jq

# Ensure CORR_DB_PASS is set in update mode (read from existing env)
if [[ "$MODE" == "update" ]]; then
    CORR_DB_PASS=$(grep "^POSTGRES_PASSWORD=" /opt/cycentra/cysiemstack.env 2>/dev/null \
        | cut -d= -f2 || true)
    if [[ -z "$CORR_DB_PASS" ]]; then
        error "Cannot find POSTGRES_PASSWORD in /opt/cycentra/cysiemstack.env"
        error "Run full install first: sudo bash cycentra-setup.sh"
        exit 1
    fi
fi

# ── Download release bundle ───────────────────────────────────────────────────
step_header "DOWNLOAD RELEASE BUNDLE"

CYCENTRA_VERSION="${CYCENTRA_VERSION:-latest}"
if [[ "$CYCENTRA_VERSION" == "latest" ]]; then
    _BASE="https://github.com/cycentra/cycentra360/releases/latest/download"
else
    _BASE="https://github.com/cycentra/cycentra360/releases/download/${CYCENTRA_VERSION}"
fi
CYCENTRA_RELEASE_URL="${CYCENTRA_RELEASE_URL:-${_BASE}/cycentra-release.tar.gz}"

BUNDLE_DIR="/tmp/cycentra-release"
rm -rf "$BUNDLE_DIR" /tmp/cycentra-release.tar.gz

info "Downloading: ${CYCENTRA_RELEASE_URL}"
if [[ "$CYCENTRA_RELEASE_URL" == http* ]]; then
    curl -fsSL "$CYCENTRA_RELEASE_URL" -o /tmp/cycentra-release.tar.gz \
        && success "Bundle downloaded" \
        || { error "Download failed. Check CYCENTRA_RELEASE_URL."; exit 1; }
    tar -xzf /tmp/cycentra-release.tar.gz -C /tmp/
else
    tar -xzf "$CYCENTRA_RELEASE_URL" -C /tmp/
fi

# Read manifest
MANIFEST="$BUNDLE_DIR/manifest.json"
[[ ! -f "$MANIFEST" ]] && { error "manifest.json not found — bundle may be corrupt"; exit 1; }

BUNDLE_VERSION=$(jq -r '.version'                     "$MANIFEST")
PKG_INDEX_URL=$(jq  -r '.packages.backend.index_url'  "$MANIFEST")
BACKEND_PKG=$(jq    -r '.packages.backend.name'        "$MANIFEST")
BACKEND_VER=$(jq    -r '.packages.backend.version'     "$MANIFEST")
ENGINE_PKG=$(jq     -r '.packages.engine.name'         "$MANIFEST")
ENGINE_VER=$(jq     -r '.packages.engine.version'      "$MANIFEST")

success "Bundle version  : ${BUNDLE_VERSION}"
info    "Backend package : ${BACKEND_PKG}==${BACKEND_VER}"
info    "Engine package  : ${ENGINE_PKG}==${ENGINE_VER}"

# ── Interactive config (only on full install) ─────────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "CLIENT INFORMATION"
    ask CLIENT_NAME  "Client / Organisation name" "cycentra"
    ask CLIENT_EMAIL "Primary admin email"        "admin@${CLIENT_NAME,,}.com"
    ask BASE_DOMAIN  "Base domain"                "${CLIENT_NAME,,}.com"
    echo ""
    info "Subdomains: cy360 · cyscan · cysiem · cyiris · cysoar all on .${BASE_DOMAIN}"
    echo ""
    if ! ask_yn "Are all subdomains pointing at this server in DNS?"; then
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        warn "Add DNS A records: cy360 cyscan cysiem cyiris cysoar → ${SERVER_IP}"
        ask_yn "Continue anyway?" "n" || exit 0
    fi

    INSTALL_CYSIEM=true; INSTALL_CYIRIS=true; INSTALL_CYSOAR=true

    step_header "OAUTH / SSO"
    PS3="  Choose provider: "
    select OAUTH_PROVIDER in "Google" "Microsoft Azure AD" "Skip"; do
        case $REPLY in 1) OAUTH_PROVIDER="google";    break;;
                       2) OAUTH_PROVIDER="microsoft"; break;;
                       3) OAUTH_PROVIDER="skip";      break;; esac
    done
    OAUTH_CLIENT_ID=""; OAUTH_CLIENT_SECRET=""
    if [[ "$OAUTH_PROVIDER" != "skip" ]]; then
        ask OAUTH_CLIENT_ID "OAuth Client ID" ""
        ask_secret OAUTH_CLIENT_SECRET "OAuth Client Secret"
    fi

    step_header "AI ENRICHMENT (OPTIONAL)"
    AI_PROVIDER="none"; AI_API_KEY=""; AI_MODEL=""
    PS3="  Choose: "
    select choice in "OpenAI (GPT-4)" "Anthropic (Claude)" "Local (Ollama)" "Skip"; do
        case $REPLY in
            1) AI_PROVIDER="openai";    AI_MODEL="gpt-4o";            break;;
            2) AI_PROVIDER="anthropic"; AI_MODEL="claude-sonnet-4-5"; break;;
            3) AI_PROVIDER="local";     AI_MODEL="mistral:7b";        break;;
            4) AI_PROVIDER="none";                                     break;;
        esac
    done
    [[ "$AI_PROVIDER" != "none" && "$AI_PROVIDER" != "local" ]] \
        && ask AI_API_KEY "API Key for ${AI_PROVIDER}"

    step_header "SMTP (OPTIONAL)"
    SMTP_HOST=""; SMTP_PORT=""; SMTP_USER=""; SMTP_PASS=""; SUPPORT_EMAIL=""
    if ask_yn "Configure SMTP?" "n"; then
        ask SMTP_HOST "SMTP hostname" "smtp.gmail.com"
        ask SMTP_PORT "SMTP port"     "587"
        ask SMTP_USER "SMTP username" ""
        ask_secret SMTP_PASS "SMTP password"
        ask SUPPORT_EMAIL "Support email" "support@${BASE_DOMAIN}"
    fi

    step_header "GENERATING SECRETS"
    _env="/opt/cycentra/.env"
    _get() { grep -m1 "^${1}=" "$_env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true; }
    if [[ -f "$_env" ]]; then
        info "Preserving existing session secrets ..."
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
    success "Secrets ready"

    step_header "REVIEW & CONFIRM"
    echo -e "  ${DIM}Client  :${NC} ${WHITE}${CLIENT_NAME}${NC}"
    echo -e "  ${DIM}Domain  :${NC} ${WHITE}${BASE_DOMAIN}${NC}"
    echo -e "  ${DIM}OAuth   :${NC} ${WHITE}${OAUTH_PROVIDER}${NC}"
    echo -e "  ${DIM}AI      :${NC} ${WHITE}${AI_PROVIDER}${NC}"
    echo -e "  ${DIM}Version :${NC} ${WHITE}${BUNDLE_VERSION}${NC}"
    echo ""
    ask_yn "Proceed?" || exit 0

else
    # Update mode — read existing values from .env
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

# ── Write env files (full install only — update preserves existing) ───────────
if [[ "$MODE" == "full" ]]; then

    step_header "WRITING .env FILES"
    mkdir -p /opt/cycentra && chmod 700 /opt/cycentra

    cat > /opt/cycentra/.env << ENVEOF
# CyCentra 360 — generated by setup wizard v7.0
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
ENVEOF
    chmod 600 /opt/cycentra/.env
    mkdir -p /root/cy-asm && cp /opt/cycentra/.env /root/cy-asm/.env
    success ".env written"

    _LLM="${AI_PROVIDER:-none}"; [[ "$_LLM" == "none" ]] && _LLM_FLAG="false" || _LLM_FLAG="true"
    _WAZUH_PASS=$(grep "^WAZUH_API_PASSWORD=" /opt/cycentra/cysiemstack.env 2>/dev/null \
        | cut -d= -f2 || echo "CHANGE_ME_after_wazuh_install")

    cat > /opt/cycentra/cysiemstack.env << SIEMEOF
# CySIEMStack environment — set WAZUH_API_PASSWORD then restart cysiemstack-engine

DATABASE_URL=postgresql+asyncpg://corruser:${CORR_DB_PASS}@127.0.0.1:5433/correlation
POSTGRES_PASSWORD=${CORR_DB_PASS}
REDIS_URL=redis://127.0.0.1:6379/0
REDIS_ALERT_KEY=cysiemstack:alerts:raw

WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=${_WAZUH_PASS}

OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=${AI_MODEL:-llama3.1:8b}
LLM_ENABLED=${_LLM_FLAG}

CORRELATION_WINDOW_MINUTES=15
UEBA_BASELINE_DAYS=30
RISK_DECAY_HOURS=24
INCIDENT_ID_PREFIX=INC
LOG_LEVEL=INFO
UEBA_ML_SHADOW_MODE=true
UEBA_ML_MIN_TRAIN_DAYS=7
MISP_ENABLED=false
SIEMEOF
    chmod 600 /opt/cycentra/cysiemstack.env
    success "cysiemstack.env written"

fi  # end full-install env block

# ── Deploy portal static files ────────────────────────────────────────────────
step_header "DEPLOYING PORTAL"
PORTAL_DIR="/var/www/cycentra360"
mkdir -p "$PORTAL_DIR"
if [[ -d "$BUNDLE_DIR/portal/dist" ]]; then
    rsync -a --delete "$BUNDLE_DIR/portal/dist/" "$PORTAL_DIR/"
    success "Portal deployed → ${PORTAL_DIR} ($(find $PORTAL_DIR -type f | wc -l) files)"
else
    warn "portal/dist not in bundle"; ERRORS+=("Portal dist missing")
fi

# Deploy config assets
BRANDING_DIR="/opt/cycentra-branding"
mkdir -p "$BRANDING_DIR" /tmp/cycentra-config
[[ -d "$BUNDLE_DIR/scripts"       ]] && cp -r "$BUNDLE_DIR/scripts/."       "$BRANDING_DIR/scripts/"
[[ -d "$BUNDLE_DIR/assets"        ]] && cp -r "$BUNDLE_DIR/assets/."        "$BRANDING_DIR/assets/"
[[ -d "$BUNDLE_DIR/CYSIEM-Config" ]] && cp -r "$BUNDLE_DIR/CYSIEM-Config/." "/tmp/cycentra-config/"

# ── Install Flask backend from Cloudsmith ─────────────────────────────────────
step_header "INSTALLING FLASK BACKEND PACKAGE"

FLASK_VENV="/opt/cycentra/backend-venv"
mkdir -p "$FLASK_VENV"
[[ ! -d "$FLASK_VENV/lib" ]] && python3 -m venv "$FLASK_VENV"

info "pip install ${BACKEND_PKG}==${BACKEND_VER} ..."
"$FLASK_VENV/bin/pip" install \
    --index-url "$PKG_INDEX_URL" \
    --extra-index-url https://pypi.org/simple/ \
    "${BACKEND_PKG}==${BACKEND_VER}" \
    --upgrade -q \
    && success "Installed: ${BACKEND_PKG}==${BACKEND_VER}" \
    || { error "Flask package install failed"; ERRORS+=("Flask install failed"); }

FLASK_SITE=$(find "$FLASK_VENV/lib" -type d -name "site-packages" | head -1)
info "Installed to: ${FLASK_SITE}"

# ── Install CySIEMStack engine from Cloudsmith ────────────────────────────────
step_header "INSTALLING CYSIEMSTACK ENGINE PACKAGE"

ENGINE_VENV="/opt/cycentra/engine-venv"
mkdir -p "$ENGINE_VENV"
[[ ! -d "$ENGINE_VENV/lib" ]] && python3 -m venv "$ENGINE_VENV"

info "pip install ${ENGINE_PKG}==${ENGINE_VER} ..."
"$ENGINE_VENV/bin/pip" install \
    --index-url "$PKG_INDEX_URL" \
    --extra-index-url https://pypi.org/simple/ \
    "${ENGINE_PKG}==${ENGINE_VER}" \
    --upgrade -q \
    && success "Installed: ${ENGINE_PKG}==${ENGINE_VER}" \
    || { error "Engine package install failed"; ERRORS+=("Engine install failed"); }

ENGINE_SITE=$(find "$ENGINE_VENV/lib" -type d -name "site-packages" | head -1)
info "Installed to: ${ENGINE_SITE}"

# ── DB schema + migrations ────────────────────────────────────────────────────
step_header "DATABASE SCHEMA & MIGRATIONS"

if [[ -f "$BUNDLE_DIR/db/init.sql" ]]; then
    PGPASSWORD="$CORR_DB_PASS" psql -h 127.0.0.1 -p 5433 \
        -U corruser -d correlation \
        -f "$BUNDLE_DIR/db/init.sql" -v ON_ERROR_STOP=0 -q 2>/dev/null || true
    success "init.sql applied"
fi

if [[ -d "$BUNDLE_DIR/db/migrations" ]]; then
    for sql in "$BUNDLE_DIR/db/migrations/"*.sql; do
        [[ -f "$sql" ]] || continue
        PGPASSWORD="$CORR_DB_PASS" psql -h 127.0.0.1 -p 5433 \
            -U corruser -d correlation \
            -f "$sql" -v ON_ERROR_STOP=0 -q 2>/dev/null \
            && success "Migration: $(basename $sql)" \
            || warn    "$(basename $sql) had warnings (may already be applied)"
    done
fi

# ── Systemd services ──────────────────────────────────────────────────────────
step_header "SYSTEMD SERVICES"

cat > /etc/systemd/system/cycentra-backend.service << UNITEOF
[Unit]
Description=CyCentra 360 Flask Backend
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
User=root
WorkingDirectory=${FLASK_SITE}
EnvironmentFile=/opt/cycentra/.env
ExecStart=${FLASK_VENV}/bin/python3 ${FLASK_SITE}/app.py
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
WorkingDirectory=${ENGINE_SITE}
EnvironmentFile=/opt/cycentra/cysiemstack.env
ExecStart=${ENGINE_VENV}/bin/uvicorn main:app --host 127.0.0.1 --port 8100 --workers 1 --log-level info
Restart=always
RestartSec=5
StandardOutput=append:/opt/cycentra/engine.log
StandardError=append:/opt/cycentra/engine.log

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable cycentra-backend cysiemstack-engine

# Restart Flask
pkill -f "python3.*app.py" 2>/dev/null || true
sleep 1
systemctl restart cycentra-backend
sleep 4
curl -s --max-time 5 http://127.0.0.1:5252/health 2>/dev/null | grep -q "ok" \
    && success "Flask backend healthy :5252" \
    || { warn "Flask not responding — check: journalctl -u cycentra-backend -n 30"; \
         ERRORS+=("Flask unhealthy"); }

# Restart engine
systemctl restart cysiemstack-engine
ENGINE_UP=false
for i in $(seq 1 12); do
    curl -sf http://127.0.0.1:8100/health >/dev/null 2>&1 \
        && { success "CySIEMStack engine healthy :8100"; ENGINE_UP=true; break; }
    sleep 5
done
[[ "$ENGINE_UP" == false ]] && \
    { warn "Engine timed out — check: journalctl -u cysiemstack-engine -n 30"; \
      ERRORS+=("Engine not responding"); }

# ── nginx + SSL (full install only) ──────────────────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "NGINX & SSL"

    SSL_CONF="/etc/nginx/sites-available/cycentra-modules"
    SSL_CONF_BACKUP="${SSL_CONF}.ssl-pending"

    cat > "$SSL_CONF" << NGINXEOF
# CyCentra 360 nginx — ${BASE_DOMAIN} — v7.0

map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }

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
    location /         { try_files \$uri \$uri/ /index.html; }
    location /assets/  { expires 1y; add_header Cache-Control "public, immutable"; }
    location = /index.html { add_header Cache-Control "no-cache, no-store, must-revalidate"; }
    location /api/  { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_read_timeout 180s; }
    location /auth/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; }
    location /oidc/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; }
    location /cysoar/ {
        proxy_pass http://127.0.0.1:1880/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_buffering off;
    }
}
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
    add_header Access-Control-Allow-Origin \$cors_origin always;
    add_header Access-Control-Allow-Credentials "true" always;
    add_header Access-Control-Allow-Methods "GET, POST, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization, X-CyCentra-AdminKey" always;
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
        proxy_pass http://127.0.0.1:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_cookie_flags ~ samesite=none secure;
    }
}
server { listen 80; server_name cyiris.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cyiris.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cyiris.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cyiris.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "" always;
    add_header Content-Security-Policy "frame-ancestors 'self' https://cy360.${BASE_DOMAIN}" always;
    add_header Access-Control-Allow-Origin "https://cy360.${BASE_DOMAIN}" always;
    add_header Access-Control-Allow-Credentials "true" always;
    if (\$request_method = OPTIONS) { return 204; }
    location / {
        proxy_pass http://127.0.0.1:4433;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300;
        proxy_cookie_flags ~ samesite=none secure;
    }
}
NGINXEOF

    cp "$SSL_CONF" "$SSL_CONF_BACKUP"

    # HTTP stub for certbot
    cat > "$SSL_CONF" << 'STUBEOF'
server {
    listen 80; server_name _;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "setup"; add_header Content-Type text/plain; }
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

    [[ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]] && \
        curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf \
             -o /etc/letsencrypt/options-ssl-nginx.conf 2>/dev/null || true

    [[ ! -f /etc/letsencrypt/ssl-dhparams.pem ]] && {
        openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 2>/dev/null &
        DHPARAM_PID=$!
    }

    certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        -m "$CLIENT_EMAIL" -d cy360.${BASE_DOMAIN} -d cyscan.${BASE_DOMAIN} 2>/dev/null \
        && success "SSL: cy360, cyscan" || warn "Certbot failed — DNS may not be ready"

    for sub in cysiem cyiris cysoar; do
        certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
            -m "$CLIENT_EMAIL" -d ${sub}.${BASE_DOMAIN} 2>/dev/null \
            && success "SSL: ${sub}" || warn "Certbot failed for ${sub}"
    done

    [[ -n "${DHPARAM_PID:-}" ]] && wait "$DHPARAM_PID" 2>/dev/null || true
    cp "$SSL_CONF_BACKUP" "$SSL_CONF"
    nginx -t 2>/dev/null \
        && systemctl reload nginx && success "nginx reloaded with full SSL config" \
        || { warn "nginx SSL pending — re-run after DNS resolves"; ERRORS+=("nginx SSL pending"); }

fi  # end full nginx/SSL block

# ── Wazuh (full install only) ─────────────────────────────────────────────────
if [[ "$MODE" == "full" ]]; then

    step_header "WAZUH / CySIEM"
    if dpkg -l 2>/dev/null | grep -q wazuh-manager; then
        success "Wazuh already installed — ensuring services up"
        systemctl start wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
    else
        info "Running Wazuh all-in-one installer (5–10 min) ..."
        cd ~ && curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
        bash wazuh-install.sh -a && success "Wazuh installed" && cd ~
    fi

    # Wazuh rules and config from bundle
    CONFIG_SRC="/tmp/cycentra-config"
    if [[ -d "$CONFIG_SRC/rules" ]] && [[ -d /var/ossec ]]; then
        cp "$CONFIG_SRC/rules/"*.xml    /var/ossec/etc/rules/    2>/dev/null || true
        cp "$CONFIG_SRC/decoders/"*.xml /var/ossec/etc/decoders/ 2>/dev/null || true
        if [[ -f "$CONFIG_SRC/integrations/custom-llm.py" ]]; then
            cp "$CONFIG_SRC/integrations/custom-llm.py" /var/ossec/integrations/
            chmod 750 /var/ossec/integrations/custom-llm.py
            chown root:wazuh /var/ossec/integrations/custom-llm.py
        fi
        [[ -f "$CONFIG_SRC/conf/ossec.conf" ]] && {
            cp "$CONFIG_SRC/conf/ossec.conf" /var/ossec/etc/ossec.conf
            chmod 660 /var/ossec/etc/ossec.conf
            chown root:wazuh /var/ossec/etc/ossec.conf
        }
        /var/ossec/bin/wazuh-analysisd -t 2>/dev/null \
            && success "Wazuh rules valid" \
            || warn "wazuh-analysisd -t reported errors"
        systemctl restart wazuh-manager && success "wazuh-manager restarted"
    fi

    # Wazuh Dashboard bind to loopback
    WAZUH_YML="/etc/wazuh-dashboard/opensearch_dashboards.yml"
    if [[ -f "$WAZUH_YML" ]]; then
        cp "$WAZUH_YML" "${WAZUH_YML}.bak-$(date +%Y%m%d)" 2>/dev/null || true
        grep -q "^server.host:" "$WAZUH_YML" \
            && sed -i 's|^server.host:.*|server.host: "127.0.0.1"|' "$WAZUH_YML" \
            || echo 'server.host: "127.0.0.1"' >> "$WAZUH_YML"
        grep -q "^server.port:" "$WAZUH_YML" \
            && sed -i 's|^server.port:.*|server.port: 5601|' "$WAZUH_YML" \
            || echo 'server.port: 5601' >> "$WAZUH_YML"
        systemctl restart wazuh-dashboard 2>/dev/null || true
        success "Wazuh Dashboard: 127.0.0.1:5601"
    fi

fi  # end Wazuh block

# ── Branding ──────────────────────────────────────────────────────────────────
step_header "PLATFORM BRANDING"
for script in apply-favicons apply-logos enable-multitenancy apply-custom-branding apply-plugin-branding; do
    SPATH="$BRANDING_DIR/scripts/${script}.sh"
    [[ -f "$SPATH" ]] && bash "$SPATH" && success "${script}.sh" || info "${script}.sh not in bundle"
done

# ── Inject domain into portal + RBAC + config.json ───────────────────────────
step_header "PORTAL CONFIG & RBAC"

PORTAL_INDEX="$PORTAL_DIR/index.html"
if [[ -f "$PORTAL_INDEX" ]]; then
    sed -i '/window\.__CYCENTRA_DOMAIN__/d' "$PORTAL_INDEX"
    sed -i '/window\.__CYCENTRA_CLIENT__/d'  "$PORTAL_INDEX"
    sed -i "s|</head>|<script>window.__CYCENTRA_DOMAIN__='${BASE_DOMAIN}';window.__CYCENTRA_CLIENT__='${CLIENT_NAME}';</script></head>|" "$PORTAL_INDEX"
    success "Domain injected: ${BASE_DOMAIN}"
else
    warn "index.html not found — re-run after portal deploys"
fi

if [[ "$MODE" == "full" ]]; then
    cat > /opt/cycentra/rbac.json << RBACEOF
{ "${CLIENT_EMAIL}": { "role": "admin" } }
RBACEOF

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
fi

mkdir -p /var/log/cycentra && touch /var/log/cycentra/auth.log
chmod 644 /var/log/cycentra/auth.log

# ── Cron ──────────────────────────────────────────────────────────────────────
WORDLIST=$(find "$FLASK_SITE" -name "update_wordlist.py" 2>/dev/null | head -1)
if [[ -n "$WORDLIST" ]]; then
    ( crontab -l 2>/dev/null | grep -v "update_wordlist"
      echo "0 0 * * * $FLASK_VENV/bin/python3 $WORDLIST >> /opt/cycentra/cron.log 2>&1" ) | crontab -
    success "Cron: wordlist update registered"
fi

# ── Health checks ─────────────────────────────────────────────────────────────
step_header "HEALTH CHECKS"

chk() {
    local label=$1 url=$2
    local code; code=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    [[ "$code" =~ ^(200|301|302|401|403)$ ]] \
        && success "${label}: HTTP ${code}" \
        || warn    "${label}: HTTP ${code} — ${url}"
}

echo ""; info "── Ports ──"
_port_up 5252 && success "Flask   :5252" || warn "Flask   :5252 DOWN"
_port_up 8100 && success "Engine  :8100" || warn "Engine  :8100 DOWN"
_port_up 5433 && success "PG      :5433" || warn "PG      :5433 DOWN"
_port_up 6379 && success "Redis   :6379" || warn "Redis   :6379 DOWN"
_port_up 5601 && success "Wazuh   :5601" || warn "Wazuh   :5601 (install via portal)"
_port_up 4433 && success "CyIRIS  :4433" || warn "CyIRIS  :4433 (install via portal)"

echo ""; info "── Services ──"
for svc in cycentra-backend cysiemstack-engine postgresql redis-server nginx; do
    systemctl is-active "$svc" >/dev/null 2>&1 \
        && success "$svc active" || warn "$svc inactive"
done

echo ""; info "── HTTP ──"
chk "Flask /health"  "http://127.0.0.1:5252/health"
chk "Engine /health" "http://127.0.0.1:8100/health"

if [[ "$MODE" == "full" ]]; then
    echo ""; info "── HTTPS ──"
    chk "Portal"  "https://cy360.${BASE_DOMAIN}"
    chk "Backend" "https://cyscan.${BASE_DOMAIN}/health"
    chk "CySIEM"  "https://cysiem.${BASE_DOMAIN}"
fi

# ── Cleanup ───────────────────────────────────────────────────────────────────
step_header "CLEANUP"
rm -rf "$BUNDLE_DIR" /tmp/cycentra-release.tar.gz /tmp/cycentra-config
rm -f ~/wazuh-install.sh ~/wazuh-install-files* 2>/dev/null || true
success "Staging files removed"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""; divider
echo -e "\n  ${BOLD}${WHITE}CyCentra 360 — ${MODE^^} Complete${NC}\n"
divider; echo ""
echo -e "  ${CYAN}Version  ${NC}  ${BUNDLE_VERSION}"
[[ "$MODE" == "full" ]] && {
echo -e "  ${CYAN}Portal   ${NC}  https://cy360.${BASE_DOMAIN}"
echo -e "  ${CYAN}Backend  ${NC}  https://cyscan.${BASE_DOMAIN}"
echo -e "  ${CYAN}CySIEM   ${NC}  https://cysiem.${BASE_DOMAIN}"
echo -e "  ${CYAN}CyIRIS   ${NC}  https://cyiris.${BASE_DOMAIN}"
}
echo ""
echo -e "  ${BOLD}Flask service  :${NC}  systemctl status cycentra-backend"
echo -e "  ${BOLD}Engine service :${NC}  systemctl status cysiemstack-engine"
echo -e "  ${BOLD}Flask log      :${NC}  /opt/cycentra/flask.log"
echo -e "  ${BOLD}Engine log     :${NC}  /opt/cycentra/engine.log"
echo ""
echo -e "  ${BOLD}${YELLOW}Next steps:${NC}"
echo -e "  ${DIM}1. Set WAZUH_API_PASSWORD in /opt/cycentra/cysiemstack.env${NC}"
echo -e "  ${DIM}   then: systemctl restart cysiemstack-engine${NC}"
echo -e "  ${DIM}2. Install CyIRIS/CySOAR via portal${NC}"
echo -e "  ${DIM}3. To update: sudo bash cycentra-setup.sh --update${NC}"
echo ""

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    warn "${#ERRORS[@]} item(s) need attention:"
    for e in "${ERRORS[@]}"; do echo -e "  ${YELLOW}⚠${NC} $e"; done
fi

echo ""; divider; echo ""
