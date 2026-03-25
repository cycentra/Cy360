#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — Initial Setup Wizard v4.2
# Run as root on a fresh server or to reconfigure an existing deployment.
# Safe to re-run — all steps are idempotent.
# Usage: bash cycentra-setup.sh
#
# What this script does:
#   1. Collects client name, base domain, OAuth credentials, AI provider
#   2. Generates all secrets (.env written to /opt/cycentra/.env)
#   3. Installs nginx vhosts for all subdomains with SSL (Let's Encrypt)
#      cy360 vhost proxies /api/ /auth/ /oidc/ to Flask locally (no CORS)
#   4. Obtains TLS certificates via certbot (HTTP-01 challenge)
#   5. Injects window.__CYCENTRA_DOMAIN__ into portal index.html so the
#      React SPA resolves all URLs dynamically (no rebuild per customer)
#   6. Writes RBAC with admin email, writes config.json
#   7. Installs Flask as a systemd service (cycentra-backend) — survives reboots
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

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

step=0; total_steps=9
step_header() {
    step=$((step+1))
    echo -e "\n${BOLD}${CYAN}  STEP ${step}/${total_steps} — $1${NC}"
    divider
}

# ── Banner ─────────────────────────────────────────────────────────────────────
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
echo -e "  ${DIM}Initial Setup Wizard — v4.2${NC}"
echo ""; divider
echo -e "  Configures: nginx vhosts · SSL · OIDC SSO · RBAC · CySIEM auth logging"
divider; echo ""

[[ $EUID -ne 0 ]] && { error "Run as root: sudo bash cycentra-setup.sh"; exit 1; }

# ═══ STEP 1 — CLIENT INFO ═════════════════════════════════════════════════════
step_header "CLIENT INFORMATION"
ask CLIENT_NAME  "Client / Organisation name" "cycentra"
ask CLIENT_EMAIL "Primary admin email" "admin@${CLIENT_NAME,,}.com"
ask BASE_DOMAIN  "Base domain (e.g. clientname.com)" "${CLIENT_NAME,,}.com"

echo ""
info "Subdomains that will be configured:"
echo -e "  ${DIM}Portal  :${NC} cy360.${BASE_DOMAIN}"
echo -e "  ${DIM}Backend :${NC} cyscan.${BASE_DOMAIN}  ${DIM}(OIDC IdP + API)${NC}"
echo -e "  ${DIM}CySIEM  :${NC} cysiem.${BASE_DOMAIN}"
echo -e "  ${DIM}CyIRIS  :${NC} cyiris.${BASE_DOMAIN}  ${DIM}(Incident Response)${NC}"
echo -e "  ${DIM}CySOAR  :${NC} cysoar.${BASE_DOMAIN}  ${DIM}(Automation)${NC}"
echo ""

if ! ask_yn "Are these DNS A records already pointing to this server?"; then
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    warn "Add these DNS A records first:"
    for sub in cy360 cyscan cysiem cyiris cysoar; do
        echo -e "  ${WHITE}${sub}.${BASE_DOMAIN}${NC} → ${CYAN}${SERVER_IP}${NC}"
    done
    echo ""
    ask_yn "Continue anyway? (SSL will fail if DNS not ready)" "n" || { info "Exiting. Re-run once DNS is ready."; exit 0; }
fi

# ═══ STEP 2 — MODULE SELECTION ════════════════════════════════════════════════
step_header "MODULE SELECTION"
#echo -e "  ${DIM}CySIEM is always included as the base module.${NC}"; echo ""

INSTALL_CYIRIS=true
INSTALL_CYSOAR=true
INSTALL_CYSIEM=true

success "CyIRIS selected (default)"
success "CySOAR selected (default)"
success "CySIEM selected (default)"

# ═══ STEP 3 — OAUTH ═══════════════════════════════════════════════════════════
step_header "OAUTH / SSO CONFIGURATION"
echo -e "  ${DIM}Portal login via Google or Microsoft. Flask backend is the OIDC IdP for sub-apps.${NC}"; echo ""

PS3="  Choose provider: "
select OAUTH_PROVIDER in "Google" "Microsoft Azure AD" "Skip for now"; do
    case $REPLY in 1) OAUTH_PROVIDER="google"; break;; 2) OAUTH_PROVIDER="microsoft"; break;; 3) OAUTH_PROVIDER="skip"; break;; esac
done

if [[ "$OAUTH_PROVIDER" != "skip" ]]; then
    echo ""
    [[ "$OAUTH_PROVIDER" == "google" ]] && info "Redirect URI: https://cyscan.${BASE_DOMAIN}/auth/google/callback" \
                                         || info "Redirect URI: https://cyscan.${BASE_DOMAIN}/auth/microsoft/callback"
    echo ""
    ask OAUTH_CLIENT_ID "OAuth Client ID" ""
    ask_secret OAUTH_CLIENT_SECRET "OAuth Client Secret"
else
    warn "OAuth skipped — configure later in /opt/cycentra/.env"
    OAUTH_CLIENT_ID=""; OAUTH_CLIENT_SECRET=""
fi

# ═══ STEP 4 — AI ══════════════════════════════════════════════════════════════
step_header "AI ENRICHMENT (OPTIONAL)"
echo -e "  ${DIM}Adds risk narrative and remediation advice to scan results.${NC}"; echo ""

AI_PROVIDER="none"; AI_API_KEY=""; AI_MODEL=""
PS3="  Choose AI provider: "
select choice in "OpenAI (GPT-4)" "Anthropic (Claude)" "Local (Ollama)" "Skip"; do
    case $REPLY in
        1) AI_PROVIDER="openai";    AI_MODEL="gpt-4o";            break;;
        2) AI_PROVIDER="anthropic"; AI_MODEL="claude-sonnet-4-5"; break;;
        3) AI_PROVIDER="local";     AI_MODEL="mistral:7b";         break;;
        4) AI_PROVIDER="none";                                      break;;
    esac
done
[[ "$AI_PROVIDER" != "none" && "$AI_PROVIDER" != "local" ]] && ask AI_API_KEY "API Key for ${AI_PROVIDER}"
[[ "$AI_PROVIDER" == "local" ]] && ask AI_MODEL "Ollama model name" "mistral:7b"

# ═══ STEP 5 — SMTP CONFIGURATION (OPTIONAL) ═══════════════════════════════════
step_header "SMTP CONFIGURATION (OPTIONAL)"
echo -e "  ${DIM}Configure SMTP to enable email notifications from CySOAR support system.${NC}"
echo -e "  ${DIM}Leave blank to skip — CySOAR will work without SMTP (local logging only).${NC}"; echo ""

SMTP_HOST=""; SMTP_PORT=""; SMTP_USER=""; SMTP_PASS=""; SUPPORT_EMAIL=""

if ask_yn "Configure SMTP for CySOAR support emails?" "n"; then
    echo ""
    info "Common providers: Gmail (smtp.gmail.com), Office365 (smtp.office365.com)"
    ask SMTP_HOST "SMTP server hostname" "smtp.gmail.com"
    ask SMTP_PORT "SMTP port" "587"
    ask SMTP_USER "SMTP username (email address)" ""
    ask_secret SMTP_PASS "SMTP password (or App Password for Gmail)"
    ask SUPPORT_EMAIL "Support email destination" "support@${BASE_DOMAIN}"
    success "SMTP configured — CySOAR will send support emails to ${SUPPORT_EMAIL}"
else
    info "SMTP skipped — CySOAR support form will log locally (configure later in /opt/cycentra/.env)"
fi

# ═══ STEP 6 — GENERATE SECRETS ════════════════════════════════════════════════
step_header "GENERATING SECRETS"
info "Generating secrets for all services..."

# Preserve SECRET_KEY and JWT_SECRET if .env already exists.
# Regenerating these invalidates all active browser sessions — safe to rotate
# on a first install, disruptive on a re-run with live users.
_existing_env="/opt/cycentra/.env"
_get_existing() { grep -m1 "^${1}=" "$_existing_env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true; }

if [ -f "$_existing_env" ]; then
    info "Existing .env found — preserving session-critical secrets (SECRET_KEY, JWT_SECRET)"
    _sk=$(_get_existing SECRET_KEY);   FLASK_SECRET=${_sk:-$(gen_secret)}
    _jk=$(_get_existing JWT_SECRET);   JWT_SECRET=${_jk:-$(gen_secret)}
    _is=$(_get_existing IRIS_SECRET);  IRIS_SECRET=${_is:-$(gen_secret)}
    _ip=$(_get_existing IRIS_DB_PASS); IRIS_DB_PASS=${_ip:-$(gen_pass)}
    _nr=$(_get_existing NODE_RED_CREDENTIAL_SECRET); NODERED_SECRET=${_nr:-$(gen_secret)}
else
    FLASK_SECRET=$(gen_secret)
    IRIS_SECRET=$(gen_secret)
    IRIS_DB_PASS=$(gen_pass)
    JWT_SECRET=$(gen_secret)
    NODERED_SECRET=$(gen_secret)
fi

# Always rotate module-scoped secrets (no live user sessions depend on these)
ADMIN_API_KEY=$(gen_secret)
CYIRIS_OIDC_SECRET=$(gen_secret)
CYSOAR_OIDC_SECRET=$(gen_secret)

success "All secrets generated"

# ═══ STEP 7 — CONFIRM ════════════════════════════════════════════════════════
step_header "REVIEW & CONFIRM"
echo -e "  ${DIM}Client    :${NC} ${WHITE}${CLIENT_NAME}${NC}"
echo -e "  ${DIM}Email     :${NC} ${WHITE}${CLIENT_EMAIL}${NC}"
echo -e "  ${DIM}Domain    :${NC} ${WHITE}${BASE_DOMAIN}${NC}"
echo -e "  ${DIM}OAuth     :${NC} ${WHITE}${OAUTH_PROVIDER}${NC}"
echo -e "  ${DIM}AI        :${NC} ${WHITE}${AI_PROVIDER}${NC}"
echo -e "  ${DIM}SMTP      :${NC} ${WHITE}${SMTP_HOST:-not configured}${NC}"
echo ""
echo -e "  ${DIM}Actions   :${NC} .env · nginx vhosts · SSL certs · OIDC secrets · RBAC · CySIEM rules · Flask restart"
echo ""
ask_yn "Proceed with setup?" || { warn "Cancelled. No changes made."; exit 0; }

# ═══ STEP 8 — APPLY ══════════════════════════════════════════════════════════
step_header "APPLYING CONFIGURATION"
ERRORS=()

# 7a-pre — Pre-flight: check services are listening before writing nginx ───────
info "Pre-flight service checks ..."
_port_up() { ss -tlnp 2>/dev/null | grep -q ":${1} "; }

_port_up 5252 && success "Flask backend    :5252 — UP" \
              || warn    "Flask backend    :5252 — NOT listening (will check again after systemd install)"
_port_up 3001 && success "Portal (PM2)     :3001 — UP" \
              || warn    "Portal (PM2)     :3001 — NOT listening (deploy portal + start PM2)"
_port_up 5601 && success "Wazuh Dashboard  :5601 — UP" \
              || warn    "Wazuh Dashboard  :5601 — NOT listening (install CySIEM via portal)"
_port_up 4433 && success "DFIR-IRIS        :4433 — UP" \
              || warn    "DFIR-IRIS        :4433 — NOT listening (install CyIRIS via portal)"
_port_up 1880 && success "Node-RED         :1880 — UP" \
              || warn    "Node-RED         :1880 — NOT listening (install CySOAR via portal)"

echo ""
info "Docker container status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
    || warn "Docker not running or no containers found"
echo ""

# 7a — Write .env ─────────────────────────────────────────────────────────────
info "Writing /opt/cycentra/.env ..."
mkdir -p /opt/cycentra

cat > /opt/cycentra/.env << EOF
# CyCentra 360 — generated by setup wizard v4.2
# Client: ${CLIENT_NAME} | Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

BASE_DOMAIN=${BASE_DOMAIN}
CLIENT_NAME=${CLIENT_NAME}
SECRET_KEY=${FLASK_SECRET}
JWT_SECRET=${JWT_SECRET}
ADMIN_API_KEY=${ADMIN_API_KEY}
FRONTEND_URL=https://cy360.${BASE_DOMAIN}
BASE_URL=https://cyscan.${BASE_DOMAIN}

# OAuth (portal login)
OAUTH_PROVIDER=${OAUTH_PROVIDER}
EOF

[[ "$OAUTH_PROVIDER" == "google" ]]    && cat >> /opt/cycentra/.env << EOF
GOOGLE_CLIENT_ID=${OAUTH_CLIENT_ID}
GOOGLE_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
EOF
[[ "$OAUTH_PROVIDER" == "microsoft" ]] && cat >> /opt/cycentra/.env << EOF
MICROSOFT_CLIENT_ID=${OAUTH_CLIENT_ID}
MICROSOFT_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
EOF

cat >> /opt/cycentra/.env << EOF

# OIDC client secrets (Flask IdP issues tokens to sub-apps using these)
CYIRIS_OIDC_SECRET=${CYIRIS_OIDC_SECRET}
CYSOAR_OIDC_SECRET=${CYSOAR_OIDC_SECRET}

# ── Image registry config ─────────────────────────────────────────────────────
USE_CUSTOM_IMAGES=yes
CUSTOM_IMAGE_REGISTRY=ghcr.io/cycentra

# CyIRIS entrypoint path (inside the container — not an image override)
CYIRIS_ENTRYPOINT=/iriswebapp/iris-entrypoint.sh

# CySIEM (Wazuh) — always use upstream public images
CYSIEM_IMAGE_MANAGER=wazuh/wazuh-manager:4.7.5
CYSIEM_IMAGE_INDEXER=wazuh/wazuh-indexer:4.7.5
CYSIEM_IMAGE_DASHBOARD=wazuh/wazuh-dashboard:4.7.5

# Node-RED credential encryption key
NODE_RED_CREDENTIAL_SECRET=${NODERED_SECRET}

# CyIRIS (DFIR IRIS)
IRIS_SECRET=${IRIS_SECRET}
IRIS_DB_PASS=${IRIS_DB_PASS}
IRIS_ADM_EMAIL=${CLIENT_EMAIL}
IRIS_ADM_PASSWORD=CyIRIS@CHANGE

# CyIRIS aliased var names (app.py compose template reads these)
CYCENTRA_PORTAL_URL=https://cy360.${BASE_DOMAIN}
IRIS_SECRET_KEY=${IRIS_SECRET}
POSTGRES_PASSWORD=${IRIS_DB_PASS}

# AI enrichment
AI_PROVIDER=${AI_PROVIDER}
AI_API_KEY=${AI_API_KEY:-}
AI_MODEL=${AI_MODEL:-}

# CySOAR SMTP Configuration
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-}
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SUPPORT_EMAIL=${SUPPORT_EMAIL:-support@cycentra.com}
EOF

# Symlink for legacy /root/cy-asm/.env path
mkdir -p /root/cy-asm
cp /opt/cycentra/.env /root/cy-asm/.env
success ".env written → /opt/cycentra/.env"

# 7b — Write nginx ────────────────────────────────────────────────────────────
# 7c-pre -- Free port 443 before nginx tries to bind it
# On servers with a native Wazuh install the dashboard binds :443 directly.

info "Writing nginx configuration ..."

cat > /etc/nginx/sites-available/cycentra-modules << NGINXEOF
# CyCentra 360 nginx — generated by setup wizard v4.2
# Client: ${CLIENT_NAME} | Domain: ${BASE_DOMAIN}
#
# Each vhost includes:
#   • frame-ancestors CSP  — only portal can embed sub-apps as iframes
#   • X-Frame-Options ""   — clears any upstream deny; CSP takes precedence
#   • proxy_cookie_flags   — forces SameSite=None; Secure on session cookies
#                            so cross-origin iframe sessions survive
#   • CORS headers          — portal JS can call sub-app APIs directly
#   • HSTS + nosniff        — baseline security headers on all vhosts

# WebSocket upgrade map — conditionally set Connection header
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# ── Portal (React SPA) ────────────────────────────────────────────────────────
server {
    listen 80; server_name cy360.${BASE_DOMAIN};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2; server_name cy360.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff"                             always;
    add_header X-XSS-Protection          "1; mode=block"                      always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin"    always;
    # Portal embeds module iframes — CSP must list all module origins in frame-src
    # Note: /node-red/ location overrides this with its own CSP
    add_header Content-Security-Policy "
        default-src 'self';
        script-src  'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com;
        style-src   'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com;
        font-src    'self' https://fonts.gstatic.com;
        img-src     'self' data: https:;
        connect-src 'self' wss: ws: https://catalogue.nodered.org https://cyscan.${BASE_DOMAIN} https://cysiem.${BASE_DOMAIN} https://cyiris.${BASE_DOMAIN} https://cysoar.${BASE_DOMAIN} https://cy360.${BASE_DOMAIN}/cyiris https://cy360.${BASE_DOMAIN}/cysiem https://cy360.${BASE_DOMAIN}/node-red;
        frame-src   'self' https://cysiem.${BASE_DOMAIN} https://cyiris.${BASE_DOMAIN} https://cysoar.${BASE_DOMAIN} https://cy360.${BASE_DOMAIN}/cyiris https://cy360.${BASE_DOMAIN}/cysiem https://cy360.${BASE_DOMAIN}/node-red;
    " always;

    root /var/www/cycentra360; index index.html;

    # ── SPA static files ───────────────────────────────────────────────────────
    location /         { try_files \$uri \$uri/ /index.html; }
    location /assets/  { expires 1y; add_header Cache-Control "public, immutable"; }
    location = /index.html { add_header Cache-Control "no-cache, no-store, must-revalidate"; expires 0; }

    # ── API proxy → Flask on loopback (127.0.0.1:5252) ────────────────────────
    # SPA calls /api/ /auth/ /oidc/ as same-origin relative URLs.
    # nginx forwards to Flask locally — zero CORS, no Cloudflare roundtrip.
    # cyscan.${BASE_DOMAIN} stays independently reachable from the internet.
    location /api/ {
        proxy_pass         http://127.0.0.1:5252;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 180s;
        proxy_send_timeout  30s;
        proxy_buffering    off;
    }
    location /auth/ {
        proxy_pass         http://127.0.0.1:5252;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout  30s;
    }
    location /oidc/ {
        proxy_pass         http://127.0.0.1:5252;
        proxy_http_version 1.1;
        proxy_set_header   Connection        "";
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout  30s;
    }

    # CySOAR - Docker port 1880
    # Override CSP for Node-RED editor — needs permissive policy for dynamic loading, blobs, workers
    # Authentication: validates Flask session before allowing access
    # Node-RED runs at root /, nginx strips /cysoar or /node-red prefix before forwarding
    # Both /cysoar/ and /node-red/ URLs work (backward compatibility)
    location /cysoar/ {
        # Check authentication via Flask backend
        auth_request /auth-check;
        error_page 401 = @node_red_login;
        
        # Clear inherited CSP and set Node-RED-compatible policy
        add_header Content-Security-Policy "
            default-src 'self' 'unsafe-inline' 'unsafe-eval';
            script-src  'self' 'unsafe-inline' 'unsafe-eval' blob:;
            style-src   'self' 'unsafe-inline';
            font-src    'self' data:;
            img-src     'self' data: blob: https:;
            connect-src 'self' ws: wss: https://catalogue.nodered.org;
            worker-src  'self' blob:;
        " always;
        
        # Trailing slash strips /cysoar prefix before forwarding to Node-RED
        proxy_pass         http://127.0.0.1:1880/;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade           \$http_upgrade;
        proxy_set_header   Connection        \$connection_upgrade;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_set_header   Cookie            \$http_cookie;
        proxy_read_timeout 120s;
        proxy_buffering    off;
        proxy_cache_bypass \$http_upgrade;
    }

    # Internal auth check endpoint
    location = /auth-check {
        internal;
        proxy_pass              http://127.0.0.1:5252/api/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        Cookie \$http_cookie;
    }

    # Redirect to portal login on auth failure
    location @node_red_login {
        return 302 https://cy360.${BASE_DOMAIN}/?returnTo=\$scheme://\$host\$request_uri;
    }

}

# ── Backend / OIDC IdP (Flask on :5252) ──────────────────────────────────────
server {
    listen 80; server_name cyscan.${BASE_DOMAIN};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2; server_name cyscan.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff" always;

    # CORS — allow all module subdomains to call the OIDC + API endpoints
    set \$cors_origin "";
    if (\$http_origin ~* "^https://(cy360|cysiem|cyiris|cysoar)\.${BASE_DOMAIN}\$") {
        set \$cors_origin \$http_origin;
    }
    add_header Access-Control-Allow-Origin      \$cors_origin                           always;
    add_header Access-Control-Allow-Credentials "true"                                   always;
    add_header Access-Control-Allow-Methods     "GET, POST, DELETE, OPTIONS"             always;
    add_header Access-Control-Allow-Headers     "Content-Type, Authorization, X-CyCentra-AdminKey" always;
    if (\$request_method = OPTIONS) { return 204; }

    location / {
        proxy_pass            http://127.0.0.1:5252;
        proxy_http_version    1.1;
        proxy_set_header      Upgrade            \$http_upgrade;
        proxy_set_header      Connection         \$connection_upgrade;
        proxy_set_header      Host               \$host;
        proxy_set_header      X-Real-IP          \$remote_addr;
        proxy_set_header      X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header      X-Forwarded-Proto  \$scheme;
        proxy_read_timeout    300;
        proxy_connect_timeout 300;
    }
}

NGINXEOF

# CyIRIS block
if [[ "$INSTALL_CYIRIS" == true ]]; then
cat >> /etc/nginx/sites-available/cycentra-modules << NGINXEOF

# ── CyIRIS / DFIR IRIS (on :4433) ────────────────────────────────────────────
server {
    listen 80; server_name cyiris.${BASE_DOMAIN};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2; server_name cyiris.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cyiris.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cyiris.${BASE_DOMAIN}/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           ""        always;
    add_header Content-Security-Policy   "frame-ancestors 'self' https://cy360.${BASE_DOMAIN}" always;
    add_header Access-Control-Allow-Origin      "https://cy360.${BASE_DOMAIN}" always;
    add_header Access-Control-Allow-Credentials "true"                          always;
    add_header Access-Control-Allow-Methods     "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers     "Authorization, Content-Type, X-IRIS-AUTH" always;
    if (\$request_method = OPTIONS) { return 204; }

    # OIDC callback must reach IRIS directly — no interference
    location /auth/oidc/callback {
        proxy_pass           http://127.0.0.1:4433;
        proxy_set_header     Host              \$host;
        proxy_set_header     X-Forwarded-Proto https;
    }

    location / {
        proxy_pass            http://127.0.0.1:4433;
        proxy_http_version    1.1;
        proxy_set_header      Upgrade           \$http_upgrade;
        proxy_set_header      Connection        \$connection_upgrade;
        proxy_set_header      Host              \$host;
        proxy_set_header      X-Real-IP         \$remote_addr;
        proxy_set_header      X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header      X-Forwarded-Proto https;
        proxy_read_timeout    300;
        proxy_connect_timeout 300;
        proxy_buffer_size     128k;
        proxy_buffers         4 256k;
        # Critical: SameSite=None; Secure so IRIS session cookie survives cross-origin iframe
        proxy_cookie_flags    ~ samesite=none secure;
    }
}
NGINXEOF
fi

# CySIEM block
if [[ "$INSTALL_CYSIEM" == true ]]; then
cat >> /etc/nginx/sites-available/cycentra-modules << NGINXEOF

# ── CySIEM (on :5601) ─────────────────────────────────────────────
server {
    listen 80; server_name cysiem.${BASE_DOMAIN};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2; server_name cysiem.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           ""        always;
    add_header Content-Security-Policy   "frame-ancestors 'self' https://cy360.${BASE_DOMAIN}" always;
    add_header Access-Control-Allow-Origin      "https://cy360.${BASE_DOMAIN}" always;
    add_header Access-Control-Allow-Credentials "true"                          always;
    add_header Access-Control-Allow-Methods     "GET, POST, OPTIONS"            always;
    add_header Access-Control-Allow-Headers     "Content-Type, Authorization"   always;
    if (\$request_method = OPTIONS) { return 204; }

    # OIDC callback
    location /auth/callback {
        proxy_pass           http://127.0.0.1:5601;
        proxy_set_header     Host              \$host;
        proxy_set_header     X-Forwarded-Proto https;
    }

    location / {
        proxy_pass            http://127.0.0.1:5601;
        proxy_http_version    1.1;
        proxy_set_header      Upgrade           \$http_upgrade;
        proxy_set_header      Connection        \$connection_upgrade;
        proxy_set_header      Host              \$host;
        proxy_set_header      X-Real-IP         \$remote_addr;
        proxy_set_header      X-Forwarded-Proto https;
        proxy_read_timeout    120;
        proxy_buffering       off;
        proxy_cookie_flags    ~ samesite=none secure;
    }
}
NGINXEOF
fi

# Save full SSL config, write HTTP-only stub so nginx starts for ACME challenge
SSL_CONF="/etc/nginx/sites-available/cycentra-modules"
SSL_CONF_BACKUP="/etc/nginx/sites-available/cycentra-modules.ssl-pending"
cp "$SSL_CONF" "$SSL_CONF_BACKUP"

mkdir -p /var/www/html  # webroot for certbot challenge

# Stub: plain HTTP per subdomain, just enough for certbot HTTP-01 challenge
cat > "$SSL_CONF" << STUBEOF
server {
    listen 80;
    server_name cy360.${BASE_DOMAIN} cyscan.${BASE_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "setup-in-progress"; add_header Content-Type text/plain; }
}
STUBEOF
[[ "$INSTALL_CYSIEM" == true ]] && cat >> "$SSL_CONF" << STUBEOF
server {
    listen 80; server_name cysiem.${BASE_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "setup-in-progress"; add_header Content-Type text/plain; }
}
STUBEOF
[[ "$INSTALL_CYIRIS" == true ]] && cat >> "$SSL_CONF" << STUBEOF
server {
    listen 80; server_name cyiris.${BASE_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "setup-in-progress"; add_header Content-Type text/plain; }
}
STUBEOF
[[ "$INSTALL_CYSOAR" == true ]] && cat >> "$SSL_CONF" << STUBEOF
server {
    listen 80; server_name cysoar.${BASE_DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 200 "setup-in-progress"; add_header Content-Type text/plain; }
}
STUBEOF

ln -sf /etc/nginx/sites-available/cycentra-modules \
        /etc/nginx/sites-enabled/cycentra-modules 2>/dev/null || true
nginx -t 2>/dev/null \
    && { systemctl reload nginx 2>/dev/null || systemctl start nginx 2>/dev/null; success "nginx started (HTTP stub for Certbot)"; } \
    || { error "nginx stub config invalid"; ERRORS+=("nginx failed to start"); }

# 7d-pre — Generate Certbot support files missing on fresh servers ────────────
# options-ssl-nginx.conf and ssl-dhparams.pem are normally created by certbot
# when using --nginx mode, but since we use --webroot they must be created manually.
# dhparam generation runs in the background so it doesn't block certbot.
if [[ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]]; then
    info "Downloading options-ssl-nginx.conf ..."
    mkdir -p /etc/letsencrypt
    curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf \
        -o /etc/letsencrypt/options-ssl-nginx.conf \
        && success "options-ssl-nginx.conf downloaded" \
        || { error "Failed to download options-ssl-nginx.conf"; ERRORS+=("options-ssl-nginx.conf missing"); }
fi
if [[ ! -f /etc/letsencrypt/ssl-dhparams.pem ]]; then
    info "Generating ssl-dhparams.pem in background (2048-bit, ~30s) ..."
    openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 2>/dev/null &
    DHPARAM_PID=$!
fi

# 7d — SSL certificates (Independent Subdomains)
info "Obtaining SSL certificates ..."

# 1. Base Portal & Backend (Bundled together as the core platform)
BASE_CERT_DOMAINS="-d cy360.${BASE_DOMAIN} -d cyscan.${BASE_DOMAIN}"
certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
    -m "${CLIENT_EMAIL}" ${BASE_CERT_DOMAINS} 2>/dev/null \
    && success "SSL cert obtained (cy360, cyscan)" \
    || warn "Certbot failed for base domains"

# 2. Independent CyIRIS
if [[ "$INSTALL_CYIRIS" == true ]]; then
    certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        -m "${CLIENT_EMAIL}" -d cyiris.${BASE_DOMAIN} 2>/dev/null \
        && success "CyIRIS SSL cert obtained" \
        || warn "Certbot failed for cyiris"
fi

# 3. Independent CySIEM
if [[ "$INSTALL_CYSIEM" == true ]]; then
    certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        -m "${CLIENT_EMAIL}" -d cysiem.${BASE_DOMAIN} 2>/dev/null \
        && success "CySIEM SSL cert obtained" \
        || warn "Certbot failed for cysiem"
fi

# 4. Independent CySOAR
if [[ "$INSTALL_CYSOAR" == true ]]; then
    certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
        -m "${CLIENT_EMAIL}" -d cysoar.${BASE_DOMAIN} 2>/dev/null \
        && success "CySOAR SSL cert obtained" \
        || warn "Certbot failed for cysoar"
fi

# Restore full SSL config now that certs exist
# Wait for background dhparam generation to finish first
if [[ -n "${DHPARAM_PID:-}" ]]; then
    info "Waiting for ssl-dhparams.pem to finish generating ..."
    wait "$DHPARAM_PID" && success "ssl-dhparams.pem ready" \
        || { error "dhparam generation failed — retrying foreground"; \
             openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048 2>/dev/null; }
fi
cp "$SSL_CONF_BACKUP" "$SSL_CONF"
if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null && success "nginx reloaded with full SSL config"
else
    warn "nginx SSL config not valid yet — certs may still be missing"
    warn "After DNS resolves, run: certbot certonly --nginx -m ${CLIENT_EMAIL} ${BASE_CERT_DOMAINS} && nginx -t && systemctl reload nginx"
    ERRORS+=("nginx SSL config pending — run certbot then reload nginx")
fi

# 7e — Inject BASE_DOMAIN into portal index.html ─────────────────────────────
# App.jsx reads window.__CYCENTRA_DOMAIN__ at runtime to derive all URLs
# (cyscan.domain, cysiem.domain, etc.) without a rebuild per customer.
info "Injecting domain config into portal index.html ..."
PORTAL_INDEX="/var/www/cycentra360/index.html"
if [[ -f "$PORTAL_INDEX" ]]; then
    # Remove any existing injection (safe on re-run)
    sed -i '/window\.__CYCENTRA_DOMAIN__/d' "$PORTAL_INDEX"
    sed -i '/window\.__CYCENTRA_CLIENT__/d'  "$PORTAL_INDEX"
    # Inject before </head> — App.jsx will read these on startup
    sed -i "s|</head>|<script>window.__CYCENTRA_DOMAIN__='${BASE_DOMAIN}';window.__CYCENTRA_CLIENT__='${CLIENT_NAME}';</script></head>|" "$PORTAL_INDEX"
    success "Injected __CYCENTRA_DOMAIN__='${BASE_DOMAIN}' into portal"
else
    warn "Portal index.html not found at ${PORTAL_INDEX} — will inject after portal is deployed"
    warn "After deploying portal, run:  bash cycentra-setup.sh  (re-run is safe)"
    ERRORS+=("Portal index.html not found — re-run setup after deploying portal files")
fi

# Write config.json — consumed by any external tooling, monitoring, or status pages
mkdir -p /var/www/cycentra360
cat > /var/www/cycentra360/config.json << EOF
{
  "base_domain": "${BASE_DOMAIN}",
  "client_name": "${CLIENT_NAME}",
  "cyscan_url":  "https://cyscan.${BASE_DOMAIN}",
  "portal_url":  "https://cy360.${BASE_DOMAIN}",
  "cysiem_url":  "https://cy360.${BASE_DOMAIN}/cysiem",
  "cyiris_url":  "https://cy360.${BASE_DOMAIN}/cyiris",
  "cysiem_subdomain":  "https://cysiem.${BASE_DOMAIN}",
  "cyiris_subdomain":  "https://cyiris.${BASE_DOMAIN}",
  "cysoar_subdomain":  "https://cysoar.${BASE_DOMAIN}",
  "modules": { "cyiris": ${INSTALL_CYIRIS}, "cysoar": ${INSTALL_CYSOAR}, "cysiem": ${INSTALL_CYSIEM} },
  "routing": "path-based",
  "generated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
success "config.json written → /var/www/cycentra360/config.json"

# 7f — RBAC ───────────────────────────────────────────────────────────────────
info "Configuring RBAC — ${CLIENT_EMAIL} → admin ..."
cat > /opt/cycentra/rbac.json << EOF
{ "${CLIENT_EMAIL}": { "role": "admin" } }
EOF
success "RBAC initialised. Add users: POST https://cyscan.${BASE_DOMAIN}/api/rbac/users"


# 7g — CySIEM auth log ingestion — manual step (do after CySIEM installed)
mkdir -p /var/log/cycentra && touch /var/log/cycentra/auth.log
chmod 644 /var/log/cycentra/auth.log
success "Auth log file created: /var/log/cycentra/auth.log"

# 7h — nginx reload handled above after certbot completes

# 7i — Install systemd service + start Flask backend ────────────────────────────
info "Installing Flask backend as systemd service ..."
FLASK_DIR="/opt/cycentra/backend"
if [[ ! -f "${FLASK_DIR}/app.py" ]]; then
    error "app.py not found at ${FLASK_DIR}/app.py — was the backend repo cloned?"
    ERRORS+=("Flask app.py missing at ${FLASK_DIR}")
else
    # Determine python binary (prefer venv)
    PYTHON_BIN="${FLASK_DIR}/venv/bin/python3"
    [[ ! -f "$PYTHON_BIN" ]] && PYTHON_BIN="$(which python3)"

    # Write systemd unit — survives reboots, auto-restarts on crash
    cat > /etc/systemd/system/cycentra-backend.service << UNITEOF
[Unit]
Description=CyCentra 360 Flask Backend
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${FLASK_DIR}
EnvironmentFile=/opt/cycentra/.env
ExecStart=${PYTHON_BIN} app.py
Restart=always
RestartSec=5
StandardOutput=append:${FLASK_DIR}/flask.log
StandardError=append:${FLASK_DIR}/flask.log

[Install]
WantedBy=multi-user.target
UNITEOF

    systemctl daemon-reload
    systemctl enable cycentra-backend
    # Stop old nohup instance if running before starting via systemd
    pkill -f "python3.*app.py" 2>/dev/null || true
    sleep 1
    systemctl restart cycentra-backend
    sleep 3
    if curl -s --max-time 5 http://127.0.0.1:5252/health | grep -q "ok"; then
        success "Flask backend running → http://127.0.0.1:5252 (systemd: cycentra-backend)"
    else
        error "Flask backend failed to start — check: journalctl -u cycentra-backend -n 30"
        ERRORS+=("Flask backend failed — check: journalctl -u cycentra-backend -n 30")
    fi
fi

# 7j — Check portal files + inject domain ────────────────────────────────────
PORTAL_DIR="/var/www/cycentra360"
mkdir -p "${PORTAL_DIR}"
if [[ ! -f "${PORTAL_DIR}/index.html" ]]; then
    warn "Portal not yet deployed to ${PORTAL_DIR}/index.html"
    warn "Build and deploy the portal, then re-run this script to inject the domain config."
    warn ""
    warn "  Option A — build on this server:"
    warn "    cd /opt/cycentra/portal && npm ci && npm run build"
    warn "    cp -r dist/* ${PORTAL_DIR}/"
    warn ""
    warn "  Option B — build on your workstation then copy:"
    warn "    npm run build"
    warn "    rsync -av dist/ root@SERVER_IP:${PORTAL_DIR}/"
    warn ""
    warn "  Then re-run:  bash cycentra-setup.sh"
    ERRORS+=("Portal not deployed — deploy to ${PORTAL_DIR}/ then re-run setup")
else
    success "Portal files present at ${PORTAL_DIR}"
    # Re-inject domain in case portal was deployed after initial setup run
    sed -i '/window\.__CYCENTRA_DOMAIN__/d' "${PORTAL_DIR}/index.html" 2>/dev/null || true
    sed -i '/window\.__CYCENTRA_CLIENT__/d'  "${PORTAL_DIR}/index.html" 2>/dev/null || true
    sed -i "s|</head>|<script>window.__CYCENTRA_DOMAIN__='${BASE_DOMAIN}';window.__CYCENTRA_CLIENT__='${CLIENT_NAME}';</script></head>|" "${PORTAL_DIR}/index.html"
    success "Domain config injected into portal → ${BASE_DOMAIN}"
fi

# 7k — Health checks ──────────────────────────────────────────────────────────
info "Running health checks ..."
sleep 2

chk() {
    local label=$1 url=$2
    local code
    code=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    if [[ "$code" =~ ^(200|301|302|401|403)$ ]]; then
        success "${label}: HTTP ${code} — ${DIM}${url}${NC}"
    else
        warn "${label}: HTTP ${code} (unreachable or not started) — ${DIM}${url}${NC}"
    fi
}

_port_up() { ss -tlnp 2>/dev/null | grep -q ":${1} "; }

echo ""
info "── Internal port checks ──"
_port_up 5252 && success "Flask backend    :5252 — listening" || warn "Flask backend    :5252 — NOT listening"
_port_up 3001 && success "Portal (PM2)     :3001 — listening" || warn "Portal (PM2)     :3001 — NOT listening"
_port_up 5601 && success "Wazuh Dashboard  :5601 — listening" || warn "Wazuh Dashboard  :5601 — NOT listening"
_port_up 4433 && success "DFIR-IRIS        :4433 — listening" || warn "DFIR-IRIS        :4433 — NOT listening"
_port_up 1880 && success "Node-RED         :1880 — listening" || warn "Node-RED         :1880 — NOT listening"

echo ""
info "── Internal HTTP checks ──"
chk "Flask /health"   "http://127.0.0.1:5252/health"
chk "OIDC discovery"  "http://127.0.0.1:5252/oidc/.well-known/openid-configuration"

echo ""
info "── Docker container status ──"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
    || warn "Docker not running or no containers found"

echo ""
info "── nginx config validation ──"
if nginx -t 2>/dev/null; then
    success "nginx config valid"
else
    warn "nginx config has errors — run: nginx -t  for details"
    ERRORS+=("nginx config invalid — run nginx -t")
fi

echo ""
info "── External HTTPS checks ──"
chk "Portal (HTTPS)"  "https://cy360.${BASE_DOMAIN}"
chk "Backend (HTTPS)" "https://cyscan.${BASE_DOMAIN}/health"
[[ "$INSTALL_CYSIEM" == true ]] && chk "CySIEM"  "https://cysiem.${BASE_DOMAIN}"
[[ "$INSTALL_CYIRIS" == true ]] && chk "CyIRIS"  "https://cyiris.${BASE_DOMAIN}/api/v2/ping"
[[ "$INSTALL_CYSOAR" == true ]] && chk "CySOAR"  "https://cysoar.${BASE_DOMAIN}"

# ═══ STEP 8 — SUMMARY ════════════════════════════════════════════════════════
step_header "COMPLETE"
echo ""
divider
echo -e "\n  ${BOLD}${WHITE}CyCentra 360 — Setup Summary:${NC}\n"
divider
echo ""
echo -e "  ${CYAN}Portal   ${NC}  https://cy360.${BASE_DOMAIN}"
echo -e "  ${CYAN}Backend  ${NC}  https://cyscan.${BASE_DOMAIN}"
echo -e "  ${CYAN}CySIEM   ${NC}  https://cysiem.${BASE_DOMAIN}"
[[ "$INSTALL_CYIRIS" == true ]] && echo -e "  ${CYAN}CyIRIS   ${NC}  https://cyiris.${BASE_DOMAIN}"
[[ "$INSTALL_CYSOAR" == true ]] && echo -e "  ${CYAN}CySOAR   ${NC}  https://cysoar.${BASE_DOMAIN}"
echo ""
echo -e "  ${BOLD}Flask backend:${NC}  ${FLASK_DIR}/app.py"
echo -e "  ${BOLD}Flask log:${NC}      ${FLASK_DIR}/flask.log"
echo -e "  ${BOLD}Flask service:${NC}  systemctl status cycentra-backend"
echo -e "  ${BOLD}Portal files:${NC}   ${PORTAL_DIR}/"
echo -e "  ${BOLD}Env file:${NC}       /opt/cycentra/.env"
echo -e "  ${BOLD}RBAC file:${NC}      /opt/cycentra/rbac.json"
echo -e "  ${BOLD}nginx config:${NC}   /etc/nginx/sites-available/cycentra-modules
  ${BOLD}Reload nginx:${NC}   nginx -t && systemctl reload nginx"
echo ""
echo -e "  ${BOLD}Admin API key:${NC}  ${WHITE}${ADMIN_API_KEY}${NC}"
[[ "$INSTALL_CYIRIS" == true ]] && echo -e "  ${BOLD}CyIRIS secret:${NC}  ${WHITE}${CYIRIS_OIDC_SECRET}${NC}"
[[ "$INSTALL_CYSOAR" == true ]] && echo -e "  ${BOLD}CySOAR secret:${NC}  ${WHITE}${CYSOAR_OIDC_SECRET}${NC}"
echo ""

cat > /root/cycentra-setup-summary.txt << EOF
CyCentra 360 Setup Summary v4.2
Generated: $(date)
═══════════════════════════════════
Client:  ${CLIENT_NAME}
Domain:  ${BASE_DOMAIN}
Email:   ${CLIENT_EMAIL}
OAuth:   ${OAUTH_PROVIDER}
AI:      ${AI_PROVIDER}

URLs:
  Portal:   https://cy360.${BASE_DOMAIN}
  Backend:  https://cyscan.${BASE_DOMAIN}
  CySIEM:   https://cysiem.${BASE_DOMAIN}
$([ "$INSTALL_CYIRIS" == true ] && echo "  CyIRIS:   https://cyiris.${BASE_DOMAIN}")
$([ "$INSTALL_CYSOAR" == true ] && echo "  CySOAR:   https://cysoar.${BASE_DOMAIN}")

Paths:
  Flask app:    ${FLASK_DIR}/app.py
  Flask log:    ${FLASK_DIR}/flask.log
  Portal:       ${PORTAL_DIR}/
  Env:          /opt/cycentra/.env
  RBAC:         /opt/cycentra/rbac.json
  Nginx:        /etc/nginx/sites-available/cycentra-modules

Secrets:
  ADMIN_API_KEY=${ADMIN_API_KEY}
$([ "$INSTALL_CYIRIS" == true ] && echo "  CYIRIS_OIDC_SECRET=${CYIRIS_OIDC_SECRET}")
$([ "$INSTALL_CYSOAR" == true ] && echo "  CYSOAR_OIDC_SECRET=${CYSOAR_OIDC_SECRET}")
  JWT_SECRET=${JWT_SECRET}

Next steps:
  1. Deploy portal to ${PORTAL_DIR}/ then re-run setup to inject domain config
     Option A (on server):   cd /opt/cycentra/portal && npm ci && npm run build && cp -r dist/* ${PORTAL_DIR}/
     Option B (workstation): rsync -av dist/ root@SERVER_IP:${PORTAL_DIR}/
  2. Manage Flask service:  systemctl status|restart|stop cycentra-backend
  3. Install modules via portal or API: POST https://cyscan.${BASE_DOMAIN}/api/platform/install
  4. Add Wazuh auth log ingestion for CySIEM correlation
EOF
success "Summary saved → /root/cycentra-setup-summary.txt"

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo ""
    warn "${#ERRORS[@]} item(s) need attention:"
    for e in "${ERRORS[@]}"; do echo -e "  ${YELLOW}⚠${NC} $e"; done
    echo ""
else
    echo ""
    success "All steps completed with no errors."
fi
echo ""; divider
echo -e "  ${DIM}Re-run 'bash cycentra-setup.sh' at any time to reconfigure.${NC}"; echo ""