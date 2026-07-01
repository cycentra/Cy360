#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 -- Setup & Update Wizard v1.0.141 -- 2026-07-01 18:15 UTC
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

# ── TEMP: Azure Arc Service Principal (TESTING ONLY — remove before go-live) ──
# Replace with env var injection before deploying to production:
#   export ARC_SP_ID=... ARC_SP_SECRET=... bash cycentra-setup.sh
export ARC_SP_ID="${ARC_SP_ID:-e61cedfb-0e04-4d0f-81a7-4b881240bb35}" # Application (client) ID under App Registration 
export ARC_SP_SECRET="${ARC_SP_SECRET:-1Wr8Q~woFk1eXNL~YSbwcIsJPwzXhzIBNj~jMb24}" # Application Client secret value (rotate after use)
export ARC_SUBSCRIPTION_ID="${ARC_SUBSCRIPTION_ID:-968ad81f-3859-45b7-b9b3-c8bcd0361e32}" # Azure subscription ID
export ARC_RESOURCE_GROUP="${ARC_RESOURCE_GROUP:-cy-keyvault-group}" # Resource group where the Key Vault is located
export ARC_TENANT_ID="${ARC_TENANT_ID:-00864d66-c8a8-443f-8d0a-3df93346e266}" # Tenant ID of the Azure AD where the service principal is registered
export ARC_LOCATION="${ARC_LOCATION:-westeurope}"
# ─────────────────────────────────────────────────────────────────────────────

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
# Escape a string for use as the replacement field in a sed s|...|...|  expression.
# Handles: \ (escape char), | (our delimiter), & (sed backreference).
_escape_sed_repl() { local s="$1"; s="${s//\\/\\\\}"; s="${s//|/\\|}"; s="${s//&/\\&}"; printf '%s' "$s"; }

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
_SCRIPT_VERSION="v1.0.409"

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

# ── Step 0: Azure Arc enrollment (optional — enables Managed Identity for KV) ─
# If ARC_SP_ID and ARC_SP_SECRET are set in the environment, the server is
# enrolled with Azure Arc before any app component is installed.  Once enrolled
# the server gets a Managed Identity and the app uses DefaultAzureCredential()
# to authenticate to Azure Key Vault — no static secrets needed at runtime.
#
# Pass credentials as environment variables, never hardcode them:
#   export ARC_SP_ID="<service-principal-app-id>"
#   export ARC_SP_SECRET="<service-principal-secret>"
#   export ARC_SUBSCRIPTION_ID="<subscription-id>"
#   export ARC_RESOURCE_GROUP="<resource-group>"
#   export ARC_TENANT_ID="<tenant-id>"
#   export ARC_LOCATION="westeurope"   # or your region
#   bash cycentra-setup.sh
#
# The SP only needs "Azure Connected Machine Onboarding" role — rotate or
# revoke it after all servers are enrolled.  The runtime app never uses it.
if [[ -n "${ARC_SP_ID:-}" && -n "${ARC_SP_SECRET:-}" ]]; then
    step_header "AZURE ARC ENROLLMENT"
    _arc_sub="${ARC_SUBSCRIPTION_ID:?ARC_SUBSCRIPTION_ID must be set for Arc enrollment}"
    _arc_rg="${ARC_RESOURCE_GROUP:?ARC_RESOURCE_GROUP must be set for Arc enrollment}"
    _arc_tenant="${ARC_TENANT_ID:?ARC_TENANT_ID must be set for Arc enrollment}"
    _arc_location="${ARC_LOCATION:-westeurope}"

    # Check both "Connected" and "Disconnected" states — a disconnected resource
    # still exists in Azure Arc and re-running connect would fail with AZCM0044.
    if command -v azcmagent >/dev/null 2>&1 && azcmagent show 2>/dev/null | grep -qE "Status\s*:\s*(Connected|Disconnected)"; then
        success "Azure Arc agent already registered ($(azcmagent show 2>/dev/null | grep -oP '(?<=Status\s:\s)\S+' || echo 'see azcmagent show')) — skipping enrollment"
    else
        info "Downloading Azure Connected Machine Agent ..."
        LINUX_INSTALL_SCRIPT="/tmp/install_linux_azcmagent.sh"
        [[ -f "$LINUX_INSTALL_SCRIPT" ]] && rm -f "$LINUX_INSTALL_SCRIPT"
        wget -q https://gbl.his.arc.azure.com/azcmagent-linux -O "$LINUX_INSTALL_SCRIPT"
        _arc_install_rc=0
        bash "$LINUX_INSTALL_SCRIPT" || _arc_install_rc=$?
        if [[ $_arc_install_rc -ne 0 ]]; then
            warn "Azure Arc agent installer exited with code $_arc_install_rc"
            warn "  This OS may not yet be supported by the Azure Connected Machine Agent."
            warn "  Skipping Arc enrollment — Managed Identity will not be available."
            warn "  Use static credentials in /opt/cycentra/.env as an alternative."
            warn "  Re-run setup once Microsoft adds support for this OS distribution."
            unset ARC_SP_SECRET
        else
        sleep 5

        info "Connecting server to Azure Arc ..."
        _arc_connect_rc=0
        sudo azcmagent connect \
            --service-principal-id     "$ARC_SP_ID" \
            --service-principal-secret "$ARC_SP_SECRET" \
            --resource-group           "$_arc_rg" \
            --tenant-id                "$_arc_tenant" \
            --location                 "$_arc_location" \
            --subscription-id          "$_arc_sub" \
            --cloud "AzureCloud" || _arc_connect_rc=$?

        # Clear SP secret from memory immediately after use
        unset ARC_SP_SECRET

        # Exit code 44 = AZCM0044 — resource already exists in Azure Arc from a
        # previous enrollment.  Treat as success; the resource is already registered.
        if [[ $_arc_connect_rc -eq 44 ]]; then
            warn "Azure Arc resource already exists in Azure (AZCM0044) — server was previously enrolled."
            warn "  Managed Identity is already active. Run 'azcmagent show' to confirm."
        elif [[ $_arc_connect_rc -ne 0 ]]; then
            warn "azcmagent connect exited with code $_arc_connect_rc — Arc enrollment incomplete."
            warn "  Managed Identity will not be available. Check 'azcmagent show' for details."
        else
            success "Azure Arc enrollment complete — Managed Identity is now active"
            info "Set AZURE_KEYVAULT_URL in /opt/cycentra/.env to enable Key Vault bootstrap"
        fi
        fi
    fi
else
    info "ARC_SP_ID not set — skipping Azure Arc enrollment"
    info "  To enable: export ARC_SP_ID=... ARC_SP_SECRET=... then re-run setup"
fi

# ── Step 0.5: Infisical CLI + secret refresh timer ────────────────────────────
# Installs the Infisical CLI for developer tooling and provisions a daily
# systemd timer that restarts the backend service so any rotated secrets are
# picked up without manual intervention.
#
# "Going native with the SDK" means the app fetches secrets in-process at
# startup (via kv_secrets.py).  The timer simply triggers that path daily by
# gracefully restarting the backend — no daemon or sidecar required.
#
# Set INFISICAL_PROJECT_ID in .env (or pass as env var before running setup)
# to enable the Infisical path.  See kv_secrets.py for full auth method docs.
step_header "INFISICAL CLI + SECRET REFRESH"

# ── Install Infisical CLI ──────────────────────────────────────────────────────
if command -v infisical >/dev/null 2>&1; then
    success "Infisical CLI already installed — $(infisical --version 2>/dev/null || echo 'ok')"
else
    info "Installing Infisical CLI ..."
    curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.deb.sh' \
        | bash 2>/dev/null
    apt-get install -y -qq infisical 2>/dev/null
    if command -v infisical >/dev/null 2>&1; then
        success "Infisical CLI installed"
    else
        warn "Infisical CLI install failed — manual install may be required"
        warn "  See: https://infisical.com/docs/cli/overview"
    fi
fi

# ── Write secret refresh script ───────────────────────────────────────────────
# This script is called by the systemd timer.  It gracefully reloads the
# backend (SIGHUP to gunicorn triggers a worker restart without dropping
# connections), which re-runs load_kv_secrets() and picks up any rotated values.
mkdir -p /opt/cycentra/scripts
cat > /opt/cycentra/scripts/infisical-refresh.sh << 'REFRESHEOF'
#!/bin/bash
# /opt/cycentra/scripts/infisical-refresh.sh
# Triggered daily by cycentra-secret-refresh.timer
# Reloads the backend to pick up any rotated secrets from the vault.
set -euo pipefail

LOG="/var/log/cycentra/secret-refresh.log"
mkdir -p "$(dirname "$LOG")"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Starting secret refresh" >> "$LOG"

# Test vault connectivity before reloading
BACKEND="${SECRETS_BACKEND:-$(grep '^SECRETS_BACKEND=' /opt/cycentra/.env 2>/dev/null | cut -d= -f2)}"

case "${BACKEND:-azure}" in
  infisical)
    PROJECT_ID="$(grep '^INFISICAL_PROJECT_ID=' /opt/cycentra/.env 2>/dev/null | cut -d= -f2)"
    if [[ -z "$PROJECT_ID" ]]; then
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] INFISICAL_PROJECT_ID not set — skipping" >> "$LOG"
        exit 0
    fi
    # Validate Arc MSI endpoint is reachable (confirms Arc agent is healthy).
    # HIMDS always returns 401 first (challenge-response) — a 401 means healthy.
    # Do NOT use -f flag; it treats 4xx as errors and always reports unreachable.
    _himds_code=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" \
        -H "Metadata: true" \
        "http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https://management.azure.com/" \
        2>/dev/null || echo "000")
    if [[ "$_himds_code" != "401" ]]; then
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] WARN: Arc MSI endpoint unhealthy (HTTP ${_himds_code}) — skipping reload" >> "$LOG"
        exit 1
    fi
    ;;
  azure)
    VAULT_URL="$(grep '^AZURE_KEYVAULT_URL=' /opt/cycentra/.env 2>/dev/null | cut -d= -f2)"
    [[ -z "$VAULT_URL" ]] && { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] AZURE_KEYVAULT_URL not set — skipping" >> "$LOG"; exit 0; }
    ;;
esac

# Graceful reload: SIGHUP to gunicorn triggers worker restart, picks up new secrets
if systemctl is-active --quiet cycentra-backend.service; then
    systemctl reload-or-restart cycentra-backend.service
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Backend reloaded — secrets refreshed" >> "$LOG"
else
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Backend service not active — skipping reload" >> "$LOG"
fi
REFRESHEOF
chmod 700 /opt/cycentra/scripts/infisical-refresh.sh

# ── Install systemd service + timer for daily secret refresh ──────────────────
cat > /etc/systemd/system/cycentra-secret-refresh.service << 'SRVCEOF'
[Unit]
Description=CyCentra Secret Refresh — reload backend to pick up rotated vault secrets
After=network-online.target cycentra-backend.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/cycentra/scripts/infisical-refresh.sh
StandardOutput=journal
StandardError=journal
SRVCEOF

cat > /etc/systemd/system/cycentra-secret-refresh.timer << 'TIMEREOF'
[Unit]
Description=Daily CyCentra secret refresh (03:00 UTC)
Requires=cycentra-secret-refresh.service

[Timer]
# Runs at 03:00 UTC every day — backend restarts in off-peak hours and
# re-fetches all secrets from the vault, picking up any rotations.
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=300
Persistent=true
Unit=cycentra-secret-refresh.service

[Install]
WantedBy=timers.target
TIMEREOF

systemctl daemon-reload
systemctl enable cycentra-secret-refresh.timer
systemctl start  cycentra-secret-refresh.timer
success "Secret refresh timer installed — daily at 03:00 UTC"
info    "  Logs: journalctl -u cycentra-secret-refresh.service"
info    "  Manual trigger: systemctl start cycentra-secret-refresh.service"

# ── Step 1: System packages ───────────────────────────────────────────────────
step_header "SYSTEM DEPENDENCIES"
apt-get update -y -qq
apt-get install -y -qq \
    curl wget gnupg lsb-release ca-certificates jq \
    python3 python3-pip \
    nmap whois rsync git openssl \
    snmp \
    nginx certbot python3-certbot-nginx \
    2>/dev/null
success "System packages installed"

# ── pip3 compatibility: --break-system-packages (pip >= 23.x / Python 3.11+) ─
# Older distros (Ubuntu 20.04, pip 21.x) reject this flag with "no such option".
# Detect support once and store in _PIP_BSP for reuse everywhere.
_PIP_BSP=""
pip3 install --break-system-packages --dry-run pip 2>&1 | grep -q "no such option" || _PIP_BSP="--break-system-packages"

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

# Bind to :5433 to avoid conflict with other Docker postgres containers on :5432
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

    # Break into two steps so a 403/rate-limit from the GitHub API doesn't abort the
    # whole script via set -euo pipefail (curl exits 22 on HTTP 4xx with -f flag).
    _NUCLEI_API=$(curl -sSL --max-time 15 \
        "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" \
        2>/dev/null) || true
    _NUCLEI_URL=$(printf '%s' "$_NUCLEI_API" \
        | python3 -c "import sys,json; assets=json.load(sys.stdin)['assets']; print(next(a['browser_download_url'] for a in assets if 'linux_amd64.zip' in a['name']))" \
        2>/dev/null) || true

    # Fallback: resolve latest tag via HTTP redirect (no API quota needed)
    if [[ -z "$_NUCLEI_URL" ]]; then
        _NUCLEI_TAG=$(curl -sSL -o /dev/null -w '%{url_effective}' --max-time 10 \
            "https://github.com/projectdiscovery/nuclei/releases/latest" 2>/dev/null \
            | sed 's|.*/tag/||') || true
        if [[ -n "$_NUCLEI_TAG" && "$_NUCLEI_TAG" =~ ^v[0-9] ]]; then
            _NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${_NUCLEI_TAG}/nuclei_${_NUCLEI_TAG#v}_linux_amd64.zip"
        fi
    fi

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

# ── pip3 compatibility re-detection (all modes) ───────────────────────────────
# _PIP_BSP is initialised above only when the INFRA block runs (fresh install).
# In --update mode the INFRA block is skipped so pip3 is already installed;
# re-run the detection here so the variable is always bound before the APP BLOCK.
_PIP_BSP=""
pip3 install --break-system-packages --dry-run pip 2>&1 | grep -q "no such option" || _PIP_BSP="--break-system-packages"

# ── Python reporting prerequisites (all modes — needed for PDF report generation) ─
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
    #
    # NOTE: On a CyCentra 360 installation, step 4.3b (further in this script)
    # configures opensearch_security.auth.type: openid, which replaces the
    # kibanaserver username/password auth entirely.  If OIDC is already active
    # (re-run / --update) or will be configured this run (CYSIEM_OIDC_SECRET is
    # set), the kibanaserver credential block is not needed and its absence is
    # not an error.  Skip with an info message in those cases.
    # grep -c exits 1 on zero matches (and outputs "0") — using || echo "0" would
    # produce "0\n0" and break the [[ ]] arithmetic test.  Use || true instead and
    # fall back via parameter expansion for the file-not-found (empty output) case.
    _oidc_already_active=$(grep -c "^opensearch_security.auth.type: openid" "$WAZUH_YML" 2>/dev/null || true)
    if [[ "${_oidc_already_active:-0}" -gt 0 ]]; then
        info "CySIEM Dashboard: OIDC auth already active — kibanaserver credentials not required"
    else
        _ks_line_user=$(grep -E "^#?\s*opensearch\.username:" "$WAZUH_YML" | head -1 || true)
        _ks_line_pass=$(grep -E "^#?\s*opensearch\.password:" "$WAZUH_YML" | head -1 || true)
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
                # CYSIEM_OIDC_SECRET being set means step 4.3b will configure OIDC this
                # run, making kibanaserver credentials irrelevant.  Demote to info.
                if [[ -n "${CYSIEM_OIDC_SECRET:-}" ]]; then
                    info "kibanaserver password not found — not required (step 4.3b will configure OIDC auth)"
                else
                    warn "kibanaserver password unknown — opensearch.username/password may be missing from opensearch_dashboards.yml. Re-run once CYSIEM_OIDC_SECRET is set to switch to OIDC auth."
                fi
            fi
        fi
    fi

    # ── Strip legacy proxy-auth settings (idempotent early cleanup) ─────────
    # Removes proxy-cache and requestHeadersAllowlist overrides left by older
    # proxy_auth_domain installs. OIDC settings (auth.type, openid.*) are NOT
    # stripped here — step 4.3b handles those idempotently. Stripping OIDC keys
    # here without re-writing them (when step 4.3b is gated on oauth2proxy
    # secrets) leaves the dashboard in basic-auth mode on every --update.
    python3 - "$WAZUH_YML" << 'WAZUH_EARLY_PROXY_EOF'
import sys
path = sys.argv[1]
with open(path, "rb") as f:
    raw = f.read().replace(b"\x00", b"")
text = raw.decode("utf-8")
remove_prefixes = [
    "opensearch_security.proxycache.",
    "opensearch.requestHeadersAllowlist",
    "# Authentication gate:",
    "# Wazuh trusts",
]
cleaned = "\n".join(
    line for line in text.splitlines()
    if not any(line.strip().startswith(p) for p in remove_prefixes)
).rstrip() + "\n"
with open(path, "w") as f:
    f.write(cleaned)
print("Legacy proxy-auth settings removed — OIDC config preserved for step 4.3b")
WAZUH_EARLY_PROXY_EOF

    systemctl restart wazuh-dashboard 2>/dev/null || true
    success "CySIEM Dashboard configured: host=127.0.0.1, port=5601 (OIDC settings applied in step 4.3b)"

fi

# ── Step 4.3: CySIEM Dashboard variable reference ────────────────────────────
# OIDC auth is configured in step 4.3b after .env is available.
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
                sed -i "s|^WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=$(_escape_sed_repl "${_detected}")|" /opt/cycentra/cysiemstack.env
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
systemctl restart cysiem-to-redis 2>/dev/null \
    || { warn "cysiem-to-redis failed to start — check: journalctl -u cysiem-to-redis -n 20"; \
         ERRORS+=("cysiem-to-redis restart failed"); }
sleep 2
systemctl is-active cysiem-to-redis >/dev/null 2>&1 \
    && success "cysiem-to-redis running — tailing CySIEM alerts → Redis :6379" \
    || { warn "cysiem-to-redis failed — check: journalctl -u cysiem-to-redis -n 20"; \
         ERRORS+=("cysiem-to-redis failed"); }

# ── Download release bundle ───────────────────────────────────────────────────
step_header "DOWNLOAD RELEASE BUNDLE"

# In update mode .env is not sourced until Step 5, so read GH_TOKEN early
# from .env if it is not already in the shell environment.
if [[ -z "${GH_TOKEN:-}" && -f "/opt/cycentra/.env" ]]; then
    GH_TOKEN="$(grep '^GH_TOKEN=' /opt/cycentra/.env 2>/dev/null | head -1 | cut -d= -f2- | tr -d ' \r')"
fi
GH_ORG="cycentra"
GH_REPO="Cy360"

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

if [[ -f "$_SCRIPT_DIR/manifest.json" && "$_SCRIPT_DIR" != "/opt/cycentra" ]]; then
    info "Local bundle detected — skipping download"
    BUNDLE_DIR="$_SCRIPT_DIR"
    # Resolve version from local bundle for the update-mode pre-check below
    CYCENTRA_VERSION=$(cat "$_SCRIPT_DIR/VERSION" 2>/dev/null || jq -r '.version' "$_SCRIPT_DIR/manifest.json" 2>/dev/null || echo "unknown")
    _RELEASE_JSON=""
else
    # ── Remote download path: requires GH_TOKEN ───────────────────────────────
    if [[ -z "$GH_TOKEN" ]]; then
        error "GH_TOKEN is not set. Add it to /opt/cycentra/.env or pass inline:"
        error "  GH_TOKEN=ghp_... sudo -E bash cycentra-setup.sh --update"
        error "Token needs 'repo' scope (or 'contents:read' on a fine-grained PAT) for cycentra/Cy360."
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
# NOTE: we do NOT exit early when already at the latest version.
# Pip install is idempotent and the service restarts below are required to
# ensure the running engine process loads the latest deployed bytecode.
# Without the restart, stale in-memory bytecode survives indefinitely even
# when .py files on disk are updated by pip.
if [[ "$MODE" == "update" && "${FORCE_UPDATE:-0}" != "1" ]]; then
    _installed_ver=$(cat /opt/cycentra/version 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ -n "$_installed_ver" && "$_installed_ver" == "$CYCENTRA_VERSION" ]]; then
        echo ""
        success "Already at the latest version: ${CYCENTRA_VERSION}"
        info    "Re-applying packages and restarting services to ensure running code is current."
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

# ── Early agent-package seed ─────────────────────────────────────────────────
# Install bundle packages NOW — before the self-copy below overwrites this
# script.  Bash is still reading the file it originally opened here, so this
# block is guaranteed to execute on every run regardless of inode behaviour.
# Step 22b later re-confirms permissions; if files are already present it no-ops.
_EARLY_PKG_DIR="/var/lib/cycentra-agent-packages"
mkdir -p "$_EARLY_PKG_DIR"
chmod 755 "$_EARLY_PKG_DIR"; chown www-data:www-data "$_EARLY_PKG_DIR" 2>/dev/null || true
_early_bundle_pkgs="${BUNDLE_DIR}/agent-packages"
if [[ -d "$_early_bundle_pkgs" ]]; then
    _early_ver="${PKG_VER}"   # already resolved from manifest.json (e.g. "1.0.45")
    for _bpkg in "${_early_bundle_pkgs}"/cy360-agent-*; do
        [[ -f "$_bpkg" ]] || continue
        _bn=$(basename "$_bpkg")
        if [[ "$_bn" =~ ^cy360-agent-[0-9]+\.[0-9]+\.[0-9]+(.*)$ ]]; then
            _sfx="${BASH_REMATCH[1]}"
            [[ "$_sfx" =~ ^[._]([^.]+\.[^.]+)$ ]] && _sfx="-${BASH_REMATCH[1]}"
            _dest="${_EARLY_PKG_DIR}/cy360-agent-${_early_ver}${_sfx}"
            if [[ ! -f "$_dest" ]]; then
                cp "$_bpkg" "$_dest"
                chmod 644 "$_dest"; chown www-data:www-data "$_dest" 2>/dev/null || true
                success "Agent pkg seeded early: $(basename "$_dest")"
            fi
        fi
    done
fi

# ── Stage CyEDR installer + agent files (mirrors Wazuh package seeding above) ─
# Source files live in the repo; this block copies them to the NGINX-served dir
# automatically on every install/update run — no manual download-packages step needed.
_EDR_PKG_DEST="${_EARLY_PKG_DIR}/edr"
mkdir -p "$_EDR_PKG_DEST"
chmod 755 "$_EDR_PKG_DEST"; chown www-data:www-data "$_EDR_PKG_DEST" 2>/dev/null || true

for _edr_src_dest in \
    "${BUNDLE_DIR}/scripts/cyedr-install.sh:cyedr-install.sh" \
    "${BUNDLE_DIR}/scripts/cyedr-install.ps1:cyedr-install.ps1" \
    "${BUNDLE_DIR}/agent/cyedr_agent.py:cyedr_agent.py" \
    "${BUNDLE_DIR}/CYSIEM-Config/yara/cycentra.yar:cycentra.yar"; do
    _src="${_edr_src_dest%%:*}"
    _dst_name="${_edr_src_dest##*:}"
    if [[ -f "$_src" ]]; then
        cp -f "$_src" "${_EDR_PKG_DEST}/${_dst_name}"
        chmod 644 "${_EDR_PKG_DEST}/${_dst_name}"
        chown www-data:www-data "${_EDR_PKG_DEST}/${_dst_name}" 2>/dev/null || true
        success "CyEDR asset staged: ${_dst_name}"
    else
        warn "CyEDR asset not found in bundle: ${_src##*/}"
    fi
done

# Write RELEASE_NOTES.md for System Settings page — shipped inside the release bundle
_RN_DEST="/opt/cycentra/RELEASE_NOTES.md"
mkdir -p /opt/cycentra

if [[ -f "$BUNDLE_DIR/docs/RELEASE_NOTES.md" ]]; then
    cp "$BUNDLE_DIR/docs/RELEASE_NOTES.md" "$_RN_DEST"
    success "RELEASE_NOTES.md deployed to ${_RN_DEST}"
elif [[ -f "$BUNDLE_DIR/RELEASE_NOTES.md" ]]; then
    cp "$BUNDLE_DIR/RELEASE_NOTES.md" "$_RN_DEST"
    success "RELEASE_NOTES.md deployed to ${_RN_DEST}"
else
    warn "RELEASE_NOTES.md not found in bundle — Settings tab release history may be outdated"
fi

# Update /opt/cycentra/cycentra-setup.sh from the bundle (idempotent).
# When invoked as `bash /opt/cycentra/cycentra-setup.sh --update` the self-copy
# below is a no-op (_SELF == _SETUP_DEST).  Preferring the bundle copy fixes that:
# on the first run the bundle's newer .sh is written to /opt/cycentra/; subsequent
# runs see identical files and skip the copy.
_SELF="$(realpath "$0")"
_SETUP_DEST="/opt/cycentra/cycentra-setup.sh"
_BUNDLE_SETUP="$BUNDLE_DIR/cycentra-setup.sh"
if [[ -f "$_BUNDLE_SETUP" ]] && \
   ! cmp -s "$_BUNDLE_SETUP" "$_SETUP_DEST" 2>/dev/null; then
    cp "$_BUNDLE_SETUP" "$_SETUP_DEST"
    chmod 750 "$_SETUP_DEST"
    success "Setup script updated from bundle — re-executing new version..."
    # Re-exec from the bundle copy so the NEW script runs completely from line 1.
    # Running from $BUNDLE_DIR means manifest.json is present → local bundle detection
    # fires → download is skipped → bundle-seed copies agent packages → no 404.
    exec bash "$_BUNDLE_SETUP" "$@"
elif [[ "$_SELF" != "$_SETUP_DEST" ]]; then
    cp "$_SELF" "$_SETUP_DEST"
    chmod 750  "$_SETUP_DEST"
    success "Setup script deployed to $_SETUP_DEST"
else
    success "Setup script already current at $_SETUP_DEST"
fi

# Deploy docker-maintenance.sh alongside setup script
# Use BUNDLE_DIR so this works in both fresh-install (BUNDLE_DIR==_SCRIPT_DIR) and
# portal --update paths (script runs from /opt/cycentra but bundle is at /tmp/cycentra-release).
_MAINT_SRC="${BUNDLE_DIR}/docker-maintenance.sh"
[[ ! -f "$_MAINT_SRC" ]] && _MAINT_SRC="${_SCRIPT_DIR}/docker-maintenance.sh"   # fallback for dev
_MAINT_DEST="/opt/cycentra/docker-maintenance.sh"
if [[ -f "$_MAINT_SRC" ]]; then
    if [[ "$(realpath "$_MAINT_SRC")" != "$(realpath "$_MAINT_DEST" 2>/dev/null)" ]]; then
        cp "$_MAINT_SRC" "$_MAINT_DEST"
        chmod 750 "$_MAINT_DEST"
        success "docker-maintenance.sh deployed to ${_MAINT_DEST}"
    else
        success "docker-maintenance.sh already at ${_MAINT_DEST} — no copy needed"
    fi
else
    # Not in bundle — check if a previous install already deployed it.
    # If so, keep the existing copy silently.
    # If not, this is a fresh server: the Flask backend generates and writes
    # docker-maintenance.sh automatically the first time the Scheduler is saved
    # in System Settings → Scheduler (via _write_docker_maintenance_script()).
    # No manual action is required.
    if [[ -f "$_MAINT_DEST" ]]; then
        success "docker-maintenance.sh already present at ${_MAINT_DEST} — keeping existing copy"
    else
        info "docker-maintenance.sh not in bundle — will be created automatically when Scheduler is saved in System Settings"
    fi
fi

# NOTE: Docker maintenance schedule is managed by the CyCentra 360 Scheduler
# (System Settings → Scheduler tab). When the schedule is enabled and saved,
# the Flask backend generates and writes docker-maintenance.sh to /opt/cycentra/
# automatically (via _write_docker_maintenance_script() in blueprints/system/routes.py).
# cron entries are written by the portal's /api/system/schedules endpoint.

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
    # Not in bundle or alongside installer.
    # Two self-healing mechanisms exist — no action required:
    #   1. If /opt/cycentra/license_validator.py already exists (previous install
    #      or prior --update), it is used as-is by the Flask backend.
    #   2. If it does not exist, the Flask license endpoint (_run_validator() in
    #      blueprints/system/routes.py) automatically falls back to the copy
    #      inside the installed cycentra-backend wheel at:
    #      backend/core/license_validator.py
    # The deployed copy at /opt/cycentra/ is only required for the daily watchdog
    # cron. It is deployed on the next --update once the file is in the bundle.
    if [[ -f "/opt/cycentra/license_validator.py" ]]; then
        success "license_validator.py already present at /opt/cycentra/ — keeping existing copy"
    else
        info "license_validator.py not in bundle — license UI uses in-package fallback; daily watchdog will use it once deployed via --update"
    fi
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
    INSTALL_CYSIEM=true; INSTALL_CYSOAR=true

    info "Domain : ${BASE_DOMAIN}  |  OAuth: ${OAUTH_PROVIDER}"
    info "Post-install → edit /opt/cycentra/.env and restart: systemctl restart cycentra"

    step_header "GENERATING SECRETS"
    _env="/opt/cycentra/.env"
    _get() { grep -m1 "^${1}=" "$_env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true; }
    if [[ -f "$_env" ]]; then
        info "Existing .env found — preserving session secrets"
        FLASK_SECRET=$(_get SECRET_KEY);   [[ -z "$FLASK_SECRET"   ]] && FLASK_SECRET=$(gen_secret)
        JWT_SECRET=$(_get JWT_SECRET);     [[ -z "$JWT_SECRET"     ]] && JWT_SECRET=$(gen_secret)
        NODERED_SECRET=$(_get NODE_RED_CREDENTIAL_SECRET)
        [[ -z "$NODERED_SECRET" ]] && NODERED_SECRET=$(gen_secret)
    else
        FLASK_SECRET=$(gen_secret); JWT_SECRET=$(gen_secret)
        NODERED_SECRET=$(gen_secret)
    fi
    ADMIN_API_KEY=$(gen_secret)
    CYSOAR_OIDC_SECRET=$(gen_secret)
    CYSIEM_OIDC_SECRET=$(gen_secret)
    CY360SSO_OIDC_SECRET=$(gen_secret)
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
    INSTALL_CYSIEM=true; INSTALL_CYSOAR=true
    success "Loaded existing configuration (domain: ${BASE_DOMAIN})"

    # ── Patch .env for update mode ────────────────────────────────────────────
    # SAFE: only removes specific dead/orphaned vars by name, and only appends
    # vars that are missing entirely.  Customer custom entries ARE preserved.
    # The full .env is NEVER rewritten in update mode — only surgical edits.
    step_header "PATCHING /opt/cycentra/.env"
    _env="/opt/cycentra/.env"

    # Remove dead / orphaned variables
    for _dead in USE_CUSTOM_IMAGES SIEM_LLM_ENABLED SIEM_MISP_ENABLED \
                 AI_PROVIDER AI_API_KEY AI_MODEL \
                 POSTGRES_PASSWORD; do
        if grep -q "^${_dead}=" "$_env" 2>/dev/null; then
            sed -i "/^${_dead}=/d" "$_env"
            info "Removed orphaned var: ${_dead}"
        fi
    done

    # Add CLOUD_MISP_* if missing (introduced in v1.0.X)
    if ! grep -q "^CLOUD_MISP_URL=" "$_env" 2>/dev/null; then
        cat >> "$_env" << PATCHEOF

# ── Cloud CyMISP (Cycentra-managed MISP at cymisp.cycentra.com) ────────────────
CLOUD_MISP_URL=${CLOUD_MISP_URL:-https://cymisp.cycentra.com}
CLOUD_MISP_API_KEY=${CLOUD_MISP_API_KEY:-}
AZURE_KEYVAULT_URL=${AZURE_KEYVAULT_URL:-}
PATCHEOF
        info "Added CLOUD_MISP_* to .env"
    fi

    # Backfill CLOUD_MISP defaults if the value was written empty (pre-v1.2.56)
    if grep -q "^CLOUD_MISP_URL=$" "$_env" 2>/dev/null; then
        _fill_misp_url="${CLOUD_MISP_URL:-https://cymisp.cycentra.com}"
        sed -i "s|^CLOUD_MISP_URL=$|CLOUD_MISP_URL=${_fill_misp_url}|" "$_env"
        info "Backfilled CLOUD_MISP_URL → ${_fill_misp_url}"
    fi
    if grep -q "^CLOUD_MISP_API_KEY=$" "$_env" 2>/dev/null; then
        _fill_misp_key="${CLOUD_MISP_API_KEY:-BPxY79PEX9Y39eooVpNVu0UpayhYaqCfe74ZOHJb}"
        sed -i "s|^CLOUD_MISP_API_KEY=$|CLOUD_MISP_API_KEY=${_fill_misp_key}|" "$_env"
        info "Backfilled CLOUD_MISP_API_KEY default"
    fi


    # Add CYSIEM_OIDC_SECRET if missing (SSO v1 — introduced with full OIDC)
    if ! grep -q "^CYSIEM_OIDC_SECRET=" "$_env" 2>/dev/null; then
        echo "CYSIEM_OIDC_SECRET=$(openssl rand -hex 32)" >> "$_env"
        info "Added CYSIEM_OIDC_SECRET to .env"
    fi

    # Add CYMIND_API_* if missing (central CyMind vault-managed credentials)
    if ! grep -q "^CYMIND_API_URL=" "$_env" 2>/dev/null; then
        cat >> "$_env" << PATCHEOF

# ── CyMind (central AI hub — company-wide instance) ───────────────────────────
# Populated at startup from vault (CYMIND-API-URL / CYMIND-API-KEY).
# Leave empty to use vault injection; set non-empty to override vault.
CYMIND_API_URL=${CYMIND_API_URL:-}
CYMIND_API_KEY=${CYMIND_API_KEY:-}
PATCHEOF
        info "Added CYMIND_API_* to .env"
    fi

    # Add CY360SSO_OIDC_SECRET if missing (portal self-IdP SSO client)
    if ! grep -q "^CY360SSO_OIDC_SECRET=" "$_env" 2>/dev/null; then
        echo "CY360SSO_OIDC_SECRET=$(openssl rand -hex 32)" >> "$_env"
        info "Added CY360SSO_OIDC_SECRET to .env"
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

    # Add CYCENTRA_DB_URL if missing (introduced with PostgreSQL-backed RBAC)
    if ! grep -q "^CYCENTRA_DB_URL=" "$_env" 2>/dev/null; then
        _CY_DB_URL="postgresql://corruser:${CORR_DB_PASS}@127.0.0.1:5433/correlation"
        cat >> "$_env" << PATCHEOF

# ── CyCentra 360 user DB — Flask RBAC backed by PostgreSQL ─────────────────────
CYCENTRA_DB_URL=${_CY_DB_URL}
PATCHEOF
        info "Added CYCENTRA_DB_URL to .env"
    fi

    # Add ASM scanner tuning vars if missing (introduced with protocol-probe engine)
    if ! grep -q "^PROTO_PROBE_TIMEOUT=" "$_env" 2>/dev/null; then
        cat >> "$_env" << PATCHEOF

# ── ASM Scanner tuning ────────────────────────────────────────────────────────
ENABLE_EXTENDED_PORT_SCAN=false
ENABLE_UDP_SCAN=false
PROTO_PROBE_TIMEOUT=5
INFRA_EXPOSURE_PORTS=2375,2376,6443,9200,9300,11211,5900,9090,9091,8161
PATCHEOF
        info "Added ASM scanner tuning vars to .env"
    fi

    # Add MAXMIND_KEY if missing (hardcoded default shipped with setup.sh)
    if ! grep -q "^MAXMIND_KEY=" "$_env" 2>/dev/null; then
        echo "MAXMIND_KEY=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" >> "$_env"
        info "Added MAXMIND_KEY to .env"
    fi

    # Sync Wazuh API vars from cysiemstack.env → .env.
    # cycentra-backend.service loads EnvironmentFile=/opt/cycentra/.env only;
    # cysiemstack-engine.service loads EnvironmentFile=/opt/cycentra/cysiemstack.env only.
    # Both services need Wazuh creds — .env is the Flask copy, cysiemstack.env is the master.
    _siem_env_path="/opt/cycentra/cysiemstack.env"
    if [[ -f "$_siem_env_path" ]]; then
        _wp="$(grep "^WAZUH_API_PASSWORD=" "$_siem_env_path" 2>/dev/null | cut -d= -f2)"
        if [[ -n "$_wp" ]]; then
            if grep -q "^WAZUH_API_PASSWORD=" "$_env" 2>/dev/null; then
                sed -i "s|^WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=$(_escape_sed_repl "${_wp}")|" "$_env"
            else
                echo "WAZUH_API_PASSWORD=${_wp}" >> "$_env"
            fi
            grep -q "^WAZUH_API_URL="  "$_env" || echo "WAZUH_API_URL=https://127.0.0.1:55000" >> "$_env"
            grep -q "^WAZUH_API_USER=" "$_env" || echo "WAZUH_API_USER=wazuh-wui"              >> "$_env"
            info "Wazuh API vars synced from cysiemstack.env → .env"
        fi
    fi

    # Remove stale CYMIND_API_KEY / CYMIND_API_URL from cysiemstack.env.
    # v1.2.45+ moves these shared keys to .env which the engine service now loads
    # FIRST via EnvironmentFile=/opt/cycentra/.env. If the old cymk_ admin key is
    # still present in cysiemstack.env it wins (last EnvironmentFile wins for
    # duplicate keys) and overrides the correct CyM_ chat key, causing 401 on
    # every SIEM AI analysis call.
    _siem_env_cymi="/opt/cycentra/cysiemstack.env"
    if [[ -f "$_siem_env_cymi" ]]; then
        _cymi_changed=false
        if grep -q "^CYMIND_API_KEY=" "$_siem_env_cymi" 2>/dev/null; then
            sed -i "/^CYMIND_API_KEY=/d" "$_siem_env_cymi"
            _cymi_changed=true
        fi
        if grep -q "^CYMIND_API_URL=" "$_siem_env_cymi" 2>/dev/null; then
            sed -i "/^CYMIND_API_URL=/d" "$_siem_env_cymi"
            _cymi_changed=true
        fi
        [[ "$_cymi_changed" == "true" ]] && \
            info "Removed stale CYMIND_API_KEY/URL from cysiemstack.env (now inherited from .env)"
    fi

    chmod 600 "$_env"
    success ".env patched"
fi
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
FRONTEND_URL=https://cy360.${BASE_DOMAIN}
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

CYSOAR_OIDC_SECRET=${CYSOAR_OIDC_SECRET}
CYSIEM_OIDC_SECRET=${CYSIEM_OIDC_SECRET}
CY360SSO_OIDC_SECRET=${CY360SSO_OIDC_SECRET}

# ── IAP oauth2-proxy ────────────────────────────────────────────────────────────
# oauth2-proxy uses OIDC against cyasm.DOMAIN. It is the single SSO gate for
# cysoar and cysiem subdomains via nginx auth_request.
OAUTH2PROXY_SECRET=${OAUTH2PROXY_SECRET}
OAUTH2PROXY_COOKIE_SECRET=${OAUTH2PROXY_COOKIE_SECRET}

CYCENTRA_PORTAL_URL=https://cy360.${BASE_DOMAIN}
NODE_RED_CREDENTIAL_SECRET=${NODERED_SECRET}

SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-}
SMTP_USER=${SMTP_USER:-}
SMTP_PASS=${SMTP_PASS:-}
SUPPORT_EMAIL=${SUPPORT_EMAIL:-support@cycentra.com}

SIEM_ENGINE_URL=http://127.0.0.1:8100

# ── CyCentra 360 user DB — Flask RBAC backed by PostgreSQL ─────────────────────
# Reuses the existing correlation DB (port 5433) — no new database required.
CYCENTRA_DB_URL=postgresql://corruser:${CORR_DB_PASS}@127.0.0.1:5433/correlation

# GitHub token — used by the portal backend to download updates/upgrades without
# requiring the customer to enter it in the UI.  Set via GH_TOKEN env var at install time.
GH_TOKEN=${GH_TOKEN:-}

# ── Cloud CyMISP (Cycentra-managed MISP at cymisp.cycentra.com) ────────────────
# When a customer selects "Cloud CyMISP" in System Settings > Integrations, the
# backend uses these credentials automatically.  CLOUD_MISP_API_KEY must be set
# to the vendor-issued API key for this installation.
CLOUD_MISP_URL=${CLOUD_MISP_URL:-https://cymisp.cycentra.com}
CLOUD_MISP_API_KEY=${CLOUD_MISP_API_KEY:-BPxY79PEX9Y39eooVpNVu0UpayhYaqCfe74ZOHJb}


# ── CyMind (central AI hub — company-wide instance) ───────────────────────────
# Populated at startup from vault (CYMIND-API-URL / CYMIND-API-KEY).
# Leave empty to use vault injection; set non-empty to override vault.
CYMIND_API_URL=${CYMIND_API_URL:-}
CYMIND_API_KEY=${CYMIND_API_KEY:-}

# ── Secrets backend selection ─────────────────────────────────────────────────
# Choose ONE backend to use for secret injection at startup:
#   azure      → Azure Key Vault via DefaultAzureCredential
#                (supports Azure Arc Managed Identity automatically)
#   hashicorp  → HashiCorp Vault via Token or AppRole auth
#   infisical  → Infisical via Machine Identity (Universal Auth or Native Azure Auth)
# Leave blank to rely solely on values in this .env file.
SECRETS_BACKEND=${SECRETS_BACKEND:-azure}

# ── Azure Key Vault — set to your vault URL to enable secret bootstrap ─────────
# The app fetches secrets from Key Vault at startup when this is set.
# Auth (tried in order by DefaultAzureCredential):
#   1. Azure Arc Managed Identity  ← recommended for Arc-enrolled servers
#   2. AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID  ← Service Principal
#   3. `az login` CLI session  ← local dev
AZURE_KEYVAULT_URL=${AZURE_KEYVAULT_URL:-}

# ── Infisical — set these to use Infisical as the secrets backend ──────────────
# INFISICAL_URL: your self-hosted Infisical URL (omit for Infisical Cloud)
# INFISICAL_CLIENT_ID: Machine Identity client ID (UUID from Infisical UI)
# INFISICAL_AUTH_METHOD: how to authenticate to Infisical
#   azure      → Azure Native Auth via Arc MSI (default, recommended for prod)
#   oidc       → Manual Arc JWT exchange (Machine Identity must be OIDC type in Infisical UI)
#   universal  → Client ID + Secret (dev/staging — not Arc-enrolled machines)
# INFISICAL_CLIENT_SECRET: required for universal auth only
#   (omit when using azure or oidc — Arc MSI is used instead)
# INFISICAL_PROJECT_ID: your Infisical project ID
# INFISICAL_ENVIRONMENT: secret environment to pull from (dev | staging | prod)
INFISICAL_URL=${INFISICAL_URL:-}
INFISICAL_CLIENT_ID=${INFISICAL_CLIENT_ID:-}
INFISICAL_AUTH_METHOD=${INFISICAL_AUTH_METHOD:-azure}
INFISICAL_CLIENT_SECRET=${INFISICAL_CLIENT_SECRET:-}
INFISICAL_PROJECT_ID=${INFISICAL_PROJECT_ID:-}
INFISICAL_ENVIRONMENT=${INFISICAL_ENVIRONMENT:-prod}
ENVEOF
    echo "MAXMIND_KEY=${MAXMIND_KEY:-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}" >> /opt/cycentra/.env

    # ── ASM Scanner tuning (optional — defaults are safe for most deployments) ──
    cat >> /opt/cycentra/.env << ASMEOF

# ── ASM Scanner tuning ────────────────────────────────────────────────────────
# These vars tune the cy-asm engine. Defaults are safe for standard installs.
# ENABLE_EXTENDED_PORT_SCAN: scan all 65535 ports (slower, more thorough)
ENABLE_EXTENDED_PORT_SCAN=${ENABLE_EXTENDED_PORT_SCAN:-false}
# ENABLE_UDP_SCAN: add UDP scan layer (requires root; significantly slower)
ENABLE_UDP_SCAN=${ENABLE_UDP_SCAN:-false}
# PROTO_PROBE_TIMEOUT: seconds per protocol-specific handshake probe (SSH/RDP/SMB/etc.)
PROTO_PROBE_TIMEOUT=${PROTO_PROBE_TIMEOUT:-5}
# INFRA_EXPOSURE_PORTS: extra ports checked for infrastructure exposure in Deep scans
# Default covers Docker, Kubernetes, Elasticsearch, Memcached, VNC, Prometheus, ActiveMQ
INFRA_EXPOSURE_PORTS=${INFRA_EXPOSURE_PORTS:-2375,2376,6443,9200,9300,11211,5900,9090,9091,8161}
ASMEOF
    chmod 600 /opt/cycentra/.env
   # mkdir -p /root/cy-asm && cp /opt/cycentra/.env /root/cy-asm/.env
   # success "Main .env written → /opt/cycentra/.env"

    # LLM enrichment is on by default; operators can set LLM_ENABLED=false in
    # /opt/cycentra/cysiemstack.env to disable automated background enrichment.
    # Manual on-demand analysis (analyst-triggered from the portal) is never blocked.
    _LLM_FLAG="true"

    # Use auto-detected password if available, otherwise preserve existing, or placeholder
    _WAZUH_PASS="${_CYSIEM_WUI_PASS:-$(grep "^WAZUH_API_PASSWORD=" /opt/cycentra/cysiemstack.env 2>/dev/null | cut -d= -f2)}"
    _WAZUH_PASS="${_WAZUH_PASS:-CHANGE_ME_after_cysiem_install}"

    cat > /opt/cycentra/cysiemstack.env << SIEMEOF
# CySIEMStack environment — auto-generated by setup.sh — DO NOT EDIT MANUALLY
# Engine-specific settings only.  Shared config (vault credentials, API keys,
# CLOUD_MISP_*, CYMIND_*, BASE_DOMAIN, etc.) comes from /opt/cycentra/.env,
# which the cysiemstack-engine.service loads first.  Only update .env.

DATABASE_URL=postgresql+asyncpg://corruser:${CORR_DB_PASS}@127.0.0.1:5433/correlation
# Standalone key so --update mode can read the DB password without parsing DATABASE_URL
POSTGRES_PASSWORD=${CORR_DB_PASS}

REDIS_URL=redis://127.0.0.1:6379/0
REDIS_ALERT_KEY=cysiemstack:alerts:raw

WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=${_WAZUH_PASS}

# LLM enrichment — set to false to disable automated background enrichment.
# Manual on-demand analysis (analyst-triggered from the portal) is never blocked.
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
SIEMEOF
    chmod 600 /opt/cycentra/cysiemstack.env
    success "cysiemstack.env written → /opt/cycentra/cysiemstack.env"

    # Propagate Wazuh credentials to Flask env (full install; --update mode does the same
    # in the update-mode patch section above).  Flask (cycentra-backend.service) loads only
    # EnvironmentFile=/opt/cycentra/.env while the correlation engine loads only
    # EnvironmentFile=/opt/cycentra/cysiemstack.env, so both files must carry these vars.
    if grep -q "^WAZUH_API_PASSWORD=" /opt/cycentra/.env 2>/dev/null; then
        sed -i "s|^WAZUH_API_PASSWORD=.*|WAZUH_API_PASSWORD=$(_escape_sed_repl "${_WAZUH_PASS}")|" /opt/cycentra/.env
    else
        echo "WAZUH_API_PASSWORD=${_WAZUH_PASS}" >> /opt/cycentra/.env
    fi
    if grep -q "^WAZUH_API_URL=" /opt/cycentra/.env 2>/dev/null; then
        sed -i "s|^WAZUH_API_URL=.*|WAZUH_API_URL=https://127.0.0.1:55000|" /opt/cycentra/.env
    else
        echo "WAZUH_API_URL=https://127.0.0.1:55000" >> /opt/cycentra/.env
        echo "WAZUH_API_USER=wazuh-wui"              >> /opt/cycentra/.env
    fi
    success "WAZUH_API_PASSWORD propagated to /opt/cycentra/.env (benchmark engine access)"

    # Auto-detect and persist the server's public IP as CY360_PUBLIC_IP.
    # The agent installer uses this so clients connect directly to the server IP
    # instead of the Cloudflare-proxied hostname (Wazuh ports 1514/1515 are TCP,
    # not HTTP — Cloudflare does not proxy them).
    _PUBLIC_IP=$(curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null || \
                 curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)
    if [[ -n "$_PUBLIC_IP" ]]; then
        if grep -q '^CY360_PUBLIC_IP=' /opt/cycentra/.env 2>/dev/null; then
            sed -i "s|^CY360_PUBLIC_IP=.*|CY360_PUBLIC_IP=${_PUBLIC_IP}|" /opt/cycentra/.env
        else
            echo "CY360_PUBLIC_IP=${_PUBLIC_IP}" >> /opt/cycentra/.env
        fi
        success "Server public IP detected: ${_PUBLIC_IP} → CY360_PUBLIC_IP in .env"
    else
        warn "Could not detect public IP — agent installer will fall back to cysiem.${BASE_DOMAIN}"
        warn "Set CY360_PUBLIC_IP=<your-server-ip> in /opt/cycentra/.env to fix agent registration"
    fi

    # Create ML model persistence directory
    mkdir -p /opt/cycentra/ml_models
    chmod 755 /opt/cycentra/ml_models
    success "ML model directory created → /opt/cycentra/ml_models"

    # ── Vault bootstrap: push freshly-generated secrets to Infisical ────────
    # If SECRETS_BACKEND=infisical is set in the installer environment AND the
    # infisical CLI is available, push every vault-managed key from .env into
    # Infisical immediately after the .env is written.  This makes vault the
    # source of truth from the very first install — no manual CSV export needed.
    #
    # Auth method determines how the CLI authenticates:
    #   universal  → uses INFISICAL_CLIENT_ID + INFISICAL_CLIENT_SECRET (scripted)
    #   azure/oidc → uses Arc Managed Identity; vault push is skipped with
    #                instructions because the CLI does not support non-interactive
    #                Azure Native Auth for 'secrets set'.  Add secrets via the
    #                Infisical UI or run the push separately after an interactive
    #                'infisical login --native-azure' session.
    #
    # Skipped silently if:
    #   - SECRETS_BACKEND != infisical
    #   - infisical CLI is not installed
    #   - INFISICAL_PROJECT_ID or INFISICAL_CLIENT_ID not set
    #   - auth method is azure/oidc (runtime reads work; write bootstrap requires UI)
    #
    # Keys that are intentionally excluded from vault (app-managed at runtime)
    # are also excluded here: CLOUD_MISP_API_KEY,
    # CYSOAR_SESSION_SECRET, WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD.
    _vault_push_env() {
        local env_file="$1"
        local env_tag="${INFISICAL_ENVIRONMENT:-prod}"
        local project_id="${INFISICAL_PROJECT_ID:-}"
        local client_id="${INFISICAL_CLIENT_ID:-}"
        local client_secret="${INFISICAL_CLIENT_SECRET:-}"
        local auth_method="${INFISICAL_AUTH_METHOD:-azure}"
        local infisical_url="${INFISICAL_URL:-}"

        [[ "${SECRETS_BACKEND:-}" != "infisical" ]] && return 0
        command -v infisical &>/dev/null || { warn "infisical CLI not found — skipping vault push"; return 0; }
        [[ -z "$project_id" || -z "$client_id" ]] && { warn "INFISICAL_PROJECT_ID / INFISICAL_CLIENT_ID not set — skipping vault push"; return 0; }

        # Azure Native Auth and OIDC: runtime reads work (Python SDK), but the
        # CLI 'secrets set' command does not support non-interactive Arc auth.
        # Print the list of keys so the operator can paste them into the Infisical UI.
        if [[ "$auth_method" == "azure" || "$auth_method" == "oidc" ]]; then
            warn "Vault bootstrap: auth_method=${auth_method} — CLI push requires Universal Auth."
            warn "  Add the following secrets manually in the Infisical UI (Project → Secrets → ${env_tag}):"
            local -a VAULT_KEYS_INFO=(MARKETPLACE_CATALOG_TOKEN SSO_CLIENT_ID SSO_CLIENT_SECRET
                GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET MICROSOFT_CLIENT_ID MICROSOFT_CLIENT_SECRET
                GH_TOKEN MAXMIND_KEY CLOUD_MISP_URL CLOUD_MISP_API_KEY CYMIND_API_URL CYMIND_API_KEY)
            for key in "${VAULT_KEYS_INFO[@]}"; do
                local val
                val=$(grep -m1 "^${key}=" "${env_file}" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
                [[ -n "$val" ]] && info "  ${key} = ${val}"
            done
            info "  Once added, secrets are pulled automatically at every backend restart."
            return 0
        fi

        # Universal Auth — fully scripted push
        if [[ -z "$client_secret" ]]; then
            warn "INFISICAL_CLIENT_SECRET not set — skipping vault push (required for universal auth)"
            return 0
        fi

        step_header "VAULT BOOTSTRAP (Infisical — Universal Auth)"

        # Only company-wide secrets are pushed to the vault — values that are
        # identical across every CyCentra deployment (external API keys, company
        # OAuth apps, shared SMTP / catalog credentials).
        #
        # Install-specific secrets (generated by setup.sh or unique per server)
        # are intentionally excluded:
        #   SECRET_KEY, JWT_SECRET, ADMIN_API_KEY          — openssl rand per install
        #   CYCENTRA_DB_URL, POSTGRES_PASSWORD              — per-install DB
        #   OAUTH2PROXY_SECRET, OAUTH2PROXY_COOKIE_SECRET   — openssl rand per install
        #   CYSIEM_OIDC_SECRET,
        #     CY360SSO_OIDC_SECRET                          — openssl rand per install
                #   NODE_RED_CREDENTIAL_SECRET                      — openssl rand per install
        #   CORRELATION_DB_URL                              — per-install DB URL
        local -a VAULT_KEYS=(
            # Marketplace
            MARKETPLACE_CATALOG_TOKEN
            # OAuth2 / SSO (company-registered apps, same on all deployments)
            SSO_CLIENT_ID SSO_CLIENT_SECRET
            GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET
            MICROSOFT_CLIENT_ID MICROSOFT_CLIENT_SECRET
            # External integrations (company-level credentials)
            GH_TOKEN MAXMIND_KEY
            CLOUD_MISP_URL CLOUD_MISP_API_KEY
            CYMIND_API_URL CYMIND_API_KEY
        )

        local _auth_args=(
            "--clientId=${client_id}"
            "--clientSecret=${client_secret}"
            "--projectId=${project_id}"
            "--env=${env_tag}"
        )
        [[ -n "$infisical_url" ]] && _auth_args+=("--domain=${infisical_url}")

        local pushed=0 skipped=0
        for key in "${VAULT_KEYS[@]}"; do
            local val
            val=$(grep -m1 "^${key}=" "${env_file}" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
            if [[ -z "$val" ]]; then
                ((skipped++)) || true
                continue
            fi
            if infisical secrets set "${key}=${val}" "${_auth_args[@]}" --silent 2>/dev/null; then
                ((pushed++)) || true
            else
                warn "Vault push failed for ${key} — check Infisical credentials"
            fi
        done
        success "Vault bootstrap complete: ${pushed} secrets pushed, ${skipped} skipped (empty)"
    }
    _vault_push_env /opt/cycentra/.env

fi  # end full env block

# ── Step 4.3b: IAP Gateway + CySIEM OIDC ────────────────────────────────────
# Runs in all modes (full / update). Idempotent.
# oauth2-proxy: single OIDC gate for cysoar and cysiem subdomains.
# Wazuh Dashboard: configured for native OIDC auth via cyasm.DOMAIN/oidc.
#   - Individual user identity from OIDC token email claim
#   - OpenSearch Security backend roles from OIDC token roles claim
#   - admin/analyst → all_access; viewer → kibana_user + wazuh_ui_user

step_header "IAP GATEWAY (oauth2-proxy)"

# Load vars from .env if not already in memory (update mode)
[[ -z "${BASE_DOMAIN:-}" ]] && \
    BASE_DOMAIN=$(grep "^BASE_DOMAIN=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)
BASE_DOMAIN="${BASE_DOMAIN:-cycentra.com}"
[[ -z "${OAUTH2PROXY_SECRET:-}" ]] && \
    OAUTH2PROXY_SECRET=$(grep "^OAUTH2PROXY_SECRET=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)
[[ -z "${OAUTH2PROXY_COOKIE_SECRET:-}" ]] && \
    OAUTH2PROXY_COOKIE_SECRET=$(grep "^OAUTH2PROXY_COOKIE_SECRET=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)
[[ -z "${CYSIEM_OIDC_SECRET:-}" ]] && \
    CYSIEM_OIDC_SECRET=$(grep "^CYSIEM_OIDC_SECRET=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2- || true)

# ── oauth2-proxy container (gated on its own secrets) ────────────────────────
if [[ -z "$OAUTH2PROXY_SECRET" || -z "$OAUTH2PROXY_COOKIE_SECRET" ]]; then
    warn "oauth2-proxy secrets missing in .env — oauth2-proxy container skipped; re-run --update"
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
            -e OAUTH2_PROXY_REDIRECT_URL="https://cy360.${BASE_DOMAIN}/oauth2/callback" \
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
fi  # end oauth2proxy gate

# ── Wazuh Dashboard: configure OIDC authentication ───────────────────────────
# Runs in all modes regardless of oauth2proxy secrets — Wazuh OIDC is
# independent of oauth2proxy. The SSO mechanism: Wazuh Dashboard authenticates
# via the CyCentra OIDC IdP at cyasm.DOMAIN. Each user gets their individual
# identity; the `roles` OIDC claim maps to OpenSearch Security backend roles:
#   admin / analyst → all_access (full Wazuh Dashboard access)
#   viewer          → kibana_user + wazuh_ui_user (read-only)
if [[ -f "$_WAZUH_DASH_YML" ]]; then
    step_header "CySIEM OIDC Authentication"
    cp "$_WAZUH_DASH_YML" "${_WAZUH_DASH_YML}.pre-oidc-$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

        # ── Inject OIDC settings into opensearch_dashboards.yml ─────────────────
        if [[ -n "${CYSIEM_OIDC_SECRET:-}" ]]; then
            python3 - "$_WAZUH_DASH_YML" "$CYSIEM_OIDC_SECRET" "$BASE_DOMAIN" << 'WAZUH_OIDC_PY'
import sys
path, secret, domain = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "rb") as f:
    raw = f.read().replace(b"\x00", b"")
text = raw.decode("utf-8")
remove_prefixes = [
    "opensearch_security.auth.type",
    "opensearch_security.proxycache.",
    "opensearch_security.openid.",
    "opensearch.requestHeadersAllowlist",
    "# CyCentra 360",
    "# ── CyCentra 360",
    "# Authentication gate:",
    "# Wazuh trusts",
]
cleaned = "\n".join(
    line for line in text.splitlines()
    if not any(line.strip().startswith(p) for p in remove_prefixes)
).rstrip()
oidc = (
    "\n# ── CyCentra 360 OIDC SSO ─────────────────────────────────────────────────────\n"
    "opensearch_security.auth.type: openid\n"
    f'opensearch_security.openid.connect_url: "https://cyasm.{domain}/oidc/.well-known/openid-configuration"\n'
    'opensearch_security.openid.client_id: "cysiem"\n'
    f'opensearch_security.openid.client_secret: "{secret}"\n'
    'opensearch_security.openid.scope: "openid email profile"\n'
    f'opensearch_security.openid.base_redirect_url: "https://cysiem.{domain}"\n'
    f'opensearch_security.openid.logout_url: "https://cyasm.{domain}/auth/logout"\n'
    "opensearch_security.openid.verify_hostnames: false\n"
)
# Insert OIDC block BEFORE the Custom Branding section so that
# apply-custom-branding.sh (which deletes from "# Custom Branding" to EOF)
# does not erase the OIDC settings on every branding update.
if "# Custom Branding" in cleaned:
    idx = cleaned.index("# Custom Branding")
    result = cleaned[:idx].rstrip() + oidc + "\n" + cleaned[idx:]
else:
    result = cleaned + oidc
with open(path, "w") as f:
    f.write(result)
print("Wazuh Dashboard OIDC settings applied")
WAZUH_OIDC_PY
            success "CySIEM Dashboard: OIDC settings written"
        else
            warn "CYSIEM_OIDC_SECRET not available — OIDC settings not written; re-run --update"
        fi

        _OS_SEC_CFG="/etc/wazuh-indexer/opensearch-security/config.yml"
        _CY_SEC_LOG="/var/log/cycentra/securityadmin.log"
        _CERT_DIR="/etc/wazuh-indexer/certs"
        _SEC_ADMIN="/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh"
        _IU_YML="/etc/wazuh-indexer/opensearch-security/internal_users.yml"
        mkdir -p /var/log/cycentra 2>/dev/null || true

        # ── Keep cy360_sso / cy360_readonly as internal users (legacy compat) ────
        if [[ -f "$_IU_YML" && -f "${_CERT_DIR}/admin.pem" ]]; then
            _CY360_SSO_HASH='$2y$12$nv335OI0o5tb4dnYtda8OeQastkTuiivxpkzh0nAYoxoZpMrJZ40S'
            _CY360_RO_HASH='$2y$12$0Tim1grS5kbbBdG20PFsF.WF2eovIc23rrYO2D0E92pqdNjecI.lO'
            _USERS_CHANGED=false
            if ! grep -q "^cy360_sso:" "$_IU_YML" 2>/dev/null; then
                cat >> "$_IU_YML" << CY360_SSO_EOF

cy360_sso:
  hash: "${_CY360_SSO_HASH}"
  reserved: false
  backend_roles:
  - "admin"
  description: "CyCentra 360 admin SSO service account (legacy)"
CY360_SSO_EOF
                _USERS_CHANGED=true
                success "OpenSearch cy360_sso user added"
            else
                success "OpenSearch cy360_sso user already present"
            fi
            if ! grep -q "^cy360_readonly:" "$_IU_YML" 2>/dev/null; then
                cat >> "$_IU_YML" << CY360_RO_EOF

cy360_readonly:
  hash: "${_CY360_RO_HASH}"
  reserved: false
  backend_roles:
  - "viewer"
  description: "CyCentra 360 viewer SSO service account (legacy)"
CY360_RO_EOF
                _USERS_CHANGED=true
                success "OpenSearch cy360_readonly user added"
            else
                success "OpenSearch cy360_readonly user already present"
            fi
            if [[ "$_USERS_CHANGED" == "true" ]]; then
                export JAVA_HOME=/usr/share/wazuh-indexer/jdk
                cd / && "$_SEC_ADMIN" \
                    -f "$_IU_YML" -t internalusers \
                    -icl -nhnv \
                    -cacert "${_CERT_DIR}/root-ca.pem" \
                    -cert   "${_CERT_DIR}/admin.pem" \
                    -key    "${_CERT_DIR}/admin-key.pem" \
                    -h 127.0.0.1 2>>"$_CY_SEC_LOG" \
                    && success "OpenSearch internal users applied via securityadmin" \
                    || warn "securityadmin.sh failed — check ${_CY_SEC_LOG}"
            fi
        fi

        # ── OpenSearch Security: add openid_auth_domain to config.yml ────────────
        if [[ -f "$_OS_SEC_CFG" && -f "${_CERT_DIR}/admin.pem" ]]; then
            _cfg_py_rc=0
            python3 - "$_OS_SEC_CFG" "$BASE_DOMAIN" << 'OS_OIDC_PY' || _cfg_py_rc=$?
import sys, re
path, domain = sys.argv[1], sys.argv[2]
with open(path, "r") as f:
    lines = f.read().splitlines()
if any("openid_auth_domain:" in ln for ln in lines):
    print("openid_auth_domain already present in config.yml")
    sys.exit(2)  # 2 = already present, no change needed
anchor_idx = None
anchor_indent = 0
for i, ln in enumerate(lines):
    m = re.match(r'^(\s+)basic_internal_auth_domain:', ln)
    if m:
        anchor_idx    = i
        anchor_indent = len(m.group(1))
        break
if anchor_idx is None:
    print("WARNING: basic_internal_auth_domain not found — config.yml unchanged", file=sys.stderr)
    sys.exit(1)
block_end = anchor_idx + 1
while block_end < len(lines):
    ln = lines[block_end]
    stripped = ln.lstrip()
    if stripped and not stripped.startswith("#"):
        if len(ln) - len(stripped) <= anchor_indent:
            break
    block_end += 1
p  = " " * anchor_indent
c  = " " * (anchor_indent + 2)
g  = " " * (anchor_indent + 4)
gg = " " * (anchor_indent + 6)
oidc = [
    "",
    f"{p}openid_auth_domain:",
    f"{c}http_enabled: true",
    f"{c}transport_enabled: false",
    f"{c}order: 0",
    f"{c}http_authenticator:",
    f"{g}type: openid",
    f"{g}challenge: false",
    f"{g}config:",
    f"{gg}subject_key: email",
    f"{gg}roles_key: roles",
    f'{gg}openid_connect_url: "https://cyasm.{domain}/oidc/.well-known/openid-configuration"',
    f"{gg}jwt_clock_skew_tolerance_seconds: 30",
    f"{c}authentication_backend:",
    f"{g}type: noop",
]
result = lines[:block_end] + oidc + lines[block_end:]
with open(path, "w") as f:
    f.write("\n".join(result) + "\n")
print("openid_auth_domain added to config.yml")
OS_OIDC_PY

            # Wait for OpenSearch indexer (up to 90 s)
            info "Waiting for OpenSearch indexer to be ready (up to 90 s)..."
            _INDEXER_READY=false
            for _n in $(seq 1 18); do
                _code=$(curl -sk -o /dev/null -w '%{http_code}' \
                    --cert "${_CERT_DIR}/admin.pem" \
                    --key  "${_CERT_DIR}/admin-key.pem" \
                    "https://127.0.0.1:9200/_cluster/health" 2>/dev/null || true)
                [[ "$_code" =~ ^2 ]] && { _INDEXER_READY=true; success "OpenSearch indexer ready"; break; }
                sleep 5
            done

            if [[ "$_INDEXER_READY" == "true" ]]; then
                # Apply config.yml (openid_auth_domain) via securityadmin.sh
                # rc=0: file updated; rc=2: already present; rc=1: error
                if [[ "$_cfg_py_rc" -eq 0 && -x "$_SEC_ADMIN" ]]; then
                    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
                    cd / && "$_SEC_ADMIN" \
                        -f "$_OS_SEC_CFG" -t config \
                        -icl -nhnv \
                        -cacert "${_CERT_DIR}/root-ca.pem" \
                        -cert   "${_CERT_DIR}/admin.pem" \
                        -key    "${_CERT_DIR}/admin-key.pem" \
                        -h 127.0.0.1 2>>"$_CY_SEC_LOG" \
                        && success "OpenSearch openid_auth_domain applied via securityadmin" \
                        || warn "securityadmin.sh failed — see ${_CY_SEC_LOG}"
                elif [[ "$_cfg_py_rc" -eq 2 ]]; then
                    success "openid_auth_domain already in config.yml — securityadmin not needed"
                else
                    warn "config.yml patch failed (rc=${_cfg_py_rc}) — check ${_OS_SEC_CFG}"
                fi

                # ── Roles mapping via REST API ────────────────────────────────────
                # admin + analyst OIDC roles → all_access; viewer → kibana_user + wazuh_ui_user
                _rm_aa=$(curl -sk -o /dev/null -w '%{http_code}' \
                    --cert "${_CERT_DIR}/admin.pem" --key "${_CERT_DIR}/admin-key.pem" \
                    -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/all_access" \
                    -H 'Content-Type: application/json' \
                    -d '{"backend_roles":["admin","analyst","all_access"],"hosts":[],"users":[]}' \
                    2>/dev/null || true)
                _rm_ku=$(curl -sk -o /dev/null -w '%{http_code}' \
                    --cert "${_CERT_DIR}/admin.pem" --key "${_CERT_DIR}/admin-key.pem" \
                    -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/kibana_user" \
                    -H 'Content-Type: application/json' \
                    -d '{"backend_roles":["viewer","kibanauser"],"hosts":[],"users":[]}' \
                    2>/dev/null || true)
                # wazuh_ui_user is a Wazuh-defined OpenSearch role that may be absent in
                # some installations (renamed or not pre-loaded).  Ensure it exists before
                # attempting the rolesmapping PUT — a missing role returns 404 from the API.
                _role_wu_status=$(curl -sk -o /dev/null -w '%{http_code}' \
                    --cert "${_CERT_DIR}/admin.pem" --key "${_CERT_DIR}/admin-key.pem" \
                    "https://127.0.0.1:9200/_plugins/_security/api/roles/wazuh_ui_user" \
                    2>/dev/null || true)
                if [[ "$_role_wu_status" == "404" ]]; then
                    info "wazuh_ui_user role absent — creating with read-only Wazuh index permissions ..."
                    curl -sk -o /dev/null \
                        --cert "${_CERT_DIR}/admin.pem" --key "${_CERT_DIR}/admin-key.pem" \
                        -X PUT "https://127.0.0.1:9200/_plugins/_security/api/roles/wazuh_ui_user" \
                        -H 'Content-Type: application/json' \
                        -d '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-*",".wazuh",".wazuh-version",".kibana*"],"allowed_actions":["read","indices:data/read/search"]}],"tenant_permissions":[]}' \
                        2>/dev/null || true
                fi
                _rm_wu=$(curl -sk -o /dev/null -w '%{http_code}' \
                    --cert "${_CERT_DIR}/admin.pem" --key "${_CERT_DIR}/admin-key.pem" \
                    -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/wazuh_ui_user" \
                    -H 'Content-Type: application/json' \
                    -d '{"backend_roles":["viewer","wazuh_ui_user"],"hosts":[],"users":[]}' \
                    2>/dev/null || true)
                [[ "$_rm_aa" =~ ^(200|201)$ ]] && success "all_access rolesmapping updated (admin+analyst)" \
                    || warn "all_access rolesmapping REST PUT returned ${_rm_aa}"
                [[ "$_rm_ku" =~ ^(200|201)$ ]] && success "kibana_user rolesmapping updated (viewer)" \
                    || warn "kibana_user rolesmapping REST PUT returned ${_rm_ku}"
                [[ "$_rm_wu" =~ ^(200|201)$ ]] && success "wazuh_ui_user rolesmapping updated (viewer)" \
                    || warn "wazuh_ui_user rolesmapping REST PUT returned ${_rm_wu}"
            else
                warn "OpenSearch not reachable — security config skipped; re-run --update once Wazuh is healthy"
            fi
        fi

        # ── Wazuh Manager API RBAC rules (maps OIDC backend_roles → Wazuh roles) ────
        # OpenSearch Security gives dashboard access; the Wazuh Manager API has its own
        # RBAC layer that controls Wazuh operations (agent mgmt, policies, etc.).
        # Map OIDC backend_roles to Wazuh roles via the security/rules + roles API.
        #   admin   → administrator (id 1) — full Wazuh access incl. agent management
        #   analyst → agents_admin (id 5)  — manage agents, no user/role administration
        #   viewer  → readonly (id 2)       — read-only access to all Wazuh resources
        # Idempotent: skips rule creation if a rule with the same name already exists.
        if [[ -n "${_WAZUH_PASS:-}" ]]; then
            _WAPI_TOKEN=$(curl -sk -u "wazuh-wui:${_WAZUH_PASS}" \
                -X POST 'https://127.0.0.1:55000/security/user/authenticate?raw=true' 2>/dev/null)
            if [[ -n "$_WAPI_TOKEN" && "$_WAPI_TOKEN" != *"error"* ]]; then
                _existing_rules=$(curl -sk \
                    -H "Authorization: Bearer ${_WAPI_TOKEN}" \
                    'https://127.0.0.1:55000/security/rules' 2>/dev/null)

                _make_wazuh_rule() {
                    local name="$1" field="$2" value="$3" role_id="$4"
                    if echo "$_existing_rules" | grep -q "\"$name\"" 2>/dev/null; then
                        info "Wazuh rule '$name' already exists — skipping"
                        return
                    fi
                    local new_rule
                    new_rule=$(curl -sk -H "Authorization: Bearer ${_WAPI_TOKEN}" \
                        -H 'Content-Type: application/json' \
                        -X POST 'https://127.0.0.1:55000/security/rules' \
                        -d "{\"name\":\"${name}\",\"rule\":{\"FIND\":{\"${field}\":\"${value}\"}}}" 2>/dev/null)
                    local new_id
                    new_id=$(echo "$new_rule" | python3 -c \
                        'import sys,json; d=json.load(sys.stdin); print(d["data"]["affected_items"][0]["id"])' 2>/dev/null)
                    if [[ -n "$new_id" ]]; then
                        curl -sk -H "Authorization: Bearer ${_WAPI_TOKEN}" \
                            -X POST "https://127.0.0.1:55000/security/roles/${role_id}/rules?rule_ids=${new_id}" \
                            >/dev/null 2>&1
                        success "Wazuh rule '$name' → Wazuh role ${role_id} (id ${new_id})"
                    else
                        warn "Wazuh rule '$name' creation failed: $new_rule"
                    fi
                }

                _make_wazuh_rule "cy360_oidc_admin"   "backend_roles" "admin"   1
                _make_wazuh_rule "cy360_oidc_analyst"  "backend_roles" "analyst" 5
                _make_wazuh_rule "cy360_oidc_viewer"   "backend_roles" "viewer"  2
            else
                warn "Wazuh API auth failed — RBAC rules skipped; check WAZUH_API_PASSWORD"
            fi
        else
            warn "WAZUH_API_PASSWORD not set — Wazuh API RBAC rules skipped"
        fi

        systemctl restart wazuh-dashboard 2>/dev/null || true
        success "CySIEM OIDC: Dashboard configured, OpenSearch security updated"
    else
        info "Wazuh not installed — CySIEM OIDC will run when Wazuh is deployed"
    fi

    # ── Migrate nginx cysiem block to OIDC mode (idempotent) ─────────────────────
    # Removes the siem-gate auth_request + Authorization header injection.
    # Wazuh Dashboard OIDC now handles authentication natively.
    _NGINX_MOD="/etc/nginx/sites-available/cycentra-modules"
    if [[ -f "$_NGINX_MOD" ]]; then
        if ! grep -q 'siem-gate\|Authorization.*wazuh_auth\|proxy_set_header.*Authorization.*wazuh' "$_NGINX_MOD" 2>/dev/null; then
            success "nginx cysiem: already in OIDC mode"
        else
            python3 - "$_NGINX_MOD" << 'NGINX_OIDC_PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    text = f.read()

# Remove IAP comments + siem-gate auth_request lines
text = re.sub(
    r'    # IAP gate[^\n]*\n(?:    # [^\n]*\n)*'
    r'    auth_request\s+/siem-gate[^\n]*\n'
    r'    auth_request_set[^\n]*\n'
    r'    error_page 401 = @error401;\n',
    '    # Authentication handled by Wazuh Dashboard OIDC (cyasm.DOMAIN/oidc)\n',
    text
)
# Remove location @error401 block pointing to cysiem
text = re.sub(r'    location @error401 \{ return 302[^\n]*cysiem[^\n]*\n', '', text)
# Remove location = /siem-gate { ... } block
text = re.sub(r'    location = /siem-gate \{[^}]+\}\n', '', text, flags=re.DOTALL)
# Remove Role-appropriate comment + Authorization $wazuh_auth header
text = re.sub(r'        # Role-appropriate[^\n]*\n', '', text)
text = re.sub(r'        proxy_set_header Authorization \$wazuh_auth;\n', '', text)

with open(path, 'w') as f:
    f.write(text)
print("nginx cysiem: migrated to OIDC mode (siem-gate removed)")
NGINX_OIDC_PY
            nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
                success "nginx cysiem: migrated to OIDC mode" || \
                warn "nginx config invalid after OIDC migration — check: nginx -t"
        fi
    fi

    # ── Remove duplicate CORS headers from cyasm nginx block (added before v1.0.286) ──
    # Flask's global after_request hook is the single CORS authority. nginx was also
    # adding CORS headers on the cyasm vhost, producing duplicates that caused the
    # browser to reject every /auth/local response with "Network error".
    if [[ -f "$_NGINX_MOD" ]] && grep -q 'cors_origin\|Access-Control-Allow-Origin' "$_NGINX_MOD" 2>/dev/null; then
        sed -i '/set \$cors_origin/d' "$_NGINX_MOD" || true
        sed -i '/if.*http_origin.*cors_origin/d' "$_NGINX_MOD" || true
        sed -i '/add_header Access-Control-Allow-Origin/d' "$_NGINX_MOD" || true
        sed -i '/add_header Access-Control-Allow-Credentials/d' "$_NGINX_MOD" || true
        sed -i '/add_header Access-Control-Allow-Methods/d' "$_NGINX_MOD" || true
        sed -i '/add_header Access-Control-Allow-Headers.*CyCentra/d' "$_NGINX_MOD" || true
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
            success "nginx cyasm: duplicate CORS headers removed" || \
            warn "nginx reload failed after CORS patch — check: nginx -t"
    fi

    # ── Remove OPTIONS intercept from cyasm nginx block (added before v1.0.295) ──
    # The Flask app.py blanket handler (/auth/<path>) returns 204 + full CORS
    # headers for every OPTIONS preflight. The nginx-level `if ($request_method
    # = OPTIONS) { return 204; }` was intercepting those requests before Flask
    # saw them and returning 204 with NO Access-Control-* headers, causing the
    # browser to reject every /auth/local CORS preflight → "Network error".
    if [[ -f "$_NGINX_MOD" ]] && grep -q 'request_method = OPTIONS.*return 204' "$_NGINX_MOD" 2>/dev/null; then
        sed -i '/if (\$request_method = OPTIONS) { return 204; }/d' "$_NGINX_MOD" || true
        sed -i '/if ($request_method = OPTIONS) { return 204; }/d' "$_NGINX_MOD" || true
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
            success "nginx cyasm: OPTIONS intercept removed — Flask handles CORS preflight" || \
            warn "nginx reload failed after OPTIONS patch — check: nginx -t"
    fi

    # ── Inject /edr-packages/ nginx location if missing (idempotent) ────────────
    # Serves pre-built CyEDR agent binaries (.deb/.rpm/.msi/.pkg + standalone exe).
    # Built by agent-packages/build-edr-packages.sh; stored in the edr/ subdirectory.
    if [[ -f "$_NGINX_MOD" ]] && ! grep -q '/edr-packages/' "$_NGINX_MOD" 2>/dev/null; then
        python3 - "$_NGINX_MOD" << 'EDR_PKG_NGINX_PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    text = f.read()

block = (
    "    # ── CyEDR agent package distribution — served directly by nginx ──\n"
    "    location /edr-packages/ {\n"
    "        alias /var/lib/cycentra-agent-packages/edr/;\n"
    "        autoindex off;\n"
    "        add_header Content-Disposition \"attachment\" always;\n"
    "        add_header X-Content-Type-Options \"nosniff\" always;\n"
    "        add_header Cache-Control \"no-store, must-revalidate\" always;\n"
    "    }\n"
)

anchor = "    location /     { try_files"
if "/edr-packages/" not in text and anchor in text:
    idx = text.find(anchor)
    text = text[:idx] + block + text[idx:]
    with open(path, "w") as f:
        f.write(text)
    print("nginx cy360: /edr-packages/ location block injected")
else:
    print("nginx cy360: /edr-packages/ already present or anchor not found")
EDR_PKG_NGINX_PY
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
            success "nginx: /edr-packages/ location block added and reloaded" || \
            warn "nginx reload failed after edr-packages injection — check: nginx -t"
    else
        [[ -f "$_NGINX_MOD" ]] && success "nginx: /edr-packages/ location already configured"
    fi

    # ── Inject /agent-packages/ nginx location if missing (idempotent) ──────────
    # Fresh installs already have this block from the heredoc above.
    # Updates on existing servers need it injected into the live config.
    if [[ -f "$_NGINX_MOD" ]] && ! grep -q '/agent-packages/' "$_NGINX_MOD" 2>/dev/null; then
        python3 - "$_NGINX_MOD" << 'AGENT_PKG_NGINX_PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    text = f.read()

block = (
    "    # ── Agent package distribution — served directly by nginx ──\n"
    "    location /agent-packages/ {\n"
    "        alias /var/lib/cycentra-agent-packages/;\n"
    "        autoindex off;\n"
    "        add_header Content-Disposition \"attachment\" always;\n"
    "        add_header X-Content-Type-Options \"nosniff\" always;\n"
    "        add_header Cache-Control \"no-store, must-revalidate\" always;\n"
    "    }\n"
)

# Insert before the catch-all "location /" in the cy360 server block
anchor = "    location /     { try_files"
if "/agent-packages/" not in text and anchor in text:
    idx = text.find(anchor)
    text = text[:idx] + block + text[idx:]
    with open(path, "w") as f:
        f.write(text)
    print("nginx cy360: /agent-packages/ location block injected")
else:
    print("nginx cy360: /agent-packages/ already present or anchor not found")
AGENT_PKG_NGINX_PY
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
            success "nginx: /agent-packages/ location block added and reloaded" || \
            warn "nginx reload failed after agent-packages injection — check: nginx -t"
    else
        [[ -f "$_NGINX_MOD" ]] && success "nginx: /agent-packages/ location already configured"
    fi

    # ── Ensure agent-packages location uses correct alias path ──────────────────
    # Target: alias /var/lib/cycentra-agent-packages/;
    # Old broken configs: alias /opt/cycentra/agent-packages/ (NGINX can't traverse 700 dir)
    # Also fixes no-alias configs (symlink approach that also failed for the same reason).
    if [[ -f "$_NGINX_MOD" ]]; then
        python3 - "$_NGINX_MOD" << 'ALIAS_FIX_PY'
import sys, re
path = sys.argv[1]
with open(path) as f:
    text = f.read()

correct_alias = "        alias /var/lib/cycentra-agent-packages/;\n"
changed = False

# Replace wrong alias (old path)
new_text = re.sub(
    r'([ \t]+location /agent-packages/ \{)\n([ \t]+alias [^\n]+;\n)?',
    lambda m: m.group(1) + "\n" + correct_alias if m.group(2) != correct_alias else m.group(0),
    text
)
if new_text != text:
    text = new_text
    changed = True

# Add alias if the block exists but has no alias at all
def add_alias_if_missing(m):
    block = m.group(0)
    if "alias " not in block:
        return block.replace("location /agent-packages/ {\n", "location /agent-packages/ {\n" + correct_alias, 1)
    return block
new_text = re.sub(r'location /agent-packages/ \{[^}]+\}', add_alias_if_missing, text, flags=re.DOTALL)
if new_text != text:
    text = new_text
    changed = True

with open(path, 'w') as f:
    f.write(text)
print("nginx: agent-packages alias updated" if changed else "nginx: agent-packages alias already correct")
ALIAS_FIX_PY
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
            success "nginx: agent-packages alias verified/fixed and nginx reloaded" || \
            warn "nginx reload failed — check: nginx -t"
    fi

    # ── Inject /agent-packages/ into cysiem nginx block if missing (idempotent) ──
    # Packages must also be downloadable from cysiem.DOMAIN because the agent
    # connects to CySIEM (Wazuh) and the installer uses SERVER_URL=cysiem.DOMAIN.
    if [[ -f "$_NGINX_MOD" ]]; then
        python3 - "$_NGINX_MOD" << 'CYSIEM_PKG_INJECT_PY'
import sys

path = sys.argv[1]
text = open(path).read()

# Anchor unique to the cysiem block — the Wazuh Dashboard proxy_pass
cysiem_anchor = "    location / {\n        proxy_pass https://127.0.0.1:5601;\n"

if cysiem_anchor not in text:
    print("nginx cysiem: anchor not found (block may not exist yet)")
    sys.exit(0)

anchor_pos = text.find(cysiem_anchor)
# Check 600 chars before anchor for an existing agent-packages block
if "/agent-packages/" in text[max(0, anchor_pos - 600):anchor_pos]:
    print("nginx cysiem: /agent-packages/ already present")
    sys.exit(0)

block = (
    "    location /agent-packages/ {\n"
    "        alias /var/lib/cycentra-agent-packages/;\n"
    "        autoindex off;\n"
    "        add_header Content-Disposition \"attachment\" always;\n"
    "        add_header X-Content-Type-Options \"nosniff\" always;\n"
    "        add_header Cache-Control \"no-store, must-revalidate\" always;\n"
    "    }\n"
)

new_text = text.replace(cysiem_anchor, block + cysiem_anchor, 1)
open(path, 'w').write(new_text)
print("nginx cysiem: /agent-packages/ location block injected")
CYSIEM_PKG_INJECT_PY
        _py_exit=$?
        if [[ $_py_exit -eq 0 ]]; then
            nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && \
                success "nginx cysiem: /agent-packages/ block added and nginx reloaded" || \
                warn "nginx reload failed after cysiem agent-packages injection — check: nginx -t"
        fi
    fi

    # ── Ensure sites-enabled is a symlink to sites-available ─────────────────────
    # On servers where sites-enabled/cycentra-modules is a hardcopy file (not a
    # symlink), all nginx migration edits above are invisible to nginx because it
    # reads sites-enabled directly. Force-recreate the symlink so sites-enabled
    # always reflects sites-available. This is idempotent — ln -sf is safe to
    # repeat and the full-install step also runs this same command.
    if [[ -f "/etc/nginx/sites-available/cycentra-modules" ]]; then
        _SE="/etc/nginx/sites-enabled/cycentra-modules"
        if [[ ! -L "$_SE" ]]; then
            ln -sf /etc/nginx/sites-available/cycentra-modules "$_SE" 2>/dev/null && \
                info "nginx: sites-enabled replaced with symlink to sites-available" || true
        fi
    fi

# ── Step 11: Deploy portal static files ──────────────────────────────────────
step_header "DEPLOYING PORTAL"

PORTAL_DIR="/var/www/cycentra360"
mkdir -p "$PORTAL_DIR"
if [[ -d "$BUNDLE_DIR/portal/dist" ]]; then
    rsync -a --delete "$BUNDLE_DIR/portal/dist/" "$PORTAL_DIR/"
    success "Portal deployed → ${PORTAL_DIR} ($(find $PORTAL_DIR -type f | wc -l) files)"
    # Inject domain immediately after deploy so the portal never ships without it,
    # even if later steps fail or setup is run incrementally.
    _pidx="$PORTAL_DIR/index.html"
    if [[ -f "$_pidx" ]]; then
        sed -i '/window\.__CYCENTRA_DOMAIN__/d' "$_pidx"
        sed -i '/window\.__CYCENTRA_CLIENT__/d'  "$_pidx"
        sed -i "s|</head>|<script>window.__CYCENTRA_DOMAIN__='${BASE_DOMAIN}';window.__CYCENTRA_CLIENT__='${CLIENT_NAME:-cycentra}';</script></head>|" "$_pidx"
        success "Domain injected into portal index.html → ${BASE_DOMAIN}"
    fi
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
    -qq \
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
# Load .env first as the shared base (vault creds, API keys, BASE_DOMAIN, etc.)
# cysiemstack.env then adds / overrides with engine-specific vars only.
# Operators only need to update /opt/cycentra/.env — the engine inherits it.
EnvironmentFile=/opt/cycentra/.env
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
systemctl restart cycentra-backend \
    || { warn "Flask backend failed to start — check: journalctl -u cycentra-backend -n 30"; \
         ERRORS+=("Flask backend restart failed"); }
sleep 4
curl -s --max-time 5 http://127.0.0.1:5252/health 2>/dev/null | grep -q "ok" \
    && success "Flask backend healthy :5252" \
    || { warn "Flask not responding — check: journalctl -u cycentra-backend -n 30"; \
         ERRORS+=("Flask unhealthy"); }

# Start correlation engine (MCP bridge runs inside this same process at /mcp/sse)
systemctl restart cysiemstack-engine \
    || { warn "SIEM engine failed to start — check: journalctl -u cysiemstack-engine -n 30"; \
         ERRORS+=("SIEM engine restart failed"); }
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
# NOTE v7.2: CySOAR nginx config is managed dynamically by routes.py on module install/uninstall:
#   CySOAR  → injects location CySOAR into portal server on install
#   CyMISP  → was already routes.py-managed (unchanged)
# Only permanent core services remain here: cy360, cyasm, cysiem.
if [[ "$MODE" == "full" ]]; then

    step_header "NGINX VHOST CONFIGURATION"

    SSL_CONF="/etc/nginx/sites-available/cycentra-modules"
    SSL_CONF_BACKUP="${SSL_CONF}.ssl-pending"

    cat > "$SSL_CONF" << NGINXEOF
# CyCentra 360 nginx — generated by setup wizard v7.2 — ${BASE_DOMAIN}
# Module nginx blocks (cysoar, cymisp) are managed by routes.py.

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

# ── Machine-to-machine (M2M) — LAN HTTP, default_server ──────────────────────
# Handles direct-IP requests from CyMind (Server B) over plain HTTP.
# Named-vhost requests (cy360/cyasm/cysiem.DOMAIN) still reach their own blocks.
# All paths are protected by the CyMind API key at the application layer.
server {
    listen 80 default_server;
    server_name _;

    # MCP SSE bridge — requires Authorization: Bearer <cymind_key>
    location /mcp/ {
        proxy_pass         http://127.0.0.1:8100/mcp/;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   Authorization     \$http_authorization;
        proxy_set_header   X-CyMind-Key      \$http_x_cymind_key;
        proxy_set_header   Connection        "";
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
        chunked_transfer_encoding on;
    }

    # REST context fallback — requires X-CyMind-Key header
    location /api/cymind/ {
        proxy_pass         http://127.0.0.1:5252/api/cymind/;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-CyMind-Key      \$http_x_cymind_key;
        proxy_set_header   Authorization     \$http_authorization;
        proxy_read_timeout 60s;
    }

    # Drop all other direct-IP requests silently
    location / { return 403; }
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
    # ── Agent package distribution — served directly by nginx (no Flask proxy) ──
    # Packages live at /var/lib/cycentra-agent-packages/ (www-data owned, 755).
    # This path is outside /opt/cycentra/ (which is root-only 700) so NGINX can
    # traverse it without permission issues.
    location /agent-packages/ {
        alias /var/lib/cycentra-agent-packages/;
        autoindex off;
        add_header Content-Disposition "attachment" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cache-Control "no-store, must-revalidate" always;
    }
    location /     { try_files \$uri \$uri/ /index.html; }
    location /assets/  { expires 1y; add_header Cache-Control "public, immutable"; }
    location = /index.html { add_header Cache-Control "no-cache, no-store, must-revalidate"; }
    location /api/  { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_read_timeout 180s; }
    location /auth/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }
    location /oidc/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }
    # OIDC discovery doc — proxy /.well-known/ to Flask so cy360.<domain>/.well-known/openid-configuration works
    location /.well-known/ { proxy_pass http://127.0.0.1:5252; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; }
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
    location @error401 { return 302 https://cy360.${BASE_DOMAIN}/oauth2/sign_in?rd=https://\$host\$request_uri; }
    # ── MCP SSE bridge — public HTTPS access for CyMind on a separate server ──
    # CyMind on LAN uses the port-80 default_server block above.
    # CyMind on a public-facing server (e.g. cymind.cycentra.com) must reach
    # this via HTTPS — we proxy /mcp/ directly to the correlation engine.
    # Auth is enforced by the engine itself (Bearer cymk_... key check).
    location /mcp/ {
        proxy_pass         http://127.0.0.1:8100/mcp/;
        proxy_http_version 1.1;
        proxy_set_header   Host              \$host;
        proxy_set_header   Authorization     \$http_authorization;
        proxy_set_header   X-CyMind-Key      \$http_x_cymind_key;
        proxy_set_header   Connection        "";
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
        chunked_transfer_encoding on;
    }
    # location /cymind/ is injected here by routes.py when CyMind is configured via portal
    # location /cysoar/ is injected here by routes.py when CySOAR is installed via portal
}

# ── Backend / OIDC IdP (cyasm) ──────────────────────────────────────────────
server { listen 80; server_name cyasm.${BASE_DOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; server_name cyasm.${BASE_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;
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
    # Authentication handled by Wazuh Dashboard OIDC (cyasm.${BASE_DOMAIN}/oidc).
    # Individual user identity is established per OIDC token; roles claim maps to
    # OpenSearch Security backend roles (admin/analyst → all_access; viewer → read-only).
    location /agent-packages/ {
        alias /var/lib/cycentra-agent-packages/;
        autoindex off;
        add_header Content-Disposition "attachment" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Cache-Control "no-store, must-revalidate" always;
    }
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
# Module server blocks are added by routes.py when modules are installed via portal
# cymisp.DOMAIN server block is added by routes.py when CyMISP is installed via portal
# cymind.DOMAIN server block is added by cymind/install.sh when CyMind is installed
NGINXEOF

    # ── CyMind nginx proxy block: inject if CYMIND_SERVER_IP is known at install time ──
    # Set CYMIND_SERVER_IP env var before running setup.sh to wire up the /cymind/ proxy
    # automatically.  Otherwise routes.py handles it when admin configures via portal.
    if [[ -n "${CYMIND_SERVER_IP:-}" ]]; then
        _cymind_upstream="http://${CYMIND_SERVER_IP}"
        python3 - "$SSL_CONF" "$_cymind_upstream" << 'CYMIND_INJECT_PY'
import re, sys
conf_path, upstream = sys.argv[1], sys.argv[2].rstrip("/") + "/"
ssl_extra = "        proxy_ssl_verify    off;\n" if upstream.startswith("https") else ""
block = (
    "    # CyMind chat proxy — same-origin iframe, no mixed-content\n"
    "    location /cymind/ {\n"
    f"        proxy_pass         {upstream};\n"
    "        proxy_http_version 1.1;\n"
    f"{ssl_extra}"
    "        proxy_set_header   Host              $http_host;\n"
    "        proxy_set_header   X-Real-IP         $remote_addr;\n"
    "        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;\n"
    "        proxy_set_header   X-Forwarded-Proto $scheme;\n"
    "        proxy_set_header   Connection        \"\";\n"
    "        proxy_read_timeout 300s;\n"
    "        proxy_buffering    off;\n"
    "        proxy_cache        off;\n"
    "    }\n"
)
with open(conf_path) as f:
    text = f.read()
# Remove any stale /cymind/ block
text = re.sub(r'[ \t]+# CyMind chat proxy[^\n]*\n[ \t]+location /cymind/ \{[^}]+\}\n',
              '', text, flags=re.DOTALL)
anchor = "    # location /cymind/ is injected here"
if anchor in text:
    ins = text.find(anchor)
    eol = text.find("\n", ins)
    text = text[:ins] + block + text[eol + 1:]
    with open(conf_path, "w") as f:
        f.write(text)
    print(f"cymind: /cymind/ → {upstream} injected into nginx")
else:
    print("cymind: anchor not found — add location /cymind/ manually")
CYMIND_INJECT_PY
        info "CyMind nginx proxy block: pointing to ${CYMIND_SERVER_IP}"
    else
        info "CYMIND_SERVER_IP not set — /cymind/ proxy will be injected by routes.py when admin configures CyMind URL via portal"
    fi

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
        local primary_domain="$1"; shift   # e.g. cy360.cycentra.com
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

    # ── certbot: cy360 + cyasm ───────────────────────────────────────────────
    _CB_LOG_BASE="/tmp/certbot-cy360-$$.log"
    _certbot_if_needed "cy360.${BASE_DOMAIN}" "$_CB_LOG_BASE" \
        -m "$CLIENT_EMAIL" -d cy360.${BASE_DOMAIN} -d cyasm.${BASE_DOMAIN} \
        && success "SSL cert ready (cy360, cyasm)" \
        || true   # self-signed fallback below handles missing cert

    # ── certbot: cysiem ───────────────────────────────────────────────────────
    _CB_LOG_SIEM="/tmp/certbot-cysiem-$$.log"
    _certbot_if_needed "cysiem.${BASE_DOMAIN}" "$_CB_LOG_SIEM" \
        -m "$CLIENT_EMAIL" -d cysiem.${BASE_DOMAIN} \
        && success "SSL cert ready (cysiem)" \
        || true
    # NOTE: cymisp certs are obtained by routes.py (certbot --nginx -d cymisp.DOMAIN)
    # when those modules are installed via the portal. No cert is needed here
    # because no cymisp nginx block exists until the module is installed.

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
    _BASE_CERT="/etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem"
    _SIEM_CERT="/etc/letsencrypt/live/cysiem.${BASE_DOMAIN}/fullchain.pem"
    _SELFSIGNED_DIR="/etc/ssl/cycentra/selfsigned"

    if [[ ! -f "$_BASE_CERT" ]]; then
        info "Generating self-signed cert for cy360/cyasm (temporary — browser will show security warning)..."
        mkdir -p "$_SELFSIGNED_DIR" "/etc/letsencrypt/live/cy360.${BASE_DOMAIN}"
        openssl req -x509 -nodes -newkey rsa:2048 \
            -keyout "$_SELFSIGNED_DIR/cy360-privkey.pem" \
            -out    "$_SELFSIGNED_DIR/cy360-fullchain.pem" \
            -days 90 \
            -subj "/CN=cy360.${BASE_DOMAIN}/O=CyCentra/C=US" \
            -addext "subjectAltName=DNS:cy360.${BASE_DOMAIN},DNS:cyasm.${BASE_DOMAIN}" \
            2>/dev/null \
            && { ln -sf "$_SELFSIGNED_DIR/cy360-fullchain.pem" \
                        "/etc/letsencrypt/live/cy360.${BASE_DOMAIN}/fullchain.pem"
                 ln -sf "$_SELFSIGNED_DIR/cy360-privkey.pem" \
                        "/etc/letsencrypt/live/cy360.${BASE_DOMAIN}/privkey.pem"
                 warn "Self-signed cert installed for cy360/cyasm — re-run setup after DNS resolves to replace with Let's Encrypt"; } \
            || warn "Self-signed cert generation failed for cy360/cyasm"
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

# ── Step 18: Wazuh rules, decoders, ossec.conf, agent config ─────────────────
if [[ -d "/var/ossec" ]]; then

    step_header "WAZUH RULES & CONFIG"

    CONFIG_SRC="/tmp/cycentra-config"
    [[ -d "$CONFIG_SRC/rules" ]] && \
        cp "$CONFIG_SRC/rules/"*.xml /var/ossec/etc/rules/ 2>/dev/null || true
    [[ -d "$CONFIG_SRC/decoders" ]] && \
        cp "$CONFIG_SRC/decoders/"*.xml /var/ossec/etc/decoders/ 2>/dev/null || true

    # ── Active-response scripts — deploy all from CYSIEM-Config/active-response/ ──
    mkdir -p /var/ossec/active-response/bin
    for _ar_script in isolate-host.sh quarantine-file.sh scan-endpoint.sh block-usb.sh block-wifi.sh restrict-network.sh collect-forensics.sh; do
        if [[ -f "$CONFIG_SRC/active-response/$_ar_script" ]]; then
            cp "$CONFIG_SRC/active-response/$_ar_script" /var/ossec/active-response/bin/
            chmod 750 "/var/ossec/active-response/bin/$_ar_script"
            chown root:wazuh "/var/ossec/active-response/bin/$_ar_script"
            success "$_ar_script deployed to active-response/bin"
        else
            warn "$_ar_script not found in CYSIEM-Config/active-response — skipping"
        fi
    done

    # ── Clean up legacy LLM integration left from prior installs ─────────────
    if [[ -f "/var/ossec/integrations/custom-llm.py" ]]; then
        rm -f /var/ossec/integrations/custom-llm.py
        info "Removed legacy custom-llm.py from /var/ossec/integrations/"
    fi

    if [[ -f "$CONFIG_SRC/conf/ossec.conf" ]]; then
        if [[ "$MODE" == "update" && -f "/var/ossec/etc/ossec.conf" ]]; then
            # --update: preserve the live ossec.conf so custom integrations
            # (O365, Google Workspace, AWS, etc.) configured post-install are not wiped.
            # The template is saved alongside the live file for reference/diffing.
            cp "$CONFIG_SRC/conf/ossec.conf" "/var/ossec/etc/ossec.conf.new-$(date +%Y%m%d)"
            info "ossec.conf update skipped — live config preserved (custom integrations safe)"
            info "New template saved as /var/ossec/etc/ossec.conf.new-$(date +%Y%m%d) for reference"
        else
            # Fresh install or explicit --upgrade: deploy the bundled template
            if [[ -f "/var/ossec/etc/ossec.conf" ]]; then
                cp "/var/ossec/etc/ossec.conf" "/var/ossec/etc/ossec.conf.backup-$(date +%Y%m%d-%H%M%S)"
                info "Existing ossec.conf backed up"
            fi
            cp "$CONFIG_SRC/conf/ossec.conf" /var/ossec/etc/ossec.conf
            chmod 660 /var/ossec/etc/ossec.conf
            success "ossec.conf deployed"
        fi
    fi

    # ── MISP blacklist stub + idempotent ossec.conf patching ─────────────────
    # On fresh install the deployed template already contains these blocks.
    # On --update the live ossec.conf is preserved; we patch it in place.

    # 1. Create MISP global blacklist CDB stub if absent
    MISP_LIST_PATH="/var/ossec/etc/lists/misp_global_blacklist"
    if [[ ! -f "$MISP_LIST_PATH" ]]; then
        mkdir -p "$(dirname "$MISP_LIST_PATH")"
        touch "$MISP_LIST_PATH"
        chown root:wazuh "$MISP_LIST_PATH"
        chmod 660 "$MISP_LIST_PATH"
        info "MISP blacklist stub created at $MISP_LIST_PATH — populate via MISP feed sync"
    fi

    # 2. Patch live ossec.conf (each block guarded by grep — safe to re-run)
    _OSSEC_LIVE="/var/ossec/etc/ossec.conf"
    if [[ -f "$_OSSEC_LIVE" ]]; then

        # 2a. MISP CDB list entry
        if ! grep -q "misp_global_blacklist" "$_OSSEC_LIVE"; then
            sed -i 's|<list>etc/lists/malicious-ioc/malicious-domains</list>|<list>etc/lists/malicious-ioc/malicious-domains</list>\n    <list>etc/lists/misp_global_blacklist</list>|' "$_OSSEC_LIVE"
            info "misp_global_blacklist CDB entry injected into ossec.conf"
        fi

        # 2b. isolate-host command block
        if ! grep -q "isolate-host" "$_OSSEC_LIVE"; then
            sed -i 's|<!-- Active response -->|<!-- Active response -->\n\n  <!-- CyCentra 360 XDR: host isolation command -->\n  <command>\n    <name>isolate-host<\/name>\n    <executable>isolate-host.sh<\/executable>\n    <timeout_allowed>yes<\/timeout_allowed>\n  <\/command>|' "$_OSSEC_LIVE"
            info "isolate-host command block injected into ossec.conf"
        fi

        # 2c. isolate-host active-response blocks (python3 for clean multi-line insert)
        # rules_id 101000,101010,101030,101031 — Wazuh + CyEDR anti-tamper triggers only.
        # 101001 (auditd ptrace/memfd) removed: CyEDR owns process injection detection.
        # 101011 (Sysmon CreateRemoteThread) removed: Wazuh no longer receives Sysmon events.
        if ! grep -qF '<rules_id>101000,101010,101030,101031' "$_OSSEC_LIVE"; then
            python3 - "$_OSSEC_LIVE" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
AR_BLOCK = (
    "\n  <!-- CyCentra 360 XDR: local isolation — agent anti-tamper\n"
    "       101000: auditd Wazuh tamper | 101010: Windows Wazuh service stop\n"
    "       101030: auditd CyEDR tamper | 101031: Windows CyEDR service stop -->\n"
    "  <active-response>\n"
    "    <command>isolate-host</command>\n"
    "    <location>local</location>\n"
    "    <rules_id>101000,101010,101030,101031</rules_id>\n"
    "    <timeout>600</timeout>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n\n"
    "  <!-- CyCentra 360 XDR: extended local isolation — ransomware precursor -->\n"
    "  <active-response>\n"
    "    <command>isolate-host</command>\n"
    "    <location>local</location>\n"
    "    <rules_id>100203</rules_id>\n"
    "    <timeout>3600</timeout>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n\n"
    "  <!-- CyCentra 360 XDR: global isolation — absolute MISP threat intel match -->\n"
    "  <active-response>\n"
    "    <command>isolate-host</command>\n"
    "    <location>all</location>\n"
    "    <rules_id>101002,101003</rules_id>\n"
    "    <timeout>3600</timeout>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n\n"
)
content = content.replace('<!-- Log analysis -->', AR_BLOCK + '<!-- Log analysis -->', 1)
with open(path, 'w') as f:
    f.write(content)
PYEOF
            info "isolate-host active-response blocks injected into ossec.conf"
        fi

        # 2d. Migrate stale AR rule_id sets from prior installs to the current canonical set.
        # Old sets that predate CyEDR migration contained 101001 (auditd injection — now CyEDR)
        # and 101011 (Sysmon CreateRemoteThread — now CyEDR). Replace all known stale variants.
        for _stale in \
            '101000,101001</rules_id>' \
            '101000,101001,101010,101011</rules_id>' \
            '101000,101010,101011</rules_id>'; do
            if grep -qF "$_stale" "$_OSSEC_LIVE"; then
                sed -i "s|<rules_id>${_stale%<*}|<rules_id>101000,101010,101030,101031</rules_id>|g" "$_OSSEC_LIVE"
                info "isolate-host AR block migrated: $_stale → 101000,101010,101030,101031"
            fi
        done

        # 2e. Remove stale custom-llm.py integration block
        if grep -q 'custom-llm\.py' "$_OSSEC_LIVE"; then
            python3 - "$_OSSEC_LIVE" << 'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f: content = f.read()
content = re.sub(
    r'\n?\s*<integration>\s*<name>custom-llm\.py</name>.*?</integration>',
    '', content, flags=re.DOTALL
)
with open(path, 'w') as f: f.write(content)
PYEOF
            info "Removed stale custom-llm.py integration block from ossec.conf"
        fi

        # 2f. Remove stale CyAI active-response blocks (rules_id 100050)
        if grep -q 'rules_id>100050' "$_OSSEC_LIVE"; then
            python3 - "$_OSSEC_LIVE" << 'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f: content = f.read()
content = re.sub(
    r'\n?\s*<active-response>(?:(?!</active-response>).)*?<rules_id>100050</rules_id>.*?</active-response>',
    '', content, flags=re.DOTALL
)
with open(path, 'w') as f: f.write(content)
PYEOF
            info "Removed stale CyAI active-response blocks (rule 100050) from ossec.conf"
        fi

        # 2g. Add new CyCentra commands + AR blocks (python3 for multi-line insert)
        if ! grep -q 'quarantine-file' "$_OSSEC_LIVE"; then
            python3 - "$_OSSEC_LIVE" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f: content = f.read()
NEW_CMDS = (
    "\n  <!-- CyCentra 360: quarantine malicious file and kill owning process -->\n"
    "  <command>\n"
    "    <name>quarantine-file</name>\n"
    "    <executable>quarantine-file.sh</executable>\n"
    "    <timeout_allowed>no</timeout_allowed>\n"
    "  </command>\n\n"
    "  <!-- CyCentra 360: on-demand endpoint malware scan (portal-triggered) -->\n"
    "  <command>\n"
    "    <name>scan-endpoint</name>\n"
    "    <executable>scan-endpoint.sh</executable>\n"
    "    <timeout_allowed>no</timeout_allowed>\n"
    "  </command>\n\n"
    "  <!-- CyCentra 360: block USB storage device on endpoint -->\n"
    "  <command>\n"
    "    <name>block-usb</name>\n"
    "    <executable>block-usb.sh</executable>\n"
    "    <timeout_allowed>yes</timeout_allowed>\n"
    "  </command>\n\n"
    "  <!-- CyCentra 360: disable WiFi/wireless on endpoint (portal-triggered) -->\n"
    "  <command>\n"
    "    <name>block-wifi</name>\n"
    "    <executable>block-wifi.sh</executable>\n"
    "    <timeout_allowed>yes</timeout_allowed>\n"
    "  </command>\n"
)
NEW_AR = (
    "\n  <!-- CyCentra 360: C2 / DCSync / PtH / cryptominer — firewall-drop on local agent -->\n"
    "  <active-response>\n"
    "    <command>firewall-drop</command>\n"
    "    <location>local</location>\n"
    "    <rules_id>100950,100951,100952,100953</rules_id>\n"
    "    <timeout>3600</timeout>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n\n"
    "  <!-- CyCentra 360: MFA push bombing — lock targeted OS account -->\n"
    "  <active-response>\n"
    "    <command>disable-account</command>\n"
    "    <location>local</location>\n"
    "    <rules_id>100801</rules_id>\n"
    "    <timeout>3600</timeout>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n\n"
    "  <!-- CyCentra 360: MISP hash match — quarantine matched process binary -->\n"
    "  <active-response>\n"
    "    <command>quarantine-file</command>\n"
    "    <location>local</location>\n"
    "    <rules_id>101003</rules_id>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n\n"
    "  <!-- CyCentra 360: USB insertion — block USB storage on endpoint -->\n"
    "  <active-response>\n"
    "    <command>block-usb</command>\n"
    "    <location>local</location>\n"
    "    <rules_id>100910,100911</rules_id>\n"
    "    <timeout>0</timeout>\n"
    "    <disabled>no</disabled>\n"
    "  </active-response>\n"
)
content = content.replace('<!-- Log analysis -->', NEW_CMDS + '\n' + NEW_AR + '\n  <!-- Log analysis -->', 1)
with open(path, 'w') as f: f.write(content)
PYEOF
            info "CyCentra 360 AR commands and blocks injected into ossec.conf"
        fi

        # 2h. Add <expect>user</expect> to disable-account command if missing
        if grep -q 'name>disable-account<' "$_OSSEC_LIVE" \
           && ! grep -A5 'name>disable-account<' "$_OSSEC_LIVE" | grep -q 'expect'; then
            sed -i '/name>disable-account<\/name>/a\    <expect>user<\/expect>' "$_OSSEC_LIVE"
            info "Added <expect>user</expect> to disable-account command in ossec.conf"
        fi

    fi

    # ── Agent configuration (shared/default/agent.conf) ──────────────────────
    if [[ -f "$CONFIG_SRC/agent_config/agent.conf" ]]; then
        _AGENT_DEST="/var/ossec/etc/shared/default/agent.conf"
        # Back up any existing agent.conf before overwriting
        if [[ -f "$_AGENT_DEST" ]]; then
            cp "$_AGENT_DEST" "${_AGENT_DEST}.backup-$(date +%Y%m%d-%H%M%S)"
            info "Existing agent.conf backed up"
        fi
        mkdir -p /var/ossec/etc/shared/default
        cp "$CONFIG_SRC/agent_config/agent.conf" "$_AGENT_DEST"
        chmod 660 "$_AGENT_DEST"
        chown root:wazuh "$_AGENT_DEST"
        success "agent.conf deployed to shared/default (pushed to enrolled agents via remoted)"
    else
        warn "agent_config/agent.conf not in CYSIEM-Config bundle — skipping"
    fi

    # ── Deploy cy360 resource monitoring scripts to Wazuh shared folder ──────────
    info "Deploying resource monitoring scripts to Wazuh shared config..."
    WAZUH_SHARED="/var/ossec/etc/shared/default"
    if [ -d "$WAZUH_SHARED" ]; then
        cp -f "$CONFIG_SRC/agent_config/cy360_resource_check.sh"  "$WAZUH_SHARED/cy360_resource_check.sh"
        cp -f "$CONFIG_SRC/agent_config/cy360_resource_check.ps1" "$WAZUH_SHARED/cy360_resource_check.ps1"
        chmod 755 "$WAZUH_SHARED/cy360_resource_check.sh"
        success "Resource monitoring scripts deployed to $WAZUH_SHARED"
    else
        warn "Wazuh shared dir not found at $WAZUH_SHARED — skipping resource script deploy"
    fi

    # ── 19.1 geoip2 Python library ────────────────────────────────────────────
    if ! python3 -c "import geoip2" 2>/dev/null; then
        info "Installing geoip2 Python library..."
        PIP_ROOT_USER_ACTION=ignore pip3 install geoip2 ${_PIP_BSP} -q \
            && success "geoip2 installed" \
            || warn "geoip2 install failed — GeoIP enrichment will be disabled"
    else
        success "geoip2 already installed"
    fi

    # ── 19.2 GeoLite2-City.mmdb download (always refreshed — MaxMind updates monthly) ──
    GEOIP_DIR="/opt/cycentra/geoip"
    mkdir -p "$GEOIP_DIR"
    GEOLITE_DB="$GEOIP_DIR/GeoLite2-City.mmdb"
    _MMKEY="$(grep "^MAXMIND_KEY=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2)"
    if [[ -n "$_MMKEY" ]]; then
        info "Downloading/refreshing GeoLite2-City.mmdb..."
        GEOURL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${_MMKEY}&suffix=tar.gz"
        TMP_GEO=$(mktemp /tmp/geolite2_XXXXXX.tar.gz)
        curl -sL "$GEOURL" -o "$TMP_GEO" \
            && tar -xzf "$TMP_GEO" -C "$GEOIP_DIR" --strip-components=1 --wildcards "*.mmdb" 2>/dev/null || true
        find "$GEOIP_DIR" -name "*.mmdb" ! -name "GeoLite2-City.mmdb" -exec mv {} "$GEOLITE_DB" \; 2>/dev/null || true
        rm -f "$TMP_GEO"
        if [[ -f "$GEOLITE_DB" ]]; then
            success "GeoLite2-City.mmdb downloaded/refreshed"
            # Install monthly cron to keep the DB current (MaxMind releases a new DB every month)
            cat > /etc/cron.monthly/cycentra-geoip-refresh << 'GEOCRON'
#!/bin/bash
# Refresh GeoLite2-City.mmdb — MaxMind releases an updated DB monthly.
MMKEY="$(grep "^MAXMIND_KEY=" /opt/cycentra/.env 2>/dev/null | cut -d= -f2)"
[[ -z "$MMKEY" ]] && exit 0
GEOIP_DIR="/opt/cycentra/geoip"
GEOLITE_DB="$GEOIP_DIR/GeoLite2-City.mmdb"
TMP=$(mktemp /tmp/geolite2_XXXXXX.tar.gz)
curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MMKEY}&suffix=tar.gz" -o "$TMP" \
    && tar -xzf "$TMP" -C "$GEOIP_DIR" --strip-components=1 --wildcards "*.mmdb" 2>/dev/null || true
find "$GEOIP_DIR" -name "*.mmdb" ! -name "GeoLite2-City.mmdb" -exec mv {} "$GEOLITE_DB" \; 2>/dev/null || true
rm -f "$TMP"
# Restart the correlation engine so it reloads the updated DB from disk
systemctl restart cycentra-siem 2>/dev/null || true
GEOCRON
            chmod +x /etc/cron.monthly/cycentra-geoip-refresh
            success "Monthly GeoIP refresh cron installed → /etc/cron.monthly/cycentra-geoip-refresh"
        else
            warn "GeoLite2 download failed — GeoIP enrichment disabled until next refresh"
        fi
    else
        warn "MAXMIND_KEY not set — GeoLite2 DB skipped (GeoIP enrichment disabled)"
    fi

    # ── MISP sync script deployment ───────────────────────────────────────────
    MISP_SYNC_SRC="$CONFIG_SRC/lists/sync_misp_cache.py"
    MISP_SYNC_DEST="/var/ossec/etc/lists/sync_misp_cache.py"
    MISP_CRON="/etc/cron.d/cycentra-misp-sync"
    if [[ -f "$MISP_SYNC_SRC" ]]; then
        cp "$MISP_SYNC_SRC" "$MISP_SYNC_DEST"
        chmod 750 "$MISP_SYNC_DEST"
        chown root:wazuh "$MISP_SYNC_DEST"
        success "sync_misp_cache.py deployed to $MISP_SYNC_DEST"
    else
        warn "sync_misp_cache.py not in CYSIEM-Config/lists — skipping MISP sync deploy"
    fi
    # Install hourly cron (idempotent — overwrites same file each run)
    if [[ -f "$MISP_SYNC_DEST" ]]; then
        cat > "$MISP_CRON" << 'MISPCRON'
# CyCentra 360 — MISP threat intel hourly sync
# Fetches IOCs from MISP and compiles the Wazuh CDB blacklist.
# Logs to /var/ossec/logs/misp_sync.log
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 * * * * root /var/ossec/framework/python/bin/python3 /var/ossec/etc/lists/sync_misp_cache.py >> /var/ossec/logs/misp_sync.log 2>&1
MISPCRON
        chmod 644 "$MISP_CRON"
        success "MISP sync cron installed → $MISP_CRON (runs every hour)"
    fi

    # ── CyEDR: stage Sysmon config for platform download endpoint ────────────
    # cycentra_sysmon_config.xml is now served by the Flask backend at:
    #   GET /api/edr/installer/sysmon-config
    # cyedr-install.ps1 downloads it from there during Windows endpoint enrollment.
    # We still stage it to /opt/cycentra/sysmon/ so the backend can serve it,
    # but operators no longer need to copy it manually — cyedr-install.ps1 handles that.
    _SYSMON_PKG="/opt/cycentra/sysmon"
    if [[ -f "$CONFIG_SRC/sysmon/cycentra_sysmon_config.xml" ]]; then
        mkdir -p "$_SYSMON_PKG"
        cp "$CONFIG_SRC/sysmon/cycentra_sysmon_config.xml" "$_SYSMON_PKG/"
        success "cycentra_sysmon_config.xml staged to $_SYSMON_PKG (served via /api/edr/installer/sysmon-config)"
    fi

    # Stage CyEDR installer scripts, agent, and YARA rules to the package directory
    # served by Flask at /api/edr/installer/{unix,win,agent-py,yara-rules}
    _EDR_PKG="/var/lib/cycentra-agent-packages/edr"
    mkdir -p "$_EDR_PKG"
    for _src in \
        "$_SCRIPT_DIR/scripts/cyedr-install.sh" \
        "$_SCRIPT_DIR/scripts/cyedr-install.ps1" \
        "$_SCRIPT_DIR/agent/cyedr_agent.py" \
        "$_SCRIPT_DIR/CYSIEM-Config/yara/cycentra.yar"; do
        if [[ -f "$_src" ]]; then
            cp "$_src" "$_EDR_PKG/"
            success "Staged $(basename "$_src") → $_EDR_PKG/"
        else
            warn "CyEDR file not found, skipping: $_src"
        fi
    done

    # ── Reload Wazuh after config/decoder/agent changes ───────────────────────
    /var/ossec/bin/wazuh-analysisd -t 2>/dev/null \
        && { systemctl reload wazuh-manager 2>/dev/null || systemctl restart wazuh-manager 2>/dev/null; \
             success "wazuh-manager reloaded with new rules/decoders/agent config"; } \
        || warn "Wazuh config validation failed — fix errors before reloading"

    info "Post-install manual steps:"
    info "  1. Edit /var/ossec/etc/ossec.conf — replace PLACEHOLDER_ values in cloud wodles,"
    info "     then change <disabled>yes</disabled> → <disabled>no</disabled>"
    info "  2. GeoIP DB is refreshed automatically every month (MAXMIND_KEY is pre-configured)"
    info "  3. Deploy CyEDR on endpoints (Sysmon/auditd/ULS now managed by CyEDR, not Wazuh):"
    info "       Linux/macOS: curl -fsSL https://<platform>/cyedr-install.sh | sudo bash -s -- --token <TOKEN> --platform <URL>"
    info "       Windows:     .\\cyedr-install.ps1 -Token <TOKEN> -Platform <URL>"
    info "       Add --with-cysiem to also install the Wazuh (CySIEM) agent on the same endpoint"
    info "  4. Audit policy for Domain Controllers: run scripts/cyedr-install.ps1 or"
    info "     copy /opt/cycentra/sysmon/apply_audit_policy.ps1 to the DC and run as Domain Admin"
    info "  5. Agent config: agent.conf is deployed automatically above (pushed to agents via remoted)"
    info "     To update agent.conf post-install: sudo bash scripts/deploy_agent_config.sh"

fi  # end Wazuh block

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

systemctl restart wazuh-dashboard.service 2>/dev/null || true

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

    # RBAC: install OOB default if not already present.
    # rbac.default.json ships in the bundle with cyadmin@cycentra.com (local auth).
    # Existing deployments retain their current rbac.json untouched.
    # Always deploy rbac.default.json as a permanent reference (Flask fallback when rbac.json is absent)
    if [[ -f "${BUNDLE_DIR}/rbac.default.json" ]]; then
        cp "${BUNDLE_DIR}/rbac.default.json" /opt/cycentra/rbac.default.json
        chmod 600 /opt/cycentra/rbac.default.json
    fi

    if [[ ! -f /opt/cycentra/rbac.json ]]; then
        if [[ -f "/opt/cycentra/rbac.default.json" ]]; then
            cp /opt/cycentra/rbac.default.json /opt/cycentra/rbac.json
            chmod 600 /opt/cycentra/rbac.json
            success "rbac.json installed from bundle default (cyadmin@cycentra.com / Admin@123)"
        else
            warn "rbac.default.json not found in bundle — creating empty rbac.json"
            echo '{}' > /opt/cycentra/rbac.json
            chmod 600 /opt/cycentra/rbac.json
        fi
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
  "cyasm_url":   "https://cyasm.${BASE_DOMAIN}",
  "generated":   "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
CFGJSON

    success "Portal config.json updated"

fi

# Ensure log directory and auth log exist with correct permissions
mkdir -p /var/log/cycentra && touch /var/log/cycentra/auth.log
chmod 644 /var/log/cycentra/auth.log

# ── Step 22b: Agent Package Repository ───────────────────────────────────────
# Downloads Wazuh agent packages and renames them to the cy360-agent-* scheme.
# Runs on both fresh installs and updates. Packages are stored at
# /var/lib/cycentra-agent-packages/ — directly accessible by NGINX (www-data, 755).
# Keeping packages outside /opt/cycentra/ (which is root-only 700) avoids NGINX 403.
step_header "AGENT PACKAGE REPOSITORY"

_AGENT_PKG_DIR="/var/lib/cycentra-agent-packages"
# Use brace grouping so tr|sed apply to cat output, not just the fallback echo.
# The naive  `cat ... || echo | tr | sed`  only processes the echo branch (bash || precedence).
_CY360_VER="$( { cat /opt/cycentra/version 2>/dev/null || echo "v1.0.0"; } | tr -d '[:space:]' | sed 's/^v//' )"
_WAZUH_VER="${WAZUH_VERSION:-4.14.5}"
_WAZUH_REL="${WAZUH_RELEASE:-1}"
_WAZUH_VR="${_WAZUH_VER}-${_WAZUH_REL}"

mkdir -p "$_AGENT_PKG_DIR"
chmod 755 "$_AGENT_PKG_DIR"
chown www-data:www-data "$_AGENT_PKG_DIR" 2>/dev/null || true

# Remove any broken symlink at /var/www/cycentra360/agent-packages (legacy approach)
[[ -L "/var/www/cycentra360/agent-packages" ]] && rm -f "/var/www/cycentra360/agent-packages" || true

# Migrate packages from old location (/opt/cycentra/agent-packages/) if they exist there.
# Also strips the v-prefix bug (e.g. cy360-agent-v1.0.37-arm64.pkg → cy360-agent-1.0.37-arm64.pkg).
if [[ -d "/opt/cycentra/agent-packages" ]]; then
    for _old_f in /opt/cycentra/agent-packages/cy360-agent-*; do
        [[ -f "$_old_f" ]] || continue
        _old_bn=$(basename "$_old_f")
        _new_bn="${_old_bn/cy360-agent-v/cy360-agent-}"  # strip v prefix if present
        mv "$_old_f" "${_AGENT_PKG_DIR}/${_new_bn}" 2>/dev/null && \
            info "Migrated: ${_old_bn} → ${_new_bn}" || true
    done
    rmdir /opt/cycentra/agent-packages 2>/dev/null || true
    success "Old agent-packages migrated to ${_AGENT_PKG_DIR}"
fi

# Remove any stale v-prefixed packages in the new location (from previous broken runs)
find "$_AGENT_PKG_DIR" -maxdepth 1 -name "cy360-agent-v*" -type f -delete 2>/dev/null || true

_dl_agent_pkg() {
    local url="$1" dest="$2"
    if [[ -f "$dest" ]]; then
        # Re-apply permissions in case the file was written by root previously
        chmod 644 "$dest"
        chown www-data:www-data "$dest" 2>/dev/null || true
        success "Agent pkg present: $(basename "$dest")"
        return 0
    fi

    # Rename an existing same-type package (different cy360 version, same Wazuh binary)
    # instead of re-downloading hundreds of MB on every cy360 version bump.
    # Checks three naming variants in order:
    #   1. Current standard:  cy360-agent-VERSION-arch.ext  (dash separator)
    #   2. Legacy dot naming: cy360-agent-VERSION.arch.ext  (packages placed pre-standardisation)
    #   3. Legacy underscore: cy360-agent-VERSION_arch.ext  (original Wazuh DEB convention)
    local _suffix="${dest#${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}}"
    local _old_pkg=""

    # 1. Dash naming (current)
    _old_pkg=$(find "$_AGENT_PKG_DIR" -maxdepth 1 \
        -name "cy360-agent-*${_suffix}" -type f 2>/dev/null | sort | tail -1 || true)

    # 2. Dot naming (legacy) — "-arm64.pkg" → "*.arm64.pkg"
    if [[ -z "$_old_pkg" && "${_suffix:0:1}" == "-" ]]; then
        _old_pkg=$(find "$_AGENT_PKG_DIR" -maxdepth 1 \
            -name "cy360-agent-*.${_suffix:1}" -type f 2>/dev/null | sort | tail -1 || true)
    fi

    # 3. Underscore naming (legacy DEB) — "-amd64.deb" → "*_amd64.deb"
    if [[ -z "$_old_pkg" && "${_suffix:0:1}" == "-" ]]; then
        _old_pkg=$(find "$_AGENT_PKG_DIR" -maxdepth 1 \
            -name "cy360-agent-*_${_suffix:1}" -type f 2>/dev/null | sort | tail -1 || true)
    fi

    if [[ -n "$_old_pkg" ]]; then
        mv "$_old_pkg" "$dest"
        chmod 644 "$dest"
        chown www-data:www-data "$dest" 2>/dev/null || true
        success "Renamed: $(basename "$_old_pkg") → $(basename "$dest")"
        return 0
    fi

    info "Downloading agent package: $(basename "$dest")"
    if curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 15 --max-time 300 \
            -o "${dest}.tmp" "$url" 2>/dev/null; then
        mv "${dest}.tmp" "$dest"
        chmod 644 "$dest"
        chown www-data:www-data "$dest" 2>/dev/null || true
        success "Downloaded: $(basename "$dest")"
    else
        warn "Could not download $(basename "$dest") — portal will show missing package"
        rm -f "${dest}.tmp" || true
    fi
}

# ── Seed from release bundle (avoids packages.wazuh.com dependency) ─────────
# deploy.yml bundles agent-packages/ into cycentra-release.tar.gz; setup.sh
# extracts to $BUNDLE_DIR.  Copy any bundled packages into the target dir now,
# renaming to the current cy360 version and normalising separator to dash.
_bundle_pkgs="${BUNDLE_DIR:-/tmp/cycentra-release}/agent-packages"
if [[ -d "$_bundle_pkgs" ]]; then
    _bundled=0
    for _bpkg in "${_bundle_pkgs}"/cy360-agent-*; do
        [[ -f "$_bpkg" ]] || continue
        _bn=$(basename "$_bpkg")
        if [[ "$_bn" =~ ^cy360-agent-[0-9]+\.[0-9]+\.[0-9]+(.*)$ ]]; then
            _sfx="${BASH_REMATCH[1]}"
            # Normalise separator: .arch.ext or _arch.ext → -arch.ext
            if [[ "$_sfx" =~ ^[._]([^.]+\.[^.]+)$ ]]; then
                _sfx="-${BASH_REMATCH[1]}"
            fi
            _dest="${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}${_sfx}"
            if [[ ! -f "$_dest" ]]; then
                cp "$_bpkg" "$_dest"
                chmod 644 "$_dest"
                chown www-data:www-data "$_dest" 2>/dev/null || true
                success "Bundle pkg installed: $_bn → $(basename "$_dest")"
                _bundled=$((_bundled+1))
            fi
        fi
    done
    [[ $_bundled -gt 0 ]] && success "Installed $_bundled agent package(s) from release bundle"
fi

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/yum/wazuh-agent-${_WAZUH_VR}.x86_64.rpm" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}-x86_64.rpm"

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/yum/wazuh-agent-${_WAZUH_VR}.aarch64.rpm" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}-aarch64.rpm"

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${_WAZUH_VR}_amd64.deb" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}-amd64.deb"

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${_WAZUH_VR}_arm64.deb" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}-aarch64.deb"

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/windows/wazuh-agent-${_WAZUH_VR}.msi" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}.msi"

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/macos/wazuh-agent-${_WAZUH_VR}.intel64.pkg" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}-intel64.pkg"

_dl_agent_pkg \
    "https://packages.wazuh.com/4.x/macos/wazuh-agent-${_WAZUH_VR}.arm64.pkg" \
    "${_AGENT_PKG_DIR}/cy360-agent-${_CY360_VER}-arm64.pkg"

_pkg_count=$(find "$_AGENT_PKG_DIR" -maxdepth 1 -name "cy360-agent-*" | wc -l)
success "Agent packages ready: ${_pkg_count}/7 at ${_AGENT_PKG_DIR}"

# ── Step 23: Cron jobs ────────────────────────────────────────────────────────
step_header "CRON JOBS"

# NOTE: All cron schedules (docker-maintenance, ASM wordlist, ASM scan) are
# now managed by the CyCentra 360 Scheduler tab in System Settings.
# The portal's /api/system/schedules endpoint writes cron entries directly.
# No cron jobs are auto-provisioned during setup any longer.
info "Cron schedule management delegated to System Settings → Scheduler tab"

# ── Step 23b: Firewall (UFW) ──────────────────────────────────────────────────
# Strategy: all public traffic flows through nginx (80/443).  Internal services
# (Flask 5252, SIEM engine 8100, PostgreSQL 5433, Redis 6379, Wazuh 5601,
# oauth2-proxy 4180, CySOAR 1880) bind to loopback only — no UFW
# rules needed for them.  CyMind on Server B reaches CyCentra via port 80
# (nginx proxy), so no extra firewall holes are required.
step_header "FIREWALL (UFW)"

command -v ufw >/dev/null 2>&1 || apt-get install -y -qq ufw 2>/dev/null

# Set defaults (idempotent)
ufw default deny incoming  >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true

# Allow public-facing ports
# NOTE: port 22 is opened temporarily here; Step 26 (SSH hardening) moves SSH
# to port 2026 and removes this rule at the very end of setup.
ufw allow 22/tcp   comment "SSH (temp — moved to 2026 by Step 26)" >/dev/null 2>&1 || true
ufw allow 80/tcp   comment "HTTP (nginx)"   >/dev/null 2>&1 || true
ufw allow 443/tcp  comment "HTTPS (nginx)"  >/dev/null 2>&1 || true
# Wazuh agent ports — cannot be proxied through nginx (binary protocol)
ufw allow 1514/tcp comment "Wazuh remoted (agent ↔ manager encrypted comms)" >/dev/null 2>&1 || true
ufw allow 1515/tcp comment "Wazuh authd (agent enrollment/registration)"      >/dev/null 2>&1 || true

# Remove any legacy rules that expose internal services directly
for _p in 5252 8100 5433 6379 5601 4180 4433 1880 11434 6333; do
    ufw delete allow ${_p}/tcp >/dev/null 2>&1 || true
    ufw delete allow ${_p}     >/dev/null 2>&1 || true
done

echo "y" | ufw enable >/dev/null 2>&1 || ufw --force enable >/dev/null 2>&1 || true
success "UFW: ports 22 (temp), 80, 443, 1514, 1515 open — all other ports blocked externally"
info    "Internal services (Flask 5252, engine 8100, Redis, PG) bind to loopback only"
info    "Wazuh agent ports 1514 (remoted) and 1515 (authd) open for external agent enrollment"
info    "SSH will be moved from port 22 → 2026 in Step 26 (last step)"

# ── Step 24: Health checks ────────────────────────────────────────────────────
step_header "HEALTH CHECKS"

chk() {
    local label=$1 url=$2
    local code
    code=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null) || code="000"
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
    chk "Portal"  "https://cy360.${BASE_DOMAIN}"
    chk "Backend" "https://cyasm.${BASE_DOMAIN}/health"
    chk "CySIEM"  "https://cysiem.${BASE_DOMAIN}"
fi

# ── Agent package distribution validation ─────────────────────────────────────
echo ""; info "── Agent package distribution ──"

# 1. Verify NGINX config includes the agent-packages location block
_NGINX_MOD_CHECK="/etc/nginx/sites-available/cycentra-modules"
if [[ -f "$_NGINX_MOD_CHECK" ]]; then
    if grep -q '/agent-packages/' "$_NGINX_MOD_CHECK" 2>/dev/null; then
        success "NGINX: /agent-packages/ location block present"
    else
        warn "NGINX: /agent-packages/ location block MISSING — run update to inject it"
        ERRORS+=("NGINX agent-packages block missing")
    fi

    # 2. nginx -t syntax check
    if nginx -t 2>/dev/null; then
        success "NGINX: config syntax OK"
    else
        warn "NGINX: config has syntax errors — run: nginx -t"
        ERRORS+=("NGINX config syntax error")
    fi
else
    warn "NGINX config not found at ${_NGINX_MOD_CHECK} — skipping NGINX validation"
fi

# 3. Verify agent packages directory and count
_APD="/var/lib/cycentra-agent-packages"
if [[ -d "$_APD" ]]; then
    _ap_count=$(find "$_APD" -maxdepth 1 -name "cy360-agent-*" -type f 2>/dev/null | wc -l)
    if [[ "$_ap_count" -ge 1 ]]; then
        success "Agent packages: ${_ap_count} package(s) present at ${_APD}"
    else
        warn "Agent packages: directory exists but no cy360-agent-* files found — run Step 22b"
        ERRORS+=("No agent packages found")
    fi
else
    warn "Agent packages directory not found: ${_APD}"
    ERRORS+=("Agent packages directory missing")
fi

# 4. Verify download URL reachable via HTTPS (only for full installs with SSL)
if [[ "$MODE" == "full" ]] && [[ -n "${BASE_DOMAIN:-}" ]]; then
    _first_pkg=$(find "$_APD" -maxdepth 1 -name "cy360-agent-*.rpm" -type f 2>/dev/null | head -1)
    if [[ -n "$_first_pkg" ]]; then
        _pkg_name=$(basename "$_first_pkg")
        _pkg_url="https://cy360.${BASE_DOMAIN}/agent-packages/${_pkg_name}"
        _http_code=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$_pkg_url" 2>/dev/null || echo "000")
        if [[ "$_http_code" == "200" ]]; then
            success "Agent package URL reachable: ${_pkg_url} → HTTP 200"
        else
            warn "Agent package URL returned HTTP ${_http_code}: ${_pkg_url}"
            warn "  Check: nginx is running, SSL cert is valid, and /agent-packages/ block is in place"
            ERRORS+=("Agent package URL not reachable (HTTP ${_http_code})")
        fi
    else
        info "No agent packages present yet — skipping URL reachability check"
    fi
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
    echo -e "  ${CYAN}Backend API    ${NC}  https://cyasm.${BASE_DOMAIN}"
    echo -e "  ${CYAN}CySIEM         ${NC}  https://cysiem.${BASE_DOMAIN}"
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
echo -e "  ${DIM}5. Install CySOAR or CyMISP via portal${NC}"
echo -e "  ${DIM}6. To update: sudo bash cycentra-setup.sh --update${NC}"
echo -e "  ${DIM}7. CyMind integration: install CyMind on Server B, then set CyMind URL in${NC}"
echo -e "  ${DIM}   System Settings → CyMind — nginx /cymind/ proxy is injected automatically${NC}"
echo -e "  ${DIM}   Or pass CYMIND_SERVER_IP=<ip> to this script to wire it up at install time${NC}"
echo -e "  ${DIM}8. SSH is now on port ${_SSH_PORT:-2026} — reconnect: ssh -p ${_SSH_PORT:-2026} user@<server>${NC}"
echo -e "  ${DIM}   Open port ${_SSH_PORT:-2026} in your Cloud Provider firewall/security group${NC}"
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
  Backend:  https://cyasm.${BASE_DOMAIN}
  CySIEM:   https://cysiem.${BASE_DOMAIN}
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
  5. Install CySOAR or CyMISP via portal
  6. Update: sudo bash cycentra-setup.sh --update
  7. SSH is on port ${_SSH_PORT:-2026} — reconnect: ssh -p ${_SSH_PORT:-2026} user@<server>
     Open port ${_SSH_PORT:-2026} in your Cloud Provider firewall before disconnecting.
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

# ── Step 26: SSH Hardening — runs last to avoid dropping current session ──────
step_header "SSH HARDENING"

_SSH_PORT="${SSH_PORT:-2026}"

# Check if already on the target port — skip if so
_current_ssh_port=$(ss -tlnp 2>/dev/null | grep -oP '(?<=:)\d+(?=\s)' | grep -E "^(22|${_SSH_PORT})$" | head -1 || echo "22")
if [[ "$_current_ssh_port" == "$_SSH_PORT" ]]; then
    success "SSH already on port ${_SSH_PORT} — skipping hardening"
else
    echo ""
    warn "Moving SSH from port 22 → ${_SSH_PORT}."
    warn "Your CURRENT session will remain active through the transition."
    warn "After this completes, reconnect on port ${_SSH_PORT}."
    warn "IMPORTANT: Also open port ${_SSH_PORT} in your Cloud Provider firewall/security group."
    echo ""

    # 1. Open new port in UFW BEFORE touching SSH (avoids any lockout window)
    ufw allow ${_SSH_PORT}/tcp comment "SSH (hardened)" >/dev/null 2>&1 || true
    ufw --force reload >/dev/null 2>&1 || true
    success "UFW: port ${_SSH_PORT} opened"

    # 2. Update /etc/ssh/sshd_config (handles commented, uncommented, and missing Port lines)
    if grep -qE "^#?Port 22$" /etc/ssh/sshd_config 2>/dev/null; then
        sed -i "s/^#*Port 22$/Port ${_SSH_PORT}/" /etc/ssh/sshd_config
    elif grep -q "^Port " /etc/ssh/sshd_config 2>/dev/null; then
        sed -i "s/^Port .*/Port ${_SSH_PORT}/" /etc/ssh/sshd_config
    else
        echo "Port ${_SSH_PORT}" >> /etc/ssh/sshd_config
    fi
    success "sshd_config updated → Port ${_SSH_PORT}"

    # 3. Ubuntu 24.04+ systemd socket activation override
    mkdir -p /etc/systemd/system/ssh.socket.d/
    cat > /etc/systemd/system/ssh.socket.d/listen.conf << SSHDEOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${_SSH_PORT}
ListenStream=[::]:${_SSH_PORT}
SSHDEOF
    success "ssh.socket.d/listen.conf written"

    # 4. Apply — daemon-reload first, then restart socket + service
    systemctl daemon-reload
    systemctl restart ssh.socket 2>/dev/null || true
    systemctl restart ssh        2>/dev/null || true
    sleep 2

    # 5. Verify SSH is now up on the new port before removing old rule
    if ss -tlnp 2>/dev/null | grep -q ":${_SSH_PORT} "; then
        # Remove old port 22 UFW rule now that SSH is confirmed on new port
        ufw delete allow 22/tcp >/dev/null 2>&1 || true
        ufw delete allow 22     >/dev/null 2>&1 || true
        ufw --force reload      >/dev/null 2>&1 || true
        success "SSH hardened — listening on port ${_SSH_PORT}, port 22 closed"
    else
        warn "SSH did not come up on port ${_SSH_PORT} — port 22 rule kept as fallback"
        warn "Check: systemctl status ssh && journalctl -u ssh -n 20"
        ERRORS+=("SSH hardening: port ${_SSH_PORT} not confirmed — manual check required")
    fi

    echo ""
    echo -e "  ${BOLD}${YELLOW}⚠  SSH CONNECTION NOTICE  ⚠${NC}"
    echo -e "  ${YELLOW}Reconnect using: ssh -p ${_SSH_PORT} user@<server>${NC}"
    echo -e "  ${YELLOW}Open port ${_SSH_PORT} in your Cloud Provider firewall/security group NOW.${NC}"
    echo ""
fi