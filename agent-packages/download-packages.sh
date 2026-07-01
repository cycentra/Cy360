#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — Agent Package Downloader
# ═══════════════════════════════════════════════════════════════════════════════
# Downloads the matching Wazuh agent packages and renames them to the
# cy360-agent-VERSION-ARCH.EXT naming scheme.
#
# Called by cycentra-setup.sh during fresh install and upgrades.
# Packages are stored at /var/lib/cycentra-agent-packages/ (www-data, 755) and
# served over HTTPS via NGINX alias from cy360.DOMAIN/agent-packages/.
#
# Usage:
#   sudo bash download-packages.sh [VERSION]
#
# Example:
#   sudo bash download-packages.sh 1.0.31
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.5}"
WAZUH_RELEASE="${WAZUH_RELEASE:-1}"
CY360_VERSION="${1:-$(cat /opt/cycentra/version 2>/dev/null || echo "1.0.0")}"
DEST_DIR="${DEST_DIR:-/var/lib/cycentra-agent-packages}"
WAZUH_BASE_RPM="https://packages.wazuh.com/4.x/yum"
WAZUH_BASE_DEB="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent"
WAZUH_BASE_WIN="https://packages.wazuh.com/4.x/windows"
WAZUH_BASE_MAC="https://packages.wazuh.com/4.x/macos"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${CYAN}  ▸ ${NC}$*"; }
ok()      { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()    { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
fail()    { echo -e "${RED}  ✗ ${NC}$*"; }

mkdir -p "$DEST_DIR"
cd "$DEST_DIR"

download_pkg() {
    local url="$1"
    local dest="$2"
    if [[ -f "$dest" ]]; then
        ok "Already present: $dest"
        return 0
    fi
    info "Downloading: $(basename "$url") → $dest"
    if curl -fsSL --retry 3 --retry-delay 5 -o "${dest}.tmp" "$url"; then
        mv "${dest}.tmp" "$dest"
        ok "$dest"
    else
        fail "Failed to download: $url"
        rm -f "${dest}.tmp" || true
        return 1
    fi
}

WV="${WAZUH_VERSION}-${WAZUH_RELEASE}"
CV="${CY360_VERSION}"

info "CyCentra 360 Agent Package Downloader"
info "Wazuh version : ${WAZUH_VERSION}-${WAZUH_RELEASE}"
info "Cy360 version : ${CV}"
info "Destination   : ${DEST_DIR}"
echo

ERRORS=0

# ── Linux RPM x86_64 ──────────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_RPM}/wazuh-agent-${WV}.x86_64.rpm" \
    "cy360-agent-${CV}-x86_64.rpm" || ERRORS=$((ERRORS+1))

# ── Linux RPM aarch64 ─────────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_RPM}/wazuh-agent-${WV}.aarch64.rpm" \
    "cy360-agent-${CV}-aarch64.rpm" || ERRORS=$((ERRORS+1))

# ── Linux DEB amd64 ───────────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_DEB}/wazuh-agent_${WV}_amd64.deb" \
    "cy360-agent-${CV}-amd64.deb" || ERRORS=$((ERRORS+1))

# ── Linux DEB aarch64 ─────────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_DEB}/wazuh-agent_${WV}_arm64.deb" \
    "cy360-agent-${CV}-aarch64.deb" || ERRORS=$((ERRORS+1))

# ── Windows MSI ───────────────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_WIN}/wazuh-agent-${WV}.msi" \
    "cy360-agent-${CV}.msi" || ERRORS=$((ERRORS+1))

# ── macOS Intel ───────────────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_MAC}/wazuh-agent-${WV}.intel64.pkg" \
    "cy360-agent-${CV}-intel64.pkg" || ERRORS=$((ERRORS+1))

# ── macOS Apple Silicon ───────────────────────────────────────────────────────
download_pkg \
    "${WAZUH_BASE_MAC}/wazuh-agent-${WV}.arm64.pkg" \
    "cy360-agent-${CV}-arm64.pkg" || ERRORS=$((ERRORS+1))

# ── Set Wazuh package permissions ─────────────────────────────────────────────
chmod 644 "${DEST_DIR}/cy360-agent-${CV}"* 2>/dev/null || true
chown www-data:www-data "${DEST_DIR}" 2>/dev/null || true
chown www-data:www-data "${DEST_DIR}/cy360-agent-${CV}"* 2>/dev/null || true

echo
if [[ $ERRORS -eq 0 ]]; then
    ok "All Wazuh agent packages downloaded successfully → ${DEST_DIR}"
else
    warn "${ERRORS} Wazuh package(s) failed. Check connectivity to packages.wazuh.com"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# CyEDR Agent Packages
# Built by agent-packages/build-edr-packages.sh and staged here.
# Naming scheme: cyedr-agent-VERSION-ARCH.EXT
# ═══════════════════════════════════════════════════════════════════════════════
EDR_DEST_DIR="${DEST_DIR}/edr"
mkdir -p "$EDR_DEST_DIR"

info ""
info "CyEDR package staging check"
info "EDR packages dir: ${EDR_DEST_DIR}"

EDR_ERRORS=0
EDR_PRESENT=0

# Expected CyEDR package filenames for this version
declare -a EDR_PACKAGES=(
    "cyedr-agent-linux-x86_64"
    "cyedr-agent-linux-aarch64"
    "cyedr-agent-macos-intel64"
    "cyedr-agent-macos-arm64"
    "cyedr-agent-${CV}-amd64.deb"
    "cyedr-agent-${CV}-arm64.deb"
    "cyedr-agent-${CV}-x86_64.rpm"
    "cyedr-agent-${CV}-aarch64.rpm"
    "cyedr-agent-${CV}-intel64.pkg"
    "cyedr-agent-${CV}-arm64.pkg"
    "cyedr-agent-${CV}-x64.msi"
    "cyedr-agent-${CV}-arm64.msi"
)

for pkg in "${EDR_PACKAGES[@]}"; do
    if [[ -f "${EDR_DEST_DIR}/${pkg}" ]]; then
        ok "Present: $pkg"
        EDR_PRESENT=$((EDR_PRESENT+1))
    else
        warn "Missing: $pkg  (run agent-packages/build-edr-packages.sh to build)"
        EDR_ERRORS=$((EDR_ERRORS+1))
    fi
done

# Copy YARA rules + Sysmon assets if present in source tree
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for asset in \
    "${REPO_ROOT}/CYSIEM-Config/sysmon/cycentra_sysmon_config.xml" \
    "${REPO_ROOT}/CYSIEM-Config/yara/cycentra.yar"; do
    if [[ -f "$asset" ]]; then
        cp -f "$asset" "${EDR_DEST_DIR}/"
        ok "Staged: $(basename "$asset")"
    fi
done

# Stage CySIEM install script (used by --with-cysiem flag)
if [[ -f "${REPO_ROOT}/scripts/agent-installer.sh" ]]; then
    cp -f "${REPO_ROOT}/scripts/agent-installer.sh" "${EDR_DEST_DIR}/cysiem-install.sh"
    chmod 644 "${EDR_DEST_DIR}/cysiem-install.sh"
    ok "Staged: cysiem-install.sh"
fi

# Note: cyedr-install.sh, cyedr_agent.py, and cycentra.yar are staged automatically
# by cycentra-setup.sh on every install/update run. Run download-packages.sh only
# when you need to re-stage Wazuh packages or CySIEM assets independently.

chmod -R 644 "${EDR_DEST_DIR}"/* 2>/dev/null || true
chmod 755 "${EDR_DEST_DIR}"
chown -R www-data:www-data "${EDR_DEST_DIR}" 2>/dev/null || true

echo
if [[ $EDR_ERRORS -gt 0 ]]; then
    warn "${EDR_ERRORS} CyEDR package(s) missing — run: sudo bash agent-packages/build-edr-packages.sh ${CV}"
else
    ok "All ${EDR_PRESENT} CyEDR packages present → ${EDR_DEST_DIR}"
fi

echo
[[ $ERRORS -gt 0 ]] && exit 1
exit 0
