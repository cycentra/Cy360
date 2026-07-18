#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — CyEDR Package Staging Check
# ═══════════════════════════════════════════════════════════════════════════════
# Verifies CyEDR agent binaries (built by build-edr-packages.sh) are staged and
# copies YARA rules + Sysmon config assets into place.
# Packages are stored at /var/lib/cycentra-agent-packages/edr/ (www-data, 755)
# and served over HTTPS via NGINX alias from cy360.DOMAIN/edr-packages/.
#
# Usage:
#   sudo bash download-packages.sh [VERSION]
#
# Example:
#   sudo bash download-packages.sh 1.0.31
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

CY360_VERSION="${1:-$(cat /opt/cycentra/version 2>/dev/null || echo "1.0.0")}"
DEST_DIR="${DEST_DIR:-/var/lib/cycentra-agent-packages}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${CYAN}  ▸ ${NC}$*"; }
ok()      { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()    { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
fail()    { echo -e "${RED}  ✗ ${NC}$*"; }

mkdir -p "$DEST_DIR"
cd "$DEST_DIR"

CV="${CY360_VERSION}"

info "CyCentra 360 CyEDR Package Staging Check"
info "Cy360 version : ${CV}"
info "Destination   : ${DEST_DIR}"
echo

ERRORS=0

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

# Note: cyedr-install.sh, cyedr_agent.py, and cycentra.yar are staged automatically
# by cycentra-setup.sh on every install/update run. Run download-packages.sh only
# when you need to re-stage CyEDR assets independently.

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
