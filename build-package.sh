#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CyCentra 360 — Installer Package Builder
# Compiles cycentra-setup.sh to a binary using SHC and bundles all required
# assets into a distributable installer archive.
#
# Output:
#   dist/cycentra-360-installer-<version>.tar.gz
#     ├── cycentra-setup          (binary — not human-readable)
#     ├── license_validator.py    (runtime validator — called daily by watchdog)
#     ├── cycentra.lic            (customer license — placed by vendor)
#     └── README-INSTALLER.txt
#
# Requirements:
#   - shc (brew install shc  /  apt install shc)
#   - openssl, gcc
#
# Usage:
#   bash build-package.sh [--license /path/to/customer.lic]
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_SH="$REPO_ROOT/cycentra-setup.sh"
VALIDATOR_PY="$REPO_ROOT/backend/core/license_validator.py"
DIST_DIR="$REPO_ROOT/dist"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}  ▸ ${NC}$*"; }
success() { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()    { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
error()   { echo -e "${RED}  ✗ ${NC}$*"; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────────────
LICENSE_FILE=""
for arg in "$@"; do
    case "$arg" in
        --license) shift; LICENSE_FILE="$1" ;;
        --license=*) LICENSE_FILE="${arg#*=}" ;;
    esac
done

# ── Preflight ─────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}  CyCentra 360 — Package Builder${NC}\n"

command -v shc  >/dev/null 2>&1 || error "shc not installed. Install with: brew install shc  /  apt install shc"
command -v gcc  >/dev/null 2>&1 || error "gcc not installed"
[[ -f "$SETUP_SH" ]]       || error "cycentra-setup.sh not found at $SETUP_SH"
[[ -f "$VALIDATOR_PY" ]]   || error "license_validator.py not found at $VALIDATOR_PY"

# Read version from line 3
VERSION=$(sed -n '3p' "$SETUP_SH" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[[ -z "$VERSION" ]] && VERSION="v1.0.0"
info "Building installer for version: $VERSION"

# ── Compile with SHC ──────────────────────────────────────────────────────────
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

cp "$SETUP_SH" "$BUILD_DIR/cycentra-setup.sh"
info "Compiling cycentra-setup.sh with SHC..."

# -r = allow running without expiry; -T = bypass timeout (Linux SHC only)
# Try with -T first (Linux), fall back to without -T (macOS homebrew SHC)
if ! shc -r -T -f "$BUILD_DIR/cycentra-setup.sh" -o "$BUILD_DIR/cycentra-setup" 2>/dev/null; then
    shc -r -f "$BUILD_DIR/cycentra-setup.sh" -o "$BUILD_DIR/cycentra-setup" 2>&1 || \
        error "SHC compilation failed"
fi

strip "$BUILD_DIR/cycentra-setup" 2>/dev/null || true
chmod +x "$BUILD_DIR/cycentra-setup"
success "Binary compiled: $(du -sh "$BUILD_DIR/cycentra-setup" | cut -f1)"

# ── Assemble package ──────────────────────────────────────────────────────────
PKG_DIR="$BUILD_DIR/package"
mkdir -p "$PKG_DIR"

cp "$BUILD_DIR/cycentra-setup"    "$PKG_DIR/cycentra-setup"
# The runtime validator must be in the tarball so setup.sh can deploy it to
# /opt/cycentra/license_validator.py (called daily by the license watchdog).
# Without this file the watchdog gets Python exit code 2 ("can't open file"),
# which it treats as "license expired", stopping all services every 24 h.
cp "$VALIDATOR_PY"               "$PKG_DIR/license_validator.py"
success "Runtime validator included: license_validator.py"

if [[ -n "$LICENSE_FILE" && -f "$LICENSE_FILE" ]]; then
    cp "$LICENSE_FILE" "$PKG_DIR/cycentra.lic"
    success "License file included: $LICENSE_FILE"
else
    warn "No license file specified — installer will run in demo mode"
    warn "To include a license: bash build-package.sh --license /path/to/customer.lic"
fi

# Write installer README
cat > "$PKG_DIR/README-INSTALLER.txt" << 'README'
CyCentra 360 Installer
======================

QUICK START
-----------
1. (Optional) Place your cycentra.lic in this directory.
   Without a license file, a 15-day demo is installed automatically.

2. Run the installer as root:
       sudo BASE_DOMAIN=your.domain.com ./cycentra-setup

Optional environment variables:
   BASE_DOMAIN      Your company's base domain (required)
   OAUTH_PROVIDER   google | microsoft | skip  (default: google)

After install:
   - Portal:      https://cysoc.YOUR_DOMAIN
   - Backend API: https://cyasm.YOUR_DOMAIN
   - Edit /opt/cycentra/.env to change any config
   - systemctl restart cycentra-backend to apply changes
   - Upload or renew your license from Portal → System Settings → License

Support: support@cycentra.com
README

# ── Create tarball ────────────────────────────────────────────────────────────
mkdir -p "$DIST_DIR"
ARCHIVE_NAME="cycentra-360-installer-${VERSION}.tar.gz"
ARCHIVE_PATH="$DIST_DIR/$ARCHIVE_NAME"

tar -czf "$ARCHIVE_PATH" -C "$PKG_DIR" .
success "Package created: $ARCHIVE_PATH"

# Also copy a standalone binary for single-file distribution
STANDALONE="$DIST_DIR/cycentra-setup-${VERSION}"
cp "$BUILD_DIR/cycentra-setup" "$STANDALONE"
chmod +x "$STANDALONE"
success "Standalone binary: $STANDALONE"

echo ""
echo -e "  ${BOLD}Tarball size    :${NC} $(du -sh "$ARCHIVE_PATH" | cut -f1)  ← for licensed customers"
echo -e "  ${BOLD}Binary size     :${NC} $(du -sh "$STANDALONE"   | cut -f1)  ← single-file distribution"
echo -e "  ${BOLD}Tarball contents:${NC}"
tar -tzf "$ARCHIVE_PATH" | sed 's/^/      /'
echo ""
echo -e "  ${CYAN}Customer flow (tarball with license):${NC}"
echo -e "  ${CYAN}  tar -xzf $(basename "$ARCHIVE_PATH") && sudo BASE_DOMAIN=example.com ./cycentra-setup${NC}"
echo ""
echo -e "  ${CYAN}Customer flow (single-file download):${NC}"
echo -e "  ${CYAN}  curl -LO <release-url>/cycentra-setup-${VERSION} && chmod +x cycentra-setup-${VERSION}${NC}"
echo -e "  ${CYAN}  sudo BASE_DOMAIN=example.com ./cycentra-setup-${VERSION}${NC}"
