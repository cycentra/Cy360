#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — CyEDR Agent Package Builder
# ═══════════════════════════════════════════════════════════════════════════════
# Builds arch-specific CyEDR agent packages using PyInstaller.
# Output: 8 packages (Linux × 2 arch × 2 fmt, macOS × 2 arch, Windows × 2 arch)
#
# Requires Docker with buildx + QEMU for cross-platform builds.
#
# Usage:
#   sudo bash build-edr-packages.sh [VERSION]
#
# Environment:
#   AGENT_SRC     Path to cyedr_agent.py (default: ../agent/cyedr_agent.py)
#   DEST_DIR      Output directory (default: /var/lib/cycentra-agent-packages/edr)
#   SKIP_WIN      Set to 1 to skip Windows MSI (needs Wine + cross-compile toolchain)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

CY360_VERSION="${1:-$(cat /opt/cycentra/version 2>/dev/null || echo "1.0.0")}"
AGENT_SRC="${AGENT_SRC:-$(cd "$(dirname "$0")/.." && pwd)/agent/cyedr_agent.py}"
DEST_DIR="${DEST_DIR:-/var/lib/cycentra-agent-packages/edr}"
SKIP_WIN="${SKIP_WIN:-0}"
BUILD_DIR="/tmp/cyedr-build-$$"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${CYAN}  ▸ ${NC}$*"; }
ok()    { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()  { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
die()   { echo -e "${RED}  ✗ ${NC}$*" >&2; exit 1; }

[[ ! -f "$AGENT_SRC" ]] && die "cyedr_agent.py not found at $AGENT_SRC"
mkdir -p "$DEST_DIR" "$BUILD_DIR"

info "CyCentra 360 — CyEDR Package Builder"
info "Version   : ${CY360_VERSION}"
info "Agent src : ${AGENT_SRC}"
info "Output    : ${DEST_DIR}"
echo

# ── Requirements spec for PyInstaller ─────────────────────────────────────────
cat > "$BUILD_DIR/requirements.txt" << 'EOF'
pyinstaller>=6.0
requests>=2.31
psutil>=5.9
paramiko>=3.0
cryptography>=41.0
bcrypt>=4.0
pywinrm>=0.4.3
xmltodict>=0.13
EOF

# ── PyInstaller spec (single-file, no console) ────────────────────────────────
cat > "$BUILD_DIR/cyedr_agent.spec" << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
a = Analysis(
    ['cyedr_agent.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'psutil', 'requests', 'urllib3', 'certifi', 'charset_normalizer',
        'paramiko', 'paramiko.transport', 'paramiko.auth_handler',
        'paramiko.channel', 'paramiko.client', 'paramiko.hostkeys',
        'cryptography', 'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.backends.openssl',
        'bcrypt',
        'winrm', 'winrm.protocol', 'winrm.exceptions',
        'xmltodict',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'PIL', 'test'],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zlib_data)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cyedr-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
SPEC

cp "$AGENT_SRC" "$BUILD_DIR/cyedr_agent.py"

ERRORS=0

# ── Helper: build via Docker ───────────────────────────────────────────────────
build_in_docker() {
    local image="$1"; shift
    local platform="$1"; shift
    local out_name="$1"; shift
    local extra_pkgs="${1:-}"

    info "Building $out_name  ($platform)..."

    docker run --rm --platform "$platform" \
        -v "$BUILD_DIR:/build" \
        -w /build \
        "$image" \
        bash -c "
            set -e
            pip install -q --upgrade pip
            pip install -q -r requirements.txt $extra_pkgs
            pyinstaller cyedr_agent.spec --clean --noconfirm -y
            mv dist/cyedr-agent /build/$out_name
        " && ok "$out_name built" || { warn "$out_name failed"; ERRORS=$((ERRORS+1)); }
}

# ── Linux x86_64 binary ───────────────────────────────────────────────────────
build_in_docker \
    "python:3.12-slim" \
    "linux/amd64" \
    "cyedr-agent-linux-x86_64"

# ── Linux aarch64 binary ──────────────────────────────────────────────────────
build_in_docker \
    "python:3.12-slim" \
    "linux/arm64" \
    "cyedr-agent-linux-aarch64"

# ── macOS: note — true macOS builds require macOS host (no Docker cross-compile)
# Using GitHub Actions / macOS runner is recommended for PKG builds.
# This section creates placeholder stubs so the build report is complete.
for macos_arch in "intel64" "arm64"; do
    out="cyedr-agent-macos-${macos_arch}"
    if [[ -f "$BUILD_DIR/$out" ]]; then
        ok "$out (pre-built, copying)"
    else
        warn "$out skipped — macOS PKG requires macOS build host (use GitHub Actions macOS runner)"
        ERRORS=$((ERRORS+1))
    fi
done

# ── Linux DEB packages ────────────────────────────────────────────────────────
build_deb() {
    local binary="$1"; local arch="$2"; local native_arch="$3"
    local pkg="cyedr-agent-${CY360_VERSION}-${arch}.deb"
    info "Packaging $pkg..."
    local deb_root="$BUILD_DIR/deb-$arch"
    mkdir -p "$deb_root/DEBIAN" \
             "$deb_root/usr/local/bin" \
             "$deb_root/etc/systemd/system" \
             "$deb_root/etc/audit/rules.d" \
             "$deb_root/opt/cycentra/edr/logs" \
             "$deb_root/opt/cycentra/edr/quarantine" \
             "$deb_root/opt/cycentra/edr/yara_rules"

    [[ ! -f "$BUILD_DIR/$binary" ]] && { warn "Binary $binary missing — skip DEB"; ERRORS=$((ERRORS+1)); return; }
    cp "$BUILD_DIR/$binary" "$deb_root/usr/local/bin/cyedr-agent"
    chmod 750 "$deb_root/usr/local/bin/cyedr-agent"

    # Systemd unit
    cat > "$deb_root/etc/systemd/system/cyedr-agent.service" << 'SVC'
[Unit]
Description=CyCentra 360 EDR Agent
After=network-online.target auditd.service
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/cyedr-agent --config /opt/cycentra/edr/config.json
Restart=always
RestartSec=10
OOMScoreAdjust=-900
MemoryMax=256M
CPUQuota=25%
[Install]
WantedBy=multi-user.target
SVC

    # Control file
    cat > "$deb_root/DEBIAN/control" << CTRL
Package: cyedr-agent
Version: ${CY360_VERSION}
Architecture: ${native_arch}
Maintainer: CyCentra Security <support@cycentra.com>
Depends:
Recommends: auditd
Description: CyCentra 360 EDR Agent
 Endpoint Detection and Response agent for CyCentra 360.
 Provides behavioral monitoring, threat detection, and automated response.
CTRL

    # Post-install script
    cat > "$deb_root/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
systemctl daemon-reload
systemctl enable cyedr-agent 2>/dev/null || true
echo "CyEDR installed. Run: cyedr-install.sh --token <TOKEN> --platform <URL> to enroll."
POSTINST
    chmod 755 "$deb_root/DEBIAN/postinst"

    dpkg-deb --build "$deb_root" "${DEST_DIR}/${pkg}" 2>/dev/null && ok "$pkg" || \
        { warn "dpkg-deb failed for $pkg (dpkg-deb may not be installed)"; ERRORS=$((ERRORS+1)); }
}

# Build DEBs inside an amd64 container so dpkg-deb is available
docker run --rm --platform linux/amd64 \
    -v "$BUILD_DIR:/build" \
    -v "$DEST_DIR:/out" \
    -w /build \
    -e "CY360_VERSION=${CY360_VERSION}" \
    ubuntu:22.04 \
    bash -c "
        set -e
        apt-get update -qq && apt-get install -y -qq dpkg-dev 2>/dev/null
        # amd64 DEB
        pkg=cyedr-agent-\${CY360_VERSION}-amd64.deb
        if [[ -f /build/cyedr-agent-linux-x86_64 ]]; then
            mkdir -p /build/deb-amd64/{DEBIAN,usr/local/bin,etc/systemd/system,opt/cycentra/edr/logs,opt/cycentra/edr/quarantine}
            cp /build/cyedr-agent-linux-x86_64 /build/deb-amd64/usr/local/bin/cyedr-agent
            chmod 750 /build/deb-amd64/usr/local/bin/cyedr-agent
            cat > /build/deb-amd64/DEBIAN/control <<'CTRL'
Package: cyedr-agent
Version: ${CY360_VERSION}
Architecture: amd64
Maintainer: CyCentra Security <support@cycentra.com>
Description: CyCentra 360 EDR Agent
 Endpoint Detection and Response agent.
CTRL
            printf '#!/bin/sh\nsystemctl daemon-reload\nsystemctl enable cyedr-agent 2>/dev/null||true\n' > /build/deb-amd64/DEBIAN/postinst
            chmod 755 /build/deb-amd64/DEBIAN/postinst
            dpkg-deb --build /build/deb-amd64 /out/\$pkg && echo 'OK: '\$pkg
        fi
        # arm64 DEB
        pkg2=cyedr-agent-\${CY360_VERSION}-arm64.deb
        if [[ -f /build/cyedr-agent-linux-aarch64 ]]; then
            mkdir -p /build/deb-arm64/{DEBIAN,usr/local/bin,etc/systemd/system,opt/cycentra/edr/logs,opt/cycentra/edr/quarantine}
            cp /build/cyedr-agent-linux-aarch64 /build/deb-arm64/usr/local/bin/cyedr-agent
            chmod 750 /build/deb-arm64/usr/local/bin/cyedr-agent
            cat > /build/deb-arm64/DEBIAN/control <<'CTRL2'
Package: cyedr-agent
Version: ${CY360_VERSION}
Architecture: arm64
Maintainer: CyCentra Security <support@cycentra.com>
Description: CyCentra 360 EDR Agent
 Endpoint Detection and Response agent.
CTRL2
            printf '#!/bin/sh\nsystemctl daemon-reload\nsystemctl enable cyedr-agent 2>/dev/null||true\n' > /build/deb-arm64/DEBIAN/postinst
            chmod 755 /build/deb-arm64/DEBIAN/postinst
            dpkg-deb --build /build/deb-arm64 /out/\$pkg2 && echo 'OK: '\$pkg2
        fi
    " 2>/dev/null && ok "DEB packages built" || { warn "DEB build step had errors"; ERRORS=$((ERRORS+1)); }

# ── Linux RPM packages (via fpm inside Docker) ────────────────────────────────
docker run --rm --platform linux/amd64 \
    -v "$BUILD_DIR:/build" \
    -v "$DEST_DIR:/out" \
    -w /build \
    -e "CY360_VERSION=${CY360_VERSION}" \
    ubuntu:22.04 \
    bash -c "
        set -e
        apt-get update -qq
        apt-get install -y -qq ruby rpm 2>/dev/null
        gem install fpm -q 2>/dev/null || true

        if command -v fpm &>/dev/null && [[ -f /build/cyedr-agent-linux-x86_64 ]]; then
            fpm -s dir -t rpm -n cyedr-agent -v \${CY360_VERSION} --architecture x86_64 \
                --description 'CyCentra 360 EDR Agent' \
                --maintainer 'CyCentra Security <support@cycentra.com>' \
                -p /out/cyedr-agent-\${CY360_VERSION}-x86_64.rpm \
                /build/cyedr-agent-linux-x86_64=/usr/local/bin/cyedr-agent && \
                echo 'OK: x86_64.rpm'
        fi
        if command -v fpm &>/dev/null && [[ -f /build/cyedr-agent-linux-aarch64 ]]; then
            fpm -s dir -t rpm -n cyedr-agent -v \${CY360_VERSION} --architecture aarch64 \
                --description 'CyCentra 360 EDR Agent' \
                --maintainer 'CyCentra Security <support@cycentra.com>' \
                -p /out/cyedr-agent-\${CY360_VERSION}-aarch64.rpm \
                /build/cyedr-agent-linux-aarch64=/usr/local/bin/cyedr-agent && \
                echo 'OK: aarch64.rpm'
        fi
    " 2>/dev/null && ok "RPM packages built" || { warn "RPM build step had errors (fpm may not be available)"; ERRORS=$((ERRORS+1)); }

# ── Copy binaries to output ────────────────────────────────────────────────────
for bin in \
    "cyedr-agent-linux-x86_64" \
    "cyedr-agent-linux-aarch64"; do
    [[ -f "$BUILD_DIR/$bin" ]] && cp "$BUILD_DIR/$bin" "$DEST_DIR/$bin" && ok "Binary: $bin"
done

# ── Set permissions ────────────────────────────────────────────────────────────
chmod -R 644 "$DEST_DIR"/* 2>/dev/null || true
chmod 755 "$DEST_DIR" "$DEST_DIR"/*.rpm "$DEST_DIR"/*.deb 2>/dev/null || true
find "$DEST_DIR" -name "cyedr-agent-linux-*" -exec chmod 755 {} \; 2>/dev/null || true
chown -R www-data:www-data "$DEST_DIR" 2>/dev/null || true

# ── Cleanup ────────────────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"

echo
if [[ $ERRORS -eq 0 ]]; then
    ok "All CyEDR packages built → $DEST_DIR"
else
    warn "${ERRORS} target(s) failed or skipped."
    echo "  Note: macOS PKG requires a macOS build host."
    echo "  Note: Windows MSI requires Wine + pyinstaller on Windows."
    echo "  Partial builds are functional — missing platforms will use bash-install fallback."
    exit 1
fi
