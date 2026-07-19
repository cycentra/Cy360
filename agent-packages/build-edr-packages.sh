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
#   TRAY_SRC      Path to cyedr_tray.py (default: ../agent/cyedr_tray.py)
#   DEST_DIR      Output directory (default: /var/lib/cycentra-agent-packages/edr)
#   SKIP_WIN      Set to 1 to skip Windows MSI (needs Wine + cross-compile toolchain)
#   SKIP_TRAY     Set to 1 to skip building the system-tray binaries
#   SKIP_DEB_RPM  Set to 1 to skip DEB/RPM packaging — no installer script consumes
#                 these today (cyedr-install.sh/.ps1 only ever download the raw
#                 binaries via /api/edr/installer/agent-bundle|tray-bundle). Used
#                 by CI (.github/workflows/deploy.yml) to build just the binaries
#                 every release needs, fast, without dpkg-deb/fpm dependencies.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

CY360_VERSION="${1:-$(cat /opt/cycentra/version 2>/dev/null || echo "1.0.0")}"
AGENT_SRC="${AGENT_SRC:-$(cd "$(dirname "$0")/.." && pwd)/agent/cyedr_agent.py}"
TRAY_SRC="${TRAY_SRC:-$(cd "$(dirname "$0")/.." && pwd)/agent/cyedr_tray.py}"
DEST_DIR="${DEST_DIR:-/var/lib/cycentra-agent-packages/edr}"
SKIP_WIN="${SKIP_WIN:-0}"
SKIP_TRAY="${SKIP_TRAY:-0}"
BUILD_DIR="/tmp/cyedr-build-$$"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${CYAN}  ▸ ${NC}$*"; }
ok()    { echo -e "${GREEN}  ✓ ${NC}$*"; }
warn()  { echo -e "${YELLOW}  ⚠ ${NC}$*"; }
die()   { echo -e "${RED}  ✗ ${NC}$*" >&2; exit 1; }

[[ ! -f "$AGENT_SRC" ]] && die "cyedr_agent.py not found at $AGENT_SRC"
mkdir -p "$DEST_DIR" "$BUILD_DIR"

# macOS agent/tray binaries cannot be produced by Docker cross-compilation
# (PyInstaller bundles native Mach-O + the target OS's own Python — there is
# no cross-compiler for that). They can only be built by running this script
# ON a Mac. When that's the case, HOST_MAC_ARCH_LABEL builds just the host's
# own arch natively below; the other mac arch still needs its own Mac host.
HOST_OS="$(uname -s)"
HOST_MAC_ARCH_LABEL=""
if [[ "$HOST_OS" == "Darwin" ]]; then
    case "$(uname -m)" in
        arm64)  HOST_MAC_ARCH_LABEL="arm64" ;;
        x86_64) HOST_MAC_ARCH_LABEL="intel64" ;;
    esac
fi

info "CyCentra 360 — CyEDR Package Builder"
info "Version   : ${CY360_VERSION}"
info "Agent src : ${AGENT_SRC}"
info "Output    : ${DEST_DIR}"
[[ -n "$HOST_MAC_ARCH_LABEL" ]] && info "Host      : macOS/${HOST_MAC_ARCH_LABEL} — will build native macOS agent+tray binaries for this arch"
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
watchdog>=4.0
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
        'watchdog', 'watchdog.observers', 'watchdog.events',
        'watchdog.observers.inotify', 'watchdog.observers.fsevents',
        'watchdog.observers.read_directory_changes', 'watchdog.observers.winapi',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'scipy', 'PIL', 'test'],
    noarchive=False,
)
pyz = PYZ(a.pure)
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
            apt-get update -qq && apt-get install -y -qq --no-install-recommends binutils 2>/dev/null || true
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

# ── macOS: no Docker cross-compile is possible (PyInstaller bundles a native
# Mach-O binary + the host's own Python) — this only produces a real binary
# when the script itself is run on a Mac, and only for that Mac's own arch.
# GitHub Actions macOS runners would be the other option; none exist in this
# repo's CI today (removed).
if [[ -n "$HOST_MAC_ARCH_LABEL" ]]; then
    out="cyedr-agent-macos-${HOST_MAC_ARCH_LABEL}"
    info "Building $out  (native macOS build)..."
    (
        cd "$BUILD_DIR"
        python3 -m venv .venv-agent-macos
        source .venv-agent-macos/bin/activate
        pip install -q --upgrade pip
        pip install -q -r requirements.txt
        pyinstaller cyedr_agent.spec --clean --noconfirm -y \
            --distpath "$BUILD_DIR/dist-agent-macos" --workpath "$BUILD_DIR/work-agent-macos"
        deactivate
    ) && mv "$BUILD_DIR/dist-agent-macos/cyedr-agent" "$BUILD_DIR/$out" \
      && ok "$out built" || { warn "$out failed — see PyInstaller output above"; ERRORS=$((ERRORS+1)); }
fi
for macos_arch in "intel64" "arm64"; do
    out="cyedr-agent-macos-${macos_arch}"
    if [[ -f "$BUILD_DIR/$out" ]]; then
        ok "$out (built, copying)"
    else
        warn "$out skipped — macOS binaries require running this script on an actual macOS/${macos_arch} host (no Docker cross-compile for native Mach-O). Build it there, then copy the resulting file into ${DEST_DIR}/ on the platform server."
        ERRORS=$((ERRORS+1))
    fi
done

# ═══════════════════════════════════════════════════════════════════════════════
# CyEDR System Tray — separate binary from cyedr-agent above on purpose.
# The agent runs as a privileged headless service (root/SYSTEM); the tray is
# per-user/unprivileged and needs pystray+Pillow (Windows/Linux) or rumps
# (macOS) — none of those belong in the headless service binary, so they get
# their own PyInstaller spec and their own dependency set.
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_TRAY" != "1" ]]; then
    [[ ! -f "$TRAY_SRC" ]] && die "cyedr_tray.py not found at $TRAY_SRC (set TRAY_SRC or SKIP_TRAY=1)"
    cp "$TRAY_SRC" "$BUILD_DIR/cyedr_tray.py"

    cat > "$BUILD_DIR/requirements-tray.txt" << 'EOF'
pyinstaller>=6.0
pystray>=0.19
Pillow>=10.0
EOF

    # macOS uses rumps (cyedr_tray.py's run_rumps(), see OS_TYPE=="DARWIN"
    # branch), NOT pystray — pystray has no usable macOS menu-bar backend.
    # This requirements/spec pair was previously missing entirely: even
    # running this script by hand on a Mac per the old warning's own advice
    # would have failed, since nothing here ever declared or bundled rumps.
    cat > "$BUILD_DIR/requirements-tray-macos.txt" << 'EOF'
pyinstaller>=6.0
rumps>=0.4.0
EOF

    cat > "$BUILD_DIR/cyedr_tray_macos.spec" << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
a = Analysis(
    ['cyedr_tray.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['rumps'],
    hookspath=[],
    runtime_hooks=[],
    excludes=['pystray', 'PIL', 'matplotlib', 'numpy', 'scipy', 'test'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cyedr-tray',
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

    cat > "$BUILD_DIR/cyedr_tray.spec" << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
a = Analysis(
    ['cyedr_tray.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'pystray', 'pystray._base', 'PIL', 'PIL.Image', 'PIL.ImageDraw',
        'tkinter', 'tkinter.simpledialog',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'scipy', 'test'],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cyedr-tray',
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

    # ── Helper: build the tray via Docker, with GTK/AppIndicator for pystray's
    # Linux backend (not present in the slim python image the agent build uses —
    # a tray icon needs a desktop toolkit, the headless agent does not).
    build_tray_in_docker() {
        local platform="$1"; shift
        local out_name="$1"; shift

        info "Building $out_name  ($platform)..."
        docker run --rm --platform "$platform" \
            -v "$BUILD_DIR:/build" \
            -w /build \
            "python:3.12-slim" \
            bash -c "
                set -e
                apt-get update -qq
                # binutils is REQUIRED (pyinstaller needs objdump) — installed on
                # its own so a missing/renamed GTK package below can never take
                # it down too (a single apt-get install with one bad package name
                # fails the whole command, and that used to be silently masked by
                # a single '|| true' covering everything, including binutils).
                apt-get install -y -qq --no-install-recommends binutils gcc python3-dev tk-dev
                # GTK/AppIndicator are best-effort — package names vary across
                # Debian/Ubuntu base image versions; pystray can still be
                # analysed/bundled by PyInstaller without them (they're only
                # needed at runtime on a real Linux desktop), so a failure here
                # must not block the build.
                apt-get install -y -qq --no-install-recommends \
                    libgtk-3-dev gir1.2-appindicator3-0.1 python3-gi python3-gi-cairo \
                    2>/dev/null || echo 'WARN: GTK/AppIndicator packages unavailable on this base image — pystray will still bundle, but verify tray runtime on a real Linux desktop'
                pip install -q --upgrade pip
                pip install -q -r requirements-tray.txt
                pyinstaller cyedr_tray.spec --clean --noconfirm -y
                mv dist/cyedr-tray /build/$out_name
            " && ok "$out_name built" || { warn "$out_name failed — Linux tray needs a desktop toolkit (GTK/AppIndicator), verify on a real desktop build host if this fails"; ERRORS=$((ERRORS+1)); }
    }

    build_tray_in_docker "linux/amd64" "cyedr-tray-linux-x86_64"
    build_tray_in_docker "linux/arm64" "cyedr-tray-linux-aarch64"

    # macOS tray (rumps) requires a native macOS build host, same limitation
    # as the agent binary above — no Docker cross-compile for a GUI toolkit.
    if [[ -n "$HOST_MAC_ARCH_LABEL" ]]; then
        out="cyedr-tray-macos-${HOST_MAC_ARCH_LABEL}"
        info "Building $out  (native macOS build, rumps)..."
        (
            cd "$BUILD_DIR"
            python3 -m venv .venv-tray-macos
            source .venv-tray-macos/bin/activate
            pip install -q --upgrade pip
            pip install -q -r requirements-tray-macos.txt
            pyinstaller cyedr_tray_macos.spec --clean --noconfirm -y \
                --distpath "$BUILD_DIR/dist-tray-macos" --workpath "$BUILD_DIR/work-tray-macos"
            deactivate
        ) && mv "$BUILD_DIR/dist-tray-macos/cyedr-tray" "$BUILD_DIR/$out" \
          && ok "$out built" || { warn "$out failed — see PyInstaller output above"; ERRORS=$((ERRORS+1)); }
    fi
    for macos_arch in "intel64" "arm64"; do
        out="cyedr-tray-macos-${macos_arch}"
        if [[ -f "$BUILD_DIR/$out" ]]; then
            ok "$out (built, copying)"
        else
            warn "$out skipped — macOS/${macos_arch} tray binary requires running this script on an actual macOS/${macos_arch} host (needs rumps, no Docker cross-compile). Build it there, then copy the resulting file into ${DEST_DIR}/ on the platform server."
            ERRORS=$((ERRORS+1))
        fi
    done
    for win_arch in "x64" "arm64"; do
        out="cyedr-tray-windows-${win_arch}.exe"
        if [[ -f "$BUILD_DIR/$out" ]]; then
            ok "$out (pre-built, copying)"
        else
            warn "$out skipped — Windows tray requires a Windows build host (use GitHub Actions windows runner)"
            ERRORS=$((ERRORS+1))
        fi
    done

    for bin in "cyedr-tray-linux-x86_64" "cyedr-tray-linux-aarch64" \
               "cyedr-tray-macos-intel64" "cyedr-tray-macos-arm64" \
               "cyedr-tray-windows-x64.exe" "cyedr-tray-windows-arm64.exe"; do
        [[ -f "$BUILD_DIR/$bin" ]] && cp "$BUILD_DIR/$bin" "$DEST_DIR/$bin" && ok "Binary: $bin"
    done
else
    warn "SKIP_TRAY=1 — system-tray binaries not built"
fi

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

if [[ "${SKIP_DEB_RPM:-0}" == "1" ]]; then
    warn "SKIP_DEB_RPM=1 — DEB/RPM packaging skipped (not consumed by any install path; CI uses this to build only the raw agent/tray binaries the installer scripts actually download)"
else

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

fi   # SKIP_DEB_RPM

# ── Copy binaries to output ────────────────────────────────────────────────────
# NOTE: macOS agent binaries used to never exist (placeholder-only build
# above), so their absence here was invisible. Now that a native macOS host
# actually produces cyedr-agent-macos-<arch>, it must be copied out too, or
# a real build silently never reaches DEST_DIR/the installer.
for bin in \
    "cyedr-agent-linux-x86_64" \
    "cyedr-agent-linux-aarch64" \
    "cyedr-agent-macos-intel64" \
    "cyedr-agent-macos-arm64"; do
    [[ -f "$BUILD_DIR/$bin" ]] && cp "$BUILD_DIR/$bin" "$DEST_DIR/$bin" && ok "Binary: $bin"
done

# ── Set permissions ────────────────────────────────────────────────────────────
chmod -R 644 "$DEST_DIR"/* 2>/dev/null || true
chmod 755 "$DEST_DIR" "$DEST_DIR"/*.rpm "$DEST_DIR"/*.deb 2>/dev/null || true
find "$DEST_DIR" -name "cyedr-agent-linux-*" -exec chmod 755 {} \; 2>/dev/null || true
find "$DEST_DIR" -name "cyedr-agent-macos-*" -exec chmod 755 {} \; 2>/dev/null || true
find "$DEST_DIR" -name "cyedr-tray-*" -exec chmod 755 {} \; 2>/dev/null || true
# Only reassign ownership when DEST_DIR is the real production staging path
# (nginx/Flask read these directly as www-data there). Skip it for any other
# DEST_DIR (CI scratch directories, manual local builds, etc.) — chowning
# away from whoever is currently running this script silently breaks every
# later step/process that needs to read or overwrite files here afterward
# without root, e.g. re-running this script, or (in CI) the workflow step
# right after this one that needs to write more files into the same dir.
if [[ "$DEST_DIR" == "/var/lib/cycentra-agent-packages/edr" ]]; then
    chown -R www-data:www-data "$DEST_DIR" 2>/dev/null || true
fi

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
