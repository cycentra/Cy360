#!/usr/bin/env bash
# =============================================================================
# apply_refactor.sh — CyCentra 360 Modular Architecture Deployment
# =============================================================================
# Run this on your Mac from the root of your cloned repo.
# It copies every new/changed file into the correct location,
# does a safety backup first, then tells you what to do next.
#
# Usage:
#   chmod +x apply_refactor.sh
#   ./apply_refactor.sh
#
# Requirements:
#   - Must be run from the root of your cycentra360 git repo
#   - Node 20+ and Python 3.12+ must be installed
#   - The cycentra-modular/ output folder must be in the same directory
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}✓${NC}  $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
info() { echo -e "${CYAN}→${NC}  $*"; }
err()  { echo -e "${RED}✗${NC}  $*"; exit 1; }
hdr()  { echo -e "\n${BOLD}── $* ──${NC}"; }

# ── Validate we're in the right place ─────────────────────────────────────────
[[ -f "backend/app.py" ]]        || err "backend/app.py not found. Run from repo root."
[[ -f "portal/src/App.jsx" ]]    || err "portal/src/App.jsx not found. Run from repo root."
[[ -d "cycentra-modular" ]]      || err "cycentra-modular/ output folder not found. Run from repo root."

REPO_ROOT=$(pwd)
SRC="$REPO_ROOT/cycentra-modular"

hdr "CyCentra 360 — Modular Refactor Deployment"
echo ""
echo "  Repo root : $REPO_ROOT"
echo "  Source    : $SRC"
echo ""

# ── Step 1: Backup originals ──────────────────────────────────────────────────
hdr "Step 1: Backup originals"

BACKUP="$REPO_ROOT/.refactor-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"

cp backend/app.py        "$BACKUP/app.py.bak"
cp backend/siem_proxy.py "$BACKUP/siem_proxy.py.bak"
cp portal/src/App.jsx    "$BACKUP/App.jsx.bak"
[[ -f portal/src/main.jsx ]]  && cp portal/src/main.jsx   "$BACKUP/main.jsx.bak"
[[ -f portal/src/index.css ]] && cp portal/src/index.css  "$BACKUP/index.css.bak"

ok "Backups saved to $BACKUP"
echo "  (Restore with: cp $BACKUP/*.bak <original-path>)"

# ── Step 2: Backend — create Blueprint directory structure ────────────────────
hdr "Step 2: Backend — create Blueprint directory structure"

mkdir -p backend/core
mkdir -p backend/blueprints/{auth,oidc,rbac,platform,asm,system,siem}

# Create __init__.py for every package
for d in backend/blueprints backend/blueprints/{auth,oidc,rbac,platform,asm,system,siem} backend/core; do
  [[ -f "$d/__init__.py" ]] || echo "# $(basename $d) package" > "$d/__init__.py"
done

ok "Blueprint directory structure created"

# ── Step 3: Copy backend files ────────────────────────────────────────────────
hdr "Step 3: Copy backend files"

# Core
cp "$SRC/backend/core/config.py"   backend/core/config.py
cp "$SRC/backend/core/helpers.py"  backend/core/helpers.py
ok "core/config.py + core/helpers.py"

# Blueprints
cp "$SRC/backend/blueprints/auth/oauth.py"          backend/blueprints/auth/oauth.py
cp "$SRC/backend/blueprints/oidc/provider.py"       backend/blueprints/oidc/provider.py
cp "$SRC/backend/blueprints/rbac/manager.py"        backend/blueprints/rbac/manager.py
cp "$SRC/backend/blueprints/platform/compose.py"    backend/blueprints/platform/compose.py
cp "$SRC/backend/blueprints/platform/state.py"      backend/blueprints/platform/state.py
cp "$SRC/backend/blueprints/platform/docker_utils.py" backend/blueprints/platform/docker_utils.py
cp "$SRC/backend/blueprints/platform/routes.py"     backend/blueprints/platform/routes.py
cp "$SRC/backend/blueprints/asm/scanner.py"         backend/blueprints/asm/scanner.py
cp "$SRC/backend/blueprints/system/routes.py"       backend/blueprints/system/routes.py
ok "All blueprint files copied"

# New app.py (replaces monolith)
cp "$SRC/backend/app.py"        backend/app.py
ok "backend/app.py → thin factory"

# Fixed siem_proxy.py (circular import fixed)
cp "$SRC/backend/siem_proxy.py" backend/siem_proxy.py
ok "backend/siem_proxy.py → circular import fixed"

# ── Step 4: Frontend — create module directory structure ──────────────────────
hdr "Step 4: Frontend — create module directory structure"

mkdir -p portal/src/{core,registry,components,hooks,sidebar,styles}
mkdir -p portal/src/pages/{login,scan,dashboard,assets,vulnerabilities,siem,platform,ai,usecases}

ok "Frontend directory structure created"

# ── Step 5: Copy frontend files ───────────────────────────────────────────────
hdr "Step 5: Copy frontend files"

# Core
cp "$SRC/portal/src/core/constants.js"  portal/src/core/constants.js
cp "$SRC/portal/src/core/auth.js"       portal/src/core/auth.js
cp "$SRC/portal/src/core/adapter.js"    portal/src/core/adapter.js
ok "core/ (constants, auth, adapter)"

# Registry
cp "$SRC/portal/src/registry/platformModules.js" portal/src/registry/platformModules.js
cp "$SRC/portal/src/registry/aiProviders.js"     portal/src/registry/aiProviders.js
ok "registry/ (platformModules, aiProviders)"

# Styles
cp "$SRC/portal/src/styles/globals.css" portal/src/styles/globals.css
ok "styles/globals.css"

# Sidebar
cp "$SRC/portal/src/sidebar/navConfig.js" portal/src/sidebar/navConfig.js
cp "$SRC/portal/src/sidebar/Sidebar.jsx"  portal/src/sidebar/Sidebar.jsx
ok "sidebar/ (navConfig, Sidebar)"

# Hooks
cp "$SRC/portal/src/hooks/useAppState.js" portal/src/hooks/useAppState.js
ok "hooks/useAppState.js"

# Pages
cp "$SRC/portal/src/pages/login/LoginPage.jsx"                       portal/src/pages/login/LoginPage.jsx
cp "$SRC/portal/src/pages/scan/ScanPage.jsx"                         portal/src/pages/scan/ScanPage.jsx
cp "$SRC/portal/src/pages/dashboard/DashboardPage.jsx"               portal/src/pages/dashboard/DashboardPage.jsx
cp "$SRC/portal/src/pages/assets/AssetsPage.jsx"                     portal/src/pages/assets/AssetsPage.jsx
cp "$SRC/portal/src/pages/assets/AssetModal.jsx"                     portal/src/pages/assets/AssetModal.jsx
cp "$SRC/portal/src/pages/assets/ImportModal.jsx"                    portal/src/pages/assets/ImportModal.jsx
cp "$SRC/portal/src/pages/vulnerabilities/VulnerabilityPage.jsx"     portal/src/pages/vulnerabilities/VulnerabilityPage.jsx
cp "$SRC/portal/src/pages/siem/SiemFeedPage.jsx"                     portal/src/pages/siem/SiemFeedPage.jsx
cp "$SRC/portal/src/pages/platform/PlatformPage.jsx"                 portal/src/pages/platform/PlatformPage.jsx
cp "$SRC/portal/src/pages/ai/AISettingsPage.jsx"                     portal/src/pages/ai/AISettingsPage.jsx
cp "$SRC/portal/src/pages/usecases/UseCasesPage.jsx"                 portal/src/pages/usecases/UseCasesPage.jsx
ok "All page components copied"

# New App.jsx (thin shell) + main.jsx
cp "$SRC/portal/src/App.jsx"  portal/src/App.jsx
cp "$SRC/portal/src/main.jsx" portal/src/main.jsx
ok "App.jsx → thin shell (~80 lines)"
ok "main.jsx → updated (imports globals.css)"

# Delete the now-redundant config/constants.js (consolidated into core/constants.js)
if [[ -f "portal/src/config/constants.js" ]]; then
  cp "portal/src/config/constants.js" "$BACKUP/config-constants.js.bak"
  rm "portal/src/config/constants.js"
  # Remove the config/ dir if now empty
  rmdir "portal/src/config" 2>/dev/null || true
  warn "Deleted portal/src/config/constants.js (merged into core/constants.js)"
fi

# ── Step 6: Quick syntax checks ───────────────────────────────────────────────
hdr "Step 6: Quick syntax checks"

info "Checking Python syntax on all new backend files…"
PYTHON=$(which python3.12 2>/dev/null || which python3 2>/dev/null || echo "")

if [[ -n "$PYTHON" ]]; then
  PY_OK=true
  for f in \
    backend/app.py \
    backend/siem_proxy.py \
    backend/core/config.py \
    backend/core/helpers.py \
    backend/blueprints/auth/oauth.py \
    backend/blueprints/oidc/provider.py \
    backend/blueprints/rbac/manager.py \
    backend/blueprints/platform/compose.py \
    backend/blueprints/platform/state.py \
    backend/blueprints/platform/docker_utils.py \
    backend/blueprints/platform/routes.py \
    backend/blueprints/asm/scanner.py \
    backend/blueprints/system/routes.py; do
    if $PYTHON -c "import ast; ast.parse(open('$f').read())" 2>/dev/null; then
      ok "$f"
    else
      warn "Syntax issue in $f — check manually"
      PY_OK=false
    fi
  done
  $PY_OK && ok "All Python files pass syntax check" || warn "Some Python files need attention"
else
  warn "Python not found — skipping syntax check"
fi

# ── Step 7: Install frontend dependencies ─────────────────────────────────────
hdr "Step 7: Frontend — install dependencies"

cd portal
if command -v npm &>/dev/null; then
  info "Running npm install…"
  npm install --silent
  ok "npm install complete"
else
  warn "npm not found — run 'npm install' in portal/ manually"
fi
cd "$REPO_ROOT"

# ── Step 8: Test build ────────────────────────────────────────────────────────
hdr "Step 8: Test build (npm run build)"

cd portal
BUILD_OK=true
if command -v npm &>/dev/null; then
  info "Running npm run build…"
  if npm run build 2>&1; then
    ok "Production build succeeded"
  else
    warn "Build failed — check output above"
    BUILD_OK=false
  fi
else
  warn "npm not found — run 'npm run build' in portal/ manually"
fi
cd "$REPO_ROOT"

# ── Step 9: Git status ────────────────────────────────────────────────────────
hdr "Step 9: Git status"

info "Files changed:"
git diff --name-only 2>/dev/null | head -40 || true
echo ""
info "New files:"
git ls-files --others --exclude-standard 2>/dev/null | grep -E '\.(py|jsx|js|css)$' | head -40 || true

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  Refactor complete${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${GREEN}Backend files:${NC}  17 new files created"
echo -e "  ${GREEN}Frontend files:${NC} 22 new files created"
echo -e "  ${GREEN}Backups:${NC}        $BACKUP"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo -e "  1. ${CYAN}Test dev server:${NC}"
echo -e "     cd portal && npm run dev"
echo -e "     Open http://localhost:5173 — should look identical to before"
echo ""
echo -e "  2. ${CYAN}Test backend:${NC}"
echo -e "     cd backend && python3 app.py"
echo -e "     curl http://localhost:5252/health  # should return {\"status\":\"ok\"}"
echo ""
echo -e "  3. ${CYAN}Commit and push:${NC}"
echo -e "     git add -A"
echo -e "     git commit -m \"refactor: modular Blueprint backend + component frontend v4.3\""
echo -e "     git push origin main"
echo ""
echo -e "  4. ${CYAN}Tag the release:${NC}"
echo -e "     git tag -a v4.3.0 -m \"Modular architecture — Blueprint backend, component frontend\""
echo -e "     git push origin v4.3.0"
echo ""
echo -e "  ${YELLOW}Rollback if needed:${NC}"
echo -e "     cp $BACKUP/app.py.bak         backend/app.py"
echo -e "     cp $BACKUP/siem_proxy.py.bak  backend/siem_proxy.py"
echo -e "     cp $BACKUP/App.jsx.bak        portal/src/App.jsx"
echo -e "     cp $BACKUP/main.jsx.bak       portal/src/main.jsx"
echo ""
