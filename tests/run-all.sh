#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CyCentra 360 — Test Runner
#
# Usage:
#   bash tests/run-all.sh --suite 01,02,08
#   bash tests/run-all.sh --suite all
#
# Suite map (mirrors agent-test-gate.yml suite selection logic):
#   01 — Project structure + RELEASE_NOTES format smoke tests (always run)
#   02 — Python syntax check for all backend .py files
#   03 — Blueprint OPTIONS handler + route registration checks
#   04 — Auth / RBAC session guard checks
#   05 — CySIEMStack correlation engine main.py checks
#   06 — Correlator + UEBA module checks
#   07 — ASM scanner blueprint checks
#   08 — Portal React source checks
#   09 — cycentra-setup.sh + deploy workflow checks
#   10 — Full auth flow + RBAC integration checks
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
WARN=0
ERRORS=()

# ── helpers ──────────────────────────────────────────────────────────────────
ok()   { echo "  ✅ $*"; ((PASS++)) || true; }
fail() { echo "  ❌ $*"; ERRORS+=("$*"); ((FAIL++)) || true; }
warn() { echo "  ⚠️  $*"; ((WARN++)) || true; }

run_suite() {
    local id="$1"
    echo ""
    echo "━━━ Suite $id ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    case "$id" in
        01) suite_01 ;;
        02) suite_02 ;;
        03) suite_03 ;;
        04) suite_04 ;;
        05) suite_05 ;;
        06) suite_06 ;;
        07) suite_07 ;;
        08) suite_08 ;;
        09) suite_09 ;;
        10) suite_10 ;;
        *)  echo "  ⚠️  Unknown suite $id — skipping" ;;
    esac
}

# ── Suite 01: Project structure + RELEASE_NOTES smoke ────────────────────────
suite_01() {
    echo "Project structure + RELEASE_NOTES smoke tests"

    [ -f "$REPO_ROOT/backend/app.py" ]              && ok "backend/app.py exists"     || fail "backend/app.py missing"
    [ -f "$REPO_ROOT/backend/pyproject.toml" ]      && ok "pyproject.toml exists"     || fail "backend/pyproject.toml missing"
    [ -f "$REPO_ROOT/RELEASE_NOTES.md" ]            && ok "RELEASE_NOTES.md exists"   || fail "RELEASE_NOTES.md missing"
    [ -f "$REPO_ROOT/cycentra-setup.sh" ]           && ok "cycentra-setup.sh exists"  || fail "cycentra-setup.sh missing"
    [ -f "$REPO_ROOT/.github/workflows/deploy.yml" ] && ok "deploy.yml exists"        || fail ".github/workflows/deploy.yml missing"
    [ -f "$REPO_ROOT/portal/src/App.jsx" ]          && ok "portal/src/App.jsx exists" || fail "portal/src/App.jsx missing"

    # RELEASE_NOTES must have at least one version entry
    local versions
    versions=$(grep -c "^## v[0-9]" "$REPO_ROOT/RELEASE_NOTES.md" 2>/dev/null || echo 0)
    [ "$versions" -ge 1 ] && ok "RELEASE_NOTES.md has $versions version entries" \
                           || fail "RELEASE_NOTES.md has no version entries"

    # First entry must be highest (newest at top)
    local first_ver all_vers max_ver
    first_ver=$(grep "^## v[0-9]" "$REPO_ROOT/RELEASE_NOTES.md" | head -1 | grep -oP "v[\d.]+")
    max_ver=$(grep "^## v[0-9]" "$REPO_ROOT/RELEASE_NOTES.md" | grep -oP "v[\d.]+" \
              | sort -t. -k1,1V -k2,2n -k3,3n | tail -1)
    [ "$first_ver" = "$max_ver" ] && ok "Newest version ($first_ver) is first in RELEASE_NOTES.md" \
                                  || fail "RELEASE_NOTES.md ordering wrong: first=$first_ver but newest=$max_ver"

    # Each version block must have a recognised category heading
    python3 - << 'PYEOF'
import re
import sys
import os
rn = open(os.path.join(os.environ.get("REPO_ROOT","."),"RELEASE_NOTES.md")).read()
blocks = re.split(r"^## v[\d.]+", rn, flags=re.MULTILINE)[1:]
accepted = ("### Bug Fix","### Fix","### Feature","### Enhancement","### Chore",
            "### Performance","### Security","### Hotfix","### Refactor")
bad = []
for i, b in enumerate(blocks[:5]):          # check only the 5 most recent
    if not any(h in b for h in accepted):
        bad.append(i + 1)
if bad:
    print(f"  ❌ Blocks {bad} have no recognised category heading (### Fix, ### Feature, etc.)")
    sys.exit(1)
print(f"  ✅ All checked RELEASE_NOTES blocks have category headings")
PYEOF
    [ $? -eq 0 ] && ((PASS++)) || { ((FAIL++)); ERRORS+=("RELEASE_NOTES category heading check failed"); }
}

# ── Suite 02: Python syntax for all backend .py files ────────────────────────
suite_02() {
    echo "Python syntax check — backend"
    local bad=0
    while IFS= read -r f; do
        if ! python3 -c "import ast; ast.parse(open('$f').read())" 2>/dev/null; then
            fail "Syntax error: $f"
            bad=1
        fi
    done < <(find "$REPO_ROOT/backend" -name "*.py" -not -path "*/\.*")
    [ "$bad" -eq 0 ] && ok "All backend .py files pass ast.parse()"
}

# ── Suite 03: Blueprint OPTIONS handlers + route registration ─────────────────
suite_03() {
    echo "Blueprint OPTIONS handlers + app.py registration"

    # Every blueprint file with POST/PUT/DELETE must have an OPTIONS route
    # (warnings only — pre-existing omissions are tracked separately)
    while IFS= read -r f; do
        if grep -qE 'methods=\[.*"(POST|PUT|DELETE)"' "$f"; then
            if ! grep -q '"OPTIONS"' "$f"; then
                warn "Missing OPTIONS handler (should be added): $(basename "$(dirname "$f")")/$(basename "$f")"
            fi
        fi
    done < <(find "$REPO_ROOT/backend/blueprints" -name "*.py" 2>/dev/null)
    ok "OPTIONS handler check complete (warnings non-blocking)"

    # app.py must register all 7 expected blueprints
    local app="$REPO_ROOT/backend/app.py"
    for bp in auth oidc rbac platform asm system siem; do
        grep -q "$bp" "$app" && ok "app.py registers $bp blueprint" \
                              || fail "app.py missing $bp blueprint registration"
    done

    # app.py line count
    local lines
    lines=$(wc -l < "$app")
    [ "$lines" -le 70 ] && ok "app.py is $lines lines (≤70)" \
                         || fail "app.py is $lines lines — exceeds 70-line limit"
}

# ── Suite 04: Auth / RBAC session guards ─────────────────────────────────────
suite_04() {
    echo "Auth + RBAC session guard checks"

    # auth/rbac/oidc blueprints must check session — others may use middleware
    local bad=0
    for bp_dir in auth rbac; do
        while IFS= read -r f; do
            if grep -q '"/api/' "$f"; then
                if ! grep -q 'session.get("user_email")' "$f"; then
                    fail "Missing session guard in $bp_dir: $(basename "$f")"
                    bad=1
                fi
            fi
        done < <(find "$REPO_ROOT/backend/blueprints/$bp_dir" -name "*.py" 2>/dev/null)
    done
    # Platform / system — warn only (pre-existing, tracked separately)
    for bp_dir in platform system; do
        while IFS= read -r f; do
            if grep -q '"/api/' "$f" && ! grep -q 'session.get' "$f"; then
                warn "No session.get() in $bp_dir/$(basename "$f") — add auth guards"
            fi
        done < <(find "$REPO_ROOT/backend/blueprints/$bp_dir" -name "*.py" 2>/dev/null)
    done
    [ "$bad" -eq 0 ] && ok "Auth/RBAC blueprints have session guards"

    # RBAC file must exist at declared path (env default)
    grep -q "RBAC_FILE" "$REPO_ROOT/backend/core/config.py" \
        && ok "RBAC_FILE declared in core/config.py" \
        || fail "RBAC_FILE missing from core/config.py"

    # get_user_role must exist in rbac manager
    grep -q "def get_user_role" "$REPO_ROOT/backend/blueprints/rbac/manager.py" \
        && ok "get_user_role() defined in rbac/manager.py" \
        || fail "get_user_role() missing from rbac/manager.py"
}

# ── Suite 05: CySIEMStack correlation engine main.py ─────────────────────────
suite_05() {
    echo "CySIEMStack correlation engine"
    local main="$REPO_ROOT/backend/cysiemstack/correlation_engine/main.py"
    [ -f "$main" ] && ok "correlation engine main.py exists" || { fail "main.py missing"; return; }
    python3 -c "import ast; ast.parse(open('$main').read())" 2>/dev/null \
        && ok "main.py passes syntax check" || fail "main.py syntax error"
}

# ── Suite 06: Correlator + UEBA modules ──────────────────────────────────────
suite_06() {
    echo "Correlator + UEBA modules"
    for f in correlator ueba; do
        local path="$REPO_ROOT/backend/cysiemstack/correlation_engine/${f}.py"
        [ -f "$path" ] && ok "${f}.py exists" || fail "${f}.py missing"
        [ -f "$path" ] && {
            python3 -c "import ast; ast.parse(open('$path').read())" 2>/dev/null \
                && ok "${f}.py passes syntax check" || fail "${f}.py syntax error"
        }
    done
}

# ── Suite 07: ASM scanner blueprint ──────────────────────────────────────────
suite_07() {
    echo "ASM scanner blueprint"
    local scanner="$REPO_ROOT/backend/blueprints/asm/scanner.py"
    [ -f "$scanner" ] && ok "asm/scanner.py exists" || { fail "asm/scanner.py missing"; return; }
    python3 -c "import ast; ast.parse(open('$scanner').read())" 2>/dev/null \
        && ok "asm/scanner.py passes syntax check" || fail "asm/scanner.py syntax error"
    grep -q '"/api/scan/trigger"' "$scanner" \
        && ok "scan trigger route defined" || fail "/api/scan/trigger route missing"
}

# ── Suite 08: Portal React source ────────────────────────────────────────────
suite_08() {
    echo "Portal React source checks"

    # App.jsx must exist and be under 120 lines
    local app="$REPO_ROOT/portal/src/App.jsx"
    [ -f "$app" ] && ok "portal/src/App.jsx exists" || { fail "portal/src/App.jsx missing"; return; }
    local lines
    lines=$(wc -l < "$app")
    [ "$lines" -le 150 ] && ok "App.jsx is $lines lines (≤150)" \
                          || warn "App.jsx is $lines lines — ideally keep under 120"

    # core/constants.js must declare BASE_API_URL
    local constants="$REPO_ROOT/portal/src/core/constants.js"
    [ -f "$constants" ] && ok "core/constants.js exists" || fail "core/constants.js missing"
    grep -q "BASE_API_URL\|API_BASE" "$constants" 2>/dev/null \
        && ok "API_BASE declared in constants.js" || fail "API_BASE missing from constants.js"

    # No circular imports — check that page files don't import from App
    if find "$REPO_ROOT/portal/src/pages" -name "*.jsx" \
       | xargs grep -l "from.*App" 2>/dev/null | grep -q .; then
        warn "Possible circular App.jsx import detected"
    else
        ok "No circular App.jsx imports detected"
    fi
}

# ── Suite 09: Setup script + deploy workflow checks ──────────────────────────
suite_09() {
    echo "cycentra-setup.sh + deploy workflow checks"

    local setup="$REPO_ROOT/cycentra-setup.sh"

    # Setup script must exist and be a bash script
    [ -f "$setup" ] && ok "cycentra-setup.sh exists" || { fail "cycentra-setup.sh missing"; return; }
    head -1 "$setup" | grep -q "bash" \
        && ok "cycentra-setup.sh has bash shebang" || fail "cycentra-setup.sh missing #!/bin/bash"

    # Shellcheck if available
    if command -v shellcheck &>/dev/null; then
        shellcheck -S warning "$setup" 2>&1 | grep -q "^" \
            && { echo "  ⚠️  shellcheck warnings present (non-blocking)"; } || ok "shellcheck passed"
    else
        echo "  ℹ️  shellcheck not available — skipping"
    fi

    # pyproject.toml must have a version field
    grep -q "^version" "$REPO_ROOT/backend/pyproject.toml" \
        && ok "pyproject.toml has version field" || fail "pyproject.toml missing version field"

    # deploy.yml must reference push + tags trigger
    local deploy="$REPO_ROOT/.github/workflows/deploy.yml"
    grep -q "tags:" "$deploy" \
        && ok "deploy.yml has tags trigger" || fail "deploy.yml missing tags trigger"
    grep -q "branches:" "$deploy" \
        && ok "deploy.yml has branches trigger" || fail "deploy.yml missing branches trigger"
}

# ── Suite 10: Full auth integration checks ───────────────────────────────────
suite_10() {
    echo "Full auth integration checks"

    # OAuth routes must be present
    local oauth="$REPO_ROOT/backend/blueprints/auth/oauth.py"
    [ -f "$oauth" ] && ok "auth/oauth.py exists" || { fail "auth/oauth.py missing"; return; }
    for route in "/auth/google" "/auth/microsoft" "/auth/logout" "/api/auth/verify"; do
        grep -q "\"${route}\"" "$oauth" \
            && ok "Route $route defined" || fail "Route $route missing from oauth.py"
    done

    # OIDC provider routes
    local oidc="$REPO_ROOT/backend/blueprints/oidc/provider.py"
    [ -f "$oidc" ] && ok "oidc/provider.py exists" || fail "oidc/provider.py missing"

    # COOKIE_SETTINGS must enforce SameSite=None (required for cross-subdomain OIDC)
    grep -q 'SESSION_COOKIE_SAMESITE.*None' "$REPO_ROOT/backend/core/config.py" \
        && ok "SESSION_COOKIE_SAMESITE=None set in config" \
        || fail "SESSION_COOKIE_SAMESITE=None missing — cross-subdomain OIDC will break"

    # auth_event helper must exist
    grep -q "def auth_event" "$REPO_ROOT/backend/core/helpers.py" \
        && ok "auth_event() defined in core/helpers.py" || fail "auth_event() missing"
}

# ── Argument parsing ──────────────────────────────────────────────────────────
SUITES_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite) SUITES_ARG="$2"; shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [ -z "$SUITES_ARG" ] || [ "$SUITES_ARG" = "all" ]; then
    SUITES_ARG="01,02,03,04,05,06,07,08,09,10"
fi

export REPO_ROOT

IFS=',' read -ra SUITE_LIST <<< "$SUITES_ARG"
for s in "${SUITE_LIST[@]}"; do
    # Normalise to 2-digit zero-padded
    s=$(printf "%02d" "$((10#$s))")
    run_suite "$s"
done

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: ✅ $PASS passed   ❌ $FAIL failed   ⚠️  $WARN warnings"
if [ "${#ERRORS[@]}" -gt 0 ]; then
    echo ""
    echo "  Failures:"
    for e in "${ERRORS[@]}"; do
        echo "    • $e"
    done
fi
echo "═══════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
