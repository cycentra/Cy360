# CyCentra 360 — Refactor Validation Guide

## Overview

After running `apply_refactor.sh`, validate each layer independently before pushing to Git.
Every step should pass before moving to the next.

---

## Step 1 — Python syntax (2 min)

```bash
cd backend
python3 -c "
import ast, glob
files = glob.glob('**/*.py', recursive=True)
failed = []
for f in files:
    try: ast.parse(open(f).read())
    except SyntaxError as e: failed.append(f'{f}: {e}')
print('PASS' if not failed else '\n'.join(failed))
"
```

**Expected:** `PASS`

---

## Step 2 — Flask starts (2 min)

```bash
cd backend
# If you have a venv:
source venv/bin/activate

# Set minimum env vars for local test
export SECRET_KEY="test_secret_key_local"
export BASE_DOMAIN="localhost"
export FRONTEND_URL="http://localhost:5173"
export BASE_URL="http://localhost:5252"

python3 app.py &
sleep 3

curl -s http://localhost:5252/health
# Expected: {"status":"ok","version":"4.3","service":"cycentra360-backend"}

kill %1
```

---

## Step 3 — Blueprint imports (1 min)

```bash
cd backend
python3 -c "
from core.config import BASE_DOMAIN, RBAC_FILE, OIDC_CLIENTS
from core.helpers import run, enc, add_cors_headers
from blueprints.auth.oauth import auth_bp
from blueprints.oidc.provider import oidc_bp
from blueprints.rbac.manager import rbac_bp, get_user_role
from blueprints.platform.compose import COMPOSE_TEMPLATES, VALID_MODULES
from blueprints.platform.routes import platform_bp
from blueprints.asm.scanner import asm_bp
from blueprints.system.routes import system_bp
from siem_proxy import siem_bp
print('All imports OK')
print(f'Valid modules: {sorted(VALID_MODULES)}')
print(f'OIDC clients: {list(OIDC_CLIENTS.keys())}')
"
```

**Expected:**
```
All imports OK
Valid modules: ['cyiris', 'cymisp', 'cysoar']
OIDC clients: ['cyiris', 'cysoar']
```

---

## Step 4 — Frontend builds (3 min)

```bash
cd portal
npm install          # if not already done
npm run build        # must complete with 0 errors
```

**Expected:** Build completes, `dist/` folder created with `index.html` and JS/CSS chunks.

Check for circular import warnings — there should be none.

---

## Step 5 — Dev server visual check (5 min)

```bash
cd portal
npm run dev
# Opens http://localhost:5173
```

Open in browser and verify:

| Check | Expected |
|---|---|
| Login screen renders | Google + Microsoft buttons visible |
| No console errors | Browser console clean |
| No broken imports | Network tab shows no 404s for JS modules |
| After mock login | Sidebar renders with all sections |
| Dashboard tab | Loads without crash (empty state OK) |
| AI Settings tab | Provider selector, fields, prompts visible |
| Platform tab | Base modules + Add-on modules cards visible |
| Use Cases tab | 6 template cards with category filter |

---

## Step 6 — Verify key module boundaries (2 min)

Check each file has the right content and is the right size:

```bash
# App.jsx should be ~80 lines (was 2,400+)
wc -l portal/src/App.jsx
# Expected: < 120 lines

# backend/app.py should be ~55 lines (was 1,400+)
wc -l backend/app.py
# Expected: < 70 lines

# Each blueprint should be self-contained
wc -l backend/blueprints/*/  *.py 2>/dev/null | sort -n

# core/adapter.js should have all stat helpers
grep -c "export function" portal/src/core/adapter.js
# Expected: 7 (adaptCyCentraJSON + 6 stat helpers)
```

---

## Step 7 — Circular import check (siem_proxy fix)

```bash
grep "from app import" backend/siem_proxy.py
# Expected: no output (the old circular import is gone)

grep "from blueprints.rbac" backend/siem_proxy.py
# Expected: one line showing the corrected import
```

---

## Step 8 — Config constants deduplication check

```bash
# Old constants.js should be gone
ls portal/src/config/constants.js 2>/dev/null && echo "STILL EXISTS — delete it" || echo "Correctly removed"

# New constants.js should have all the right exports
grep "export const" portal/src/core/constants.js
```

---

## Step 9 — Commit and push

Once all steps pass:

```bash
# On your refactor branch (or main if you work directly)
git add -A
git status   # review what's changing

git commit -m "refactor: modular Blueprint backend + component frontend

- backend/app.py: thin factory, 50 lines (was 1400)
- blueprint modules: auth, oidc, rbac, platform, asm, system, siem
- siem_proxy.py: circular import fixed
- portal/src/App.jsx: layout shell, 80 lines (was 2400)
- core/: constants, auth, adapter
- registry/: platformModules, aiProviders
- pages/: 11 page components
- sidebar/: Sidebar + navConfig
- hooks/: useAppState
- styles/globals.css extracted from GLOBAL_CSS string
- portal/src/config/constants.js: deleted (merged)"

git push origin main

# Tag the release
git tag -a v4.3.0 -m "Modular architecture refactor"
git push origin v4.3.0
```

---

## Rollback (if anything breaks)

```bash
# Restore from backup (path shown at end of apply_refactor.sh output)
BACKUP=".refactor-backup-YYYYMMDD-HHMMSS"   # ← replace with actual

cp $BACKUP/app.py.bak         backend/app.py
cp $BACKUP/siem_proxy.py.bak  backend/siem_proxy.py
cp $BACKUP/App.jsx.bak        portal/src/App.jsx
cp $BACKUP/main.jsx.bak       portal/src/main.jsx

# Restore index.css if needed
cp $BACKUP/index.css.bak      portal/src/index.css

git checkout -- .              # reset everything else
```

---

## Troubleshooting

| Symptom | File to check |
|---|---|
| `ModuleNotFoundError: core.config` | Run Flask from `backend/` directory, not repo root |
| `ImportError: cannot import name 'auth_bp'` | Check `backend/blueprints/auth/__init__.py` exists |
| Login screen blank | Check browser console for JS import errors |
| `getModuleUrl is not defined` | Verify `portal/src/core/constants.js` was copied |
| Dashboard shows no data | `adaptCyCentraJSON` in `portal/src/core/adapter.js` |
| Module install fails | `backend/blueprints/platform/routes.py` + `compose.py` |
| SIEM proxy 401 | `backend/blueprints/rbac/manager.py` — `get_user_role` |
| OIDC token rejected | `backend/blueprints/oidc/provider.py` |
