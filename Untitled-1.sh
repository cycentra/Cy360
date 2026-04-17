#!/usr/bin/env bash
# fix-cylogo-packaging.sh
# Fixes: cylogo/, wordlists/, Utils/ missing __init__.py + pyproject.toml package-data gaps

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$REPO_ROOT/backend"

echo "==> Creating missing __init__.py files..."
touch "$BACKEND/cy_asm/modules/cylogo/__init__.py"
touch "$BACKEND/cy_asm/modules/wordlists/__init__.py"
touch "$BACKEND/cy_asm/modules/Utils/__init__.py"

echo "==> Patching pyproject.toml package-data..."
python3 - "$BACKEND/pyproject.toml" <<'PYEOF'
import sys, pathlib

toml = pathlib.Path(sys.argv[1])
content = toml.read_text()

OLD = '"*" = ["*.json", "*.yaml", "*.yml", "*.html", "*.txt", "*.sql", "*.xml"]'
NEW = '"*" = ["*.json", "*.yaml", "*.yml", "*.html", "*.txt", "*.sql", "*.xml", "*.sh", "*.png", "*.svg", "*.ico", "*.webp"]'

if OLD not in content:
    print("  WARNING: Expected package-data line not found — check pyproject.toml manually", file=sys.stderr)
    sys.exit(1)

toml.write_text(content.replace(OLD, NEW, 1))
print("  pyproject.toml updated.")
PYEOF

echo "==> Staging changes for git..."
git -C "$REPO_ROOT" add \
    backend/cy_asm/modules/cylogo/__init__.py \
    backend/cy_asm/modules/wordlists/__init__.py \
    backend/cy_asm/modules/Utils/__init__.py \
    backend/pyproject.toml

git -C "$REPO_ROOT" commit -m "fix: add __init__.py to cylogo/wordlists/Utils; expand package-data to include .sh and image files"

echo ""
echo "==> Done. Now run ./git-push.sh to tag and push."