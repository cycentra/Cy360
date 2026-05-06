"""
PATCH 7b — Fix 'name pathlib is not defined' in _read_misp_config
==================================================================
The function used pathlib.Path(...) but the file imports Path directly:
    from pathlib import Path
So the fix is simply: replace pathlib.Path with Path throughout _read_misp_config.

Run from repo root:
    python3 benchmark-patch/PATCH_7b_fix_pathlib.py
"""

import pathlib, sys

TARGET = pathlib.Path("backend/blueprints/benchmark/routes.py")

FIND    = '    _AI_SETTINGS = pathlib.Path("/opt/cycentra/ai_settings.json")'
REPLACE = '    _AI_SETTINGS = Path("/opt/cycentra/ai_settings.json")'

def main():
    if not TARGET.exists():
        print(f"✗  {TARGET} not found — run from repo root.")
        sys.exit(1)

    content = TARGET.read_text()

    if FIND not in content:
        # Already fixed or different text — check what's there
        for i, line in enumerate(content.splitlines(), 1):
            if "ai_settings.json" in line and "_read_misp" not in line:
                print(f"  line {i}: {line}")
        print("✗  Search string not found — paste lines above and I'll adjust.")
        sys.exit(1)

    TARGET.write_text(content.replace(FIND, REPLACE, 1))
    print("✓  Fixed: pathlib.Path → Path in _read_misp_config")
    print()
    print("Restart backend:")
    print("  Local:      pkill -f 'python3 app.py'; cd backend && python3 app.py &")
    print("  Production: sudo systemctl restart cycentra-backend")

if __name__ == "__main__":
    main()
