"""
PATCH 8 — MISP config: full fallback chain + sync on portal save
=================================================================
Two files patched:

1. backend/blueprints/benchmark/routes.py
   _read_misp_config() now reads in order:
     a) ai_settings.json  → "misp" key  (url + apiKey)
     b) cysiemstack.env   → MISP_URL / MISP_API_KEY / MISP_MODE
     c) os.environ        → same keys
   Exactly the same fallback pattern as iris_connector.py.
   First source that has both url AND apiKey wins.

2. backend/blueprints/system/routes.py
   _sync_misp_to_siem_env() already writes to cysiemstack.env.
   Add 4 lines to also write url + apiKey into ai_settings.json["misp"]
   so both consumers stay in sync from the next portal save onward.

Run from repo root:
    python3 benchmark-patch/PATCH_8_misp_fallback.py
"""

import pathlib, sys

ROOT = pathlib.Path(".")

# ══════════════════════════════════════════════════════════════════════════════
# PATCH 1 — benchmark/routes.py : _read_misp_config() fallback chain
# ══════════════════════════════════════════════════════════════════════════════

BENCH = ROOT / "backend/blueprints/benchmark/routes.py"

BENCH_FIND = """\
def _read_misp_config() -> dict | None:
    \"\"\"
    Read MISP credentials from /opt/cycentra/ai_settings.json.

    This is the single authoritative source for MISP config in the Flask
    backend context — same approach used by iris_connector.py.
    The cysiemstack.env equivalents are written for the engine process only
    and are not available in os.environ inside the Flask process.

    Returns a dict with keys: url, apiKey, mode
    Returns None if MISP is disabled or credentials are missing.
    \"\"\"
    _AI_SETTINGS = Path("/opt/cycentra/ai_settings.json")
    try:
        raw    = _AI_SETTINGS.read_text() if _AI_SETTINGS.exists() else "{}"
        stored = json.loads(raw)
    except Exception as exc:
        log.warning("[benchmark] ai_settings.json read error: %s", exc)
        return None

    misp = stored.get("misp") or {}
    mode = str(misp.get("mode", "disabled")).lower()

    if mode == "disabled" or not misp:
        return None

    url     = str(misp.get("url", "")).strip().rstrip("/")
    api_key = str(misp.get("apiKey", "")).strip()

    if not url or not api_key:
        return None

    return {"url": url, "apiKey": api_key, "mode": mode}"""

BENCH_REPLACE = """\
def _read_cysiemstack_env() -> dict:
    \"\"\"
    Parse /opt/cycentra/cysiemstack.env into a key→value dict.
    Mirrors iris_connector._read_cycentra_env() for the same reason:
    the engine's systemd unit loads cysiemstack.env but the Flask process
    does not, so we read the file directly as a fallback.
    \"\"\"
    env: dict = {}
    env_file = Path("/opt/cycentra/cysiemstack.env")
    if not env_file.exists():
        return env
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return env


def _read_misp_config() -> dict | None:
    \"\"\"
    Resolve MISP credentials using a three-level fallback chain.
    Mirrors the pattern in iris_connector._load_iris_config().

    Priority (first source with both url AND apiKey wins):
      1. /opt/cycentra/ai_settings.json  → misp.url / misp.apiKey
      2. /opt/cycentra/cysiemstack.env   → MISP_URL / MISP_API_KEY
      3. os.environ                      → MISP_URL / MISP_API_KEY

    Returns dict(url, apiKey, mode) or None if MISP is disabled/unconfigured.
    \"\"\"
    # ── Source 1: ai_settings.json ────────────────────────────────────────────
    url     = ""
    api_key = ""
    mode    = "disabled"

    ai_file = Path("/opt/cycentra/ai_settings.json")
    try:
        if ai_file.exists():
            stored = json.loads(ai_file.read_text())
            misp   = stored.get("misp") or {}
            mode   = str(misp.get("mode", "disabled")).lower()
            url     = str(misp.get("url",    "")).strip().rstrip("/")
            api_key = str(misp.get("apiKey", "")).strip()
    except Exception as exc:
        log.warning("[benchmark] ai_settings.json read error: %s", exc)

    # ── Source 2: cysiemstack.env (fallback) ──────────────────────────────────
    if not url or not api_key:
        siem_env = _read_cysiemstack_env()
        url      = url      or siem_env.get("MISP_URL",     "").strip().rstrip("/")
        api_key  = api_key  or siem_env.get("MISP_API_KEY", "").strip()
        if not mode or mode == "disabled":
            mode = siem_env.get("MISP_MODE", "local").lower()
        # Also check MISP_ENABLED — if explicitly false, respect it
        if siem_env.get("MISP_ENABLED", "true").lower() == "false":
            return None

    # ── Source 3: os.environ (last resort) ───────────────────────────────────
    if not url or not api_key:
        import os as _os
        url     = url     or _os.environ.get("MISP_URL",     "").strip().rstrip("/")
        api_key = api_key or _os.environ.get("MISP_API_KEY", "").strip()
        if not mode or mode == "disabled":
            mode = _os.environ.get("MISP_MODE", "local").lower()

    # ── Final check ───────────────────────────────────────────────────────────
    if mode == "disabled":
        return None
    if not url or not api_key:
        log.debug("[benchmark] MISP: mode=%s but url/apiKey not found in any source", mode)
        return None

    return {"url": url, "apiKey": api_key, "mode": mode}"""


# ══════════════════════════════════════════════════════════════════════════════
# PATCH 2 — system/routes.py : _sync_misp_to_siem_env() also writes ai_settings
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM = ROOT / "backend/blueprints/system/routes.py"

# We search for the line that writes MISP_ENABLED to cysiemstack.env —
# that's the last write in _sync_misp_to_siem_env(). We insert the
# ai_settings.json update immediately after it.
# The exact anchor is the env_utils.set_env_var call for MISP_ENABLED.

SYSTEM_FIND = """\
def _sync_misp_to_siem_env(misp_cfg: dict) -> None:
    \"\"\"Write MISP settings to cysiemstack.env so the correlation engine picks them up.\"\"\""""

# We find the function and append the ai_settings sync block inside it.
# Strategy: search for the last env_utils call in the function and add after it.
# Because the exact body may vary, we use a unique closing line as anchor.

SYSTEM_ANCHOR = "    env_utils.set_env_var(SIEM_ENV, \"MISP_ENABLED\","

SYSTEM_ANCHOR_REPLACE = """\
    env_utils.set_env_var(SIEM_ENV, "MISP_ENABLED","""

SYSTEM_AFTER = """\

    # ── Also write url + apiKey into ai_settings.json ─────────────────────────
    # The benchmark module reads from ai_settings.json (Flask context).
    # The correlation engine reads from cysiemstack.env (systemd context).
    # Both must stay in sync whenever MISP settings are saved from the portal.
    try:
        import json as _json
        from pathlib import Path as _Path
        _ai_file = _Path("/opt/cycentra/ai_settings.json")
        _ai_data = _json.loads(_ai_file.read_text()) if _ai_file.exists() else {}
        _ai_data["misp"] = {
            "mode":   misp_cfg.get("mode", "disabled"),
            "url":    misp_cfg.get("url", ""),
            "apiKey": misp_cfg.get("apiKey", ""),
        }
        _ai_file.write_text(_json.dumps(_ai_data, indent=4))
        log.info("[system] MISP config synced to ai_settings.json")
    except Exception as _sync_err:
        log.warning("[system] Could not sync MISP to ai_settings.json: %s", _sync_err)"""


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _str_replace(path, find, replace, label):
    content = path.read_text()
    if find not in content:
        print(f"  ✗  {label} — search string not found")
        return False
    path.write_text(content.replace(find, replace, 1))
    print(f"  ✓  {label}")
    return True


def _insert_after(path, anchor, insertion, label):
    """Insert `insertion` immediately after the first occurrence of `anchor`."""
    content = path.read_text()
    if anchor not in content:
        print(f"  ✗  {label} — anchor not found")
        # Print context lines to help diagnose
        for i, line in enumerate(content.splitlines(), 1):
            if "MISP_ENABLED" in line or "misp_enabled" in line.lower():
                print(f"     line {i}: {line[:100]}")
        return False
    # Find the end of the line containing the anchor
    idx  = content.index(anchor)
    eol  = content.index("\n", idx)
    new  = content[:eol] + insertion + content[eol:]
    path.write_text(new)
    print(f"  ✓  {label}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ok = True

    print("\n── Patch 1: benchmark/routes.py — _read_misp_config() fallback chain")
    if not BENCH.exists():
        print(f"  ✗  {BENCH} not found — run from repo root")
        ok = False
    elif "_read_cysiemstack_env" in BENCH.read_text():
        print("  ✓  Already patched")
    else:
        ok &= _str_replace(BENCH, BENCH_FIND, BENCH_REPLACE,
                           "replace _read_misp_config with fallback chain")

    print("\n── Patch 2: system/routes.py — sync MISP to ai_settings.json on save")
    if not SYSTEM.exists():
        print(f"  ✗  {SYSTEM} not found — run from repo root")
        ok = False
    elif "MISP config synced to ai_settings.json" in SYSTEM.read_text():
        print("  ✓  Already patched")
    else:
        ok &= _insert_after(SYSTEM, SYSTEM_ANCHOR, SYSTEM_AFTER,
                            "insert ai_settings sync after MISP_ENABLED write")

    print()
    if ok:
        print("✅  Both patches applied.")
        print()
        print("  MISP config fallback order (benchmark widget):")
        print("    1. /opt/cycentra/ai_settings.json  → misp.url / misp.apiKey")
        print("    2. /opt/cycentra/cysiemstack.env   → MISP_URL / MISP_API_KEY")
        print("    3. os.environ                      → MISP_URL / MISP_API_KEY")
        print()
        print("  Going forward: saving MISP in the portal writes to BOTH files.")
        print()
        print("  Syntax check:")
        print("    python3 -m py_compile backend/blueprints/benchmark/routes.py && echo OK")
        print("    python3 -m py_compile backend/blueprints/system/routes.py    && echo OK")
        print()
        print("  Then:")
        print("    git add backend/blueprints/benchmark/routes.py backend/blueprints/system/routes.py")
        print('    git commit -m "fix: MISP config fallback chain + sync ai_settings on portal save"')
        print("    git push")
    else:
        print("❌  Some patches failed — check output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
