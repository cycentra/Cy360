"""
PATCH 7 — Fix Threat Intelligence score showing 0
==================================================
File patched: backend/blueprints/benchmark/routes.py

ROOT CAUSE
----------
_collect_threat_intel_score() calls get_misp_config() from core.helpers.
That function does not exist. The ImportError is caught silently and the
collector returns {"score": None} → widget shows 0.

WHERE MISP CREDENTIALS ACTUALLY LIVE
-------------------------------------
/opt/cycentra/ai_settings.json → key "misp" → written by System Settings UI
Same file used by iris_connector.py and ai_router.py.

Structure:
{
  "misp": {
    "mode":   "local" | "cloud" | "disabled",
    "url":    "http://...",
    "apiKey": "...",
    ...
  }
}

The cysiemstack.env equivalents (misp_url, misp_api_key, misp_enabled) are
written by system/routes.py _sync_misp_to_siem_env() for the engine process
but are NOT available in the Flask backend process context.

FIX
---
Read ai_settings.json directly, exactly as iris_connector.py does.
Then query three MISP REST endpoints with requests (sync, not httpx):
  GET  /feeds              → enabled feed count    → 0-40 pts
  POST /attributes/statistics/type → total IOC count → 0-30 pts
  POST /attributes/restSearch (count, to_ids=1)    → actionable ratio → 0-30 pts

Run from repo root:
    python3 benchmark-patch/PATCH_7_fix_threat_intel.py
"""

import pathlib, sys

TARGET = pathlib.Path("backend/blueprints/benchmark/routes.py")

# ── Exact live function text (verified from project knowledge) ─────────────────

FIND = '''\
def _collect_threat_intel_score() -> dict:
    """
    Threat intelligence coverage score (0-100) via direct MISP REST API.

    Uses get_misp_config() from core.helpers — the single source of truth
    for MISP credentials (handles cloud/local/disabled modes).

    Sub-signals:
      a) Enabled feed count      → 0-40 pts  (3+ feeds = full 40)
      b) Total IOC attribute count → 0-30 pts (10,000+ attrs = full 30)
      c) Active attribute ratio    → 0-30 pts (to_ids=true / total)
    """
    misp_cfg = get_misp_config()
    if not misp_cfg:
        return {"score": None, "stale": False,
                "detail": "MISP disabled — configure in System Settings → CyMISP"}

    url     = misp_cfg["url"].rstrip("/")
    api_key = misp_cfg["apiKey"]
    headers = {
        "Authorization": api_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    timeout = 8
    verify  = False  # MISP often runs with a self-signed cert

    # ── a) Feed count ─────────────────────────────────────────────────────────
    feed_score   = 0
    feed_detail  = "feeds unavailable"
    try:
        r = _req.get(f"{url}/feeds/index", headers=headers,
                     timeout=timeout, verify=verify)
        if r.status_code == 200:
            feeds   = r.json() if isinstance(r.json(), list) else []
            enabled = sum(1 for f in feeds if f.get("enabled"))
            # 3 feeds = full credit; proportional below 3
            feed_score  = min(40, round((enabled / 3) * 40))
            feed_detail = f"{enabled} enabled feeds"
    except Exception as exc:
        log.debug("[benchmark] MISP feeds error: %s", exc)

    # ── b) Total attribute count ──────────────────────────────────────────────
    attr_score  = 0
    attr_detail = "attribute count unavailable"
    try:
        r = _req.post(f"{url}/attributes/statistics/type",
                      headers=headers, json={},
                      timeout=timeout, verify=verify)
        if r.status_code == 200:
            stats = r.json()
            # stats is {type_name: count, ...}
            total_attrs = sum(int(v) for v in stats.values() if str(v).isdigit())
            # 10,000 attributes = full 30 pts
            attr_score  = min(30, round((total_attrs / 10_000) * 30))
            attr_detail = f"{total_attrs:,} total IOC attributes"
    except Exception as exc:
        log.debug("[benchmark] MISP attribute statistics error: %s", exc)

    # ── c) Active (to_ids=true) ratio ─────────────────────────────────────────
    active_score  = 0
    active_detail = ""
    try:
        # Get count with to_ids=1
        r_active = _req.post(
            f"{url}/attributes/restSearch",
            headers=headers,
            json={"returnFormat": "count", "to_ids": 1},
            timeout=timeout, verify=verify,
        )
        r_total = _req.post(
            f"{url}/attributes/restSearch",
            headers=headers,
            json={"returnFormat": "count"},
            timeout=timeout, verify=verify,
        )
        if r_active.status_code == 200 and r_total.status_code == 200:
            active_n = int(r_active.json().get("response", {}).get("count", 0))
            total_n  = int(r_total.json().get("response",  {}).get("count", 1))
            ratio    = active_n / max(total_n, 1)
            active_score  = min(30, round(ratio * 30))
            active_detail = f"{ratio*100:.0f}% actionable (to_ids)"
    except Exception as exc:
        log.debug("[benchmark] MISP active ratio error: %s", exc)

    composite = min(100, feed_score + attr_score + active_score)
    parts     = [p for p in [feed_detail, attr_detail, active_detail] if p]

    return {
        "score":  composite,
        "stale":  False,
        "detail": " · ".join(parts),
        "mode":   misp_cfg.get("mode", "unknown"),
    }'''

REPLACE = '''\
def _read_misp_config() -> dict | None:
    """
    Read MISP credentials from /opt/cycentra/ai_settings.json.

    This is the single authoritative source for MISP config in the Flask
    backend context — same approach used by iris_connector.py.
    The cysiemstack.env equivalents are written for the engine process only
    and are not available in os.environ inside the Flask process.

    Returns a dict with keys: url, apiKey, mode
    Returns None if MISP is disabled or credentials are missing.
    """
    _AI_SETTINGS = pathlib.Path("/opt/cycentra/ai_settings.json")
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

    return {"url": url, "apiKey": api_key, "mode": mode}


def _collect_threat_intel_score() -> dict:
    """
    Threat intelligence coverage score (0-100).

    Reads MISP credentials from /opt/cycentra/ai_settings.json directly
    (same source as iris_connector.py — ai_settings.json is written by the
    System Settings UI and is available to the Flask backend process).

    Sub-signals:
      a) Enabled feed count        → 0-40 pts  (3+ feeds = full 40)
      b) Total IOC attribute count → 0-30 pts  (10,000+ attrs = full 30)
      c) Actionable ratio (to_ids) → 0-30 pts
    """
    import pathlib as _pl
    misp_cfg = _read_misp_config()
    if not misp_cfg:
        return {"score": None, "stale": False,
                "detail": "MISP disabled or not configured — enable in System Settings → CyMISP"}

    url     = misp_cfg["url"]
    api_key = misp_cfg["apiKey"]
    headers = {
        "Authorization": api_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    timeout = 8
    verify  = False   # MISP commonly uses self-signed certs

    # ── a) Feed count — GET /feeds/index ──────────────────────────────────────
    feed_score  = 0
    feed_detail = "feeds unavailable"
    enabled_n   = 0
    try:
        r = _req.get(f"{url}/feeds/index", headers=headers,
                     timeout=timeout, verify=verify)
        if r.status_code == 200:
            feeds     = r.json() if isinstance(r.json(), list) else []
            enabled_n = sum(1 for f in feeds if f.get("enabled"))
            total_n   = len(feeds)
            # 3+ enabled feeds = full 40 pts; proportional below 3
            feed_score  = min(40, round((enabled_n / max(3, 1)) * 40))
            feed_detail = f"{enabled_n}/{total_n} feeds enabled"
        else:
            log.debug("[benchmark] MISP /feeds/index returned HTTP %s", r.status_code)
    except Exception as exc:
        log.debug("[benchmark] MISP feeds error: %s", exc)

    # ── b) Total attribute count — POST /attributes/statistics/type ───────────
    attr_score  = 0
    attr_detail = "attribute count unavailable"
    total_attrs = 0
    try:
        r = _req.post(f"{url}/attributes/statistics/type",
                      headers=headers, json={},
                      timeout=timeout, verify=verify)
        if r.status_code == 200:
            stats = r.json()
            # Response is {type_name: count_str, ...}
            total_attrs = sum(
                int(v) for v in stats.values()
                if str(v).isdigit()
            )
            # 10,000 attributes = full 30 pts
            attr_score  = min(30, round((total_attrs / 10_000) * 30))
            attr_detail = f"{total_attrs:,} IOC attributes"
        else:
            log.debug("[benchmark] MISP /attributes/statistics returned HTTP %s",
                      r.status_code)
    except Exception as exc:
        log.debug("[benchmark] MISP attribute statistics error: %s", exc)

    # ── c) Actionable ratio — to_ids=1 vs total ───────────────────────────────
    active_score  = 0
    active_detail = ""
    try:
        r_active = _req.post(
            f"{url}/attributes/restSearch",
            headers=headers,
            json={"returnFormat": "count", "to_ids": 1},
            timeout=timeout, verify=verify,
        )
        r_total = _req.post(
            f"{url}/attributes/restSearch",
            headers=headers,
            json={"returnFormat": "count"},
            timeout=timeout, verify=verify,
        )
        if r_active.status_code == 200 and r_total.status_code == 200:
            active_n = int(r_active.json().get("response", {}).get("count", 0))
            total_n  = int(r_total.json().get("response",  {}).get("count", 1))
            ratio    = active_n / max(total_n, 1)
            active_score  = min(30, round(ratio * 30))
            active_detail = f"{ratio*100:.0f}% actionable"
    except Exception as exc:
        log.debug("[benchmark] MISP active ratio error: %s", exc)

    composite = min(100, feed_score + attr_score + active_score)
    parts     = [p for p in [feed_detail, attr_detail, active_detail] if p]

    return {
        "score":        composite,
        "stale":        False,
        "detail":       " · ".join(parts),
        "mode":         misp_cfg.get("mode", "unknown"),
        "feeds_enabled": enabled_n,
        "total_attrs":  total_attrs,
    }'''


def main():
    if not TARGET.exists():
        print(f"✗  {TARGET} not found — run from repo root.")
        sys.exit(1)

    content = TARGET.read_text()

    if "_read_misp_config" in content:
        print("✓  Already patched.")
        sys.exit(0)

    if FIND not in content:
        print("✗  Search string not found. Lines containing 'misp' or 'threat_intel':")
        for i, line in enumerate(content.splitlines(), 1):
            if "misp" in line.lower() or "threat_intel" in line.lower():
                print(f"   line {i}: {line[:100]}")
        sys.exit(1)

    TARGET.write_text(content.replace(FIND, REPLACE, 1))
    print(f"✓  Patched {TARGET}")
    print()
    print("MISP credentials now read from: /opt/cycentra/ai_settings.json")
    print("Same source as iris_connector.py — no get_misp_config() needed.")
    print()
    print("Restart backend:")
    print("  Local:      pkill -f 'python3 app.py'; cd backend && python3 app.py &")
    print("  Production: sudo systemctl restart cycentra-backend")
    print()
    print("Then open Posture Benchmark — Threat Intel widget should show a real score.")


if __name__ == "__main__":
    main()
