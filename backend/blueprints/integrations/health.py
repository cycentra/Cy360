"""
blueprints/integrations/health.py
===================================
Integration health monitor for CyCentra 360.

Checks each configured integration on a schedule (default: every 5 min).
When an integration is down or stops ingesting it auto-creates a synthetic
incident and opens a CyCase.  When it recovers the incident is resolved.

Integrations monitored
  - wazuh          : Wazuh manager API reachability + active-agent count
  - siem_engine    : CySIEM correlation engine /health
  - cymind         : CyMind AI /api/v1/health (only if enabled)
  - misp           : MISP /servers/getPyMISPVersion.json (only if not disabled)
  - cysoar         : CySOAR Node-RED (only if module installed)
  - marketplace_*  : Office 365 / GCP log ingest gaps (only if integration installed)
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import psycopg2
import psycopg2.extras
import requests

log = logging.getLogger("cycentra.integrations.health")

_INGEST_WINDOW_MIN = int(os.environ.get("INTEGRATION_HEALTH_INGEST_WINDOW", "15"))
_MARKETPLACE_STATE  = Path("/var/ossec/etc/cycentra_marketplace.json")
_AI_SETTINGS_FILE   = Path(os.environ.get("AI_SETTINGS_FILE", "/opt/cycentra/ai_settings.json"))
_MODULES_STATE      = Path("/opt/cycentra/modules_state.json")
_REQUEST_TIMEOUT    = 8  # seconds per health-check HTTP call


# ── DB helpers ────────────────────────────────────────────────────────────────

def _corr_db_url() -> str:
    for var in ("CORRELATION_DB_URL", "CYCENTRA_DB_URL"):
        url = os.environ.get(var, "").strip()
        if url:
            return url
    try:
        env_file = Path("/opt/cycentra/cysiemstack.env")
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                if k.strip() == "DATABASE_URL":
                    raw = v.strip().strip('"').strip("'")
                    return raw.replace("postgresql+asyncpg://", "postgresql://")
    except Exception:
        pass
    return "postgresql://corruser:changeme@127.0.0.1:5433/correlation"


def _db():
    conn = psycopg2.connect(_corr_db_url())
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def ensure_health_tables():
    """Create integration_health_status if it doesn't exist. Safe to call repeatedly."""
    ddl = """
    CREATE TABLE IF NOT EXISTS integration_health_status (
        integration_name      VARCHAR(100) PRIMARY KEY,
        display_name          VARCHAR(200),
        status                VARCHAR(20)  NOT NULL DEFAULT 'unknown',
        last_checked          TIMESTAMPTZ,
        last_ok               TIMESTAMPTZ,
        error_message         TEXT,
        ingest_gap_minutes    INTEGER,
        incident_id           VARCHAR(100),
        consecutive_failures  INTEGER NOT NULL DEFAULT 0,
        metadata              JSONB
    );
    """
    try:
        conn = _db()
        cur = conn.cursor()
        cur.execute(ddl)
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error("ensure_health_tables failed: %s", exc)


def _upsert_status(name: str, display_name: str, status: str,
                   error: Optional[str], ingest_gap: Optional[int],
                   metadata: Optional[dict]) -> dict:
    """Persist status row; return previous row so callers can diff."""
    now = datetime.now(timezone.utc)
    conn = _db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT status, incident_id, consecutive_failures, last_ok FROM integration_health_status WHERE integration_name = %s",
        [name],
    )
    prev = cur.fetchone() or {}

    last_ok_val = now if status == "ok" else (prev.get("last_ok") if prev else None)
    consec = 0 if status == "ok" else (int(prev.get("consecutive_failures") or 0) + 1)

    cur.execute(
        """
        INSERT INTO integration_health_status
            (integration_name, display_name, status, last_checked, last_ok,
             error_message, ingest_gap_minutes, incident_id, consecutive_failures, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (integration_name) DO UPDATE SET
            display_name         = EXCLUDED.display_name,
            status               = EXCLUDED.status,
            last_checked         = EXCLUDED.last_checked,
            last_ok              = EXCLUDED.last_ok,
            error_message        = EXCLUDED.error_message,
            ingest_gap_minutes   = EXCLUDED.ingest_gap_minutes,
            consecutive_failures = EXCLUDED.consecutive_failures,
            metadata             = EXCLUDED.metadata
        """,
        [name, display_name, status, now, last_ok_val,
         error, ingest_gap, prev.get("incident_id"), consec,
         json.dumps(metadata or {})],
    )
    conn.commit()

    cur.execute(
        "SELECT incident_id FROM integration_health_status WHERE integration_name = %s", [name]
    )
    row = cur.fetchone() or {}
    conn.close()
    return {"prev_status": prev.get("status", "unknown"),
            "incident_id": row.get("incident_id"),
            "consecutive_failures": consec}


def _set_incident_id(name: str, incident_id: Optional[str]):
    try:
        conn = _db()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE integration_health_status SET incident_id = %s WHERE integration_name = %s",
            [incident_id, name],
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error("_set_incident_id failed for %s: %s", name, exc)


# ── Incident / case management ────────────────────────────────────────────────

def _incident_id_for(name: str) -> str:
    return "INTEG-" + hashlib.sha256(name.encode()).hexdigest()[:8].upper()


def _raise_integration_incident(name: str, display_name: str, status: str, error: str,
                                  ingest_gap: Optional[int]):
    """Create a synthetic incident and open a CyCase when integration is unhealthy."""
    inc_id = _incident_id_for(name)
    sev    = "high" if status == "down" else "medium"

    notes_parts = [f"Integration Health Alert: {display_name} is {status.upper()}"]
    if error:
        notes_parts.append(f"Error: {error}")
    if ingest_gap is not None:
        notes_parts.append(f"No events ingested for {ingest_gap} minutes (threshold: {_INGEST_WINDOW_MIN} min)")
    notes_parts.append(f"Detected at: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    notes = "\n".join(notes_parts)

    try:
        conn = _db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO incidents
                (id, first_seen, last_seen, updated_at, status, severity,
                 alert_count, categories, notes)
            VALUES (%s, NOW(), NOW(), NOW(), 'investigating', %s, 0,
                    ARRAY['integration_health'], %s)
            ON CONFLICT (id) DO UPDATE SET
                last_seen   = NOW(),
                updated_at  = NOW(),
                notes       = EXCLUDED.notes,
                status      = CASE WHEN incidents.status = 'resolved'
                                   THEN 'investigating'
                                   ELSE incidents.status END
        """, [inc_id, sev, notes])
        conn.commit()

        from blueprints.cases.service import open_case
        open_case(conn, inc_id, "integration-monitor", case_type="operational")
        conn.commit()
        conn.close()

        _set_incident_id(name, inc_id)
        log.warning("integration-health: raised incident %s for %s (%s)", inc_id, name, status)
    except Exception as exc:
        log.error("_raise_integration_incident failed for %s: %s", name, exc)


def _resolve_integration_incident(name: str, display_name: str):
    """Resolve the open incident when an integration recovers."""
    inc_id = _incident_id_for(name)
    try:
        conn = _db()
        cur  = conn.cursor()
        cur.execute("SELECT status FROM incidents WHERE id = %s", [inc_id])
        row = cur.fetchone()
        if row and row["status"] not in ("resolved", None):
            cur.execute("""
                UPDATE incidents
                SET status     = 'resolved',
                    updated_at = NOW()
                WHERE id = %s
            """, [inc_id])
            cur.execute("""
                INSERT INTO case_comments (incident_id, author_email, body, is_system)
                VALUES (%s, 'system', %s, TRUE)
            """, [inc_id, f"Integration {display_name} has RECOVERED. Auto-resolved by health monitor."])
            conn.commit()
            log.info("integration-health: resolved incident %s for %s (recovered)", inc_id, name)
        conn.close()
        _set_incident_id(name, None)
    except Exception as exc:
        log.error("_resolve_integration_incident failed for %s: %s", name, exc)


# ── Ingest gap helper ─────────────────────────────────────────────────────────

def _last_alert_age_minutes(rule_groups_filter: Optional[list] = None) -> Optional[int]:
    """Return minutes since last alert matching the filter, or None on error."""
    try:
        conn = _db()
        cur  = conn.cursor()
        if rule_groups_filter:
            placeholders = ",".join(["%s"] * len(rule_groups_filter))
            cur.execute(
                f"SELECT MAX(timestamp) FROM alerts WHERE rule_groups && ARRAY[{placeholders}]::varchar[]",
                rule_groups_filter,
            )
        else:
            cur.execute("SELECT MAX(timestamp) FROM alerts")
        row = cur.fetchone()
        conn.close()
        if not row or row[0] is None:
            return None
        last_ts = row[0]
        if last_ts.tzinfo is None:
            last_ts = last_ts.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - last_ts
        return int(delta.total_seconds() / 60)
    except Exception:
        return None


# ── Per-integration check functions ──────────────────────────────────────────

def check_wazuh() -> dict:
    """Check Wazuh manager API + alert ingest gap."""
    wazuh_api   = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
    wazuh_user  = os.environ.get("WAZUH_API_USER", "wazuh-wui")
    wazuh_pass  = os.environ.get("WAZUH_API_PASSWORD", "")
    name        = "wazuh"
    display     = "Wazuh SIEM"

    # Step 1: API reachability
    try:
        token_resp = requests.post(
            f"{wazuh_api}/security/user/authenticate",
            auth=(wazuh_user, wazuh_pass),
            verify=False, timeout=_REQUEST_TIMEOUT,
        )
        if token_resp.status_code not in (200, 201):
            return {"name": name, "display": display,
                    "status": "down",
                    "error": f"Wazuh auth returned HTTP {token_resp.status_code}",
                    "ingest_gap": None}
    except requests.exceptions.RequestException as exc:
        return {"name": name, "display": display, "status": "down",
                "error": str(exc), "ingest_gap": None}

    # Step 2: Alert ingest gap
    gap = _last_alert_age_minutes()
    if gap is not None and gap > _INGEST_WINDOW_MIN:
        return {"name": name, "display": display, "status": "degraded",
                "error": f"No alerts ingested for {gap} min", "ingest_gap": gap}

    return {"name": name, "display": display, "status": "ok",
            "error": None, "ingest_gap": gap}


def check_siem_engine() -> dict:
    """Check CySIEM correlation engine /health."""
    engine_url = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100")
    name       = "siem_engine"
    display    = "CySIEM Correlation Engine"
    try:
        r = requests.get(f"{engine_url}/health", timeout=_REQUEST_TIMEOUT)
        if r.status_code == 200:
            return {"name": name, "display": display, "status": "ok",
                    "error": None, "ingest_gap": None}
        return {"name": name, "display": display, "status": "degraded",
                "error": f"HTTP {r.status_code}", "ingest_gap": None}
    except requests.exceptions.RequestException as exc:
        return {"name": name, "display": display, "status": "down",
                "error": str(exc), "ingest_gap": None}


def check_cymind() -> dict:
    """Check CyMind AI health endpoint (only if enabled in ai_settings.json)."""
    name    = "cymind"
    display = "CyMind AI"
    try:
        settings = json.loads(_AI_SETTINGS_FILE.read_text()) if _AI_SETTINGS_FILE.exists() else {}
    except Exception:
        settings = {}
    cymind_cfg = settings.get("cymind_integration", {})
    if not cymind_cfg.get("enabled"):
        return {"name": name, "display": display, "status": "skipped",
                "error": "CyMind integration is disabled", "ingest_gap": None}
    cymind_url = cymind_cfg.get("cymindUrl", "").rstrip("/")
    if not cymind_url:
        return {"name": name, "display": display, "status": "skipped",
                "error": "CyMind URL not configured", "ingest_gap": None}
    try:
        r = requests.get(f"{cymind_url}/api/v1/health", timeout=_REQUEST_TIMEOUT)
        if r.status_code == 200:
            return {"name": name, "display": display, "status": "ok",
                    "error": None, "ingest_gap": None}
        return {"name": name, "display": display, "status": "down",
                "error": f"HTTP {r.status_code}", "ingest_gap": None}
    except requests.exceptions.RequestException as exc:
        return {"name": name, "display": display, "status": "down",
                "error": str(exc), "ingest_gap": None}


def check_misp() -> dict:
    """Check MISP threat intelligence connectivity."""
    name    = "misp"
    display = "MISP Threat Intelligence"
    try:
        from core.helpers import get_misp_config
        cfg = get_misp_config()
    except Exception:
        cfg = None
    if not cfg or cfg.get("mode") == "disabled":
        return {"name": name, "display": display, "status": "skipped",
                "error": "MISP is disabled or not configured", "ingest_gap": None}
    misp_url = cfg.get("url", "").rstrip("/")
    api_key  = cfg.get("apiKey", "")
    try:
        r = requests.get(
            f"{misp_url}/servers/getPyMISPVersion.json",
            headers={"Authorization": api_key, "Accept": "application/json"},
            verify=False, timeout=_REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            return {"name": name, "display": display, "status": "ok",
                    "error": None, "ingest_gap": None}
        return {"name": name, "display": display, "status": "down",
                "error": f"HTTP {r.status_code}", "ingest_gap": None}
    except requests.exceptions.RequestException as exc:
        return {"name": name, "display": display, "status": "down",
                "error": str(exc), "ingest_gap": None}


def check_cysoar() -> dict:
    """Check CySOAR (Node-RED) — only if the module is installed."""
    name    = "cysoar"
    display = "CySOAR Automation"
    installed = False
    try:
        if _MODULES_STATE.exists():
            state = json.loads(_MODULES_STATE.read_text())
            installed = bool(state.get("cysoar", {}).get("installed"))
    except Exception:
        pass
    if not installed:
        return {"name": name, "display": display, "status": "skipped",
                "error": "CySOAR module is not installed", "ingest_gap": None}
    soar_url = os.environ.get("CYSOAR_URL", "http://127.0.0.1:1880").rstrip("/")
    try:
        r = requests.get(soar_url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
        if r.status_code < 500:
            return {"name": name, "display": display, "status": "ok",
                    "error": None, "ingest_gap": None}
        return {"name": name, "display": display, "status": "down",
                "error": f"HTTP {r.status_code}", "ingest_gap": None}
    except requests.exceptions.RequestException as exc:
        return {"name": name, "display": display, "status": "down",
                "error": str(exc), "ingest_gap": None}


_CUSTOM_CATALOG = Path("/opt/cycentra/marketplace_custom.json")

# Builtin baseline: well-known log-source integrations from the cloud catalog.
# Any integration NOT listed here can still be monitored if its marketplace catalog
# item carries a `health_config` block (see _build_marketplace_health_map).
_BUILTIN_LOG_SOURCE_MAP = {
    "office365": {
        "display": "Office 365 Log Ingest",
        "groups":  ["office365", "ms365"],
    },
    "google-cloud": {
        "display": "Google Cloud Log Ingest",
        "groups":  ["gcp", "google-cloud", "gcp-pubsub"],
    },
    "aws": {
        "display": "AWS CloudTrail Log Ingest",
        "groups":  ["aws", "amazon", "cloudtrail"],
    },
    "github": {
        "display": "GitHub Audit Log Ingest",
        "groups":  ["github"],
    },
    "azure": {
        "display": "Microsoft Azure Log Ingest",
        "groups":  ["azure", "ms-azure"],
    },
}


def _build_marketplace_health_map() -> dict:
    """
    Merge the builtin map with health_config blocks declared in the custom catalog.

    Custom catalog items can declare:
        "health_config": {
            "type": "ingest_gap",          # or "http"
            "rule_groups": ["my-group"],   # for ingest_gap type
            "endpoint_url": "https://...", # for http type
            "display_name": "My Integration Health"
        }

    This makes health monitoring automatically extensible to any new integration
    installed via the marketplace without code changes.
    """
    merged = dict(_BUILTIN_LOG_SOURCE_MAP)
    try:
        if not _CUSTOM_CATALOG.exists():
            return merged
        items = json.loads(_CUSTOM_CATALOG.read_text())
        for item in items:
            item_id = item.get("id", "")
            hcfg    = item.get("health_config")
            if not item_id or not hcfg:
                continue
            if item_id in merged:
                continue  # builtin takes precedence
            htype = hcfg.get("type", "ingest_gap")
            if htype == "ingest_gap" and hcfg.get("rule_groups"):
                merged[item_id] = {
                    "display": hcfg.get("display_name") or item.get("name") or item_id,
                    "groups":  hcfg["rule_groups"],
                }
            elif htype == "http" and hcfg.get("endpoint_url"):
                merged[item_id] = {
                    "display":      hcfg.get("display_name") or item.get("name") or item_id,
                    "groups":       None,
                    "endpoint_url": hcfg["endpoint_url"],
                }
    except Exception as exc:
        log.warning("_build_marketplace_health_map: %s", exc)
    return merged


def check_marketplace_integrations() -> list:
    """
    Check health for all installed marketplace log-source integrations.

    Monitors both builtin well-known integrations and any custom integrations
    added via the marketplace that declare a `health_config` in their catalog item.
    Supports two check types:
      - ingest_gap : queries the alerts table for recent events by rule_groups
      - http       : HTTP GET to endpoint_url, expects non-5xx response
    """
    results = []
    try:
        if not _MARKETPLACE_STATE.exists():
            return []
        state     = json.loads(_MARKETPLACE_STATE.read_text())
        installed = state.get("installed", [])
    except Exception:
        return []

    health_map = _build_marketplace_health_map()

    for item_id in installed:
        if item_id not in health_map:
            continue
        cfg      = health_map[item_id]
        int_name = f"marketplace_{item_id.replace('-', '_')}"
        display  = cfg["display"]

        # HTTP endpoint check (custom integrations with endpoint_url)
        if cfg.get("endpoint_url"):
            try:
                r = requests.get(cfg["endpoint_url"], timeout=_REQUEST_TIMEOUT)
                if r.status_code < 500:
                    results.append({"name": int_name, "display": display,
                                    "status": "ok", "error": None, "ingest_gap": None})
                else:
                    results.append({"name": int_name, "display": display,
                                    "status": "down",
                                    "error": f"HTTP {r.status_code}",
                                    "ingest_gap": None})
            except requests.exceptions.RequestException as exc:
                results.append({"name": int_name, "display": display,
                                "status": "down", "error": str(exc), "ingest_gap": None})
            continue

        # Ingest gap check (log-source integrations)
        gap = _last_alert_age_minutes(rule_groups_filter=cfg.get("groups"))
        if gap is None:
            results.append({"name": int_name, "display": display,
                            "status": "degraded",
                            "error": "No events ever received from this integration",
                            "ingest_gap": None})
        elif gap > _INGEST_WINDOW_MIN:
            results.append({"name": int_name, "display": display,
                            "status": "degraded",
                            "error": f"No events for {gap} min",
                            "ingest_gap": gap})
        else:
            results.append({"name": int_name, "display": display,
                            "status": "ok", "error": None, "ingest_gap": gap})
    return results


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_all_checks() -> list:
    """
    Run all integration health checks, persist results, and raise/resolve incidents.
    Returns list of result dicts.  Safe to call from APScheduler background thread.
    """
    try:
        ensure_health_tables()
    except Exception as exc:
        log.error("integration-health: ensure_health_tables failed: %s", exc)
        return []

    checks = [
        check_siem_engine(),
        check_wazuh(),
        check_cymind(),
        check_misp(),
        check_cysoar(),
    ]
    checks += check_marketplace_integrations()

    results = []
    for c in checks:
        name    = c["name"]
        display = c["display"]
        status  = c["status"]
        error   = c.get("error")
        gap     = c.get("ingest_gap")

        if status == "skipped":
            results.append({**c, "skipped": True})
            continue

        state = _upsert_status(name, display, status, error, gap, c.get("metadata"))

        if status in ("down", "degraded"):
            _raise_integration_incident(name, display, status, error or "", gap)
        elif status == "ok" and state.get("incident_id"):
            _resolve_integration_incident(name, display)

        results.append({**c, "skipped": False,
                        "consecutive_failures": state.get("consecutive_failures", 0)})
        log.debug("integration-health: %s → %s", name, status)

    return results
