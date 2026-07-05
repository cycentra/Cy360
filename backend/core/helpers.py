"""
core/helpers.py
===============
Shared utility functions used across multiple blueprints.
Import individual functions — do not import * from here.
"""

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests as http_requests
from flask import request

from core.config import AUTH_LOG_FILE, CORS_ALLOWED_ORIGINS

_log = logging.getLogger(__name__)


# ── subprocess runner ──────────────────────────────────────────────────────────

def run(cmd, cwd=None, timeout=300):
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, cwd=cwd, timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


# ── URL-encode helper ─────────────────────────────────────────────────────────

def enc(s):
    """URL-encode a string for use in redirect query params."""
    return http_requests.utils.quote(str(s), safe='')


# ── Auth event logger ─────────────────────────────────────────────────────────

def auth_event(event_type: str, email: str, client_id: str = "",
               result: str = "success", detail: str = "", ip: str = ""):
    """
    Append a JSON auth event to AUTH_LOG_FILE.
    Wazuh agent tails this file for security monitoring.
    """
    # Lazy import to avoid circular dependency at module load
    from blueprints.rbac.manager import get_user_role

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type":      event_type,
        "email":     email,
        "client_id": client_id,
        "result":    result,
        "role":      get_user_role(email) if email else "unknown",
        "ip":        ip or (request.remote_addr if request else ""),
        "detail":    detail,
    }
    try:
        AUTH_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUTH_LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass  # never raise from logging — audit failures must not break auth


# ── CORS headers ──────────────────────────────────────────────────────────────

def add_cors_headers(response):
    """Add CORS headers to a Flask response object."""
    origin = request.headers.get('Origin', '')
    if origin in CORS_ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = \
        'Content-Type, Authorization, X-CyCentra-AdminKey'
    response.headers['Access-Control-Allow-Methods'] = \
        'GET, POST, PATCH, DELETE, OPTIONS'
    return response


# ── Tenant ID generator ────────────────────────────────────────────────────────

def generate_tenant_id(domain: str) -> str:
    """Derive a short, filesystem-safe tenant ID from a domain name."""
    clean  = re.sub(r'^https?://', '', domain)
    clean  = re.sub(r'^www\.', '', clean)
    prefix = re.sub(r'[^a-z0-9]', '', clean.lower())[:8]
    return f"{prefix}-ten-01"


# ── CyTIM client ───────────────────────────────────────────────────────────────

class CyTIMClient:
    """
    Thin client for CyTIM threat intelligence module.
    Used by blueprints instead of calling MISP/VT directly when CyTIM is deployed.
    """

    def __init__(self, base_url: str, api_key: str, timeout: int = 15):
        self._base = base_url.rstrip("/")
        self._headers = {"X-CyTIM-Key": api_key, "Content-Type": "application/json"}
        self._timeout = timeout

    def enrich(self, ioc_type: str, ioc_value: str) -> Optional[dict]:
        """
        Returns enrichment dict {score, confidence, tags, sources, cache_hit}
        or None if CyTIM is unreachable or IOC not found.
        """
        try:
            r = http_requests.get(
                f"{self._base}/api/cytim/enrich",
                headers=self._headers,
                params={"type": ioc_type, "value": ioc_value},
                timeout=self._timeout,
            )
            if r.status_code == 200:
                return r.json()
            _log.warning("CyTIM enrich %s/%s → HTTP %s", ioc_type, ioc_value, r.status_code)
            return None
        except Exception as e:
            _log.warning("CyTIM unreachable: %s", e)
            return None

    def bulk_enrich(self, iocs: list[dict]) -> list[dict]:
        """
        iocs: [{"type": "ip", "value": "1.2.3.4"}, ...]
        Returns list of enrichment dicts, empty list on failure.
        """
        try:
            r = http_requests.post(
                f"{self._base}/api/cytim/bulk-enrich",
                headers=self._headers,
                json={"iocs": iocs},
                timeout=self._timeout,
            )
            if r.status_code == 200:
                return r.json().get("results", [])
            return []
        except Exception as e:
            _log.warning("CyTIM bulk_enrich failed: %s", e)
            return []


_cytim_client: Optional[CyTIMClient] = None


def get_threat_intel_client() -> Optional[CyTIMClient]:
    """
    Returns a CyTIMClient if CyTIM is configured, otherwise None.
    Callers that get None should fall back to direct MISP/VT calls.

    Usage in blueprints:
        client = get_threat_intel_client()
        if client:
            result = client.enrich("ip", "1.2.3.4")
        else:
            # existing MISP/VT logic here
    """
    global _cytim_client
    from core.config import CYTIM_URL, CYTIM_API_KEY, CYTIM_TIMEOUT
    if CYTIM_URL and CYTIM_API_KEY:
        if _cytim_client is None:
            _cytim_client = CyTIMClient(CYTIM_URL, CYTIM_API_KEY, CYTIM_TIMEOUT)
        return _cytim_client
    return None


# ── Centralized CyTIM gateway helpers (used by all ASM + SIEM modules) ────────

def _get_cytim_settings() -> tuple[str, str]:
    """Return (cytim_url, api_key) from ai_settings.json, falling back to env vars.

    ai_settings.json is the source of truth — CYTIM_URL / CYTIM_API_KEY in os.environ
    are only populated if the admin explicitly added them to /opt/cycentra/.env.
    Reading from the settings file at call-time means the values are always current
    without requiring a Flask restart after the user saves CyTIM config in the UI.
    """
    import json as _json
    from core.config import AI_SETTINGS_FILE
    try:
        if AI_SETTINGS_FILE.exists():
            data = _json.loads(AI_SETTINGS_FILE.read_text())
            cytim = data.get("cytim", {})
            url     = (cytim.get("url") or "").strip().rstrip("/")
            api_key = (cytim.get("apiKey") or "").strip()
            if url and api_key:
                return url, api_key
    except Exception:
        pass
    # Fallback: honour explicit env-var override
    from core.config import CYTIM_URL, CYTIM_API_KEY
    return CYTIM_URL, CYTIM_API_KEY


def is_cytim_enabled() -> bool:
    from core.config import CYTIM_ENABLED
    url, api_key = _get_cytim_settings()
    return bool(CYTIM_ENABLED and url and api_key)


def cytim_bulk_enrich(iocs: list, profile: str = "default") -> dict:
    """POST /api/cytim/bulk-enrich. Returns {ioc_value_lower: result_dict}. Never raises."""
    import requests as _req
    from core.config import CYTIM_TIMEOUT
    url, api_key = _get_cytim_settings()
    if not url or not api_key:
        return {}
    try:
        resp = _req.post(
            f"{url}/api/cytim/bulk-enrich",
            json={"iocs": iocs, "profile": profile},
            headers={"X-CyTIM-Key": api_key},
            timeout=CYTIM_TIMEOUT,
        )
        resp.raise_for_status()
        return {r["ioc_value"].lower(): r for r in resp.json().get("results", [])}
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("[CyTIM] bulk_enrich failed: %s", e)
        return {}


def cytim_darkweb_enrich(iocs: list) -> dict:
    """POST /api/cytim/darkweb-enrich. Returns raw response dict. Never raises."""
    import requests as _req
    from core.config import CYTIM_TIMEOUT
    url, api_key = _get_cytim_settings()
    if not url or not api_key:
        return {"enabled": False, "results": []}
    try:
        resp = _req.post(
            f"{url}/api/cytim/darkweb-enrich",
            json={"iocs": iocs},
            headers={"X-CyTIM-Key": api_key},
            timeout=CYTIM_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("[CyTIM] darkweb_enrich failed: %s", e)
        return {"enabled": False, "results": []}


def is_darkweb_enabled() -> bool:
    """GET /api/cytim/darkweb-status. Returns False if CyTIM not configured or unreachable."""
    if not is_cytim_enabled():
        return False
    import requests as _req
    url, _ = _get_cytim_settings()
    try:
        resp = _req.get(f"{url}/api/cytim/darkweb-status", timeout=5)
        return resp.json().get("enabled", False)
    except Exception:
        return False


def cytim_recon(domain: str, modules: list, **kwargs) -> dict:
    """POST /api/cytim/recon. Returns results dict keyed by module. Never raises."""
    import requests as _req
    from core.config import CYTIM_TIMEOUT
    url, api_key = _get_cytim_settings()
    if not url or not api_key:
        return {}
    try:
        payload = {"domain": domain, "modules": modules}
        payload.update(kwargs)
        resp = _req.post(
            f"{url}/api/cytim/recon",
            json=payload,
            headers={"X-CyTIM-Key": api_key},
            timeout=CYTIM_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("results", {})
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("[CyTIM] recon failed: %s", e)
        return {}


