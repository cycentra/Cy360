"""
core/helpers.py
===============
Shared utility functions used across multiple blueprints.
Import individual functions — do not import * from here.
"""

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import requests as http_requests
from flask import request

from core.config import AUTH_LOG_FILE, CORS_ALLOWED_ORIGINS


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


# ── MISP config resolver ───────────────────────────────────────────────────────

_CLOUD_MISP_URL_DEFAULT = "https://cymisp.cycentra.com"


def get_misp_config() -> dict | None:
    """
    Returns MISP connection config sourced exclusively from vault secrets.

    CLOUD_MISP_URL and CLOUD_MISP_API_KEY are injected into os.environ at
    process startup by core/kv_secrets.py (FLASK_KV_MAP / ENGINE_KV_MAP).
    No UI configuration or ai_settings.json reads — vault is the only source.

    Returns dict with keys url, apiKey, mode — or None if key is absent.
    """
    import logging as _log
    _logger = _log.getLogger(__name__)
    url = os.environ.get("CLOUD_MISP_URL", _CLOUD_MISP_URL_DEFAULT).rstrip("/")
    key = os.environ.get("CLOUD_MISP_API_KEY", "").strip()
    if not key:
        _logger.warning(
            "⏭️  [MISP] CLOUD_MISP_API_KEY not set — IOC lookups disabled. "
            "Add the secret to your vault (Infisical / Azure KV / HashiCorp) "
            "under key CLOUD_MISP_API_KEY."
        )
        return None
    return {"url": url, "apiKey": key, "mode": "cloud"}


_CLOUD_IRIS_URL_DEFAULT = "https://cyiris.cycentra.com"


def get_iris_config() -> dict | None:
    """
    Single source of truth for CyIRIS (DFIR IRIS) connection configuration.

    Modes
    -----
    - ``disabled``  → returns None
    - ``cloud``     → returns Cloud CyIRIS creds from ``CLOUD_IRIS_URL`` /
                      ``CLOUD_IRIS_API_KEY`` in the environment
    - ``local``     → returns the customer-configured URL + key from ai_settings.json

    Returns dict with keys: url, apiKey, customerId, fpThreshold, mode — or None.
    """
    from core.config import AI_SETTINGS_FILE
    try:
        raw = AI_SETTINGS_FILE.read_text() if AI_SETTINGS_FILE.exists() else "{}"
        stored = json.loads(raw)
    except Exception:
        stored = {}

    iris = stored.get("iris", {})
    mode = iris.get("mode", "disabled")

    # Auto-activate: if the post-install capture wrote CLOUD_IRIS_API_KEY into
    # os.environ (platform/routes.py) but ai_settings.json was not yet updated,
    # treat this as cloud mode so the integration works immediately after install.
    if mode in ("disabled", "") and os.environ.get("CLOUD_IRIS_API_KEY", "").strip():
        mode = "cloud"

    if mode == "cloud":
        url = os.environ.get("CLOUD_IRIS_URL", _CLOUD_IRIS_URL_DEFAULT).rstrip("/")
        # Prefer env var; fall back to key stored in ai_settings.json by the UI
        key = os.environ.get("CLOUD_IRIS_API_KEY", "").strip() or iris.get("apiKey", "").strip()
        if not key:
            import logging as _log
            _log.getLogger(__name__).warning(
                "⚠️ [CyIRIS] Cloud mode selected but no API key found "
                "(set CLOUD_IRIS_API_KEY env var or configure via System Settings → CyIRIS).")
            return None
        return {
            "url":         url,
            "apiKey":      key,
            "customerId":  int(os.environ.get("CLOUD_IRIS_CUSTOMER_ID", "") or iris.get("customerId", 1)),
            "fpThreshold": float(iris.get("fpThreshold", 90.0)),
            "mode":        "cloud",
        }

    if mode == "local":
        url = iris.get("url", "").strip().rstrip("/")
        key = iris.get("apiKey", "").strip()
        if not url or not key:
            return None
        return {
            "url":         url,
            "apiKey":      key,
            "customerId":  int(iris.get("customerId", 1)),
            "fpThreshold": float(iris.get("fpThreshold", 90.0)),
            "mode":        "local",
        }

    return None
