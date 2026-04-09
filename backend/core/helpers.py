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

_CLOUD_MISP_URL_DEFAULT = "https://misp.cycentra.com"


def get_misp_config() -> dict | None:
    """
    Single source of truth for MISP connection configuration.

    Reads ``misp.mode`` from ``/opt/cycentra/ai_settings.json`` and resolves
    the effective URL + API key based on the selected mode.

    Modes
    -----
    - ``disabled``  → returns None (all MISP calls should be skipped)
    - ``cloud``     → returns Cloud CyMISP creds from ``CLOUD_MISP_URL`` and
                      ``CLOUD_MISP_API_KEY`` in the environment (set by setup.sh)
    - ``local``     → returns the customer-configured URL + key from ai_settings.json

    Returns
    -------
    dict with keys ``url``, ``apiKey``, ``mode`` — or ``None`` if disabled /
    credentials are missing.
    """
    from core.config import AI_SETTINGS_FILE  # lazy to avoid circular imports at module load
    try:
        raw = AI_SETTINGS_FILE.read_text() if AI_SETTINGS_FILE.exists() else "{}"
        settings = json.loads(raw)
    except Exception:
        settings = {}

    misp = settings.get("misp", {})
    mode = misp.get("mode", "disabled")

    if mode == "cloud":
        url = os.environ.get("CLOUD_MISP_URL", _CLOUD_MISP_URL_DEFAULT).rstrip("/")
        key = os.environ.get("CLOUD_MISP_API_KEY", "")
        if not key:
            return None  # Cloud key not yet provisioned on this server
        return {"url": url, "apiKey": key, "mode": "cloud"}

    if mode == "local":
        url = misp.get("url", "").strip().rstrip("/")
        key = misp.get("apiKey", "").strip()
        if not url or not key:
            return None
        return {"url": url, "apiKey": key, "mode": "local"}

    # "disabled" or any unrecognised value
    return None
