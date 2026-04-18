"""
core/config.py
==============
Single source of truth for all environment variables, path constants,
and derived configuration. Import from here everywhere — never call
os.environ.get() directly in blueprint files.
"""

import os
import site
from pathlib import Path
from datetime import timedelta

# ── .env loading ───────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    if os.path.exists("/opt/cycentra/.env"):
        load_dotenv("/opt/cycentra/.env")
    elif os.path.exists(".env"):
        load_dotenv(".env")
except ImportError:
    pass  # dotenv optional — system env is used directly

# ── Azure Key Vault bootstrap ──────────────────────────────────────────────────
# Runs after dotenv so AZURE_KEYVAULT_URL is already in env from .env file.
# Injects KV secrets into os.environ before any os.environ.get() calls below.
try:
    from core.kv_secrets import load_kv_secrets, FLASK_KV_MAP
    load_kv_secrets(FLASK_KV_MAP)
except Exception:
    pass  # never block app startup if KV is unreachable


# ── Domain & URL ───────────────────────────────────────────────────────────────
BASE_DOMAIN  = os.environ.get("BASE_DOMAIN",  "cycentra.com")
FRONTEND_URL = os.environ.get("FRONTEND_URL", f"https://cysoc.{BASE_DOMAIN}")
BASE_URL     = os.environ.get("BASE_URL",      f"https://cyasm.{BASE_DOMAIN}")

# ── Secrets ────────────────────────────────────────────────────────────────────
SECRET_KEY            = os.environ.get("SECRET_KEY", "change_this_to_something_secure_32ch")
JWT_SECRET            = os.environ.get("JWT_SECRET", SECRET_KEY)
TOKEN_TTL             = 3600  # seconds
OAUTH2PROXY_SECRET    = os.environ.get("OAUTH2PROXY_SECRET", "")
OAUTH2PROXY_COOKIE_SECRET = os.environ.get("OAUTH2PROXY_COOKIE_SECRET", "")

# ── OAuth — Google ─────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

# ── OAuth — Microsoft ──────────────────────────────────────────────────────────
MS_CLIENT_ID     = os.environ.get("MICROSOFT_CLIENT_ID", "")
MS_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")

# ── OIDC clients ───────────────────────────────────────────────────────────────
# oauth2-proxy is the single IAP gate for all subdomains.
# CyIRIS and CySOAR no longer register individual OIDC clients — they trust
# the X-Email header injected by nginx after oauth2-proxy validates the session.
# cysiem (Wazuh) uses proxy auth mode — not OIDC — so no client needed there.
OIDC_CLIENTS = {
    "oauth2proxy": {
        "client_secret": os.environ.get("OAUTH2PROXY_SECRET", ""),
        "redirect_uris": [
            f"https://cysoc.{BASE_DOMAIN}/oauth2/callback",
        ],
        "allowed_scopes": ["openid", "email", "profile"],
        "allowed_roles":  ["admin", "analyst", "viewer", "cyiris", "cysoar"],
    },
}

# ── RBAC ───────────────────────────────────────────────────────────────────────
ROLE_APPS = {
    "admin":   ["cysoc", "cysiem", "cyiris", "cysoar", "cyasm"],
    "analyst": ["cysoc", "cysiem", "cyiris", "cysoar", "cyasm"],
    "viewer":  ["cysoc", "cysiem"],
    "cyiris":  ["cysoc", "cyiris"],
    "cysoar":  ["cysoc", "cysoar"],
}
VALID_ROLES = set(ROLE_APPS.keys())

# ── File / directory paths ─────────────────────────────────────────────────────
RBAC_FILE     = Path("/opt/cycentra/rbac.json")
AUTH_LOG_FILE = Path("/var/log/cycentra/auth.log")
MODULES_DIR   = Path("/opt/cycentra/modules")
MODULES_STATE = Path("/opt/cycentra/modules_state.json")
SCANS_DIR        = Path("/var/log/cycentra/cy-asm/scans")
ASM_LOGS         = Path("/var/log/cycentra/cy-asm/logs")
AI_SETTINGS_FILE = Path("/opt/cycentra/ai_settings.json")

# Locate cy_asm package regardless of install method
_SITE_PKG = Path(site.getsitepackages()[0])
ASM_DIR   = _SITE_PKG / "cy_asm"

# ── Docker images ──────────────────────────────────────────────────────────────
CYSOAR_IMAGE     = os.environ.get("CYSOAR_IMAGE",     "ghcr.io/cycentra/cysoar:latest")
CYIRIS_IMAGE_APP = os.environ.get("CYIRIS_IMAGE_APP", "ghcr.io/cycentra/cyiris:latest")
CYIRIS_IMAGE_DB  = os.environ.get("CYIRIS_IMAGE_DB",  "postgres:15-alpine")

# ── IRIS (Incident Response) Integration ─────────────────────────────────────
# Set IRIS_URL and IRIS_API_KEY in /opt/cycentra/.env to enable escalation.
# IRIS_URL example: https://iris.cycentra.com
IRIS_URL     = os.environ.get("IRIS_URL", "")
IRIS_API_KEY = os.environ.get("IRIS_API_KEY", "")

# ── Wazuh Dashboard ───────────────────────────────────────────────────────────
# Set WAZUH_URL to allow deep-links from UEBA anomaly cards into Wazuh.
# WAZUH_URL example: https://wazuh.cycentra.com
WAZUH_URL    = os.environ.get("WAZUH_URL", "")

# ── CORS allowed origins ───────────────────────────────────────────────────────
CORS_ALLOWED_ORIGINS = {
    FRONTEND_URL,
    BASE_URL,
    f"https://cysoc.{BASE_DOMAIN}",
    f"https://cyasm.{BASE_DOMAIN}",
    f"https://cyiris.{BASE_DOMAIN}",
    f"https://cysoar.{BASE_DOMAIN}",
    f"https://cysiem.{BASE_DOMAIN}",
    f"https://cymisp.{BASE_DOMAIN}",
}

# ── Flask session cookie settings ─────────────────────────────────────────────
COOKIE_SETTINGS = {
    "SESSION_COOKIE_SECURE":    True,
    "SESSION_COOKIE_SAMESITE":  "None",
    "SESSION_COOKIE_HTTPONLY":  True,
    "SESSION_COOKIE_DOMAIN":    f".{BASE_DOMAIN}",
    "PERMANENT_SESSION_LIFETIME": timedelta(days=1),
}
