"""
blueprints/sso/routes.py — Generic OIDC/OAuth2 SSO for CyCentra 360
====================================================================
Mirrors the CyMind SSO blueprint but adapted for Flask (sync) + psycopg2.

Routes (all under /api/sso/):
  GET  /api/sso/providers           → list configured SSO providers
  GET  /api/sso/status              → probe provider connectivity
  GET  /api/sso/redirect            → initiate OIDC login flow
  GET  /api/sso/callback            → exchange code, provision user, set session
  POST /api/sso/configure           → admin: save provider settings
  POST /api/sso/disable             → admin: disable SSO

  GET  /api/sso/pending             → admin: list users pending approval
  POST /api/sso/approve/<email>     → admin: approve a pending user
  POST /api/sso/reject/<email>      → admin: reject a pending user

  GET  /api/sso/smtp/config         → admin: get current SMTP settings
  POST /api/sso/smtp/config         → admin: save SMTP settings
  POST /api/sso/smtp/test           → admin: send a test email

Configuration is persisted in cy_sso_config table (key/value store backed by
the same PostgreSQL cluster as cy_users).

Approval workflow:
  1. New SSO user logs in.
  2. If sso_require_approval="true", user.approval_status is set to "pending"
     and they are redirected to the frontend with sso_error=pending_approval.
  3. Admin receives an email with approve/reject links (if SMTP is configured).
  4. Admin approves/rejects via /api/sso/approve|reject or the Settings UI.
  5. On approval, the user receives an email and can sign in normally.
"""

import hashlib
import json
import logging
import secrets
import time
import threading
import urllib.parse
from datetime import datetime as _dt

import requests as http_req
from flask import Blueprint, request, redirect, jsonify, session, make_response

from core.config import (
    FRONTEND_URL, BASE_URL,
    VALID_ROLES, CYCENTRA_DB_URL,
    SSO_ENABLED, SSO_PROVIDER, SSO_CLIENT_ID, SSO_CLIENT_SECRET,
    SSO_DISCOVERY_URL, SSO_REDIRECT_URI, SSO_DEFAULT_ROLE,
    SSO_AUTO_PROVISION, SSO_REQUIRE_APPROVAL, SSO_ALLOWED_DOMAINS,
)
from core.helpers import add_cors_headers, auth_event
from blueprints.rbac.manager import get_user_role, get_user_apps, _db, _ensure_table

logger = logging.getLogger("cycentra.sso")

sso_bp = Blueprint("sso", __name__)

# ── In-memory OIDC state store (state → {…, ts}) ────────────────────────────
_STATE_STORE: dict = {}
_STATE_TTL = 600  # 10 minutes

# ── Built-in discovery URL table ─────────────────────────────────────────────
_PROVIDER_DISCOVERY_URLS: dict = {
    "google":      "https://accounts.google.com/.well-known/openid-configuration",
    "microsoft":   "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    "okta":        "",   # tenant-specific — must be supplied
    "keycloak":    "",   # realm-specific  — must be supplied
    # CyCentra 360 OIDC IdP — route is at /oidc/.well-known/openid-configuration
    # Works on both cyasm.<domain> and cy360.<domain> via /oidc/ nginx proxy
    "cycentra360": f"{BASE_URL}/oidc/.well-known/openid-configuration",
    "custom":      "",
}

_BUILTIN_PROVIDERS = {
    "cycentra360": {"name": "CyCentra 360 IdP",   "icon": "cycentra"},
    "google":      {"name": "Google Workspace",    "icon": "google"},
    "microsoft":   {"name": "Microsoft / Azure AD","icon": "microsoft"},
    "okta":        {"name": "Okta",                "icon": "okta"},
    "keycloak":    {"name": "Keycloak",            "icon": "keycloak"},
    "custom":      {"name": "Custom OIDC",         "icon": "oidc"},
}

# ── cy_sso_config DB helpers ─────────────────────────────────────────────────

_SSO_TABLE_READY = False

_CREATE_SSO_CONFIG = """
CREATE TABLE IF NOT EXISTS cy_sso_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


def _ensure_sso_table() -> None:
    global _SSO_TABLE_READY
    if _SSO_TABLE_READY:
        return
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(_CREATE_SSO_CONFIG)
        _SSO_TABLE_READY = True
    except Exception as exc:
        err_str = str(exc)
        # "duplicate key" means the table already exists (concurrent creation race) — treat as success
        if "duplicate key" in err_str or "already exists" in err_str:
            _SSO_TABLE_READY = True
        else:
            logger.error("cy_sso_config table init failed: %s", exc)


def _sso_db_get_all() -> dict:
    """Return all cy_sso_config rows as a dict."""
    _ensure_sso_table()
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM cy_sso_config;")
            return {k: v for k, v in cur.fetchall()}
    except Exception:
        return {}


def _sso_db_get(key: str, default: str = "") -> str:
    _ensure_sso_table()
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM cy_sso_config WHERE key = %s;", (key,))
            row = cur.fetchone()
        return row[0] if row else default
    except Exception:
        return default


def _sso_db_set(key: str, value: str) -> None:
    _ensure_sso_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cy_sso_config (key, value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
        """, (key, value))


def _get_sso_cfg() -> dict:
    """
    Merge DB config over env-var defaults.
    DB values always win so admins can reconfigure without restarting.
    """
    db = _sso_db_get_all()
    return {
        "sso_enabled":          db.get("sso_enabled",          "true" if SSO_ENABLED else "false"),
        "sso_provider":         db.get("sso_provider",         SSO_PROVIDER),
        "sso_client_id":        db.get("sso_client_id",        SSO_CLIENT_ID),
        "sso_client_secret":    db.get("sso_client_secret",    SSO_CLIENT_SECRET),
        "sso_discovery_url":    db.get("sso_discovery_url",    SSO_DISCOVERY_URL),
        "sso_redirect_uri":     db.get("sso_redirect_uri",     SSO_REDIRECT_URI),
        "sso_default_role":     db.get("sso_default_role",     SSO_DEFAULT_ROLE),
        "sso_auto_provision":   db.get("sso_auto_provision",   "true" if SSO_AUTO_PROVISION else "false"),
        "sso_require_approval": db.get("sso_require_approval", "true" if SSO_REQUIRE_APPROVAL else "false"),
        "sso_allowed_domains":  db.get("sso_allowed_domains",  SSO_ALLOWED_DOMAINS),
    }


# ── OIDC helpers ──────────────────────────────────────────────────────────────

def _discover(discovery_url: str) -> dict:
    """Fetch and return OIDC discovery document."""
    r = http_req.get(discovery_url, timeout=8)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        ct = r.headers.get("content-type", "unknown")
        raise ValueError(
            f"Discovery URL returned non-JSON (Content-Type: {ct}). "
            f"URL must point to /.well-known/openid-configuration."
        )


def _exchange_code(token_endpoint: str, code: str,
                   client_id: str, client_secret: str, redirect_uri: str) -> dict:
    r = http_req.post(token_endpoint, data={
        "grant_type":    "authorization_code",
        "code":          code,
        "client_id":     client_id,
        "client_secret": client_secret,
        "redirect_uri":  redirect_uri,
    }, timeout=10)
    r.raise_for_status()
    return r.json()


def _fetch_userinfo(userinfo_endpoint: str, access_token: str) -> dict:
    r = http_req.get(
        userinfo_endpoint,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=8,
    )
    r.raise_for_status()
    return r.json()


def _parse_role(claims: dict, default_role: str) -> str:
    """Map IdP roles/groups claim to a CyCentra 360 role string."""
    raw = claims.get("roles", claims.get("groups", []))
    if isinstance(raw, str):
        raw = [raw]
    mapping = {
        "admin":          "admin",
        "analyst":        "analyst",
        "viewer":         "viewer",
        "soc_analyst":    "analyst",
        "soc_admin":      "admin",
        "security_admin": "admin",
    }
    for r in raw:
        if r.lower() in mapping:
            return mapping[r.lower()]
    return default_role if default_role in VALID_ROLES else "viewer"


# ── User DB helpers ──────────────────────────────────────────────────────────

def _get_user_full(email: str) -> dict | None:
    """Extended user lookup including SSO and approval fields."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT email, role, auth_type, name, sso_provider, sso_id, "
            "       approval_status, approval_requested_at, "
            "       approval_resolved_at, rejection_reason "
            "FROM cy_users WHERE email = %s;", (email,)
        )
        row = cur.fetchone()
    if not row:
        return None
    keys = ["email", "role", "auth_type", "name", "sso_provider", "sso_id",
            "approval_status", "approval_requested_at",
            "approval_resolved_at", "rejection_reason"]
    d = dict(zip(keys, row))
    # Normalise timestamps
    for ts_key in ("approval_requested_at", "approval_resolved_at"):
        if d.get(ts_key) and hasattr(d[ts_key], "isoformat"):
            d[ts_key] = d[ts_key].isoformat()
    return d


def _provision_user(email: str, name: str, role: str,
                    provider: str, sso_id: str,
                    approval_status: str) -> None:
    """Insert a new SSO-provisioned user into cy_users."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cy_users
                (email, role, auth_type, name, sso_provider, sso_id,
                 approval_status, approval_requested_at, updated_at)
            VALUES (%s, %s, 'sso', %s, %s, %s, %s,
                    CASE WHEN %s = 'pending' THEN NOW() ELSE NULL END,
                    NOW())
            ON CONFLICT (email) DO UPDATE SET
                sso_provider = EXCLUDED.sso_provider,
                sso_id       = EXCLUDED.sso_id,
                name         = COALESCE(EXCLUDED.name, cy_users.name),
                auth_type    = 'sso',
                updated_at   = NOW();
        """, (email, role, name, provider, sso_id, approval_status, approval_status))


def _set_approval(email: str, status: str, reason: str = "") -> bool:
    """Update approval_status for a user. Returns True if row was found."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("""
            UPDATE cy_users
            SET approval_status     = %s,
                approval_resolved_at = NOW(),
                rejection_reason    = %s,
                updated_at          = NOW()
            WHERE email = %s;
        """, (status, reason if status == "rejected" else None, email))
        return cur.rowcount > 0


def _get_pending_users() -> list:
    """Return users with approval_status='pending'."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT email, name, role, sso_provider, approval_requested_at "
            "FROM cy_users WHERE approval_status = 'pending' ORDER BY approval_requested_at;"
        )
        rows = cur.fetchall()
    result = []
    for email, name, role, provider, req_at in rows:
        result.append({
            "email":                 email,
            "name":                  name,
            "role":                  role,
            "sso_provider":          provider,
            "approval_requested_at": req_at.isoformat() if req_at and hasattr(req_at, "isoformat") else None,
        })
    return result


# ── CORS pre-flight ───────────────────────────────────────────────────────────

for _path in ("/api/sso/configure", "/api/sso/disable",
              "/api/sso/smtp/config", "/api/sso/smtp/test",
              "/api/sso/approve/<email>", "/api/sso/reject/<email>"):
    pass  # handled by blanket OPTIONS handler in app.py


# ── Endpoints ─────────────────────────────────────────────────────────────────

@sso_bp.route("/api/sso/providers")
def sso_providers():
    """Return SSO provider status without exposing client_secret."""
    cfg         = _get_sso_cfg()
    enabled     = cfg["sso_enabled"].lower() == "true"
    provider_id = cfg.get("sso_provider", "")
    client_id   = cfg.get("sso_client_id", "")

    providers_list = [{
        "provider":      provider_id,
        "sso_enabled":   enabled,
        "provider_name": _BUILTIN_PROVIDERS.get(provider_id, {}).get("name", provider_id),
        "icon":          _BUILTIN_PROVIDERS.get(provider_id, {}).get("icon", "oidc"),
    }] if enabled and provider_id else []

    return jsonify({
        "sso_enabled":       enabled,
        "configured":        bool(provider_id and client_id),
        "providers":         providers_list,
        "provider_id":       provider_id,
        "provider_name":     _BUILTIN_PROVIDERS.get(provider_id, {}).get("name", provider_id),
        "discovery_url":     cfg.get("sso_discovery_url", ""),
        "builtin_providers": _BUILTIN_PROVIDERS,
    })


@sso_bp.route("/api/sso/status")
def sso_status():
    """Probe the configured OIDC provider and return connectivity info."""
    cfg = _get_sso_cfg()
    discovery_url = cfg.get("sso_discovery_url", "")
    if not discovery_url:
        return jsonify({"ok": False, "error": "No discovery URL configured"}), 200
    try:
        doc = _discover(discovery_url)
        return jsonify({
            "ok":              True,
            "provider":        cfg.get("sso_provider", ""),
            "issuer":          doc.get("issuer", ""),
            "auth_endpoint":   doc.get("authorization_endpoint", ""),
            "token_endpoint":  doc.get("token_endpoint", ""),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 200


@sso_bp.route("/api/sso/redirect")
def sso_redirect():
    """Initiate OIDC authorization code flow."""
    cfg = _get_sso_cfg()

    if cfg["sso_enabled"].lower() != "true":
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+not+enabled")

    client_id     = cfg.get("sso_client_id", "")
    discovery_url = cfg.get("sso_discovery_url", "")
    redirect_uri  = cfg.get("sso_redirect_uri", "")

    if not client_id or not discovery_url or not redirect_uri:
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+not+fully+configured")

    try:
        doc = _discover(discovery_url)
    except Exception as exc:
        logger.error("SSO discovery failed: %s", exc)
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+provider+unreachable")

    auth_endpoint = doc.get("authorization_endpoint", "")
    if not auth_endpoint:
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+discovery+invalid")

    return_to = request.args.get("return_to", "")
    state     = secrets.token_urlsafe(24)
    nonce     = secrets.token_urlsafe(16)

    _STATE_STORE[state] = {
        "provider":         cfg.get("sso_provider", "custom"),
        "nonce":            nonce,
        "return_to":        return_to,
        "ts":               time.time(),
        "token_endpoint":   doc.get("token_endpoint", ""),
        "userinfo_endpoint": doc.get("userinfo_endpoint", ""),
    }
    # Prune stale states
    stale = [k for k, v in list(_STATE_STORE.items()) if time.time() - v["ts"] > _STATE_TTL]
    for k in stale:
        del _STATE_STORE[k]

    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "scope":         "openid email profile",
        "state":         state,
        "nonce":         nonce,
    })
    return redirect(f"{auth_endpoint}?{params}", code=302)


@sso_bp.route("/api/sso/callback")
def sso_callback():
    """
    Handle IdP callback:
    1. Validate state.
    2. Exchange code for tokens.
    3. Fetch userinfo.
    4. Provision or gate existing user (approval_status check).
    5. Set Flask session and redirect to frontend.
    """
    error = request.args.get("error")
    code  = request.args.get("code")
    state = request.args.get("state")

    if error:
        desc = request.args.get("error_description", error)
        auth_event("login", "", "portal", "error", f"SSO: {desc}")
        return redirect(f"{FRONTEND_URL}?auth=error&message={urllib.parse.quote(desc)}")

    if not code or not state:
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+missing+code+or+state")

    state_data = _STATE_STORE.pop(state, None)
    if not state_data or (time.time() - state_data.get("ts", 0)) > _STATE_TTL:
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+state+expired.+Please+try+again.")

    cfg             = _get_sso_cfg()
    client_id       = cfg.get("sso_client_id", "")
    client_secret   = cfg.get("sso_client_secret", "")
    redirect_uri    = cfg.get("sso_redirect_uri", "")
    provider_id     = cfg.get("sso_provider", "custom")
    auto_provision  = cfg.get("sso_auto_provision", "true").lower() == "true"
    default_role    = cfg.get("sso_default_role", "viewer")
    require_approval = cfg.get("sso_require_approval", "false").lower() == "true"

    token_endpoint    = state_data.get("token_endpoint", "")
    userinfo_endpoint = state_data.get("userinfo_endpoint", "")
    return_to         = state_data.get("return_to", "") or FRONTEND_URL

    # 1 — Exchange code
    try:
        tokens = _exchange_code(token_endpoint, code, client_id, client_secret, redirect_uri)
    except Exception as exc:
        logger.error("SSO token exchange failed: %s", exc)
        auth_event("login", "", "portal", "error", f"SSO token exchange: {exc}")
        return redirect(f"{FRONTEND_URL}?auth=error&message=Token+exchange+failed")

    access_token = tokens.get("access_token", "")

    # 2 — Fetch userinfo
    claims: dict = {}
    if userinfo_endpoint and access_token:
        try:
            claims = _fetch_userinfo(userinfo_endpoint, access_token)
        except Exception as exc:
            logger.warning("SSO userinfo fetch failed — trying id_token: %s", exc)

    if not claims:
        id_token = tokens.get("id_token", "")
        if id_token:
            try:
                import base64
                parts = id_token.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * (-len(parts[1]) % 4)
                    claims = json.loads(base64.urlsafe_b64decode(padded))
            except Exception:
                pass

    email = (claims.get("email") or "").lower().strip()
    name  = claims.get("name") or claims.get("email", "SSO User")
    sub   = claims.get("sub") or email

    if not email:
        return redirect(f"{FRONTEND_URL}?auth=error&message=SSO+did+not+return+email")

    # 3 — Domain allowlist
    allowed_domains_raw = cfg.get("sso_allowed_domains", "").strip()
    if allowed_domains_raw:
        allowed = {d.strip().lower() for d in allowed_domains_raw.split(",") if d.strip()}
        domain  = email.split("@")[-1] if "@" in email else ""
        if domain not in allowed:
            auth_event("login", email, "portal", "denied", f"SSO domain blocked: {domain}")
            return redirect(
                f"{FRONTEND_URL}?auth=error"
                f"&message={urllib.parse.quote(f'Email domain {domain!r} is not authorised for this instance.')}"
            )

    # 4 — Provision or gate user
    existing = _get_user_full(email)
    is_new   = existing is None

    if is_new:
        if not auto_provision:
            auth_event("login", email, "portal", "denied", "SSO auto-provision disabled")
            return redirect(f"{FRONTEND_URL}?auth=error&message=No+local+account+found.+Contact+your+administrator.")

        role             = _parse_role(claims, default_role)
        approval_status  = "pending" if require_approval else "approved"
        _provision_user(email, name, role, provider_id, sub, approval_status)
        existing = _get_user_full(email)

        if require_approval:
            _notify_admin_pending(email, name, provider_id)
            auth_event("login", email, "portal", "pending", f"SSO new user pending approval, provider={provider_id}")
    else:
        # Update SSO linkage on existing account
        _ensure_table()
        with _db() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE cy_users
                SET sso_provider = %s, sso_id = %s,
                    name = COALESCE(%s, name), auth_type = 'sso', updated_at = NOW()
                WHERE email = %s;
            """, (provider_id, sub, name, email))

    # Re-fetch after any update
    existing = _get_user_full(email)
    approval = (existing or {}).get("approval_status", "approved")

    if approval == "pending":
        sep = "&" if "?" in return_to else "?"
        return redirect(
            f"{return_to}{sep}sso_error=pending_approval&email={urllib.parse.quote(email)}"
        )

    if approval == "rejected":
        reason = (existing or {}).get("rejection_reason", "")
        msg = urllib.parse.quote(f"Access denied — {reason}" if reason else "Access request was not approved. Contact your administrator.")
        return redirect(f"{FRONTEND_URL}?auth=error&message={msg}")

    # 5 — Set session
    avatar = "".join([w[0].upper() for w in (name or "").split()[:2]])
    role   = (existing or {}).get("role", "viewer")
    apps   = get_user_apps(email)

    session["user_email"] = email
    session["user_name"]  = name
    session["user_uid"]   = f"sso_{sub}"
    session.permanent     = True
    auth_event("login", email, "portal", "success", f"provider={provider_id}")

    sep = "&" if "?" in return_to else "?"
    return redirect(
        f"{return_to}{sep}auth=success&provider={urllib.parse.quote(provider_id)}"
        f"&name={urllib.parse.quote(name)}&email={urllib.parse.quote(email)}"
        f"&uid={urllib.parse.quote(f'sso_{sub}')}&avatar={urllib.parse.quote(avatar)}"
        f"&role={urllib.parse.quote(role)}&apps={urllib.parse.quote(json.dumps(apps))}"
    )


# ── Admin — configure SSO ─────────────────────────────────────────────────────

@sso_bp.route("/api/sso/configure", methods=["POST"])
def sso_configure():
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    data = request.get_json(silent=True) or {}

    provider      = data.get("provider", "").strip()
    client_id     = data.get("client_id", "").strip()
    client_secret = data.get("client_secret", "").strip()
    discovery_url = data.get("discovery_url", "").strip()
    redirect_uri  = data.get("redirect_uri", "").strip()
    default_role  = data.get("default_role", "viewer").strip()
    auto_provision   = bool(data.get("auto_provision", True))
    require_approval = bool(data.get("require_approval", False))
    allowed_domains  = data.get("allowed_domains", "").strip()

    # ── cycentra360 self-IdP: enforce the registered OIDC client and redirect URI
    # so that a misconfigured or outdated DB entry can never produce an
    # "unknown_client" error from the OIDC provider.  Set these before the
    # required-field validation so the admin doesn't have to enter them manually.
    if provider == "cycentra360":
        from core.config import CY360SSO_OIDC_SECRET as _cy360_secret
        from core.config import FRONTEND_URL as _fe_url
        client_id    = "cy360sso"
        redirect_uri = f"{_fe_url}/api/sso/callback"
        if not client_secret and _cy360_secret:
            client_secret = _cy360_secret

    if not provider or not client_id:
        return jsonify({"error": "provider and client_id are required"}), 400
    if default_role not in VALID_ROLES:
        return jsonify({"error": f"default_role must be one of {sorted(VALID_ROLES)}"}), 400

    # Auto-fill known discovery URLs
    if ".well-known" not in discovery_url:
        builtin = _PROVIDER_DISCOVERY_URLS.get(provider, "")
        if builtin:
            discovery_url = builtin
        elif not discovery_url:
            return jsonify({"error": "discovery_url is required for this provider"}), 400

    # Probe before saving
    try:
        _discover(discovery_url)
    except Exception as exc:
        return jsonify({"error": f"Discovery URL probe failed: {exc}"}), 400

    pairs = [
        ("sso_enabled",          "true"),
        ("sso_provider",         provider),
        ("sso_client_id",        client_id),
        ("sso_discovery_url",    discovery_url),
        ("sso_redirect_uri",     redirect_uri),
        ("sso_default_role",     default_role),
        ("sso_auto_provision",   "true" if auto_provision else "false"),
        ("sso_require_approval", "true" if require_approval else "false"),
        ("sso_allowed_domains",  allowed_domains),
    ]
    if client_secret:
        pairs.append(("sso_client_secret", client_secret))

    for k, v in pairs:
        _sso_db_set(k, v)

    auth_event("sso_configure", caller, "portal", "success",
               f"provider={provider} require_approval={require_approval}")
    logger.info("SSO configured by %s: provider=%s", caller, provider)
    return jsonify({"ok": True, "provider": provider})


@sso_bp.route("/api/sso/disable", methods=["POST"])
def sso_disable():
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403
    _sso_db_set("sso_enabled", "false")
    auth_event("sso_disable", caller, "portal", "success", "SSO disabled")
    return jsonify({"ok": True, "sso_enabled": False})


# ── Admin — approval workflow ─────────────────────────────────────────────────

@sso_bp.route("/api/sso/pending")
def sso_pending():
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403
    return jsonify({"pending": _get_pending_users()})


@sso_bp.route("/api/sso/approve/<path:email>", methods=["POST"])
def sso_approve(email: str):
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    email = email.strip().lower()
    user  = _get_user_full(email)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.get("approval_status") != "pending":
        return jsonify({"error": f"User is not pending (current: {user.get('approval_status')})"}), 400

    _set_approval(email, "approved")
    auth_event("sso_approve", caller, "portal", "success", f"approved {email}")

    # Notify user
    try:
        from smtp_service import send_access_approved
        send_access_approved(email, user.get("name", ""))
    except Exception as exc:
        logger.warning("Could not send approval email to %s: %s", email, exc)

    return jsonify({"ok": True, "email": email, "approval_status": "approved"})


@sso_bp.route("/api/sso/reject/<path:email>", methods=["POST"])
def sso_reject(email: str):
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    email  = email.strip().lower()
    data   = request.get_json(silent=True) or {}
    reason = data.get("reason", "").strip()

    user = _get_user_full(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    _set_approval(email, "rejected", reason)
    auth_event("sso_reject", caller, "portal", "success", f"rejected {email}: {reason}")

    # Notify user
    try:
        from smtp_service import send_access_rejected
        send_access_rejected(email, user.get("name", ""), reason)
    except Exception as exc:
        logger.warning("Could not send rejection email to %s: %s", email, exc)

    return jsonify({"ok": True, "email": email, "approval_status": "rejected"})


# ── SMTP configuration ────────────────────────────────────────────────────────

@sso_bp.route("/api/sso/smtp/config", methods=["GET", "POST"])
def smtp_config():
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    if request.method == "GET":
        try:
            from smtp_service import get_smtp_config, SMTP_CONFIG_KEYS
            cfg = get_smtp_config()
            # Never expose the password value to the UI
            cfg["smtp_password"] = "••••••••" if cfg.get("smtp_password") else ""
            return jsonify(cfg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    data = request.get_json(silent=True) or {}
    try:
        from smtp_service import save_smtp_config
        save_smtp_config(data)
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@sso_bp.route("/api/sso/smtp/test", methods=["POST"])
def smtp_test():
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role as _gur
    if _gur(caller) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    data = request.get_json(silent=True) or {}
    to   = (data.get("email") or caller).strip()
    try:
        from smtp_service import send_test_email
        ok, err = send_test_email(to)
        if ok:
            return jsonify({"ok": True, "message": f"Test email sent to {to}"})
        return jsonify({"ok": False, "error": err}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── SMTP notification helper (called from callback) ───────────────────────────

def _notify_admin_pending(user_email: str, user_name: str, provider: str) -> None:
    """Fire-and-forget: send approval request email to admin."""
    def _send():
        try:
            from smtp_service import get_smtp_config, send_approval_request
            cfg         = get_smtp_config()
            admin_email = cfg.get("smtp_admin_email", "")
            if not admin_email:
                logger.debug("No smtp_admin_email configured — skipping approval notification")
                return
            approve_url = f"{BASE_URL}/api/sso/approve/{urllib.parse.quote(user_email)}"
            reject_url  = f"{BASE_URL}/api/sso/reject/{urllib.parse.quote(user_email)}"
            send_approval_request(admin_email, user_email, user_name,
                                  provider, approve_url, reject_url)
        except Exception as exc:
            logger.warning("Failed to send admin approval notification: %s", exc)

    threading.Thread(target=_send, daemon=True).start()
