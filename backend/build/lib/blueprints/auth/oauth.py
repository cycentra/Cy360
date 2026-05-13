"""
blueprints/auth/oauth.py
========================
OAuth 2.0 authentication — Google and Microsoft providers.

Routes:
  GET  /auth/google             → redirect to Google OAuth
  GET  /auth/google/callback    → exchange code, set session
  GET  /auth/microsoft          → redirect to Microsoft OAuth
  GET  /auth/microsoft/callback → exchange code, set session
  GET  /auth/logout             → clear session, redirect portal
  GET  /api/auth/verify         → nginx sub-request gate
  GET  /api/auth/logs           → last N auth events (JSON)
"""

import json
import base64
import urllib.parse

import requests as http_requests
from flask import Blueprint, request, redirect, jsonify, session, make_response

from core.config import (
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
    MS_CLIENT_ID, MS_CLIENT_SECRET,
    FRONTEND_URL, BASE_URL,
)
from core.helpers import enc, auth_event
from blueprints.rbac.manager import get_user_role, get_user_apps, _get_user, _db, _ensure_table
from core.config import AUTH_LOG_FILE

auth_bp = Blueprint("auth", __name__)


# ── Local pending account helper ──────────────────────────────────────────────

def _provision_local_pending(email: str, name: str) -> None:
    """Insert (or reset a rejected) local account to pending — no password, awaiting admin approval."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cy_users
                (email, role, auth_type, name, approval_status, approval_requested_at, updated_at)
            VALUES (%s, 'viewer', 'local', %s, 'pending', NOW(), NOW())
            ON CONFLICT (email) DO UPDATE SET
                approval_status       = 'pending',
                approval_requested_at = NOW(),
                rejection_reason      = NULL,
                updated_at            = NOW();
        """, (email, name))


# ── Google OAuth ──────────────────────────────────────────────────────────────

@auth_bp.route("/auth/google")
def auth_google():
    redirect_target = request.args.get('redirect', FRONTEND_URL)
    callback = f"{BASE_URL}/auth/google/callback"
    state    = base64.urlsafe_b64encode(redirect_target.encode()).decode()
    params   = urllib.parse.urlencode({
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  callback,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
    })
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@auth_bp.route("/auth/google/callback")
def auth_google_callback():
    code  = request.args.get("code")
    state = request.args.get("state", "")
    error = request.args.get("error")

    if error:
        auth_event("login", "", "portal", "error", f"Google: {error}")
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(error)}")

    try:
        redirect_target = base64.urlsafe_b64decode(state.encode()).decode()
    except Exception:
        redirect_target = FRONTEND_URL

    if not code:
        return redirect(f"{FRONTEND_URL}?auth=error&message=no_code")

    resp = http_requests.post("https://oauth2.googleapis.com/token", data={
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  f"{BASE_URL}/auth/google/callback",
        "grant_type":    "authorization_code",
    }, timeout=10)

    if not resp.ok:
        auth_event("login", "", "portal", "error", resp.text[:200])
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(resp.text[:200])}")

    info   = http_requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {resp.json().get('access_token')}"},
        timeout=10,
    ).json()

    name   = info.get("name", info.get("email", "Unknown"))
    email  = info.get("email", "")
    uid    = f"google_{info.get('sub', 'unknown')}"
    avatar = ''.join([w[0].upper() for w in name.split()[:2]])

    if not _get_user(email):
        # Auto-provision via the same policy as the generic OIDC SSO flow.
        from blueprints.sso.routes import _get_sso_cfg, _provision_user, _notify_admin_pending
        cfg = _get_sso_cfg()
        if cfg.get("sso_auto_provision", "true").lower() != "true":
            auth_event("login", email, "portal", "denied", "not in allowlist provider=google")
            return redirect(
                f"{FRONTEND_URL}?auth=error&message=Access+denied.+Contact+your+administrator."
            )
        require_approval = cfg.get("sso_require_approval", "false").lower() == "true"
        approval_status  = "pending" if require_approval else "approved"
        _provision_user(email, name, cfg.get("sso_default_role", "viewer"),
                        "google", uid, approval_status)
        if require_approval:
            _notify_admin_pending(email, name, "google")
        auth_event("login", email, "portal",
                   "pending" if require_approval else "provisioned",
                   "provider=google auto-provisioned")

    # ── Approval gate ────────────────────────────────────────────────────────
    user_entry = _get_user(email)
    approval = user_entry.get("approval_status", "approved") if user_entry else "approved"
    if approval == "pending":
        auth_event("login", email, "portal", "pending", "provider=google")
        return redirect(
            f"{redirect_target}?sso_error=pending_approval&email={urllib.parse.quote(email)}"
        )
    if approval == "rejected":
        auth_event("login", email, "portal", "denied", "provider=google rejected")
        reason = user_entry.get("rejection_reason", "") if user_entry else ""
        msg = urllib.parse.quote(f"Access denied — {reason}" if reason else "Access request was not approved.")
        return redirect(f"{FRONTEND_URL}?auth=error&message={msg}")

    session["user_email"] = email
    session["user_name"]  = name
    session["user_uid"]   = uid
    session.permanent     = True
    auth_event("login", email, "portal", "success", "provider=google")

    return redirect(
        f"{redirect_target}?auth=success&provider=google"
        f"&name={enc(name)}&email={enc(email)}&uid={enc(uid)}&avatar={enc(avatar)}"
        f"&role={enc(get_user_role(email))}&apps={enc(json.dumps(get_user_apps(email)))}"
    )


# ── Microsoft OAuth ───────────────────────────────────────────────────────────

@auth_bp.route("/auth/microsoft")
def auth_microsoft():
    redirect_target = request.args.get('redirect', FRONTEND_URL)
    callback = f"{BASE_URL}/auth/microsoft/callback"
    state    = base64.urlsafe_b64encode(redirect_target.encode()).decode()
    params   = urllib.parse.urlencode({
        "client_id":     MS_CLIENT_ID,
        "redirect_uri":  callback,
        "response_type": "code",
        "scope":         "openid email profile User.Read",
        "state":         state,
    })
    return redirect(
        f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}"
    )


@auth_bp.route("/auth/microsoft/callback")
def auth_microsoft_callback():
    code  = request.args.get("code")
    state = request.args.get("state", "")
    error = request.args.get("error")

    if error:
        desc = request.args.get('error_description', error)
        auth_event("login", "", "portal", "error", desc)
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(desc)}")

    try:
        redirect_target = base64.urlsafe_b64decode(state.encode()).decode()
    except Exception:
        redirect_target = FRONTEND_URL

    if not code:
        return redirect(f"{FRONTEND_URL}?auth=error&message=no_code")

    resp = http_requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "code":          code,
            "client_id":     MS_CLIENT_ID,
            "client_secret": MS_CLIENT_SECRET,
            "redirect_uri":  f"{BASE_URL}/auth/microsoft/callback",
            "grant_type":    "authorization_code",
            "scope":         "openid email profile User.Read",
        },
        timeout=10,
    )

    if not resp.ok:
        auth_event("login", "", "portal", "error", resp.text[:200])
        return redirect(f"{FRONTEND_URL}?auth=error&message={enc(resp.text[:200])}")

    graph  = http_requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {resp.json().get('access_token')}"},
        timeout=10,
    ).json()

    name   = graph.get("displayName", graph.get("userPrincipalName", "Unknown"))
    email  = graph.get("mail") or graph.get("userPrincipalName", "")
    uid    = f"microsoft_{graph.get('id', 'unknown')}"
    avatar = ''.join([w[0].upper() for w in name.split()[:2]])

    if not _get_user(email):
        # Auto-provision via the same policy as the generic OIDC SSO flow.
        from blueprints.sso.routes import _get_sso_cfg, _provision_user, _notify_admin_pending
        cfg = _get_sso_cfg()
        if cfg.get("sso_auto_provision", "true").lower() != "true":
            auth_event("login", email, "portal", "denied", "not in allowlist provider=microsoft")
            return redirect(
                f"{FRONTEND_URL}?auth=error&message=Access+denied.+Contact+your+administrator."
            )
        require_approval = cfg.get("sso_require_approval", "false").lower() == "true"
        approval_status  = "pending" if require_approval else "approved"
        _provision_user(email, name, cfg.get("sso_default_role", "viewer"),
                        "microsoft", uid, approval_status)
        if require_approval:
            _notify_admin_pending(email, name, "microsoft")
        auth_event("login", email, "portal",
                   "pending" if require_approval else "provisioned",
                   "provider=microsoft auto-provisioned")

    # ── Approval gate ────────────────────────────────────────────────────────
    user_entry = _get_user(email)
    approval = user_entry.get("approval_status", "approved") if user_entry else "approved"
    if approval == "pending":
        auth_event("login", email, "portal", "pending", "provider=microsoft")
        return redirect(
            f"{redirect_target}?sso_error=pending_approval&email={urllib.parse.quote(email)}"
        )
    if approval == "rejected":
        auth_event("login", email, "portal", "denied", "provider=microsoft rejected")
        reason = user_entry.get("rejection_reason", "") if user_entry else ""
        msg = urllib.parse.quote(f"Access denied — {reason}" if reason else "Access request was not approved.")
        return redirect(f"{FRONTEND_URL}?auth=error&message={msg}")

    session["user_email"] = email
    session["user_name"]  = name
    session["user_uid"]   = uid
    session.permanent     = True
    auth_event("login", email, "portal", "success", "provider=microsoft")

    return redirect(
        f"{redirect_target}?auth=success&provider=microsoft"
        f"&name={enc(name)}&email={enc(email)}&uid={enc(uid)}&avatar={enc(avatar)}"
        f"&role={enc(get_user_role(email))}&apps={enc(json.dumps(get_user_apps(email)))}"
    )


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/auth/logout")
def logout():
    email = session.get("user_email", "")
    session.clear()
    auth_event("logout", email)
    return redirect(FRONTEND_URL)


# ── Auth verify (nginx sub-request gate) ──────────────────────────────────────

@auth_bp.route("/api/auth/verify")
def auth_verify():
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Not authenticated"}), 401
    # Real-time DB check — immediate revocation when an admin deletes or revokes a user.
    # This runs on every proxied API request (nginx auth_request gate).
    user = _get_user(email)
    if not user:
        session.clear()
        return jsonify({"error": "Account not found"}), 401
    approval = user.get("approval_status", "approved")
    if approval in ("pending", "rejected"):
        session.clear()
        return jsonify({"error": "Access suspended"}), 401
    return jsonify({
        "email": email,
        "name":  session.get("user_name", ""),
        "uid":   session.get("user_uid", ""),
        "role":  get_user_role(email),
    })


# ── Auth log API ──────────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/logs")
def auth_logs():
    n = int(request.args.get("n", 100))
    try:
        lines  = AUTH_LOG_FILE.read_text().splitlines()[-n:]
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except Exception:
                pass
        return jsonify({"events": events, "total": len(events)})
    except Exception:
        return jsonify({"events": [], "total": 0})


# ── Local (username/password) authentication ──────────────────────────────────

@auth_bp.route("/auth/local", methods=["OPTIONS"])
def auth_local_options():
    return make_response('', 204)


@auth_bp.route("/auth/local", methods=["POST"])
def auth_local():
    """Authenticate with email + password against cy_users (local accounts only)."""
    try:
        import bcrypt as _bcrypt
    except ImportError:
        return jsonify({"error": "Local authentication unavailable (bcrypt not installed)"}), 503

    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        auth_event("login", email, "portal", "error", "provider=local missing credentials")
        return jsonify({"error": "Email and password are required"}), 400

    entry = _get_user(email)

    if not entry:
        auth_event("login", email, "portal", "denied", "provider=local user not found")
        return jsonify({"error": "Invalid credentials"}), 401

    auth_type = entry.get("auth_type", "sso")
    pw_hash   = entry.get("password_hash", "")

    if auth_type != "local" or not pw_hash:
        auth_event("login", email, "portal", "denied", "provider=local not a local account")
        return jsonify({"error": "Local login not enabled for this account"}), 401

    try:
        valid = _bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8"))
    except Exception:
        valid = False

    if not valid:
        auth_event("login", email, "portal", "denied", "provider=local bad password")
        return jsonify({"error": "Invalid credentials"}), 401

    name   = entry.get("name") or email.split("@")[0].title()
    uid    = f"local_{email}"
    avatar = ''.join([w[0].upper() for w in name.split()[:2]])

    session["user_email"] = email
    session["user_name"]  = name
    session["user_uid"]   = uid
    session.permanent     = True
    auth_event("login", email, "portal", "success", "provider=local")

    return jsonify({
        "status":   "success",
        "provider": "local",
        "name":     name,
        "email":    email,
        "uid":      uid,
        "avatar":   avatar,
        "role":     get_user_role(email),
        "apps":     get_user_apps(email),
    }), 200


# ── Self-registration (local accounts — request access) ───────────────────────

@auth_bp.route("/api/auth/request-access", methods=["OPTIONS"])
def request_access_options():
    return make_response('', 204)


@auth_bp.route("/api/auth/request-access", methods=["POST"])
def request_access():
    """
    Self-registration for local accounts.
    Creates a pending user record (no password) and notifies the admin via SMTP.
    Access is granted only after an admin approves via User Management.
    """
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    name  = (data.get("name") or "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid email address required"}), 400

    existing = _get_user(email)
    if existing:
        status = existing.get("approval_status", "approved")
        if status == "pending":
            return jsonify({"error": "An access request for this email is already pending."}), 409
        if status == "approved":
            return jsonify({"error": "An account already exists. Please sign in."}), 409
        # rejected — allow re-request (will reset to pending)

    display_name = name or email.split("@")[0].replace(".", " ").title()
    _provision_local_pending(email, display_name)
    from blueprints.sso.routes import _notify_admin_pending as _notify
    _notify(email, display_name, "local")
    auth_event("register", email, "portal", "pending", "provider=local request-access")
    return jsonify({"ok": True}), 200
