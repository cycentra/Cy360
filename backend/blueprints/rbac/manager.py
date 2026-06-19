"""
blueprints/rbac/manager.py
===========================
RBAC — Role-Based Access Control backed by PostgreSQL (cy_users table).

Single source of truth: `cy_users` table in the `correlation` database
(PostgreSQL 16, port 5433).  On every startup the table is auto-created (if
missing) and the default admin account is guaranteed to exist.

Schema
------
  email         TEXT PRIMARY KEY
  role          TEXT NOT NULL DEFAULT 'viewer'
  auth_type     TEXT NOT NULL DEFAULT 'sso'   -- 'sso' | 'local'
  password_hash TEXT                           -- bcrypt, local accounts only
  name          TEXT
  apps          TEXT                           -- JSON-encoded list or NULL
  created_at    TIMESTAMPTZ DEFAULT NOW()
  updated_at    TIMESTAMPTZ DEFAULT NOW()

Exposes:
  get_user_role(email)       → role string
  get_user_apps(email)       → list of permitted app IDs
  user_can_access_client()   → bool

API routes:
  GET    /api/rbac/users               list all users
  POST   /api/rbac/users               add / update a user
  DELETE /api/rbac/users/<email>       remove a user
"""

import json
import logging
import re
from contextlib import contextmanager

from flask import Blueprint, request, jsonify, session, make_response

from core.config import ROLE_APPS, VALID_ROLES, OIDC_CLIENTS, CYCENTRA_DB_URL
from core.helpers import auth_event, add_cors_headers

log = logging.getLogger(__name__)

rbac_bp = Blueprint("rbac", __name__)

# ── Role page-permission defaults ─────────────────────────────────────────────
# None = unrestricted (admin only).  Used during bootstrap and as a DB fallback.
_DEFAULT_ROLE_PAGES: dict = {
    "admin":   None,  # full access — never restrict
    "analyst": [
        "benchmark", "dashboard", "assets", "vulns", "scan",
        "internal-dashboard", "host-inventory", "siem-incidents",
        "siem-ueba", "threat-hunting", "cases",
        "comp-dashboard", "comp-assessment", "comp-findings",
        "comp-risks", "comp-reports",
        "marketplace", "platform-extensions", "audit-trail",
    ],
    "viewer": [
        "benchmark", "dashboard", "assets", "vulns",
        "siem-incidents", "comp-dashboard", "comp-findings", "marketplace",
    ],
    "cysoar": ["dashboard", "siem-incidents", "marketplace"],
}
_BUILTIN_ROLES: frozenset = frozenset(_DEFAULT_ROLE_PAGES.keys())

# ── DDL ───────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cy_users (
    email                   TEXT PRIMARY KEY,
    role                    TEXT        NOT NULL DEFAULT 'viewer',
    auth_type               TEXT        NOT NULL DEFAULT 'sso',
    password_hash           TEXT,
    name                    TEXT,
    apps                    TEXT,
    -- SSO linkage (populated by SSO blueprint on first login)
    sso_provider            TEXT,
    sso_id                  TEXT,
    -- Approval workflow
    approval_status         TEXT        NOT NULL DEFAULT 'approved',
    approval_requested_at   TIMESTAMPTZ,
    approval_resolved_at    TIMESTAMPTZ,
    rejection_reason        TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

# Migration: add new columns to existing deployments (ALTER TABLE … ADD COLUMN IF NOT EXISTS)
_MIGRATE_COLUMNS = [
    "ALTER TABLE cy_users ADD COLUMN IF NOT EXISTS sso_provider           TEXT;",
    "ALTER TABLE cy_users ADD COLUMN IF NOT EXISTS sso_id                 TEXT;",
    "ALTER TABLE cy_users ADD COLUMN IF NOT EXISTS approval_status        TEXT NOT NULL DEFAULT 'approved';",
    "ALTER TABLE cy_users ADD COLUMN IF NOT EXISTS approval_requested_at  TIMESTAMPTZ;",
    "ALTER TABLE cy_users ADD COLUMN IF NOT EXISTS approval_resolved_at   TIMESTAMPTZ;",
    "ALTER TABLE cy_users ADD COLUMN IF NOT EXISTS rejection_reason       TEXT;",
]

_CREATE_ROLES_TABLE = """
CREATE TABLE IF NOT EXISTS cy_roles (
    role_name        TEXT PRIMARY KEY,
    display_name     TEXT,
    is_builtin       BOOLEAN NOT NULL DEFAULT FALSE,
    page_permissions TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

_UPSERT_USER = """
INSERT INTO cy_users (email, role, auth_type, password_hash, name, apps, updated_at)
VALUES (%s, %s, %s, %s, %s, %s, NOW())
ON CONFLICT (email) DO UPDATE SET
    role          = EXCLUDED.role,
    auth_type     = EXCLUDED.auth_type,
    password_hash = EXCLUDED.password_hash,
    name          = EXCLUDED.name,
    apps          = EXCLUDED.apps,
    updated_at    = NOW();
"""

# Pre-computed bcrypt hash of "Admin@123" (rounds=12).
# Used only when bcrypt is unavailable at bootstrap time.
_DEFAULT_ADMIN_HASH = "$2b$12$r34CmzfuwGx8mu49lMiWm.WfeOOKeX8MDzpwEtkg6gmwA81q80sBm"

# ── DB connection ─────────────────────────────────────────────────────────────

_db_ready: bool = False   # set True once table + bootstrap confirmed


@contextmanager
def _db():
    """Yield a psycopg2 connection; caller must commit or the block rolls back."""
    try:
        import psycopg2
    except ImportError:
        raise RuntimeError("psycopg2-binary not installed")
    conn = psycopg2.connect(CYCENTRA_DB_URL, connect_timeout=3)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _bootstrap_admin(cur) -> None:
    """Ensure cyadmin@cycentra.com exists in cy_users. Idempotent."""
    try:
        import bcrypt as _bcrypt
        pw_hash = _bcrypt.hashpw(b"Admin@123", _bcrypt.gensalt(12)).decode()
    except ImportError:
        pw_hash = _DEFAULT_ADMIN_HASH
    cur.execute("""
        INSERT INTO cy_users (email, role, auth_type, password_hash, name)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (email) DO NOTHING;
    """, ("cyadmin@cycentra.com", "admin", "local", pw_hash, "CyCentra Admin"))
    log.info("Bootstrap: cyadmin@cycentra.com ensured in cy_users")


def _bootstrap_roles(cur) -> None:
    """Ensure built-in roles exist in cy_roles. ON CONFLICT DO NOTHING so custom edits persist."""
    _DISPLAY = {
        "admin": "Administrator", "analyst": "Analyst", "viewer": "Viewer",
        "cysoar": "CySOAR User",
    }
    for role_name, pages in _DEFAULT_ROLE_PAGES.items():
        cur.execute("""
            INSERT INTO cy_roles (role_name, display_name, is_builtin, page_permissions)
            VALUES (%s, %s, TRUE, %s) ON CONFLICT (role_name) DO NOTHING;
        """, (role_name, _DISPLAY.get(role_name, role_name.capitalize()),
               json.dumps(pages) if pages is not None else None))
    log.info("Bootstrap: built-in roles ensured in cy_roles")


def _ensure_table() -> None:
    """Create cy_users + cy_roles if missing, run column migrations, and guarantee defaults."""
    global _db_ready
    if _db_ready:
        return
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(_CREATE_TABLE)
            cur.execute(_CREATE_ROLES_TABLE)
            # Idempotent column additions for existing deployments
            for stmt in _MIGRATE_COLUMNS:
                try:
                    cur.execute(stmt)
                except Exception as m_exc:
                    log.debug("Migration stmt skipped (%s): %s", stmt[:60], m_exc)
            _bootstrap_admin(cur)
            _bootstrap_roles(cur)
        _db_ready = True
        log.info("cy_users + cy_roles tables ready (CYCENTRA_DB_URL=%s)", CYCENTRA_DB_URL)
    except Exception as exc:
        log.error("cy_users table init failed — local auth unavailable: %s", exc)


# ── Internal DB helpers ───────────────────────────────────────────────────────

def _row_to_entry(row: tuple) -> dict:
    """Convert a (role, auth_type, pw_hash, name, apps_json, sso_provider, sso_id,
    approval_status, approval_requested_at, approval_resolved_at, rejection_reason) row."""
    (role, auth_type, pw_hash, name, apps_json,
     sso_provider, sso_id,
     approval_status, approval_requested_at,
     approval_resolved_at, rejection_reason) = row + (None,) * max(0, 11 - len(row))
    entry: dict = {
        "role": role,
        "auth_type": auth_type,
        "approval_status": approval_status or "approved",
    }
    if pw_hash:
        entry["password_hash"] = pw_hash
    if name:
        entry["name"] = name
    if apps_json:
        try:
            entry["apps"] = json.loads(apps_json)
        except Exception:
            pass
    if sso_provider:
        entry["sso_provider"] = sso_provider
    if sso_id:
        entry["sso_id"] = sso_id
    if approval_requested_at:
        entry["approval_requested_at"] = approval_requested_at.isoformat() if hasattr(approval_requested_at, "isoformat") else str(approval_requested_at)
    if rejection_reason:
        entry["rejection_reason"] = rejection_reason
    return entry


def _get_user(email: str) -> dict | None:
    """Return the cy_users row for email as a dict, or None if not found."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT role, auth_type, password_hash, name, apps, "
            "       sso_provider, sso_id, "
            "       approval_status, approval_requested_at, "
            "       approval_resolved_at, rejection_reason "
            "FROM cy_users WHERE email = %s;", (email,)
        )
        row = cur.fetchone()
    return _row_to_entry(row) if row else None


def _get_all_users() -> dict:
    """Return all cy_users rows as {email: entry dict}."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT email, role, auth_type, password_hash, name, apps, "
            "       sso_provider, sso_id, "
            "       approval_status, approval_requested_at, "
            "       approval_resolved_at, rejection_reason "
            "FROM cy_users ORDER BY email;"
        )
        rows = cur.fetchall()
    return {email: _row_to_entry(tuple(rest)) for email, *rest in rows}


def _upsert_user(email: str, role: str, auth_type: str = "sso",
                 password_hash: str | None = None, name: str | None = None,
                 apps: list | None = None) -> None:
    """Insert or update a user in cy_users."""
    _ensure_table()
    apps_json = json.dumps(apps) if apps is not None else None
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(_UPSERT_USER, (email, role, auth_type, password_hash, name, apps_json))


def _delete_user(email: str) -> None:
    """Delete a user from cy_users."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cy_users WHERE email = %s;", (email,))


# ── Role DB helpers ───────────────────────────────────────────────────────────

def _get_all_roles() -> list:
    """Return all rows from cy_roles as a list of dicts."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT role_name, display_name, is_builtin, page_permissions "
            "FROM cy_roles ORDER BY is_builtin DESC, role_name;"
        )
        rows = cur.fetchall()
    result = []
    for role_name, display_name, is_builtin, pages_json in rows:
        pages = None
        if pages_json:
            try:
                pages = json.loads(pages_json)
            except Exception:
                pass
        result.append({
            "role_name":        role_name,
            "display_name":     display_name or role_name,
            "is_builtin":       bool(is_builtin),
            "page_permissions": pages,
        })
    return result


def _get_role_pages(role_name: str):
    """Return page_permissions list for a role, or None for unrestricted. Falls back to defaults."""
    try:
        _ensure_table()
        with _db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT page_permissions FROM cy_roles WHERE role_name = %s;", (role_name,))
            row = cur.fetchone()
        if row is None:
            return _DEFAULT_ROLE_PAGES.get(role_name, _DEFAULT_ROLE_PAGES["viewer"])
        return json.loads(row[0]) if row[0] is not None else None
    except Exception as exc:
        log.error("_get_role_pages failed for %s: %s", role_name, exc)
        return _DEFAULT_ROLE_PAGES.get(role_name, _DEFAULT_ROLE_PAGES["viewer"])


def _upsert_role(role_name: str, display_name: str, page_permissions, is_builtin: bool = False) -> None:
    """Insert or update a role in cy_roles."""
    _ensure_table()
    pages_json = json.dumps(page_permissions) if page_permissions is not None else None
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO cy_roles (role_name, display_name, is_builtin, page_permissions, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (role_name) DO UPDATE SET
                display_name     = EXCLUDED.display_name,
                page_permissions = EXCLUDED.page_permissions,
                updated_at       = NOW();
        """, (role_name, display_name, is_builtin, pages_json))


def _delete_custom_role(role_name: str) -> None:
    """Delete a non-built-in role from cy_roles."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cy_roles WHERE role_name = %s AND is_builtin = FALSE;", (role_name,))


def _get_all_role_names() -> set:
    """Return set of all valid role names (built-in + custom) from cy_roles."""
    try:
        _ensure_table()
        with _db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT role_name FROM cy_roles;")
            return {r[0] for r in cur.fetchall()}
    except Exception:
        return set(_BUILTIN_ROLES)


# ── Public functions (imported by other blueprints) ───────────────────────────

def get_user_role(email: str) -> str:
    """Return the RBAC role for an email address. Defaults to 'viewer'."""
    try:
        entry = _get_user(email)
        return entry.get("role", "viewer") if entry else "viewer"
    except Exception as exc:
        log.error("get_user_role failed for %s: %s", email, exc)
        return "viewer"


def get_user_apps(email: str) -> list:
    """Return the list of permitted app IDs for an email address."""
    try:
        entry = _get_user(email) or {}
    except Exception:
        entry = {}
    if "apps" in entry:
        return entry["apps"]
    return ROLE_APPS.get(entry.get("role", "viewer"), ["cy360"])


def user_can_access_client(email: str, client_id: str) -> bool:
    """Check whether the user's role permits access to an OIDC client."""
    client = OIDC_CLIENTS.get(client_id)
    if not client:
        return False
    role = get_user_role(email)
    if role == "admin":
        return True
    if role in client["allowed_roles"]:
        return True
    if client_id in get_user_apps(email):
        return True
    return False


def get_user_allowed_pages(email: str):
    """Return list of allowed page IDs for this user's role, or None for unrestricted (admin)."""
    try:
        role = get_user_role(email)
        return _get_role_pages(role)
    except Exception as exc:
        log.error("get_user_allowed_pages failed for %s: %s", email, exc)
        return _DEFAULT_ROLE_PAGES.get("viewer")


# ── API routes ────────────────────────────────────────────────────────────────

@rbac_bp.route("/api/rbac/users", methods=["GET", "POST"])
def rbac_users():
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Not authenticated"}), 401

    caller_role = get_user_role(caller)
    if caller_role != "admin":
        auth_event("rbac_denied", caller, "", "failure",
                   f"{request.method} /api/rbac/users", request.remote_addr)
        return jsonify({"error": "Admin access required"}), 403

    if request.method == "GET":
        return jsonify(_get_all_users())

    data          = request.get_json() or {}
    email         = data.get("email", "").strip().lower()
    role          = data.get("role", "viewer")
    auth_type     = data.get("auth_type", "sso")
    password_hash = data.get("password_hash")
    name          = data.get("name")
    apps          = data.get("apps")

    if not email or role not in _get_all_role_names():
        return jsonify({"error": "email and valid role required"}), 400

    # If setting a local account password via API, hash it
    if auth_type == "local" and data.get("password"):
        try:
            import bcrypt as _bcrypt
            password_hash = _bcrypt.hashpw(
                data["password"].encode("utf-8"), _bcrypt.gensalt(12)
            ).decode()
        except ImportError:
            return jsonify({"error": "bcrypt not available"}), 503

    try:
        _upsert_user(email, role, auth_type, password_hash, name, apps)
    except Exception as exc:
        log.error("Failed to upsert user %s: %s", email, exc)
        return jsonify({"error": "Database error"}), 500

    auth_event("rbac_role_assigned", caller, "", "success",
               f"assigned role={role} auth_type={auth_type} to {email}",
               request.remote_addr)
    return jsonify({"status": "ok", "email": email, "role": role})


@rbac_bp.route("/api/rbac/users/<path:email>", methods=["DELETE"])
def rbac_delete_user(email):
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Not authenticated"}), 401

    caller_role = get_user_role(caller)
    if caller_role != "admin":
        auth_event("rbac_denied", caller, "", "failure",
                   f"DELETE /api/rbac/users/{email}", request.remote_addr)
        return jsonify({"error": "Admin access required"}), 403

    try:
        _delete_user(email)
    except Exception as exc:
        log.error("Failed to delete user %s: %s", email, exc)
        return jsonify({"error": "Database error"}), 500

    auth_event("rbac_user_deleted", caller, "", "success",
               f"removed user {email} from cy_users", request.remote_addr)
    return jsonify({"status": "deleted", "email": email})


# ── Password reset (local accounts only, admin-only) ─────────────────────────

@rbac_bp.route("/api/rbac/users/<path:email>/reset-password", methods=["OPTIONS"])
def rbac_reset_pw_options(email):
    return add_cors_headers(make_response('', 204))


@rbac_bp.route("/api/rbac/users/<path:email>/reset-password", methods=["POST"])
def rbac_reset_password(email):
    """Reset the password for a local user account.  Admin-only."""
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Not authenticated"}), 401

    if get_user_role(caller) != "admin":
        auth_event("rbac_denied", caller, "", "failure",
                   f"POST /api/rbac/users/{email}/reset-password", request.remote_addr)
        return jsonify({"error": "Admin access required"}), 403

    entry = _get_user(email)
    if not entry:
        return jsonify({"error": "User not found"}), 404
    if entry.get("auth_type") != "local":
        return jsonify({"error": "Password reset is only available for local accounts"}), 400

    data = request.get_json() or {}
    new_password = data.get("password", "").strip()
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    try:
        import bcrypt as _bcrypt
        pw_hash = _bcrypt.hashpw(new_password.encode("utf-8"), _bcrypt.gensalt(12)).decode()
    except ImportError:
        return jsonify({"error": "bcrypt not available on this server"}), 503

    try:
        _upsert_user(email, entry["role"], "local", pw_hash,
                     entry.get("name"), entry.get("apps"))
    except Exception as exc:
        log.error("Failed to reset password for %s: %s", email, exc)
        return jsonify({"error": "Database error"}), 500

    auth_event("rbac_password_reset", caller, "", "success",
               f"password reset for local user {email}", request.remote_addr)
    return jsonify({"status": "ok", "email": email})


# ── Role management routes ────────────────────────────────────────────────────

@rbac_bp.route("/api/rbac/roles", methods=["GET", "POST"])
def rbac_roles():
    """List all roles (GET) or create / update a role (POST). Admin-only."""
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Not authenticated"}), 401
    if get_user_role(caller) != "admin":
        auth_event("rbac_denied", caller, "", "failure",
                   f"{request.method} /api/rbac/roles", request.remote_addr)
        return jsonify({"error": "Admin access required"}), 403

    if request.method == "GET":
        try:
            return jsonify(_get_all_roles())
        except Exception as exc:
            log.error("Failed to list roles: %s", exc)
            return jsonify({"error": "Database error"}), 500

    data             = request.get_json() or {}
    role_name        = (data.get("role_name") or "").strip().lower()
    display_name     = (data.get("display_name") or "").strip()
    page_permissions = data.get("page_permissions")  # list[str] | None

    if not role_name or not re.match(r'^[a-z0-9][a-z0-9_-]*$', role_name):
        return jsonify({"error": "role_name must start with alphanumeric and use only a-z 0-9 _ -"}), 400

    is_builtin = role_name in _BUILTIN_ROLES
    if role_name == "admin":
        page_permissions = None  # admin is always unrestricted

    try:
        _upsert_role(role_name, display_name or role_name, page_permissions, is_builtin)
    except Exception as exc:
        log.error("Failed to upsert role %s: %s", role_name, exc)
        return jsonify({"error": "Database error"}), 500

    auth_event("rbac_role_updated", caller, "", "success",
               f"upserted role={role_name}", request.remote_addr)
    return jsonify({"status": "ok", "role_name": role_name})


@rbac_bp.route("/api/rbac/roles/<role_name>", methods=["DELETE"])
def rbac_delete_role(role_name):
    """Delete a custom (non-built-in) role. Admin-only."""
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Not authenticated"}), 401
    if get_user_role(caller) != "admin":
        auth_event("rbac_denied", caller, "", "failure",
                   f"DELETE /api/rbac/roles/{role_name}", request.remote_addr)
        return jsonify({"error": "Admin access required"}), 403
    if role_name in _BUILTIN_ROLES:
        return jsonify({"error": "Built-in roles cannot be deleted"}), 400

    try:
        _delete_custom_role(role_name)
    except Exception as exc:
        log.error("Failed to delete role %s: %s", role_name, exc)
        return jsonify({"error": "Database error"}), 500

    auth_event("rbac_role_deleted", caller, "", "success",
               f"deleted role={role_name}", request.remote_addr)
    return jsonify({"status": "deleted", "role_name": role_name})


@rbac_bp.route("/api/rbac/my-permissions", methods=["GET"])
def rbac_my_permissions():
    """Return the list of allowed page IDs for the current session user.

    Response: {"allowed_pages": ["dashboard", ...] | null}
    null means unrestricted (admin role).
    """
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Not authenticated"}), 401
    try:
        pages = get_user_allowed_pages(email)
        return jsonify({"allowed_pages": pages})
    except Exception as exc:
        log.error("rbac_my_permissions failed for %s: %s", email, exc)
        return jsonify({"error": "Server error"}), 500
