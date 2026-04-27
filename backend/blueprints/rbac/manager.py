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
from contextlib import contextmanager

from flask import Blueprint, request, jsonify, session, make_response

from core.config import ROLE_APPS, VALID_ROLES, OIDC_CLIENTS, CYCENTRA_DB_URL
from core.helpers import auth_event, add_cors_headers

log = logging.getLogger(__name__)

rbac_bp = Blueprint("rbac", __name__)

# ── DDL ───────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cy_users (
    email         TEXT PRIMARY KEY,
    role          TEXT        NOT NULL DEFAULT 'viewer',
    auth_type     TEXT        NOT NULL DEFAULT 'sso',
    password_hash TEXT,
    name          TEXT,
    apps          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
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


def _ensure_table() -> None:
    """Create cy_users if missing and guarantee the default admin exists."""
    global _db_ready
    if _db_ready:
        return
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(_CREATE_TABLE)
            _bootstrap_admin(cur)
        _db_ready = True
        log.info("cy_users table ready (CYCENTRA_DB_URL=%s)", CYCENTRA_DB_URL)
    except Exception as exc:
        log.error("cy_users table init failed — local auth unavailable: %s", exc)


# ── Internal DB helpers ───────────────────────────────────────────────────────

def _row_to_entry(row: tuple) -> dict:
    """Convert a (role, auth_type, pw_hash, name, apps_json) row to an entry dict."""
    role, auth_type, pw_hash, name, apps_json = row
    entry: dict = {"role": role, "auth_type": auth_type}
    if pw_hash:
        entry["password_hash"] = pw_hash
    if name:
        entry["name"] = name
    if apps_json:
        try:
            entry["apps"] = json.loads(apps_json)
        except Exception:
            pass
    return entry


def _get_user(email: str) -> dict | None:
    """Return the cy_users row for email as a dict, or None if not found."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT role, auth_type, password_hash, name, apps "
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
            "SELECT email, role, auth_type, password_hash, name, apps "
            "FROM cy_users ORDER BY email;"
        )
        rows = cur.fetchall()
    return {email: _row_to_entry(rest) for email, *rest in rows}


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

    if not email or role not in VALID_ROLES:
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
