"""
blueprints/rbac/manager.py
===========================
RBAC — Role-Based Access Control backed by PostgreSQL (cy_users table).

Single source of truth: `cy_users` table in the `correlation` database
(PostgreSQL 16, port 5433).  On first startup the table is auto-created and
any existing rbac.json entries are migrated in.  rbac.json / rbac.default.json
are retained as a cold fallback in case the DB is unreachable.

Schema
------
  email         TEXT PRIMARY KEY
  role          TEXT NOT NULL DEFAULT 'viewer'
  auth_type     TEXT NOT NULL DEFAULT 'sso'   -- 'sso' | 'local'
  password_hash TEXT                           -- bcrypt, local accounts only
  name          TEXT
  apps          TEXT                           -- JSON array or NULL
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

from flask import Blueprint, request, jsonify, session

from core.config import RBAC_FILE, ROLE_APPS, VALID_ROLES, OIDC_CLIENTS, CYCENTRA_DB_URL
from core.helpers import auth_event

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

# ── DB connection ─────────────────────────────────────────────────────────────

_db_ready: bool = False   # set True once table exists + migration done


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


def _ensure_table():
    """Create cy_users if missing; migrate rbac.json on first run."""
    global _db_ready
    if _db_ready:
        return
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(_CREATE_TABLE)

            # Migrate rbac.json → DB if the table is still empty
            cur.execute("SELECT COUNT(*) FROM cy_users;")
            count = cur.fetchone()[0]
            if count == 0:
                _migrate_json(cur)
        _db_ready = True
    except Exception as exc:
        log.warning("cy_users table init failed — falling back to JSON: %s", exc)


def _migrate_json(cur):
    """Import every entry from rbac.json (or rbac.default.json) into cy_users.

    Falls back to rbac.json.old and, as a final guarantee, seeds the hardcoded
    default admin so the system always has at least one login even when no JSON
    files are present.
    """
    data = _json_load_raw()

    # Additional fallback: try rbac.json.old (created when admin renames the file)
    if not data:
        _old = RBAC_FILE.parent / "rbac.json.old"
        try:
            if _old.exists():
                data = json.loads(_old.read_text())
                log.info("Migrating from rbac.json.old (%d entries)", len(data))
        except Exception:
            pass

    if data:
        for email, entry in data.items():
            cur.execute(_UPSERT_USER, (
                email,
                entry.get("role", "viewer"),
                entry.get("auth_type", "sso"),
                entry.get("password_hash"),
                entry.get("name"),
                json.dumps(entry["apps"]) if "apps" in entry else None,
            ))
        log.info("Migrated %d users from rbac JSON into cy_users table", len(data))

    # Always guarantee the default admin account exists — INSERT only if absent.
    # This is idempotent: if cyadmin already came from JSON above, ON CONFLICT
    # leaves it untouched (DO NOTHING variant keeps the existing password_hash).
    _DEFAULT_HASH = "$2b$12$r34CmzfuwGx8mu49lMiWm.WfeOOKeX8MDzpwEtkg6gmwA81q80sBm"
    try:
        import bcrypt as _bcrypt
        _default_pw = _bcrypt.hashpw(b"Admin@123", _bcrypt.gensalt(12)).decode()
    except ImportError:
        _default_pw = _DEFAULT_HASH  # pre-computed fallback

    cur.execute("""
        INSERT INTO cy_users (email, role, auth_type, password_hash, name)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (email) DO NOTHING;
    """, ("cyadmin@cycentra.com", "admin", "local", _default_pw, "CyCentra Admin"))
    log.info("Default admin bootstrap: cyadmin@cycentra.com ensured in cy_users")


# ── JSON helpers (fallback + migration source) ────────────────────────────────

def _json_load_raw() -> dict:
    """Load rbac.json, falling back to rbac.default.json."""
    for path in (RBAC_FILE, RBAC_FILE.parent / "rbac.default.json"):
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception:
            pass
    return {}


# ── Public read functions ─────────────────────────────────────────────────────

def _get_user(email: str) -> dict | None:
    """Return the cy_users row for email as a dict, or None. Falls back to JSON."""
    _ensure_table()
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT role, auth_type, password_hash, name, apps "
                "FROM cy_users WHERE email = %s;", (email,)
            )
            row = cur.fetchone()
        if row is None:
            return None
        role, auth_type, pw_hash, name, apps_json = row
        entry = {"role": role, "auth_type": auth_type}
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
    except Exception as exc:
        log.warning("DB read failed for %s — falling back to JSON: %s", email, exc)
        return _json_load_raw().get(email)


def _get_all_users() -> dict:
    """Return all cy_users as {email: entry}. Falls back to JSON."""
    _ensure_table()
    try:
        with _db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT email, role, auth_type, password_hash, name, apps "
                "FROM cy_users ORDER BY email;"
            )
            rows = cur.fetchall()
        result = {}
        for email, role, auth_type, pw_hash, name, apps_json in rows:
            entry = {"role": role, "auth_type": auth_type}
            if pw_hash:
                entry["password_hash"] = pw_hash
            if name:
                entry["name"] = name
            if apps_json:
                try:
                    entry["apps"] = json.loads(apps_json)
                except Exception:
                    pass
            result[email] = entry
        return result
    except Exception as exc:
        log.warning("DB read (all users) failed — falling back to JSON: %s", exc)
        return _json_load_raw()


def _upsert_user(email: str, role: str, auth_type: str = "sso",
                 password_hash: str | None = None, name: str | None = None,
                 apps: list | None = None):
    """Insert or update a user in cy_users."""
    _ensure_table()
    apps_json = json.dumps(apps) if apps is not None else None
    with _db() as conn:
        cur = conn.cursor()
        cur.execute(_UPSERT_USER, (email, role, auth_type, password_hash, name, apps_json))


def _delete_user(email: str):
    """Delete a user from cy_users."""
    _ensure_table()
    with _db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cy_users WHERE email = %s;", (email,))


# ── Public functions (imported by other blueprints) ───────────────────────────

def get_user_role(email: str) -> str:
    """Return the RBAC role for an email address. Defaults to 'viewer'."""
    entry = _get_user(email)
    return entry.get("role", "viewer") if entry else "viewer"


def get_user_apps(email: str) -> list:
    """Return the list of permitted app IDs for an email address."""
    entry = _get_user(email) or {}
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


# ── Backward-compat shim (used by blueprints/auth/oauth.py) ──────────────────

def _load_rbac() -> dict:
    """Legacy shim — returns all users as a dict. New code uses _get_user()."""
    return _get_all_users()


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
