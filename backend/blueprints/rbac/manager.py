"""
blueprints/rbac/manager.py
===========================
RBAC — Role-Based Access Control.

Exposes:
  get_user_role(email)       → role string
  get_user_apps(email)       → list of permitted app IDs
  user_can_access_client()   → bool

API routes:
  GET  /api/rbac/users       list all users
  POST /api/rbac/users       add / update a user role
  DELETE /api/rbac/users/<email>   remove a user
"""

import json
from flask import Blueprint, request, jsonify, session

from core.config import RBAC_FILE, ROLE_APPS, VALID_ROLES, OIDC_CLIENTS
from core.helpers import auth_event

rbac_bp = Blueprint("rbac", __name__)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _load_rbac() -> dict:
    try:
        if RBAC_FILE.exists():
            return json.loads(RBAC_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_rbac(rbac: dict):
    RBAC_FILE.parent.mkdir(parents=True, exist_ok=True)
    RBAC_FILE.write_text(json.dumps(rbac, indent=2))


# ── Public functions (imported by other blueprints) ───────────────────────────

def get_user_role(email: str) -> str:
    """Return the RBAC role for an email address. Defaults to 'viewer'."""
    return _load_rbac().get(email, {}).get("role", "viewer")


def get_user_apps(email: str) -> list:
    """Return the list of permitted app IDs for an email address."""
    entry = _load_rbac().get(email, {})
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
        return jsonify(_load_rbac())

    data  = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    role  = data.get("role", "viewer")

    if not email or role not in VALID_ROLES:
        return jsonify({"error": "email and valid role required"}), 400

    rbac = _load_rbac()
    rbac[email] = {"role": role}
    _save_rbac(rbac)
    auth_event("rbac_role_assigned", caller, "", "success",
               f"assigned role={role} to {email}", request.remote_addr)
    return jsonify({"status": "ok", "email": email, "role": role})


@rbac_bp.route("/api/rbac/users/<email>", methods=["DELETE"])
def rbac_delete_user(email):
    caller = session.get("user_email")
    if not caller:
        return jsonify({"error": "Not authenticated"}), 401

    caller_role = get_user_role(caller)
    if caller_role != "admin":
        auth_event("rbac_denied", caller, "", "failure",
                   f"DELETE /api/rbac/users/{email}", request.remote_addr)
        return jsonify({"error": "Admin access required"}), 403

    rbac = _load_rbac()
    rbac.pop(email, None)
    _save_rbac(rbac)
    auth_event("rbac_user_deleted", caller, "", "success",
               f"removed user {email} from RBAC", request.remote_addr)
    return jsonify({"status": "deleted", "email": email})
