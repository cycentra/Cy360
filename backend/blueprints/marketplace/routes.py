"""
blueprints/marketplace/routes.py
=================================
Integration Marketplace install-state tracking.

Endpoints:
  GET    /api/marketplace/installed          list installed integration/playbook IDs
  POST   /api/marketplace/install            pull an item from cloud (admin only)
  DELETE /api/marketplace/install/<item_id>  remove an installed item  (admin only)

Install state is persisted to _MARKETPLACE_STATE_FILE as a simple JSON document.
No actual software is installed here — this tracks which catalog items the admin
has pulled so the UI can show Installed vs Available correctly.
"""

import json
import os
import datetime

from flask import Blueprint, jsonify, request, session
from core.helpers import add_cors_headers

marketplace_bp = Blueprint("marketplace", __name__)

_MARKETPLACE_STATE_FILE = "/var/ossec/etc/cycentra_marketplace.json"

# Allowed catalog item IDs — must match catalog.json on cycentra.com.
# Used for basic input validation; not a security boundary.
_KNOWN_ITEM_IDS = {
    "office365", "google-cloud",
    "phishing-response", "block-ip", "ioc-enrichment",
    "malware-isolation", "vuln-ticket", "brute-force-response",
}


def _read_state():
    try:
        with open(_MARKETPLACE_STATE_FILE, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _write_state(state):
    os.makedirs(os.path.dirname(_MARKETPLACE_STATE_FILE), exist_ok=True)
    with open(_MARKETPLACE_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── CORS preflight ────────────────────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/installed", methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/install", methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/install/<item_id>", methods=["OPTIONS"])
def marketplace_options(item_id=None):
    resp = jsonify({})
    return add_cors_headers(resp)


# ── GET /api/marketplace/installed ───────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/installed", methods=["GET"])
def marketplace_installed():
    """Return the list of installed item IDs. Any authenticated user may call this."""
    if not session.get("user_email"):
        resp = jsonify({"error": "Authentication required"})
        return add_cors_headers(resp), 401

    state = _read_state()
    installed = state.get("installed", [])
    resp = jsonify({"ok": True, "installed": installed})
    return add_cors_headers(resp)


# ── POST /api/marketplace/install ────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/install", methods=["POST"])
def marketplace_install():
    """Mark a catalog item as installed. Admin only."""
    if not session.get("user_email"):
        resp = jsonify({"error": "Authentication required"})
        return add_cors_headers(resp), 401

    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        resp = jsonify({"error": "Admin role required to pull marketplace items"})
        return add_cors_headers(resp), 403

    data    = request.get_json() or {}
    item_id = (data.get("id") or "").strip()

    if not item_id:
        resp = jsonify({"error": "item id required"})
        return add_cors_headers(resp), 400

    if item_id not in _KNOWN_ITEM_IDS:
        resp = jsonify({"error": f"Unknown item: {item_id}"})
        return add_cors_headers(resp), 400

    state     = _read_state()
    installed = state.get("installed", [])
    meta      = state.get("installed_meta", {})

    if item_id not in installed:
        installed.append(item_id)
        meta[item_id] = {
            "installed_at": datetime.datetime.utcnow().isoformat() + "Z",
            "installed_by": session["user_email"],
        }
        state["installed"]      = installed
        state["installed_meta"] = meta
        _write_state(state)

    resp = jsonify({"ok": True, "installed": installed})
    return add_cors_headers(resp)


# ── DELETE /api/marketplace/install/<item_id> ─────────────────────────────────

@marketplace_bp.route("/api/marketplace/install/<item_id>", methods=["DELETE"])
def marketplace_uninstall(item_id):
    """Remove a catalog item from the installed list. Admin only."""
    if not session.get("user_email"):
        resp = jsonify({"error": "Authentication required"})
        return add_cors_headers(resp), 401

    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        resp = jsonify({"error": "Admin role required to remove marketplace items"})
        return add_cors_headers(resp), 403

    state     = _read_state()
    installed = state.get("installed", [])
    meta      = state.get("installed_meta", {})

    if item_id in installed:
        installed.remove(item_id)
        meta.pop(item_id, None)
        state["installed"]      = installed
        state["installed_meta"] = meta
        _write_state(state)

    resp = jsonify({"ok": True, "installed": installed})
    return add_cors_headers(resp)
