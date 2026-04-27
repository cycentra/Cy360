"""
blueprints/marketplace/routes.py
=================================
Integration Marketplace — catalog proxy, install-state tracking, and
custom catalog management.

Endpoints:
  GET  /api/marketplace/catalog               fetch catalog (cloud + custom), admin-gated
  POST /api/marketplace/catalog/custom        add a custom catalog item     (admin only)
  PUT  /api/marketplace/catalog/custom/<id>   update a custom catalog item  (admin only)
  DEL  /api/marketplace/catalog/custom/<id>   delete a custom catalog item  (admin only)

  GET    /api/marketplace/installed           list installed item IDs
  POST   /api/marketplace/install             mark an item as installed      (admin only)
  DELETE /api/marketplace/install/<item_id>   remove from installed list     (admin only)

Security model:
  - Catalog is fetched server-to-server from cycentra.com using a pre-shared
    token (MARKETPLACE_CATALOG_TOKEN).  The token and the cloud URL never reach
    the browser — only this backend knows them.
  - Any authenticated session may read the catalog and the installed list.
  - All write operations require admin role.
"""

import json
import os
import re
import datetime

import requests as http_requests
from flask import Blueprint, jsonify, request, session

from core.helpers import add_cors_headers
from core.config  import MARKETPLACE_CATALOG_TOKEN, MARKETPLACE_CATALOG_URL

marketplace_bp = Blueprint("marketplace", __name__)

_INSTALL_STATE_FILE  = "/var/ossec/etc/cycentra_marketplace.json"
_CUSTOM_CATALOG_FILE = "/opt/cycentra/marketplace_custom.json"

_BUILTIN_IDS = {
    "office365", "google-cloud",
    "phishing-response", "block-ip", "ioc-enrichment",
    "malware-isolation", "vuln-ticket", "brute-force-response",
}

_VALID_TYPES      = {"integration", "playbook"}
_VALID_CONFIG_TYPES = {"o365", "gcloud", None}
_ID_RE            = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")


# ── helpers ───────────────────────────────────────────────────────────────────

def _require_auth():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    return None


def _require_admin():
    err = _require_auth()
    if err:
        return err
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Admin role required"}), 403
    return None


def _read_json(path, default):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else default
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _fetch_cloud_catalog():
    """Fetch the cloud catalog server-to-server using the pre-shared token."""
    if not MARKETPLACE_CATALOG_TOKEN:
        return []
    try:
        resp = http_requests.get(
            MARKETPLACE_CATALOG_URL,
            headers={"X-CyCentra-Token": MARKETPLACE_CATALOG_TOKEN},
            timeout=6,
        )
        if resp.ok:
            return resp.json().get("items", [])
    except Exception:
        pass
    return []


def _read_custom_catalog():
    return _read_json(_CUSTOM_CATALOG_FILE, {"items": []}).get("items", [])


def _write_custom_catalog(items):
    _write_json(_CUSTOM_CATALOG_FILE, {"items": items})


# ── CORS preflight ────────────────────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog",                   methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/catalog/custom",            methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>",  methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/installed",                 methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/install",                   methods=["OPTIONS"])
@marketplace_bp.route("/api/marketplace/install/<item_id>",         methods=["OPTIONS"])
def marketplace_options(item_id=None):
    return add_cors_headers(jsonify({}))


# ── GET /api/marketplace/catalog ─────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog", methods=["GET"])
def marketplace_catalog():
    """Return the merged catalog (cloud items + custom items).
    Any authenticated user can read. The cloud fetch uses the pre-shared token
    transparently — the browser never sees the token or the cycentra.com URL."""
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    cloud_items  = _fetch_cloud_catalog()
    custom_items = _read_custom_catalog()

    for item in cloud_items:
        item["source"] = "cloud"
    for item in custom_items:
        item["source"] = "custom"

    resp = jsonify({"ok": True, "items": cloud_items + custom_items})
    return add_cors_headers(resp)


# ── POST /api/marketplace/catalog/custom ─────────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom", methods=["POST"])
def catalog_custom_create():
    """Add a new custom catalog item. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    data = request.get_json() or {}
    err_resp = _validate_catalog_item(data, existing_id=None)
    if err_resp:
        return add_cors_headers(err_resp[0]), err_resp[1]

    items = _read_custom_catalog()

    # Guard: no duplicate IDs across cloud built-ins or existing custom items
    all_ids = _BUILTIN_IDS | {i["id"] for i in items}
    if data["id"] in all_ids:
        resp = jsonify({"error": f"ID '{data['id']}' is already in use"})
        return add_cors_headers(resp), 409

    item = _sanitise_item(data)
    item["created_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    item["created_by"] = session["user_email"]
    items.append(item)
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": item})
    return add_cors_headers(resp), 201


# ── PUT /api/marketplace/catalog/custom/<id> ─────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>", methods=["PUT"])
def catalog_custom_update(item_id):
    """Update an existing custom catalog item. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    if item_id in _BUILTIN_IDS:
        resp = jsonify({"error": "Built-in cloud items cannot be edited here"})
        return add_cors_headers(resp), 403

    items = _read_custom_catalog()
    idx   = next((i for i, x in enumerate(items) if x["id"] == item_id), None)
    if idx is None:
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    data = request.get_json() or {}
    data["id"] = item_id  # id is immutable
    err_resp = _validate_catalog_item(data, existing_id=item_id)
    if err_resp:
        return add_cors_headers(err_resp[0]), err_resp[1]

    updated = _sanitise_item(data)
    updated["created_at"] = items[idx].get("created_at")
    updated["created_by"] = items[idx].get("created_by")
    updated["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"
    updated["updated_by"] = session["user_email"]
    items[idx] = updated
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": updated})
    return add_cors_headers(resp)


# ── DELETE /api/marketplace/catalog/custom/<id> ───────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>", methods=["DELETE"])
def catalog_custom_delete(item_id):
    """Delete a custom catalog item. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    if item_id in _BUILTIN_IDS:
        resp = jsonify({"error": "Built-in cloud items cannot be deleted"})
        return add_cors_headers(resp), 403

    items = _read_custom_catalog()
    new_items = [i for i in items if i["id"] != item_id]
    if len(new_items) == len(items):
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    _write_custom_catalog(new_items)

    # Also remove from installed list if present
    state     = _read_json(_INSTALL_STATE_FILE, {})
    installed = state.get("installed", [])
    if item_id in installed:
        installed.remove(item_id)
        state.get("installed_meta", {}).pop(item_id, None)
        state["installed"] = installed
        _write_json(_INSTALL_STATE_FILE, state)

    resp = jsonify({"ok": True, "deleted": item_id})
    return add_cors_headers(resp)


# ── GET /api/marketplace/installed ───────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/installed", methods=["GET"])
def marketplace_installed():
    """Return the list of installed item IDs. Any authenticated user may call this."""
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    state     = _read_json(_INSTALL_STATE_FILE, {})
    installed = state.get("installed", [])
    resp = jsonify({"ok": True, "installed": installed})
    return add_cors_headers(resp)


# ── POST /api/marketplace/install ────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/install", methods=["POST"])
def marketplace_install():
    """Mark a catalog item as installed on this server. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    data    = request.get_json() or {}
    item_id = (data.get("id") or "").strip()

    if not item_id:
        return add_cors_headers(jsonify({"error": "item id required"})), 400

    custom_ids = {i["id"] for i in _read_custom_catalog()}
    if item_id not in _BUILTIN_IDS and item_id not in custom_ids:
        resp = jsonify({"error": f"Unknown item '{item_id}' — pull from a valid catalog entry"})
        return add_cors_headers(resp), 400

    state     = _read_json(_INSTALL_STATE_FILE, {})
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
        _write_json(_INSTALL_STATE_FILE, state)

    resp = jsonify({"ok": True, "installed": installed})
    return add_cors_headers(resp)


# ── DELETE /api/marketplace/install/<item_id> ─────────────────────────────────

@marketplace_bp.route("/api/marketplace/install/<item_id>", methods=["DELETE"])
def marketplace_uninstall(item_id):
    """Remove an item from the installed list. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    state     = _read_json(_INSTALL_STATE_FILE, {})
    installed = state.get("installed", [])
    meta      = state.get("installed_meta", {})

    if item_id in installed:
        installed.remove(item_id)
        meta.pop(item_id, None)
        state["installed"]      = installed
        state["installed_meta"] = meta
        _write_json(_INSTALL_STATE_FILE, state)

    resp = jsonify({"ok": True, "installed": installed})
    return add_cors_headers(resp)


# ── validation helpers ────────────────────────────────────────────────────────

def _validate_catalog_item(data, existing_id):
    """Return (jsonify_response, status_code) on error, None on success."""
    item_id = (data.get("id") or "").strip()
    if not item_id or not _ID_RE.match(item_id):
        resp = jsonify({"error": "id must be lowercase alphanumeric + hyphens, 3–50 chars"})
        return resp, 400

    if not (data.get("name") or "").strip():
        return jsonify({"error": "name is required"}), 400

    if data.get("type") not in _VALID_TYPES:
        return jsonify({"error": f"type must be one of: {sorted(_VALID_TYPES)}"}), 400

    if not (data.get("description") or "").strip():
        return jsonify({"error": "description is required"}), 400

    config_type = data.get("config_type")
    if config_type not in _VALID_CONFIG_TYPES:
        return jsonify({"error": f"config_type must be one of: o365, gcloud, or omitted"}), 400

    return None


def _sanitise_item(data):
    """Return a clean dict with only recognised catalog fields."""
    steps = data.get("steps") or []
    if not isinstance(steps, list):
        steps = []

    modules = data.get("modules_required") or []
    if not isinstance(modules, list):
        modules = []

    tags = data.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    item = {
        "id":               (data.get("id") or "").strip(),
        "name":             (data.get("name") or "").strip(),
        "type":             data.get("type"),
        "category":         (data.get("category") or "").strip(),
        "vendor":           (data.get("vendor") or "CyCentra").strip(),
        "icon":             (data.get("icon") or "🔧").strip(),
        "color":            (data.get("color") or "#4d9eff").strip(),
        "description":      (data.get("description") or "").strip(),
        "modules_required": [str(m).strip() for m in modules if str(m).strip()],
        "estimated_time":   (data.get("estimated_time") or "").strip(),
        "tags":             [str(t).strip().lower() for t in tags if str(t).strip()],
    }

    if data.get("config_type"):
        item["config_type"] = data["config_type"]
    if data.get("cysoar_flow"):
        item["cysoar_flow"] = (data["cysoar_flow"] or "").strip()
    if steps:
        item["steps"] = [str(s).strip() for s in steps if str(s).strip()]

    return item
