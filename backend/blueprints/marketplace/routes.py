"""
blueprints/marketplace/routes.py
=================================
Integration Marketplace — catalog, install-state, and submission workflow.

Catalog hierarchy (merged in this order, later entries win on id collision):
  1. Cloud items   — fetched live from cycentra.com when MARKETPLACE_CATALOG_TOKEN is set
  2. Custom items  — created by admins on this server (only "approved" ones shown
                     in the public catalog; draft/submitted visible to admins only)

No items are bundled or hardcoded. Everything comes from the cloud marketplace.

Submission lifecycle (custom items only):
  draft      → created by admin, not visible in public catalog
  submitted  → submitted for review, visible only to admin + cycentra_admin
  approved   → visible to everyone in the catalog
  rejected   → not visible; admin sees the rejection reason

Endpoints:
  GET  /api/marketplace/catalog
  POST /api/marketplace/catalog/custom
  PUT  /api/marketplace/catalog/custom/<id>
  DEL  /api/marketplace/catalog/custom/<id>
  POST /api/marketplace/catalog/custom/<id>/submit
  POST /api/marketplace/catalog/custom/<id>/approve  (cycentra_admin only)
  POST /api/marketplace/catalog/custom/<id>/reject   (cycentra_admin only)
  GET  /api/marketplace/submissions                  (cycentra_admin only)

  GET    /api/marketplace/installed
  POST   /api/marketplace/install
  DELETE /api/marketplace/install/<item_id>
"""

import json
import logging
import os
import re
import datetime

import requests as http_requests
from flask import Blueprint, jsonify, request, session

from core.helpers import add_cors_headers
from core.config  import MARKETPLACE_CATALOG_TOKEN, MARKETPLACE_CATALOG_URL, CYCENTRA_ADMIN_EMAIL

marketplace_bp = Blueprint("marketplace", __name__)
log = logging.getLogger(__name__)

_INSTALL_STATE_FILE  = "/var/ossec/etc/cycentra_marketplace.json"
_CUSTOM_CATALOG_FILE = "/opt/cycentra/marketplace_custom.json"

_VALID_TYPES        = {"integration", "playbook"}
_VALID_STATUSES     = {"draft", "submitted", "approved", "rejected"}
_VALID_CONFIG_TYPES = {"o365", "gcloud", "github", None}
_ID_RE              = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")



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


def _is_cycentra_admin():
    email = session.get("user_email", "")
    return email == CYCENTRA_ADMIN_EMAIL


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
    """Fetch the catalog from cycentra.com.

    Sends X-CyCentra-Token when MARKETPLACE_CATALOG_TOKEN is configured,
    allowing cycentra.com/marketplace/ to restrict access to licensed instances.
    When the token is not set on either side the endpoint is open (backwards compat).

    Returns a (items, status) tuple where status is one of:
      'ok'          — successfully fetched
      'fetch_error' — network/parse error
    """
    try:
        headers = {}
        if MARKETPLACE_CATALOG_TOKEN:
            headers["X-CyCentra-Token"] = MARKETPLACE_CATALOG_TOKEN
        resp = http_requests.get(
            MARKETPLACE_CATALOG_URL,
            headers=headers,
            timeout=6,
        )
        if resp.ok:
            items = resp.json().get("items", [])
            for item in items:
                item["source"] = "cloud"
            return items, "ok"
        log.warning(
            "marketplace catalog fetch failed — HTTP %s from %s",
            resp.status_code, MARKETPLACE_CATALOG_URL,
        )
    except Exception as exc:
        log.warning("marketplace catalog fetch error — %s: %s", type(exc).__name__, exc)
    return [], "fetch_error"


def _read_custom_catalog():
    return _read_json(_CUSTOM_CATALOG_FILE, {"items": []}).get("items", [])


def _write_custom_catalog(items):
    _write_json(_CUSTOM_CATALOG_FILE, {"items": items})


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


# ── CORS preflight ────────────────────────────────────────────────────────────

_PREFLIGHT_ROUTES = [
    "/api/marketplace/catalog",
    "/api/marketplace/catalog/custom",
    "/api/marketplace/catalog/custom/<item_id>",
    "/api/marketplace/catalog/custom/<item_id>/submit",
    "/api/marketplace/catalog/custom/<item_id>/approve",
    "/api/marketplace/catalog/custom/<item_id>/reject",
    "/api/marketplace/submissions",
    "/api/marketplace/installed",
    "/api/marketplace/install",
    "/api/marketplace/install/<item_id>",
]

for _r in _PREFLIGHT_ROUTES:
    marketplace_bp.add_url_rule(
        _r, f"options_{_r.replace('/', '_').replace('<', '').replace('>', '')}",
        lambda **_kw: add_cors_headers(jsonify({})),
        methods=["OPTIONS"],
    )


# ── GET /api/marketplace/catalog ─────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog", methods=["GET"])
def marketplace_catalog():
    """Return the merged catalog visible to the calling user.

    Catalog sources:
      - Cloud items   — fetched from cycentra.com (requires MARKETPLACE_CATALOG_TOKEN)
      - Custom items  — admin-created on this server; only 'approved' ones public

    Admin view extras:
      - Custom items with status == 'draft' or 'submitted' (scoped to creator,
        or all if cycentra_admin)

    Response includes cloud_status so the frontend can show a setup prompt when
    the token is not yet configured.
    """
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    caller       = session["user_email"]
    from blueprints.rbac.manager import get_user_role
    caller_role  = get_user_role(caller)
    is_admin     = caller_role == "admin"
    is_cycentra  = _is_cycentra_admin()

    # Cloud items are the primary source of catalog content
    cloud_items, cloud_status = _fetch_cloud_catalog()
    by_id = {item["id"]: item for item in cloud_items}
    public_items = list(by_id.values())

    # Append custom items based on status + role
    custom_items = _read_custom_catalog()
    for item in custom_items:
        status = item.get("status", "draft")
        if status == "approved":
            item["source"] = "custom"
            public_items.append(item)
        elif is_admin or is_cycentra:
            # Admins see their own drafts/submitted; cycentra_admin sees all
            if is_cycentra or item.get("created_by") == caller:
                item["source"] = "custom"
                public_items.append(item)

    # Count pending submissions so the frontend can show a badge
    pending_count = sum(1 for i in custom_items if i.get("status") == "submitted")

    resp = jsonify({
        "ok":                True,
        "items":             public_items,
        "cloud_status":      cloud_status,
        "is_cycentra_admin": is_cycentra,
        "pending_count":     pending_count if is_cycentra else 0,
    })
    return add_cors_headers(resp)


# ── GET /api/marketplace/submissions ─────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/submissions", methods=["GET"])
def marketplace_submissions():
    """List items pending review. CyCentra admin only."""
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    if not _is_cycentra_admin():
        return add_cors_headers(jsonify({"error": "CyCentra admin access required"})), 403

    custom_items = _read_custom_catalog()
    pending = [i for i in custom_items if i.get("status") == "submitted"]
    resp = jsonify({"ok": True, "submissions": pending, "count": len(pending)})
    return add_cors_headers(resp)


# ── POST /api/marketplace/catalog/custom ─────────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom", methods=["POST"])
def catalog_custom_create():
    """Create a new custom catalog item as a draft. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    data = request.get_json() or {}
    err_resp = _validate_catalog_item(data, existing_id=None)
    if err_resp:
        return add_cors_headers(err_resp[0]), err_resp[1]

    items  = _read_custom_catalog()
    # Prevent duplicate IDs against both cloud catalog and existing custom items
    cloud_ids = {i["id"] for i in _fetch_cloud_catalog()[0]}
    all_ids   = cloud_ids | {i["id"] for i in items}
    if data["id"] in all_ids:
        resp = jsonify({"error": f"ID '{data['id']}' is already in use"})
        return add_cors_headers(resp), 409

    item = _sanitise_item(data)
    item["status"]     = "draft"
    item["created_at"] = _now()
    item["created_by"] = session["user_email"]
    items.append(item)
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": item})
    return add_cors_headers(resp), 201


# ── PUT /api/marketplace/catalog/custom/<id> ─────────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>", methods=["PUT"])
def catalog_custom_update(item_id):
    """Update a custom item (allowed while draft or rejected). Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    # Cloud-sourced items live in the cloud catalog, not the custom file;
    # if someone tries an ID that matches a cloud item it simply won't be found below.
    items = _read_custom_catalog()
    idx   = next((i for i, x in enumerate(items) if x["id"] == item_id), None)
    if idx is None:
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    existing_status = items[idx].get("status", "draft")
    if existing_status == "submitted":
        return add_cors_headers(jsonify({"error": "Cannot edit while under review — recall first"})), 409

    data     = request.get_json() or {}
    data["id"] = item_id
    err_resp = _validate_catalog_item(data, existing_id=item_id)
    if err_resp:
        return add_cors_headers(err_resp[0]), err_resp[1]

    updated = _sanitise_item(data)
    updated["status"]     = existing_status
    updated["created_at"] = items[idx].get("created_at")
    updated["created_by"] = items[idx].get("created_by")
    updated["updated_at"] = _now()
    updated["updated_by"] = session["user_email"]
    items[idx] = updated
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": updated})
    return add_cors_headers(resp)


# ── DELETE /api/marketplace/catalog/custom/<id> ───────────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>", methods=["DELETE"])
def catalog_custom_delete(item_id):
    """Delete a custom item. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    # Cloud items live only in the cloud catalog; they are not in the custom file
    # and will simply return 404 below if someone passes a cloud item ID.
    items     = _read_custom_catalog()
    new_items = [i for i in items if i["id"] != item_id]
    if len(new_items) == len(items):
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    _write_custom_catalog(new_items)

    state     = _read_json(_INSTALL_STATE_FILE, {})
    installed = state.get("installed", [])
    if item_id in installed:
        installed.remove(item_id)
        state.get("installed_meta", {}).pop(item_id, None)
        state["installed"] = installed
        _write_json(_INSTALL_STATE_FILE, state)

    return add_cors_headers(jsonify({"ok": True, "deleted": item_id}))


# ── POST /api/marketplace/catalog/custom/<id>/submit ─────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>/submit", methods=["POST"])
def catalog_custom_submit(item_id):
    """Submit a draft item for CyCentra review. Admin only."""
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    items = _read_custom_catalog()
    idx   = next((i for i, x in enumerate(items) if x["id"] == item_id), None)
    if idx is None:
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    if items[idx].get("status") not in ("draft", "rejected"):
        return add_cors_headers(jsonify({"error": f"Item is already {items[idx].get('status')}"})), 409

    items[idx]["status"]       = "submitted"
    items[idx]["submitted_at"] = _now()
    items[idx]["submitted_by"] = session["user_email"]
    items[idx].pop("rejection_reason", None)
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": items[idx], "message": "Submitted for CyCentra review. You will be notified once approved."})
    return add_cors_headers(resp)


# ── POST /api/marketplace/catalog/custom/<id>/approve ────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>/approve", methods=["POST"])
def catalog_custom_approve(item_id):
    """Approve a submitted item — makes it visible in the public catalog. CyCentra admin only."""
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    if not _is_cycentra_admin():
        return add_cors_headers(jsonify({"error": "CyCentra admin access required to approve items"})), 403

    items = _read_custom_catalog()
    idx   = next((i for i, x in enumerate(items) if x["id"] == item_id), None)
    if idx is None:
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    if items[idx].get("status") != "submitted":
        return add_cors_headers(jsonify({"error": "Only submitted items can be approved"})), 409

    items[idx]["status"]      = "approved"
    items[idx]["approved_at"] = _now()
    items[idx]["approved_by"] = session["user_email"]
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": items[idx], "message": f"'{items[idx]['name']}' is now live in the marketplace."})
    return add_cors_headers(resp)


# ── POST /api/marketplace/catalog/custom/<id>/reject ─────────────────────────

@marketplace_bp.route("/api/marketplace/catalog/custom/<item_id>/reject", methods=["POST"])
def catalog_custom_reject(item_id):
    """Reject a submitted item with a reason. CyCentra admin only."""
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    if not _is_cycentra_admin():
        return add_cors_headers(jsonify({"error": "CyCentra admin access required to reject items"})), 403

    items = _read_custom_catalog()
    idx   = next((i for i, x in enumerate(items) if x["id"] == item_id), None)
    if idx is None:
        return add_cors_headers(jsonify({"error": "Item not found"})), 404

    data   = request.get_json() or {}
    reason = (data.get("reason") or "").strip()
    if not reason:
        return add_cors_headers(jsonify({"error": "A rejection reason is required"})), 400

    items[idx]["status"]           = "rejected"
    items[idx]["rejected_at"]      = _now()
    items[idx]["rejected_by"]      = session["user_email"]
    items[idx]["rejection_reason"] = reason
    _write_custom_catalog(items)

    resp = jsonify({"ok": True, "item": items[idx], "message": "Item rejected."})
    return add_cors_headers(resp)


# ── GET /api/marketplace/installed ───────────────────────────────────────────

def _configured_items(installed: list) -> list:
    """Return the subset of installed items whose backend integration is actively configured.

    For cloud integrations (office365, google-cloud) we check that the corresponding
    Wazuh config block is present and non-placeholder in ossec.conf.
    All other items (playbooks, integrations without active Wazuh config) are
    considered configured once installed.
    """
    configured = []
    for item_id in installed:
        if item_id == "office365":
            try:
                from pathlib import Path as _Path
                content = _Path("/var/ossec/etc/ossec.conf").read_text()
                m = re.search(r'<office365>(.*?)</office365>', content, re.DOTALL)
                if m and "PLACEHOLDER" not in m.group(1):
                    configured.append("office365")
            except OSError:
                pass
        elif item_id == "google-cloud":
            try:
                from pathlib import Path as _Path
                content = _Path("/var/ossec/etc/ossec.conf").read_text()
                if re.search(r'<wodle name="gcp-pubsub">', content):
                    configured.append("google-cloud")
            except OSError:
                pass
        else:
            # Playbooks and all other integrations are configured once installed
            configured.append(item_id)
    return configured


@marketplace_bp.route("/api/marketplace/installed", methods=["GET"])
def marketplace_installed():
    err = _require_auth()
    if err:
        return add_cors_headers(err[0]), err[1]

    state     = _read_json(_INSTALL_STATE_FILE, {})
    installed = state.get("installed", [])
    configured = _configured_items(installed)
    return add_cors_headers(jsonify({"ok": True, "installed": installed, "configured": configured}))


# ── POST /api/marketplace/install ────────────────────────────────────────────

@marketplace_bp.route("/api/marketplace/install", methods=["POST"])
def marketplace_install():
    err = _require_admin()
    if err:
        return add_cors_headers(err[0]), err[1]

    data    = request.get_json() or {}
    item_id = (data.get("id") or "").strip()
    if not item_id:
        return add_cors_headers(jsonify({"error": "item id required"})), 400

    if not _ID_RE.match(item_id):
        return add_cors_headers(jsonify({"error": "Invalid item id format"})), 400

    state     = _read_json(_INSTALL_STATE_FILE, {})
    installed = state.get("installed", [])
    meta      = state.get("installed_meta", {})

    if item_id not in installed:
        installed.append(item_id)
        meta[item_id] = {"installed_at": _now(), "installed_by": session["user_email"]}
        state["installed"]      = installed
        state["installed_meta"] = meta
        _write_json(_INSTALL_STATE_FILE, state)

    return add_cors_headers(jsonify({"ok": True, "installed": installed}))


# ── DELETE /api/marketplace/install/<item_id> ─────────────────────────────────

@marketplace_bp.route("/api/marketplace/install/<item_id>", methods=["DELETE"])
def marketplace_uninstall(item_id):
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

    return add_cors_headers(jsonify({"ok": True, "installed": installed}))


# ── validation helpers ────────────────────────────────────────────────────────

def _validate_catalog_item(data, existing_id):
    item_id = (data.get("id") or "").strip()
    if not item_id or not _ID_RE.match(item_id):
        return jsonify({"error": "id must be lowercase alphanumeric + hyphens, 3–50 chars"}), 400
    if not (data.get("name") or "").strip():
        return jsonify({"error": "name is required"}), 400
    if data.get("type") not in _VALID_TYPES:
        return jsonify({"error": f"type must be one of: {sorted(_VALID_TYPES)}"}), 400
    if not (data.get("description") or "").strip():
        return jsonify({"error": "description is required"}), 400
    config_type = data.get("config_type")
    if config_type not in _VALID_CONFIG_TYPES:
        return jsonify({"error": "config_type must be o365, gcloud, github, or omitted"}), 400
    return None


def _sanitise_item(data):
    steps   = data.get("steps") or []
    modules = data.get("modules_required") or []
    tags    = data.get("tags") or []
    if not isinstance(steps,   list): steps   = []
    if not isinstance(modules, list): modules = []
    if not isinstance(tags,    list): tags    = []

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
