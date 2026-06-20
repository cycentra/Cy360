"""
blueprints/integrations/routes.py
====================================
REST API for integration health monitoring.

Routes:
  GET  /api/integrations/health           — list all statuses (viewer+)
  GET  /api/integrations/health/<name>    — single integration status (viewer+)
  POST /api/integrations/health/check     — trigger manual check (analyst+)
  GET  /api/integrations/health/config    — read health-check config (admin)
  POST /api/integrations/health/config    — write health-check config (admin)
"""

import json
import logging
import os
from datetime import datetime, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, make_response, request, session

from blueprints.rbac.manager import get_user_role
from core.helpers import add_cors_headers

log = logging.getLogger("cycentra.integrations")

integrations_bp = Blueprint("integrations", __name__)

_CONFIG_FILE = "/opt/cycentra/integration_health_config.json"


# ── RBAC decorators ───────────────────────────────────────────────────────────

def _require_viewer(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return _inner


def _require_analyst(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        email = session.get("user_email")
        if not email:
            return jsonify({"error": "Authentication required"}), 401
        if get_user_role(email) not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return _inner


def _require_admin(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        email = session.get("user_email")
        if not email:
            return jsonify({"error": "Authentication required"}), 401
        if get_user_role(email) != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*args, **kwargs)
    return _inner


# ── DB helper ─────────────────────────────────────────────────────────────────

def _db():
    url = os.environ.get("CORRELATION_DB_URL") or os.environ.get("CYCENTRA_DB_URL") or \
          "postgresql://corruser:changeme@127.0.0.1:5433/correlation"
    conn = psycopg2.connect(url)
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


def _serialize_row(row: dict) -> dict:
    return {k: _iso(v) for k, v in row.items()}


# ── Config helpers ────────────────────────────────────────────────────────────

def _read_config() -> dict:
    try:
        return json.loads(open(_CONFIG_FILE).read())
    except Exception:
        return {
            "enabled":          True,
            "interval_seconds": int(os.environ.get("INTEGRATION_HEALTH_INTERVAL", "300")),
            "ingest_window_min": int(os.environ.get("INTEGRATION_HEALTH_INGEST_WINDOW", "15")),
            "notify_on_recovery": True,
        }


def _write_config(cfg: dict):
    with open(_CONFIG_FILE, "w") as fh:
        json.dump(cfg, fh, indent=2)


# ── Routes ────────────────────────────────────────────────────────────────────

@integrations_bp.route("/api/integrations/health", methods=["GET"])
@_require_viewer
def list_health():
    """Return all integration health statuses from DB."""
    try:
        from blueprints.integrations.health import ensure_health_tables
        ensure_health_tables()
        conn = _db()
        cur  = conn.cursor()
        cur.execute(
            "SELECT * FROM integration_health_status ORDER BY integration_name"
        )
        rows = [_serialize_row(dict(r)) for r in cur.fetchall()]
        conn.close()
        return jsonify({"integrations": rows, "count": len(rows)}), 200
    except Exception as exc:
        log.error("list_health: %s", exc)
        return jsonify({"error": str(exc)}), 500


@integrations_bp.route("/api/integrations/health/<name>", methods=["GET"])
@_require_viewer
def get_health(name):
    """Return status for one integration."""
    try:
        conn = _db()
        cur  = conn.cursor()
        cur.execute(
            "SELECT * FROM integration_health_status WHERE integration_name = %s", [name]
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            return jsonify({"error": f"Integration '{name}' not found"}), 404
        return jsonify(_serialize_row(dict(row))), 200
    except Exception as exc:
        log.error("get_health(%s): %s", name, exc)
        return jsonify({"error": str(exc)}), 500


@integrations_bp.route("/api/integrations/health/check", methods=["POST"])
@_require_analyst
def trigger_check():
    """Run all health checks immediately (synchronous — returns results)."""
    try:
        from blueprints.integrations.health import run_all_checks
        results = run_all_checks()
        checked_at = datetime.now(timezone.utc).isoformat()
        return jsonify({"results": results, "checked_at": checked_at}), 200
    except Exception as exc:
        log.error("trigger_check: %s", exc)
        return jsonify({"error": str(exc)}), 500


@integrations_bp.route("/api/integrations/health/config", methods=["GET"])
@_require_admin
def get_config():
    return jsonify(_read_config()), 200


@integrations_bp.route("/api/integrations/health/config", methods=["POST"])
@_require_admin
def set_config():
    body = request.get_json(silent=True) or {}
    cfg  = _read_config()
    if "enabled" in body:
        cfg["enabled"] = bool(body["enabled"])
    if "interval_seconds" in body:
        cfg["interval_seconds"] = max(60, int(body["interval_seconds"]))
    if "ingest_window_min" in body:
        cfg["ingest_window_min"] = max(1, int(body["ingest_window_min"]))
    if "notify_on_recovery" in body:
        cfg["notify_on_recovery"] = bool(body["notify_on_recovery"])
    try:
        _write_config(cfg)
        return jsonify({"ok": True, "config": cfg}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── OPTIONS (CORS preflight) ──────────────────────────────────────────────────

@integrations_bp.route("/api/integrations/health", methods=["OPTIONS"])
@integrations_bp.route("/api/integrations/health/<path:subpath>", methods=["OPTIONS"])
def _options(subpath=""):
    return add_cors_headers(make_response("", 204))
