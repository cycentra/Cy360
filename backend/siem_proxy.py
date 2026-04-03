"""
siem_proxy.py
=============
Flask Blueprint — authenticated reverse proxy for the CySIEM Correlation Engine.
Mounts at /api/siem/* in app.py.

FIX v4.3: Removed circular import `from app import get_user_role`.
          Now imports from blueprints.rbac.manager directly.

RBAC:
  - GET  routes: all logged-in users (viewer, analyst, admin)
  - PATCH routes: analyst + admin only
  - POST /alerts/ingest, POST /engine/restart: admin only
"""

import os
import subprocess
from functools import wraps

import requests as _req
from flask import Blueprint, request, Response, jsonify, session

SIEM_ENGINE_URL = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100")
PROXY_TIMEOUT   = int(os.environ.get("SIEM_PROXY_TIMEOUT", "10"))

siem_bp = Blueprint("siem", __name__, url_prefix="/api/siem")


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_role():
    email = session.get("user_email", "")
    if not email:
        return None
    # Import here (not at module level) to avoid any load-order issues
    from blueprints.rbac.manager import get_user_role
    return get_user_role(email)


def require_siem_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def require_siem_analyst(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _get_role() not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


def require_siem_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _get_role() != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Engine guard ──────────────────────────────────────────────────────────────

def _engine_offline_response():
    return jsonify({
        "error":   "engine_unavailable",
        "message": (
            "The CySIEM Correlation Engine is not running. "
            "Start it with: systemctl start cysiemstack-engine"
        ),
    }), 503


def _proxy(path, method=None, **kwargs):
    """Forward a request to the correlation engine and stream back the response."""
    method = method or request.method
    url    = f"{SIEM_ENGINE_URL}{path}"
    try:
        resp = _req.request(
            method, url,
            headers={k: v for k, v in request.headers if k != 'Host'},
            data=request.get_data(),
            params=request.args,
            timeout=PROXY_TIMEOUT,
            **kwargs,
        )
        return Response(
            resp.content,
            status=resp.status_code,
            headers=dict(resp.headers),
        )
    except _req.exceptions.ConnectionError:
        return _engine_offline_response()
    except _req.exceptions.Timeout:
        return jsonify({"error": "Engine request timed out"}), 504


# ── Routes ────────────────────────────────────────────────────────────────────

@siem_bp.route("/health")
@require_siem_auth
def siem_health():
    return _proxy("/health")


@siem_bp.route("/stats")
@require_siem_auth
def siem_stats():
    return _proxy("/stats")


@siem_bp.route("/incidents")
@require_siem_auth
def siem_incidents():
    return _proxy("/incidents")


@siem_bp.route("/incidents/<incident_id>", methods=["GET"])
@require_siem_auth
def siem_incident_detail(incident_id):
    return _proxy(f"/incidents/{incident_id}")


@siem_bp.route("/incidents/<incident_id>", methods=["PATCH"])
@require_siem_analyst
def siem_incident_patch(incident_id):
    return _proxy(f"/incidents/{incident_id}", method="PATCH")


@siem_bp.route("/risk-scores")
@require_siem_auth
def siem_risk_scores():
    return _proxy("/risk-scores")


@siem_bp.route("/ueba/users")
@require_siem_auth
def siem_ueba_users():
    # Forward filter query params to the engine
    from flask import request as _req
    qs = _req.query_string.decode()
    path = f"/ueba/users?{qs}" if qs else "/ueba/users"
    return _proxy(path)


@siem_bp.route("/ueba/<username>")
@require_siem_auth
def siem_ueba_detail(username):
    return _proxy(f"/ueba/{username}")


@siem_bp.route("/alerts")
@require_siem_auth
def siem_alerts():
    return _proxy("/alerts")


@siem_bp.route("/alerts/ingest", methods=["POST"])
@require_siem_admin
def siem_alerts_ingest():
    return _proxy("/alerts/ingest", method="POST")


@siem_bp.route("/config")
@require_siem_auth
def siem_config():
    return _proxy("/config")


@siem_bp.route("/engine/status")
@require_siem_auth
def siem_engine_status():
    return _proxy("/engine/status")


@siem_bp.route("/engine/restart", methods=["POST"])
@require_siem_admin
def siem_engine_restart():
    try:
        subprocess.run(
            ["systemctl", "restart", "cysiemstack-engine"],
            timeout=30, check=True,
        )
        return jsonify({"status": "restarting"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
