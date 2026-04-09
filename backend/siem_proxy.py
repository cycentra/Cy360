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


@siem_bp.route("/incidents", methods=["DELETE"])
@require_siem_admin
def siem_incidents_purge():
    """Hard-delete incidents by status. Admin only."""
    return _proxy("/incidents", method="DELETE")


@siem_bp.route("/incidents/<incident_id>", methods=["GET"])
@require_siem_auth
def siem_incident_detail(incident_id):
    return _proxy(f"/incidents/{incident_id}")


@siem_bp.route("/incidents/<incident_id>", methods=["PATCH"])
@require_siem_analyst
def siem_incident_patch(incident_id):
    return _proxy(f"/incidents/{incident_id}", method="PATCH")


@siem_bp.route("/incidents/<incident_id>/escalate", methods=["POST"])
@require_siem_analyst
def siem_incident_escalate(incident_id):
    """Manually escalate a SIEM incident to CyIRIS regardless of FP score."""
    return _proxy(f"/incidents/{incident_id}/escalate", method="POST")


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


@siem_bp.route("/ueba/escalate", methods=["POST"])
@require_siem_analyst
def siem_ueba_escalate():
    """Create a case in IRIS from a UEBA anomaly.

    Uses get_iris_config() so it works with all three IRIS modes: local,
    cloud (CLOUD_IRIS_*), and the legacy IRIS_URL / IRIS_API_KEY env vars.
    Calls /api/v2/cases to match the engine iris_connector and ASM escalate routes.
    """
    from core.helpers import get_iris_config
    cfg = get_iris_config()
    if not cfg:
        return jsonify({"error": "CyIRIS not configured. Enable it in AI & Integration Settings."}), 503

    body = request.get_json(silent=True) or {}
    username     = body.get("username", "unknown")
    anomaly_type = body.get("anomaly_type", "unknown")
    description  = body.get("description", "")
    agent_name   = body.get("agent_name", "unknown")
    src_ip       = body.get("src_ip", "")
    rule_id      = body.get("rule_id", "")
    rule_desc    = body.get("rule_desc", "")
    process_name = body.get("process_name", "")
    file_path    = body.get("file_path", "")
    raw_log      = body.get("raw_log", "")
    detected_at  = body.get("detected_at", "")
    incident_id  = body.get("incident_id", "")
    risk_score   = body.get("risk_contribution", 0)

    analyst_email = session.get("user_email", "unknown")

    case_name = f"[UEBA] {anomaly_type.replace('_', ' ').title()} — {username} on {agent_name}"

    case_description = (
        f"## UEBA Anomaly: {anomaly_type.replace('_', ' ').title()}\n\n"
        f"**User:** `{username}`  \n"
        f"**Host:** `{agent_name}`  \n"
        f"**Detected:** {detected_at}  \n"
        f"**Risk Contribution:** +{risk_score}  \n\n"
        f"### Detection Details\n"
        f"{description}\n\n"
    )
    if src_ip:
        case_description += f"**Source IP:** `{src_ip}`  \n"
    if rule_id:
        case_description += f"**Rule:** {rule_id} — {rule_desc}  \n"
    if process_name:
        case_description += f"**Process:** `{process_name}`  \n"
    if file_path:
        case_description += f"**File:** `{file_path}`  \n"
    if incident_id:
        case_description += f"\n**CySIEM Incident:** `{incident_id}`  \n"
    if raw_log:
        case_description += f"\n### Raw Log\n```\n{raw_log[:1000]}\n```\n"
    case_description += f"\n---\n*Escalated by {analyst_email} via CyCentra360 UEBA*"

    # Severity: UEBA anomalies don't have a simple severity field so default to medium (3)
    _UEBA_SEV_MAP = {"high_risk": 2, "critical_risk": 1}
    case_sev = _UEBA_SEV_MAP.get(anomaly_type, 3)

    try:
        resp = _req.post(
            f"{cfg['url'].rstrip('/')}/api/v2/cases",
            headers={
                "Authorization": f"Bearer {cfg['apiKey']}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            json={
                "case_name":         case_name,
                "case_description":  case_description,
                "case_customer":     cfg.get("customerId", 1),
                "case_severity_id":  case_sev,
                "case_soc_id":       incident_id or "",
            },
            timeout=10,
            verify=False,  # self-signed certs common on internal IRIS installs
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            case = data if "case_id" in data else data.get("data", data)
            case_id  = case.get("case_id")
            case_url = f"{cfg['url'].rstrip('/')}/case?cid={case_id}" if case_id else cfg["url"]
            return jsonify({"case_id": case_id, "case_url": case_url, "case_name": case_name})
        return jsonify({"error": f"IRIS returned HTTP {resp.status_code}", "detail": resp.text[:300]}), 502
    except _req.exceptions.ConnectionError:
        return jsonify({"error": "Cannot reach CyIRIS. Check the URL in AI & Integration Settings."}), 503
    except _req.exceptions.Timeout:
        return jsonify({"error": "CyIRIS request timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@siem_bp.route("/ueba/integrations")
@require_siem_auth
def siem_ueba_integrations():
    """Return public integration URLs (no secrets) for the frontend to construct deep-links.

    Uses get_iris_config() so iris_enabled is True for local, cloud, and legacy
    IRIS_URL/IRIS_API_KEY configs — not just the old env-var path.
    """
    from core.config import WAZUH_URL
    from core.helpers import get_iris_config
    iris_cfg = get_iris_config()
    return jsonify({
        "iris_url":      iris_cfg["url"] if iris_cfg else None,
        "wazuh_url":     WAZUH_URL or None,
        "iris_enabled":  bool(iris_cfg),
        "wazuh_enabled": bool(WAZUH_URL),
    })


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
