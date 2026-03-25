"""
siem_proxy.py
=============
Flask Blueprint — authenticated reverse proxy for the CySIEM Correlation Engine.

Mounts at /api/siem/* in app.py.

All routes require a valid portal session (enforced by @require_siem_auth).
The correlation engine (FastAPI on port 8100) is never exposed to the internet —
all analyst traffic flows: browser → nginx → Flask (5252) → engine (8100).

RBAC:
  - GET  routes: all logged-in users (viewer, analyst, admin)
  - PATCH routes: analyst + admin only
  - POST /alerts/ingest, POST /engine/restart: admin only

WebSocket /ws/live is handled directly by nginx (see cycentra-setup.sh).
"""

import os
import subprocess
from functools import wraps
from flask import Blueprint, request, Response, jsonify, session
import requests as _req

# ── Config ────────────────────────────────────────────────────────────────────
SIEM_ENGINE_URL = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100")
PROXY_TIMEOUT   = int(os.environ.get("SIEM_PROXY_TIMEOUT", "10"))

siem_bp = Blueprint("siem", __name__, url_prefix="/api/siem")

# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_role():
    """Return the current user's role from the Flask session (set by OAuth flow)."""
    email = session.get("user_email", "")
    if not email:
        return None
    try:
        from app import get_user_role
        return get_user_role(email)
    except ImportError:
        return None


def require_siem_auth(f):
    """Decorator: require a valid portal session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def require_siem_analyst(f):
    """Decorator: require analyst or admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        role = _get_role()
        if role not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


def require_siem_admin(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _get_role() != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*args, **kwargs)
    return decorated


# ── Engine availability guard ─────────────────────────────────────────────────

def _engine_offline_response():
    # FIX 1: removed Docker instruction — engine is now a native systemd service
    return jsonify({
        "error": "engine_unavailable",
        "message": (
            "The CySIEM Correlation Engine is not running. "
            "Start it with: sudo systemctl start cysiemstack-engine"
        ),
    }), 503


def _proxy_get(path, params=None):
    """Forward a GET request to the engine and stream back the response."""
    try:
        r = _req.get(
            f"{SIEM_ENGINE_URL}{path}",
            params=params,
            timeout=PROXY_TIMEOUT,
        )
        return Response(r.content, status=r.status_code,
                        content_type=r.headers.get("content-type", "application/json"))
    except (_req.exceptions.ConnectionError, _req.exceptions.Timeout):
        return _engine_offline_response()


def _proxy_patch(path, body):
    """Forward a PATCH request to the engine."""
    try:
        r = _req.patch(
            f"{SIEM_ENGINE_URL}{path}",
            json=body,
            timeout=PROXY_TIMEOUT,
        )
        return Response(r.content, status=r.status_code,
                        content_type=r.headers.get("content-type", "application/json"))
    except (_req.exceptions.ConnectionError, _req.exceptions.Timeout):
        return _engine_offline_response()


def _proxy_post(path, body):
    """Forward a POST request to the engine."""
    try:
        r = _req.post(
            f"{SIEM_ENGINE_URL}{path}",
            json=body,
            timeout=PROXY_TIMEOUT,
        )
        return Response(r.content, status=r.status_code,
                        content_type=r.headers.get("content-type", "application/json"))
    except (_req.exceptions.ConnectionError, _req.exceptions.Timeout):
        return _engine_offline_response()


# ── Routes ────────────────────────────────────────────────────────────────────

@siem_bp.route("/health")
@require_siem_auth
def siem_health():
    """Engine liveness probe — used by portal EngineStatus guard."""
    return _proxy_get("/health")


@siem_bp.route("/stats")
@require_siem_auth
def siem_stats():
    """Engine-level metrics: alert count, incident count, uptime."""
    return _proxy_get("/stats")


@siem_bp.route("/incidents")
@require_siem_auth
def siem_incidents():
    """
    Paginated incident list.
    Query params: status, severity, limit (max 200), offset
    """
    params = {k: v for k, v in request.args.items()
              if k in ("status", "severity", "limit", "offset")}
    return _proxy_get("/incidents", params=params)


@siem_bp.route("/incidents/<incident_id>")
@require_siem_auth
def siem_incident_detail(incident_id):
    """Full incident detail including child alerts, MISP hits, LLM narrative."""
    return _proxy_get(f"/incidents/{incident_id}")


@siem_bp.route("/incidents/<incident_id>", methods=["PATCH", "OPTIONS"])
@require_siem_analyst
def siem_incident_patch(incident_id):
    """
    Update incident: status, assigned_to, notes, false_positive_reason.
    Requires analyst or admin role.
    """
    if request.method == "OPTIONS":
        from flask import make_response
        from app import _cors_headers
        return _cors_headers(make_response("", 204))
    return _proxy_patch(f"/incidents/{incident_id}", request.get_json() or {})


@siem_bp.route("/risk-scores")
@require_siem_auth
def siem_risk_scores():
    """
    Entity risk leaderboard (0–100 composite score).
    Query params: entity_type (host|user), min_score, limit
    """
    params = {k: v for k, v in request.args.items()
              if k in ("entity_type", "min_score", "limit")}
    return _proxy_get("/risk-scores", params=params)


@siem_bp.route("/ueba/users")
@require_siem_auth
def siem_ueba_users():
    """List all UEBA baselines (one per monitored user)."""
    return _proxy_get("/ueba/users")


@siem_bp.route("/ueba/<username>")
@require_siem_auth
def siem_ueba_user(username):
    """Full UEBA profile for a user: baseline + anomaly history."""
    return _proxy_get(f"/ueba/{username}")


@siem_bp.route("/alerts")
@require_siem_auth
def siem_alerts():
    """Recent raw alert list (last 100 by default)."""
    params = {k: v for k, v in request.args.items() if k in ("limit", "offset")}
    return _proxy_get("/alerts", params=params)


@siem_bp.route("/alerts/ingest", methods=["POST", "OPTIONS"])
@require_siem_admin
def siem_alerts_ingest():
    """
    Manual alert push for testing / external ingestion.
    Admin only.
    """
    if request.method == "OPTIONS":
        from flask import make_response
        from app import _cors_headers
        return _cors_headers(make_response("", 204))
    return _proxy_post("/alerts/ingest", request.get_json() or {})


# ── Feedback routes ────────────────────────────────────────────────────────────

@siem_bp.route("/feedback", methods=["POST", "OPTIONS"])
@require_siem_analyst
def siem_feedback_post():
    """
    Submit analyst verdict for an incident (ENH-6 feedback loop).
    Requires analyst or admin role.
    """
    if request.method == "OPTIONS":
        from flask import make_response
        from app import _cors_headers
        return _cors_headers(make_response("", 204))
    return _proxy_post("/feedback", request.get_json() or {})


@siem_bp.route("/feedback/accuracy")
@require_siem_auth
def siem_feedback_accuracy():
    """Per-rule TP/FP/accuracy stats (ENH-6)."""
    return _proxy_get("/feedback/accuracy")


# ── Engine configuration & management ─────────────────────────────────────────

@siem_bp.route("/config")
@require_siem_auth
def siem_config_get():
    """Return sanitised engine configuration (no secrets)."""
    return jsonify({
        "siem_engine_url":            SIEM_ENGINE_URL,
        "misp_enabled":               os.environ.get("SIEM_MISP_ENABLED", "false"),
        "llm_enabled":                os.environ.get("SIEM_LLM_ENABLED", "true"),
        # FIX 3: default changed from host.docker.internal to 127.0.0.1
        "ollama_url":                 os.environ.get("SIEM_OLLAMA_URL", "http://127.0.0.1:11434"),
        "ollama_model":               os.environ.get("SIEM_OLLAMA_MODEL", "llama3.1:8b"),
        "correlation_window_minutes": os.environ.get("SIEM_CORRELATION_WINDOW", "15"),
        "ueba_baseline_days":         os.environ.get("SIEM_UEBA_BASELINE_DAYS", "30"),
        "risk_decay_hours":           os.environ.get("SIEM_RISK_DECAY_HOURS", "24"),
    })


@siem_bp.route("/engine/status")
@require_siem_auth
def siem_engine_status():
    """
    Check whether the CySIEM Correlation Engine systemd service is running.

    FIX 2: Replaced docker compose ps (Docker-era) with systemctl is-active.
    Returns a consistent shape the portal EngineStatus component already expects:
      { "running": bool, "state": str, "engine_url": str }
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "cysiemstack-engine"],
            capture_output=True, text=True, timeout=5,
        )
        # systemctl is-active exits 0 and prints "active" when running,
        # exits non-zero and prints "inactive"/"failed"/"unknown" otherwise.
        state   = result.stdout.strip()   # "active" | "inactive" | "failed" | "unknown"
        running = (state == "active")
        return jsonify({
            "running":    running,
            "state":      state,
            "engine_url": SIEM_ENGINE_URL,
        })
    except Exception as e:
        return jsonify({
            "running": False,
            "state":   "unknown",
            "error":   str(e),
        }), 200


@siem_bp.route("/engine/restart", methods=["POST", "OPTIONS"])
@require_siem_admin
def siem_engine_restart():
    """
    Restart the CySIEM Correlation Engine via systemd.
    Admin only.

    FIX 4: Removed SIEM_COMPOSE_DIR reference — not applicable to native deploy.
    """
    if request.method == "OPTIONS":
        from flask import make_response
        from app import _cors_headers
        return _cors_headers(make_response("", 204))
    try:
        result = subprocess.run(
            ["systemctl", "restart", "cysiemstack-engine"],
            capture_output=True, text=True, timeout=60,
        )
        return jsonify({
            "status": "restarted" if result.returncode == 0 else "failed",
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500