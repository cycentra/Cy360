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
import json
import logging
import time
import subprocess
from collections import defaultdict

_logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from functools import wraps

import requests as _req
from flask import Blueprint, request, Response, jsonify, session, make_response

SIEM_ENGINE_URL = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100")
PROXY_TIMEOUT   = int(os.environ.get("SIEM_PROXY_TIMEOUT", "10"))

# Wazuh API credentials — same env vars used by benchmark/routes.py
WAZUH_API_URL  = os.environ.get("WAZUH_API_URL",      "https://127.0.0.1:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER",     "wazuh-wui")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASSWORD", "")

# Rate-limiter: max 10 wazuh-launch requests per user per 60-second window
_WAZUH_LAUNCH_WINDOW = 60   # seconds
_WAZUH_LAUNCH_LIMIT  = 10   # requests per window
_wazuh_launch_hits: dict = defaultdict(list)  # email -> [timestamp, ...]

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
    """Health check — returns 200 if the correlation DB is reachable.
    All Flask SIEM routes read directly from the DB; the FastAPI engine
    is a background enrichment process and its absence does not block data.
    """
    try:
        conn = _corr_conn()
        conn.close()
    except Exception as exc:
        return jsonify({"error": "engine_unavailable",
                        "message": f"Correlation DB unreachable: {exc}"}), 503
    engine_ok = False
    try:
        r = _req.get(f"{SIEM_ENGINE_URL}/health", timeout=2)
        engine_ok = r.status_code == 200
    except Exception:
        pass
    return jsonify({"status": "ok", "db": "ok",
                    "engine": "ok" if engine_ok else "offline"})


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


@siem_bp.route("/incidents/batch-close", methods=["POST"])
@require_siem_analyst
def siem_incidents_batch_close():
    """Soft-close all false_positive and resolved incidents → closed. Analyst+."""
    return _proxy("/incidents/batch-close", method="POST")


@siem_bp.route("/incidents/batch-close", methods=["OPTIONS"])
def siem_incidents_batch_close_options():
    from core.helpers import add_cors_headers
    from flask import make_response
    return add_cors_headers(make_response('', 204))


@siem_bp.route("/incidents/<incident_id>", methods=["GET"])
@require_siem_auth
def siem_incident_detail(incident_id):
    return _proxy(f"/incidents/{incident_id}")


@siem_bp.route("/incidents/<incident_id>", methods=["PATCH"])
@require_siem_analyst
def siem_incident_patch(incident_id):
    return _proxy(f"/incidents/{incident_id}", method="PATCH")


@siem_bp.route("/incidents/<incident_id>/audit", methods=["GET"])
@require_siem_auth
def siem_incident_audit(incident_id):
    """Fetch the full audit trail for an incident."""
    return _proxy(f"/incidents/{incident_id}/audit")


@siem_bp.route("/incidents/<incident_id>/audit", methods=["OPTIONS"])
def siem_incident_audit_options(incident_id):
    from core.helpers import add_cors_headers
    from flask import make_response
    return add_cors_headers(make_response('', 204))


@siem_bp.route("/incidents/<incident_id>/transition", methods=["POST"])
@require_siem_analyst
def siem_incident_transition(incident_id):
    """Analyst-initiated status transition with mandatory audit comment.
    Proxied directly to the correlation engine's /transition endpoint.
    The actor field is injected server-side from the session email.
    """
    import json as _json
    body = request.get_json(silent=True) or {}
    if not body.get("comment", "").strip():
        return jsonify({"error": "Audit comment is required for status transitions."}), 422
    body["actor"] = session.get("user_email", "analyst")
    resp = None
    try:
        resp = _req.post(
            f"{SIEM_ENGINE_URL}/incidents/{incident_id}/transition",
            json=body,
            timeout=PROXY_TIMEOUT,
        )
        return Response(resp.content, status=resp.status_code,
                        headers=dict(resp.headers))
    except _req.exceptions.ConnectionError:
        return _engine_offline_response()
    except _req.exceptions.Timeout:
        return jsonify({"error": "Engine request timed out"}), 504


@siem_bp.route("/incidents/<incident_id>/transition", methods=["OPTIONS"])
def siem_incident_transition_options(incident_id):
    from core.helpers import add_cors_headers
    from flask import make_response
    return add_cors_headers(make_response('', 204))



@siem_bp.route("/incidents/<incident_id>/analyse", methods=["POST"])
@require_siem_analyst
def siem_incident_analyse(incident_id):
    """Trigger on-demand LLM AI analysis for an incident. Analyst+."""
    try:
        resp = _req.post(
            f"{SIEM_ENGINE_URL}/incidents/{incident_id}/analyse",
            timeout=120,  # LLM calls can take up to 2 minutes
        )
        return Response(resp.content, status=resp.status_code,
                        headers=dict(resp.headers))
    except _req.exceptions.ConnectionError:
        return _engine_offline_response()
    except _req.exceptions.Timeout:
        return jsonify({"error": "AI analysis request timed out"}), 504


@siem_bp.route("/incidents/<incident_id>/analyse", methods=["OPTIONS"])
def siem_incident_analyse_options(incident_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


# ── FP Pattern management endpoints ───────────────────────────────────────────

@siem_bp.route("/fp-patterns")
@require_siem_auth
def siem_fp_patterns_list():
    """List all learned FP patterns."""
    return _proxy("/fp-patterns")


@siem_bp.route("/fp-patterns/<int:pattern_id>", methods=["PATCH"])
@require_siem_analyst
def siem_fp_pattern_patch(pattern_id):
    """Toggle auto_close or update threshold/description. Analyst+."""
    return _proxy(f"/fp-patterns/{pattern_id}", method="PATCH")


@siem_bp.route("/fp-patterns/<int:pattern_id>", methods=["DELETE"])
@require_siem_admin
def siem_fp_pattern_delete(pattern_id):
    """Delete a learned FP pattern. Admin only."""
    return _proxy(f"/fp-patterns/{pattern_id}", method="DELETE")


@siem_bp.route("/fp-patterns/<int:pattern_id>", methods=["OPTIONS"])
def siem_fp_pattern_options(pattern_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


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



@siem_bp.route("/ueba/integrations")
@require_siem_auth
def siem_ueba_integrations():
    """Return public integration URLs for the frontend to construct deep-links."""
    from core.config import WAZUH_URL
    return jsonify({
        "wazuh_url":     WAZUH_URL or None,
        "wazuh_enabled": bool(WAZUH_URL),
    })


@siem_bp.route("/wazuh-launch", methods=["GET"])
def siem_wazuh_launch():
    """Return a Wazuh JWT so the frontend can open an authenticated session.

    RBAC:
      - No session         → 401
      - viewer role        → 403 (read-only users do not get raw Wazuh access)
      - analyst / admin    → 200 with {"launch_url": ..., "token": ...}
      - Rate limit         → 429 after 10 calls / 60 s per user

    Fallback: if Wazuh API creds are missing or the API is unreachable,
    returns {"launch_url": <WAZUH_URL>, "token": null} so the frontend
    still opens the Wazuh dashboard (unauthenticated, current behaviour).
    """
    from core.config import WAZUH_URL
    from core.helpers import auth_event
    import base64

    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Authentication required"}), 401

    role = _get_role()
    if role not in ("admin", "analyst"):
        auth_event(
            event_type="rbac_denied",
            email=email,
            client_id="",
            result="failure",
            detail="wazuh-launch: viewer role denied",
            ip=request.remote_addr,
        )
        return jsonify({"error": "Analyst or admin role required to launch Wazuh SSO"}), 403

    # ── Rate limiting ──────────────────────────────────────────────────────────
    now = time.time()
    hits = _wazuh_launch_hits[email]
    # Evict timestamps outside the current window
    hits[:] = [t for t in hits if now - t < _WAZUH_LAUNCH_WINDOW]
    if len(hits) >= _WAZUH_LAUNCH_LIMIT:
        return jsonify({"error": "Too many Wazuh launch requests — try again shortly"}), 429
    hits.append(now)

    # ── Determine Wazuh dashboard URL ─────────────────────────────────────────
    # Prefer the configured WAZUH_URL; fall back to deriving from request host.
    launch_url = WAZUH_URL or ""
    if not launch_url:
        host = request.host.split(":")[0]
        wazuh_host = host.replace("cy360.", "cysiem.") if host.startswith("cy360.") else host
        launch_url = f"https://{wazuh_host}/app/wazuh"

    # ── Obtain Wazuh JWT ───────────────────────────────────────────────────────
    token = None
    if WAZUH_API_PASS:
        try:
            creds = base64.b64encode(
                f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()
            ).decode()
            resp = _req.get(
                f"{WAZUH_API_URL}/security/user/authenticate",
                headers={"Authorization": f"Basic {creds}"},
                timeout=8,
                verify=False,  # Wazuh uses self-signed cert
            )
            resp.raise_for_status()
            token = resp.json().get("data", {}).get("token")
        except Exception:
            # Graceful fallback: return URL without token
            token = None

    auth_event(
        event_type="oauth_login",
        email=email,
        client_id="wazuh",
        result="success" if token else "failure",
        detail=f"wazuh-launch SSO {'token obtained' if token else 'fallback (no token)'}",
        ip=request.remote_addr,
    )

    return jsonify({"launch_url": launch_url, "token": token})


# ── Wazuh Basic Auth credentials for nginx siem-gate ─────────────────────────
# Computed once at import time; passwords never appear in logs or responses.
import base64 as _b64
_WAZUH_ADMIN_BASIC = "Basic " + _b64.b64encode(b"cy360_sso:CyCentra360!SiemSSO").decode()
_WAZUH_RO_BASIC    = "Basic " + _b64.b64encode(b"cy360_readonly:CyCentra360!ReadOnly").decode()


@siem_bp.route("/internal/auth", methods=["GET"])
def siem_internal_auth():
    """nginx auth_request gate for cysiem.DOMAIN — called per browser request.

    Validates the Cy360 session cookie forwarded by nginx, then returns the
    role-appropriate Wazuh Basic Auth credential via the X-Wazuh-Auth header.
    nginx picks that value up via auth_request_set and injects it into the
    proxy_set_header Authorization for the upstream Wazuh Dashboard request.

    Roles:
      - No session              → 401  (nginx redirects to Cy360 login)
      - admin / analyst         → cy360_sso    (OpenSearch admin — full Wazuh access)
      - viewer / anything else  → cy360_readonly (OpenSearch read-only access)
    """
    email = session.get("user_email")
    if not email:
        return "", 401

    role  = _get_role() or "viewer"
    basic = _WAZUH_ADMIN_BASIC if role in ("admin", "analyst") else _WAZUH_RO_BASIC
    return "", 200, {"X-Wazuh-Auth": basic, "X-Auth-Request-User": email}


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


# ── UEBA Anomaly Status — Flask-only (not proxied to engine) ──────────────────
#
# Anomaly IDs are constructed on the client as:
#   slugify(username + "_" + anomaly_type + "_" + detected_at)
# Statuses are persisted in /opt/cycentra/ueba_statuses.json
# Schema: { "<id>": { "status": "...", "audit_log": [...] } }

_UEBA_STATUSES_FILE = "/opt/cycentra/ueba_statuses.json"

_UEBA_ALLOWED_TRANSITIONS = {
    "open":           ["investigating", "in_review", "resolved", "false_positive"],
    "investigating":  ["in_review", "resolved", "false_positive"],
    "in_review":      ["resolved", "false_positive", "investigating"],
    "resolved":       ["investigating"],
    "false_positive": ["investigating"],
}


def _load_ueba_statuses():
    try:
        with open(_UEBA_STATUSES_FILE) as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_ueba_statuses(data):
    try:
        tmp = _UEBA_STATUSES_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, _UEBA_STATUSES_FILE)
    except Exception:
        pass


@siem_bp.route("/ueba/anomaly/statuses")
def ueba_anomaly_statuses():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    return jsonify(_load_ueba_statuses())


@siem_bp.route("/ueba/anomaly/<anomaly_id>/audit")
def ueba_anomaly_audit(anomaly_id):
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    entry = _load_ueba_statuses().get(anomaly_id, {})
    return jsonify(entry.get("audit_log", []))


@siem_bp.route("/ueba/anomaly/<anomaly_id>/status", methods=["OPTIONS"])
def ueba_anomaly_status_options(anomaly_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


@siem_bp.route("/ueba/anomaly/<anomaly_id>/status", methods=["POST"])
def ueba_anomaly_status_post(anomaly_id):
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body       = request.get_json() or {}
    to_status  = body.get("to_status", "")
    comment    = (body.get("comment") or "").strip()
    if not comment:
        return jsonify({"error": "Comment is required for audit trail"}), 400

    data   = _load_ueba_statuses()
    entry  = data.get(anomaly_id, {"status": "open", "audit_log": []})
    from_status = entry.get("status", "open")

    allowed = _UEBA_ALLOWED_TRANSITIONS.get(from_status, [])
    if to_status not in allowed:
        return jsonify({"error": f"Transition {from_status} → {to_status} not allowed"}), 400

    entry["status"] = to_status
    entry.setdefault("audit_log", []).append({
        "action":      "status_change",
        "from_status": from_status,
        "to_status":   to_status,
        "comment":     comment,
        "actor":       session["user_email"],
        "created_at":  datetime.now(timezone.utc).isoformat(),
    })
    data[anomaly_id] = entry
    _save_ueba_statuses(data)
    return jsonify({"status": to_status})


# ══════════════════════════════════════════════════════════════════════════════
# HOST INVENTORY & THREAT HUNTING ROUTES
# Flask-native routes that read directly from the correlation DB via psycopg2
# (sync) to avoid asyncpg event-loop conflicts in werkzeug Flask workers.
# The asyncpg connection pool binds to the startup event loop; subsequent
# asyncio.run() calls create fresh loops that can't reuse those connections.
# ══════════════════════════════════════════════════════════════════════════════

_CORR_DB_URL = (
    os.environ.get("CYCENTRA_DB_URL")
    or os.environ.get("CORRELATION_DB_URL")
    or os.environ.get("DATABASE_URL", "postgresql://corruser:changeme@127.0.0.1:5433/correlation")
).replace("+asyncpg", "")


def _corr_conn():
    import psycopg2
    import psycopg2.extras
    return psycopg2.connect(_CORR_DB_URL)


def _iso(val):
    return val.isoformat() if val and hasattr(val, "isoformat") else None


def _f(val):
    return float(val) if val is not None else None


# ── Analyst acknowledgement helpers ──────────────────────────────────────────
_acks_table_ready = False


def _ensure_acks_table():
    """Idempotent: create host_item_acks if it doesn't exist yet."""
    global _acks_table_ready
    if _acks_table_ready:
        return
    try:
        conn = _corr_conn()
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS host_item_acks (
                        agent_id   TEXT NOT NULL,
                        item_type  TEXT NOT NULL,
                        item_key   TEXT NOT NULL,
                        status     TEXT,
                        updated_at TIMESTAMPTZ DEFAULT NOW(),
                        PRIMARY KEY (agent_id, item_type, item_key)
                    );
                    CREATE INDEX IF NOT EXISTS ix_host_item_acks_agent
                        ON host_item_acks (agent_id, item_type);
                """)
        conn.close()
        _acks_table_ready = True
    except Exception as _te:
        _logger.warning("[host-acks] Table setup failed: %s", _te)


def _grade(score):
    if score is None:
        return "—"
    for g, t in [("A+", 95), ("A", 85), ("B", 70), ("C", 55), ("D", 40)]:
        if score >= t:
            return g
    return "F"


def _sync_hosts_list(status_filter, sort_by, page, per_page):
    import psycopg2.extras
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            where = "WHERE wazuh_status = %s" if status_filter and status_filter != "all" else ""
            wparams = [status_filter] if status_filter and status_filter != "all" else []
            order = {
                "posture_score": "posture_score ASC NULLS LAST",
                "risk":          "siem_risk DESC NULLS LAST",
                "name":          "agent_name ASC",
            }.get(sort_by, "posture_score ASC NULLS LAST")

            cur.execute(f"SELECT COUNT(*) AS n FROM host_posture_cache {where}", wparams)
            total = cur.fetchone()["n"]

            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT agent_id, agent_name, agent_ip, os_platform, wazuh_status,
                       last_keepalive, posture_score, posture_grade, siem_risk,
                       vuln_critical, vuln_high, incident_count, asset_tier, computed_at
                FROM host_posture_cache {where}
                ORDER BY {order} LIMIT %s OFFSET %s
            """, wparams + [per_page, offset])
            hosts = [{
                "agent_id":       r["agent_id"],
                "agent_name":     r["agent_name"],
                "agent_ip":       r["agent_ip"],
                "os_platform":    r["os_platform"],
                "wazuh_status":   r["wazuh_status"],
                "last_keepalive": _iso(r["last_keepalive"]),
                "posture_score":  _f(r["posture_score"]),
                "posture_grade":  r["posture_grade"],
                "siem_risk":      _f(r["siem_risk"]),
                "vuln_critical":  r["vuln_critical"],
                "vuln_high":      r["vuln_high"],
                "incident_count": r["incident_count"],
                "asset_tier":     r["asset_tier"],
                "computed_at":    _iso(r["computed_at"]),
            } for r in cur.fetchall()]

            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE wazuh_status = 'active') AS active,
                    COUNT(*) FILTER (WHERE posture_grade IN ('D','F')) AS critical_grade,
                    CASE WHEN SUM(CASE WHEN asset_tier=1 THEN 3 WHEN asset_tier=2 THEN 2 ELSE 1 END) > 0
                         THEN SUM(posture_score * CASE WHEN asset_tier=1 THEN 3 WHEN asset_tier=2 THEN 2 ELSE 1 END)
                              / SUM(CASE WHEN asset_tier=1 THEN 3.0 WHEN asset_tier=2 THEN 2.0 ELSE 1.0 END)
                         ELSE NULL END AS weighted_score,
                    AVG(sca_score)       FILTER (WHERE sca_score IS NOT NULL)    AS avg_sca,
                    AVG(vuln_score)      FILTER (WHERE vuln_score IS NOT NULL)   AS avg_vuln,
                    AVG(100 - siem_risk) FILTER (WHERE siem_risk IS NOT NULL)    AS avg_siem,
                    AVG(CASE WHEN fim_event_count > 0 OR malware_count > 0 THEN 50.0 ELSE 100.0 END) AS avg_fim,
                    AVG(compliance_score) FILTER (WHERE compliance_score IS NOT NULL) AS avg_comp
                FROM host_posture_cache
            """)
            agg = cur.fetchone()
            score = _f(agg["weighted_score"]) or 0.0
            internal_posture = {
                "score": round(score, 1),
                "grade": _grade(score),
                "host_count": {
                    "total":          agg["total"],
                    "active":         agg["active"],
                    "critical_grade": agg["critical_grade"],
                },
                "components": {
                    "sca":         {"score": round(_f(agg["avg_sca"])  or 0, 1), "weight": 0.30},
                    "vuln":        {"score": round(_f(agg["avg_vuln"]) or 0, 1), "weight": 0.25},
                    "siem_risk":   {"score": round(_f(agg["avg_siem"]) or 0, 1), "weight": 0.25},
                    "fim_malware": {"score": round(_f(agg["avg_fim"])  or 0, 1), "weight": 0.10},
                    "compliance":  {"score": round(_f(agg["avg_comp"]) or 0, 1), "weight": 0.10},
                },
                "worst_hosts": sorted(hosts, key=lambda x: x["posture_score"] or 100)[:5],
            }
            return {"hosts": hosts, "total": total, "page": page, "per_page": per_page,
                    "internal_posture": internal_posture}
    finally:
        conn.close()


def _sync_host_detail(agent_id):
    import psycopg2.extras
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM host_posture_cache WHERE agent_id = %s", [agent_id])
            host = cur.fetchone()
            if not host:
                return None

            cur.execute("""
                SELECT category, COUNT(*) AS cnt, MAX(timestamp) AS last_seen,
                       MAX(rule_level) AS max_level
                FROM alerts WHERE agent_id = %s AND timestamp > NOW() - INTERVAL '30 days'
                GROUP BY category ORDER BY cnt DESC
            """, [agent_id])
            alerts_by_category = {
                r["category"]: {"count": int(r["cnt"]), "last_seen": _iso(r["last_seen"]),
                                "max_level": r["max_level"]}
                for r in cur.fetchall()
            }

            cur.execute("""
                SELECT id, severity, status, first_seen, last_seen,
                       llm_summary, mitre_ids, case_opened_at
                FROM incidents
                WHERE %s = ANY(affected_agents)
                  AND status NOT IN ('closed','false_positive')
                ORDER BY last_seen DESC LIMIT 10
            """, [agent_id])
            active_incidents = [{
                "id": r["id"], "severity": r["severity"], "status": r["status"],
                "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"]),
                "summary": r["llm_summary"], "mitre_ids": r["mitre_ids"] or [],
                "case_opened_at": _iso(r["case_opened_at"]),
            } for r in cur.fetchall()]

            cur.execute("""
                SELECT mitre_id, mitre_tactic, COUNT(*) AS cnt
                FROM alerts WHERE agent_id = %s AND mitre_id IS NOT NULL
                  AND timestamp > NOW() - INTERVAL '30 days'
                GROUP BY mitre_id, mitre_tactic ORDER BY cnt DESC LIMIT 15
            """, [agent_id])
            mitre_breakdown = [{
                "mitre_id": r["mitre_id"], "tactic": r["mitre_tactic"], "count": int(r["cnt"])
            } for r in cur.fetchall()]

            cur.execute("""
                SELECT full_alert->'data'->'sca'->'check'->>'title'     AS title,
                       full_alert->'data'->'sca'->'check'->>'result'    AS result,
                       full_alert->'data'->'sca'->'check'->>'rationale' AS rationale,
                       full_alert->'data'->'sca'->>'policy_id'          AS policy_id,
                       timestamp
                FROM alerts
                WHERE agent_id = %s AND category = 'sca'
                  AND (full_alert->'data'->'sca'->'check'->>'result') = 'failed'
                  AND timestamp > NOW() - INTERVAL '7 days'
                ORDER BY timestamp DESC LIMIT 20
            """, [agent_id])
            sca_failures = [{
                "title": r["title"], "result": r["result"],
                "rationale": r["rationale"], "policy_id": r["policy_id"],
                "timestamp": _iso(r["timestamp"]),
            } for r in cur.fetchall()]

            return {
                "agent_id": host["agent_id"], "agent_name": host["agent_name"],
                "agent_ip": host["agent_ip"], "os_platform": host["os_platform"],
                "os_version": host["os_version"], "wazuh_status": host["wazuh_status"],
                "last_keepalive": _iso(host["last_keepalive"]),
                "asset_tier": host["asset_tier"],
                "posture": {
                    "score": _f(host["posture_score"]), "grade": host["posture_grade"],
                    "breakdown": host["score_breakdown"] or {},
                    "computed_at": _iso(host["computed_at"]),
                },
                "sca": {
                    "passed": host["sca_passed"], "failed": host["sca_failed"],
                    "total": host["sca_total"], "score": _f(host["sca_score"]),
                    "recent_failures": sca_failures,
                },
                "vulnerabilities": {
                    "critical": host["vuln_critical"], "high": host["vuln_high"],
                    "medium": host["vuln_medium"], "low": host["vuln_low"],
                    "score": _f(host["vuln_score"]),
                },
                "siem": {
                    "risk_score": _f(host["siem_risk"]),
                    "fim_events": host["fim_event_count"],
                    "malware_detections": host["malware_count"],
                    "active_incidents": active_incidents,
                    "incident_count": host["incident_count"],
                },
                "mitre": {
                    "techniques": host["mitre_techniques"] or [],
                    "breakdown": mitre_breakdown,
                },
                "compliance": {
                    "score": _f(host["compliance_score"]),
                    "sca_failures": len(sca_failures),
                },
                "alerts_by_category": alerts_by_category,
            }
    finally:
        conn.close()


def _sync_host_alerts(agent_id, category, page, per_page):
    import psycopg2.extras
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            offset = (page - 1) * per_page

            # Malware alerts are stored as category='system' with rootcheck/virustotal
            # rule groups — query by JSONB group membership instead of category label.
            if category == "malware":
                where_clause = """
                    agent_id = %s
                    AND timestamp > NOW() - INTERVAL '30 days'
                    AND (
                        category = 'malware'
                        OR (category = 'system' AND (
                            full_alert->'rule'->'groups' ? 'rootcheck'
                            OR full_alert->'rule'->'groups' ? 'virustotal'
                            OR full_alert->'rule'->'groups' ? 'malware'
                        ))
                    )
                """
                params = [agent_id]
                fetch_sql = f"""
                    SELECT id, timestamp, rule_id, rule_level, category,
                           mitre_id, mitre_tactic, base_score, src_ip, username,
                           file_path, incident_id,
                           COALESCE(
                               full_alert->'data'->>'title',
                               full_alert->>'full_log',
                               rule_desc
                           ) AS rule_desc,
                           full_alert->>'full_log' AS full_log,
                           full_alert->'rule'->>'description' AS rule_description
                    FROM alerts
                    WHERE {where_clause}
                    ORDER BY timestamp DESC LIMIT %s OFFSET %s
                """
                count_sql = f"SELECT COUNT(*) AS n FROM alerts WHERE {where_clause}"
            else:
                params = [agent_id]
                cat_clause = ""
                if category:
                    cat_clause = "AND category = %s"
                    params.append(category)
                where_clause = f"agent_id = %s {cat_clause} AND timestamp > NOW() - INTERVAL '30 days'"
                fetch_sql = f"""
                    SELECT id, timestamp, rule_id, rule_desc, rule_level, category,
                           mitre_id, mitre_tactic, base_score, src_ip, username,
                           file_path, incident_id,
                           NULL::text AS full_log,
                           NULL::text AS rule_description
                    FROM alerts
                    WHERE {where_clause}
                    ORDER BY timestamp DESC LIMIT %s OFFSET %s
                """
                count_sql = f"SELECT COUNT(*) AS n FROM alerts WHERE {where_clause}"

            cur.execute(fetch_sql, params + [per_page, offset])
            rows = cur.fetchall()
            cur.execute(count_sql, params)
            total = cur.fetchone()["n"]

            return {
                "alerts": [{
                    "id": r["id"], "timestamp": _iso(r["timestamp"]),
                    "rule_id": r["rule_id"], "rule_desc": r["rule_desc"],
                    "rule_level": r["rule_level"], "category": r["category"],
                    "mitre_id": r["mitre_id"], "mitre_tactic": r["mitre_tactic"],
                    "base_score": _f(r["base_score"]), "src_ip": r["src_ip"],
                    "username": r["username"], "file_path": r["file_path"],
                    "incident_id": r["incident_id"],
                    "full_log": r.get("full_log"),
                    "rule_description": r.get("rule_description"),
                } for r in rows],
                "total": total, "page": page, "per_page": per_page,
            }
    finally:
        conn.close()


def _sync_internal_posture():
    import psycopg2.extras
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE wazuh_status = 'active') AS active,
                    COUNT(*) FILTER (WHERE posture_grade IN ('D','F')) AS critical_grade,
                    CASE WHEN SUM(CASE WHEN asset_tier=1 THEN 3 WHEN asset_tier=2 THEN 2 ELSE 1 END) > 0
                         THEN SUM(posture_score * CASE WHEN asset_tier=1 THEN 3 WHEN asset_tier=2 THEN 2 ELSE 1 END)
                              / SUM(CASE WHEN asset_tier=1 THEN 3.0 WHEN asset_tier=2 THEN 2.0 ELSE 1.0 END)
                         ELSE NULL END AS weighted_score,
                    AVG(sca_score)       FILTER (WHERE sca_score IS NOT NULL)    AS avg_sca,
                    AVG(vuln_score)      FILTER (WHERE vuln_score IS NOT NULL)   AS avg_vuln,
                    AVG(100 - siem_risk) FILTER (WHERE siem_risk IS NOT NULL)    AS avg_siem,
                    AVG(CASE WHEN fim_event_count > 0 OR malware_count > 0 THEN 50.0 ELSE 100.0 END) AS avg_fim,
                    AVG(compliance_score) FILTER (WHERE compliance_score IS NOT NULL) AS avg_comp
                FROM host_posture_cache
            """)
            agg = cur.fetchone()
            if not agg or agg["total"] == 0:
                return {"score": 0, "grade": "F",
                        "host_count": {"total": 0, "active": 0, "critical_grade": 0},
                        "components": {}, "worst_hosts": []}
            score = _f(agg["weighted_score"]) or 0.0

            cur.execute("""
                SELECT agent_id, agent_name, posture_score, posture_grade, siem_risk
                FROM host_posture_cache ORDER BY posture_score ASC NULLS LAST LIMIT 5
            """)
            worst = [{"agent_id": r["agent_id"], "agent_name": r["agent_name"],
                      "score": _f(r["posture_score"]), "grade": r["posture_grade"],
                      "siem_risk": _f(r["siem_risk"])} for r in cur.fetchall()]

            return {
                "score": round(score, 1), "grade": _grade(score),
                "host_count": {"total": agg["total"], "active": agg["active"],
                               "critical_grade": agg["critical_grade"]},
                "components": {
                    "sca":         {"score": round(_f(agg["avg_sca"])  or 0, 1), "weight": 0.30},
                    "vuln":        {"score": round(_f(agg["avg_vuln"]) or 0, 1), "weight": 0.25},
                    "siem_risk":   {"score": round(_f(agg["avg_siem"]) or 0, 1), "weight": 0.25},
                    "fim_malware": {"score": round(_f(agg["avg_fim"])  or 0, 1), "weight": 0.10},
                    "compliance":  {"score": round(_f(agg["avg_comp"]) or 0, 1), "weight": 0.10},
                },
                "worst_hosts": worst,
            }
    finally:
        conn.close()


def _sync_hunt_rules():
    import psycopg2.extras
    from cysiemstack.threat_hunter.hunter import load_hunt_rules
    rules = load_hunt_rules()
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT metadata->>'hunt_rule_id' AS rule_id,
                       COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE status NOT IN ('closed','false_positive')) AS open
                FROM incidents WHERE incident_type = 'hunt_finding'
                GROUP BY metadata->>'hunt_rule_id'
            """)
            counts = {r["rule_id"]: {"total": r["total"], "open": r["open"]}
                      for r in cur.fetchall()}
        return [{
            "id": r.get("id"), "name": r.get("name"),
            "description": r.get("description"), "enabled": r.get("enabled", True),
            "window_hours": r.get("window_hours"), "min_count": r.get("min_count"),
            "total_findings": counts.get(r.get("id"), {}).get("total", 0),
            "open_findings":  counts.get(r.get("id"), {}).get("open", 0),
        } for r in rules]
    finally:
        conn.close()


def _run_hunts_background():
    """Spawn threat hunt run in a background thread with a fresh async engine."""
    import threading, asyncio

    def _worker():
        async def _run():
            db_url = os.environ.get("DATABASE_URL",
                "postgresql+asyncpg://corruser:changeme@127.0.0.1:5433/correlation")
            from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
            engine = create_async_engine(db_url, echo=False)
            session_factory = async_sessionmaker(engine, expire_on_commit=False)
            async with session_factory() as session:
                from cysiemstack.threat_hunter.hunter import run_all_hunts
                return await run_all_hunts(session)
            await engine.dispose()
        asyncio.run(_run())

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


# Guard flag: prevents stampeding the host refresh when cache is found empty.
_host_refresh_in_flight = False


def _refresh_host_cache_sync():
    """Pure psycopg2 host posture refresh — works without the correlation engine.

    Fetches agents from Wazuh (if credentials available) plus the alerts table,
    computes the 5-component posture score for each agent, and upserts the
    results directly into host_posture_cache via psycopg2.
    """
    import psycopg2.extras
    import base64 as _b64

    # ── Ensure table + all required columns exist ─────────────────────────────
    conn = _corr_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS host_posture_cache (
                        agent_id         TEXT PRIMARY KEY,
                        agent_name       TEXT,
                        agent_ip         TEXT,
                        os_platform      TEXT,
                        os_version       TEXT,
                        wazuh_status     TEXT,
                        last_keepalive   TIMESTAMPTZ,
                        posture_score    NUMERIC(5,1),
                        posture_grade    TEXT,
                        sca_score        NUMERIC(5,1),
                        sca_passed       INTEGER DEFAULT 0,
                        sca_failed       INTEGER DEFAULT 0,
                        sca_total        INTEGER DEFAULT 0,
                        vuln_score       NUMERIC(5,1),
                        vuln_critical    INTEGER DEFAULT 0,
                        vuln_high        INTEGER DEFAULT 0,
                        vuln_medium      INTEGER DEFAULT 0,
                        vuln_low         INTEGER DEFAULT 0,
                        siem_risk        NUMERIC(5,1) DEFAULT 0,
                        fim_event_count  INTEGER DEFAULT 0,
                        malware_count    INTEGER DEFAULT 0,
                        incident_count   INTEGER DEFAULT 0,
                        compliance_score NUMERIC(5,1),
                        mitre_techniques TEXT[],
                        score_breakdown  JSONB,
                        top_findings     JSONB DEFAULT '[]'::jsonb,
                        asset_tier       INTEGER DEFAULT 3,
                        computed_at      TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                for _col_sql in [
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS os_version TEXT",
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS top_findings JSONB DEFAULT '[]'::jsonb",
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS score_breakdown JSONB DEFAULT '{}'::jsonb",
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS compliance_score NUMERIC(5,1)",
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[]",
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS asset_tier INTEGER DEFAULT 3",
                ]:
                    cur.execute(_col_sql)
    finally:
        conn.close()

    # ── Wazuh token ───────────────────────────────────────────────────────────
    token = None
    if WAZUH_API_PASS:
        try:
            creds = _b64.b64encode(
                f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()
            ).decode()
            r = _req.get(
                f"{WAZUH_API_URL}/security/user/authenticate",
                headers={"Authorization": f"Basic {creds}"},
                timeout=10, verify=False,
            )
            if r.status_code == 200:
                token = r.json()["data"]["token"]
        except Exception as exc:
            _logger.debug("[host-refresh] Wazuh token error: %s", exc)

    def _wazuh(path, params=None):
        if not token:
            return None
        try:
            r = _req.get(
                f"{WAZUH_API_URL}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params or {},
                timeout=10, verify=False,
            )
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    # ── Build unified agent list ──────────────────────────────────────────────
    wazuh_agents = {}
    if token:
        data = _wazuh("/agents", {
            "status": "active,disconnected,never_connected",
            "limit": 500,
            "select": "id,name,ip,status,os.platform,os.version,lastKeepAlive,version",
        })
        if data:
            for a in data.get("data", {}).get("affected_items", []):
                wazuh_agents[a["id"]] = a

    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT agent_id, agent_name, agent_ip FROM alerts
                WHERE timestamp > NOW() - INTERVAL '90 days'
            """)
            db_agents = cur.fetchall()
    finally:
        conn.close()

    all_agents = {}
    for a in db_agents:
        all_agents[a["agent_id"]] = {
            "id": a["agent_id"], "name": a["agent_name"] or a["agent_id"],
            "ip": a["agent_ip"], "status": "unknown",
            "os_platform": None, "os_version": None, "last_keepalive": None,
        }
    for aid, a in wazuh_agents.items():
        all_agents[aid] = {
            "id": aid, "name": a.get("name", aid), "ip": a.get("ip"),
            "status": a.get("status", "unknown"),
            "os_platform": (a.get("os") or {}).get("platform"),
            "os_version":  (a.get("os") or {}).get("version"),
            "last_keepalive": a.get("lastKeepAlive"),
        }

    # Deduplicate by agent name: a host re-enrolled in Wazuh keeps the same name
    # but gets a new agent_id; the old id lingers in alerts for up to 90 days.
    # Keep the Wazuh-registered id over the DB-only stale one.
    _seen_names: dict = {}
    _deduped: dict = {}
    for _aid, _info in all_agents.items():
        _nk = (_info["name"] or _aid).lower()
        if _nk not in _seen_names:
            _seen_names[_nk] = _aid
            _deduped[_aid] = _info
        else:
            _prev = _seen_names[_nk]
            if _aid in wazuh_agents and _prev not in wazuh_agents:
                del _deduped[_prev]
                _seen_names[_nk] = _aid
                _deduped[_aid] = _info
    all_agents = _deduped

    if not all_agents:
        _logger.warning("[host-refresh] no agents found (wazuh=%d, db=%d)",
                        len(wazuh_agents), len(db_agents))
        return 0

    # ── Per-agent posture compute + upsert ────────────────────────────────────
    refreshed = 0
    for agent_id, info in all_agents.items():
        try:
            conn = _corr_conn()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

                    # Component 1 — SCA pass rate (30%)
                    sca_passed = sca_failed = sca_total = 0
                    sca_score = None
                    if token:
                        sca_data = _wazuh(f"/sca/{agent_id}", {"limit": 50})
                        if sca_data:
                            for pol in sca_data.get("data", {}).get("affected_items", []):
                                sca_passed += int(pol.get("pass",  0))
                                sca_failed += int(pol.get("fail",  0))
                                sca_total  += (int(pol.get("pass", 0))
                                               + int(pol.get("fail",  0))
                                               + int(pol.get("error", 0)))
                    if sca_total > 0:
                        sca_score = round(sca_passed / sca_total * 100, 1)
                    else:
                        cur.execute("""
                            SELECT
                              COUNT(*) FILTER (WHERE full_alert->'data'->'sca'->'check'->>'result' = 'passed') AS passed,
                              COUNT(*) FILTER (WHERE full_alert->'data'->'sca'->'check'->>'result' = 'failed') AS failed
                            FROM alerts
                            WHERE agent_id = %s AND category = 'sca'
                              AND timestamp > NOW() - INTERVAL '7 days'
                        """, [agent_id])
                        row = cur.fetchone()
                        if row and (row["passed"] + row["failed"]) > 0:
                            sca_passed, sca_failed = row["passed"], row["failed"]
                            sca_total = sca_passed + sca_failed
                            sca_score = round(sca_passed / sca_total * 100, 1)

                    # Component 2 — Vulnerability severity (25%)
                    vuln_critical = vuln_high = vuln_medium = vuln_low = 0
                    vuln_score = None
                    if token:
                        vuln_data = _wazuh(f"/vulnerability/{agent_id}", {
                            "limit": 500, "select": "severity", "status": "Active",
                        })
                        if vuln_data:
                            for v in vuln_data.get("data", {}).get("affected_items", []):
                                sev = v.get("severity", "")
                                if sev == "Critical":   vuln_critical += 1
                                elif sev == "High":     vuln_high     += 1
                                elif sev == "Medium":   vuln_medium   += 1
                                elif sev == "Low":      vuln_low      += 1
                        raw = (100.0
                               - min(60, vuln_critical * 12)
                               - min(36, vuln_high     *  6)
                               - min(20, vuln_medium   *  2))
                        vuln_score = max(0.0, min(100.0, round(raw, 1)))

                    # Component 3 — SIEM risk inverted (25%)
                    cur.execute("""
                        SELECT score FROM risk_scores
                        WHERE entity_id = %s AND entity_type = 'host' LIMIT 1
                    """, [agent_id])
                    row = cur.fetchone()
                    siem_risk_raw      = float(row["score"]) if row else 0.0
                    siem_risk_inverted = max(0.0, min(100.0, round(100 - siem_risk_raw, 1)))

                    # Component 4 — FIM + malware impact (10%)
                    cur.execute("""
                        SELECT
                          COUNT(*) FILTER (WHERE category = 'fim')     AS fim_count,
                          COUNT(*) FILTER (WHERE category = 'malware') AS malware_count,
                          COALESCE(SUM(base_score)::float, 0)          AS total_score
                        FROM alerts
                        WHERE agent_id = %s
                          AND category IN ('fim','malware')
                          AND timestamp > NOW() - INTERVAL '30 days'
                    """, [agent_id])
                    row = cur.fetchone()
                    fim_count      = int(row["fim_count"])     if row else 0
                    malware_count  = int(row["malware_count"]) if row else 0
                    fm_total       = float(row["total_score"]) if row else 0.0
                    fim_malware_component = max(0.0, min(100.0, round(100 - min(100, fm_total), 1)))

                    # Component 5 — Compliance gap (10%)
                    compliance_score = (
                        round(sca_passed / sca_total * 100, 1) if sca_total > 0 else 100.0
                    )

                    # Active incidents
                    cur.execute("""
                        SELECT COUNT(*) AS n FROM incidents
                        WHERE %s = ANY(affected_agents)
                          AND status NOT IN ('closed','false_positive')
                    """, [agent_id])
                    row = cur.fetchone()
                    incident_count = int(row["n"]) if row else 0

                    # MITRE techniques (last 30 days)
                    cur.execute("""
                        SELECT ARRAY_AGG(DISTINCT mitre_id) AS techniques
                        FROM alerts
                        WHERE agent_id = %s AND mitre_id IS NOT NULL
                          AND timestamp > NOW() - INTERVAL '30 days'
                    """, [agent_id])
                    row = cur.fetchone()
                    mitre_techniques = (row["techniques"] if row and row["techniques"] else [])

                    # Composite score
                    components = {
                        "sca":         sca_score         if sca_score  is not None else 50.0,
                        "vuln":        vuln_score        if vuln_score is not None else 50.0,
                        "siem_risk":   siem_risk_inverted,
                        "fim_malware": fim_malware_component,
                        "compliance":  compliance_score,
                    }
                    composite = round(
                        components["sca"]         * 0.30
                        + components["vuln"]      * 0.25
                        + components["siem_risk"] * 0.25
                        + components["fim_malware"] * 0.10
                        + components["compliance"]  * 0.10,
                        1,
                    )

                    last_kp = None
                    if info.get("last_keepalive"):
                        try:
                            last_kp = str(info["last_keepalive"]).replace("Z", "+00:00")
                        except Exception:
                            pass

                    # Upsert
                    cur.execute("""
                        INSERT INTO host_posture_cache (
                            agent_id, agent_name, agent_ip, os_platform, os_version,
                            wazuh_status, last_keepalive,
                            posture_score, posture_grade,
                            sca_score, sca_passed, sca_failed, sca_total,
                            vuln_score, vuln_critical, vuln_high, vuln_medium, vuln_low,
                            siem_risk, fim_event_count, malware_count, incident_count,
                            compliance_score, mitre_techniques, score_breakdown, computed_at
                        ) VALUES (
                            %s,%s,%s,%s,%s,
                            %s,%s,
                            %s,%s,
                            %s,%s,%s,%s,
                            %s,%s,%s,%s,%s,
                            %s,%s,%s,%s,
                            %s,%s,%s::jsonb,NOW()
                        )
                        ON CONFLICT (agent_id) DO UPDATE SET
                            agent_name       = EXCLUDED.agent_name,
                            agent_ip         = EXCLUDED.agent_ip,
                            os_platform      = EXCLUDED.os_platform,
                            os_version       = EXCLUDED.os_version,
                            wazuh_status     = EXCLUDED.wazuh_status,
                            last_keepalive   = EXCLUDED.last_keepalive,
                            posture_score    = EXCLUDED.posture_score,
                            posture_grade    = EXCLUDED.posture_grade,
                            sca_score        = EXCLUDED.sca_score,
                            sca_passed       = EXCLUDED.sca_passed,
                            sca_failed       = EXCLUDED.sca_failed,
                            sca_total        = EXCLUDED.sca_total,
                            vuln_score       = EXCLUDED.vuln_score,
                            vuln_critical    = EXCLUDED.vuln_critical,
                            vuln_high        = EXCLUDED.vuln_high,
                            vuln_medium      = EXCLUDED.vuln_medium,
                            vuln_low         = EXCLUDED.vuln_low,
                            siem_risk        = EXCLUDED.siem_risk,
                            fim_event_count  = EXCLUDED.fim_event_count,
                            malware_count    = EXCLUDED.malware_count,
                            incident_count   = EXCLUDED.incident_count,
                            compliance_score = EXCLUDED.compliance_score,
                            mitre_techniques = EXCLUDED.mitre_techniques,
                            score_breakdown  = EXCLUDED.score_breakdown,
                            computed_at      = NOW()
                    """, [
                        agent_id, info["name"], info["ip"],
                        info["os_platform"], info["os_version"],
                        info["status"], last_kp,
                        composite, _grade(composite),
                        sca_score, sca_passed, sca_failed, sca_total,
                        vuln_score, vuln_critical, vuln_high, vuln_medium, vuln_low,
                        siem_risk_raw, fim_count, malware_count, incident_count,
                        compliance_score, mitre_techniques, json.dumps(components),
                    ])
                conn.commit()
            finally:
                conn.close()
            refreshed += 1
        except Exception as exc:
            _logger.warning("[host-refresh] posture failed for %s: %s", agent_id, exc)

    _logger.info("[host-refresh] refreshed posture for %d hosts", refreshed)

    # Evict cache rows whose agent_id was removed by deduplication
    _surviving = list(all_agents.keys())
    if _surviving:
        _evict_conn = _corr_conn()
        try:
            with _evict_conn:
                with _evict_conn.cursor() as _cur:
                    _cur.execute(
                        "DELETE FROM host_posture_cache WHERE NOT (agent_id = ANY(%s))",
                        [_surviving]
                    )
                    if _cur.rowcount:
                        _logger.info("[host-refresh] evicted %d stale duplicate cache rows", _cur.rowcount)
        finally:
            _evict_conn.close()

    return refreshed


def _run_host_refresh_background():
    """Run _refresh_host_cache_sync() in a daemon thread — no engine needed."""
    global _host_refresh_in_flight
    if _host_refresh_in_flight:
        return
    _host_refresh_in_flight = True

    import threading

    def _worker():
        global _host_refresh_in_flight
        try:
            _refresh_host_cache_sync()
        except Exception as exc:
            _logger.error("[host-refresh] worker error: %s", exc)
        finally:
            _host_refresh_in_flight = False

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


# ── Flask routes ──────────────────────────────────────────────────────────────

@siem_bp.route("/hosts", methods=["GET"])
@require_siem_auth
def siem_hosts_list():
    status_filter = request.args.get("status", "all")
    sort_by       = request.args.get("sort", "posture_score")
    try:
        page     = max(1, int(request.args.get("page",     1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50
    try:
        result = _sync_hosts_list(status_filter, sort_by, page, per_page)
        # Auto-seed: if the cache is completely empty (not just filtered empty),
        # kick off a background refresh so the next page load shows data.
        if result.get("total", 0) == 0 and status_filter == "all":
            _run_host_refresh_background()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/refresh", methods=["POST"])
@require_siem_admin
def siem_hosts_refresh():
    try:
        _run_host_refresh_background()
        _run_hunts_background()
        return jsonify({"status": "refresh_queued",
                        "message": "Host posture refresh and threat hunts running in background"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>", methods=["GET"])
@require_siem_auth
def siem_host_detail(agent_id):
    try:
        result = _sync_host_detail(agent_id)
        if result is None:
            return jsonify({"error": "Host not found"}), 404
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/inventory", methods=["GET"])
@require_siem_auth
def siem_host_inventory(agent_id):
    """System inventory: agent identity, hardware, OS details, and installed packages."""
    import base64 as _b64i
    import psycopg2.extras

    def _wz_get(token, path, params=None):
        try:
            r = _req.get(
                f"{WAZUH_API_URL}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params or {}, timeout=10, verify=False,
            )
            return r.json() if r.status_code == 200 else None
        except Exception:
            return None

    result = {
        "agent": None, "os": None, "hardware": None,
        "packages": [], "packages_total": 0,
    }

    # Fallback: pull what we have from the posture cache
    try:
        conn = _corr_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT agent_id, agent_name, agent_ip, os_platform, os_version,
                       wazuh_status, last_keepalive, computed_at
                FROM host_posture_cache WHERE agent_id = %s
            """, [agent_id])
            row = cur.fetchone()
        conn.close()
        if row:
            result["agent"] = {
                "id": row["agent_id"], "name": row["agent_name"],
                "ip": row["agent_ip"], "status": row["wazuh_status"],
                "os_platform": row["os_platform"], "os_version": row["os_version"],
                "last_keepalive": _iso(row["last_keepalive"]),
                "date_add": None, "version": None, "hostname": None,
            }
    except Exception:
        pass

    if not WAZUH_API_PASS:
        return jsonify(result)

    try:
        creds = _b64i.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()).decode()
        tok_r = _req.get(
            f"{WAZUH_API_URL}/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
            timeout=8, verify=False,
        )
        tok_r.raise_for_status()
        token = tok_r.json()["data"]["token"]
    except Exception:
        return jsonify(result)

    # Agent identity — overrides cache values with live Wazuh data
    agent_data = _wz_get(token, "/agents", {
        "agents_list": agent_id,
        "select": "id,name,ip,status,os.platform,os.version,dateAdd,lastKeepAlive,version",
    })
    if agent_data:
        items = agent_data.get("data", {}).get("affected_items", [])
        if items:
            a = items[0]
            result["agent"] = {
                "id": a.get("id"), "name": a.get("name"),
                "ip": a.get("ip"), "status": a.get("status"),
                "os_platform": (a.get("os") or {}).get("platform"),
                "os_version":  (a.get("os") or {}).get("version"),
                "version": a.get("version"),
                "date_add": a.get("dateAdd"),
                "last_keepalive": a.get("lastKeepAlive"),
                "hostname": None,
            }

    # OS details (hostname, kernel, architecture)
    os_data = _wz_get(token, f"/syscollector/{agent_id}/os")
    if os_data:
        items = os_data.get("data", {}).get("affected_items", [])
        if items:
            o = items[0]
            result["os"] = {
                "hostname": o.get("hostname"),
                "architecture": o.get("architecture"),
                "kernel_release": o.get("release"),
                "sysname": o.get("sysname"),
                "os_name": (o.get("os") or {}).get("name"),
                "os_codename": (o.get("os") or {}).get("codename"),
                "os_major": (o.get("os") or {}).get("major"),
                "os_minor": (o.get("os") or {}).get("minor"),
                "scan_time": (o.get("scan") or {}).get("time"),
            }
            if result["agent"]:
                result["agent"]["hostname"] = o.get("hostname")

    # Hardware (CPU, RAM)
    hw_data = _wz_get(token, f"/syscollector/{agent_id}/hardware")
    if hw_data:
        items = hw_data.get("data", {}).get("affected_items", [])
        if items:
            h = items[0]
            result["hardware"] = {
                "cpu_name":  (h.get("cpu") or {}).get("name"),
                "cpu_cores": (h.get("cpu") or {}).get("cores"),
                "cpu_mhz":   (h.get("cpu") or {}).get("mhz"),
                "ram_total": (h.get("ram") or {}).get("total"),
                "ram_free":  (h.get("ram") or {}).get("free"),
                "ram_usage": (h.get("ram") or {}).get("usage"),
            }

    # Installed packages — top 100 by size (largest = most significant)
    pkg_req_params = request.args.get("pkg_limit", "100")
    try:
        pkg_limit = min(500, max(5, int(pkg_req_params)))
    except ValueError:
        pkg_limit = 100
    pkg_data = _wz_get(token, f"/syscollector/{agent_id}/packages", {
        "limit": pkg_limit, "sort": "-size",
    })
    if pkg_data:
        items = pkg_data.get("data", {}).get("affected_items", [])
        result["packages"] = [{
            "name":         p.get("name"),
            "version":      p.get("version"),
            "description":  p.get("description"),
            "architecture": p.get("architecture"),
            "size":         p.get("size"),
            "section":      p.get("section"),
            "vendor":       p.get("vendor"),
            "format":       p.get("format"),
            "install_time": p.get("install_time"),
        } for p in items]
        result["packages_total"] = pkg_data.get("data", {}).get("total_affected_items", 0)

    return jsonify(result)


@siem_bp.route("/hosts/<agent_id>/vulnerabilities", methods=["GET"])
@require_siem_auth
def siem_host_vulnerabilities(agent_id):
    """Return CVE data for a host.

    Primary source: correlation DB (full_alert JSONB), populated by cysiem-to-redis
    from Wazuh vulnerability-detector events.  This works regardless of Wazuh API
    version — the /vulnerability/{id} endpoint was removed in Wazuh 4.8+.
    """
    import psycopg2.extras
    try:
        page     = max(1, int(request.args.get("page",      1)))
        per_page = min(500, max(1, int(request.args.get("per_page", 100))))
        severity = request.args.get("severity", "")
        offset   = (page - 1) * per_page
    except ValueError:
        page, per_page, offset, severity = 1, 100, 0, ""

    try:
        conn = _corr_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            sev_clause = "AND full_alert->'data'->'vulnerability'->>'severity' = %s" if severity else ""
            params = [agent_id] + ([severity] if severity else [])

            count_sql = f"""
                SELECT COUNT(*) AS n FROM alerts
                WHERE agent_id = %s
                  AND category = 'vulnerability'
                  AND full_alert->'data'->>'vulnerability' IS NOT NULL
                  {sev_clause}
            """
            cur.execute(count_sql, params)
            total = cur.fetchone()["n"]

            fetch_sql = f"""
                SELECT
                    full_alert->'data'->'vulnerability'->>'cve'                       AS cve,
                    full_alert->'data'->'vulnerability'->>'severity'                  AS severity,
                    full_alert->'data'->'vulnerability'->'cvss'->'cvss3'->>'base_score' AS cvss,
                    full_alert->'data'->'vulnerability'->'package'->>'name'           AS name,
                    full_alert->'data'->'vulnerability'->'package'->>'version'        AS version,
                    full_alert->'data'->'vulnerability'->'package'->>'architecture'   AS architecture,
                    full_alert->'data'->'vulnerability'->>'title'                     AS title,
                    full_alert->'data'->'vulnerability'->>'status'                    AS status,
                    full_alert->'data'->'vulnerability'->>'reference'                 AS reference,
                    full_alert->'data'->'vulnerability'->'scanner'->>'reference'      AS scanner_ref,
                    full_alert->'data'->'vulnerability'->>'published'                 AS published,
                    timestamp
                FROM alerts
                WHERE agent_id = %s
                  AND category = 'vulnerability'
                  AND full_alert->'data'->>'vulnerability' IS NOT NULL
                  {sev_clause}
                ORDER BY
                    CASE full_alert->'data'->'vulnerability'->>'severity'
                        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                        WHEN 'Medium'   THEN 3 WHEN 'Low'  THEN 4
                        ELSE 5 END,
                    timestamp DESC
                LIMIT %s OFFSET %s
            """
            cur.execute(fetch_sql, params + [per_page, offset])
            rows = cur.fetchall()
        conn.close()

        vulns = [{
            "cve":          r["cve"],
            "severity":     r["severity"],
            "cvss":         float(r["cvss"]) if r["cvss"] else None,
            "name":         r["name"],
            "version":      r["version"],
            "architecture": r["architecture"],
            "title":        r["title"],
            "condition":    r["title"],
            "status":       r["status"],
            "references":   r["reference"] or r["scanner_ref"],
            "published":    str(r["published"]) if r["published"] else None,
            "detected_at":  _iso(r["timestamp"]),
        } for r in rows]

        return jsonify({
            "vulnerabilities": vulns,
            "total": total,
            "page": page, "per_page": per_page,
            "source": "db",
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/sca", methods=["GET"])
@require_siem_auth
def siem_host_sca(agent_id):
    import base64 as _b64i
    policy_id     = request.args.get("policy_id", "")
    result_filter = request.args.get("result", "")
    try:
        page     = max(1, int(request.args.get("page",      1)))
        per_page = min(500, max(1, int(request.args.get("per_page", 100))))
        offset   = (page - 1) * per_page
    except ValueError:
        page, per_page, offset = 1, 100, 0

    if not WAZUH_API_PASS:
        return jsonify({"error": "Wazuh API credentials not configured"}), 503
    try:
        creds = _b64i.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()).decode()
        token_resp = _req.get(
            f"{WAZUH_API_URL}/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
            timeout=8, verify=False,
        )
        token_resp.raise_for_status()
        token = token_resp.json()["data"]["token"]
        policies_resp = _req.get(
            f"{WAZUH_API_URL}/sca/{agent_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 50}, timeout=10, verify=False,
        )
        policies_resp.raise_for_status()
        policies = policies_resp.json().get("data", {}).get("affected_items", [])
        target_policy = policy_id or (policies[0]["policy_id"] if policies else None)
        if not target_policy:
            return jsonify({"checks": [], "policies": policies, "total": 0})
        check_params = {"limit": per_page, "offset": offset}
        if result_filter:
            check_params["result"] = result_filter
        checks_resp = _req.get(
            f"{WAZUH_API_URL}/sca/{agent_id}/checks/{target_policy}",
            headers={"Authorization": f"Bearer {token}"},
            params=check_params, timeout=10, verify=False,
        )
        checks_resp.raise_for_status()
        checks_data = checks_resp.json().get("data", {})
        return jsonify({
            "policies": policies, "policy_id": target_policy,
            "checks":   checks_data.get("affected_items", []),
            "total":    checks_data.get("total_affected_items", 0),
            "page": page, "per_page": per_page,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/alerts", methods=["GET"])
@require_siem_auth
def siem_host_alerts(agent_id):
    category = request.args.get("category", "")
    try:
        page     = max(1, int(request.args.get("page",      1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50
    try:
        return jsonify(_sync_host_alerts(agent_id, category, page, per_page))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/tier", methods=["POST"])
@require_siem_admin
def siem_host_set_tier(agent_id):
    body = request.get_json(silent=True) or {}
    tier = body.get("tier")
    if tier not in (1, 2, 3):
        return jsonify({"error": "tier must be 1, 2, or 3"}), 422
    try:
        conn = _corr_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE host_posture_cache SET asset_tier = %s WHERE agent_id = %s",
                    [tier, agent_id],
                )
                updated = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if not updated:
            return jsonify({"error": "Host not found in posture cache"}), 404
        return jsonify({"agent_id": agent_id, "tier": tier, "status": "updated"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# HOST POSTURE ITEM ENRICHMENT (AI + MISP)
# ══════════════════════════════════════════════════════════════════════════════

_HOST_ENRICH_SYSTEM = """You are a senior SOC analyst assistant. You receive a single security finding from a host posture scan and produce a concise analyst briefing with:

1. EXPLANATION: 2-3 sentences. Plain English. What is this finding, why does it matter, and what is the risk?

2. REMEDIATION: Numbered list (3-5 steps). Specific, actionable steps to fix or mitigate. Include commands or config changes where applicable.

Format EXACTLY as:
EXPLANATION:
<your explanation>

REMEDIATION:
1. <step>
2. <step>
...

Be specific. No preamble."""


def _call_ai_for_enrichment(prompt: str, timeout: float = 90.0) -> tuple[str, str, str | None]:
    """
    Call the configured LLM provider (reads ai_settings.json).
    Returns (explanation, remediation_text, error_reason).
    error_reason: None on success,
                  "not_configured" if no provider/key is present,
                  "call_failed" if config exists but the network/API call failed.
    """
    import logging as _log
    _logger = _log.getLogger(__name__)
    from core.config import AI_SETTINGS_FILE

    try:
        if not AI_SETTINGS_FILE.exists():
            return "", "", "not_configured"
        raw = AI_SETTINGS_FILE.read_text()
        cfg = json.loads(raw)
    except Exception:
        return "", "", "not_configured"

    provider = cfg.get("provider", "").strip()
    fields   = cfg.get("fields", {})

    # Guard: must have a recognised provider with required credentials
    if provider in ("anthropic", "gemini", "deepseek"):
        if not fields.get("apiKey"):
            return "", "", "not_configured"
    elif provider == "cymind":
        if not fields.get("baseUrl") or not fields.get("apiKey"):
            return "", "", "not_configured"
    elif provider == "local":
        pass  # Ollama — always attempt; may fail at call time
    else:
        return "", "", "not_configured"

    try:
        if provider == "cymind":
            base_url = fields.get("baseUrl", "").rstrip("/")
            api_key  = fields.get("apiKey", "")
            model    = fields.get("model", "").strip()
            if not base_url or not api_key:
                raise ValueError("CyMind not configured")
            _body: dict = {
                "messages":        [{"role": "user", "content": prompt}],
                "system":          _HOST_ENRICH_SYSTEM,
                "use_rag":         False,
                "use_external":    False,
                "use_mcp":         False,
                "use_integrations": False,
                "use_operational": False,
                "temperature":     0.1,
            }
            if model:
                _body["model"] = model
            resp = _req.post(
                f"{base_url}/api/v1/chat",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=_body,
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_text = data.get("content") or ""

        elif provider == "anthropic":
            api_key = fields.get("apiKey", "")
            model   = fields.get("model", "claude-3-haiku-20240307").strip()
            resp = _req.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                         "Content-Type": "application/json"},
                json={"model": model, "max_tokens": 1024,
                      "system": _HOST_ENRICH_SYSTEM,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=timeout,
            )
            resp.raise_for_status()
            raw_text = resp.json()["content"][0]["text"]

        elif provider == "gemini":
            api_key  = fields.get("apiKey", "")
            model    = fields.get("model", "gemini-1.5-flash").strip()
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            resp = _req.post(
                endpoint,
                params={"key": api_key},
                json={"contents": [{"parts": [{"text": f"{_HOST_ENRICH_SYSTEM}\n\n{prompt}"}]}]},
                timeout=timeout,
            )
            resp.raise_for_status()
            raw_text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]

        elif provider == "deepseek":
            api_key = fields.get("apiKey", "")
            model   = fields.get("model", "deepseek-chat").strip()
            resp = _req.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages": [
                    {"role": "system", "content": _HOST_ENRICH_SYSTEM},
                    {"role": "user",   "content": prompt},
                ]},
                timeout=timeout,
            )
            resp.raise_for_status()
            raw_text = resp.json()["choices"][0]["message"]["content"]

        else:  # local / ollama
            ollama_url = fields.get("baseUrl", "http://127.0.0.1:11434").rstrip("/")
            model      = fields.get("model", "llama3.1:8b").strip()
            resp = _req.post(
                f"{ollama_url}/api/generate",
                json={"model": model, "stream": False,
                      "system": _HOST_ENRICH_SYSTEM, "prompt": prompt},
                timeout=timeout,
            )
            resp.raise_for_status()
            raw_text = resp.json().get("response", "")

        # Parse explanation + remediation
        explanation  = ""
        remediation  = ""
        if "EXPLANATION:" in raw_text and "REMEDIATION:" in raw_text:
            parts       = raw_text.split("REMEDIATION:")
            explanation = parts[0].replace("EXPLANATION:", "").strip()
            remediation = parts[1].strip() if len(parts) > 1 else ""
        elif "EXPLANATION:" in raw_text:
            explanation = raw_text.replace("EXPLANATION:", "").strip()
        else:
            explanation = raw_text.strip()

        return explanation, remediation, None

    except Exception as exc:
        _logger.warning(f"[host-enrich] AI call failed: {exc}")
        return "", "", f"call_failed: {exc}"


def _misp_lookup_ioc(ioc: str, ioc_type: str = "any") -> list[dict]:
    """Query MISP for a single IOC. Returns list of attribute hits (may be empty)."""
    import logging as _log
    _logger = _log.getLogger(__name__)
    from core.helpers import get_misp_config

    cfg = get_misp_config()
    if not cfg:
        return []

    misp_url = cfg["url"].rstrip("/")
    misp_key = cfg["apiKey"]

    try:
        type_filter = {} if ioc_type == "any" else {"type": ioc_type}
        resp = _req.post(
            f"{misp_url}/attributes/restSearch",
            headers={"Authorization": misp_key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json={"returnFormat": "json", "value": ioc, "limit": 5, **type_filter},
            timeout=10,
            verify=False,  # MISP often uses self-signed certs in local installs
        )
        resp.raise_for_status()
        attrs = resp.json().get("response", {}).get("Attribute", [])
        return [
            {
                "ioc":          a.get("value", ""),
                "type":         a.get("type", ""),
                "category":     a.get("category", ""),
                "comment":      a.get("comment", ""),
                "threat_level": a.get("Event", {}).get("threat_level_id", "3"),
                "event_id":     a.get("event_id", ""),
            }
            for a in attrs[:5]
        ]
    except Exception as exc:
        _logger.debug(f"[host-enrich] MISP lookup failed for {ioc!r}: {exc}")
        return []


def _build_enrich_prompt(item_type: str, item: dict, host_name: str) -> tuple[str, list[str]]:
    """
    Build LLM prompt + list of IOCs to check in MISP for a given item.
    Returns (prompt_text, ioc_list).
    """
    iocs: list[str] = []

    if item_type == "vulnerability":
        cve      = item.get("cve", item.get("name", "unknown CVE"))
        severity = item.get("severity", "")
        pkg      = item.get("package_name", item.get("component", ""))
        version  = item.get("package_version", item.get("version", ""))
        desc     = item.get("description", item.get("summary", ""))
        cvss     = item.get("cvss3_score", item.get("cvss_score", ""))
        if cve and cve.startswith("CVE-"):
            iocs.append(cve)
        prompt = (
            f"Host: {host_name}\n"
            f"Finding type: Vulnerability\n"
            f"CVE: {cve}\n"
            f"Severity: {severity}\n"
            f"Package: {pkg} {version}\n"
            f"CVSS score: {cvss}\n"
            f"Description: {desc}\n\n"
            f"Provide a SOC analyst briefing for this vulnerability."
        )

    elif item_type == "sca":
        title   = item.get("title", item.get("description", "Unknown check"))
        result  = item.get("result", "failed")
        policy  = item.get("policy", "")
        rationale = item.get("rationale", "")
        remediation = item.get("remediation", item.get("command", ""))
        prompt = (
            f"Host: {host_name}\n"
            f"Finding type: Security Configuration Assessment (SCA)\n"
            f"Check: {title}\n"
            f"Result: {result}\n"
            f"Policy: {policy}\n"
            f"Rationale: {rationale}\n"
            f"Suggested remediation from scanner: {remediation}\n\n"
            f"Provide a SOC analyst briefing for this failed configuration check."
        )

    elif item_type == "alert":
        rule_id   = item.get("rule_id", item.get("id", ""))
        rule_desc = item.get("rule_description", item.get("description", "Alert"))
        category  = item.get("category", item.get("groups", ""))
        agent     = item.get("agent_name", host_name)
        src_ip    = item.get("src_ip", "")
        username  = item.get("username", "")
        full_log  = item.get("full_log", item.get("data", ""))[:500]
        if src_ip:
            iocs.append(src_ip)
        prompt = (
            f"Host: {agent}\n"
            f"Finding type: Security Alert\n"
            f"Rule: [{rule_id}] {rule_desc}\n"
            f"Category: {category}\n"
            f"Source IP: {src_ip or 'N/A'}\n"
            f"User: {username or 'N/A'}\n"
            f"Log excerpt: {full_log}\n\n"
            f"Provide a SOC analyst briefing for this security alert."
        )

    elif item_type == "mitre":
        technique = item.get("technique", item.get("id", ""))
        tactic    = item.get("tactic", item.get("phase", ""))
        desc      = item.get("description", "")
        count     = item.get("count", item.get("alert_count", ""))
        prompt = (
            f"Host: {host_name}\n"
            f"Finding type: MITRE ATT&CK Technique\n"
            f"Technique: {technique}\n"
            f"Tactic: {tactic}\n"
            f"Description: {desc}\n"
            f"Alert count on this host: {count}\n\n"
            f"Provide a SOC analyst briefing for this MITRE ATT&CK technique observed on the host."
        )

    elif item_type == "compliance":
        requirement = item.get("requirement", item.get("id", ""))
        framework   = item.get("framework", item.get("policy", ""))
        result      = item.get("result", item.get("status", "failed"))
        description = item.get("description", item.get("title", ""))
        prompt = (
            f"Host: {host_name}\n"
            f"Finding type: Compliance Check\n"
            f"Framework: {framework}\n"
            f"Requirement: {requirement}\n"
            f"Status: {result}\n"
            f"Description: {description}\n\n"
            f"Provide a SOC analyst briefing for this compliance failure."
        )

    else:
        prompt = (
            f"Host: {host_name}\n"
            f"Finding type: {item_type}\n"
            f"Item data: {json.dumps(item, default=str)[:800]}\n\n"
            f"Provide a SOC analyst briefing for this security finding."
        )

    return prompt, iocs


@siem_bp.route("/hosts/<agent_id>/enrich", methods=["POST"])
@require_siem_analyst
def siem_host_item_enrich(agent_id):
    """
    AI + MISP enrichment for a single host posture item.

    Request body:
      {
        "item_type": "vulnerability|sca|alert|mitre|compliance",
        "item": { ...item fields from the relevant tab },
        "host_name": "optional-hostname"
      }

    Response:
      {
        "explanation": "...",
        "remediation": "...",
        "misp_hits": [...],
        "ai_available": true|false
      }
    """
    body      = request.get_json(silent=True) or {}
    item_type = body.get("item_type", "generic").strip().lower()
    item      = body.get("item", {})
    host_name = body.get("host_name", agent_id)

    if not item:
        return jsonify({"error": "item is required"}), 422

    # Build prompt + extract IOCs
    prompt, iocs = _build_enrich_prompt(item_type, item, host_name)

    # Call AI
    explanation, remediation, ai_error = _call_ai_for_enrichment(prompt)

    # MISP lookup for any IOCs found in the item
    misp_hits: list[dict] = []
    for ioc in iocs[:3]:  # cap at 3 to avoid long waits
        hits = _misp_lookup_ioc(ioc)
        misp_hits.extend(hits)

    return jsonify({
        "explanation":    explanation,
        "remediation":    remediation,
        "misp_hits":      misp_hits,
        "ai_available":   bool(explanation),
        "ai_configured":  ai_error != "not_configured",
        "ai_error":       ai_error,
    })


@siem_bp.route("/hosts/<agent_id>/enrich", methods=["OPTIONS"])
def siem_host_item_enrich_options(agent_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


# ── Host posture item acknowledgements ────────────────────────────────────────

@siem_bp.route("/hosts/<agent_id>/item-statuses", methods=["GET"])
@require_siem_auth
def siem_host_item_statuses_get(agent_id):
    """
    Return all saved item acknowledgements for a host, grouped by item_type.

    Response: { "sca": {"<key>": "<status>", ...}, "vulnerability": {...}, ... }
    """
    _ensure_acks_table()
    try:
        import psycopg2.extras
        conn = _corr_conn()
        result: dict = {}
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT item_type, item_key, status FROM host_item_acks WHERE agent_id = %s",
                    [agent_id],
                )
                for row in cur.fetchall():
                    result.setdefault(row["item_type"], {})[row["item_key"]] = row["status"]
        conn.close()
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/item-statuses", methods=["POST"])
@require_siem_analyst
def siem_host_item_statuses_post(agent_id):
    """
    Upsert or delete a single item acknowledgement.

    Request body: { "item_type": "sca|vulnerability|alert|mitre|compliance",
                    "item_key": "<stable item identifier>",
                    "status": "investigating|in_review|resolved|false_positive" }
    Pass status=null or omit to clear the acknowledgement.
    """
    _ensure_acks_table()
    body      = request.get_json(silent=True) or {}
    item_type = body.get("item_type", "").strip()
    item_key  = body.get("item_key",  "").strip()
    status    = body.get("status")        # None or empty → delete

    _valid_types    = {"sca", "vulnerability", "alert", "mitre", "compliance"}
    _valid_statuses = {"investigating", "in_review", "resolved", "false_positive"}

    if not item_type or item_type not in _valid_types:
        return jsonify({"error": "invalid item_type"}), 400
    if not item_key:
        return jsonify({"error": "item_key required"}), 400
    if status and status not in _valid_statuses:
        return jsonify({"error": "invalid status"}), 400
    try:
        conn = _corr_conn()
        with conn:
            with conn.cursor() as cur:
                if not status:
                    cur.execute(
                        "DELETE FROM host_item_acks "
                        "WHERE agent_id=%s AND item_type=%s AND item_key=%s",
                        [agent_id, item_type, item_key],
                    )
                else:
                    cur.execute("""
                        INSERT INTO host_item_acks
                            (agent_id, item_type, item_key, status, updated_at)
                        VALUES (%s, %s, %s, %s, NOW())
                        ON CONFLICT (agent_id, item_type, item_key)
                        DO UPDATE SET status=EXCLUDED.status, updated_at=NOW()
                    """, [agent_id, item_type, item_key, status])
        conn.close()
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/item-statuses", methods=["OPTIONS"])
def siem_host_item_statuses_options(agent_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))




# ══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@siem_bp.route("/threat-hunting/rules", methods=["GET"])
@require_siem_auth
def siem_threat_hunt_rules():
    try:
        return jsonify(_sync_hunt_rules())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/threat-hunting/findings", methods=["GET"])
@require_siem_auth
def siem_threat_hunt_findings():
    return _proxy("/incidents?category=hunt_finding")


@siem_bp.route("/threat-hunting/run", methods=["POST"])
@require_siem_admin
def siem_threat_hunt_run():
    try:
        _run_hunts_background()
        return jsonify({"status": "hunt_queued",
                        "message": "Threat hunt running in background"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/posture/internal", methods=["GET"])
@require_siem_auth
def siem_internal_posture():
    try:
        return jsonify(_sync_internal_posture())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
