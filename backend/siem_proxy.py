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
import time
import subprocess
from collections import defaultdict
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


@siem_bp.route("/incidents/<incident_id>/escalate", methods=["POST"])
@require_siem_analyst
def siem_incident_escalate(incident_id):
    """Manually escalate a SIEM incident to CyIRIS.

    Handled entirely within Flask (not proxied to the engine) so that
    get_iris_config() can read cloud credentials from /opt/cycentra/.env —
    the systemd engine service uses cysiemstack.env which does not have those vars.

    Steps:
      1. Fetch incident from engine
      2. If already ticketed, return existing ticket info
      3. Create IRIS case via get_iris_config()
      4. PATCH incident in engine to persist iris_case_id/url/status
    """
    from core.helpers import get_iris_config

    # ── 1. Fetch incident from engine ─────────────────────────────────────────
    try:
        inc_resp = _req.get(
            f"{SIEM_ENGINE_URL}/incidents/{incident_id}",
            timeout=PROXY_TIMEOUT,
        )
    except _req.exceptions.ConnectionError:
        return _engine_offline_response()
    except _req.exceptions.Timeout:
        return jsonify({"error": "Engine request timed out"}), 504

    if inc_resp.status_code == 404:
        return jsonify({"error": "Incident not found"}), 404
    if not inc_resp.ok:
        return jsonify({"error": f"Engine returned HTTP {inc_resp.status_code}"}), 502

    inc = inc_resp.json()

    # ── 2. Already ticketed ────────────────────────────────────────────────────
    if inc.get("iris_case_id"):
        return jsonify({
            "iris_case_id":     inc["iris_case_id"],
            "iris_case_url":    inc.get("iris_case_url"),
            "iris_case_status": inc.get("iris_case_status", "open"),
            "already_existed":  True,
        })

    # ── 3. Check IRIS config ───────────────────────────────────────────────────
    cfg = get_iris_config()
    if not cfg:
        return jsonify({"error": "CyIRIS is not configured. Enable it in System Settings → Integrations → CyIRIS."}), 422

    # ── 4. Build IRIS case ─────────────────────────────────────────────────────
    analyst_email = session.get("user_email", "unknown")
    sev = (inc.get("severity") or "low").lower()
    _SEV_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    case_sev = _SEV_MAP.get(sev, 4)

    agents = ", ".join(inc.get("affected_agents") or []) or "unknown"
    users  = ", ".join(inc.get("affected_users")  or []) or "none"
    ips    = ", ".join(inc.get("src_ips")          or []) or "none"
    mitre  = ", ".join(inc.get("mitre_ids")        or []) or "None"

    rules_fired = inc.get("correlated_rules") or []
    rules_str = "\n".join(
        f"  • {r.get('rule_id', '?')} — {r.get('description', '')}"
        for r in rules_fired[:5]
    ) or "  (none)"

    case_name = (
        f"[Incident] {sev.upper()} — {inc.get('id', incident_id)}"
    )
    case_description = (
        f"## CySIEM Incident: {inc.get('id', incident_id)}\n\n"
        f"**Severity:** {sev.upper()}  \n"
        f"**Status:** {inc.get('status', 'open')}  \n"
        f"**First Seen:** {inc.get('first_seen', 'N/A')}  \n"
        f"**Last Seen:** {inc.get('last_seen', 'N/A')}  \n"
        f"**Alert Count:** {inc.get('alert_count', 0)}  \n\n"
        f"**Affected Hosts:** {agents}  \n"
        f"**Affected Users:** {users}  \n"
        f"**Source IPs:** {ips}  \n"
        f"**MITRE ATT&CK:** {mitre}  \n\n"
        f"### Correlated Rules\n{rules_str}\n"
    )
    if inc.get("llm_summary"):
        case_description += f"\n### AI Narrative\n{inc['llm_summary']}\n"
    case_description += f"\n---\n*Escalated manually by {analyst_email} via CyCentra360 Active Incidents*"

    try:
        resp = _req.post(
            f"{cfg['url'].rstrip('/')}/api/v2/cases",
            headers={
                "Authorization": f"Bearer {cfg['apiKey']}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            json={
                "case_name":        case_name,
                "case_description": case_description,
                "case_customer":    cfg.get("customerId", 1),
                "case_severity_id": case_sev,
                "case_soc_id":      incident_id,
            },
            timeout=10,
            verify=False,
        )
    except _req.exceptions.ConnectionError:
        return jsonify({"error": "Cannot reach CyIRIS. Check URL in System Settings → CyIRIS."}), 503
    except _req.exceptions.Timeout:
        return jsonify({"error": "CyIRIS request timed out"}), 504

    if resp.status_code not in (200, 201):
        return jsonify({"error": f"IRIS returned HTTP {resp.status_code}", "detail": resp.text[:300]}), 502

    data  = resp.json()
    case  = data if "case_id" in data else data.get("data", data)
    case_id  = case.get("case_id")
    case_url = f"{cfg['url'].rstrip('/')}/case?cid={case_id}" if case_id else cfg["url"]

    # ── 5. Persist ticket info back to the engine ──────────────────────────────
    try:
        _req.patch(
            f"{SIEM_ENGINE_URL}/incidents/{incident_id}",
            json={
                "iris_case_id":     str(case_id),
                "iris_case_url":    case_url,
                "iris_case_status": "open",
            },
            timeout=PROXY_TIMEOUT,
        )
    except Exception:
        pass  # ticket was created — don't fail the response over a patch error

    return jsonify({
        "iris_case_id":     case_id,
        "iris_case_url":    case_url,
        "iris_case_status": "open",
        "already_existed":  False,
    })


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
                       llm_summary, mitre_ids, iris_case_id
                FROM incidents
                WHERE %s = ANY(affected_agents)
                  AND status NOT IN ('closed','false_positive')
                ORDER BY last_seen DESC LIMIT 10
            """, [agent_id])
            active_incidents = [{
                "id": r["id"], "severity": r["severity"], "status": r["status"],
                "first_seen": _iso(r["first_seen"]), "last_seen": _iso(r["last_seen"]),
                "summary": r["llm_summary"], "mitre_ids": r["mitre_ids"] or [],
                "iris_case_id": r["iris_case_id"],
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
            params = [agent_id]
            cat_clause = ""
            if category:
                cat_clause = "AND category = %s"
                params.append(category)
            offset = (page - 1) * per_page
            cur.execute(f"""
                SELECT id, timestamp, rule_id, rule_desc, rule_level, category,
                       mitre_id, mitre_tactic, base_score, src_ip, username,
                       file_path, incident_id
                FROM alerts
                WHERE agent_id = %s {cat_clause}
                  AND timestamp > NOW() - INTERVAL '30 days'
                ORDER BY timestamp DESC LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = cur.fetchall()
            cur.execute(f"""
                SELECT COUNT(*) AS n FROM alerts
                WHERE agent_id = %s {cat_clause}
                  AND timestamp > NOW() - INTERVAL '30 days'
            """, params)
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
        return jsonify(_sync_hosts_list(status_filter, sort_by, page, per_page))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/refresh", methods=["POST"])
@require_siem_admin
def siem_hosts_refresh():
    try:
        _run_hunts_background()
        return jsonify({"status": "refresh_queued",
                        "message": "Posture refresh running in background"})
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


@siem_bp.route("/hosts/<agent_id>/vulnerabilities", methods=["GET"])
@require_siem_auth
def siem_host_vulnerabilities(agent_id):
    import base64 as _b64i
    try:
        page     = max(1, int(request.args.get("page",      1)))
        per_page = min(500, max(1, int(request.args.get("per_page", 100))))
        severity = request.args.get("severity", "")
        offset   = (page - 1) * per_page
    except ValueError:
        page, per_page, offset, severity = 1, 100, 0, ""

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
        params = {"limit": per_page, "offset": offset, "status": "Active"}
        if severity:
            params["severity"] = severity
        vuln_resp = _req.get(
            f"{WAZUH_API_URL}/vulnerability/{agent_id}",
            headers={"Authorization": f"Bearer {token}"},
            params=params, timeout=10, verify=False,
        )
        vuln_resp.raise_for_status()
        data = vuln_resp.json().get("data", {})
        return jsonify({
            "vulnerabilities": data.get("affected_items", []),
            "total":           data.get("total_affected_items", 0),
            "page": page, "per_page": per_page,
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


def _call_ai_for_enrichment(prompt: str, timeout: float = 90.0) -> tuple[str, str]:
    """
    Call the configured LLM provider (reads ai_settings.json).
    Returns (explanation, remediation_text). Falls back to empty strings on failure.
    """
    import logging as _log
    _logger = _log.getLogger(__name__)
    from core.config import AI_SETTINGS_FILE

    try:
        raw = AI_SETTINGS_FILE.read_text() if AI_SETTINGS_FILE.exists() else "{}"
        cfg = json.loads(raw)
    except Exception:
        cfg = {}

    provider = cfg.get("provider", "local")
    fields   = cfg.get("fields", {})

    try:
        if provider == "cymind":
            base_url = fields.get("baseUrl", "").rstrip("/")
            api_key  = fields.get("apiKey", "")
            model    = fields.get("model", "").strip() or "llama3:8b"
            if not base_url or not api_key:
                raise ValueError("CyMind not configured")
            resp = _req.post(
                f"{base_url}/api/v1/chat",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"message": prompt, "system_prompt": _HOST_ENRICH_SYSTEM,
                      "model": model, "stream": False},
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_text = data.get("response") or data.get("message") or ""

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

        return explanation, remediation

    except Exception as exc:
        _logger.warning(f"[host-enrich] AI call failed: {exc}")
        return "", ""


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
    explanation, remediation = _call_ai_for_enrichment(prompt)

    # MISP lookup for any IOCs found in the item
    misp_hits: list[dict] = []
    for ioc in iocs[:3]:  # cap at 3 to avoid long waits
        hits = _misp_lookup_ioc(ioc)
        misp_hits.extend(hits)

    return jsonify({
        "explanation":  explanation,
        "remediation":  remediation,
        "misp_hits":    misp_hits,
        "ai_available": bool(explanation),
    })


@siem_bp.route("/hosts/<agent_id>/enrich", methods=["OPTIONS"])
def siem_host_item_enrich_options(agent_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


_HOST_SEV_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}


@siem_bp.route("/hosts/<agent_id>/raise-ticket", methods=["POST"])
@require_siem_analyst
def siem_host_raise_ticket(agent_id):
    """
    Create a CyIRIS case from a host posture finding (SCA/CVE/Alert/MITRE/Compliance).

    Request body:
      {
        "item_type":   "vulnerability|sca|alert|mitre|compliance",
        "item":        { ...item fields },
        "host_name":   "hostname",
        "explanation": "AI explanation from /enrich (optional, enriches case body)",
        "remediation": "AI remediation steps (optional)"
      }
    """
    from core.helpers import get_iris_config
    import hashlib

    cfg = get_iris_config()
    if not cfg:
        return jsonify({
            "error": "CyIRIS is not configured. Enable it in System Settings → Integrations → CyIRIS."
        }), 503

    body        = request.get_json(silent=True) or {}
    item_type   = body.get("item_type", "finding").strip().lower()
    item        = body.get("item", {})
    host_name   = body.get("host_name", agent_id)
    explanation = body.get("explanation", "")
    remediation = body.get("remediation", "")
    analyst     = session.get("user_email", "analyst")

    # Derive title, severity, soc_id from item_type
    if item_type == "vulnerability":
        cve      = item.get("cve", item.get("name", "CVE-Unknown"))
        pkg      = item.get("name", item.get("package_name", ""))
        ver      = item.get("version", item.get("package_version", ""))
        sev_key  = (item.get("severity") or "medium").lower()
        case_name = f"[HOST-VULN] {cve} — {host_name}"
        soc_id_raw = f"{host_name}|{cve}".lower()
        detail_md = (
            f"**CVE:** `{cve}`  \n"
            f"**Package:** {pkg} {ver}  \n"
            f"**CVSS:** {item.get('cvss', item.get('cvss3_score', '—'))}  \n"
            f"**Description:** {item.get('title', item.get('description', '—'))}  \n"
        )
    elif item_type == "sca":
        title    = item.get("title", item.get("description", "SCA Failure"))
        sev_key  = "medium"
        case_name = f"[HOST-SCA] {title[:80]} — {host_name}"
        soc_id_raw = f"{host_name}|sca|{item.get('id', title)}".lower()
        detail_md = (
            f"**Check:** {title}  \n"
            f"**Policy:** {item.get('policy', '—')}  \n"
            f"**Result:** {item.get('result', 'failed')}  \n"
            f"**Rationale:** {item.get('rationale', '—')}  \n"
        )
    elif item_type == "alert":
        rule_desc = item.get("rule_description", item.get("description", "Security Alert"))
        lvl       = int(item.get("rule_level", 7))
        sev_key   = "critical" if lvl >= 15 else "high" if lvl >= 12 else "medium" if lvl >= 7 else "low"
        case_name = f"[HOST-ALERT] {rule_desc[:80]} — {host_name}"
        soc_id_raw = f"{host_name}|alert|{item.get('rule_id', rule_desc)}".lower()
        detail_md = (
            f"**Rule:** [{item.get('rule_id', '—')}] {rule_desc}  \n"
            f"**Level:** {lvl}  \n"
            f"**Category:** {item.get('category', '—')}  \n"
            f"**Source IP:** {item.get('src_ip', '—')}  \n"
            f"**User:** {item.get('username', '—')}  \n"
        )
    elif item_type == "mitre":
        tech  = item.get("technique", item.get("id", "Unknown Technique"))
        tactic = item.get("tactic", "—")
        sev_key = "high"
        case_name = f"[HOST-MITRE] {tech} — {host_name}"
        soc_id_raw = f"{host_name}|mitre|{tech}".lower()
        detail_md = (
            f"**Technique:** {tech}  \n"
            f"**Tactic:** {tactic}  \n"
            f"**Alert count:** {item.get('count', '—')}  \n"
            f"**Description:** {item.get('description', '—')}  \n"
        )
    else:  # compliance or generic
        title   = item.get("requirement", item.get("title", item.get("description", "Compliance Finding")))
        sev_key = "medium"
        case_name = f"[HOST-COMP] {str(title)[:80]} — {host_name}"
        soc_id_raw = f"{host_name}|compliance|{title}".lower()
        detail_md = (
            f"**Framework:** {item.get('framework', item.get('policy', '—'))}  \n"
            f"**Requirement:** {title}  \n"
            f"**Status:** {item.get('result', item.get('status', '—'))}  \n"
        )

    severity_id = _HOST_SEV_MAP.get(sev_key, 3)
    soc_id = "HPST-" + hashlib.sha256(soc_id_raw.encode()).hexdigest()[:6].upper()

    case_body = (
        f"## Host Posture Finding: {item_type.upper()}\n\n"
        f"**Host:** `{host_name}` (agent ID: `{agent_id}`)  \n"
        f"**Severity:** {sev_key.upper()}  \n\n"
        f"### Finding Details\n{detail_md}\n"
    )
    if explanation:
        case_body += f"\n### AI Analysis\n{explanation}\n"
    if remediation:
        case_body += f"\n### Recommended Remediation\n{remediation}\n"
    case_body += f"\n---\n*Raised by `{analyst}` via CyCentra360 Host Intelligence*"

    payload = {
        "case_name":        case_name,
        "case_description": case_body,
        "case_customer":    cfg["customerId"],
        "case_severity_id": severity_id,
        "case_soc_id":      soc_id,
    }
    try:
        resp = _req.post(
            f"{cfg['url'].rstrip('/')}/api/v2/cases",
            headers={
                "Authorization": f"Bearer {cfg['apiKey']}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
            json=payload,
            timeout=10,
            verify=False,
        )
        if resp.status_code in (200, 201):
            data    = resp.json()
            case    = data if "case_id" in data else data.get("data", data)
            case_id = case.get("case_id")
            case_url = f"{cfg['url'].rstrip('/')}/case?cid={case_id}" if case_id else cfg["url"]
            return jsonify({"case_id": case_id, "case_url": case_url, "case_name": case_name})
        return jsonify({"error": f"IRIS returned HTTP {resp.status_code}", "detail": resp.text[:300]}), 502
    except _req.exceptions.ConnectionError:
        return jsonify({"error": "Cannot reach CyIRIS. Check URL in System Settings."}), 503
    except _req.exceptions.Timeout:
        return jsonify({"error": "CyIRIS request timed out."}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/raise-ticket", methods=["OPTIONS"])
def siem_host_raise_ticket_options(agent_id):
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
