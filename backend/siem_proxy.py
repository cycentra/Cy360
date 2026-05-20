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
# HOST INVENTORY ROUTES
# All routes are Flask-native (not proxied to engine) — they read from the
# host_posture_cache table populated by host_service.refresh_all_hosts().
# ══════════════════════════════════════════════════════════════════════════════

def _run_async(coro):
    """Run an async coroutine from a sync Flask route.

    Uses asyncio.run() which always creates a fresh event loop — safe for
    sync werkzeug workers where a prior async init may have left a closed loop
    on the thread, which would cause run_until_complete() to raise RuntimeError.
    If a loop is already running (e.g., async WSGI server), offload to a thread.
    """
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        # Already inside a running loop — submit to a thread pool
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=30)
    except RuntimeError:
        # No running loop — safe to call asyncio.run() directly
        return asyncio.run(coro)


async def _host_list_async(status_filter, sort_by, page, per_page):
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.host_service import get_all_hosts_summary
    async with AsyncSessionLocal() as session:
        return await get_all_hosts_summary(session, status_filter, sort_by, page, per_page)


async def _host_detail_async(agent_id):
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.host_service import get_host_detail
    async with AsyncSessionLocal() as session:
        return await get_host_detail(agent_id, session)


async def _internal_posture_async():
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.host_service import get_internal_posture
    async with AsyncSessionLocal() as session:
        return await get_internal_posture(session)


async def _set_tier_async(agent_id, tier):
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.host_service import set_host_asset_tier
    async with AsyncSessionLocal() as session:
        return await set_host_asset_tier(agent_id, tier, session)


async def _refresh_hosts_async():
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.host_service import refresh_all_hosts
    async with AsyncSessionLocal() as session:
        return await refresh_all_hosts(session)


@siem_bp.route("/hosts", methods=["GET"])
@require_siem_auth
def siem_hosts_list():
    """List all known hosts with posture summary + overall internal posture score.

    Query params:
      status  — active | disconnected | all (default: all)
      sort    — posture_score | risk | name (default: posture_score)
      page    — page number (default: 1)
      per_page — items per page (default: 50, max: 200)
    """
    status_filter = request.args.get("status", "all")
    sort_by       = request.args.get("sort", "posture_score")
    try:
        page     = max(1, int(request.args.get("page",     1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50

    try:
        result = _run_async(_host_list_async(status_filter, sort_by, page, per_page))
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/refresh", methods=["POST"])
@require_siem_admin
def siem_hosts_refresh():
    """Trigger an on-demand posture cache refresh for all hosts. Admin only."""
    try:
        count = _run_async(_refresh_hosts_async())
        return jsonify({"refreshed": count, "status": "ok"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>", methods=["GET"])
@require_siem_auth
def siem_host_detail(agent_id):
    """Full security profile for a single host.

    Returns: posture score/breakdown, SCA findings, vulnerability counts,
             active incidents, MITRE techniques, compliance gaps,
             alerts by category.
    """
    try:
        result = _run_async(_host_detail_async(agent_id))
        if result is None:
            return jsonify({"error": "Host not found"}), 404
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/vulnerabilities", methods=["GET"])
@require_siem_auth
def siem_host_vulnerabilities(agent_id):
    """Live vulnerability list for a host directly from Wazuh API (paginated).

    Query params: page, per_page, severity (Critical|High|Medium|Low)
    """
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
            "page":            page,
            "per_page":        per_page,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/sca", methods=["GET"])
@require_siem_auth
def siem_host_sca(agent_id):
    """SCA policy checks for a host directly from Wazuh API (paginated).

    Query params: page, per_page, result (passed|failed|not applicable)
    """
    import base64 as _b64i
    policy_id = request.args.get("policy_id", "")
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

        # First fetch the list of SCA policies for this agent
        policies_resp = _req.get(
            f"{WAZUH_API_URL}/sca/{agent_id}",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 50}, timeout=10, verify=False,
        )
        policies_resp.raise_for_status()
        policies = policies_resp.json().get("data", {}).get("affected_items", [])

        # Then fetch checks for the requested (or first) policy
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
            "policies":  policies,
            "policy_id": target_policy,
            "checks":    checks_data.get("affected_items", []),
            "total":     checks_data.get("total_affected_items", 0),
            "page":      page,
            "per_page":  per_page,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/alerts", methods=["GET"])
@require_siem_auth
def siem_host_alerts(agent_id):
    """Recent alerts for a specific host (from correlation DB, not Wazuh directly)."""
    category = request.args.get("category", "")
    try:
        page     = max(1, int(request.args.get("page",      1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50

    async def _fetch():
        from cysiemstack.correlation_engine.models import AsyncSessionLocal
        from sqlalchemy import text as _text
        async with AsyncSessionLocal() as db:
            params = {"aid": agent_id, "limit": per_page, "offset": (page - 1) * per_page}
            cat_clause = "AND category = :cat" if category else ""
            if category:
                params["cat"] = category
            rows = await db.execute(
                _text(f"""
                    SELECT id, timestamp, rule_id, rule_desc, rule_level,
                           category, mitre_id, mitre_tactic, base_score,
                           src_ip, username, file_path, incident_id
                    FROM alerts
                    WHERE agent_id = :aid {cat_clause}
                      AND timestamp > NOW() - INTERVAL '30 days'
                    ORDER BY timestamp DESC
                    LIMIT :limit OFFSET :offset
                """),
                params,
            )
            count_row = await db.execute(
                _text(f"SELECT COUNT(*) FROM alerts WHERE agent_id = :aid {cat_clause} AND timestamp > NOW() - INTERVAL '30 days'"),
                params,
            )
            total = count_row.scalar() or 0
            alerts = [
                {
                    "id":          r.id,
                    "timestamp":   r.timestamp.isoformat() if r.timestamp else None,
                    "rule_id":     r.rule_id,
                    "rule_desc":   r.rule_desc,
                    "rule_level":  r.rule_level,
                    "category":    r.category,
                    "mitre_id":    r.mitre_id,
                    "mitre_tactic":r.mitre_tactic,
                    "base_score":  float(r.base_score) if r.base_score else None,
                    "src_ip":      r.src_ip,
                    "username":    r.username,
                    "file_path":   r.file_path,
                    "incident_id": r.incident_id,
                }
                for r in rows.fetchall()
            ]
            return {"alerts": alerts, "total": total, "page": page, "per_page": per_page}

    try:
        return jsonify(_run_async(_fetch()))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/hosts/<agent_id>/tier", methods=["POST"])
@require_siem_admin
def siem_host_set_tier(agent_id):
    """Set the asset criticality tier for a host. Admin only.

    Body: { "tier": 1 }  — 1=crown jewel, 2=business critical, 3=standard
    """
    body = request.get_json(silent=True) or {}
    tier = body.get("tier")
    if tier not in (1, 2, 3):
        return jsonify({"error": "tier must be 1, 2, or 3"}), 422
    try:
        ok = _run_async(_set_tier_async(agent_id, tier))
        if not ok:
            return jsonify({"error": "Host not found in posture cache"}), 404
        return jsonify({"agent_id": agent_id, "tier": tier, "status": "updated"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING ROUTES
# ══════════════════════════════════════════════════════════════════════════════

async def _hunt_rules_async():
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.threat_hunter.hunter import get_hunt_rules_status
    async with AsyncSessionLocal() as session:
        return await get_hunt_rules_status(session)


async def _hunt_run_async():
    from cysiemstack.correlation_engine.models import AsyncSessionLocal
    from cysiemstack.threat_hunter.hunter import run_all_hunts
    async with AsyncSessionLocal() as session:
        return await run_all_hunts(session)


@siem_bp.route("/threat-hunting/rules", methods=["GET"])
@require_siem_auth
def siem_threat_hunt_rules():
    """List all threat hunt rules with last-run finding counts."""
    try:
        return jsonify(_run_async(_hunt_rules_async()))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/threat-hunting/findings", methods=["GET"])
@require_siem_auth
def siem_threat_hunt_findings():
    """List hunt_finding incidents (proxied to correlation engine)."""
    return _proxy("/incidents?category=hunt_finding")


@siem_bp.route("/threat-hunting/run", methods=["POST"])
@require_siem_admin
def siem_threat_hunt_run():
    """On-demand threat hunt run across all rules. Admin only."""
    try:
        result = _run_async(_hunt_run_async())
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/posture/internal", methods=["GET"])
@require_siem_auth
def siem_internal_posture():
    """Overall internal security posture score across all hosts.

    Aggregates host_posture_cache weighted by asset tier.
    Returns: score (0-100), grade, component breakdown, worst hosts, host counts.
    Used by: Host Inventory page banner, Benchmark CSPI internal bucket.
    """
    try:
        result = _run_async(_internal_posture_async())
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
