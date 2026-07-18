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
import re
import json
import json as _json
import logging
import time
import subprocess

_logger = logging.getLogger(__name__)
from datetime import datetime, timezone, timedelta
from functools import wraps

import requests as _req
from flask import Blueprint, request, Response, jsonify, session, make_response

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
    resp = _proxy("/incidents")
    if resp.status_code != 200:
        return resp
    try:
        data = resp.get_json(force=True) or {}
        incs = data.get("incidents")
        if isinstance(incs, list):
            _inject_case_fields(incs)
        return jsonify(data)
    except Exception:
        return resp


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
    resp = _proxy(f"/incidents/{incident_id}")
    if resp.status_code != 200:
        return resp
    try:
        data = resp.get_json(force=True) or {}
        if data.get("id"):
            _inject_case_fields([data])
        return jsonify(data)
    except Exception:
        return resp


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


# ── Phase 5: SOAR status endpoint ─────────────────────────────────────────────

@siem_bp.route("/soar/status", methods=["GET"])
@require_siem_auth
def siem_soar_status():
    """Return CySOAR connection state (installed/running/url/source).
    Used by the portal Response tab to show the CySOAR status bar.
    GET → viewer+
    """
    try:
        import psycopg2.extras
        from datetime import timedelta
        conn = _corr_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            cur.execute("""
                SELECT
                    COUNT(*) FILTER (WHERE soar_dispatched = TRUE
                        AND soar_dispatched_at >= %s)              AS auto_dispatched_24h,
                    COUNT(*) FILTER (
                        WHERE soar_dispatch_log IS NOT NULL
                          AND soar_dispatched = FALSE
                          AND confidence_score >= 0.70
                          AND confidence_score < 0.90
                          AND status NOT IN ('closed','false_positive')
                    )                                               AS pending_approval,
                    COUNT(*) FILTER (
                        WHERE confidence_score IS NOT NULL
                          AND confidence_score < 0.70
                          AND status NOT IN ('closed','false_positive')
                    )                                               AS needs_review
                FROM incidents
            """, [cutoff])
            row = cur.fetchone() or {}
        conn.close()
    except Exception:
        row = {}

    # Read CySOAR install state from modules/state.json
    try:
        import json as _json
        state_raw = open("/opt/cycentra/modules/state.json").read()
        state = _json.loads(state_raw)
        soar_state = state.get("cysoar") or {}
        installed = soar_state.get("installed", False)
        running   = soar_state.get("status") == "running"
    except Exception:
        installed = False
        running   = False

    # Resolve URL without exposing auto-detected internal address
    url_src = ""
    try:
        import json as _json
        from pathlib import Path as _P
        ai_raw = _P("/opt/cycentra/ai_settings.json").read_text()
        ai_cfg = _json.loads(ai_raw)
        url_src = (ai_cfg.get("soar", {}).get("webhookUrl") or "").strip()
    except Exception:
        pass
    env_url = os.environ.get("SOAR_WEBHOOK_URL", "").strip()

    return jsonify({
        "installed":           installed,
        "running":             running,
        "url":                 env_url or url_src,
        "source":              "env" if env_url else ("config" if url_src else ("auto" if running else "none")),
        "auto_dispatched_24h": int(row.get("auto_dispatched_24h") or 0),
        "pending_approval":    int(row.get("pending_approval") or 0),
        "needs_review":        int(row.get("needs_review") or 0),
    })


# ── Phase 5: Analyst approval gate for 70–89% confidence incidents ────────────

@siem_bp.route("/incidents/<incident_id>/approve-soar", methods=["POST"])
@require_siem_analyst
def siem_incident_approve_soar(incident_id):
    """Analyst manually approves SOAR dispatch for an incident in the 70–89% gate.

    Reads recommendation from DB, forwards to Node-RED, records dispatch log.
    POST → analyst+
    """
    import psycopg2.extras
    try:
        conn = _corr_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, recommendation, confidence_score, severity, "
                "mitre_ids, kill_chain_stage_name, affected_agents, affected_users, "
                "src_ips, soar_dispatch_log, soar_dispatched "
                "FROM incidents WHERE id = %s",
                [incident_id],
            )
            inc = cur.fetchone()
        conn.close()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    if not inc:
        return jsonify({"error": "Incident not found"}), 404

    recommendation = inc.get("recommendation") or {}
    confidence     = float(inc.get("confidence_score") or 0)

    if confidence >= 0.90:
        return jsonify({"error": "This incident was already auto-dispatched (confidence ≥ 90%)"}), 400
    if confidence < 0.70:
        return jsonify({"error": "Confidence too low for SOAR dispatch (< 70%)"}), 400
    if inc.get("soar_dispatched"):
        return jsonify({"error": "Already dispatched"}), 409
    if not recommendation:
        return jsonify({"error": "No structured recommendation available yet"}), 422

    analyst_email = session.get("user_email", "analyst")
    now = datetime.now(timezone.utc)

    # Resolve webhook URL
    soar_url = os.environ.get("SOAR_WEBHOOK_URL", "").strip()
    if not soar_url:
        try:
            import json as _j
            ai_raw = open("/opt/cycentra/ai_settings.json").read()
            ai_cfg = _j.loads(ai_raw)
            soar_url = (ai_cfg.get("soar", {}).get("webhookUrl") or "").strip()
        except Exception:
            pass
    if not soar_url:
        try:
            import json as _j
            state_raw = open("/opt/cycentra/modules/state.json").read()
            state = _j.loads(state_raw)
            if (state.get("cysoar") or {}).get("status") == "running":
                soar_url = "http://127.0.0.1:1880"
        except Exception:
            pass

    if not soar_url:
        return jsonify({"error": "CySOAR not installed or not running"}), 503

    payload = {
        "incident_id":      incident_id,
        "confidence_score": round(confidence * 100, 1),
        "approved_by":      analyst_email,
        "severity":         inc.get("severity"),
        "mitre_ids":        inc.get("mitre_ids") or [],
        "recommendation":   recommendation,
        "timestamp":        now.isoformat(),
    }

    http_status = None
    success = False
    try:
        import requests as _rqs
        resp = _rqs.post(soar_url, json=payload, timeout=10, verify=False)
        http_status = resp.status_code
        success = resp.status_code in (200, 201, 202, 204)
    except Exception as exc:
        _logger.warning("[approve-soar] Node-RED call failed: %s", exc)

    rec = recommendation or {}
    actions_count = (
        len(rec.get("containment", []))
        + len(rec.get("eradication", []))
        + len(rec.get("recovery", []))
    )

    entry = {
        "timestamp":    now.isoformat(),
        "confidence":   round(confidence * 100, 1),
        "actor":        analyst_email,
        "status":       "analyst_dispatched" if success else "dispatch_failed",
        "reason":       f"Analyst-approved dispatch by {analyst_email}",
        "actions_sent": actions_count,
        "http_status":  http_status,
    }

    existing_log = list(inc.get("soar_dispatch_log") or [])
    existing_log.append(entry)

    try:
        import json as _j
        conn = _corr_conn()
        with conn:
            with conn.cursor() as cur:
                if success:
                    cur.execute(
                        "UPDATE incidents SET soar_dispatched=TRUE, soar_dispatched_at=%s, "
                        "soar_dispatch_log=%s WHERE id=%s",
                        [now, _j.dumps(existing_log), incident_id],
                    )
                else:
                    cur.execute(
                        "UPDATE incidents SET soar_dispatch_log=%s WHERE id=%s",
                        [_j.dumps(existing_log), incident_id],
                    )
        conn.close()
    except Exception as exc:
        _logger.warning("[approve-soar] DB update failed: %s", exc)

    return jsonify({
        "ok":          success,
        "dispatch_log": entry,
        "http_status": http_status,
    })


@siem_bp.route("/incidents/<incident_id>/approve-soar", methods=["OPTIONS"])
def siem_incident_approve_soar_options(incident_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


# ── Phase 6: Similar past incidents ───────────────────────────────────────────

@siem_bp.route("/incidents/<incident_id>/similar", methods=["GET"])
@require_siem_auth
def siem_incident_similar(incident_id):
    """Return up to 3 similar past resolved incidents from incident_patterns.

    Matches on technique + kill_chain_stage. Similarity score is computed as
    a weighted Jaccard overlap of payload_indicators. GET → viewer+
    """
    import psycopg2.extras
    try:
        conn = _corr_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Get the incident's technique + kill-chain
            cur.execute(
                "SELECT mitre_ids, kill_chain_stage_name FROM incidents WHERE id = %s",
                [incident_id],
            )
            inc = cur.fetchone()
            if not inc:
                conn.close()
                return jsonify({"similar": []}), 200

            mitre_ids = inc.get("mitre_ids") or []
            kill_chain = inc.get("kill_chain_stage_name") or ""

            # Find patterns with matching technique or kill-chain stage (last 90 days)
            cur.execute("""
                SELECT id, source_incident_id, technique, kill_chain_stage,
                       payload_indicators, response_actions, outcome,
                       confidence_at_resolution, created_at
                FROM incident_patterns
                WHERE (technique = ANY(%s) OR kill_chain_stage = %s)
                  AND source_incident_id != %s
                  AND created_at > NOW() - INTERVAL '90 days'
                ORDER BY created_at DESC
                LIMIT 20
            """, [mitre_ids if mitre_ids else ["__none__"], kill_chain or "__none__", incident_id])
            patterns = cur.fetchall()
        conn.close()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    if not patterns:
        return jsonify({"similar": []}), 200

    # Score: exact technique match = 0.6, exact kill-chain match = 0.4
    scored = []
    for p in patterns:
        score = 0.0
        p_technique = p.get("technique") or ""
        p_kill = p.get("kill_chain_stage") or ""
        if p_technique and p_technique in mitre_ids:
            score += 0.60
        if p_kill and kill_chain and p_kill == kill_chain:
            score += 0.40
        if score > 0.40:  # surface threshold matching the plan's 0.4 filter
            scored.append({
                "pattern_id":               p["id"],
                "source_incident_id":       p["source_incident_id"],
                "technique":                p_technique,
                "kill_chain_stage":         p_kill,
                "similarity":               round(score, 2),
                "outcome":                  p.get("outcome"),
                "confidence_at_resolution": _f(p.get("confidence_at_resolution")),
                "created_at":               _iso(p.get("created_at")),
            })

    # Sort by similarity desc, take top 3
    scored.sort(key=lambda x: x["similarity"], reverse=True)
    return jsonify({"similar": scored[:3]})


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


def _resolve_edr_agent_id(cur, agent_id: str):
    """
    Resolve the agent_id in a /hosts/<agent_id>/* URL to the corresponding
    edr_agents.agent_id, whether the URL id is already an EDR agent's own UUID
    or a Wazuh/SIEM-style id linked via network_assets (Phase 0 crossref).
    Returns None if this host has no EDR agent at all (Wazuh-only/unlinked) —
    callers use that to fall back to the legacy Wazuh/alerts-table path.
    """
    cur.execute("SELECT 1 FROM edr_agents WHERE agent_id = %s", [agent_id])
    if cur.fetchone():
        return agent_id
    cur.execute(
        "SELECT edr_agent_id FROM network_assets "
        "WHERE siem_agent_id = %s AND edr_agent_id IS NOT NULL LIMIT 1",
        [agent_id],
    )
    row = cur.fetchone()
    return row["edr_agent_id"] if row else None


def _inject_case_fields(incidents: list) -> None:
    """Overwrite case_opened_at (and related case columns) in a list of incident
    dicts with values read directly from psycopg2 — the authoritative source.

    The SIEM engine's SQLAlchemy async ORM session can serve stale None values
    for case_opened_at when its in-process connection pool holds an asyncpg
    connection whose transaction snapshot predates the psycopg2 case-open write.
    Bypassing the engine session entirely for these small, case-specific fields
    eliminates that staleness without requiring an engine restart.
    """
    if not incidents:
        return
    ids = [inc.get("id") for inc in incidents if inc.get("id")]
    if not ids:
        return
    try:
        import psycopg2.extras as _pge
        conn = _corr_conn()
        conn.cursor_factory = _pge.RealDictCursor
        cur = conn.cursor()
        cur.execute(
            "SELECT id, case_opened_at, case_type, case_mttd_seconds, "
            "case_mtta_seconds, case_restricted "
            "FROM incidents WHERE id = ANY(%s)",
            [ids],
        )
        case_map = {row["id"]: row for row in cur.fetchall()}
        conn.close()
        for inc in incidents:
            row = case_map.get(inc.get("id"))
            if row is None:
                continue
            inc["case_opened_at"]    = _iso(row["case_opened_at"])
            inc["case_type"]         = row["case_type"]
            inc["case_mttd_seconds"] = row["case_mttd_seconds"]
            inc["case_mtta_seconds"] = row["case_mtta_seconds"]
            inc["case_restricted"]   = row["case_restricted"]
    except Exception:
        pass  # best-effort: SIEM engine response is still valid without overrides


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


def _edr_native_host_overlay(cur, edr_agent_id: str) -> dict:
    """
    Build a Host Security Profile overlay purely from EDR-native tables
    (edr_detections, edr_fim_events, edr_sca_results, and ITAM's
    software_inventory via network_assets). Used both to enrich a host that
    already has a host_posture_cache row (whose Wazuh-derived SCA/vuln/MITRE
    fields may be stale or entirely absent) and to build a full response for
    EDR-only hosts that have no host_posture_cache row at all (see
    _sync_host_detail's fallback branch below).
    """
    overlay = {
        "mitre_breakdown": [], "mitre_techniques": [],
        "sca": None, "vuln_counts": None, "fim_events": 0, "malware_detections": 0,
        "compliance_score": None,
    }

    cur.execute("""
        SELECT mitre_id, mitre_tactic, COUNT(*) AS cnt
        FROM edr_detections
        WHERE agent_id = %s AND mitre_id IS NOT NULL AND mitre_id <> ''
          AND detected_at > NOW() - INTERVAL '30 days'
        GROUP BY mitre_id, mitre_tactic ORDER BY cnt DESC LIMIT 15
    """, [edr_agent_id])
    rows = cur.fetchall()
    overlay["mitre_breakdown"] = [
        {"mitre_id": r["mitre_id"], "tactic": r["mitre_tactic"], "count": int(r["cnt"])}
        for r in rows
    ]
    overlay["mitre_techniques"] = sorted({r["mitre_id"] for r in rows})

    cur.execute(
        "SELECT COUNT(*) AS n FROM edr_fim_events WHERE agent_id = %s "
        "AND detected_at > NOW() - INTERVAL '30 days'",
        [edr_agent_id],
    )
    overlay["fim_events"] = cur.fetchone()["n"]

    cur.execute(
        "SELECT COUNT(*) AS n FROM edr_detections WHERE agent_id = %s "
        "AND event_category = 'malware' AND detected_at > NOW() - INTERVAL '30 days'",
        [edr_agent_id],
    )
    overlay["malware_detections"] = cur.fetchone()["n"]

    cur.execute("""
        SELECT COUNT(*) FILTER (WHERE result = 'passed') AS passed,
               COUNT(*) FILTER (WHERE result = 'failed') AS failed,
               COUNT(*) AS total
        FROM edr_sca_results WHERE agent_id = %s
    """, [edr_agent_id])
    sca_row = cur.fetchone()
    if sca_row and sca_row["total"]:
        _pass, _fail, _tot = int(sca_row["passed"] or 0), int(sca_row["failed"] or 0), int(sca_row["total"] or 0)
        _scored = _pass + _fail
        overlay["sca"] = {
            "passed": _pass, "failed": _fail, "total": _tot,
            "score": round(_pass / _scored * 100, 1) if _scored else None,
        }
        overlay["compliance_score"] = overlay["sca"]["score"]

    cur.execute("SELECT id FROM network_assets WHERE edr_agent_id = %s LIMIT 1", [edr_agent_id])
    na = cur.fetchone()
    if na:
        cur.execute("""
            SELECT elem->>'severity' AS severity, COUNT(*) AS cnt
            FROM software_inventory si, jsonb_array_elements(si.cves) elem
            WHERE si.asset_id = %s
            GROUP BY elem->>'severity'
        """, [na["id"]])
        counts = {r["severity"]: int(r["cnt"]) for r in cur.fetchall()}
        if counts:
            overlay["vuln_counts"] = {
                "critical": counts.get("critical", 0), "high": counts.get("high", 0),
                "medium": counts.get("medium", 0), "low": counts.get("low", 0),
            }

    return overlay


def _sync_host_detail(agent_id):
    import psycopg2.extras
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM host_posture_cache WHERE agent_id = %s", [agent_id])
            host = cur.fetchone()

            edr_agent_id = _resolve_edr_agent_id(cur, agent_id)
            overlay = _edr_native_host_overlay(cur, edr_agent_id) if edr_agent_id else None

            if not host and not edr_agent_id:
                return None
            if not host:
                # EDR-only host with no Wazuh/alerts-derived posture-cache row yet
                # (e.g. never had a host-refresh cycle run) — build a minimal
                # response from edr_agents instead of 404ing the whole panel.
                cur.execute("""
                    SELECT agent_id, hostname, os_type, agent_ip, status, version, last_seen
                    FROM edr_agents WHERE agent_id = %s
                """, [edr_agent_id])
                ea = cur.fetchone() or {}
                host = {
                    "agent_id": ea.get("agent_id", agent_id), "agent_name": ea.get("hostname"),
                    "agent_ip": ea.get("agent_ip"), "os_platform": ea.get("os_type"),
                    "os_version": None, "wazuh_status": ea.get("status"),
                    "last_keepalive": ea.get("last_seen"), "asset_tier": None,
                    "posture_score": None, "posture_grade": None, "score_breakdown": {},
                    "computed_at": None,
                    "sca_passed": None, "sca_failed": None, "sca_total": None, "sca_score": None,
                    "vuln_critical": None, "vuln_high": None, "vuln_medium": None, "vuln_low": None,
                    "vuln_score": None, "siem_risk": None,
                    "fim_event_count": 0, "malware_count": 0, "incident_count": 0,
                    "mitre_techniques": [], "compliance_score": None,
                }

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

            # EDR-native SCA failures take priority over the (likely empty, for
            # EDR-only hosts) Wazuh-shaped alerts query above.
            if overlay is not None:
                cur.execute("""
                    SELECT title, result, rationale, policy_id, scanned_at
                    FROM edr_sca_results WHERE agent_id = %s AND result = 'failed'
                    ORDER BY scanned_at DESC LIMIT 20
                """, [edr_agent_id])
                edr_sca_failures = [{
                    "title": r["title"], "result": r["result"], "rationale": r["rationale"],
                    "policy_id": r["policy_id"], "timestamp": _iso(r["scanned_at"]),
                } for r in cur.fetchall()]
                if edr_sca_failures:
                    sca_failures = edr_sca_failures

            # ── Blend EDR-native overlay into the Wazuh/alerts-shaped fields ──
            if overlay and overlay["mitre_breakdown"]:
                combined = {}
                for m in mitre_breakdown + overlay["mitre_breakdown"]:
                    key = (m["mitre_id"], m["tactic"])
                    combined[key] = combined.get(key, 0) + m["count"]
                mitre_breakdown = sorted(
                    ({"mitre_id": k[0], "tactic": k[1], "count": v} for k, v in combined.items()),
                    key=lambda m: -m["count"],
                )[:15]
            mitre_techniques = sorted(set((host["mitre_techniques"] or []) +
                                          (overlay["mitre_techniques"] if overlay else [])))

            if overlay and overlay["sca"]:
                sca_block = {**overlay["sca"], "recent_failures": sca_failures}
            else:
                sca_block = {
                    "passed": host["sca_passed"], "failed": host["sca_failed"],
                    "total": host["sca_total"], "score": _f(host["sca_score"]),
                    "recent_failures": sca_failures,
                }

            if overlay and overlay["vuln_counts"]:
                vuln_block = {**overlay["vuln_counts"], "score": _f(host["vuln_score"])}
            else:
                vuln_block = {
                    "critical": host["vuln_critical"], "high": host["vuln_high"],
                    "medium": host["vuln_medium"], "low": host["vuln_low"],
                    "score": _f(host["vuln_score"]),
                }

            fim_events = (overlay["fim_events"] if overlay and overlay["fim_events"]
                          else host["fim_event_count"])
            malware_detections = (overlay["malware_detections"] if overlay and overlay["malware_detections"]
                                   else host["malware_count"])
            compliance_score = (overlay["compliance_score"] if (overlay and overlay["compliance_score"] is not None)
                                 else _f(host["compliance_score"]))

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
                "sca": sca_block,
                "vulnerabilities": vuln_block,
                "siem": {
                    "risk_score": _f(host["siem_risk"]),
                    "fim_events": fim_events,
                    "malware_detections": malware_detections,
                    "active_incidents": active_incidents,
                    "incident_count": host["incident_count"],
                },
                "mitre": {
                    "techniques": mitre_techniques,
                    "breakdown": mitre_breakdown,
                },
                "compliance": {
                    "score": compliance_score,
                    "sca_failures": len(sca_failures),
                },
                "alerts_by_category": alerts_by_category,
                "source": "edr_native" if overlay else "wazuh",
            }
    finally:
        conn.close()


def _edr_native_alerts(cur, edr_agent_id: str, category: str, page: int, per_page: int, offset: int):
    """
    EDR-native source for the FIM and Malware tabs — edr_fim_events (Phase 2)
    and edr_detections (Phase 5 malware rollup) respectively. Column aliases
    exactly match _sync_host_alerts()'s legacy-path SELECT so both paths feed
    the same row-mapping code below. Returns None (not an empty result) if the
    EDR-native table has zero rows for this agent, so the caller can fall back
    to the legacy alerts-table path instead of showing a false "no events".
    """
    if category == "fim":
        cur.execute(
            "SELECT COUNT(*) AS n FROM edr_fim_events WHERE agent_id = %s", [edr_agent_id]
        )
        if cur.fetchone()["n"] == 0:
            return None
        cur.execute("""
            SELECT id, detected_at AS timestamp, NULL::int AS rule_id,
                   (INITCAP(event_type) || ': ' || path) AS rule_desc,
                   CASE severity WHEN 'critical' THEN 15 WHEN 'high' THEN 12
                                 WHEN 'medium' THEN 7 ELSE 3 END AS rule_level,
                   'fim' AS category, NULL::text AS mitre_id, NULL::text AS mitre_tactic,
                   NULL::numeric AS base_score, NULL::text AS src_ip,
                   owner AS username, path AS file_path, NULL::text AS incident_id,
                   CASE WHEN old_sha256 IS NOT NULL OR new_sha256 IS NOT NULL
                        THEN 'sha256: ' || COALESCE(old_sha256, '—') || ' -> ' || COALESCE(new_sha256, '—')
                        ELSE NULL END AS full_log,
                   event_type AS rule_description
            FROM edr_fim_events
            WHERE agent_id = %s
            ORDER BY detected_at DESC LIMIT %s OFFSET %s
        """, [edr_agent_id, per_page, offset])
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) AS n FROM edr_fim_events WHERE agent_id = %s", [edr_agent_id])
        total = cur.fetchone()["n"]
        return rows, total

    if category == "malware":
        cur.execute(
            "SELECT COUNT(*) AS n FROM edr_detections WHERE agent_id = %s AND event_category = 'malware'",
            [edr_agent_id],
        )
        if cur.fetchone()["n"] == 0:
            return None
        cur.execute("""
            SELECT id, detected_at AS timestamp, rule_id, rule_desc,
                   CASE severity WHEN 'critical' THEN 15 WHEN 'high' THEN 12
                                 WHEN 'medium' THEN 7 ELSE 3 END AS rule_level,
                   'malware' AS category, mitre_id, mitre_tactic,
                   score AS base_score, src_ip, username, file_path,
                   case_id AS incident_id,
                   command_line AS full_log,
                   process_name AS rule_description
            FROM edr_detections
            WHERE agent_id = %s AND event_category = 'malware'
            ORDER BY detected_at DESC LIMIT %s OFFSET %s
        """, [edr_agent_id, per_page, offset])
        rows = cur.fetchall()
        cur.execute(
            "SELECT COUNT(*) AS n FROM edr_detections WHERE agent_id = %s AND event_category = 'malware'",
            [edr_agent_id],
        )
        total = cur.fetchone()["n"]
        return rows, total

    return None


def _sync_host_alerts(agent_id, category, page, per_page):
    import psycopg2.extras
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            offset = (page - 1) * per_page

            if category in ("fim", "malware"):
                edr_agent_id = _resolve_edr_agent_id(cur, agent_id)
                edr_result = _edr_native_alerts(cur, edr_agent_id, category, page, per_page, offset) \
                    if edr_agent_id else None
                if edr_result is not None:
                    rows, total = edr_result
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
                        "source": "edr_native",
                    }

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
            # correlated_rules is JSONB stored as [{rule_id: "HT-001", ...}, ...]
            # categories ARRAY tags hunt incidents as 'hunt_finding' (no incident_type column)
            cur.execute("""
                SELECT correlated_rules->0->>'rule_id' AS rule_id,
                       COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE status NOT IN ('closed','false_positive')) AS open
                FROM incidents
                WHERE 'hunt_finding' = ANY(categories)
                GROUP BY correlated_rules->0->>'rule_id'
            """)
            counts = {r["rule_id"]: {"total": r["total"], "open": r["open"]}
                      for r in cur.fetchall() if r["rule_id"]}
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

    Builds the host list from edr_agents + collector_agents (CyEDR/CyCollector's
    own agent registries) plus a 90-day alerts-table scan as a fallback for any
    agent_id neither table knows about (e.g. a connector-sourced entity), then
    computes the 5-component posture score for each and upserts the results
    directly into host_posture_cache via psycopg2.

    No live Wazuh Manager API call anywhere in this function (CyDataLake
    migration): SCA comes from edr_sca_results (the agent's own ScaScanner
    thread), vulnerabilities from ITAM's software_inventory (per-CVE severity
    via network_assets), and the master host list from CyEDR/CyCollector's own
    registries — agent enrollment/connection state is Wazuh Manager-side state
    with no Kafka/data-lake equivalent, so it has to come from an agent
    registry table, not an alert stream. See docs/SIEM_PROXY_AUDIT.md.
    """
    import psycopg2.extras

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
                    "ALTER TABLE host_posture_cache ADD COLUMN IF NOT EXISTS primary_mac TEXT",
                ]:
                    cur.execute(_col_sql)
    finally:
        conn.close()

    # ── Build unified agent list: CyEDR + CyCollector registries first (their
    # own hardware_uuid dedup already ran at enrollment time), then a 90-day
    # alerts-table scan as a fallback for any agent_id neither table knows
    # about (e.g. a connector-sourced entity with no agent registry of its own).
    _STALE_AFTER = timedelta(minutes=5)

    def _liveness(last_seen):
        if not last_seen:
            return "never_connected"
        try:
            now = datetime.now(timezone.utc)
            ls = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
            return "active" if (now - ls) < _STALE_AFTER else "disconnected"
        except Exception:
            return "unknown"

    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT agent_id, hostname, agent_ip, os_type, version, last_seen
                FROM edr_agents WHERE status <> 'removed'
            """)
            edr_rows = cur.fetchall()
            cur.execute("""
                SELECT agent_id, hostname, agent_ip, os_type, version, last_seen
                FROM collector_agents WHERE status <> 'removed'
            """)
            collector_rows = cur.fetchall()
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
    for a in list(edr_rows) + list(collector_rows):
        all_agents[a["agent_id"]] = {
            "id": a["agent_id"], "name": a["hostname"] or a["agent_id"],
            "ip": a["agent_ip"], "status": _liveness(a["last_seen"]),
            "os_platform": a["os_type"], "os_version": None,
            "last_keepalive": a["last_seen"].isoformat() if a["last_seen"] else None,
        }

    # ── Hostname-stem dedup: same physical host re-enrolled under a new name ──
    # (roaming laptops, hostname changes across networks). CyEDR/CyCollector
    # already dedupe by hardware_uuid at enrollment time, so this only remains
    # a safety net for alerts-table-only ghost entries with no registry row.
    _STEM_RE = re.compile(
        r"\.(lan|local|home|internal|localdomain|corp|office|intranet|priv)$", re.I
    )

    def _hostname_stem(name: str) -> str:
        return _STEM_RE.sub("", name.lower()).strip()

    def _ka(aid):
        return all_agents[aid].get("last_keepalive") or ""

    _stem_seen: dict[str, str] = {}  # (stem|platform) → winning agent_id
    _stem_deduped: dict = {}
    for _aid, _info in all_agents.items():
        _plat = (_info.get("os_platform") or "").lower()
        _stem = _hostname_stem(_info.get("name") or _aid)
        _sk   = f"{_stem}|{_plat}"
        if not _plat:
            # Cannot safely stem-dedup without OS platform — keep as-is
            _stem_deduped[_aid] = _info
            continue
        if _sk not in _stem_seen:
            _stem_seen[_sk] = _aid
            _stem_deduped[_aid] = _info
        else:
            _prev_aid = _stem_seen[_sk]
            if _ka(_aid) > _ka(_prev_aid):
                _logger.info(
                    "[host-refresh] stem dedup: %s (%s) supersedes %s (%s) — stem '%s'",
                    _aid, _info.get("name"), _prev_aid, all_agents[_prev_aid].get("name"), _stem,
                )
                del _stem_deduped[_prev_aid]
                _stem_seen[_sk] = _aid
                _stem_deduped[_aid] = _info
            # else: existing entry is newer; discard this one silently
    all_agents = _stem_deduped

    if not all_agents:
        _logger.warning("[host-refresh] no agents found (edr=%d, collector=%d, db=%d)",
                        len(edr_rows), len(collector_rows), len(db_agents))
        return 0

    # ── Per-agent posture compute + upsert ────────────────────────────────────
    refreshed = 0
    for agent_id, info in all_agents.items():
        try:
            conn = _corr_conn()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

                    # Component 1 — SCA pass rate (30%), EDR-native first
                    # (the agent's own ScaScanner thread — see edr_sca_results)
                    cur.execute("""
                        SELECT COUNT(*) FILTER (WHERE result = 'passed') AS passed,
                               COUNT(*) FILTER (WHERE result = 'failed') AS failed
                        FROM edr_sca_results WHERE agent_id = %s
                    """, [agent_id])
                    row = cur.fetchone()
                    sca_passed = int(row["passed"] or 0) if row else 0
                    sca_failed = int(row["failed"] or 0) if row else 0
                    sca_total  = sca_passed + sca_failed
                    sca_score  = round(sca_passed / sca_total * 100, 1) if sca_total else None

                    if sca_total == 0:
                        # Fall back to historical SCA alerts (older
                        # Wazuh-connector-sourced events retained in `alerts`).
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

                    # Component 2 — Vulnerability severity (25%), ITAM-native
                    # (software_inventory's per-CVE severity, joined via the
                    # network_assets row CyEDR's InventoryReporter maintains)
                    vuln_critical = vuln_high = vuln_medium = vuln_low = 0
                    vuln_score = None
                    cur.execute("""
                        SELECT elem->>'severity' AS severity, COUNT(*) AS cnt
                        FROM network_assets na
                        JOIN software_inventory si ON si.asset_id = na.id
                        CROSS JOIN LATERAL jsonb_array_elements(si.cves) elem
                        WHERE na.edr_agent_id = %s
                        GROUP BY elem->>'severity'
                    """, [agent_id])
                    for r in cur.fetchall():
                        sev = (r["severity"] or "").lower()
                        n = int(r["cnt"])
                        if sev == "critical":   vuln_critical = n
                        elif sev == "high":     vuln_high     = n
                        elif sev == "medium":   vuln_medium   = n
                        elif sev == "low":      vuln_low      = n
                    if vuln_critical + vuln_high + vuln_medium + vuln_low > 0:
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

                    # Upsert — primary_mac is no longer collected (no live
                    # syscollector data); COALESCE below preserves any value a
                    # prior run already had rather than clobbering it with NULL.
                    _primary_mac = None
                    cur.execute("""
                        INSERT INTO host_posture_cache (
                            agent_id, agent_name, agent_ip, os_platform, os_version,
                            wazuh_status, last_keepalive,
                            posture_score, posture_grade,
                            sca_score, sca_passed, sca_failed, sca_total,
                            vuln_score, vuln_critical, vuln_high, vuln_medium, vuln_low,
                            siem_risk, fim_event_count, malware_count, incident_count,
                            compliance_score, mitre_techniques, score_breakdown,
                            primary_mac, computed_at
                        ) VALUES (
                            %s,%s,%s,%s,%s,
                            %s,%s,
                            %s,%s,
                            %s,%s,%s,%s,
                            %s,%s,%s,%s,%s,
                            %s,%s,%s,%s,
                            %s,%s,%s::jsonb,
                            %s,NOW()
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
                            primary_mac      = COALESCE(EXCLUDED.primary_mac, host_posture_cache.primary_mac),
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
                        _primary_mac,
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


@siem_bp.route("/hosts/<agent_id>", methods=["OPTIONS"])
def siem_host_options(agent_id):
    from core.helpers import add_cors_headers
    return add_cors_headers(make_response('', 204))


@siem_bp.route("/hosts/<agent_id>", methods=["DELETE"])
@require_siem_admin
def siem_host_delete(agent_id):
    """
    Remove a host: soft-deletes the underlying CyEDR/CyCollector agent record
    (status='removed', so it drops out of the next _refresh_host_cache_sync()
    build and won't reappear) and purges its host_posture_cache row.

    No Wazuh Manager call — hosts are sourced from edr_agents/collector_agents
    now, not a Wazuh agent registry (see docs/SIEM_PROXY_AUDIT.md). A hard
    DELETE on the agent row is deliberately avoided: edr_detections and other
    tables carry a NOT NULL FK to edr_agents.agent_id, so removal is a status
    flag, not a row delete.

    Refuses to delete agent 000 (reserved id). Admin-only — permanent action.
    """
    if agent_id == "000":
        return jsonify({"error": "Cannot delete reserved agent id 000"}), 400

    errors = []
    try:
        conn = _corr_conn()
        with conn.cursor() as cur:
            cur.execute("UPDATE edr_agents SET status = 'removed' WHERE agent_id = %s", [agent_id])
            edr_hit = cur.rowcount
            cur.execute("UPDATE collector_agents SET status = 'removed' WHERE agent_id = %s", [agent_id])
            collector_hit = cur.rowcount
            cur.execute("DELETE FROM host_posture_cache WHERE agent_id = %s", [agent_id])
            cache_hit = cur.rowcount
        conn.commit()
        conn.close()
        if not (edr_hit or collector_hit or cache_hit):
            return jsonify({"error": "Host not found"}), 404
    except Exception as exc:
        errors.append(f"Removal failed: {exc}")

    if errors:
        return jsonify({"status": "partial", "errors": errors, "agent_id": agent_id}), 207
    return jsonify({"status": "deleted", "agent_id": agent_id})


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


def _edr_itam_inventory(agent_id: str, pkg_limit: int) -> dict | None:
    """
    EDR/ITAM-first inventory lookup for the Host Security Profile Inventory tab.

    CyEDR's InventoryReporter (agent-side) self-reports into ITAM's
    network_assets/software_inventory tables (see POST /api/edr/inventory in
    blueprints/edr/routes.py) — this reads that data back out in the exact
    response shape HostDetailPanel.jsx's InventoryTab already expects, so the
    tab works without any Wazuh dependency. `agent_id` may be either an EDR
    agent's own UUID or a Wazuh/SIEM-style agent_id — network_assets carries
    both edr_agent_id and siem_agent_id (linked via _crossref_agents_conn),
    so either one resolves to the same row.

    Returns None if no linked network_assets row exists yet (e.g. the agent
    hasn't completed its first inventory cycle) — caller falls back to the
    legacy Wazuh/posture-cache path.
    """
    import psycopg2.extras
    try:
        conn = _corr_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, hostname, ip_address::text AS ip, os_info, hardware_info,
                       last_deep_scan, edr_agent_id, siem_agent_id,
                       software_count, vuln_count, highest_cve_severity
                FROM network_assets
                WHERE edr_agent_id = %s OR siem_agent_id = %s
                LIMIT 1
            """, [agent_id, agent_id])
            na = cur.fetchone()
            if not na:
                conn.close()
                return None

            ea = {}
            if na["edr_agent_id"]:
                cur.execute("""
                    SELECT agent_id, hostname, os_type, agent_ip, status, version,
                           enrolled_at, last_seen
                    FROM edr_agents WHERE agent_id = %s
                """, [na["edr_agent_id"]])
                ea = cur.fetchone() or {}

            cur.execute("""
                SELECT name, version, vendor, package_manager, architecture,
                       cve_count, highest_severity
                FROM software_inventory WHERE asset_id = %s
                ORDER BY cve_count DESC, name ASC
                LIMIT %s
            """, [na["id"], pkg_limit])
            pkgs = cur.fetchall() or []
            cur.execute(
                "SELECT COUNT(*) AS n FROM software_inventory WHERE asset_id = %s", [na["id"]]
            )
            pkg_total = (cur.fetchone() or {}).get("n", 0)
        conn.close()
    except Exception as exc:
        _logger.debug("EDR/ITAM inventory lookup failed for %s: %s", agent_id, exc)
        return None

    os_info = na["os_info"] or {}
    hw      = na["hardware_info"] or {}

    return {
        "agent": {
            "id":             na["edr_agent_id"] or agent_id,
            "name":           ea.get("hostname") or na["hostname"],
            "ip":             na["ip"] or ea.get("agent_ip"),
            "status":         ea.get("status") or ("active" if na["last_deep_scan"] else "unknown"),
            "os_platform":    ea.get("os_type") or os_info.get("platform"),
            "os_version":     os_info.get("release") or os_info.get("name"),
            "version":        ea.get("version"),
            "date_add":       _iso(ea.get("enrolled_at")),
            "last_keepalive": _iso(ea.get("last_seen")) or _iso(na["last_deep_scan"]),
            "hostname":       na["hostname"] or ea.get("hostname"),
        },
        "os": {
            "hostname":       na["hostname"],
            "architecture":   os_info.get("architecture"),
            "kernel_release": os_info.get("kernel"),
            "sysname":        os_info.get("platform"),
            "os_name":        os_info.get("name"),
            "os_codename":    None,
            "os_major":       None,
            "os_minor":       None,
            "scan_time":      _iso(na["last_deep_scan"]),
        },
        "hardware": {
            "cpu_name":  hw.get("cpu_model"),
            "cpu_cores": hw.get("cpu_count"),
            "cpu_mhz":   hw.get("cpu_freq_mhz"),
            "ram_total": (hw["memory_total_bytes"] // 1024) if hw.get("memory_total_bytes") else None,
            "ram_free":  (hw["memory_available_bytes"] // 1024) if hw.get("memory_available_bytes") else None,
            "ram_usage": hw.get("memory_percent"),
        },
        "packages": [{
            "name":              p["name"],
            "version":           p["version"],
            "description":       None,
            "architecture":      p["architecture"],
            "size":              None,
            "section":           None,
            "vendor":            p["vendor"],
            "format":            p["package_manager"],
            "install_time":      None,
            "cve_count":         p["cve_count"],
            "highest_severity":  p["highest_severity"],
        } for p in pkgs],
        "packages_total": pkg_total,
        "source": "edr_itam",
        "vuln_summary": {
            "count":             na["vuln_count"],
            "highest_severity":  na["highest_cve_severity"],
        },
    }


@siem_bp.route("/hosts/<agent_id>/inventory", methods=["GET"])
@require_siem_auth
def siem_host_inventory(agent_id):
    """System inventory: agent identity, hardware, OS details, and installed packages.

    Sourced entirely from CyEDR/ITAM (network_assets + software_inventory) — no
    Wazuh Manager API dependency. Hosts without a CyEDR agent reporting into
    ITAM yet will return the empty shape below until CyEDR is deployed on them.
    """
    pkg_limit_arg = request.args.get("pkg_limit", "100")
    try:
        pkg_limit = min(500, max(5, int(pkg_limit_arg)))
    except ValueError:
        pkg_limit = 100

    edr_result = _edr_itam_inventory(agent_id, pkg_limit)
    if edr_result is not None:
        return jsonify(edr_result)

    return jsonify({
        "agent": None, "os": None, "hardware": None,
        "packages": [], "packages_total": 0,
    })


def _edr_itam_vulnerabilities(agent_id: str, page: int, per_page: int, severity: str):
    """
    EDR/ITAM-native vulnerability data (Host Security Profile — Vulnerabilities,
    Phase 4), sourced from ITAM's software_inventory.cves — already NVD/KEV
    CVE-matched (blueprints/itam/software_inventory.py: enrich_asset_cves()),
    populated for free once CyEDR's InventoryReporter starts reporting
    software (Phase 1). No network scanning required — inventory-based
    detection, per the spec this feature was built against.

    Returns None if no linked network_assets row / no CVE data exists yet, so
    the caller falls back to the legacy Wazuh-vulnerability-detector path.
    """
    import psycopg2.extras
    offset = (page - 1) * per_page
    sev_lower = (severity or "").strip().lower()
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id FROM network_assets
                WHERE edr_agent_id = %s OR siem_agent_id = %s
                LIMIT 1
            """, [agent_id, agent_id])
            na = cur.fetchone()
            if not na:
                return None
            asset_id = na["id"]

            sev_clause = "AND (elem->>'severity') = %s" if sev_lower else ""
            params = [asset_id] + ([sev_lower] if sev_lower else [])

            cur.execute(f"""
                SELECT COUNT(*) AS n
                FROM software_inventory si, jsonb_array_elements(si.cves) elem
                WHERE si.asset_id = %s AND si.cve_count > 0 {sev_clause}
            """, params)
            total = cur.fetchone()["n"]
            if total == 0:
                return None

            cur.execute(f"""
                SELECT si.name, si.version, si.architecture, si.last_scanned,
                       elem->>'cve_id' AS cve, elem->>'severity' AS severity,
                       (elem->>'score')::numeric AS cvss, elem->>'description' AS description
                FROM software_inventory si, jsonb_array_elements(si.cves) elem
                WHERE si.asset_id = %s AND si.cve_count > 0 {sev_clause}
                ORDER BY (elem->>'score')::numeric DESC NULLS LAST
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = cur.fetchall()
    finally:
        conn.close()

    vulns = [{
        "cve":          r["cve"],
        "severity":     r["severity"],
        "cvss":         _f(r["cvss"]),
        "name":         r["name"],
        "version":      r["version"],
        "architecture": r["architecture"],
        "title":        r["description"],
        "condition":    r["description"],
        "status":       None,
        "references":   None,
        "published":    None,
        "detected_at":  _iso(r["last_scanned"]),
    } for r in rows]

    return {
        "vulnerabilities": vulns,
        "total": total,
        "page": page, "per_page": per_page,
        "source": "edr_itam",
    }


@siem_bp.route("/hosts/<agent_id>/vulnerabilities", methods=["GET"])
@require_siem_auth
def siem_host_vulnerabilities(agent_id):
    """Return CVE data for a host.

    EDR/ITAM-native path (software_inventory.cves) is tried first; falls back
    to the legacy correlation DB path (full_alert JSONB, populated by
    cysiem-to-redis from Wazuh vulnerability-detector events) if this host has
    no linked network_assets row or no CVE data yet.
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
        edr_itam_result = _edr_itam_vulnerabilities(agent_id, page, per_page, severity)
        if edr_itam_result is not None:
            return jsonify(edr_itam_result)
    except Exception as exc:
        _logger.debug("EDR/ITAM vulnerability lookup failed for %s: %s", agent_id, exc)

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


def _sca_from_alerts_db(agent_id, result_filter, page, per_page, offset):
    """Return SCA check data sourced from the alerts table.

    Called when the Wazuh API returns no SCA policies for an agent_id — typically
    because the agent re-enrolled under a new ID and the old one is disconnected.
    Constructs a compatible response so the SCA tab renders historical data.
    """
    import psycopg2.extras
    try:
        conn = _corr_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                result_clause = "AND full_alert->'data'->'sca'->'check'->>'result' = %s" if result_filter else ""
                base_params   = [agent_id] + ([result_filter] if result_filter else [])

                cur.execute(f"""
                    SELECT COUNT(*) AS n FROM alerts
                    WHERE agent_id = %s AND category = 'sca'
                      AND full_alert->'data'->'sca'->'check'->>'result' IS NOT NULL
                      AND timestamp > NOW() - INTERVAL '30 days'
                      {result_clause}
                """, base_params)
                total = cur.fetchone()["n"]

                cur.execute(f"""
                    SELECT DISTINCT ON (
                        full_alert->'data'->'sca'->'check'->>'id',
                        full_alert->'data'->'sca'->>'policy_id'
                    )
                        (full_alert->'data'->'sca'->'check'->>'id')::INTEGER  AS id,
                        full_alert->'data'->'sca'->'check'->>'title'          AS title,
                        full_alert->'data'->'sca'->'check'->>'result'         AS result,
                        full_alert->'data'->'sca'->'check'->>'rationale'      AS rationale,
                        full_alert->'data'->'sca'->'check'->>'remediation'    AS remediation,
                        full_alert->'data'->'sca'->'check'->>'description'    AS description,
                        full_alert->'data'->'sca'->>'policy_id'               AS policy_id,
                        full_alert->'data'->'sca'->>'policy'                  AS policy_name,
                        timestamp
                    FROM alerts
                    WHERE agent_id = %s AND category = 'sca'
                      AND full_alert->'data'->'sca'->'check'->>'result' IS NOT NULL
                      AND timestamp > NOW() - INTERVAL '30 days'
                      {result_clause}
                    ORDER BY
                        full_alert->'data'->'sca'->'check'->>'id',
                        full_alert->'data'->'sca'->>'policy_id',
                        timestamp DESC
                    LIMIT %s OFFSET %s
                """, base_params + [per_page, offset])
                rows = cur.fetchall()

                # Synthesise a policy summary from the same window
                cur.execute("""
                    SELECT
                        full_alert->'data'->'sca'->>'policy_id' AS policy_id,
                        full_alert->'data'->'sca'->>'policy'    AS policy_name,
                        COUNT(*) FILTER (WHERE full_alert->'data'->'sca'->'check'->>'result' = 'passed') AS passed,
                        COUNT(*) FILTER (WHERE full_alert->'data'->'sca'->'check'->>'result' = 'failed') AS failed
                    FROM alerts
                    WHERE agent_id = %s AND category = 'sca'
                      AND timestamp > NOW() - INTERVAL '30 days'
                    GROUP BY 1, 2
                """, [agent_id])
                policy_rows = cur.fetchall()
        finally:
            conn.close()

        policies = []
        for p in policy_rows:
            if not p["policy_id"]:
                continue
            _pass = int(p["passed"] or 0)
            _fail = int(p["failed"] or 0)
            _tot  = _pass + _fail
            policies.append({
                "policy_id": p["policy_id"],
                "name":      p["policy_name"] or p["policy_id"],
                "pass":      _pass, "fail": _fail, "error": 0,
                "score":     round(_pass / _tot * 100) if _tot else 0,
            })

        checks = [{
            "id":          r["id"],
            "title":       r["title"],
            "result":      r["result"],
            "rationale":   r["rationale"],
            "remediation": r["remediation"],
            "description": r["description"],
            "policy_id":   r["policy_id"],
        } for r in rows if r["id"] is not None]

        return jsonify({
            "policies":  policies,
            "policy_id": policies[0]["policy_id"] if policies else None,
            "checks":    checks,
            "total":     total,
            "page": page, "per_page": per_page,
            "source": "alerts_db",
        })
    except Exception as exc:
        return jsonify({"checks": [], "policies": [], "total": 0,
                        "source": "alerts_db", "error": str(exc)})


def _edr_sca(edr_agent_id: str, result_filter: str, page: int, per_page: int, offset: int):
    """
    EDR-native SCA/CIS data (Host Security Profile — SCA, Phase 3), sourced
    from edr_sca_results (populated by the agent's ScaScanner thread — see
    POST /api/edr/sca/results). Returns None if this agent has no SCA rows
    yet, so the caller falls back to the legacy Wazuh/alerts_db path.

    The frontend's filter buttons send result="not applicable" (a literal
    space, matching Wazuh's own convention) while this table stores
    "not_applicable" (underscore) — normalise both directions at the edges.
    """
    import psycopg2.extras
    norm_filter = (result_filter or "").replace(" ", "_")
    conn = _corr_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            result_clause = "AND result = %s" if norm_filter and norm_filter != "all" else ""
            params = [edr_agent_id] + ([norm_filter] if (norm_filter and norm_filter != "all") else [])

            cur.execute(f"SELECT COUNT(*) AS n FROM edr_sca_results WHERE agent_id = %s {result_clause}", params)
            total = cur.fetchone()["n"]
            if total == 0:
                return None

            cur.execute(f"""
                SELECT check_id, title, result, rationale, remediation, description, policy_id
                FROM edr_sca_results
                WHERE agent_id = %s {result_clause}
                ORDER BY
                    CASE result WHEN 'failed' THEN 1 WHEN 'passed' THEN 2 ELSE 3 END,
                    CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                                  WHEN 'medium' THEN 3 ELSE 4 END,
                    check_id
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = cur.fetchall()

            cur.execute("""
                SELECT policy_id, policy_name,
                       COUNT(*) FILTER (WHERE result = 'passed') AS passed,
                       COUNT(*) FILTER (WHERE result = 'failed') AS failed,
                       COUNT(*) FILTER (WHERE result = 'not_applicable') AS na
                FROM edr_sca_results WHERE agent_id = %s
                GROUP BY policy_id, policy_name
            """, [edr_agent_id])
            policy_rows = cur.fetchall()
    finally:
        conn.close()

    policies = []
    for p in policy_rows:
        _pass, _fail, _na = int(p["passed"] or 0), int(p["failed"] or 0), int(p["na"] or 0)
        _tot = _pass + _fail
        policies.append({
            "policy_id": p["policy_id"], "name": p["policy_name"] or p["policy_id"],
            "pass": _pass, "fail": _fail, "error": _na,
            "score": round(_pass / _tot * 100) if _tot else 0,
        })

    checks = [{
        "id":          r["check_id"],
        "title":       r["title"],
        "result":      "not applicable" if r["result"] == "not_applicable" else r["result"],
        "rationale":   r["rationale"],
        "remediation": r["remediation"],
        "description": r["description"],
        "policy_id":   r["policy_id"],
    } for r in rows]

    return {
        "policies": policies,
        "policy_id": policies[0]["policy_id"] if policies else None,
        "checks": checks, "total": total,
        "page": page, "per_page": per_page,
        "source": "edr_native",
    }


@siem_bp.route("/hosts/<agent_id>/sca", methods=["GET"])
@require_siem_auth
def siem_host_sca(agent_id):
    import psycopg2.extras
    policy_id     = request.args.get("policy_id", "")
    result_filter = request.args.get("result", "")
    try:
        page     = max(1, int(request.args.get("page",      1)))
        per_page = min(500, max(1, int(request.args.get("per_page", 100))))
        offset   = (page - 1) * per_page
    except ValueError:
        page, per_page, offset = 1, 100, 0

    try:
        _conn = _corr_conn()
        with _conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as _cur:
            _edr_agent_id = _resolve_edr_agent_id(_cur, agent_id)
        _conn.close()
        if _edr_agent_id:
            _edr_result = _edr_sca(_edr_agent_id, result_filter, page, per_page, offset)
            if _edr_result is not None:
                return jsonify(_edr_result)
    except Exception as exc:
        _logger.debug("EDR-native SCA lookup failed for %s: %s", agent_id, exc)

    # No EDR-native SCA data (agent hasn't completed a scan cycle yet, or is a
    # historical connector-sourced entity) — fall back to whatever SCA-shaped
    # events already landed in the alerts table. No live Wazuh Manager call —
    # see docs/SIEM_PROXY_AUDIT.md.
    return _sca_from_alerts_db(agent_id, result_filter, page, per_page, offset)


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


def _cytim_lookup_iocs(iocs: list[str]) -> list[dict]:
    """Look up IOCs via CyTIM. Returns list of hit dicts (may be empty)."""
    if not iocs:
        return []
    from core.helpers import get_threat_intel_client
    client = get_threat_intel_client()
    if not client:
        return []
    ioc_list = [{"type": "ip", "value": ioc} for ioc in iocs]
    results = client.bulk_enrich(ioc_list)
    hits = []
    if isinstance(results, dict):
        for key, result in results.items():
            if result and result.get("score", 0) > 0:
                hits.append({
                    "ioc":     result.get("value", key),
                    "type":    result.get("type", "ip"),
                    "score":   result.get("score", 0),
                    "verdict": result.get("verdict", "unknown"),
                    "tags":    result.get("tags", []),
                })
    return hits


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
    AI + Threat Intel enrichment for a single host posture item.

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
        "ti_hits": [...],
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

    # CyTIM lookup for IOCs found in the item
    ti_hits = _cytim_lookup_iocs(iocs[:3])

    return jsonify({
        "explanation":    explanation,
        "remediation":    remediation,
        "ti_hits":        ti_hits,
        "misp_hits":      ti_hits,   # backward compat alias for frontend
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
    import psycopg2.extras
    limit  = min(int(request.args.get("limit",  100)), 500)
    offset = int(request.args.get("offset", 0))
    status = request.args.get("status")
    try:
        conn = _corr_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                wheres = ["'hunt_finding' = ANY(categories)"]
                params: list = []
                if status:
                    wheres.append("status = %s")
                    params.append(status)
                where_sql = " AND ".join(wheres)
                cur.execute(f"SELECT COUNT(*) AS total FROM incidents WHERE {where_sql}", params)
                total = cur.fetchone()["total"] or 0
                cur.execute(
                    f"SELECT id, status, severity, first_seen, last_seen, "
                    f"       affected_agents, affected_agent_names, affected_users, "
                    f"       categories, mitre_ids, correlated_rules, llm_summary, "
                    f"       fp_probability, risk_score "
                    f"FROM incidents WHERE {where_sql} "
                    f"ORDER BY first_seen DESC LIMIT %s OFFSET %s",
                    params + [limit, offset],
                )
                rows = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()
        return jsonify({"total": total, "incidents": rows})
    except Exception as exc:
        _logger.exception("siem_threat_hunt_findings error")
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/threat-hunting/run", methods=["POST"])
@require_siem_admin
def siem_threat_hunt_run():
    try:
        _run_hunts_background()
        return jsonify({"status": "hunt_queued",
                        "message": "Threat hunt running in background"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/threat-hunting/summary", methods=["GET"])
@require_siem_auth
def siem_threat_hunt_summary():
    """Aggregate stats for the Threat Hunting dashboard tile."""
    try:
        import psycopg2.extras
        from datetime import timedelta

        rules = _sync_hunt_rules()

        conn = _corr_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Total hunt_finding incidents (any status)
                cur.execute("""
                    SELECT COUNT(*) AS total
                    FROM incidents
                    WHERE 'hunt_finding' = ANY(categories)
                """)
                findings_total = cur.fetchone()["total"] or 0

                # Open hunt_finding incidents
                cur.execute("""
                    SELECT COUNT(*) AS open
                    FROM incidents
                    WHERE 'hunt_finding' = ANY(categories)
                      AND status NOT IN ('closed', 'false_positive')
                """)
                findings_open = cur.fetchone()["open"] or 0

                # Critical + high open hunt_finding incidents
                cur.execute("""
                    SELECT COUNT(*) AS crit_high
                    FROM incidents
                    WHERE 'hunt_finding' = ANY(categories)
                      AND status NOT IN ('closed', 'false_positive')
                      AND severity IN ('critical', 'high')
                """)
                findings_critical_high = cur.fetchone()["crit_high"] or 0

                # Open hunt_finding incidents created in last 24 h
                cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
                cur.execute("""
                    SELECT COUNT(*) AS last_24h
                    FROM incidents
                    WHERE 'hunt_finding' = ANY(categories)
                      AND status NOT IN ('closed', 'false_positive')
                      AND first_seen >= %s
                """, [cutoff])
                findings_last_24h = cur.fetchone()["last_24h"] or 0
        finally:
            conn.close()

        rules_with_open = sum(1 for r in rules if (r.get("open_findings") or 0) > 0)
        top_rules = sorted(
            [r for r in rules if (r.get("open_findings") or 0) > 0],
            key=lambda r: r.get("open_findings", 0),
            reverse=True,
        )[:5]

        return jsonify({
            "rules_total":             len(rules),
            "rules_with_open_findings": rules_with_open,
            "findings_total":          int(findings_total),
            "findings_open":           int(findings_open),
            "findings_critical_high":  int(findings_critical_high),
            "findings_last_24h":       int(findings_last_24h),
            "top_rules": [
                {
                    "id":           r.get("id"),
                    "name":         r.get("name"),
                    "open_findings": r.get("open_findings", 0),
                    "severity":     r.get("severity"),
                }
                for r in top_rules
            ],
        })
    except Exception as exc:
        _logger.exception("siem_threat_hunt_summary error")
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/threat-hunting/analyze", methods=["POST"])
@require_siem_auth
def siem_threat_hunt_analyze():
    """Call CyMind to produce a natural-language analysis of current hunt state."""
    try:
        import psycopg2.extras
        from cy_comp.services.policy_rag import get_cymind_api_key, get_cymind_url

        rules = _sync_hunt_rules()

        # Fetch the 10 most-recent open hunt_finding incidents
        conn = _corr_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, severity, llm_summary, mitre_ids,
                           correlated_rules, first_seen
                    FROM incidents
                    WHERE 'hunt_finding' = ANY(categories)
                      AND status NOT IN ('closed', 'false_positive')
                    ORDER BY first_seen DESC
                    LIMIT 10
                """)
                recent_findings = cur.fetchall()
        finally:
            conn.close()

        # Build prompt context
        rules_summary_lines = []
        for r in rules:
            firing = "FIRING" if (r.get("open_findings") or 0) > 0 else "quiet"
            rules_summary_lines.append(
                f"  - [{r.get('id')}] {r.get('name')}: {firing} "
                f"({r.get('open_findings', 0)} open / {r.get('total_findings', 0)} total)"
            )
        rules_block = "\n".join(rules_summary_lines) or "  (no rules loaded)"

        findings_lines = []
        for f in recent_findings:
            rule_name = ""
            cr = f.get("correlated_rules")
            if cr and isinstance(cr, list) and len(cr) > 0:
                rule_name = cr[0].get("rule_name", "") if isinstance(cr[0], dict) else ""
            mitre = ", ".join(f.get("mitre_ids") or []) or "N/A"
            findings_lines.append(
                f"  - [{f.get('severity','?').upper()}] {f.get('llm_summary') or 'No summary'} "
                f"| MITRE: {mitre} | Rule: {rule_name} | first_seen: {_iso(f.get('first_seen'))}"
            )
        findings_block = "\n".join(findings_lines) or "  (no open findings)"

        prompt = (
            "You are a threat hunting analyst reviewing active hunt rule results for "
            "a CyCentra 360 SIEM deployment. Provide a concise, actionable analysis "
            "covering: (1) which hunt rules are producing the most noise, "
            "(2) MITRE ATT&CK technique patterns in the findings, "
            "(3) recommended triage priorities, and (4) any potential false positive patterns.\n\n"
            f"## Active Hunt Rules ({len(rules)} total)\n{rules_block}\n\n"
            f"## Recent Open Findings (up to 10)\n{findings_block}\n\n"
            "Respond in plain prose, under 400 words."
        )

        # Call CyMind
        cymind_url = get_cymind_url()
        api_key    = get_cymind_api_key()

        if not cymind_url or not api_key:
            return jsonify({"analysis": None, "error": "CyMind not configured"}), 200

        chat_resp = _req.post(
            f"{cymind_url}/api/v1/chat",
            json={"message": prompt, "stream": False},
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            timeout=60,
        )
        chat_resp.raise_for_status()
        data = chat_resp.json()

        return jsonify({
            "analysis":         data.get("content", ""),
            "model":            data.get("model_used", ""),
            "rules_analyzed":   len(rules),
            "findings_analyzed": len(recent_findings),
        })

    except _req.exceptions.RequestException as exc:
        _logger.warning("siem_threat_hunt_analyze: CyMind request failed: %s", exc)
        return jsonify({"analysis": None, "error": f"CyMind request failed: {exc}"}), 200
    except Exception as exc:
        _logger.exception("siem_threat_hunt_analyze error")
        return jsonify({"error": str(exc)}), 500


@siem_bp.route("/posture/internal", methods=["GET"])
@require_siem_auth
def siem_internal_posture():
    try:
        return jsonify(_sync_internal_posture())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


