"""
blueprints/edr/routes.py
==========================
CyEDR — Endpoint Detection & Response Blueprint.

Mounts at /api/edr/* in app.py.

Auth model (dual-mode):
  UI routes  — standard Flask session RBAC (viewer/analyst/admin)
  Agent routes — Bearer enrollment token in Authorization header

RBAC summary:
  GET  /api/edr/*           → viewer+
  POST /api/edr/agents/enroll → admin only
  POST /api/edr/response/*  → analyst+
  POST /api/edr/telemetry   → enrollment token (no session)
  GET  /api/edr/response/<id>/pending → enrollment token
  POST /api/edr/response/<id>/commands/<cid>/complete → enrollment token
"""
from __future__ import annotations
import json
import uuid
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session, make_response

from blueprints.rbac.manager import get_user_role
from core.helpers import add_cors_headers, auth_event
from core.config import CYCENTRA_DB_URL

from .normalizer import normalise_telemetry
from .response_orchestrator import (
    ensure_tables, queue_response_command, get_pending_commands,
    complete_command, auto_respond, update_agent_isolation, VALID_ACTIONS,
)
from .confidence_matrix import HEURISTIC_TABLE

_log = logging.getLogger(__name__)

edr_bp = Blueprint("edr", __name__, url_prefix="/api/edr")

# ── DB helper ─────────────────────────────────────────────────────────────────

def _db():
    return psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


# ── Auth decorators ───────────────────────────────────────────────────────────

def _session_role() -> str | None:
    email = session.get("user_email", "")
    return get_user_role(email) if email else None


def require_viewer(f):
    @wraps(f)
    def _w(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return _w


def require_analyst(f):
    @wraps(f)
    def _w(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _session_role() not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*args, **kwargs)
    return _w


def require_admin(f):
    @wraps(f)
    def _w(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _session_role() != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*args, **kwargs)
    return _w


def _resolve_agent_token(agent_id: str) -> str | None:
    """Return the enrollment token for an agent, or None if not found."""
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT enrollment_token FROM edr_agents WHERE agent_id=%s AND status='active'",
                [agent_id],
            )
            row = cur.fetchone()
        conn.close()
        return row["enrollment_token"] if row else None
    except Exception:
        return None


def require_agent_token(f):
    """Validate Bearer <enrollment_token> for agent-facing endpoints."""
    @wraps(f)
    def _w(*args, **kwargs):
        agent_id = kwargs.get("agent_id") or request.view_args.get("agent_id", "")
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Bearer token required"}), 401
        token = auth[7:]
        expected = _resolve_agent_token(agent_id)
        if not expected or not secrets.compare_digest(token, expected):
            return jsonify({"error": "Invalid or expired enrollment token"}), 401
        return f(*args, **kwargs)
    return _w


# ── Blueprint init ────────────────────────────────────────────────────────────

def init_edr(app):
    """Called by app.py after blueprint registration to set up DB tables."""
    with app.app_context():
        ensure_tables(CYCENTRA_DB_URL)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _store_detection(conn, alert: dict, envelope: dict) -> str:
    """Persist a normalised EDR alert as an edr_detection row. Returns detection ID."""
    det_id = str(uuid.uuid4())
    process = envelope.get("process") or {}
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO edr_detections
              (id, agent_id, event_uuid, severity, score, rule_id, rule_desc,
               mitre_id, mitre_tactic, event_category, process_name,
               process_path, command_line, file_path, src_ip, dst_ip,
               username, triggers, ti_match, raw_envelope)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (event_uuid) DO NOTHING
            RETURNING id
            """,
            [
                det_id,
                alert["agent_id"],
                envelope.get("event_uuid"),
                alert["_edr_severity"],
                alert["_edr_score"],
                alert["rule_id"],
                alert["rule_desc"],
                alert.get("mitre_id"),
                alert.get("mitre_tactic"),
                alert.get("category"),
                alert.get("process_name"),
                process.get("executable_path"),
                process.get("command_line"),
                alert.get("file_path"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("username"),
                json.dumps(alert.get("_edr_triggers", [])),
                bool(envelope.get("ti_match")),
                json.dumps(envelope),
            ],
        )
        row = cur.fetchone()
    return (row["id"] if row else det_id)


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT ENROLLMENT
# ═══════════════════════════════════════════════════════════════════════════════

@edr_bp.route("/agents/enroll", methods=["OPTIONS"])
def _opt_enroll():
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/agents/enroll", methods=["POST"])
@require_admin
def enroll_agent():
    """
    Register a new EDR agent and return its enrollment token.

    Body: { hostname, os_type, asset_type, agent_ip, tags, metadata }
    Response: { agent_id, enrollment_token }
    """
    body = request.get_json(force=True, silent=True) or {}
    hostname  = (body.get("hostname") or "").strip()
    os_type   = (body.get("os_type") or "unknown").upper()
    asset_type = body.get("asset_type", "workstation")
    agent_ip  = body.get("agent_ip", "")
    tags      = body.get("tags", [])
    metadata  = body.get("metadata", {})

    if not hostname:
        return jsonify({"error": "hostname required"}), 400
    if os_type not in ("WINDOWS", "LINUX", "MACOS", "UNKNOWN"):
        return jsonify({"error": "os_type must be WINDOWS, LINUX, or MACOS"}), 400

    agent_id = str(uuid.uuid4())
    token    = secrets.token_urlsafe(48)
    email    = session.get("user_email", "system")

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO edr_agents
                  (agent_id, hostname, os_type, agent_ip, asset_type,
                   enrollment_token, enrolled_by, tags, metadata)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                [
                    agent_id, hostname, os_type, agent_ip, asset_type,
                    token, email,
                    json.dumps(tags), json.dumps(metadata),
                ],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("enroll_agent DB error: %s", exc)
        return jsonify({"error": "Database error during enrollment"}), 500

    auth_event(email, "edr_enroll", f"Enrolled agent {hostname} ({agent_id})")
    return jsonify({"agent_id": agent_id, "enrollment_token": token}), 201


# ═══════════════════════════════════════════════════════════════════════════════
# FLEET MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@edr_bp.route("/agents", methods=["GET"])
@require_viewer
def list_agents():
    """Return all enrolled agents with summary stats."""
    status_filter = request.args.get("status", "active")
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.*,
                  (SELECT COUNT(*) FROM edr_detections d
                   WHERE d.agent_id=a.agent_id AND d.status='open') AS open_detections,
                  (SELECT COUNT(*) FROM edr_response_commands c
                   WHERE c.agent_id=a.agent_id AND c.status='pending') AS pending_commands
                FROM edr_agents a
                WHERE (%s = 'all' OR a.status = %s)
                ORDER BY a.last_seen DESC NULLS LAST
                """,
                [status_filter, status_filter],
            )
            rows = [dict(r) for r in cur.fetchall()]
        conn.close()
    except psycopg2.Error as exc:
        _log.error("list_agents DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    # Strip token from list response
    for r in rows:
        r.pop("enrollment_token", None)
        r["last_seen"] = r["last_seen"].isoformat() if r.get("last_seen") else None
        r["enrolled_at"] = r["enrolled_at"].isoformat() if r.get("enrolled_at") else None

    return jsonify({"agents": rows, "total": len(rows)})


@edr_bp.route("/agents/<agent_id>", methods=["GET"])
@require_viewer
def get_agent(agent_id):
    """Return agent detail with recent detections."""
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM edr_agents WHERE agent_id=%s", [agent_id]
            )
            agent = cur.fetchone()
            if not agent:
                conn.close()
                return jsonify({"error": "Agent not found"}), 404
            agent = dict(agent)
            agent.pop("enrollment_token", None)

            cur.execute(
                """
                SELECT id, detected_at, severity, score, rule_desc, mitre_id,
                       event_category, process_name, status, triggers
                FROM edr_detections
                WHERE agent_id=%s
                ORDER BY detected_at DESC LIMIT 25
                """,
                [agent_id],
            )
            detections = [dict(r) for r in cur.fetchall()]

            cur.execute(
                """
                SELECT id, action, status, issued_at, completed_at, auto_triggered
                FROM edr_response_commands
                WHERE agent_id=%s
                ORDER BY issued_at DESC LIMIT 10
                """,
                [agent_id],
            )
            commands = [dict(r) for r in cur.fetchall()]
        conn.close()
    except psycopg2.Error as exc:
        _log.error("get_agent DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    def _fmt(r):
        for k in ("detected_at", "issued_at", "completed_at", "enrolled_at", "last_seen"):
            if k in r and r[k]:
                r[k] = r[k].isoformat()
        return r

    agent = _fmt(agent)
    return jsonify({
        "agent":      agent,
        "detections": [_fmt(d) for d in detections],
        "commands":   [_fmt(c) for c in commands],
    })


@edr_bp.route("/agents/<agent_id>/heartbeat", methods=["OPTIONS"])
def _opt_heartbeat(agent_id):
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/agents/<agent_id>/heartbeat", methods=["POST"])
@require_agent_token
def agent_heartbeat(agent_id):
    """
    Agent-facing: update last_seen and version.
    Body: { version, agent_ip }
    """
    body    = request.get_json(force=True, silent=True) or {}
    version = body.get("version", "")
    ip      = body.get("agent_ip", "")
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE edr_agents
                SET last_seen=NOW(), version=%s,
                    agent_ip=COALESCE(NULLIF(%s,''), agent_ip)
                WHERE agent_id=%s
                """,
                [version, ip, agent_id],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("heartbeat DB error: %s", exc)
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════════════════════════════════════════
# TELEMETRY INGEST
# ═══════════════════════════════════════════════════════════════════════════════

@edr_bp.route("/telemetry", methods=["OPTIONS"])
def _opt_telemetry():
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/telemetry", methods=["POST"])
@require_agent_token
def ingest_telemetry(agent_id):
    """
    Agent-facing: receive a batch of TelemetryEnvelope events.

    Body: { events: [ TelemetryEnvelope, ... ] }
    Each envelope is normalised, scored, stored as an edr_detection, and
    forwarded to the SIEM Redis queue via edr_bridge.
    """
    body   = request.get_json(force=True, silent=True) or {}
    events = body.get("events", [])
    if not events:
        return jsonify({"ingested": 0}), 200

    from cysiemstack.edr_bridge import forward_to_siem

    ingested = 0
    try:
        conn = _db()
        for envelope in events:
            if not isinstance(envelope, dict):
                continue
            # Stamp the source agent_id from the URL path (authoritative)
            envelope["endpoint_uuid"] = agent_id
            alert = normalise_telemetry(envelope)
            if alert is None:
                continue
            try:
                det_id = _store_detection(conn, alert, envelope)
                alert["_detection_id"] = det_id
                # Auto-respond to critical detections
                auto_respond(CYCENTRA_DB_URL, alert, agent_id)
                # Forward normalized event to SIEM pipeline
                forward_to_siem(alert)
                ingested += 1
            except Exception as exc:
                _log.warning("ingest event error: %s", exc)
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("telemetry DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    # Update agent last_seen
    try:
        conn2 = _db()
        with conn2.cursor() as cur:
            cur.execute("UPDATE edr_agents SET last_seen=NOW() WHERE agent_id=%s", [agent_id])
        conn2.commit()
        conn2.close()
    except Exception:
        pass

    return jsonify({"ingested": ingested})


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTIONS
# ═══════════════════════════════════════════════════════════════════════════════

@edr_bp.route("/detections", methods=["GET"])
@require_viewer
def list_detections():
    """Return recent EDR detections with optional filters."""
    severity  = request.args.get("severity")
    status    = request.args.get("status")
    agent_id  = request.args.get("agent_id")
    limit     = min(int(request.args.get("limit", 100)), 500)
    offset    = int(request.args.get("offset", 0))

    clauses = []
    params  = []
    if severity:
        clauses.append("d.severity=%s"); params.append(severity)
    if status:
        clauses.append("d.status=%s"); params.append(status)
    if agent_id:
        clauses.append("d.agent_id=%s"); params.append(agent_id)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT d.*, a.hostname, a.os_type, a.asset_type
                FROM edr_detections d
                LEFT JOIN edr_agents a ON a.agent_id=d.agent_id
                {where}
                ORDER BY d.detected_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [limit, offset],
            )
            rows = [dict(r) for r in cur.fetchall()]
            cur.execute(f"SELECT COUNT(*) FROM edr_detections d {where}", params)
            total = cur.fetchone()["count"]
        conn.close()
    except psycopg2.Error as exc:
        _log.error("list_detections DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    for r in rows:
        r["detected_at"] = r["detected_at"].isoformat() if r.get("detected_at") else None

    return jsonify({"detections": rows, "total": total, "limit": limit, "offset": offset})


@edr_bp.route("/detections/<det_id>", methods=["GET"])
@require_viewer
def get_detection(det_id):
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT d.*, a.hostname, a.os_type, a.asset_type, a.isolation_state
                FROM edr_detections d
                LEFT JOIN edr_agents a ON a.agent_id=d.agent_id
                WHERE d.id=%s
                """,
                [det_id],
            )
            row = cur.fetchone()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("get_detection DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    if not row:
        return jsonify({"error": "Detection not found"}), 404

    result = dict(row)
    result["detected_at"] = result["detected_at"].isoformat() if result.get("detected_at") else None
    return jsonify(result)


@edr_bp.route("/detections/<det_id>/status", methods=["OPTIONS"])
def _opt_det_status(det_id):
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/detections/<det_id>/status", methods=["PATCH"])
@require_analyst
def update_detection_status(det_id):
    """Analyst: update detection status (open → investigating → resolved / fp)."""
    body   = request.get_json(force=True, silent=True) or {}
    status = body.get("status", "").lower()
    notes  = body.get("notes", "")
    valid  = {"open", "investigating", "resolved", "false_positive", "in_review"}
    if status not in valid:
        return jsonify({"error": f"status must be one of {sorted(valid)}"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE edr_detections SET status=%s, notes=%s WHERE id=%s",
                [status, notes, det_id],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("update_detection_status DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    auth_event(
        session.get("user_email", "system"),
        "edr_detection_update",
        f"Detection {det_id} → {status}",
    )
    return jsonify({"status": status, "detection_id": det_id})


# ═══════════════════════════════════════════════════════════════════════════════
# RESPONSE ACTIONS (analyst+ UI routes)
# ═══════════════════════════════════════════════════════════════════════════════

def _opts_response(agent_id, **_):
    return add_cors_headers(make_response("", 204))


for _path in (
    "/response/<agent_id>/isolate",
    "/response/<agent_id>/unisolate",
    "/response/<agent_id>/kill-process",
    "/response/<agent_id>/block-hash",
    "/response/<agent_id>/collect-forensics",
    "/response/<agent_id>/quarantine-file",
    "/response/<agent_id>/rollback",
    "/response/<agent_id>/run-scan",
):
    edr_bp.add_url_rule(_path, endpoint=f"opts{_path.replace('/', '_').replace('-', '_').replace('<', '').replace('>', '')}",
                        view_func=_opts_response, methods=["OPTIONS"])


def _issue_action(agent_id: str, action: str, params: dict) -> tuple:
    email = session.get("user_email", "system")
    detection_id = params.pop("detection_id", None)
    incident_id  = params.pop("incident_id", None)
    try:
        cmd = queue_response_command(
            CYCENTRA_DB_URL, agent_id, action, params,
            issued_by=email,
            detection_id=detection_id,
            incident_id=incident_id,
        )
        auth_event(email, f"edr_response_{action.lower()}", f"Agent {agent_id}: {action}")
        return jsonify({"command_id": cmd["id"], "action": action, "status": "pending"}), 202
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        _log.error("issue_action error: %s", exc)
        return jsonify({"error": "Failed to queue command"}), 500


@edr_bp.route("/response/<agent_id>/isolate", methods=["POST"])
@require_analyst
def isolate(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    return _issue_action(agent_id, "ISOLATE", {
        "reason": body.get("reason", "Manual isolation by analyst"),
        "detection_id": body.get("detection_id"),
        "incident_id":  body.get("incident_id"),
    })


@edr_bp.route("/response/<agent_id>/unisolate", methods=["POST"])
@require_analyst
def unisolate(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    return _issue_action(agent_id, "UNISOLATE", {
        "reason": body.get("reason", "Isolation lifted by analyst"),
        "detection_id": body.get("detection_id"),
    })


@edr_bp.route("/response/<agent_id>/kill-process", methods=["POST"])
@require_analyst
def kill_process(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    if not body.get("pid") and not body.get("image_name"):
        return jsonify({"error": "pid or image_name required"}), 400
    return _issue_action(agent_id, "KILL_PROCESS", {
        "pid":          body.get("pid"),
        "image_name":   body.get("image_name"),
        "detection_id": body.get("detection_id"),
    })


@edr_bp.route("/response/<agent_id>/block-hash", methods=["POST"])
@require_analyst
def block_hash(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    if not body.get("sha256"):
        return jsonify({"error": "sha256 required"}), 400
    return _issue_action(agent_id, "BLOCK_HASH", {
        "sha256":       body["sha256"],
        "reason":       body.get("reason", "Manual block"),
        "detection_id": body.get("detection_id"),
    })


@edr_bp.route("/response/<agent_id>/collect-forensics", methods=["POST"])
@require_analyst
def collect_forensics(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    return _issue_action(agent_id, "COLLECT_FORENSICS", {
        "scope":        body.get("scope", "memory,process,network"),
        "reason":       body.get("reason", "Manual collection"),
        "detection_id": body.get("detection_id"),
        "incident_id":  body.get("incident_id"),
    })


@edr_bp.route("/response/<agent_id>/quarantine-file", methods=["POST"])
@require_analyst
def quarantine_file(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    if not body.get("file_path"):
        return jsonify({"error": "file_path required"}), 400
    return _issue_action(agent_id, "QUARANTINE_FILE", {
        "file_path":    body["file_path"],
        "detection_id": body.get("detection_id"),
    })


@edr_bp.route("/response/<agent_id>/rollback", methods=["POST"])
@require_analyst
def rollback(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    return _issue_action(agent_id, "ROLLBACK", {
        "snapshot":     body.get("snapshot", "latest"),
        "scope":        body.get("scope", "modified_files"),
        "detection_id": body.get("detection_id"),
    })


@edr_bp.route("/response/<agent_id>/run-scan", methods=["POST"])
@require_analyst
def run_scan(agent_id):
    body = request.get_json(force=True, silent=True) or {}
    return _issue_action(agent_id, "RUN_SCAN", {
        "scan_type":  body.get("scan_type", "full"),
        "path":       body.get("path", "/"),
        "yara_rules": body.get("yara_rules", "all"),
        "detection_id": body.get("detection_id"),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# AGENT-FACING COMMAND POLLING
# ═══════════════════════════════════════════════════════════════════════════════

@edr_bp.route("/response/<agent_id>/pending", methods=["OPTIONS"])
def _opt_pending(agent_id):
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/response/<agent_id>/pending", methods=["GET"])
@require_agent_token
def pending_commands(agent_id):
    """Agent polls this to receive and acknowledge queued response commands."""
    cmds = get_pending_commands(CYCENTRA_DB_URL, agent_id)
    return jsonify({"commands": cmds})


@edr_bp.route("/response/<agent_id>/commands/<cmd_id>/complete", methods=["OPTIONS"])
def _opt_complete(agent_id, cmd_id):
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/response/<agent_id>/commands/<cmd_id>/complete", methods=["POST"])
@require_agent_token
def command_complete(agent_id, cmd_id):
    """Agent reports completion (or failure) of a response command."""
    body    = request.get_json(force=True, silent=True) or {}
    success = bool(body.get("success", True))
    result  = body.get("result", {})
    action  = body.get("action", "")

    complete_command(CYCENTRA_DB_URL, agent_id, cmd_id, result, success)

    # Sync isolation state for ISOLATE/UNISOLATE completions
    if success:
        if action == "ISOLATE":
            update_agent_isolation(CYCENTRA_DB_URL, agent_id, "isolated")
        elif action == "UNISOLATE":
            update_agent_isolation(CYCENTRA_DB_URL, agent_id, "normal")

    return jsonify({"status": "recorded"})


# ═══════════════════════════════════════════════════════════════════════════════
# STATS & REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════

@edr_bp.route("/stats", methods=["GET"])
@require_viewer
def edr_stats():
    """Fleet-wide EDR statistics for the dashboard widget."""
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                  (SELECT COUNT(*) FROM edr_agents WHERE status='active') AS total_agents,
                  (SELECT COUNT(*) FROM edr_agents WHERE isolation_state='isolated') AS isolated_agents,
                  (SELECT COUNT(*) FROM edr_agents
                   WHERE last_seen > NOW()-INTERVAL '5 minutes') AS online_agents,
                  (SELECT COUNT(*) FROM edr_detections WHERE status='open') AS open_detections,
                  (SELECT COUNT(*) FROM edr_detections
                   WHERE severity='critical' AND status='open') AS critical_open,
                  (SELECT COUNT(*) FROM edr_detections
                   WHERE detected_at > NOW()-INTERVAL '24 hours') AS detections_24h,
                  (SELECT COUNT(*) FROM edr_response_commands
                   WHERE status='pending') AS pending_commands,
                  (SELECT COUNT(*) FROM edr_response_commands
                   WHERE auto_triggered=TRUE AND status='completed'
                   AND issued_at > NOW()-INTERVAL '24 hours') AS auto_responses_24h
            """)
            stats = dict(cur.fetchone())
        conn.close()
    except psycopg2.Error as exc:
        _log.error("edr_stats DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    return jsonify(stats)


@edr_bp.route("/triggers", methods=["GET"])
@require_viewer
def list_triggers():
    """Return the heuristic trigger catalog for the UI."""
    return jsonify({
        k: {
            "weight":      v["weight"],
            "mitre_id":    v["mitre"][0],
            "mitre_tactic": v["mitre"][1],
            "desc":        v["desc"],
        }
        for k, v in HEURISTIC_TABLE.items()
    })


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

from .policy_engine import (
    create_policy, list_policies, get_policy, update_policy, delete_policy,
    assign_policy, get_agent_effective_policies,
    create_deployment_token, list_deployment_tokens, revoke_deployment_token,
    create_group, list_groups, add_agents_to_group,
    POLICY_TYPES, POLICY_DEFAULTS,
    ensure_policy_tables,
)


def _init_policy_tables(app):
    with app.app_context():
        ensure_policy_tables(CYCENTRA_DB_URL)


# Wire policy table init into the existing init_edr call
_orig_init_edr = init_edr


def init_edr(app):
    _orig_init_edr(app)
    _init_policy_tables(app)


# ── Policy OPTIONS ────────────────────────────────────────────────────────────
for _pp in ("/policies", "/policies/<pol_id>", "/policies/<pol_id>/assign",
            "/agents/<agent_id>/policies", "/groups", "/groups/<grp_id>/members"):
    edr_bp.add_url_rule(
        _pp,
        endpoint=f"opts_pol_{_pp.replace('/', '_').replace('<', '').replace('>', '')}",
        view_func=lambda **_: add_cors_headers(make_response("", 204)),
        methods=["OPTIONS"],
    )


@edr_bp.route("/policies", methods=["GET"])
@require_viewer
def get_policies():
    ptype = request.args.get("type")
    return jsonify({"policies": list_policies(CYCENTRA_DB_URL, ptype)})


@edr_bp.route("/policies", methods=["POST"])
@require_admin
def post_policy():
    body = request.get_json(force=True, silent=True) or {}
    name        = (body.get("name") or "").strip()
    policy_type = body.get("policy_type", "")
    config      = body.get("config", {})
    description = body.get("description", "")
    if not name:
        return jsonify({"error": "name required"}), 400
    try:
        pol = create_policy(CYCENTRA_DB_URL, name, policy_type, config, description,
                            session.get("user_email", "system"))
        auth_event(session.get("user_email", ""), "edr_policy_create", f"Created policy: {name}")
        return jsonify(pol), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@edr_bp.route("/policies/<pol_id>", methods=["GET"])
@require_viewer
def get_policy_detail(pol_id):
    pol = get_policy(CYCENTRA_DB_URL, pol_id)
    if not pol:
        return jsonify({"error": "Policy not found"}), 404
    return jsonify(pol)


@edr_bp.route("/policies/<pol_id>", methods=["PUT"])
@require_admin
def put_policy(pol_id):
    body = request.get_json(force=True, silent=True) or {}
    try:
        pol = update_policy(CYCENTRA_DB_URL, pol_id, body)
        auth_event(session.get("user_email", ""), "edr_policy_update", f"Updated policy {pol_id}")
        return jsonify(pol)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@edr_bp.route("/policies/<pol_id>", methods=["DELETE"])
@require_admin
def delete_policy_route(pol_id):
    delete_policy(CYCENTRA_DB_URL, pol_id)
    auth_event(session.get("user_email", ""), "edr_policy_delete", f"Deleted policy {pol_id}")
    return jsonify({"deleted": pol_id})


@edr_bp.route("/policies/<pol_id>/assign", methods=["POST"])
@require_analyst
def assign_policy_route(pol_id):
    body        = request.get_json(force=True, silent=True) or {}
    target_type = body.get("target_type", "agent")
    target_ids  = body.get("target_ids", [])
    if not target_ids:
        return jsonify({"error": "target_ids required"}), 400
    try:
        count = assign_policy(CYCENTRA_DB_URL, pol_id, target_type, target_ids,
                              session.get("user_email", "system"))
        auth_event(session.get("user_email", ""), "edr_policy_assign",
                   f"Assigned policy {pol_id} to {count} {target_type}(s)")
        return jsonify({"assigned": count})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@edr_bp.route("/agents/<agent_id>/policies", methods=["GET"])
@require_viewer
def agent_policies(agent_id):
    pols = get_agent_effective_policies(CYCENTRA_DB_URL, agent_id)
    return jsonify({"policies": pols})


@edr_bp.route("/policy-defaults", methods=["GET"])
@require_viewer
def policy_defaults():
    ptype = request.args.get("type")
    if ptype:
        if ptype not in POLICY_TYPES:
            return jsonify({"error": f"Unknown type: {ptype}"}), 400
        return jsonify({"defaults": POLICY_DEFAULTS[ptype], "type": ptype})
    return jsonify({"types": list(POLICY_TYPES), "defaults": POLICY_DEFAULTS})


# ── Agent Groups ──────────────────────────────────────────────────────────────

@edr_bp.route("/groups", methods=["GET"])
@require_viewer
def get_groups():
    return jsonify({"groups": list_groups(CYCENTRA_DB_URL)})


@edr_bp.route("/groups", methods=["POST"])
@require_analyst
def post_group():
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    grp = create_group(CYCENTRA_DB_URL, name, body.get("description", ""),
                       session.get("user_email", "system"))
    return jsonify(grp), 201


@edr_bp.route("/groups/<grp_id>/members", methods=["POST"])
@require_analyst
def add_group_members(grp_id):
    body = request.get_json(force=True, silent=True) or {}
    agent_ids = body.get("agent_ids", [])
    if not agent_ids:
        return jsonify({"error": "agent_ids required"}), 400
    count = add_agents_to_group(CYCENTRA_DB_URL, grp_id, agent_ids)
    return jsonify({"added": count})


# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT TOKENS (agent installer)
# ═══════════════════════════════════════════════════════════════════════════════

for _dp in ("/installer/token", "/installer/token/<tok_id>/revoke"):
    edr_bp.add_url_rule(
        _dp,
        endpoint=f"opts_ins_{_dp.replace('/', '_').replace('<', '').replace('>', '')}",
        view_func=lambda **_: add_cors_headers(make_response("", 204)),
        methods=["OPTIONS"],
    )


@edr_bp.route("/installer/token", methods=["GET"])
@require_admin
def get_deployment_tokens():
    return jsonify({"tokens": list_deployment_tokens(CYCENTRA_DB_URL)})


@edr_bp.route("/installer/token", methods=["POST"])
@require_admin
def create_deployment_token_route():
    body    = request.get_json(force=True, silent=True) or {}
    label   = body.get("label", "Default deployment token")
    os_type = body.get("os_type", "any")
    max_uses     = int(body.get("max_uses", 0))
    expires_hours = int(body.get("expires_hours", 0))
    tok = create_deployment_token(CYCENTRA_DB_URL, label,
                                   session.get("user_email", "system"),
                                   os_type, max_uses, expires_hours)
    auth_event(session.get("user_email", ""), "edr_token_create", f"Created deployment token: {label}")
    return jsonify(tok), 201


@edr_bp.route("/installer/token/<tok_id>/revoke", methods=["POST"])
@require_admin
def revoke_token(tok_id):
    revoke_deployment_token(CYCENTRA_DB_URL, tok_id)
    auth_event(session.get("user_email", ""), "edr_token_revoke", f"Revoked deployment token {tok_id}")
    return jsonify({"revoked": tok_id})


@edr_bp.route("/installer/commands", methods=["GET"])
@require_admin
def installer_commands():
    """
    Return platform-specific install commands for a given deployment token.
    Query param: token=<value>
    """
    token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "token query param required"}), 400
    from core.config import BASE_DOMAIN
    collector_url = f"https://cy360.{BASE_DOMAIN}/api/edr"
    return jsonify({
        "windows": {
            "powershell": (
                f'$Token="{token}"; $Url="{collector_url}"; '
                f'Invoke-WebRequest "$Url/installer/win/cyedr-setup.exe" -OutFile cyedr-setup.exe; '
                f'Start-Process cyedr-setup.exe -ArgumentList "/token $Token /url $Url /S" -Wait; '
                f'Remove-Item cyedr-setup.exe'
            ),
            "msiexec": (
                f'msiexec /i cyedr.msi DEPLOYMENT_TOKEN="{token}" '
                f'COLLECTOR_URL="{collector_url}" /qn /l*v cyedr-install.log'
            ),
        },
        "linux": {
            "bash": (
                f'curl -fsSL {collector_url}/installer/linux/cyedr-install.sh | '
                f'DEPLOYMENT_TOKEN="{token}" COLLECTOR_URL="{collector_url}" bash'
            ),
            "rpm": (
                f'DEPLOYMENT_TOKEN="{token}" COLLECTOR_URL="{collector_url}" '
                f'rpm -ivh cyedr-agent.rpm && systemctl enable --now cyedr-agent'
            ),
            "deb": (
                f'DEPLOYMENT_TOKEN="{token}" COLLECTOR_URL="{collector_url}" '
                f'dpkg -i cyedr-agent.deb && systemctl enable --now cyedr-agent'
            ),
        },
        "macos": {
            "bash": (
                f'curl -fsSL {collector_url}/installer/macos/cyedr-install.sh | '
                f'DEPLOYMENT_TOKEN="{token}" COLLECTOR_URL="{collector_url}" bash'
            ),
            "pkg": (
                f'sudo installer -pkg cyedr-agent.pkg -target / && '
                f'sudo /Library/CyEDR/cyedr-ctl configure '
                f'--token "{token}" --collector "{collector_url}"'
            ),
        },
        "collector_url": collector_url,
        "token":         token,
    })


# ── Self-enrollment (agent calls this with deployment token) ──────────────────

@edr_bp.route("/agents/self-enroll", methods=["OPTIONS"])
def _opt_self_enroll():
    return add_cors_headers(make_response("", 204))


@edr_bp.route("/agents/self-enroll", methods=["POST"])
def self_enroll_agent():
    """
    Agent-facing: register using a deployment token (not a session).
    Returns enrollment_token for subsequent API calls.

    Body: { deployment_token, hostname, os_type, agent_ip, version, asset_type }
    """
    from .policy_engine import validate_deployment_token
    body  = request.get_json(force=True, silent=True) or {}
    dtoken = body.get("deployment_token", "")
    if not dtoken or not validate_deployment_token(CYCENTRA_DB_URL, dtoken):
        return jsonify({"error": "Invalid or expired deployment token"}), 401

    hostname   = (body.get("hostname") or "").strip()
    os_type    = (body.get("os_type") or "UNKNOWN").upper()
    agent_ip   = body.get("agent_ip", "")
    version    = body.get("version", "")
    asset_type = body.get("asset_type", "workstation")
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    import secrets as _s
    agent_id = str(uuid.uuid4())
    token    = _s.token_urlsafe(48)
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO edr_agents
                  (agent_id, hostname, os_type, agent_ip, asset_type,
                   enrollment_token, enrolled_by, version)
                VALUES (%s,%s,%s,%s,%s,%s,'self-enrollment',%s)
                """,
                [agent_id, hostname, os_type, agent_ip, asset_type, token, version],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("self_enroll DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    return jsonify({
        "agent_id":         agent_id,
        "enrollment_token": token,
        "message":          "Agent enrolled successfully",
    }), 201
