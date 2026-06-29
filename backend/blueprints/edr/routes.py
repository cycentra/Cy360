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
import os
import uuid
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session, make_response, send_file

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
    Agent-facing: update last_seen, version, and optionally ingest ARP neighbors.
    Body: { version, agent_ip, arp_neighbors?: [{ip, mac}] }
    """
    body      = request.get_json(force=True, silent=True) or {}
    version   = body.get("version", "")
    ip        = body.get("agent_ip", "")
    neighbors = body.get("arp_neighbors", [])
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

    # Feed ARP neighbors into ITAM network_assets (non-blocking, best-effort)
    if neighbors:
        try:
            from blueprints.itam.routes import ingest_arp_neighbors
            import threading
            threading.Thread(
                target=ingest_arp_neighbors,
                args=(agent_id, neighbors),
                daemon=True,
            ).start()
        except Exception as exc:
            _log.debug("ITAM ARP ingest skipped: %s", exc)

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

            # Shadow AI events are governance — route to ITAM, skip SIEM pipeline
            if envelope.get("event_category") == "shadow_ai":
                try:
                    from blueprints.itam.routes import ingest_shadow_ai
                    raw = envelope.get("raw") or {}
                    ingest_shadow_ai(
                        agent_id=agent_id,
                        hostname=envelope.get("hostname", ""),
                        ai_tool=raw.get("ai_tool", raw.get("process_name", "unknown")),
                        process_name=raw.get("process_name", ""),
                        severity="medium",
                    )
                except Exception as _e:
                    _log.debug("shadow_ai ingest error: %s", _e)
                continue  # do not store as edr_detection

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
        elif action == "RUN_SCAN":
            _ingest_yara_scan_result(agent_id, cmd_id, result)

    return jsonify({"status": "recorded"})


def _ingest_yara_scan_result(agent_id: str, cmd_id: str, result: dict | str) -> None:
    """
    Parse RUN_SCAN result from the agent and write YARA matches to:
      1. edr_detections (for EDR Detections page)
      2. alerts table (for threat hunter HT-013/HT-014 sweep + SIEM correlation)

    The agent returns result as a string: "YARA scan complete. Matches:\nRULENAME /path/to/file\n..."
    or as {"output": "...", "matches": [{"rule": ..., "path": ...}]}.
    """
    if not result:
        return

    # Normalise to string
    raw_output = result if isinstance(result, str) else (
        result.get("output") or result.get("matches_text") or json.dumps(result)
    )
    # Structured matches take priority
    structured = result.get("matches") if isinstance(result, dict) else None

    if not structured:
        # Parse text format: "RULENAME /path/to/file"
        structured = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or line.startswith("YARA scan"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                structured.append({"rule": parts[0], "path": parts[1]})
            elif len(parts) == 1:
                structured.append({"rule": parts[0], "path": "unknown"})

    if not structured:
        return  # no matches — nothing to ingest

    # Determine if this is a custom rule hit (rule name contains 'custom_yara' prefix
    # OR came from the custom.yar file — agent tags these in the result)
    is_custom = isinstance(result, dict) and result.get("source") == "custom_yara"

    try:
        conn = _db()
        # Fetch agent hostname for the alert record
        with conn.cursor() as cur:
            cur.execute(
                "SELECT hostname, agent_ip FROM edr_agents WHERE agent_id=%s",
                [agent_id],
            )
            ag = cur.fetchone() or {}
            hostname = ag.get("hostname", agent_id)
            agent_ip = ag.get("agent_ip", "")

        now = datetime.now(timezone.utc)
        rule_desc_prefix = "custom_yara" if is_custom else "yara"

        for match in structured:
            rule_name = match.get("rule", "UNKNOWN_RULE")
            file_path = match.get("path", "unknown")
            det_id    = str(uuid.uuid4())
            event_uuid = f"yara-{cmd_id}-{det_id[:8]}"

            # 1. Write to edr_detections
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO edr_detections
                      (id, agent_id, event_uuid, severity, score, rule_desc,
                       event_category, file_path, raw_envelope)
                    VALUES (%s,%s,%s,'critical',95,%s,'malware',%s,%s)
                    ON CONFLICT (event_uuid) DO NOTHING
                    """,
                    [
                        det_id, agent_id, event_uuid,
                        f"{rule_desc_prefix} match: {rule_name}",
                        file_path,
                        json.dumps({"cmd_id": cmd_id, "match": match, "source": "RUN_SCAN"}),
                    ],
                )

            # 2. Write to alerts table so threat hunter (HT-013/HT-014) can sweep it
            # Rule ID 100210 = CyEDR YARA match (custom range, picked up by MALWARE_RULE_IDS)
            alert_rule_id = 100210 if not is_custom else 100211
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO alerts
                      (wazuh_id, timestamp, agent_id, agent_name, agent_ip,
                       rule_id, rule_desc, rule_level, base_score,
                       category, file_path, full_alert)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,12,9.5,'malware',%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    [
                        event_uuid, now, agent_id, hostname, agent_ip,
                        alert_rule_id,
                        f"{rule_desc_prefix} match: {rule_name} in {file_path}",
                        file_path,
                        json.dumps({
                            "rule": {"id": str(alert_rule_id), "level": 12,
                                     "description": f"YARA match: {rule_name}",
                                     "groups": ["malware", "yara"]},
                            "agent": {"id": agent_id, "name": hostname},
                            "data": {"yara_rule": rule_name, "file_path": file_path,
                                     "source": "CyEDR_RUN_SCAN", "is_custom": is_custom},
                        }),
                    ],
                )

        conn.commit()
        conn.close()
        _log.info("Ingested %d YARA matches from agent %s (cmd %s)", len(structured), agent_id, cmd_id)
    except Exception as exc:
        _log.error("_ingest_yara_scan_result failed for agent %s: %s", agent_id, exc)


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
    Return arch-aware install commands for a deployment token.
    Response: { os: { arch: { method: cmd, "method+siem": cmd } }, collector_url, token }
    """
    token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "token query param required"}), 400
    from core.config import BASE_DOMAIN
    base = f"https://cy360.{BASE_DOMAIN}"
    u    = f"{base}/api/edr"

    def _sh(siem=False):
        sf = " --with-cysiem" if siem else ""
        return (
            f'curl -fsSL {u}/installer/unix | '
            f'sudo bash -s -- --token "{token}" --platform "{base}"{sf}'
        )

    def _pkg(os_key, arch, ext, siem=False):
        inst = {
            "deb": f'dpkg -i cyedr-agent.{ext} && systemctl enable --now cyedr-agent',
            "rpm": f'rpm -ivh cyedr-agent.{ext} && systemctl enable --now cyedr-agent',
            "pkg": f'sudo installer -pkg cyedr-agent.{ext} -target /',
        }[ext]
        siem_tail = (
            f' && curl -fsSL -H "Authorization: Bearer {token}" '
            f'{u}/installer/cysiem-script | sudo bash'
        ) if siem else ""
        return (
            f'curl -fsSL -H "Authorization: Bearer {token}" '
            f'"{u}/installer/agent-bundle?os={os_key}&arch={arch}" '
            f'-o cyedr-agent.{ext} && {inst}{siem_tail}'
        )

    def _ps1(arch, siem=False):
        sf = " -WithCySIEM" if siem else ""
        return (
            f'[Net.ServicePointManager]::SecurityProtocol="Tls12"; '
            f'$t="{token}"; $p="{base}"; '
            f'iwr "$p/api/edr/installer/win" -UseBasicParsing | '
            f'iex; '
            f'cyedr-install.ps1 -Token $t -Platform $p -Arch {arch}{sf}'
        )

    def _msi(arch, siem=False):
        sf = " INSTALL_CYSIEM=1" if siem else ""
        return (
            f'msiexec /i cyedr-agent-{arch}.msi '
            f'DEPLOYMENT_TOKEN="{token}" '
            f'COLLECTOR_URL="{u}" '
            f'/qn /l*v cyedr-install.log{sf}'
        )

    return jsonify({
        "windows": {
            "x64": {
                "powershell":      _ps1("x64"),
                "msiexec":         _msi("x64"),
                "powershell+siem": _ps1("x64", siem=True),
                "msiexec+siem":    _msi("x64", siem=True),
            },
            "arm64": {
                "powershell":      _ps1("arm64"),
                "msiexec":         _msi("arm64"),
                "powershell+siem": _ps1("arm64", siem=True),
                "msiexec+siem":    _msi("arm64", siem=True),
            },
        },
        "linux": {
            "amd64": {
                "bash":      _sh(),
                "deb":       _pkg("LINUX", "amd64", "deb"),
                "bash+siem": _sh(siem=True),
                "deb+siem":  _pkg("LINUX", "amd64", "deb", siem=True),
            },
            "arm64": {
                "bash":      _sh(),
                "deb":       _pkg("LINUX", "arm64", "deb"),
                "bash+siem": _sh(siem=True),
                "deb+siem":  _pkg("LINUX", "arm64", "deb", siem=True),
            },
            "x86_64-rpm": {
                "bash":      _sh(),
                "rpm":       _pkg("LINUX", "x86_64", "rpm"),
                "bash+siem": _sh(siem=True),
                "rpm+siem":  _pkg("LINUX", "x86_64", "rpm", siem=True),
            },
            "aarch64-rpm": {
                "bash":      _sh(),
                "rpm":       _pkg("LINUX", "aarch64", "rpm"),
                "bash+siem": _sh(siem=True),
                "rpm+siem":  _pkg("LINUX", "aarch64", "rpm", siem=True),
            },
        },
        "macos": {
            "intel": {
                "bash":      _sh(),
                "pkg":       _pkg("MACOS", "intel64", "pkg"),
                "bash+siem": _sh(siem=True),
                "pkg+siem":  _pkg("MACOS", "intel64", "pkg", siem=True),
            },
            "apple_silicon": {
                "bash":      _sh(),
                "pkg":       _pkg("MACOS", "arm64", "pkg"),
                "bash+siem": _sh(siem=True),
                "pkg+siem":  _pkg("MACOS", "arm64", "pkg", siem=True),
            },
        },
        "collector_url": u,
        "token":         token,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# INSTALLER ASSET ENDPOINTS
# Serve pre-built binaries and config files to installer scripts.
# All require a valid deployment token in Authorization: Bearer <token>.
# ═══════════════════════════════════════════════════════════════════════════════

_EDR_PKG_DIR = "/var/lib/cycentra-agent-packages/edr"

# Deployment-token auth (for installer scripts; no session needed)
def _require_deploy_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Bearer deployment token required"}), 401
    from .policy_engine import validate_deployment_token
    if not validate_deployment_token(CYCENTRA_DB_URL, auth[7:]):
        return jsonify({"error": "Invalid or expired deployment token"}), 401
    return None  # OK


for _ap in ("/installer/agent-bundle", "/installer/sysmon-config",
            "/installer/sysmon-exe", "/installer/yara-rules",
            "/installer/yara-exe", "/installer/cysiem-script",
            "/installer/cysiem-msi", "/installer/unix", "/installer/win"):
    edr_bp.add_url_rule(
        _ap,
        endpoint=f"opts_asset_{_ap.replace('/','_').replace('-','_')}",
        view_func=lambda **_: add_cors_headers(make_response("", 204)),
        methods=["OPTIONS"],
    )


@edr_bp.route("/installer/agent-bundle", methods=["GET"])
def installer_agent_bundle():
    """Serve arch-specific standalone CyEDR binary for quick-install path."""
    err = _require_deploy_token()
    if err:
        return err
    os_key = request.args.get("os", "LINUX").upper()
    arch   = request.args.get("arch", "x86_64")
    _map = {
        ("LINUX",  "x86_64"):  "cyedr-agent-linux-x86_64",
        ("LINUX",  "aarch64"): "cyedr-agent-linux-aarch64",
        ("LINUX",  "amd64"):   "cyedr-agent-linux-x86_64",
        ("LINUX",  "arm64"):   "cyedr-agent-linux-aarch64",
        ("MACOS",  "intel64"): "cyedr-agent-macos-intel64",
        ("MACOS",  "arm64"):   "cyedr-agent-macos-arm64",
        ("MACOS",  "x86_64"):  "cyedr-agent-macos-intel64",
    }
    fname = _map.get((os_key, arch))
    if not fname:
        return jsonify({"error": f"Unsupported platform: {os_key}/{arch}"}), 400
    fpath = os.path.join(_EDR_PKG_DIR, fname)
    if not os.path.exists(fpath):
        return jsonify({
            "error": f"Agent binary not built for {os_key}/{arch}. Run agent-packages/build-edr-packages.sh"
        }), 404
    return send_file(fpath, as_attachment=True, download_name=fname,
                     mimetype="application/octet-stream")


@edr_bp.route("/installer/sysmon-config", methods=["GET"])
def installer_sysmon_config():
    """Serve CyCentra Sysmon XML config for Windows deployment."""
    err = _require_deploy_token()
    if err:
        return err
    fpath = os.path.join(_EDR_PKG_DIR, "cycentra_sysmon_config.xml")
    if not os.path.exists(fpath):
        return jsonify({"error": "Sysmon config not staged"}), 404
    return send_file(fpath, mimetype="application/xml")


@edr_bp.route("/installer/sysmon-exe", methods=["GET"])
def installer_sysmon_exe():
    """Serve Sysmon64.exe for Windows deployment."""
    err = _require_deploy_token()
    if err:
        return err
    fpath = os.path.join(_EDR_PKG_DIR, "Sysmon64.exe")
    if not os.path.exists(fpath):
        return jsonify({"error": "Sysmon64.exe not staged"}), 404
    return send_file(fpath, as_attachment=True, mimetype="application/octet-stream")


@edr_bp.route("/installer/yara-rules", methods=["GET"])
def installer_yara_rules():
    """Serve bundled YARA rules for CyEDR scanning."""
    err = _require_deploy_token()
    if err:
        return err
    fpath = os.path.join(_EDR_PKG_DIR, "cycentra.yar")
    if not os.path.exists(fpath):
        return jsonify({"error": "YARA rules not staged"}), 404
    return send_file(fpath, mimetype="text/plain")


@edr_bp.route("/installer/yara-exe", methods=["GET"])
def installer_yara_exe():
    """Serve yara64.exe for Windows."""
    err = _require_deploy_token()
    if err:
        return err
    fpath = os.path.join(_EDR_PKG_DIR, "yara64.exe")
    if not os.path.exists(fpath):
        return jsonify({"error": "yara64.exe not staged"}), 404
    return send_file(fpath, as_attachment=True, mimetype="application/octet-stream")


@edr_bp.route("/installer/cysiem-script", methods=["GET"])
def installer_cysiem_script():
    """Serve CySIEM (Wazuh) shell installer for Linux/macOS."""
    err = _require_deploy_token()
    if err:
        return err
    fpath = os.path.join(_EDR_PKG_DIR, "cysiem-install.sh")
    if not os.path.exists(fpath):
        return jsonify({"error": "CySIEM installer script not staged"}), 404
    return send_file(fpath, mimetype="text/x-shellscript")


@edr_bp.route("/installer/cysiem-msi", methods=["GET"])
def installer_cysiem_msi():
    """Serve Wazuh MSI for Windows CySIEM installation."""
    err = _require_deploy_token()
    if err:
        return err
    # Serve from the Wazuh agent packages directory
    from core.config import CY360_VERSION
    wazuh_dir = "/var/lib/cycentra-agent-packages"
    arch = request.args.get("arch", "x64")
    fname = f"cy360-agent-{CY360_VERSION}.msi"
    fpath = os.path.join(wazuh_dir, fname)
    if not os.path.exists(fpath):
        return jsonify({"error": f"CySIEM MSI not found: {fname}"}), 404
    return send_file(fpath, as_attachment=True, mimetype="application/octet-stream")


@edr_bp.route("/installer/unix", methods=["GET"])
def installer_unix_script():
    """Serve the CyEDR Unix installer shell script (no auth — public endpoint)."""
    fpath = os.path.join(os.path.dirname(__file__), "../../../../scripts/cyedr-install.sh")
    fpath = os.path.realpath(fpath)
    if not os.path.exists(fpath):
        return jsonify({"error": "Unix installer not found on platform"}), 404
    return send_file(fpath, mimetype="text/x-shellscript")


@edr_bp.route("/installer/win", methods=["GET"])
def installer_win_script():
    """Serve the CyEDR Windows PowerShell installer (no auth — public endpoint)."""
    fpath = os.path.join(os.path.dirname(__file__), "../../../../scripts/cyedr-install.ps1")
    fpath = os.path.realpath(fpath)
    if not os.path.exists(fpath):
        return jsonify({"error": "Windows installer not found on platform"}), 404
    return send_file(fpath, mimetype="text/plain")


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


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM YARA RULES — Zero-Day / Threat Intel Hunting
# Admins upload analyst-authored YARA rules. Agents fetch merged ruleset on
# their hourly IOC sync. Fleet-scan pushes RUN_SCAN to all active agents.
# ═══════════════════════════════════════════════════════════════════════════════

for _yp in ("/yara-rules/custom", "/yara-rules/custom/<rule_id>",
            "/yara-rules/custom/<rule_id>/activate",
            "/yara-rules/custom/<rule_id>/deactivate",
            "/fleet-scan", "/installer/custom-yara"):
    edr_bp.add_url_rule(
        _yp,
        endpoint=f"opts_yara_{_yp.replace('/','_').replace('<','').replace('>','')}",
        view_func=lambda **_: add_cors_headers(make_response("", 204)),
        methods=["OPTIONS"],
    )


@edr_bp.route("/yara-rules/custom", methods=["GET"])
@require_viewer
def list_custom_yara_rules():
    """Return all custom YARA rules with metadata and match counts."""
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, threat_name, mitre_id, author, active,
                       created_at, updated_at, last_deployed, match_count,
                       LENGTH(rule_text) AS rule_size
                FROM edr_custom_yara_rules
                ORDER BY created_at DESC
            """)
            rules = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"rules": rules, "total": len(rules)})
    except psycopg2.Error as exc:
        _log.error("list_custom_yara_rules DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@edr_bp.route("/yara-rules/custom", methods=["POST"])
@require_admin
def create_custom_yara_rule():
    """
    Upload a new custom YARA rule.

    Body: { name, threat_name, rule_text, mitre_id?, author? }

    The rule_text must be valid YARA syntax. The platform validates it with
    the yara Python bindings before storing.
    """
    body        = request.get_json(force=True, silent=True) or {}
    name        = (body.get("name") or "").strip()
    threat_name = (body.get("threat_name") or "").strip()
    rule_text   = (body.get("rule_text") or "").strip()
    mitre_id    = (body.get("mitre_id") or "").strip() or None
    author      = session.get("user_email", "unknown")

    if not name:
        return jsonify({"error": "name is required"}), 400
    if not threat_name:
        return jsonify({"error": "threat_name is required"}), 400
    if not rule_text:
        return jsonify({"error": "rule_text is required"}), 400

    # Validate YARA syntax before storing
    try:
        import yara
        yara.compile(source=rule_text)
    except ImportError:
        pass  # yara-python not installed on platform host — skip validation
    except Exception as exc:
        return jsonify({"error": f"Invalid YARA syntax: {exc}"}), 400

    rule_id = str(uuid.uuid4())
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO edr_custom_yara_rules
                  (id, name, threat_name, mitre_id, rule_text, author)
                VALUES (%s,%s,%s,%s,%s,%s)
                RETURNING id, name, threat_name, active, created_at
                """,
                [rule_id, name, threat_name, mitre_id, rule_text, author],
            )
            row = dict(cur.fetchone())
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("create_custom_yara_rule DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    auth_event(author, "yara_rule_create", f"Created custom YARA rule: {name} (threat: {threat_name})")
    return jsonify(row), 201


@edr_bp.route("/yara-rules/custom/<rule_id>", methods=["GET"])
@require_viewer
def get_custom_yara_rule(rule_id):
    """Return full detail including rule_text for a single custom YARA rule."""
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM edr_custom_yara_rules WHERE id = %s",
                [rule_id],
            )
            row = cur.fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Rule not found"}), 404
        return jsonify(dict(row))
    except psycopg2.Error as exc:
        _log.error("get_custom_yara_rule DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@edr_bp.route("/yara-rules/custom/<rule_id>", methods=["PUT"])
@require_admin
def update_custom_yara_rule(rule_id):
    """Update name, threat_name, mitre_id, or rule_text of a custom YARA rule."""
    body = request.get_json(force=True, silent=True) or {}
    fields, vals = [], []
    for col in ("name", "threat_name", "mitre_id", "rule_text"):
        if col in body:
            if col == "rule_text":
                try:
                    import yara
                    yara.compile(source=body[col])
                except ImportError:
                    pass
                except Exception as exc:
                    return jsonify({"error": f"Invalid YARA syntax: {exc}"}), 400
            fields.append(f"{col} = %s")
            vals.append(body[col])
    if not fields:
        return jsonify({"error": "No updatable fields provided"}), 400
    fields.append("updated_at = NOW()")
    vals.append(rule_id)
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE edr_custom_yara_rules SET {', '.join(fields)} WHERE id = %s RETURNING id",
                vals,
            )
            if not cur.fetchone():
                conn.close()
                return jsonify({"error": "Rule not found"}), 404
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("update_custom_yara_rule DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500
    auth_event(session.get("user_email", ""), "yara_rule_update", f"Updated YARA rule {rule_id}")
    return jsonify({"updated": rule_id})


@edr_bp.route("/yara-rules/custom/<rule_id>", methods=["DELETE"])
@require_admin
def delete_custom_yara_rule(rule_id):
    """Permanently remove a custom YARA rule."""
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM edr_custom_yara_rules WHERE id = %s RETURNING name",
                [rule_id],
            )
            row = cur.fetchone()
        conn.commit()
        conn.close()
        if not row:
            return jsonify({"error": "Rule not found"}), 404
    except psycopg2.Error as exc:
        _log.error("delete_custom_yara_rule DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500
    auth_event(session.get("user_email", ""), "yara_rule_delete", f"Deleted YARA rule {rule_id}: {row['name']}")
    return jsonify({"deleted": rule_id})


@edr_bp.route("/yara-rules/custom/<rule_id>/activate", methods=["POST"])
@require_admin
def activate_yara_rule(rule_id):
    """Enable a previously deactivated custom YARA rule."""
    return _set_yara_active(rule_id, True)


@edr_bp.route("/yara-rules/custom/<rule_id>/deactivate", methods=["POST"])
@require_admin
def deactivate_yara_rule(rule_id):
    """Disable a custom YARA rule without deleting it."""
    return _set_yara_active(rule_id, False)


def _set_yara_active(rule_id: str, active: bool):
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE edr_custom_yara_rules SET active=%s, updated_at=NOW() WHERE id=%s RETURNING id",
                [active, rule_id],
            )
            if not cur.fetchone():
                conn.close()
                return jsonify({"error": "Rule not found"}), 404
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("set_yara_active DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500
    state = "activated" if active else "deactivated"
    auth_event(session.get("user_email", ""), f"yara_rule_{state}", f"YARA rule {rule_id} {state}")
    return jsonify({"rule_id": rule_id, "active": active})


@edr_bp.route("/installer/custom-yara", methods=["GET"])
@require_agent_token
def installer_custom_yara(agent_id):
    """
    Agent-facing: return all active custom YARA rules merged into one text block.
    Agents poll this on their hourly IOC sync cycle and write the result to
    {edr_home}/custom.yar. The RUN_SCAN handler then compiles and applies both
    cycentra.yar and custom.yar.
    """
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, threat_name, rule_text
                FROM edr_custom_yara_rules
                WHERE active = TRUE
                ORDER BY created_at ASC
                """,
            )
            rows = cur.fetchall()
            # stamp last_deployed for every active rule
            if rows:
                cur.execute(
                    "UPDATE edr_custom_yara_rules SET last_deployed=NOW() WHERE active=TRUE",
                )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("installer_custom_yara DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    if not rows:
        return "/* CyCentra: no active custom YARA rules */\n", 200, {"Content-Type": "text/plain"}

    parts = [
        "/* CyCentra Custom YARA Rules — auto-generated */",
        f"/* Rules: {len(rows)} | Generated: {datetime.now(timezone.utc).isoformat()} */",
        "",
    ]
    for row in rows:
        parts.append(f"/* Rule: {row['name']} | Threat: {row['threat_name']} | ID: {row['id']} */")
        parts.append(row["rule_text"].strip())
        parts.append("")

    return "\n".join(parts), 200, {"Content-Type": "text/plain"}


@edr_bp.route("/fleet-scan", methods=["POST"])
@require_analyst
def fleet_scan():
    """
    Push a RUN_SCAN command to all currently active EDR agents simultaneously.

    Body (optional): { scan_path, yara_rules, reason }

    Returns: { queued, agents, scan_id }

    This is the zero-day response trigger: an analyst writes a custom YARA rule,
    uploads it via POST /api/edr/yara-rules/custom, then calls this endpoint to
    scan the entire fleet without waiting for the next scheduled hunt cycle.
    """
    body      = request.get_json(force=True, silent=True) or {}
    scan_path = body.get("scan_path", "/")
    yara_set  = body.get("yara_rules", "all")
    reason    = body.get("reason", "on-demand fleet scan")
    issued_by = session.get("user_email", "system")

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT agent_id, hostname FROM edr_agents WHERE status='active'",
            )
            agents = [dict(r) for r in cur.fetchall()]
        conn.close()
    except psycopg2.Error as exc:
        _log.error("fleet_scan agent query error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    if not agents:
        return jsonify({"queued": 0, "agents": [], "message": "No active agents found"}), 200

    scan_id = str(uuid.uuid4())
    queued  = []
    for ag in agents:
        try:
            queue_response_command(
                CYCENTRA_DB_URL,
                ag["agent_id"],
                "RUN_SCAN",
                {
                    "scan_path":  scan_path,
                    "yara_rules": yara_set,
                    "scan_id":    scan_id,
                    "reason":     reason,
                },
                issued_by,
                auto_triggered=False,
            )
            queued.append(ag["agent_id"])
        except Exception as exc:
            _log.warning("fleet_scan: failed to queue for agent %s: %s", ag["agent_id"], exc)

    auth_event(
        issued_by, "fleet_scan_triggered",
        f"Fleet scan {scan_id} queued for {len(queued)}/{len(agents)} agents. Reason: {reason}",
    )
    return jsonify({
        "scan_id": scan_id,
        "queued":  len(queued),
        "agents":  queued,
        "message": f"RUN_SCAN queued for {len(queued)} active agents",
    })
