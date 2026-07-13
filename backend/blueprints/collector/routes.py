"""
blueprints/collector/routes.py
================================
CyCollector — Phase 1 of the CyDataLake initiative.

Generic host log collection agent enrollment + ingest. This is a
collection-only path today: events land in the existing SIEM correlation
pipeline as low-severity/"system"-category alerts via cysiemstack/
collector_bridge.py. No decode/detection engine exists yet (that is a
separate, later phase) — do not expect rule-engine parity with Wazuh from
this endpoint alone.

Mounts at /api/collector/* in app.py.

Auth model (dual-mode, same convention as CyEDR):
  UI routes    — standard Flask session RBAC (viewer/analyst/admin)
  Agent routes — Bearer enrollment token in Authorization header

RBAC summary:
  GET  /api/collector/agents          → viewer+
  GET  /api/collector/agents/<id>     → viewer+
  POST /api/collector/agents/self-enroll → deployment token (no session)
  POST /api/collector/logs            → enrollment token (no session)
  POST /api/collector/heartbeat        → enrollment token (no session)

Deployment tokens are reused from the existing CyEDR deployment-token table
(edr_deployment_tokens / policy_engine.validate_deployment_token) rather than
standing up a parallel token-admin subsystem for a Phase 1 collector — the
token model (expiry, max_uses, revocation) is generic, not EDR-specific.
"""
from __future__ import annotations
import logging
import uuid
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session, make_response

from blueprints.rbac.manager import get_user_role
from core.helpers import add_cors_headers
from core.config import CYCENTRA_DB_URL

_log = logging.getLogger(__name__)

collector_bp = Blueprint("collector", __name__, url_prefix="/api/collector")


def _db():
    return psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def ensure_tables(db_url: str = CYCENTRA_DB_URL) -> None:
    """Create collector_agents table if it doesn't exist (called at app startup)."""
    ddl = """
    CREATE TABLE IF NOT EXISTS collector_agents (
        agent_id         TEXT PRIMARY KEY,
        hostname         TEXT NOT NULL,
        os_type          TEXT NOT NULL,
        agent_ip         TEXT,
        hardware_uuid    TEXT,
        enrollment_token TEXT NOT NULL,
        enrolled_by      TEXT,
        enrolled_at      TIMESTAMPTZ DEFAULT NOW(),
        last_seen        TIMESTAMPTZ,
        status           TEXT DEFAULT 'active',
        version          TEXT,
        source_types     JSONB DEFAULT '[]'::jsonb,
        events_shipped   BIGINT DEFAULT 0,
        metadata         JSONB DEFAULT '{}'::jsonb
    );
    CREATE UNIQUE INDEX IF NOT EXISTS collector_agents_hw_uuid_idx
        ON collector_agents(hardware_uuid) WHERE hardware_uuid IS NOT NULL;
    """
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


# ── Session RBAC helpers ──────────────────────────────────────────────────────

def _session_role() -> str | None:
    email = session.get("user_email", "")
    return get_user_role(email) if email else None


def _require_viewer():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    return None


# ── Agent bearer-token helper ─────────────────────────────────────────────────

def _agent_from_bearer():
    """Look up the collector_agents row matching the Bearer enrollment token.
    Returns (agent_row, None) on success or (None, (response, status)) on failure."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "Bearer enrollment token required"}), 401)
    token = auth[len("Bearer "):].strip()
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM collector_agents WHERE enrollment_token=%s AND status='active'",
                [token],
            )
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None, (jsonify({"error": "Invalid or inactive enrollment token"}), 401)
    return row, None


# ── Self-enrollment ────────────────────────────────────────────────────────────

@collector_bp.route("/agents/self-enroll", methods=["OPTIONS"])
def opt_self_enroll():
    return add_cors_headers(make_response("", 204))


@collector_bp.route("/agents/self-enroll", methods=["POST"])
def self_enroll_agent():
    """
    Body: { deployment_token, hostname, os_type, agent_ip, version, hardware_uuid }
    Returns { agent_id, enrollment_token }
    """
    from blueprints.edr.policy_engine import validate_deployment_token

    body   = request.get_json(force=True, silent=True) or {}
    dtoken = body.get("deployment_token", "")
    if not dtoken or not validate_deployment_token(CYCENTRA_DB_URL, dtoken):
        return jsonify({"error": "Invalid or expired deployment token"}), 401

    hostname      = (body.get("hostname") or "").strip()
    os_type       = (body.get("os_type") or "UNKNOWN").upper()
    agent_ip      = body.get("agent_ip", "")
    version       = body.get("version", "")
    hardware_uuid = (body.get("hardware_uuid") or "").strip().upper() or None
    if not hostname:
        return jsonify({"error": "hostname required"}), 400

    import secrets as _s
    token = _s.token_urlsafe(48)
    try:
        conn = _db()
        with conn.cursor() as cur:
            row = None

            # Pass 1: match by hardware_uuid — survives hostname changes and reinstalls.
            if hardware_uuid:
                cur.execute(
                    """
                    UPDATE collector_agents
                       SET enrollment_token=%s, os_type=%s, agent_ip=%s,
                           version=%s, enrolled_by='self-enrollment',
                           hostname=%s, status='active', last_seen=NOW()
                     WHERE hardware_uuid=%s
                    RETURNING agent_id
                    """,
                    [token, os_type, agent_ip, version, hostname, hardware_uuid],
                )
                row = cur.fetchone()

            # Pass 2: match by hostname (backwards compat — agents without hardware_uuid).
            if not row:
                cur.execute(
                    """
                    UPDATE collector_agents
                       SET enrollment_token=%s, os_type=%s, agent_ip=%s,
                           version=%s, enrolled_by='self-enrollment',
                           hardware_uuid=COALESCE(hardware_uuid, %s),
                           status='active', last_seen=NOW()
                     WHERE hostname=%s
                    RETURNING agent_id
                    """,
                    [token, os_type, agent_ip, version, hardware_uuid, hostname],
                )
                row = cur.fetchone()

            if row:
                agent_id = row["agent_id"]
            else:
                agent_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO collector_agents
                      (agent_id, hostname, os_type, agent_ip, enrollment_token,
                       enrolled_by, version, hardware_uuid)
                    VALUES (%s,%s,%s,%s,%s,'self-enrollment',%s,%s)
                    """,
                    [agent_id, hostname, os_type, agent_ip, token, version, hardware_uuid],
                )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("collector self_enroll DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    return jsonify({
        "agent_id":         agent_id,
        "enrollment_token": token,
        "message":          "Agent enrolled successfully",
    }), 201


# ── Log ingest ─────────────────────────────────────────────────────────────────

@collector_bp.route("/logs", methods=["OPTIONS"])
def opt_logs():
    return add_cors_headers(make_response("", 204))


@collector_bp.route("/logs", methods=["POST"])
def ingest_logs():
    """
    Agent-facing: Bearer enrollment token.
    Body: { events: [ {source_type, timestamp, program, severity, message, raw, metadata}, ... ] }
    """
    from cysiemstack.collector_bridge import push_collector_events

    agent, err = _agent_from_bearer()
    if err:
        return err

    body   = request.get_json(force=True, silent=True) or {}
    events = body.get("events") or []
    if not isinstance(events, list) or not events:
        return jsonify({"error": "events[] required"}), 400
    if len(events) > 5000:
        return jsonify({"error": "Batch too large (max 5000 events)"}), 400

    pushed = push_collector_events(dict(agent), events)

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE collector_agents
                   SET last_seen=NOW(), events_shipped = events_shipped + %s
                 WHERE agent_id=%s
                """,
                [pushed, agent["agent_id"]],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("collector ingest_logs DB update failed: %s", exc)

    return jsonify({"received": len(events), "pushed": pushed}), 202


# ── Heartbeat ──────────────────────────────────────────────────────────────────

@collector_bp.route("/heartbeat", methods=["OPTIONS"])
def opt_heartbeat():
    return add_cors_headers(make_response("", 204))


@collector_bp.route("/heartbeat", methods=["POST"])
def heartbeat():
    """Agent-facing: Bearer enrollment token. Body: { source_types, version }"""
    import json as _json

    agent, err = _agent_from_bearer()
    if err:
        return err

    body         = request.get_json(force=True, silent=True) or {}
    source_types = body.get("source_types") or []
    version      = body.get("version", "")

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE collector_agents
                   SET last_seen=NOW(), source_types=%s, version=COALESCE(NULLIF(%s,''), version)
                 WHERE agent_id=%s
                """,
                [_json.dumps(source_types), version, agent["agent_id"]],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("collector heartbeat DB update failed: %s", exc)
        return jsonify({"error": "Database error"}), 500

    return jsonify({"ok": True}), 200


# ── UI-facing agent list (viewer+) ────────────────────────────────────────────

@collector_bp.route("/agents", methods=["GET"])
def list_agents():
    err = _require_viewer()
    if err:
        return err
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT agent_id, hostname, os_type, agent_ip, last_seen, status,
                       version, source_types, events_shipped, enrolled_at
                  FROM collector_agents
                 ORDER BY last_seen DESC NULLS LAST
                """
            )
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({"agents": [dict(r) for r in rows]}), 200


@collector_bp.route("/agents/<agent_id>", methods=["GET"])
def agent_detail(agent_id):
    err = _require_viewer()
    if err:
        return err
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM collector_agents WHERE agent_id=%s", [agent_id])
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Agent not found"}), 404
    out = dict(row)
    out.pop("enrollment_token", None)
    return jsonify(out), 200
