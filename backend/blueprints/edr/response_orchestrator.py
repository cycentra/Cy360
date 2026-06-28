"""
blueprints/edr/response_orchestrator.py
=========================================
EDR Response Action Orchestrator.

Maps SIEM incidents / EDR detections → containment commands queued for
agent execution.  Commands are stored in the `edr_response_commands` table;
agents poll GET /api/edr/response/<agent_id>/pending and acknowledge via
POST /api/edr/response/<agent_id>/commands/<cmd_id>/complete.

Supported response actions:
  ISOLATE           — block all network except EDR management channel
  UNISOLATE         — restore network connectivity
  KILL_PROCESS      — terminate process by PID or image name
  BLOCK_HASH        — add file hash to local blocklist
  COLLECT_FORENSICS — trigger memory/disk snapshot collection
  ROLLBACK          — restore files from VSS/APFS/Btrfs snapshot
  QUARANTINE_FILE   — move file to quarantine directory
  RUN_SCAN          — trigger on-demand YARA/AV scan

All write operations are audit-logged via core/helpers.auth_event.
"""
from __future__ import annotations
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
import psycopg2.extras

_log = logging.getLogger(__name__)

VALID_ACTIONS = {
    "ISOLATE",
    "UNISOLATE",
    "KILL_PROCESS",
    "BLOCK_HASH",
    "COLLECT_FORENSICS",
    "ROLLBACK",
    "QUARANTINE_FILE",
    "RUN_SCAN",
}

# Actions that require analyst+ role (all write actions)
ANALYST_ACTIONS = VALID_ACTIONS

# Score threshold above which critical detections auto-isolate
AUTO_ISOLATE_THRESHOLD = 90.0


def _get_db(db_url: str):
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = False
    return conn


def ensure_tables(db_url: str) -> None:
    """Create EDR tables if they don't exist (called at blueprint init)."""
    ddl = """
    CREATE TABLE IF NOT EXISTS edr_agents (
        agent_id        TEXT PRIMARY KEY,
        hostname        TEXT NOT NULL,
        os_type         TEXT NOT NULL,
        agent_ip        TEXT,
        asset_type      TEXT DEFAULT 'workstation',
        enrollment_token TEXT NOT NULL,
        enrolled_by     TEXT,
        enrolled_at     TIMESTAMPTZ DEFAULT NOW(),
        last_seen       TIMESTAMPTZ,
        status          TEXT DEFAULT 'active',
        version         TEXT,
        isolation_state TEXT DEFAULT 'normal',
        tags            JSONB DEFAULT '[]'::jsonb,
        metadata        JSONB DEFAULT '{}'::jsonb
    );

    CREATE TABLE IF NOT EXISTS edr_detections (
        id              TEXT PRIMARY KEY,
        agent_id        TEXT NOT NULL REFERENCES edr_agents(agent_id),
        event_uuid      TEXT UNIQUE,
        detected_at     TIMESTAMPTZ DEFAULT NOW(),
        severity        TEXT NOT NULL,
        score           NUMERIC(5,1) NOT NULL,
        rule_id         INTEGER,
        rule_desc       TEXT,
        mitre_id        TEXT,
        mitre_tactic    TEXT,
        event_category  TEXT,
        process_name    TEXT,
        process_path    TEXT,
        command_line    TEXT,
        file_path       TEXT,
        src_ip          TEXT,
        dst_ip          TEXT,
        username        TEXT,
        triggers        JSONB DEFAULT '[]'::jsonb,
        ti_match        BOOLEAN DEFAULT FALSE,
        status          TEXT DEFAULT 'open',
        siem_incident_id TEXT,
        case_id         TEXT,
        raw_envelope    JSONB,
        notes           TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_edr_det_agent    ON edr_detections(agent_id);
    CREATE INDEX IF NOT EXISTS idx_edr_det_severity ON edr_detections(severity, detected_at DESC);
    CREATE INDEX IF NOT EXISTS idx_edr_det_status   ON edr_detections(status);

    CREATE TABLE IF NOT EXISTS edr_response_commands (
        id              TEXT PRIMARY KEY,
        agent_id        TEXT NOT NULL REFERENCES edr_agents(agent_id),
        action          TEXT NOT NULL,
        parameters      JSONB DEFAULT '{}'::jsonb,
        status          TEXT DEFAULT 'pending',
        issued_by       TEXT,
        issued_at       TIMESTAMPTZ DEFAULT NOW(),
        acknowledged_at TIMESTAMPTZ,
        completed_at    TIMESTAMPTZ,
        result          JSONB,
        detection_id    TEXT REFERENCES edr_detections(id),
        incident_id     TEXT,
        auto_triggered  BOOLEAN DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_edr_cmd_agent  ON edr_response_commands(agent_id, status);
    CREATE INDEX IF NOT EXISTS idx_edr_cmd_status ON edr_response_commands(status, issued_at DESC);

    CREATE TABLE IF NOT EXISTS edr_custom_yara_rules (
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        threat_name     TEXT NOT NULL,
        mitre_id        TEXT,
        rule_text       TEXT NOT NULL,
        author          TEXT,
        active          BOOLEAN DEFAULT TRUE,
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        updated_at      TIMESTAMPTZ DEFAULT NOW(),
        last_deployed   TIMESTAMPTZ,
        match_count     INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_edr_yara_active ON edr_custom_yara_rules(active, created_at DESC);
    """
    try:
        conn = _get_db(db_url)
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()
        conn.close()
    except Exception as exc:
        _log.warning("EDR table init failed (non-fatal): %s", exc)


def queue_response_command(
    db_url: str,
    agent_id: str,
    action: str,
    parameters: dict,
    issued_by: str,
    detection_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    auto_triggered: bool = False,
) -> dict[str, Any]:
    """
    Insert a new response command into the queue.

    Returns the created command record dict.
    Raises ValueError for unknown action or agent_id.
    """
    if action not in VALID_ACTIONS:
        raise ValueError(f"Unknown action: {action}. Valid: {sorted(VALID_ACTIONS)}")

    cmd_id = str(uuid.uuid4())
    conn = _get_db(db_url)
    try:
        with conn.cursor() as cur:
            # Verify agent exists
            cur.execute("SELECT agent_id FROM edr_agents WHERE agent_id = %s", [agent_id])
            if not cur.fetchone():
                raise ValueError(f"Agent not found: {agent_id}")

            cur.execute(
                """
                INSERT INTO edr_response_commands
                  (id, agent_id, action, parameters, issued_by, detection_id,
                   incident_id, auto_triggered)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING *
                """,
                [
                    cmd_id, agent_id, action,
                    json.dumps(parameters),
                    issued_by,
                    detection_id, incident_id, auto_triggered,
                ],
            )
            row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()

    return row


def get_pending_commands(db_url: str, agent_id: str) -> list[dict]:
    """Return pending commands for an agent (called by agent poll endpoint)."""
    conn = _get_db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, action, parameters, issued_at, incident_id
                FROM edr_response_commands
                WHERE agent_id = %s AND status = 'pending'
                ORDER BY issued_at ASC
                LIMIT 20
                """,
                [agent_id],
            )
            rows = [dict(r) for r in cur.fetchall()]
            if rows:
                ids = [r["id"] for r in rows]
                cur.execute(
                    "UPDATE edr_response_commands SET status='acknowledged', acknowledged_at=NOW() WHERE id = ANY(%s)",
                    [ids],
                )
        conn.commit()
    finally:
        conn.close()
    return rows


def complete_command(
    db_url: str,
    agent_id: str,
    cmd_id: str,
    result: dict,
    success: bool,
) -> None:
    """Agent calls this once the command has been executed."""
    final_status = "completed" if success else "failed"
    conn = _get_db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE edr_response_commands
                SET status=%s, completed_at=NOW(), result=%s
                WHERE id=%s AND agent_id=%s
                """,
                [final_status, json.dumps(result), cmd_id, agent_id],
            )
        conn.commit()
    finally:
        conn.close()


def auto_respond(
    db_url: str,
    detection: dict[str, Any],
    agent_id: str,
) -> list[str]:
    """
    Evaluate a new detection and automatically queue response actions based
    on severity and trigger type.

    Returns list of queued command IDs.
    """
    score     = float(detection.get("_edr_score", 0))
    triggers  = detection.get("_edr_triggers", [])
    severity  = detection.get("_edr_severity", "low")
    detection_id = detection.get("_detection_id")
    queued = []

    # Critical ransomware → immediate network isolation + forensic collection
    if "ransomware_canary" in triggers or "ransomware_extension" in triggers:
        for action, params in [
            ("ISOLATE",           {"reason": "Ransomware activity detected — auto-isolation"}),
            ("COLLECT_FORENSICS", {"scope": "memory,disk", "reason": "ransomware_response"}),
            ("ROLLBACK",          {"scope": "modified_files", "snapshot": "latest"}),
        ]:
            try:
                cmd = queue_response_command(
                    db_url, agent_id, action, params,
                    issued_by="cyedr-auto",
                    detection_id=detection_id,
                    auto_triggered=True,
                )
                queued.append(cmd["id"])
            except Exception as exc:
                _log.error("auto_respond queue failed: %s", exc)

    # High confidence lateral movement → isolate
    elif score >= AUTO_ISOLATE_THRESHOLD and "lateral_movement" in triggers:
        try:
            cmd = queue_response_command(
                db_url, agent_id, "ISOLATE",
                {"reason": f"Auto-isolation: score={score}, lateral movement"},
                issued_by="cyedr-auto",
                detection_id=detection_id,
                auto_triggered=True,
            )
            queued.append(cmd["id"])
        except Exception as exc:
            _log.error("auto_respond isolate failed: %s", exc)

    # Critical C2 beacon → block hash + quarantine
    elif "c2_beacon" in triggers and severity in ("critical", "high"):
        try:
            cmd = queue_response_command(
                db_url, agent_id, "COLLECT_FORENSICS",
                {"scope": "network,process", "reason": "c2_beacon_detected"},
                issued_by="cyedr-auto",
                detection_id=detection_id,
                auto_triggered=True,
            )
            queued.append(cmd["id"])
        except Exception as exc:
            _log.error("auto_respond c2 failed: %s", exc)

    return queued


def update_agent_isolation(db_url: str, agent_id: str, state: str) -> None:
    """Sync isolation state after ISOLATE/UNISOLATE command completes."""
    if state not in ("normal", "isolated", "partial"):
        return
    conn = _get_db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE edr_agents SET isolation_state=%s WHERE agent_id=%s",
                [state, agent_id],
            )
        conn.commit()
    finally:
        conn.close()
