"""
blueprints/connectors/routes.py
==================================
CyDataLake multi-vendor SIEM connectors — CRUD + manual/scheduled polling.

Mounts at /api/connectors/* in app.py. Session RBAC only (no agent/Bearer
auth here — unlike collector/edr, nothing external calls this; polling is
server-initiated against each configured vendor's API).

RBAC:
  GET    /api/connectors            → viewer+
  GET    /api/connectors/<id>       → viewer+
  POST   /api/connectors            → admin
  PUT    /api/connectors/<id>       → admin
  DELETE /api/connectors/<id>       → admin
  POST   /api/connectors/<id>/test  → analyst+
  POST   /api/connectors/<id>/pull  → analyst+ (manual trigger, same code path the scheduler uses)

Secret fields (password/api_token/sec_token/api_key) are masked as
"•STORED•" in every GET response and never accepted back as a literal value
on PUT — same convention as blueprints/itam/routes.py's itam_settings().
"""
from __future__ import annotations
import json
import logging
import uuid
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session, make_response

from blueprints.rbac.manager import get_user_role
from core.helpers import add_cors_headers
from core.config import CYCENTRA_DB_URL
from cysiemstack.connectors.registry import CONNECTOR_REGISTRY, build_connector

_log = logging.getLogger(__name__)

connectors_bp = Blueprint("connectors", __name__, url_prefix="/api/connectors")

_SECRET_KEYS = {"password", "api_token", "sec_token", "api_key"}
_STORED_SENTINEL = "•STORED•"


def _db():
    return psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def ensure_tables(db_url: str = CYCENTRA_DB_URL) -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS siem_connectors (
        id                TEXT PRIMARY KEY,
        vendor            TEXT NOT NULL,
        name              TEXT NOT NULL,
        enabled           BOOLEAN DEFAULT TRUE,
        config            JSONB DEFAULT '{}'::jsonb,
        poll_interval_sec INTEGER DEFAULT 300,
        last_cursor       TEXT,
        last_pull_at      TIMESTAMPTZ,
        last_status       TEXT DEFAULT 'never_run',
        last_error        TEXT,
        events_pulled     BIGINT DEFAULT 0,
        created_by        TEXT,
        created_at        TIMESTAMPTZ DEFAULT NOW(),
        updated_at        TIMESTAMPTZ DEFAULT NOW()
    );
    """
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()
    finally:
        conn.close()


def _mask(row: dict) -> dict:
    out = dict(row)
    cfg = dict(out.get("config") or {})
    for k in _SECRET_KEYS:
        if cfg.get(k):
            cfg[k] = _STORED_SENTINEL
    out["config"] = cfg
    return out


def _role() -> str | None:
    email = session.get("user_email", "")
    return get_user_role(email) if email else None


def _require(min_role: str):
    order = {"viewer": 0, "analyst": 1, "admin": 2}
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if order.get(_role(), -1) < order[min_role]:
        return jsonify({"error": f"{min_role.capitalize()} role or higher required"}), 403
    return None


# ── CRUD ───────────────────────────────────────────────────────────────────────

@connectors_bp.route("", methods=["GET", "POST", "OPTIONS"])
def connectors_collection():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))

    if request.method == "GET":
        err = _require("viewer")
        if err:
            return err
        conn = _db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM siem_connectors ORDER BY created_at DESC")
                rows = cur.fetchall()
        finally:
            conn.close()
        return jsonify({"connectors": [_mask(dict(r)) for r in rows]}), 200

    # POST — admin only
    err = _require("admin")
    if err:
        return err
    body   = request.get_json(force=True, silent=True) or {}
    vendor = body.get("vendor", "")
    name   = (body.get("name") or "").strip()
    if vendor not in CONNECTOR_REGISTRY:
        return jsonify({"error": f"Unknown vendor. Supported: {sorted(CONNECTOR_REGISTRY)}"}), 400
    if not name:
        return jsonify({"error": "name required"}), 400

    conn_id = str(uuid.uuid4())
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO siem_connectors
                  (id, vendor, name, enabled, config, poll_interval_sec, created_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                [conn_id, vendor, name, bool(body.get("enabled", True)),
                 json.dumps(body.get("config") or {}),
                 int(body.get("poll_interval_sec", 300)),
                 session.get("user_email", "")],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("connectors create DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500

    return jsonify({"id": conn_id, "vendor": vendor, "name": name}), 201


@connectors_bp.route("/<conn_id>", methods=["GET", "PUT", "DELETE", "OPTIONS"])
def connector_detail(conn_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM siem_connectors WHERE id=%s", [conn_id])
            row = cur.fetchone()

            if request.method == "GET":
                err = _require("viewer")
                if err:
                    return err
                if not row:
                    return jsonify({"error": "Connector not found"}), 404
                return jsonify(_mask(dict(row))), 200

            if not row:
                return jsonify({"error": "Connector not found"}), 404

            if request.method == "DELETE":
                err = _require("admin")
                if err:
                    return err
                cur.execute("DELETE FROM siem_connectors WHERE id=%s", [conn_id])
                conn.commit()
                return jsonify({"deleted": True}), 200

            # PUT — admin only
            err = _require("admin")
            if err:
                return err
            body = request.get_json(force=True, silent=True) or {}

            new_config = dict(row["config"] or {})
            for k, v in (body.get("config") or {}).items():
                if k in _SECRET_KEYS and (v == _STORED_SENTINEL or v == ""):
                    continue  # unchanged — never overwrite a stored secret with the masked sentinel
                new_config[k] = v

            cur.execute(
                """
                UPDATE siem_connectors
                   SET name=%s, enabled=%s, config=%s, poll_interval_sec=%s, updated_at=NOW()
                 WHERE id=%s
                """,
                [body.get("name", row["name"]),
                 bool(body.get("enabled", row["enabled"])),
                 json.dumps(new_config),
                 int(body.get("poll_interval_sec", row["poll_interval_sec"])),
                 conn_id],
            )
            conn.commit()
            return jsonify({"updated": True}), 200
    except psycopg2.Error as exc:
        _log.error("connector_detail DB error: %s", exc)
        return jsonify({"error": "Database error"}), 500
    finally:
        conn.close()


# ── Test connection ────────────────────────────────────────────────────────────

@connectors_bp.route("/<conn_id>/test", methods=["POST", "OPTIONS"])
def test_connector(conn_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    err = _require("analyst")
    if err:
        return err

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM siem_connectors WHERE id=%s", [conn_id])
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Connector not found"}), 404

    try:
        connector = build_connector(row["vendor"], row["config"] or {})
        ok, message = connector.test_connection()
    except Exception as exc:
        return jsonify({"ok": False, "message": str(exc)}), 200
    return jsonify({"ok": ok, "message": message}), 200


# ── Manual pull trigger (same code path the scheduler uses) ──────────────────

@connectors_bp.route("/<conn_id>/pull", methods=["POST", "OPTIONS"])
def pull_connector_now(conn_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    err = _require("analyst")
    if err:
        return err

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM siem_connectors WHERE id=%s", [conn_id])
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Connector not found"}), 404

    result = run_connector_pull(dict(row))
    status_code = 200 if result["status"] == "ok" else 502
    return jsonify(result), status_code


# ── Shared pull logic (used by manual trigger + scheduler job) ───────────────

def run_connector_pull(row: dict) -> dict:
    """Execute one pull cycle for a single connector row and persist the
    result (cursor/status/error/counters). Never raises — errors are caught
    and recorded on the row so a bad vendor tenant can't crash the scheduler."""
    from cysiemstack.connector_bridge import push_connector_events

    conn_id = row["id"]
    vendor  = row["vendor"]
    pushed  = 0
    status  = "ok"
    error   = None
    next_cursor = row.get("last_cursor")

    try:
        connector = build_connector(vendor, row.get("config") or {})
        events, next_cursor = connector.pull(row.get("last_cursor"))
        pushed = push_connector_events(vendor, events)
    except Exception as exc:
        status = "error"
        error  = str(exc)[:2000]
        _log.error("Connector pull failed id=%s vendor=%s: %s", conn_id, vendor, exc)

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE siem_connectors
                   SET last_cursor=%s, last_pull_at=NOW(), last_status=%s,
                       last_error=%s, events_pulled = events_pulled + %s
                 WHERE id=%s
                """,
                [next_cursor, status, error, pushed, conn_id],
            )
        conn.commit()
        conn.close()
    except psycopg2.Error as exc:
        _log.error("Connector pull result persist failed id=%s: %s", conn_id, exc)

    return {"id": conn_id, "vendor": vendor, "status": status, "error": error, "events_pushed": pushed}


# ── Scheduler wiring ───────────────────────────────────────────────────────────

def _poll_due_connectors() -> None:
    """Runs every 60s (registered by register_connector_scheduler). Pulls any
    enabled connector whose poll_interval_sec has elapsed since last_pull_at."""
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM siem_connectors
                 WHERE enabled = TRUE
                   AND (last_pull_at IS NULL
                        OR last_pull_at < NOW() - (poll_interval_sec || ' seconds')::interval)
                """
            )
            due = cur.fetchall()
    finally:
        conn.close()

    for row in due:
        run_connector_pull(dict(row))


def register_connector_scheduler(scheduler) -> None:
    """Called from blueprints/scheduler/routes.py init_scheduler(). Registers
    a single dispatcher job that checks every connector's own poll_interval_sec
    — connectors don't each get a dedicated APScheduler job, since intervals
    are user-editable at runtime via PUT and a fixed dispatcher avoids having
    to add/remove/reschedule jobs whenever a connector's interval changes."""
    from apscheduler.triggers.interval import IntervalTrigger
    scheduler.add_job(
        _poll_due_connectors,
        trigger=IntervalTrigger(seconds=60),
        id="siem_connector_poll_dispatcher",
        name="SIEM Connector Poll Dispatcher",
        replace_existing=True,
        misfire_grace_time=120,
    )
