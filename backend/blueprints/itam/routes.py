"""
blueprints/itam/routes.py
==========================
ITAM — IT Asset Management Blueprint.
Mounts at /api/itam/* in app.py.

Coverage tracks all network assets vs EDR/SIEM-enrolled subsets.
IoT registry classifies and risk-scores non-agent devices.
Shadow AI monitor surfaces unauthorized AI tool usage.

RBAC:
  GET  /api/itam/*            → viewer+
  POST /PUT /api/itam/*       → analyst+
  DELETE / import / scan      → admin
"""
from __future__ import annotations
import json
import logging
import threading
import uuid
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session, make_response

from blueprints.rbac.manager import get_user_role
from core.helpers import add_cors_headers, auth_event
from core.config import CYCENTRA_DB_URL, ITAM_SUBNET, ITAM_IOT_PORTS, ITAM_PROBE_CREDS

from .iot_classifier import oui_lookup, classify_ports, compute_risk_score, is_iot_candidate
from .network_discovery import parse_cmdb_csv, upsert_assets, parse_arp_neighbors, run_nmap_discovery

_log = logging.getLogger(__name__)

itam_bp = Blueprint("itam", __name__, url_prefix="/api/itam")

# ── DB helper ─────────────────────────────────────────────────────────────────

def _db():
    return psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


# ── RBAC decorators ───────────────────────────────────────────────────────────

def _role():
    email = session.get("user_email", "")
    return get_user_role(email) if email else None


def require_viewer(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*a, **kw)
    return _w


def require_analyst(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _role() not in ("admin", "analyst"):
            return jsonify({"error": "Analyst or admin role required"}), 403
        return f(*a, **kw)
    return _w


def require_admin(f):
    @wraps(f)
    def _w(*a, **kw):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        if _role() != "admin":
            return jsonify({"error": "Admin role required"}), 403
        return f(*a, **kw)
    return _w


# ── DB schema bootstrap ───────────────────────────────────────────────────────

def init_itam_tables(db_url: str) -> None:
    """Called by app.py after blueprint registration to set up DB tables."""
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_assets (
              id              SERIAL PRIMARY KEY,
              ip_address      INET NOT NULL,
              mac_address     TEXT,
              hostname        TEXT,
              vendor          TEXT,
              asset_type      TEXT DEFAULT 'unknown',
              edr_agent_id    TEXT,
              siem_agent_id   TEXT,
              os_fingerprint  TEXT,
              source          TEXT DEFAULT 'manual',
              last_seen       TIMESTAMPTZ DEFAULT NOW(),
              first_seen      TIMESTAMPTZ DEFAULT NOW(),
              tags            TEXT[] DEFAULT '{}',
              notes           TEXT,
              UNIQUE(ip_address)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS iot_devices (
              id                   SERIAL PRIMARY KEY,
              network_asset_id     INTEGER REFERENCES network_assets(id) ON DELETE CASCADE,
              ip_address           INET NOT NULL,
              mac_address          TEXT,
              vendor               TEXT,
              device_category      TEXT DEFAULT 'unknown',
              device_model         TEXT,
              firmware_version     TEXT,
              open_ports           JSONB DEFAULT '[]'::jsonb,
              default_creds_risk   BOOLEAN DEFAULT FALSE,
              risk_score           SMALLINT DEFAULT 50,
              risk_factors         JSONB DEFAULT '[]'::jsonb,
              status               TEXT DEFAULT 'active',
              last_seen            TIMESTAMPTZ DEFAULT NOW(),
              first_seen           TIMESTAMPTZ DEFAULT NOW(),
              notes                TEXT,
              tags                 TEXT[] DEFAULT '{}',
              UNIQUE(ip_address)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS shadow_ai_findings (
              id              SERIAL PRIMARY KEY,
              agent_id        TEXT,
              hostname        TEXT,
              ai_tool         TEXT NOT NULL,
              detection_layer TEXT NOT NULL,
              detail          JSONB DEFAULT '{}'::jsonb,
              severity        TEXT DEFAULT 'medium',
              status          TEXT DEFAULT 'open',
              detected_at     TIMESTAMPTZ DEFAULT NOW(),
              resolved_at     TIMESTAMPTZ,
              notes           TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ai_tool_whitelist (
              id          SERIAL PRIMARY KEY,
              tool_name   TEXT NOT NULL,
              tool_type   TEXT DEFAULT 'saas',
              department  TEXT DEFAULT 'ALL',
              approved_by TEXT,
              approved_at TIMESTAMPTZ DEFAULT NOW(),
              expires_at  TIMESTAMPTZ,
              notes       TEXT,
              UNIQUE(tool_name, department)
            )
        """)
        # Indexes
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_network_assets_ip ON network_assets(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_network_assets_type ON network_assets(asset_type)",
            "CREATE INDEX IF NOT EXISTS idx_network_assets_edr ON network_assets(edr_agent_id)",
            "CREATE INDEX IF NOT EXISTS idx_iot_devices_risk ON iot_devices(risk_score DESC)",
            "CREATE INDEX IF NOT EXISTS idx_shadow_ai_status ON shadow_ai_findings(status)",
            "CREATE INDEX IF NOT EXISTS idx_shadow_ai_tool ON shadow_ai_findings(ai_tool)",
        ]:
            cur.execute(stmt)
    conn.commit()
    conn.close()
    _log.info("ITAM tables initialised")


# ── Coverage ──────────────────────────────────────────────────────────────────

@itam_bp.route("/coverage", methods=["GET"])
@itam_bp.route("/coverage", methods=["OPTIONS"])
def _opts_coverage():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    return _coverage_get()


def _coverage_get():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _db()
        with conn.cursor() as cur:
            # Total network assets
            cur.execute("SELECT COUNT(*) AS n FROM network_assets")
            total = cur.fetchone()["n"]

            # EDR covered (has edr_agent_id)
            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE edr_agent_id IS NOT NULL")
            edr_covered = cur.fetchone()["n"]

            # SIEM covered (has siem_agent_id)
            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE siem_agent_id IS NOT NULL")
            siem_covered = cur.fetchone()["n"]

            # Both covered
            cur.execute("SELECT COUNT(*) AS n FROM network_assets WHERE edr_agent_id IS NOT NULL AND siem_agent_id IS NOT NULL")
            both_covered = cur.fetchone()["n"]

            # IoT devices
            cur.execute("SELECT COUNT(*) AS n FROM iot_devices WHERE status='active'")
            iot_count = cur.fetchone()["n"]

            # Shadow AI open findings
            cur.execute("SELECT COUNT(*) AS n FROM shadow_ai_findings WHERE status='open'")
            shadow_ai_open = cur.fetchone()["n"]

            # Breakdown by asset_type
            cur.execute("""
                SELECT asset_type,
                       COUNT(*) AS total,
                       COUNT(edr_agent_id) AS edr_covered,
                       COUNT(siem_agent_id) AS siem_covered
                FROM network_assets
                GROUP BY asset_type
                ORDER BY total DESC
            """)
            breakdown = {
                row["asset_type"]: {
                    "total":       row["total"],
                    "edr_covered": row["edr_covered"],
                    "siem_covered": row["siem_covered"],
                }
                for row in cur.fetchall()
            }

            # Source breakdown
            cur.execute("SELECT source, COUNT(*) AS n FROM network_assets GROUP BY source")
            sources = {row["source"]: row["n"] for row in cur.fetchall()}

        conn.close()

        uncovered = total - max(edr_covered, siem_covered)
        coverage_pct = round((max(edr_covered, siem_covered) / total * 100), 1) if total else 0.0

        return jsonify({
            "total_network_assets": total,
            "edr_covered":          edr_covered,
            "siem_covered":         siem_covered,
            "both_covered":         both_covered,
            "uncovered":            max(0, uncovered),
            "coverage_pct":         coverage_pct,
            "iot_devices":          iot_count,
            "shadow_ai_open":       shadow_ai_open,
            "breakdown":            breakdown,
            "sources":              sources,
        })
    except psycopg2.Error as exc:
        _log.error("coverage query error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── Asset list ────────────────────────────────────────────────────────────────

@itam_bp.route("/assets", methods=["GET", "OPTIONS"])
def assets_list():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    page     = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    offset   = (page - 1) * per_page
    atype    = request.args.get("asset_type", "")
    covered  = request.args.get("covered", "")   # "yes"/"no"/"edr"/"siem"
    search   = request.args.get("q", "")

    where_parts = []
    params = []
    if atype:
        where_parts.append("asset_type = %s"); params.append(atype)
    if covered == "no":
        where_parts.append("edr_agent_id IS NULL AND siem_agent_id IS NULL")
    elif covered == "edr":
        where_parts.append("edr_agent_id IS NOT NULL")
    elif covered == "siem":
        where_parts.append("siem_agent_id IS NOT NULL")
    elif covered == "yes":
        where_parts.append("(edr_agent_id IS NOT NULL OR siem_agent_id IS NOT NULL)")
    if search:
        where_parts.append("(hostname ILIKE %s OR ip_address::text ILIKE %s OR vendor ILIKE %s)")
        like = f"%{search}%"
        params += [like, like, like]

    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM network_assets {where}", params)
            total = cur.fetchone()["n"]
            cur.execute(f"""
                SELECT na.*,
                       ea.hostname AS edr_hostname, ea.status AS edr_status,
                       hpc.agent_name AS siem_hostname
                FROM network_assets na
                LEFT JOIN edr_agents ea ON ea.agent_id = na.edr_agent_id
                LEFT JOIN host_posture_cache hpc ON hpc.agent_id = na.siem_agent_id
                {where}
                ORDER BY na.last_seen DESC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("ip_address"):
                    r["ip_address"] = str(r["ip_address"])
        conn.close()
        return jsonify({"assets": rows, "total": total, "page": page, "per_page": per_page})
    except psycopg2.Error as exc:
        _log.error("assets_list error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/assets/<int:asset_id>", methods=["PUT", "OPTIONS"])
def asset_update(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403
    body = request.get_json(silent=True) or {}
    allowed = {"asset_type", "notes", "tags", "hostname", "vendor"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400
    try:
        conn = _db()
        with conn.cursor() as cur:
            set_clause = ", ".join(f"{k}=%s" for k in updates)
            cur.execute(
                f"UPDATE network_assets SET {set_clause} WHERE id=%s RETURNING id",
                list(updates.values()) + [asset_id],
            )
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Asset not found"}), 404
        conn.commit(); conn.close()
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("asset_update error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/assets/<int:asset_id>", methods=["DELETE", "OPTIONS"])
def asset_delete(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM network_assets WHERE id=%s RETURNING id", [asset_id])
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Asset not found"}), 404
        conn.commit(); conn.close()
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("asset_delete error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── CMDB Import ───────────────────────────────────────────────────────────────

@itam_bp.route("/assets/import", methods=["POST", "OPTIONS"])
def assets_import():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403

    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file uploaded"}), 400
    content = f.read()
    if len(content) > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (max 5 MB)"}), 413

    rows, errors = parse_cmdb_csv(content)
    if not rows and errors:
        return jsonify({"error": errors[0], "all_errors": errors}), 400

    try:
        conn = _db()
        imported = upsert_assets(conn, rows, source="manual")
        conn.close()
        # Trigger cross-reference to link EDR/SIEM agents
        threading.Thread(target=_crossref_agents, daemon=True).start()
        auth_event(session.get("user_email"), "itam_cmdb_import", f"Imported {imported} assets")
        return jsonify({"imported": imported, "warnings": errors})
    except psycopg2.Error as exc:
        _log.error("assets_import error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── Subnet Scan ───────────────────────────────────────────────────────────────

@itam_bp.route("/assets/scan", methods=["POST", "OPTIONS"])
def assets_scan():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403

    body   = request.get_json(silent=True) or {}
    subnet = body.get("subnet", ITAM_SUBNET)
    if not subnet:
        return jsonify({"error": "No subnet configured. Set ITAM_SUBNET in .env or pass subnet in body."}), 400

    def _run():
        assets = run_nmap_discovery(subnet, ITAM_IOT_PORTS)
        if assets:
            try:
                conn = _db()
                upsert_assets(conn, assets, source="nmap")
                # Classify IoT candidates from scan results
                _classify_iot_from_assets(conn, assets)
                _crossref_agents_conn(conn)
                conn.close()
            except Exception as exc:
                _log.error("scan background error: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
    auth_event(session.get("user_email"), "itam_subnet_scan", f"Subnet scan triggered: {subnet}")
    return jsonify({"ok": True, "subnet": subnet, "message": "Scan started in background"})


# ── IoT Registry ──────────────────────────────────────────────────────────────

@itam_bp.route("/iot", methods=["GET", "OPTIONS"])
def iot_list():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    page     = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    offset   = (page - 1) * per_page
    risk_min = int(request.args.get("risk_min", 0))
    cat      = request.args.get("category", "")

    where_parts = ["status='active'"]
    params = []
    if risk_min:
        where_parts.append("risk_score >= %s"); params.append(risk_min)
    if cat:
        where_parts.append("device_category = %s"); params.append(cat)
    where = "WHERE " + " AND ".join(where_parts)

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM iot_devices {where}", params)
            total = cur.fetchone()["n"]
            cur.execute(f"""
                SELECT * FROM iot_devices {where}
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("ip_address"): r["ip_address"] = str(r["ip_address"])
        conn.close()
        return jsonify({"devices": rows, "total": total, "page": page, "per_page": per_page})
    except psycopg2.Error as exc:
        _log.error("iot_list error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/iot/risk-summary", methods=["GET", "OPTIONS"])
def iot_risk_summary():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                  COUNT(*) FILTER (WHERE risk_score >= 75) AS critical,
                  COUNT(*) FILTER (WHERE risk_score >= 50 AND risk_score < 75) AS high,
                  COUNT(*) FILTER (WHERE risk_score >= 25 AND risk_score < 50) AS medium,
                  COUNT(*) FILTER (WHERE risk_score < 25) AS low,
                  COUNT(*) FILTER (WHERE default_creds_risk) AS default_creds,
                  COUNT(*) AS total
                FROM iot_devices WHERE status='active'
            """)
            row = dict(cur.fetchone())
            cur.execute("SELECT device_category, COUNT(*) AS n FROM iot_devices WHERE status='active' GROUP BY device_category ORDER BY n DESC")
            row["by_category"] = {r["device_category"]: r["n"] for r in cur.fetchall()}
        conn.close()
        return jsonify(row)
    except psycopg2.Error as exc:
        _log.error("iot_risk_summary error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/iot/<int:iot_id>", methods=["GET", "PUT", "OPTIONS"])
def iot_device(iot_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    if request.method == "GET":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM iot_devices WHERE id=%s", [iot_id])
                row = cur.fetchone()
            conn.close()
            if not row: return jsonify({"error": "Not found"}), 404
            r = dict(row)
            if r.get("ip_address"): r["ip_address"] = str(r["ip_address"])
            return jsonify(r)
        except psycopg2.Error as exc:
            return jsonify({"error": "Database error"}), 500

    # PUT
    if _role() not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403
    body = request.get_json(silent=True) or {}
    allowed = {"notes", "tags", "status", "device_model", "firmware_version"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return jsonify({"error": "No valid fields"}), 400
    try:
        conn = _db()
        with conn.cursor() as cur:
            set_clause = ", ".join(f"{k}=%s" for k in updates)
            cur.execute(f"UPDATE iot_devices SET {set_clause} WHERE id=%s RETURNING id",
                        list(updates.values()) + [iot_id])
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Not found"}), 404
        conn.commit(); conn.close()
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/iot/scan", methods=["POST", "OPTIONS"])
def iot_scan():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body   = request.get_json(silent=True) or {}
    subnet = body.get("subnet", ITAM_SUBNET)
    if not subnet:
        return jsonify({"error": "No subnet configured"}), 400

    def _run():
        assets = run_nmap_discovery(subnet, ITAM_IOT_PORTS)
        if assets:
            try:
                conn = _db()
                upsert_assets(conn, assets, source="nmap")
                _classify_iot_from_assets(conn, assets)
                conn.close()
            except Exception as exc:
                _log.error("iot_scan background error: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"ok": True, "subnet": subnet})


# ── Shadow AI ─────────────────────────────────────────────────────────────────

@itam_bp.route("/shadow-ai", methods=["GET", "OPTIONS"])
def shadow_ai_list():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    page     = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    offset   = (page - 1) * per_page
    status   = request.args.get("status", "")
    severity = request.args.get("severity", "")
    hostname = request.args.get("hostname", "")
    tool     = request.args.get("ai_tool", "")

    where_parts = []
    params = []
    if status:
        where_parts.append("status=%s"); params.append(status)
    if severity:
        where_parts.append("severity=%s"); params.append(severity)
    if hostname:
        where_parts.append("hostname ILIKE %s"); params.append(f"%{hostname}%")
    if tool:
        where_parts.append("ai_tool ILIKE %s"); params.append(f"%{tool}%")
    where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM shadow_ai_findings {where}", params)
            total = cur.fetchone()["n"]
            cur.execute(f"""
                SELECT * FROM shadow_ai_findings {where}
                ORDER BY detected_at DESC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"findings": rows, "total": total, "page": page, "per_page": per_page})
    except psycopg2.Error as exc:
        _log.error("shadow_ai_list error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/shadow-ai/summary", methods=["GET", "OPTIONS"])
def shadow_ai_summary():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                  COUNT(*) FILTER (WHERE status='open') AS open_total,
                  COUNT(*) FILTER (WHERE status='approved') AS approved,
                  COUNT(*) FILTER (WHERE status='suppressed') AS suppressed,
                  COUNT(*) FILTER (WHERE severity='high' AND status='open') AS high_open,
                  COUNT(*) FILTER (WHERE detected_at > NOW()-INTERVAL '7 days') AS last_7d,
                  COUNT(*) FILTER (WHERE detected_at > NOW()-INTERVAL '30 days') AS last_30d,
                  COUNT(DISTINCT hostname) FILTER (WHERE status='open') AS affected_hosts,
                  COUNT(DISTINCT ai_tool) AS unique_tools
                FROM shadow_ai_findings
            """)
            summary = dict(cur.fetchone())
            cur.execute("""
                SELECT ai_tool, detection_layer, COUNT(*) AS n
                FROM shadow_ai_findings WHERE status='open'
                GROUP BY ai_tool, detection_layer ORDER BY n DESC LIMIT 20
            """)
            summary["by_tool"] = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify(summary)
    except psycopg2.Error as exc:
        _log.error("shadow_ai_summary error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/shadow-ai/<int:finding_id>/status", methods=["PUT", "OPTIONS"])
def shadow_ai_status(finding_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403

    body       = request.get_json(silent=True) or {}
    new_status = body.get("status", "")
    notes      = body.get("notes", "")
    if new_status not in ("open", "approved", "suppressed", "escalated"):
        return jsonify({"error": "Invalid status"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE shadow_ai_findings
                SET status=%s, notes=%s,
                    resolved_at=CASE WHEN %s<>'open' THEN NOW() ELSE NULL END
                WHERE id=%s RETURNING id
            """, [new_status, notes, new_status, finding_id])
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Not found"}), 404
        conn.commit(); conn.close()
        auth_event(session.get("user_email"), "shadow_ai_status_update",
                   f"Finding {finding_id} → {new_status}")
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("shadow_ai_status error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── AI Whitelist ──────────────────────────────────────────────────────────────

@itam_bp.route("/ai-whitelist", methods=["GET", "POST", "OPTIONS"])
def ai_whitelist():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    if request.method == "GET":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM ai_tool_whitelist ORDER BY approved_at DESC")
                rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return jsonify({"whitelist": rows})
        except psycopg2.Error as exc:
            return jsonify({"error": "Database error"}), 500

    # POST
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    body = request.get_json(silent=True) or {}
    tool_name = (body.get("tool_name") or "").strip()
    if not tool_name:
        return jsonify({"error": "tool_name required"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ai_tool_whitelist (tool_name, tool_type, department, approved_by, notes)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (tool_name, department) DO UPDATE SET
                  tool_type   = EXCLUDED.tool_type,
                  approved_by = EXCLUDED.approved_by,
                  approved_at = NOW(),
                  notes       = EXCLUDED.notes
                RETURNING id
            """, [tool_name,
                  body.get("tool_type", "saas"),
                  body.get("department", "ALL"),
                  session.get("user_email"),
                  body.get("notes", "")])
            row = cur.fetchone()
        conn.commit(); conn.close()
        auth_event(session.get("user_email"), "ai_whitelist_add", f"Whitelisted: {tool_name}")
        return jsonify({"id": row["id"]}), 201
    except psycopg2.Error as exc:
        _log.error("ai_whitelist POST error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/ai-whitelist/<int:wl_id>", methods=["DELETE", "OPTIONS"])
def ai_whitelist_delete(wl_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM ai_tool_whitelist WHERE id=%s RETURNING id", [wl_id])
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Not found"}), 404
        conn.commit(); conn.close()
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        return jsonify({"error": "Database error"}), 500


# ── Ingest: ARP neighbors from EDR heartbeat ─────────────────────────────────

def ingest_arp_neighbors(agent_id: str, neighbors: list[dict]) -> int:
    """
    Called by the EDR heartbeat handler when arp_neighbors is present.
    Parses and upserts neighbors into network_assets, then cross-references.
    Returns count upserted.
    """
    parsed = parse_arp_neighbors(neighbors)
    if not parsed:
        return 0
    try:
        conn = _db()
        n = upsert_assets(conn, parsed, source="arp_report")
        _crossref_agents_conn(conn)
        conn.close()
        return n
    except Exception as exc:
        _log.error("ingest_arp_neighbors error: %s", exc)
        return 0


# ── Ingest: Shadow AI finding from EDR telemetry ─────────────────────────────

def ingest_shadow_ai(agent_id: str, hostname: str, ai_tool: str,
                     process_name: str, severity: str = "medium") -> None:
    """
    Called by EDR telemetry handler when event_category == 'shadow_ai'.
    Stores finding only if tool is not on the whitelist for ALL or any department.
    """
    try:
        conn = _db()
        with conn.cursor() as cur:
            # Check whitelist
            cur.execute("""
                SELECT id FROM ai_tool_whitelist
                WHERE LOWER(tool_name)=LOWER(%s) AND (department='ALL' OR department IS NULL)
            """, [ai_tool])
            if cur.fetchone():
                conn.close(); return  # approved tool — skip

            cur.execute("""
                INSERT INTO shadow_ai_findings
                  (agent_id, hostname, ai_tool, detection_layer, detail, severity, status)
                VALUES (%s,%s,%s,'process',%s::jsonb,%s,'open')
                ON CONFLICT DO NOTHING
            """, [agent_id, hostname, ai_tool,
                  json.dumps({"process_name": process_name}),
                  severity])
        conn.commit(); conn.close()
    except Exception as exc:
        _log.error("ingest_shadow_ai error: %s", exc)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _crossref_agents():
    """Cross-reference network_assets with edr_agents + host_posture_cache by IP."""
    try:
        conn = _db()
        _crossref_agents_conn(conn)
        conn.close()
    except Exception as exc:
        _log.error("_crossref_agents error: %s", exc)


def _crossref_agents_conn(conn) -> None:
    """Run cross-reference within an existing connection."""
    with conn.cursor() as cur:
        # Link EDR agents by IP
        cur.execute("""
            UPDATE network_assets na
            SET edr_agent_id = ea.agent_id
            FROM edr_agents ea
            WHERE ea.agent_ip::inet = na.ip_address
              AND na.edr_agent_id IS DISTINCT FROM ea.agent_id
        """)
        # Link SIEM agents by IP
        cur.execute("""
            UPDATE network_assets na
            SET siem_agent_id = hpc.agent_id
            FROM host_posture_cache hpc
            WHERE hpc.ip::inet = na.ip_address
              AND na.siem_agent_id IS DISTINCT FROM hpc.agent_id
        """)
        # Auto-populate new edr_agents into network_assets if not already there
        cur.execute("""
            INSERT INTO network_assets (ip_address, hostname, asset_type, edr_agent_id, source)
            SELECT ea.agent_ip::inet, ea.hostname, ea.asset_type, ea.agent_id, 'edr_agent'
            FROM edr_agents ea
            WHERE ea.agent_ip IS NOT NULL AND ea.agent_ip <> ''
            ON CONFLICT (ip_address) DO UPDATE SET
              edr_agent_id = EXCLUDED.edr_agent_id,
              hostname     = COALESCE(network_assets.hostname, EXCLUDED.hostname),
              asset_type   = CASE WHEN network_assets.asset_type='unknown'
                                  THEN EXCLUDED.asset_type
                                  ELSE network_assets.asset_type END,
              last_seen    = NOW()
        """)
        # Auto-populate SIEM hosts
        cur.execute("""
            INSERT INTO network_assets (ip_address, hostname, siem_agent_id, source)
            SELECT hpc.ip::inet, hpc.agent_name, hpc.agent_id, 'siem_agent'
            FROM host_posture_cache hpc
            WHERE hpc.ip IS NOT NULL AND hpc.ip NOT IN ('any', '127.0.0.1', '0.0.0.0')
            ON CONFLICT (ip_address) DO UPDATE SET
              siem_agent_id = EXCLUDED.siem_agent_id,
              hostname      = COALESCE(network_assets.hostname, EXCLUDED.hostname),
              last_seen     = NOW()
        """)
    conn.commit()


def _classify_iot_from_assets(conn, assets: list[dict]) -> None:
    """For each nmap-discovered asset that looks like IoT, upsert into iot_devices."""
    with conn.cursor() as cur:
        for a in assets:
            open_ports = a.get("open_ports") or []
            mac = a.get("mac_address") or ""
            ip  = a["ip_address"]

            if not is_iot_candidate({"mac_address": mac, "open_ports": open_ports}):
                continue

            vendor_name, oui_cat = oui_lookup(mac)
            port_cat, _  = classify_ports(open_ports)
            category = oui_cat if oui_cat != "unknown" else (port_cat or "iot_device")

            has_telnet = any(int(p.get("port", 0)) == 23 for p in open_ports)
            mgmt_ports = {80, 8080}
            has_http   = any(int(p.get("port", 0)) in mgmt_ports for p in open_ports)
            has_https  = any(int(p.get("port", 0)) in {443, 8443} for p in open_ports)
            no_tls     = has_http and not has_https

            default_creds = False
            if ITAM_PROBE_CREDS and has_http:
                from .iot_classifier import probe_default_creds
                default_creds = probe_default_creds(ip, 80, a.get("vendor", "_default_"))

            risk, factors = compute_risk_score(
                vendor=vendor_name,
                device_category=category,
                open_ports=open_ports,
                has_default_creds=default_creds,
                has_telnet=has_telnet,
                no_tls_on_mgmt=no_tls,
            )

            # Get network_asset_id
            cur.execute("SELECT id FROM network_assets WHERE ip_address=%s::inet", [ip])
            row = cur.fetchone()
            na_id = row["id"] if row else None

            cur.execute("""
                INSERT INTO iot_devices
                  (network_asset_id, ip_address, mac_address, vendor, device_category,
                   open_ports, default_creds_risk, risk_score, risk_factors)
                VALUES (%s,%s::inet,%s,%s,%s,%s::jsonb,%s,%s,%s::jsonb)
                ON CONFLICT (ip_address) DO UPDATE SET
                  vendor            = EXCLUDED.vendor,
                  device_category   = EXCLUDED.device_category,
                  open_ports        = EXCLUDED.open_ports,
                  default_creds_risk= EXCLUDED.default_creds_risk,
                  risk_score        = EXCLUDED.risk_score,
                  risk_factors      = EXCLUDED.risk_factors,
                  last_seen         = NOW()
            """, [na_id, ip, mac or None, vendor_name, category,
                  json.dumps(open_ports), default_creds, risk,
                  json.dumps(factors)])
    conn.commit()
