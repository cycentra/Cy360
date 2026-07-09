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
import ipaddress
import json
import logging
import threading
import uuid
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Blueprint, jsonify, request, session, make_response

from blueprints.rbac.manager import get_user_role
from core.helpers import add_cors_headers, auth_event
from core.config import (CYCENTRA_DB_URL, ITAM_SUBNET, ITAM_IOT_PORTS, ITAM_PROBE_CREDS,
                         ITAM_SSH_USERNAME, ITAM_SSH_PASSWORD, ITAM_SSH_KEY_PATH, ITAM_SSH_PORT,
                         ITAM_WINRM_USERNAME, ITAM_WINRM_PASSWORD, ITAM_WINRM_PORT, ITAM_WINRM_SSL,
                         NVD_API_KEY, ITAM_DNS_MONITOR_PORT, ITAM_DNS_MONITOR_ENABLED, ITAM_DNS_UPSTREAM,
                         ITAM_SNMP_COMMUNITY, ITAM_SNMP_PORT, ITAM_MDNS_ENABLED,
                         AWS_REGIONS, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
                         AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)

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
        # ai_tool_whitelist: add vendor column if missing (added v1.0.165+)
        cur.execute("ALTER TABLE ai_tool_whitelist ADD COLUMN IF NOT EXISTS vendor TEXT;")
        # Columns added by Phase 2 (agentless scan + cloud discovery)
        for col_name, col_def in [
            ("os_info",          "TEXT"),
            ("discovery_source", "TEXT DEFAULT 'manual'"),
            ("is_managed",       "BOOLEAN DEFAULT FALSE"),
            ("scan_status",      "VARCHAR(20) DEFAULT 'idle'"),
            ("scan_error",       "TEXT"),
            # Phase 3 — deep scan results
            ("hardware_info",    "JSONB DEFAULT '{}'::jsonb"),
            ("services",         "JSONB DEFAULT '[]'::jsonb"),
            ("local_users",      "JSONB DEFAULT '[]'::jsonb"),
            ("listening_ports",  "JSONB DEFAULT '[]'::jsonb"),
            ("last_deep_scan",   "TIMESTAMPTZ"),
        ]:
            cur.execute(
                f"ALTER TABLE network_assets ADD COLUMN IF NOT EXISTS {col_name} {col_def};"
            )

        # Per-subnet credential profiles for agentless scanning
        cur.execute("""
            CREATE TABLE IF NOT EXISTS itam_credential_profiles (
              id             SERIAL PRIMARY KEY,
              name           TEXT NOT NULL,
              subnet_cidr    TEXT NOT NULL,
              ssh_username   TEXT,
              ssh_key_path   TEXT,
              ssh_port       INTEGER DEFAULT 22,
              winrm_username TEXT,
              winrm_port     INTEGER DEFAULT 5985,
              winrm_ssl      BOOLEAN DEFAULT FALSE,
              snmp_community TEXT DEFAULT 'public',
              snmp_port      INTEGER DEFAULT 161,
              created_at     TIMESTAMPTZ DEFAULT NOW(),
              updated_at     TIMESTAMPTZ DEFAULT NOW(),
              UNIQUE(subnet_cidr)
            )
        """)

        # ── Network Zone tables (ARP guard feature) ───────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_zones (
              id               SERIAL PRIMARY KEY,
              zone_name        TEXT NOT NULL,
              trusted_cidrs    TEXT[] NOT NULL DEFAULT '{}',
              trusted_gateways JSONB  DEFAULT '[]',
              status           TEXT   DEFAULT 'approved',
              approved_by      TEXT,
              approved_at      TIMESTAMPTZ,
              auto_discovered  BOOLEAN DEFAULT FALSE,
              notes            TEXT,
              created_at       TIMESTAMPTZ DEFAULT NOW(),
              updated_at       TIMESTAMPTZ DEFAULT NOW(),
              UNIQUE(zone_name)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_zone_suggestions (
              id               SERIAL PRIMARY KEY,
              subnet_prefix    TEXT NOT NULL,
              gateway_mac      TEXT NOT NULL,
              gateway_ip       TEXT,
              supporting_agents TEXT[] DEFAULT '{}',
              agent_count      INTEGER DEFAULT 1,
              status           TEXT DEFAULT 'pending',
              approved_zone_id INTEGER REFERENCES network_zones(id) ON DELETE SET NULL,
              case_id          TEXT,
              created_at       TIMESTAMPTZ DEFAULT NOW(),
              updated_at       TIMESTAMPTZ DEFAULT NOW(),
              UNIQUE(subnet_prefix, gateway_mac)
            )
        """)
        # Indexes
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_network_assets_ip ON network_assets(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_network_assets_type ON network_assets(asset_type)",
            "CREATE INDEX IF NOT EXISTS idx_network_assets_edr ON network_assets(edr_agent_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_assets_source ON network_assets(discovery_source)",
            "CREATE INDEX IF NOT EXISTS idx_iot_devices_risk ON iot_devices(risk_score DESC)",
            "CREATE INDEX IF NOT EXISTS idx_shadow_ai_status ON shadow_ai_findings(status)",
            "CREATE INDEX IF NOT EXISTS idx_shadow_ai_tool ON shadow_ai_findings(ai_tool)",
            "CREATE INDEX IF NOT EXISTS idx_nz_status ON network_zones(status)",
            "CREATE INDEX IF NOT EXISTS idx_nzs_status ON network_zone_suggestions(status)",
        ]:
            cur.execute(stmt)

        # Settings key-value store for UI-configurable scan parameters
        cur.execute("""
            CREATE TABLE IF NOT EXISTS itam_settings (
              key        TEXT PRIMARY KEY,
              value      TEXT NOT NULL,
              updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # ── Network Probe job queue ────────────────────────────────────────────
        cur.execute("""
            CREATE TABLE IF NOT EXISTS itam_scan_jobs (
              id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              probe_agent_id  TEXT NOT NULL,
              scan_type       TEXT NOT NULL DEFAULT 'subnet',
              subnet          TEXT,
              target_ip       TEXT,
              ports           TEXT,
              params          JSONB DEFAULT '{}'::jsonb,
              status          TEXT DEFAULT 'queued',
              result_json     JSONB,
              error_msg       TEXT,
              created_at      TIMESTAMPTZ DEFAULT NOW(),
              started_at      TIMESTAMPTZ,
              completed_at    TIMESTAMPTZ
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_probe ON itam_scan_jobs(probe_agent_id, status)")

        # Probe status columns on edr_agents (added when probe policy is first applied)
        for col, defn in [
            ("probe_policy_active", "BOOLEAN DEFAULT FALSE"),
            ("probe_subnet",        "TEXT"),
            ("probe_last_scan",     "TIMESTAMPTZ"),
        ]:
            cur.execute(f"ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS {col} {defn}")

        # Bootstrap NVD + KEV tables so routes work even before first sync
        try:
            from blueprints.itam.nvd_mirror import ensure_nvd_tables
            ensure_nvd_tables(conn)
        except Exception as _e:
            _log.debug("nvd_mirror init skipped: %s", _e)
        try:
            from blueprints.itam.exploit_intel import ensure_exploit_tables
            ensure_exploit_tables(conn)
        except Exception as _e:
            _log.debug("exploit_intel init skipped: %s", _e)

        # Backfill discovery_source from source for rows where discovery_source
        # was never set (defaults to 'manual' even for EDR/SIEM auto-registered assets)
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE network_assets
                SET discovery_source = source
                WHERE (discovery_source IS NULL OR discovery_source = 'manual')
                  AND source IS DISTINCT FROM 'manual'
            """)
            _log.info("ITAM: backfilled discovery_source for %d rows", cur.rowcount)

    conn.commit()
    conn.close()
    _log.info("ITAM tables initialised")
    import threading
    # Enrich existing ARP assets that are missing vendor or hostname (background)
    threading.Thread(target=_backfill_arp_assets, daemon=True).start()
    # Clean up duplicate asset rows from roaming devices (runs once at startup)
    threading.Thread(target=_startup_dedup, daemon=True).start()


# ── Settings helpers ──────────────────────────────────────────────────────────

def _get_itam_setting(conn, key: str) -> str | None:
    with conn.cursor() as cur:
        cur.execute("SELECT value FROM itam_settings WHERE key=%s", [key])
        row = cur.fetchone()
    return row["value"] if row else None


def _resolve_subnet() -> str:
    """Return subnet from DB settings, falling back to env var."""
    try:
        conn = _db()
        val = _get_itam_setting(conn, "scan_subnet")
        conn.close()
        if val:
            return val
    except Exception:
        pass
    return ITAM_SUBNET


def _resolve_iot_ports() -> str:
    try:
        conn = _db()
        val = _get_itam_setting(conn, "iot_ports")
        conn.close()
        if val:
            return val
    except Exception:
        pass
    return ITAM_IOT_PORTS


# ── ITAM Settings ─────────────────────────────────────────────────────────────

@itam_bp.route("/settings", methods=["GET", "PUT", "OPTIONS"])
def itam_settings():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401

    _CRED_KEYS = {"ssh_username", "ssh_password", "ssh_key_path", "ssh_port",
                  "winrm_username", "winrm_password", "winrm_port", "winrm_ssl"}

    if request.method == "GET":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("SELECT key, value FROM itam_settings")
                rows = {r["key"]: r["value"] for r in cur.fetchall()}
            conn.close()
            resp = {
                "scan_subnet":    rows.get("scan_subnet", ITAM_SUBNET or ""),
                "iot_ports":      rows.get("iot_ports",   ITAM_IOT_PORTS),
                "ssh_username":   rows.get("ssh_username",  ITAM_SSH_USERNAME or ""),
                "ssh_key_path":   rows.get("ssh_key_path",  ITAM_SSH_KEY_PATH or ""),
                "ssh_port":       rows.get("ssh_port",      str(ITAM_SSH_PORT) if ITAM_SSH_PORT else "22"),
                "winrm_username": rows.get("winrm_username", ITAM_WINRM_USERNAME or ""),
                "winrm_port":     rows.get("winrm_port",     str(ITAM_WINRM_PORT) if ITAM_WINRM_PORT else "5985"),
                "winrm_ssl":      rows.get("winrm_ssl",      "true" if ITAM_WINRM_SSL else "false"),
                # Return masked sentinel so the frontend knows a password is stored
                "ssh_password":   "•STORED•" if (rows.get("ssh_password") or ITAM_SSH_PASSWORD) else "",
                "winrm_password": "•STORED•" if (rows.get("winrm_password") or ITAM_WINRM_PASSWORD) else "",
            }
            return jsonify(resp)
        except psycopg2.Error as exc:
            _log.error("itam_settings GET error: %s", exc)
            return jsonify({"error": "Database error"}), 500

    # PUT — admin only
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    body = request.get_json(silent=True) or {}
    allowed = {"scan_subnet", "iot_ports"} | _CRED_KEYS
    updates = {k: str(v).strip() for k, v in body.items() if k in allowed and v is not None}
    # Never store the masked sentinel back — ignore unchanged password fields
    for pw_key in ("ssh_password", "winrm_password"):
        if updates.get(pw_key) == "•STORED•" or updates.get(pw_key) == "":
            updates.pop(pw_key, None)
    if not updates:
        return jsonify({"error": "No valid settings provided"}), 400

    # Validate subnet if present
    if "scan_subnet" in updates and updates["scan_subnet"]:
        try:
            import ipaddress as _ip
            _ip.ip_network(updates["scan_subnet"], strict=False)
        except ValueError:
            return jsonify({"error": "Invalid subnet — must be CIDR notation e.g. 192.168.1.0/24"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            for key, value in updates.items():
                cur.execute("""
                    INSERT INTO itam_settings (key, value, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()
                """, [key, value])
        conn.commit()
        conn.close()
        auth_event(session.get("user_email"), "itam_settings_update", str(updates))
        return jsonify({"ok": True, "updated": list(updates.keys())})
    except psycopg2.Error as exc:
        _log.error("itam_settings PUT error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── OUI vendor DB refresh ─────────────────────────────────────────────────────

@itam_bp.route("/oui/refresh", methods=["POST", "OPTIONS"])
def oui_refresh():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(session["user_email"]) != "admin":
        return jsonify({"error": "Forbidden"}), 403
    return _do_oui_refresh()


def _do_oui_refresh():
    """Re-read OUI CSV from the installed package path and hot-reload in-memory DB."""
    from .iot_classifier import reload_oui_db, _OUI_CSV_CANDIDATES
    for csv_path in _OUI_CSV_CANDIDATES:
        if csv_path.exists():
            try:
                content = csv_path.read_text(encoding="utf-8", errors="replace")
                count = reload_oui_db(content)
                _log.info("OUI DB refreshed from %s: %d entries", csv_path, count)
                return jsonify({"ok": True, "entries": count, "source": str(csv_path)})
            except Exception as exc:
                _log.error("OUI refresh failed (%s): %s", csv_path, exc)
                return jsonify({"error": str(exc)}), 500
    return jsonify({"error": "oui_vendors.csv not found — run cycentra-setup.sh --update"}), 404


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
                       hpc.agent_name AS siem_hostname,
                       COALESCE(sv.vuln_count, 0) AS vuln_count,
                       sv.highest_severity AS highest_cve_severity,
                       zone_match.zone_name
                FROM network_assets na
                LEFT JOIN edr_agents ea ON ea.agent_id = na.edr_agent_id
                LEFT JOIN host_posture_cache hpc ON hpc.agent_id = na.siem_agent_id
                LEFT JOIN (
                    SELECT asset_id,
                           SUM(cve_count) AS vuln_count,
                           CASE MAX(CASE highest_severity
                               WHEN 'critical' THEN 4
                               WHEN 'high'     THEN 3
                               WHEN 'medium'   THEN 2
                               WHEN 'low'      THEN 1
                               ELSE 0 END)
                           WHEN 4 THEN 'critical'
                           WHEN 3 THEN 'high'
                           WHEN 2 THEN 'medium'
                           WHEN 1 THEN 'low'
                           ELSE NULL END AS highest_severity
                    FROM software_inventory
                    WHERE cve_count > 0
                    GROUP BY asset_id
                ) sv ON sv.asset_id = na.id
                LEFT JOIN LATERAL (
                    SELECT nz.zone_name FROM network_zones nz
                    WHERE nz.status = 'approved'
                      AND EXISTS (
                          SELECT 1 FROM unnest(nz.trusted_cidrs) cidr_str
                          WHERE na.ip_address <<= cidr_str::inet
                      )
                    ORDER BY cardinality(nz.trusted_cidrs) DESC
                    LIMIT 1
                ) zone_match ON TRUE
                {where}
                ORDER BY na.last_seen DESC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("ip_address"):
                    r["ip_address"] = str(r["ip_address"])
                # Derive vendor/type from os_fingerprint or source when still unknown
                os_fp = (r.get("os_fingerprint") or "").lower()
                src   = r.get("source") or r.get("discovery_source") or ""
                if not r.get("vendor") or r["vendor"] in ("Unknown", ""):
                    if "windows" in os_fp:
                        r["vendor"] = "Microsoft"
                    elif "darwin" in os_fp or "macos" in os_fp or "mac os" in os_fp:
                        r["vendor"] = "Apple"
                    elif "linux" in os_fp or "ubuntu" in os_fp or "debian" in os_fp or "centos" in os_fp or "rhel" in os_fp:
                        r["vendor"] = "Linux"
                    elif src == "edr_agent":
                        r["vendor"] = "EDR Agent"
                    elif src == "siem_agent":
                        r["vendor"] = "SIEM Agent"
                    elif src == "arp_report":
                        mac = r.get("mac_address") or ""
                        vendor_name, _ = oui_lookup(mac)
                        r["vendor"] = vendor_name if vendor_name and vendor_name != "Unknown" else "Network Device"
                if r.get("asset_type") in (None, "unknown", ""):
                    if "windows" in os_fp:
                        r["asset_type"] = "workstation"
                    elif "darwin" in os_fp or "macos" in os_fp:
                        r["asset_type"] = "workstation"
                    elif "linux" in os_fp:
                        r["asset_type"] = "server"
                    elif src == "arp_report":
                        r["asset_type"] = "network_device"
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


# ── Asset Merge ───────────────────────────────────────────────────────────────

@itam_bp.route("/assets/merge", methods=["POST", "OPTIONS"])
def assets_merge():
    """Merge two duplicate network_asset rows into one. Admin only.
    Body: {primary_id, secondary_id}
    The primary row is kept; the secondary row is deleted. Best-available
    fields from secondary are absorbed into primary where primary has gaps.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403

    body         = request.get_json(silent=True) or {}
    primary_id   = body.get("primary_id")
    secondary_id = body.get("secondary_id")
    if not primary_id or not secondary_id:
        return jsonify({"error": "primary_id and secondary_id required"}), 400
    if primary_id == secondary_id:
        return jsonify({"error": "primary and secondary must differ"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM network_assets WHERE id=ANY(%s)", [[primary_id, secondary_id]])
            rows = {r["id"]: r for r in cur.fetchall()}
            if primary_id not in rows or secondary_id not in rows:
                conn.close(); return jsonify({"error": "One or both assets not found"}), 404

            sec = rows[secondary_id]
            # Absorb best fields from secondary into primary (fill gaps only)
            cur.execute("""
                UPDATE network_assets SET
                  hostname     = COALESCE(NULLIF(hostname,''),     %s),
                  mac_address  = COALESCE(NULLIF(mac_address,''),  %s),
                  vendor       = COALESCE(NULLIF(vendor,''),       %s),
                  asset_type   = CASE WHEN asset_type IN ('unknown','') THEN COALESCE(%s, asset_type) ELSE asset_type END,
                  edr_agent_id = COALESCE(edr_agent_id,           %s),
                  siem_agent_id= COALESCE(siem_agent_id,          %s),
                  os_fingerprint=COALESCE(NULLIF(os_fingerprint,''),%s),
                  last_seen    = GREATEST(last_seen,               %s),
                  first_seen   = LEAST(first_seen,                 %s)
                WHERE id = %s
            """, [sec["hostname"], sec["mac_address"], sec["vendor"],
                  sec["asset_type"], sec["edr_agent_id"], sec["siem_agent_id"],
                  sec["os_fingerprint"], sec["last_seen"], sec["first_seen"],
                  primary_id])
            # Delete the secondary (iot_devices CASCADE will follow)
            cur.execute("DELETE FROM network_assets WHERE id=%s", [secondary_id])
        conn.commit(); conn.close()
        auth_event(session.get("user_email"), "itam_asset_merge",
                   f"Merged asset #{secondary_id} into #{primary_id}")
        return jsonify({"ok": True, "kept_id": primary_id})
    except psycopg2.Error as exc:
        _log.error("assets_merge error: %s", exc)
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
    subnet = body.get("subnet") or _resolve_subnet()
    if not subnet:
        return jsonify({"error": "No subnet configured. Set it in Asset Coverage > Scan Settings."}), 400

    iot_ports = _resolve_iot_ports()
    auth_event(session.get("user_email"), "itam_subnet_scan", f"Subnet scan triggered: {subnet}")

    # Prefer probe agent deployed inside the customer's LAN
    try:
        conn  = _db()
        probe = _get_active_probe_for_subnet(conn, subnet)
        conn.close()
    except Exception:
        probe = None

    if probe:
        try:
            conn   = _db()
            job_id = _enqueue_probe_job(conn, probe["agent_id"], "subnet",
                                        subnet=subnet, ports=iot_ports)
            conn.close()
        except Exception as exc:
            _log.error("assets_scan: failed to enqueue probe job: %s", exc)
            return jsonify({"error": "Failed to enqueue probe job"}), 500
        return jsonify({
            "ok": True, "mode": "probe",
            "probe_agent": probe.get("hostname", probe["agent_id"]),
            "subnet": subnet, "job_id": job_id,
            "message": f"Scan dispatched to probe agent '{probe.get('hostname', probe['agent_id'])}'",
        })

    def _run():
        assets = run_nmap_discovery(subnet, iot_ports)
        if assets:
            try:
                conn = _db()
                upsert_assets(conn, assets, source="nmap")
                _classify_iot_from_assets(conn, assets)
                _crossref_agents_conn(conn)
                conn.close()
            except Exception as exc:
                _log.error("scan background error: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({
        "ok": True, "mode": "local", "subnet": subnet,
        "message": "Scan started in background",
        "warning": (
            "No network probe configured for this subnet. "
            "Running from cloud server — will fail if subnet is behind NAT."
        ),
    })


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

    body      = request.get_json(silent=True) or {}
    subnet    = body.get("subnet") or _resolve_subnet()
    if not subnet:
        return jsonify({"error": "No subnet configured. Set it in Asset Coverage > Scan Settings."}), 400

    iot_ports = _resolve_iot_ports()

    # Prefer a probe agent deployed inside the customer's LAN for this subnet.
    # If none is configured, fall back to running nmap from the cloud server
    # (works only when Cy360 is co-located with the target network).
    try:
        conn  = _db()
        probe = _get_active_probe_for_subnet(conn, subnet)
        conn.close()
    except Exception:
        probe = None

    if probe:
        try:
            conn = _db()
            job_id = _enqueue_probe_job(conn, probe["agent_id"], "subnet",
                                        subnet=subnet, ports=iot_ports)
            conn.close()
        except Exception as exc:
            _log.error("iot_scan: failed to enqueue probe job: %s", exc)
            return jsonify({"error": "Failed to enqueue probe job"}), 500
        return jsonify({
            "ok": True, "mode": "probe",
            "probe_agent": probe.get("hostname", probe["agent_id"]),
            "subnet": subnet, "job_id": job_id,
        })

    def _run():
        assets = run_nmap_discovery(subnet, iot_ports)
        if assets:
            try:
                conn = _db()
                upsert_assets(conn, assets, source="nmap")
                _classify_iot_from_assets(conn, assets)
                conn.close()
            except Exception as exc:
                _log.error("iot_scan background error: %s", exc)

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({
        "ok": True, "mode": "local", "subnet": subnet,
        "warning": (
            "No network probe configured for this subnet. "
            "Running from cloud server — will fail if subnet is behind NAT. "
            "Deploy a CyEDR Network Probe policy to an endpoint on this network."
        ),
    })


# ── Network Probe infrastructure ──────────────────────────────────────────────

def _get_active_probe_for_subnet(conn, subnet: str) -> "dict | None":
    """Return the first active probe agent whose probe_subnet matches or overlaps subnet."""
    import ipaddress as _ip
    with conn.cursor() as cur:
        cur.execute("""
            SELECT agent_id, hostname, probe_subnet
            FROM edr_agents
            WHERE probe_policy_active = TRUE
              AND probe_subnet IS NOT NULL
        """)
        rows = cur.fetchall()
    if not rows:
        return None
    try:
        target = _ip.ip_network(subnet, strict=False)
    except ValueError:
        return None
    for row in rows:
        try:
            probe_net = _ip.ip_network(row["probe_subnet"], strict=False)
            if target.overlaps(probe_net) or probe_net.overlaps(target):
                return dict(row)
        except ValueError:
            continue
    return None


def _enqueue_probe_job(conn, agent_id: str, scan_type: str,
                       subnet: str = "", ports: str = "",
                       params: "dict | None" = None) -> str:
    """Insert a queued job; return the UUID job id."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO itam_scan_jobs (probe_agent_id, scan_type, subnet, ports, params, status)
            VALUES (%s, %s, %s, %s, %s, 'queued')
            RETURNING id
        """, (agent_id, scan_type, subnet or None, ports or None,
              json.dumps(params) if params else None))
        job_id = str(cur.fetchone()["id"])
    conn.commit()
    return job_id


def _ingest_probe_nmap_xml(xml_text: str, subnet: str):
    """Parse nmap XML returned by a probe agent and upsert into ITAM tables."""
    from .network_discovery import _parse_nmap_xml
    assets = _parse_nmap_xml(xml_text)
    if assets:
        conn = _db()
        upsert_assets(conn, assets, source="nmap")
        _classify_iot_from_assets(conn, assets)
        conn.close()
        _log.info("Probe nmap ingested %d asset(s) for %s", len(assets), subnet)


# ── Probe API routes ──────────────────────────────────────────────────────────

def _verify_probe_token(req) -> "str | None":
    """Return agent_id if the Bearer enrollment token is valid, else None."""
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT agent_id FROM edr_agents WHERE enrollment_token=%s LIMIT 1",
                (token,)
            )
            row = cur.fetchone()
        conn.close()
        return row["agent_id"] if row else None
    except Exception:
        return None


@itam_bp.route("/probe/jobs", methods=["GET", "OPTIONS"])
def probe_poll_jobs():
    """Agent polls this to claim pending scan jobs for itself."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    agent_id = _verify_probe_token(request)
    if not agent_id:
        return jsonify({"error": "Invalid or missing probe token"}), 401

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE itam_scan_jobs
                SET status='running', started_at=NOW()
                WHERE id IN (
                    SELECT id FROM itam_scan_jobs
                    WHERE probe_agent_id=%s AND status='queued'
                    ORDER BY created_at
                    LIMIT 5
                )
                RETURNING id, scan_type, subnet, ports, params
            """, (agent_id,))
            jobs = [dict(r) for r in cur.fetchall()]
            # Stringify UUID for JSON
            for j in jobs:
                j["id"] = str(j["id"])
        conn.commit()
        conn.close()
    except Exception as exc:
        _log.error("probe_poll_jobs error: %s", exc)
        return jsonify({"error": "DB error"}), 500

    return jsonify({"jobs": jobs})


@itam_bp.route("/probe/jobs/<job_id>/result", methods=["POST", "OPTIONS"])
def probe_post_result(job_id):
    """Agent posts completed scan results."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    agent_id = _verify_probe_token(request)
    if not agent_id:
        return jsonify({"error": "Invalid or missing probe token"}), 401

    body      = request.get_json(silent=True) or {}
    result    = body.get("result", {})
    error_msg = body.get("error")

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE itam_scan_jobs
                SET status=%s, result_json=%s, error_msg=%s, completed_at=NOW()
                WHERE id=%s::uuid AND probe_agent_id=%s
            """, (
                "error" if error_msg else "done",
                json.dumps(result),
                error_msg,
                job_id, agent_id,
            ))
            cur.execute("""
                UPDATE edr_agents SET probe_last_scan=NOW()
                WHERE agent_id=%s
            """, (agent_id,))
        conn.commit()
        conn.close()
    except Exception as exc:
        _log.error("probe_post_result error: %s", exc)
        return jsonify({"error": "DB error"}), 500

    # Ingest results in background based on scan_type
    if not error_msg:
        scan_type = result.get("scan_type", "subnet")
        if scan_type == "subnet":
            xml    = result.get("raw_nmap_xml", "")
            subnet = result.get("subnet", "")
            if xml:
                threading.Thread(
                    target=_ingest_probe_nmap_xml,
                    args=(xml, subnet),
                    daemon=True,
                ).start()
        elif scan_type == "snmp":
            asset_id_from_job = result.get("asset_id")
            ip_from_job       = result.get("ip", "")
            snmp_data         = result.get("snmp_data", {})
            if asset_id_from_job and snmp_data:
                threading.Thread(
                    target=_ingest_snmp_result,
                    args=(int(asset_id_from_job), ip_from_job, snmp_data),
                    daemon=True,
                ).start()
        elif scan_type == "deep_scan":
            asset_id_from_job = result.get("asset_id")
            ip_from_job       = result.get("ip", "")
            if asset_id_from_job:
                threading.Thread(
                    target=_ingest_deep_scan_result,
                    args=(int(asset_id_from_job), ip_from_job, result),
                    daemon=True,
                ).start()

    return jsonify({"ok": True})


@itam_bp.route("/probe/auto-result", methods=["POST", "OPTIONS"])
def probe_auto_result():
    """Agent POSTs results from its scheduled auto-scan (no job_id)."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    agent_id = _verify_probe_token(request)
    if not agent_id:
        return jsonify({"error": "Invalid or missing probe token"}), 401

    body   = request.get_json(silent=True) or {}
    result = body.get("result", {})
    subnet = body.get("subnet", result.get("subnet", ""))
    xml    = result.get("raw_nmap_xml", "")

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE edr_agents SET probe_last_scan=NOW() WHERE agent_id=%s",
                (agent_id,)
            )
        conn.commit()
        conn.close()
    except Exception as exc:
        _log.error("probe_auto_result db error: %s", exc)

    if xml:
        threading.Thread(
            target=_ingest_probe_nmap_xml,
            args=(xml, subnet),
            daemon=True,
        ).start()

    return jsonify({"ok": True})


@itam_bp.route("/probe/status", methods=["GET", "OPTIONS"])
@require_viewer
def probe_status():
    """Returns all agents with active network probe policies."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT agent_id, hostname, probe_subnet, probe_last_scan,
                       probe_policy_active, last_seen
                FROM edr_agents
                WHERE probe_policy_active = TRUE
                ORDER BY hostname
            """)
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("probe_last_scan"):
                    r["probe_last_scan"] = r["probe_last_scan"].isoformat()
                if r.get("last_seen"):
                    r["last_seen"] = r["last_seen"].isoformat()
        conn.close()
    except Exception as exc:
        _log.error("probe_status error: %s", exc)
        return jsonify({"error": "DB error"}), 500
    return jsonify({"probes": rows})


@itam_bp.route("/probe/creds", methods=["GET", "OPTIONS"])
def probe_get_creds():
    """Probe agent fetches SSH/WinRM credentials for deep scan jobs.
    Returns plaintext creds — secured by Bearer enrollment token + TLS."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    agent_id = _verify_probe_token(request)
    if not agent_id:
        return jsonify({"error": "Invalid or missing probe token"}), 401

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key, value FROM itam_settings WHERE key IN "
                "('ssh_username','ssh_password','ssh_key_path','ssh_port',"
                "'winrm_username','winrm_password','winrm_port','winrm_ssl')"
            )
            stored = {r["key"]: r["value"] for r in cur.fetchall()}
        conn.close()
    except Exception:
        stored = {}

    def _v(db_key, env_val):
        return stored.get(db_key) or env_val or ""

    username = _v("ssh_username", ITAM_SSH_USERNAME)
    password = _v("ssh_password", ITAM_SSH_PASSWORD)
    winrm_u  = _v("winrm_username", ITAM_WINRM_USERNAME) or username
    winrm_p  = _v("winrm_password", ITAM_WINRM_PASSWORD) or password

    return jsonify({
        "username":       username,
        "password":       password,
        "key_path":       _v("ssh_key_path", ITAM_SSH_KEY_PATH),
        "ssh_port":       int(stored.get("ssh_port") or ITAM_SSH_PORT or 22),
        "winrm_username": winrm_u,
        "winrm_password": winrm_p,
        "winrm_port":     int(stored.get("winrm_port") or ITAM_WINRM_PORT or 5985),
        "winrm_ssl":      (stored.get("winrm_ssl") or str(ITAM_WINRM_SSL or "false")).lower() in ("true","1","yes"),
    })


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
                SELECT id, agent_id, hostname, ai_tool,
                       detection_layer AS detection_method,
                       detail->>'process_name' AS process_name,
                       severity, status,
                       detected_at AS first_seen,
                       resolved_at, notes
                FROM shadow_ai_findings {where}
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
                  COUNT(*) FILTER (WHERE status='open')       AS open,
                  COUNT(*) FILTER (WHERE status='escalated')  AS escalated,
                  COUNT(*) FILTER (WHERE status='approved')   AS approved,
                  COUNT(*) FILTER (WHERE status='suppressed') AS suppressed,
                  COUNT(*) FILTER (WHERE severity='high' AND status='open') AS high_open,
                  COUNT(*) FILTER (WHERE detected_at > NOW()-INTERVAL '7 days')  AS total_7d,
                  COUNT(*) FILTER (WHERE detected_at > NOW()-INTERVAL '30 days') AS last_30d,
                  COUNT(DISTINCT hostname) FILTER (WHERE status='open') AS affected_hosts,
                  COUNT(DISTINCT ai_tool) AS unique_tools
                FROM shadow_ai_findings
            """)
            summary = dict(cur.fetchone())
            cur.execute("""
                SELECT ai_tool, COUNT(*) AS n
                FROM shadow_ai_findings WHERE status='open'
                GROUP BY ai_tool ORDER BY n DESC LIMIT 20
            """)
            summary["by_tool"] = {r["ai_tool"]: r["n"] for r in cur.fetchall()}
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
                cur.execute("""
                    SELECT id,
                           tool_name  AS ai_tool,
                           vendor,
                           tool_type,
                           department,
                           approved_by,
                           approved_at AS created_at,
                           notes      AS rationale
                    FROM ai_tool_whitelist ORDER BY approved_at DESC
                """)
                rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return jsonify({"tools": rows})
        except psycopg2.Error as exc:
            return jsonify({"error": "Database error"}), 500

    # POST — accept both "ai_tool" (UI field) and legacy "tool_name"
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    body = request.get_json(silent=True) or {}
    tool_name = (body.get("ai_tool") or body.get("tool_name") or "").strip()
    if not tool_name:
        return jsonify({"error": "ai_tool required"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ai_tool_whitelist (tool_name, vendor, tool_type, department, approved_by, notes)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT (tool_name, department) DO UPDATE SET
                  vendor      = EXCLUDED.vendor,
                  tool_type   = EXCLUDED.tool_type,
                  approved_by = EXCLUDED.approved_by,
                  approved_at = NOW(),
                  notes       = EXCLUDED.notes
                RETURNING id
            """, [tool_name,
                  body.get("vendor", ""),
                  body.get("tool_type", "saas"),
                  body.get("department", "ALL"),
                  session.get("user_email"),
                  body.get("rationale") or body.get("notes", "")])
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


# ── Network Zone Trust Engine ─────────────────────────────────────────────────

def _corr_db_url() -> str:
    """Resolve correlation DB URL (same pattern as cases blueprint)."""
    import os as _os
    url = _os.environ.get("CORRELATION_DB_URL", "").strip() or \
          _os.environ.get("CYCENTRA_DB_URL", "").strip()
    if url:
        return url
    try:
        from pathlib import Path
        for line in Path("/opt/cycentra/cysiemstack.env").read_text().splitlines():
            if "DATABASE_URL" in line and "=" in line:
                raw = line.partition("=")[2].strip().strip('"').strip("'")
                return raw.replace("postgresql+asyncpg://", "postgresql://")
    except Exception:
        pass
    return "postgresql://corruser:changeme@127.0.0.1:5433/correlation"


def _raise_zone_approval_case(suggestion_id: int, subnet: str, gateway_mac: str,
                               agent_count: int) -> str | None:
    """
    Create a CyCase (incident record) for a new network zone needing admin approval.
    Returns the incident ID or None on failure.
    """
    incident_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    summary = (
        f"A new network zone has been auto-discovered and requires admin approval.\n\n"
        f"Subnet prefix: {subnet}\n"
        f"Gateway MAC:   {gateway_mac}\n"
        f"Reporting agents: {agent_count}\n"
        f"Suggestion ID: #{suggestion_id}\n\n"
        f"Action required: Navigate to ITAM > Network Zones to approve or reject this zone. "
        f"Approving will enable ARP asset discovery for endpoints on this subnet. "
        f"Rejecting will permanently silence ARP collection from this gateway."
    )
    try:
        conn = psycopg2.connect(
            _corr_db_url(),
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO incidents
                  (id, first_seen, last_seen, status, severity,
                   categories, case_type, case_opened_at, llm_summary)
                VALUES (%s,%s,%s,'open','medium',
                        ARRAY['network_security'],'network_zone_approval',%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, [incident_id, now, now, now, summary])
        conn.commit()
        conn.close()
        _log.info("CyCase raised for zone suggestion #%d: %s", suggestion_id, incident_id)
        return incident_id
    except Exception as exc:
        _log.warning("_raise_zone_approval_case failed: %s", exc)
        return None


def evaluate_zone_trust(agent_ip: str, gateway_macs: list[dict]) -> tuple[bool, str | None, str]:
    """
    Determine whether an agent is on a trusted corporate network.

    Returns (arp_enabled, zone_name, confidence).
    confidence: "high" | "medium" | "low" | "unknown"

    Trust rules (layered signals):
      1. Agent IP falls within a zone's trusted_cidrs  (CIDR match)
      2. Any reported gateway MAC is in the zone's trusted_gateways list  (MAC match)
      CIDR + MAC → "high"
      CIDR only  → "medium" (VPN zones have no gateway MACs)
      MAC only   → "medium"
      Neither    → not trusted
    """
    if not agent_ip or agent_ip in ("unknown", ""):
        return True, None, "unknown"

    try:
        agent_addr = ipaddress.ip_address(agent_ip)
    except ValueError:
        return True, None, "unknown"

    reported_macs = {g.get("mac", "").upper().replace("-", ":") for g in gateway_macs if g.get("mac")}

    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT zone_name, trusted_cidrs, trusted_gateways FROM network_zones WHERE status='approved'"
            )
            zones = cur.fetchall()
        conn.close()
    except Exception as exc:
        _log.debug("evaluate_zone_trust DB error: %s", exc)
        return True, None, "unknown"

    for zone in zones:
        cidr_match = False
        mac_match  = False

        for cidr_str in (zone["trusted_cidrs"] or []):
            try:
                if agent_addr in ipaddress.ip_network(cidr_str, strict=False):
                    cidr_match = True
                    break
            except ValueError:
                continue

        gw_list = zone["trusted_gateways"] or []
        if isinstance(gw_list, str):
            gw_list = json.loads(gw_list)
        trusted_macs: set[str] = set()
        for gw in gw_list:
            for m in gw.get("macs", []):
                trusted_macs.add(m.upper().replace("-", ":"))

        if trusted_macs and reported_macs & trusted_macs:
            mac_match = True

        if cidr_match and mac_match:
            return True, zone["zone_name"], "high"
        if cidr_match:
            return True, zone["zone_name"], "medium"  # VPN zone or MAC not yet registered
        if mac_match:
            return True, zone["zone_name"], "medium"

    return False, None, "low"


def record_gateway_sighting(agent_id: str, agent_ip: str, gateway_macs: list[dict]) -> None:
    """
    Record an observed gateway MAC for auto-zone-learning.
    If 3+ distinct agents have reported the same gateway MAC from the same /16 subnet,
    a pending zone suggestion is created and a CyCase is raised for admin review.
    Called non-blocking from heartbeat handler.
    """
    if not gateway_macs or not agent_ip:
        return

    try:
        agent_addr = ipaddress.ip_address(agent_ip)
        # Derive /16 subnet prefix as zone candidate key
        parts = agent_ip.split(".")
        if len(parts) != 4:
            return
        subnet_prefix = f"{parts[0]}.{parts[1]}.0.0/16"
    except ValueError:
        return

    for gw in gateway_macs:
        mac = (gw.get("mac") or "").upper().replace("-", ":")
        gw_ip = gw.get("ip", "")
        if not mac or mac in ("", "FF:FF:FF:FF:FF:FF", "<INCOMPLETE>"):
            continue

        try:
            conn = _db()
            with conn.cursor() as cur:
                # Upsert suggestion — increment agent count when same mac+subnet is seen again
                cur.execute("""
                    INSERT INTO network_zone_suggestions
                      (subnet_prefix, gateway_mac, gateway_ip, supporting_agents, agent_count)
                    VALUES (%s,%s,%s,ARRAY[%s]::text[],1)
                    ON CONFLICT (subnet_prefix, gateway_mac) DO UPDATE SET
                      gateway_ip       = COALESCE(NULLIF(EXCLUDED.gateway_ip,''),
                                                  network_zone_suggestions.gateway_ip),
                      supporting_agents = (
                          SELECT ARRAY(
                              SELECT DISTINCT unnest(
                                  network_zone_suggestions.supporting_agents || ARRAY[%s]::text[]
                              ) LIMIT 20
                          )
                      ),
                      agent_count      = array_length(
                          (SELECT ARRAY(
                              SELECT DISTINCT unnest(
                                  network_zone_suggestions.supporting_agents || ARRAY[%s]::text[]
                              )
                          )), 1
                      ),
                      updated_at       = NOW()
                    WHERE network_zone_suggestions.status = 'pending'
                    RETURNING id, agent_count, status, case_id
                """, [subnet_prefix, mac, gw_ip, agent_id, agent_id, agent_id])
                row = cur.fetchone()

                if row and row["agent_count"] >= 3 and not row["case_id"]:
                    # Threshold reached — raise a CyCase for admin review (non-blocking later)
                    suggestion_id = row["id"]
                    agent_count   = row["agent_count"]
                    # Mark in-flight to avoid double case creation
                    cur.execute(
                        "UPDATE network_zone_suggestions SET case_id='pending' WHERE id=%s",
                        [suggestion_id]
                    )
                    conn.commit()
                    conn.close()

                    case_id = _raise_zone_approval_case(suggestion_id, subnet_prefix, mac, agent_count)
                    if case_id:
                        conn2 = _db()
                        with conn2.cursor() as cur2:
                            cur2.execute(
                                "UPDATE network_zone_suggestions SET case_id=%s WHERE id=%s",
                                [case_id, suggestion_id]
                            )
                        conn2.commit()
                        conn2.close()
                    return

            conn.commit()
            conn.close()
        except Exception as exc:
            _log.debug("record_gateway_sighting error: %s", exc)


# ── Ingest: ARP neighbors from EDR heartbeat ─────────────────────────────────

def ingest_arp_neighbors(agent_id: str, neighbors: list[dict]) -> int:
    """
    Called by the EDR heartbeat handler when arp_neighbors is present and zone is trusted.
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
                     process_name: str, severity: str = "medium",
                     detection_method: str = "process") -> None:
    """
    Called by EDR telemetry handler when event_category == 'shadow_ai',
    and by the DNS monitor / agent DNS journal parser.
    Stores finding only if tool is not on the whitelist.
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

            # Deduplicate: skip if an open finding already exists for this agent + tool.
            # Without a UNIQUE constraint the ON CONFLICT DO NOTHING is a no-op, so we
            # check explicitly to avoid a finding row every 60s per heartbeat cycle.
            cur.execute("""
                SELECT id FROM shadow_ai_findings
                WHERE agent_id=%s AND ai_tool=%s AND status='open'
                LIMIT 1
            """, [agent_id, ai_tool])
            if cur.fetchone():
                conn.close(); return  # open finding already recorded

            cur.execute("""
                INSERT INTO shadow_ai_findings
                  (agent_id, hostname, ai_tool, detection_layer, detail, severity, status)
                VALUES (%s,%s,%s,%s,%s::jsonb,%s,'open')
                RETURNING id
            """, [agent_id, hostname, ai_tool, detection_method,
                  json.dumps({"process_name": process_name}),
                  severity])
            new_row = cur.fetchone()
        conn.commit(); conn.close()

        # Only push to SIEM on new detections (ON CONFLICT DO NOTHING returned a row)
        if new_row:
            _push_shadow_ai_to_siem(agent_id, hostname, ai_tool, severity)
    except Exception as exc:
        _log.error("ingest_shadow_ai error: %s", exc)


def _push_shadow_ai_to_siem(agent_id: str, hostname: str, ai_tool: str, severity: str) -> None:
    """Push a new shadow-AI finding to the SIEM pipeline. Non-fatal."""
    try:
        from cysiemstack.edr_bridge import push_itam_anomaly
        push_itam_anomaly(
            "shadow_ai",
            {"id": 0, "ip_address": "", "hostname": hostname, "agent_name": hostname},
            {
                "description": (
                    f"Unauthorised AI tool detected on {hostname}: {ai_tool} "
                    f"(severity={severity})"
                ),
                "ai_tool":  ai_tool,
                "agent_id": agent_id,
                "severity": severity,
            },
        )
    except Exception as exc:
        _log.warning("[ITAM→SIEM] shadow-AI push failed (non-fatal): %s", exc)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _backfill_arp_assets():
    """
    One-shot enrichment for ARP-discovered rows that predate OUI/rDNS enrichment.
    Runs in a background thread at startup. Safe to run multiple times.
    """
    try:
        from blueprints.itam.network_discovery import _rdns_batch
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, ip_address::text AS ip, mac_address
                FROM network_assets
                WHERE source = 'arp_report'
                  AND (vendor IS NULL OR vendor = '' OR vendor = 'Unknown'
                       OR hostname IS NULL OR hostname = '')
            """)
            rows = cur.fetchall()

        if not rows:
            conn.close()
            return

        ips = [r["ip"] for r in rows]
        hostnames = _rdns_batch(ips, timeout=1.0)

        with conn.cursor() as cur:
            for r in rows:
                vendor_name, oui_cat = oui_lookup(r["mac_address"] or "")
                vendor    = vendor_name if vendor_name and vendor_name != "Unknown" else None
                atype     = oui_cat    if oui_cat    != "unknown"                  else None
                hostname  = hostnames.get(r["ip"]) or None
                cur.execute("""
                    UPDATE network_assets SET
                      vendor     = CASE WHEN vendor IS NULL OR vendor IN ('','Unknown')
                                        THEN COALESCE(%s, vendor) ELSE vendor END,
                      asset_type = CASE WHEN asset_type IN ('unknown','')
                                        THEN COALESCE(%s, asset_type) ELSE asset_type END,
                      hostname   = CASE WHEN hostname IS NULL OR hostname = ''
                                        THEN COALESCE(%s, hostname) ELSE hostname END
                    WHERE id = %s
                """, [vendor, atype, hostname, r["id"]])
        conn.commit()
        conn.close()
        _log.info("ITAM: ARP backfill enriched %d assets", len(rows))
    except Exception as exc:
        _log.error("_backfill_arp_assets error: %s", exc)


def _startup_dedup():
    """Background thread: dedup existing duplicate asset rows on service start."""
    try:
        conn = _db()
        n = _dedup_by_agent_id(conn)
        conn.close()
        if n:
            _log.info("ITAM startup dedup: removed %d stale duplicate row(s)", n)
    except Exception as exc:
        _log.error("ITAM startup dedup error: %s", exc)


def _dedup_by_agent_id(conn) -> int:
    """
    Merge duplicate network_asset rows that represent the same physical device.

    Dedup order:
      1. Same edr_agent_id  — one CyEDR agent = one physical device
      2. Same siem_agent_id — one Wazuh agent  = one physical device
      3. Same mac_address   — for ARP/nmap rows with no agent link

    Keeps the most-recently-seen row (highest last_seen), absorbs best-available
    fields from the dupes, then deletes the dupes.  Called after every
    _crossref_agents_conn() run so roaming devices never accumulate rows.

    Returns the number of duplicate rows deleted.
    """
    deleted = 0
    with conn.cursor() as cur:
        for field in ("edr_agent_id", "siem_agent_id"):
            other = "siem_agent_id" if field == "edr_agent_id" else "edr_agent_id"
            cur.execute(f"""
                SELECT {field},
                       array_agg(id ORDER BY last_seen DESC NULLS LAST) AS ids
                FROM network_assets
                WHERE {field} IS NOT NULL
                GROUP BY {field}
                HAVING COUNT(*) > 1
            """)
            for row in cur.fetchall():
                ids, keeper_id, dupe_ids = row["ids"], row["ids"][0], row["ids"][1:]

                # Collect best fields from dupes before deleting them
                cur.execute(f"""
                    SELECT MAX(last_seen) AS last_seen,
                           (array_agg({other} ORDER BY last_seen DESC NULLS LAST)
                            FILTER (WHERE {other} IS NOT NULL))[1]          AS other_agent_id,
                           (array_agg(hostname ORDER BY last_seen DESC NULLS LAST)
                            FILTER (WHERE hostname IS NOT NULL AND hostname <> ''))[1] AS hostname,
                           (array_agg(mac_address ORDER BY last_seen DESC NULLS LAST)
                            FILTER (WHERE mac_address IS NOT NULL AND mac_address <> ''))[1] AS mac,
                           (array_agg(vendor ORDER BY last_seen DESC NULLS LAST)
                            FILTER (WHERE vendor IS NOT NULL AND vendor <> ''))[1]     AS vendor
                    FROM network_assets WHERE id = ANY(%s)
                """, [dupe_ids])
                merge = cur.fetchone()

                cur.execute("DELETE FROM network_assets WHERE id = ANY(%s)", [dupe_ids])
                deleted += len(dupe_ids)

                if merge:
                    cur.execute(f"""
                        UPDATE network_assets SET
                          {other}      = COALESCE({other}, %s),
                          hostname     = COALESCE(NULLIF(hostname, ''), %s),
                          mac_address  = COALESCE(NULLIF(mac_address, ''), %s),
                          vendor       = COALESCE(NULLIF(vendor, ''), %s),
                          last_seen    = GREATEST(last_seen, %s)
                        WHERE id = %s
                    """, [
                        merge["other_agent_id"], merge["hostname"],
                        merge["mac"], merge["vendor"],
                        merge["last_seen"], keeper_id,
                    ])

        # MAC-based dedup for pure ARP/nmap rows (no agent IDs)
        cur.execute("""
            SELECT mac_address,
                   array_agg(id ORDER BY last_seen DESC NULLS LAST) AS ids
            FROM network_assets
            WHERE mac_address IS NOT NULL AND mac_address <> ''
              AND edr_agent_id IS NULL AND siem_agent_id IS NULL
            GROUP BY mac_address
            HAVING COUNT(*) > 1
        """)
        for row in cur.fetchall():
            dupe_ids = row["ids"][1:]
            cur.execute("DELETE FROM network_assets WHERE id = ANY(%s)", [dupe_ids])
            deleted += len(dupe_ids)

    conn.commit()
    if deleted:
        _log.info("ITAM: dedup merged %d duplicate asset row(s)", deleted)
    return deleted


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
        # Clear edr_agent_id references that point to agents no longer in edr_agents
        # (e.g. after an agent merge/delete).  Clearing first lets MAC-based dedup
        # and the IP re-link below reclaim these rows cleanly.
        cur.execute("""
            UPDATE network_assets na
               SET edr_agent_id = NULL
             WHERE edr_agent_id IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM edr_agents WHERE agent_id = na.edr_agent_id
               )
        """)
        # Similarly clear stale siem_agent_id references
        cur.execute("""
            UPDATE network_assets na
               SET siem_agent_id = NULL
             WHERE siem_agent_id IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM host_posture_cache WHERE agent_id = na.siem_agent_id
               )
        """)

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
            WHERE hpc.agent_ip::inet = na.ip_address
              AND na.siem_agent_id IS DISTINCT FROM hpc.agent_id
        """)
        # Auto-populate new edr_agents into network_assets if not already there
        cur.execute("""
            INSERT INTO network_assets
              (ip_address, hostname, asset_type, edr_agent_id, source, discovery_source,
               vendor, os_fingerprint)
            SELECT
              ea.agent_ip::inet,
              ea.hostname,
              CASE ea.os_type
                WHEN 'linux'   THEN 'server'
                WHEN 'windows' THEN 'workstation'
                WHEN 'darwin'  THEN 'workstation'
                ELSE COALESCE(NULLIF(ea.asset_type,'unknown'), 'unknown')
              END,
              ea.agent_id,
              'edr_agent',
              'edr_agent',
              CASE ea.os_type
                WHEN 'linux'   THEN 'Linux'
                WHEN 'windows' THEN 'Microsoft'
                WHEN 'darwin'  THEN 'Apple'
                ELSE NULL
              END,
              ea.os_type
            FROM edr_agents ea
            WHERE ea.agent_ip IS NOT NULL AND ea.agent_ip <> ''
            ON CONFLICT (ip_address) DO UPDATE SET
              edr_agent_id     = EXCLUDED.edr_agent_id,
              hostname         = COALESCE(network_assets.hostname, EXCLUDED.hostname),
              asset_type       = CASE WHEN network_assets.asset_type IN ('unknown','')
                                      THEN EXCLUDED.asset_type
                                      ELSE network_assets.asset_type END,
              vendor           = COALESCE(network_assets.vendor, EXCLUDED.vendor),
              os_fingerprint   = COALESCE(network_assets.os_fingerprint, EXCLUDED.os_fingerprint),
              discovery_source = CASE WHEN network_assets.discovery_source IN ('manual','')
                                      THEN 'edr_agent'
                                      ELSE network_assets.discovery_source END,
              source           = CASE WHEN network_assets.source IN ('manual','')
                                      THEN 'edr_agent'
                                      ELSE network_assets.source END,
              last_seen        = NOW()
        """)
        # Auto-populate SIEM hosts
        cur.execute("""
            INSERT INTO network_assets
              (ip_address, hostname, siem_agent_id, source, discovery_source,
               asset_type, vendor, os_fingerprint)
            SELECT
              hpc.agent_ip::inet,
              hpc.agent_name,
              hpc.agent_id,
              'siem_agent',
              'siem_agent',
              CASE
                WHEN hpc.os_platform ILIKE '%windows%' THEN 'workstation'
                WHEN hpc.os_platform ILIKE '%linux%'   THEN 'server'
                WHEN hpc.os_platform ILIKE '%darwin%'  THEN 'workstation'
                ELSE 'unknown'
              END,
              CASE
                WHEN hpc.os_platform ILIKE '%windows%' THEN 'Microsoft'
                WHEN hpc.os_platform ILIKE '%linux%'   THEN 'Linux'
                WHEN hpc.os_platform ILIKE '%darwin%'  THEN 'Apple'
                ELSE NULL
              END,
              hpc.os_platform
            FROM host_posture_cache hpc
            WHERE hpc.agent_ip IS NOT NULL AND hpc.agent_ip NOT IN ('any', '127.0.0.1', '0.0.0.0')
            ON CONFLICT (ip_address) DO UPDATE SET
              siem_agent_id    = EXCLUDED.siem_agent_id,
              hostname         = COALESCE(network_assets.hostname, EXCLUDED.hostname),
              asset_type       = CASE WHEN network_assets.asset_type IN ('unknown','')
                                      THEN EXCLUDED.asset_type
                                      ELSE network_assets.asset_type END,
              vendor           = COALESCE(network_assets.vendor, EXCLUDED.vendor),
              os_fingerprint   = COALESCE(network_assets.os_fingerprint, EXCLUDED.os_fingerprint),
              discovery_source = CASE WHEN network_assets.discovery_source IN ('manual','')
                                      THEN 'siem_agent'
                                      ELSE network_assets.discovery_source END,
              source           = CASE WHEN network_assets.source IN ('manual','')
                                      THEN 'siem_agent'
                                      ELSE network_assets.source END,
              last_seen        = NOW()
        """)
    conn.commit()
    _dedup_by_agent_id(conn)


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
                RETURNING (xmax = 0) AS is_new_row
            """, [na_id, ip, mac or None, vendor_name, category,
                  json.dumps(open_ports), default_creds, risk,
                  json.dumps(factors)])
            upsert_result = cur.fetchone()
            # Push to SIEM on first discovery of a high-risk device (not on every rescan)
            if risk >= 75 and upsert_result and upsert_result.get("is_new_row"):
                _push_iot_risk_to_siem(ip, vendor_name, category, risk, factors, open_ports)
    conn.commit()


def _push_iot_risk_to_siem(ip: str, vendor: str, category: str, risk: int,
                            factors: list, open_ports: list) -> None:
    """Push a newly-discovered high-risk IoT device (risk_score ≥ 75) to SIEM. Non-fatal."""
    try:
        from cysiemstack.edr_bridge import push_itam_anomaly
        port_list = ",".join(str(p.get("port", "")) for p in (open_ports or [])[:10])
        push_itam_anomaly(
            "iot_high_risk",
            {"id": 0, "ip_address": ip, "hostname": ip},
            {
                "description": (
                    f"High-risk IoT device discovered: {vendor or 'unknown'} [{category}] "
                    f"at {ip} — risk score {risk}/100, ports: {port_list}"
                ),
                "vendor":       vendor,
                "device_category": category,
                "risk_score":   risk,
                "risk_factors": factors,
                "open_ports":   port_list,
            },
        )
    except Exception as exc:
        _log.warning("[ITAM→SIEM] IoT risk push failed (non-fatal): %s", exc)


# ═══════════════════════════════════════════════════════════════════════════════
# ITEM 2 — Agentless SSH/WinRM deep inventory
# ═══════════════════════════════════════════════════════════════════════════════

@itam_bp.route("/assets/<int:asset_id>/deep-scan", methods=["POST", "OPTIONS"])
def agentless_deep_scan(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) not in ("admin", "analyst"):
        return jsonify({"error": "Forbidden"}), 403

    body = request.get_json(silent=True) or {}

    # Load stored credentials from DB (override env vars; body overrides DB)
    try:
        _sc = _db()
        with _sc.cursor() as _cur:
            _cur.execute("SELECT key, value FROM itam_settings WHERE key IN "
                         "('ssh_username','ssh_password','ssh_key_path','ssh_port',"
                         "'winrm_username','winrm_password','winrm_port','winrm_ssl')")
            _stored = {r["key"]: r["value"] for r in _cur.fetchall()}
        _sc.close()
    except Exception:
        _stored = {}

    def _cred(body_key, db_key, env_val):
        return body.get(body_key) or _stored.get(db_key) or env_val or ""

    credentials = {
        "username":       _cred("ssh_username",  "ssh_username",  ITAM_SSH_USERNAME),
        "password":       _cred("ssh_password",  "ssh_password",  ITAM_SSH_PASSWORD),
        "key_path":       _cred("ssh_key_path",  "ssh_key_path",  ITAM_SSH_KEY_PATH),
        "ssh_port":       int(body.get("ssh_port") or _stored.get("ssh_port") or ITAM_SSH_PORT or 22),
        "winrm_port":     int(body.get("winrm_port") or _stored.get("winrm_port") or ITAM_WINRM_PORT or 5985),
        "use_ssl":        (body.get("winrm_ssl") or _stored.get("winrm_ssl") or str(ITAM_WINRM_SSL)).lower() in ("true","1","yes"),
        "winrm_username": _cred("winrm_username", "winrm_username", ITAM_WINRM_USERNAME),
        "winrm_password": _cred("winrm_password", "winrm_password", ITAM_WINRM_PASSWORD),
    }
    # WinRM falls back to SSH creds if not set
    if not credentials["winrm_username"]:
        credentials["winrm_username"] = credentials["username"]
    if not credentials["winrm_password"]:
        credentials["winrm_password"] = credentials["password"]

    conn = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, ip_address, hostname FROM network_assets WHERE id=%s", [asset_id])
            asset = cur.fetchone()
        if not asset:
            return jsonify({"error": "Asset not found"}), 404
        ip = str(asset["ip_address"])
    finally:
        conn.close()

    # If a probe covers this IP's subnet, dispatch SSH/WinRM to the probe agent
    # (runs from inside the LAN) rather than timing out on a non-routable RFC-1918 address.
    try:
        import ipaddress as _ip
        target_addr = _ip.ip_address(ip)
        is_private  = target_addr.is_private
    except ValueError:
        is_private = False

    if is_private:
        try:
            _pc = _db()
            probe = _get_active_probe_for_subnet(_pc, ip + "/32")
            _pc.close()
        except Exception:
            probe = None
        if probe:
            # Dispatch deep scan to the probe agent; it will SSH/WinRM from inside the LAN.
            try:
                _pc2 = _db()
                job_id = _enqueue_probe_job(
                    _pc2, probe["agent_id"], "deep_scan",
                    params={"asset_id": asset_id, "target_ip": ip},
                )
                _pc2.close()
            except Exception as _e:
                _log.warning("agentless_deep_scan probe enqueue failed: %s", _e)
                return jsonify({"error": "Probe job enqueue failed", "detail": str(_e)}), 500
            # Mark asset as scanning so UI shows progress
            try:
                _pc3 = _db()
                with _pc3.cursor() as _cur3:
                    _cur3.execute(
                        "UPDATE network_assets SET scan_status='scanning' WHERE id=%s",
                        [asset_id],
                    )
                _pc3.commit()
                _pc3.close()
            except Exception:
                pass
            return jsonify({
                "status": "scanning",
                "mode": "probe",
                "asset_id": asset_id,
                "ip": ip,
                "job_id": job_id,
                "probe_agent": probe.get("hostname", probe["agent_id"]),
                "message": (
                    f"Deep scan dispatched to Network Probe "
                    f"({probe.get('hostname', probe['agent_id'])}). "
                    "Results appear in 30–90 seconds."
                ),
            })

    def _do_scan():
        from blueprints.itam.agentless_scanner import detect_and_scan
        result = detect_and_scan(ip, credentials)
        _ingest_deep_scan_result(asset_id, ip, result)

    t = threading.Thread(target=_do_scan, daemon=True)
    t.start()
    return jsonify({"status": "scanning", "asset_id": asset_id, "ip": ip})


@itam_bp.route("/assets/<int:asset_id>/detail", methods=["GET", "OPTIONS"])
def asset_detail(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    from blueprints.itam.software_inventory import get_asset_software_summary
    conn = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        summary = get_asset_software_summary(conn, asset_id)
    finally:
        conn.close()
    return jsonify(summary)


@itam_bp.route("/assets/<int:asset_id>/software", methods=["GET", "OPTIONS"])
def asset_software(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(200, int(request.args.get("per_page", 50)))
    sev_flt  = request.args.get("severity", "")
    offset   = (page - 1) * per_page

    conn = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        with conn.cursor() as cur:
            where = "WHERE asset_id=%s"
            params: list = [asset_id]
            if sev_flt:
                where += " AND highest_severity=%s"
                params.append(sev_flt)
            cur.execute(f"SELECT COUNT(*) AS n FROM software_inventory {where}", params)
            total = cur.fetchone()["n"]
            cur.execute(
                f"SELECT id,name,version,vendor,package_manager,cve_count,highest_severity,cves,last_scanned "
                f"FROM software_inventory {where} ORDER BY cve_count DESC, name LIMIT %s OFFSET %s",
                params + [per_page, offset],
            )
            rows = [dict(r) for r in cur.fetchall()]
            for r in rows:
                if r.get("last_scanned"):
                    r["last_scanned"] = r["last_scanned"].isoformat()
    finally:
        conn.close()
    return jsonify({"software": rows, "total": total, "page": page, "per_page": per_page})


@itam_bp.route("/assets/<int:asset_id>/enrich-cves", methods=["POST", "OPTIONS"])
def enrich_cves(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) not in ("admin", "analyst"):
        return jsonify({"error": "Forbidden"}), 403

    def _enrich():
        from blueprints.itam.software_inventory import enrich_asset_cves
        c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            total = enrich_asset_cves(c, asset_id, NVD_API_KEY)
            _log.info("[ITAM] CVE enrichment asset_id=%s: %s vulns found", asset_id, total)
        finally:
            c.close()

    threading.Thread(target=_enrich, daemon=True).start()
    return jsonify({"status": "enriching", "asset_id": asset_id,
                    "note": "NVD rate limit: ~50 packages/30s with API key, ~5/30s without"})


# ═══════════════════════════════════════════════════════════════════════════════
# ITEM 1 — DNS Shadow AI: watchlist API + network DNS ingest
# ═══════════════════════════════════════════════════════════════════════════════

@itam_bp.route("/shadow-ai/dns-watchlist", methods=["GET", "OPTIONS"])
def dns_watchlist():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    from blueprints.itam.dns_shadow_ai import get_watchlist
    return jsonify({"domains": get_watchlist(), "total": len(get_watchlist())})


@itam_bp.route("/shadow-ai/dns-ingest", methods=["POST", "OPTIONS"])
def dns_shadow_ai_ingest():
    """
    Called by the network DNS monitor when an AI domain query is detected.
    Also called by CyEDR agent (Linux/macOS) for journal-based DNS findings.
    Body: {query_domain, client_ip, matched_domain, hostname (optional)}
    """
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    # Allow both session auth (UI tests) and bearer token (agent/monitor)
    auth_header = request.headers.get("Authorization", "")
    if not session.get("user_email") and not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    query_domain  = body.get("query_domain", "")
    client_ip     = body.get("client_ip", "")
    matched       = body.get("matched_domain", query_domain)
    hostname      = body.get("hostname", "")
    agent_id      = body.get("agent_id", "")
    detection_method = body.get("detection_method", "dns")

    if not query_domain:
        return jsonify({"error": "query_domain required"}), 400

    ingest_shadow_ai(
        agent_id=agent_id or client_ip,
        hostname=hostname or client_ip,
        ai_tool=matched,
        process_name=query_domain,
        severity="medium",
        detection_method=detection_method,
    )
    return jsonify({"status": "ingested", "domain": matched})


def _start_dns_monitor_if_enabled():
    """Called from scheduler/routes.py after app startup if ITAM_DNS_MONITOR_ENABLED=true."""
    if not ITAM_DNS_MONITOR_ENABLED:
        return
    from blueprints.itam.dns_shadow_ai import start_network_dns_monitor

    def _callback(query_domain: str, client_ip: str, matched: str):
        try:
            ingest_shadow_ai(
                agent_id=client_ip,
                hostname=client_ip,
                ai_tool=matched,
                process_name=query_domain,
                severity="medium",
                detection_method="dns_network",
            )
        except Exception as e:
            _log.debug("[ITAM-DNS] callback error: %s", e)

    start_network_dns_monitor(ITAM_DNS_MONITOR_PORT, ITAM_DNS_UPSTREAM, _callback)
    _log.info("[ITAM-DNS] Network DNS monitor enabled on port %d", ITAM_DNS_MONITOR_PORT)


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — SNMP, Cloud Discovery, Credential Profiles, NVD Mirror, KEV
# ═══════════════════════════════════════════════════════════════════════════════

# ── SNMP scan ─────────────────────────────────────────────────────────────────

def _ingest_snmp_result(asset_id: int, ip: str, result: dict):
    """Write SNMP scan result into network_assets. Called locally or from probe result ingest."""
    from blueprints.itam.snmp_scanner import infer_device_type
    c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        if result.get("error"):
            with c.cursor() as cur:
                cur.execute(
                    "UPDATE network_assets SET scan_status='error', scan_error=%s WHERE id=%s",
                    [result["error"], asset_id])
            c.commit()
            return
        device_type = infer_device_type(result.get("description", ""), result.get("object_id", ""))
        with c.cursor() as cur:
            cur.execute("""
                UPDATE network_assets SET
                    hostname    = COALESCE(NULLIF(%s,''), hostname),
                    notes       = COALESCE(NULLIF(%s,''), notes),
                    os_info     = COALESCE(NULLIF(%s,'{}'), os_info),
                    scan_status = 'ok',
                    scan_error  = NULL,
                    last_seen   = NOW()
                WHERE id=%s
            """, [
                result.get("hostname", ""),
                result.get("description", "")[:500] if result.get("description") else "",
                json.dumps({"sys_description": result.get("description", ""),
                            "device_type": device_type,
                            "sys_location": result.get("location", ""),
                            "uptime_seconds": result.get("uptime_seconds", 0)}),
                asset_id,
            ])
        c.commit()
        _log.info("[ITAM-SNMP] %s: %d interfaces, type=%s", ip,
                  len(result.get("interfaces", [])), device_type)
    except Exception as exc:
        _log.warning("[ITAM-SNMP] ingest error for %s: %s", ip, exc)
        try:
            with c.cursor() as cur:
                cur.execute(
                    "UPDATE network_assets SET scan_status='error', scan_error=%s WHERE id=%s",
                    [str(exc), asset_id])
            c.commit()
        except Exception:
            pass
    finally:
        c.close()


def _ingest_deep_scan_result(asset_id: int, ip: str, result: dict):
    """Write SSH/WinRM deep scan result into network_assets + software_inventory.
    Called from probe_post_result (deep_scan job) or the local _do_scan() thread."""
    from blueprints.itam.software_inventory import (
        ensure_software_tables, upsert_software, enrich_asset_cves,
    )
    c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        ensure_software_tables(c)
        if result.get("status") == "ok":
            hw = result.get("hardware", {})
            with c.cursor() as cur:
                cur.execute("""
                    UPDATE network_assets SET
                        hostname        = COALESCE(NULLIF(%s,''), hostname),
                        os_info         = %s,
                        hardware_info   = %s::jsonb,
                        services        = %s::jsonb,
                        local_users     = %s::jsonb,
                        listening_ports = %s::jsonb,
                        last_deep_scan  = NOW(),
                        scan_status     = 'ok',
                        scan_error      = NULL
                    WHERE id = %s
                """, [
                    result.get("hostname", ""),
                    json.dumps(result.get("os_info", {})),
                    json.dumps(hw),
                    json.dumps(result.get("services", [])),
                    json.dumps(result.get("local_users", [])),
                    json.dumps(result.get("listening_ports", [])),
                    asset_id,
                ])
            c.commit()
            count = upsert_software(c, asset_id, result.get("packages", []))
            enrich_asset_cves(c, asset_id, NVD_API_KEY)
            _log.info("[ITAM] deep-scan %s: %d packages, method=%s", ip, count, result.get("method"))
            # Push high/critical CVEs found in this scan into Active Incidents pipeline
            _push_deep_scan_cves_to_siem(c, asset_id, ip, result)
        else:
            err_msg = result.get("error", "unknown error")
            _log.warning("[ITAM] deep-scan %s failed: %s", ip, err_msg)
            with c.cursor() as cur:
                cur.execute(
                    "UPDATE network_assets SET scan_status='error', scan_error=%s WHERE id=%s",
                    [err_msg, asset_id],
                )
            c.commit()
    except Exception as exc:
        _log.error("[ITAM] deep-scan ingest error for %s: %s", ip, exc)
        try:
            with c.cursor() as cur:
                cur.execute(
                    "UPDATE network_assets SET scan_status='error', scan_error=%s WHERE id=%s",
                    [str(exc), asset_id],
                )
            c.commit()
        except Exception:
            pass
    finally:
        c.close()


def _push_deep_scan_cves_to_siem(conn, asset_id: int, ip: str, scan_result: dict) -> None:
    """
    After a deep scan, query software_inventory for high/critical CVEs and push
    each unique CVE into the SIEM correlation pipeline so Active Incidents
    receives, enriches, and auto-cases them.  Non-fatal.
    """
    try:
        from cysiemstack.edr_bridge import push_itam_anomaly
        with conn.cursor() as cur:
            cur.execute("""
                SELECT si.name, si.version, sv.cve_id, sv.cvss_score, sv.severity,
                       sv.description, na.hostname, na.ip_address::text AS ip
                FROM software_inventory si
                JOIN software_cves sv ON sv.software_id = si.id
                LEFT JOIN network_assets na ON na.id = si.asset_id
                WHERE si.asset_id = %s
                  AND sv.severity IN ('CRITICAL','HIGH')
                ORDER BY sv.cvss_score DESC
                LIMIT 20
            """, [asset_id])
            rows = cur.fetchall() or []

        asset_info = {
            "id":         asset_id,
            "ip_address": ip,
            "hostname":   scan_result.get("hostname", ip),
        }

        pushed_cves: set = set()
        for row in rows:
            cve_id = row.get("cve_id") or ""
            if cve_id in pushed_cves:
                continue
            pushed_cves.add(cve_id)

            sev_lower  = (row.get("severity") or "high").upper()
            anom_type  = "cve_critical" if sev_lower == "CRITICAL" else "cve_high"
            pkg        = row.get("name", "unknown")
            ver        = row.get("version", "")
            cvss       = row.get("cvss_score") or 0.0
            push_itam_anomaly(anom_type, asset_info, {
                "description": (
                    f"{cve_id} ({sev_lower}, CVSS {cvss}) in {pkg} {ver} "
                    f"on {asset_info.get('hostname', ip)}"
                ),
                "cve_id":    cve_id,
                "cvss_score": float(cvss),
                "package":   pkg,
                "version":   ver,
            })
    except Exception as exc:
        _log.warning("[ITAM→SIEM] CVE push failed (non-fatal): %s", exc)


@itam_bp.route("/assets/<int:asset_id>/snmp-scan", methods=["POST", "OPTIONS"])
def snmp_scan_asset(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) not in ("admin", "analyst"):
        return jsonify({"error": "Forbidden"}), 403

    body      = request.get_json(silent=True) or {}
    community = body.get("community") or ITAM_SNMP_COMMUNITY or "public"
    port      = int(body.get("port") or ITAM_SNMP_PORT or 161)

    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, ip_address FROM network_assets WHERE id=%s", [asset_id])
            asset = cur.fetchone()
    finally:
        conn.close()

    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    ip = str(asset["ip_address"])

    # Prefer probe agent for private/RFC-1918 targets
    try:
        conn  = _db()
        probe = _get_active_probe_for_subnet(conn, ip + "/32")
        conn.close()
    except Exception:
        probe = None

    if probe:
        try:
            conn   = _db()
            # Mark asset scanning so UI shows spinner
            with conn.cursor() as cur:
                cur.execute("UPDATE network_assets SET scan_status='scanning' WHERE id=%s", [asset_id])
            conn.commit()
            job_id = _enqueue_probe_job(conn, probe["agent_id"], "snmp",
                                        target_ip=ip,
                                        params=json.dumps({
                                            "asset_id": asset_id,
                                            "community": community,
                                            "port": port,
                                        }))
            conn.close()
        except Exception as exc:
            _log.error("snmp_scan_asset: probe job enqueue failed: %s", exc)
            return jsonify({"error": "Failed to enqueue probe SNMP job"}), 500
        return jsonify({
            "status": "scanning", "mode": "probe",
            "probe_agent": probe.get("hostname", probe["agent_id"]),
            "asset_id": asset_id, "ip": ip, "job_id": job_id,
        })

    # Fallback: run SNMP from the cloud server (works only if target is reachable)
    def _do_snmp():
        from blueprints.itam.snmp_scanner import snmp_scan
        c = _db()
        try:
            with c.cursor() as cur:
                cur.execute("UPDATE network_assets SET scan_status='scanning' WHERE id=%s", [asset_id])
            c.commit()
            c.close()
        except Exception:
            pass
        result = snmp_scan(ip, community=community, port=port)
        _ingest_snmp_result(asset_id, ip, result)

    threading.Thread(target=_do_snmp, daemon=True).start()
    return jsonify({"status": "scanning", "mode": "local", "asset_id": asset_id, "ip": ip})


@itam_bp.route("/assets/<int:asset_id>/scan-status", methods=["GET", "OPTIONS"])
def asset_scan_status(asset_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, scan_status, scan_error, last_seen, last_deep_scan "
                "FROM network_assets WHERE id=%s", [asset_id])
            row = cur.fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Not found"}), 404
        return jsonify(dict(row))
    except psycopg2.Error as exc:
        return jsonify({"error": "Database error"}), 500


# ── Cloud sync ────────────────────────────────────────────────────────────────

@itam_bp.route("/cloud-sync", methods=["POST", "OPTIONS"])
def cloud_sync():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    body = request.get_json(silent=True) or {}
    provider = body.get("provider", "all")   # "aws", "azure", "all"

    def _sync():
        c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            results = {}
            if provider in ("aws", "all") and AWS_ACCESS_KEY_ID and AWS_REGIONS:
                from blueprints.itam.cloud_discovery import sync_aws_assets
                results["aws"] = sync_aws_assets(
                    c, AWS_REGIONS, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
            if provider in ("azure", "all") and AZURE_SUBSCRIPTION_ID:
                from blueprints.itam.cloud_discovery import sync_azure_assets
                results["azure"] = sync_azure_assets(
                    c, AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID,
                    AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
            if results:
                _crossref_agents_conn(c)
            _log.info("[ITAM-CLOUD] sync complete: %s", results)
        except Exception as exc:
            _log.error("[ITAM-CLOUD] sync error: %s", exc)
        finally:
            c.close()

    threading.Thread(target=_sync, daemon=True).start()
    auth_event(email, "itam_cloud_sync", f"Cloud sync triggered (provider={provider})")
    return jsonify({"status": "syncing", "provider": provider})


@itam_bp.route("/cloud-sync/status", methods=["GET", "OPTIONS"])
def cloud_sync_status():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT discovery_source, COUNT(*) AS n,
                       MAX(last_seen) AS last_synced
                FROM network_assets
                WHERE discovery_source IN ('aws', 'azure')
                GROUP BY discovery_source
            """)
            rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({
            "cloud_sources": rows,
            "aws_configured":   bool(AWS_ACCESS_KEY_ID and AWS_REGIONS),
            "azure_configured": bool(AZURE_SUBSCRIPTION_ID),
        })
    except psycopg2.Error:
        return jsonify({"error": "Database error"}), 500


# ── Credential Profiles ────────────────────────────────────────────────────────

@itam_bp.route("/credential-profiles", methods=["GET", "POST", "OPTIONS"])
def credential_profiles():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        if _role() not in ("admin", "analyst"):
            return jsonify({"error": "Forbidden"}), 403
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, name, subnet_cidr, ssh_username, ssh_port,
                           winrm_username, winrm_port, winrm_ssl,
                           snmp_community, snmp_port, created_at, updated_at
                    FROM itam_credential_profiles ORDER BY subnet_cidr
                """)
                rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return jsonify({"profiles": rows})
        except psycopg2.Error:
            return jsonify({"error": "Database error"}), 500

    # POST — create
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    body = request.get_json(silent=True) or {}
    name        = (body.get("name") or "").strip()
    subnet_cidr = (body.get("subnet_cidr") or "").strip()
    if not name or not subnet_cidr:
        return jsonify({"error": "name and subnet_cidr are required"}), 400
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO itam_credential_profiles
                    (name, subnet_cidr, ssh_username, ssh_key_path, ssh_port,
                     winrm_username, winrm_port, winrm_ssl,
                     snmp_community, snmp_port)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (subnet_cidr) DO UPDATE SET
                    name=EXCLUDED.name, ssh_username=EXCLUDED.ssh_username,
                    ssh_key_path=EXCLUDED.ssh_key_path, ssh_port=EXCLUDED.ssh_port,
                    winrm_username=EXCLUDED.winrm_username,
                    winrm_port=EXCLUDED.winrm_port, winrm_ssl=EXCLUDED.winrm_ssl,
                    snmp_community=EXCLUDED.snmp_community, snmp_port=EXCLUDED.snmp_port,
                    updated_at=NOW()
                RETURNING id
            """, [name, subnet_cidr,
                  body.get("ssh_username", ""),
                  body.get("ssh_key_path", ""),
                  int(body.get("ssh_port", 22)),
                  body.get("winrm_username", ""),
                  int(body.get("winrm_port", 5985)),
                  bool(body.get("winrm_ssl", False)),
                  body.get("snmp_community", "public"),
                  int(body.get("snmp_port", 161))])
            row = cur.fetchone()
        conn.commit(); conn.close()
        auth_event(session.get("user_email"), "itam_cred_profile_create",
                   f"Profile '{name}' for {subnet_cidr}")
        return jsonify({"id": row["id"]}), 201
    except psycopg2.Error as exc:
        _log.error("credential_profiles POST error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/credential-profiles/<int:prof_id>", methods=["PUT", "DELETE", "OPTIONS"])
def credential_profile(prof_id):
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403

    if request.method == "DELETE":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM itam_credential_profiles WHERE id=%s RETURNING id", [prof_id])
                if not cur.fetchone():
                    conn.close(); return jsonify({"error": "Not found"}), 404
            conn.commit(); conn.close()
            return jsonify({"ok": True})
        except psycopg2.Error:
            return jsonify({"error": "Database error"}), 500

    # PUT
    body = request.get_json(silent=True) or {}
    allowed = {"name", "ssh_username", "ssh_key_path", "ssh_port",
               "winrm_username", "winrm_port", "winrm_ssl",
               "snmp_community", "snmp_port"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return jsonify({"error": "No valid fields"}), 400
    updates["updated_at"] = "NOW()"
    try:
        conn = _db()
        with conn.cursor() as cur:
            set_clause = ", ".join(
                f"{k}=NOW()" if v == "NOW()" else f"{k}=%s"
                for k, v in updates.items()
            )
            vals = [v for v in updates.values() if v != "NOW()"]
            cur.execute(
                f"UPDATE itam_credential_profiles SET {set_clause} WHERE id=%s RETURNING id",
                vals + [prof_id])
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Not found"}), 404
        conn.commit(); conn.close()
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("credential_profile PUT error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── NVD Mirror & CISA KEV ─────────────────────────────────────────────────────

@itam_bp.route("/nvd-mirror/status", methods=["GET", "OPTIONS"])
def nvd_mirror_status():
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        from blueprints.itam.nvd_mirror import is_mirror_populated
        conn = _db()
        with conn.cursor() as cur:
            populated = is_mirror_populated(conn)
            cur.execute("SELECT COUNT(*) AS n FROM nvd_cves")
            total_cves = cur.fetchone()["n"]
            cur.execute("""
                SELECT last_incremental_sync, last_full_sync
                FROM nvd_sync_state WHERE id=1
            """)
            row = cur.fetchone() or {}
            cur.execute("SELECT COUNT(*) AS n FROM kev_catalog")
            kev_count = cur.fetchone()["n"]
        conn.close()
        return jsonify({
            "populated":              populated,
            "total_cves":             total_cves,
            "kev_catalog_entries":    kev_count,
            "last_incremental_sync":  row.get("last_incremental_sync"),
            "last_full_sync":         row.get("last_full_sync"),
            "api_key_configured":     bool(NVD_API_KEY),
        })
    except Exception as exc:
        _log.warning("nvd_mirror_status error: %s", exc)
        return jsonify({"populated": False, "total_cves": 0, "kev_catalog_entries": 0})


@itam_bp.route("/nvd-mirror/sync", methods=["POST", "OPTIONS"])
def nvd_mirror_sync():
    """Trigger incremental NVD sync (last 8 days)."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) not in ("admin", "analyst"):
        return jsonify({"error": "Forbidden"}), 403

    def _sync():
        from blueprints.itam.nvd_mirror import sync_nvd_incremental, ensure_nvd_tables
        c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            ensure_nvd_tables(c)
            n = sync_nvd_incremental(c, NVD_API_KEY)
            _log.info("[NVD] incremental sync done: %d CVEs upserted", n)
        except Exception as exc:
            _log.error("[NVD] incremental sync error: %s", exc)
        finally:
            c.close()

    threading.Thread(target=_sync, daemon=True).start()
    auth_event(email, "nvd_mirror_sync", "NVD incremental sync triggered")
    return jsonify({"status": "syncing", "type": "incremental"})


@itam_bp.route("/nvd-mirror/full-sync", methods=["POST", "OPTIONS"])
def nvd_mirror_full_sync():
    """Trigger a full NVD sync (admin only — can take hours without API key)."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) != "admin":
        return jsonify({"error": "Admin role required"}), 403

    body       = request.get_json(silent=True) or {}
    start_year = int(body.get("start_year", 2020))

    def _full():
        from blueprints.itam.nvd_mirror import sync_nvd_full, ensure_nvd_tables
        c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            ensure_nvd_tables(c)
            n = sync_nvd_full(c, NVD_API_KEY, start_year=start_year)
            _log.info("[NVD] full sync done: %d CVEs upserted (from %d)", n, start_year)
        except Exception as exc:
            _log.error("[NVD] full sync error: %s", exc)
        finally:
            c.close()

    threading.Thread(target=_full, daemon=True).start()
    auth_event(email, "nvd_mirror_full_sync", f"NVD full sync triggered from {start_year}")
    return jsonify({"status": "syncing", "type": "full", "start_year": start_year,
                    "note": "Full sync may take 30-60 min without NVD_API_KEY"})


@itam_bp.route("/nvd-mirror/kev-sync", methods=["POST", "OPTIONS"])
def kev_sync():
    """Sync CISA Known Exploited Vulnerabilities catalog."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    email = session.get("user_email")
    if not email:
        return jsonify({"error": "Unauthorized"}), 401
    if get_user_role(email) not in ("admin", "analyst"):
        return jsonify({"error": "Forbidden"}), 403

    def _kev():
        from blueprints.itam.exploit_intel import sync_kev_catalog, ensure_exploit_tables
        c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            ensure_exploit_tables(c)
            n = sync_kev_catalog(c)
            _log.info("[KEV] synced %d entries", n)
        except Exception as exc:
            _log.error("[KEV] sync error: %s", exc)
        finally:
            c.close()

    threading.Thread(target=_kev, daemon=True).start()
    auth_event(email, "kev_sync", "CISA KEV sync triggered")
    return jsonify({"status": "syncing", "source": "CISA Known Exploited Vulnerabilities"})


@itam_bp.route("/assets/<int:asset_id>/exploit-intel", methods=["GET", "OPTIONS"])
def asset_exploit_intel(asset_id):
    """Get EPSS scores and KEV status for an asset's software."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        from blueprints.itam.exploit_intel import get_asset_risk_intel, ensure_exploit_tables
        conn = _db()
        ensure_exploit_tables(conn)
        intel = get_asset_risk_intel(conn, asset_id)
        conn.close()
        return jsonify(intel)
    except Exception as exc:
        _log.warning("asset_exploit_intel error: %s", exc)
        return jsonify({"asset_id": asset_id, "kev_count": 0, "kev_packages": [],
                        "highest_epss": 0.0, "ransomware_risk": False})


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK ZONES — ARP Guard: trusted corporate network definitions
# ══════════════════════════════════════════════════════════════════════════════

@itam_bp.route("/network-zones", methods=["GET", "POST", "OPTIONS"])
def network_zones_list():
    """
    GET  /api/itam/network-zones  → list approved zones (viewer+)
    POST /api/itam/network-zones  → create zone manually (admin)
    """
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT nz.*,
                           (SELECT COUNT(*) FROM edr_agents ea
                            WHERE ea.current_network_zone = nz.zone_name) AS live_agent_count
                    FROM network_zones nz
                    ORDER BY nz.status, nz.zone_name
                """)
                zones = [dict(r) for r in cur.fetchall()]
            conn.close()
            return jsonify({"zones": zones})
        except psycopg2.Error as exc:
            _log.error("network_zones GET error: %s", exc)
            return jsonify({"error": "Database error"}), 500

    # POST — admin creates a zone manually
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    body = request.get_json(silent=True) or {}
    zone_name        = (body.get("zone_name") or "").strip()
    trusted_cidrs    = body.get("trusted_cidrs", [])
    trusted_gateways = body.get("trusted_gateways", [])
    notes            = body.get("notes", "")
    if not zone_name:
        return jsonify({"error": "zone_name required"}), 400
    if not trusted_cidrs:
        return jsonify({"error": "At least one trusted_cidr required"}), 400

    # Validate CIDRs
    for cidr in trusted_cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return jsonify({"error": f"Invalid CIDR: {cidr}"}), 400

    email = session.get("user_email")
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO network_zones
                  (zone_name, trusted_cidrs, trusted_gateways, status,
                   approved_by, approved_at, auto_discovered, notes)
                VALUES (%s,%s,%s::jsonb,'approved',%s,NOW(),FALSE,%s)
                RETURNING id
            """, [zone_name, trusted_cidrs, json.dumps(trusted_gateways), email, notes])
            row = cur.fetchone()
        conn.commit(); conn.close()
        auth_event(email, "network_zone_created", f"Zone '{zone_name}' created manually")
        return jsonify({"id": row["id"], "zone_name": zone_name}), 201
    except psycopg2.IntegrityError:
        return jsonify({"error": f"Zone '{zone_name}' already exists"}), 409
    except psycopg2.Error as exc:
        _log.error("network_zones POST error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/network-zones/<int:zone_id>", methods=["GET", "PUT", "DELETE", "OPTIONS"])
def network_zone_detail(zone_id):
    """GET / PUT / DELETE a single network zone (admin for PUT/DELETE)."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM network_zones WHERE id=%s", [zone_id])
                row = cur.fetchone()
            conn.close()
            if not row:
                return jsonify({"error": "Not found"}), 404
            return jsonify(dict(row))
        except psycopg2.Error:
            return jsonify({"error": "Database error"}), 500

    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403

    if request.method == "DELETE":
        try:
            conn = _db()
            with conn.cursor() as cur:
                cur.execute("DELETE FROM network_zones WHERE id=%s RETURNING zone_name", [zone_id])
                row = cur.fetchone()
            conn.commit(); conn.close()
            if not row:
                return jsonify({"error": "Not found"}), 404
            auth_event(session.get("user_email"), "network_zone_deleted",
                       f"Zone '{row['zone_name']}' deleted")
            return jsonify({"ok": True})
        except psycopg2.Error:
            return jsonify({"error": "Database error"}), 500

    # PUT
    body = request.get_json(silent=True) or {}
    allowed = {"zone_name", "trusted_cidrs", "trusted_gateways", "notes", "status"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if "trusted_cidrs" in updates:
        for cidr in updates["trusted_cidrs"]:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                return jsonify({"error": f"Invalid CIDR: {cidr}"}), 400
    if not updates:
        return jsonify({"error": "No valid fields"}), 400
    try:
        conn = _db()
        with conn.cursor() as cur:
            set_parts, vals = [], []
            for k, v in updates.items():
                if k == "trusted_gateways":
                    set_parts.append(f"{k}=%s::jsonb"); vals.append(json.dumps(v))
                else:
                    set_parts.append(f"{k}=%s"); vals.append(v)
            set_parts.append("updated_at=NOW()")
            vals.append(zone_id)
            cur.execute(f"UPDATE network_zones SET {', '.join(set_parts)} WHERE id=%s RETURNING id",
                        vals)
            if not cur.fetchone():
                conn.close(); return jsonify({"error": "Not found"}), 404
        conn.commit(); conn.close()
        auth_event(session.get("user_email"), "network_zone_updated", f"Zone #{zone_id} updated")
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("network_zone PUT error: %s", exc)
        return jsonify({"error": "Database error"}), 500


# ── Network Zone Suggestions (auto-discovered, pending admin approval) ────────

@itam_bp.route("/network-zones/suggestions", methods=["GET", "OPTIONS"])
def zone_suggestions_list():
    """List all pending zone suggestions (viewer+). Shows CyCase link."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    status_filter = request.args.get("status", "pending")
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.*, nz.zone_name AS approved_zone_name
                FROM network_zone_suggestions s
                LEFT JOIN network_zones nz ON nz.id = s.approved_zone_id
                WHERE s.status = %s
                ORDER BY s.agent_count DESC, s.created_at DESC
            """, [status_filter])
            rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return jsonify({"suggestions": rows, "total": len(rows)})
    except psycopg2.Error as exc:
        _log.error("zone_suggestions_list error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/network-zones/suggestions/<int:sug_id>/approve", methods=["POST", "OPTIONS"])
def zone_suggestion_approve(sug_id):
    """
    Approve a zone suggestion. Creates a new network_zone or merges into existing.
    Body: { zone_name, notes? }
    Admin only.
    """
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403

    body      = request.get_json(silent=True) or {}
    zone_name = (body.get("zone_name") or "").strip()
    notes     = body.get("notes", "")
    email     = session.get("user_email")
    if not zone_name:
        return jsonify({"error": "zone_name required"}), 400

    try:
        conn = _db()
        with conn.cursor() as cur:
            # Fetch suggestion
            cur.execute("SELECT * FROM network_zone_suggestions WHERE id=%s", [sug_id])
            sug = cur.fetchone()
            if not sug:
                conn.close(); return jsonify({"error": "Suggestion not found"}), 404
            if sug["status"] != "pending":
                conn.close(); return jsonify({"error": f"Suggestion already {sug['status']}"}), 409

            subnet   = sug["subnet_prefix"]
            gw_mac   = sug["gateway_mac"]
            gw_ip    = sug["gateway_ip"] or ""

            # Build or merge gateway entry
            gw_entry = {"ip": gw_ip, "macs": [gw_mac]}
            cidr     = subnet  # e.g. "10.10.0.0/16"

            # Create zone (or update if zone_name already exists)
            cur.execute("""
                INSERT INTO network_zones
                  (zone_name, trusted_cidrs, trusted_gateways, status,
                   approved_by, approved_at, auto_discovered, notes)
                VALUES (%s,ARRAY[%s],%s::jsonb,'approved',%s,NOW(),TRUE,%s)
                ON CONFLICT (zone_name) DO UPDATE SET
                  trusted_cidrs    = ARRAY(
                      SELECT DISTINCT unnest(network_zones.trusted_cidrs || ARRAY[%s])
                  ),
                  trusted_gateways = (
                      CASE WHEN network_zones.trusted_gateways::text LIKE '%%' || %s || '%%'
                           THEN network_zones.trusted_gateways
                           ELSE (network_zones.trusted_gateways::jsonb || %s::jsonb)
                      END
                  ),
                  updated_at       = NOW()
                RETURNING id
            """, [zone_name, cidr, json.dumps([gw_entry]), email, notes,
                  cidr, gw_mac, json.dumps([gw_entry])])
            zone_row = cur.fetchone()
            zone_id  = zone_row["id"]

            # Mark suggestion approved
            cur.execute("""
                UPDATE network_zone_suggestions
                SET status='approved', approved_zone_id=%s, updated_at=NOW()
                WHERE id=%s
            """, [zone_id, sug_id])

        conn.commit(); conn.close()
        auth_event(email, "network_zone_approved",
                   f"Suggestion #{sug_id} approved as zone '{zone_name}' (CIDR: {subnet})")
        return jsonify({"ok": True, "zone_id": zone_id, "zone_name": zone_name})
    except psycopg2.Error as exc:
        _log.error("zone_suggestion_approve error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/network-zones/suggestions/<int:sug_id>/reject", methods=["POST", "OPTIONS"])
def zone_suggestion_reject(sug_id):
    """Reject a pending zone suggestion. Admin only."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    email = session.get("user_email")
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE network_zone_suggestions
                SET status='rejected', updated_at=NOW()
                WHERE id=%s AND status='pending'
                RETURNING id, subnet_prefix, gateway_mac
            """, [sug_id])
            row = cur.fetchone()
        conn.commit(); conn.close()
        if not row:
            return jsonify({"error": "Suggestion not found or already actioned"}), 404
        auth_event(email, "network_zone_rejected",
                   f"Suggestion #{sug_id} rejected ({row['subnet_prefix']} / {row['gateway_mac']})")
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("zone_suggestion_reject error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/network-zones/suggestions/<int:sug_id>/reopen", methods=["POST", "OPTIONS"])
def zone_suggestion_reopen(sug_id):
    """Re-open a previously rejected suggestion, setting it back to pending. Admin only."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    if _role() != "admin":
        return jsonify({"error": "Admin role required"}), 403
    email = session.get("user_email")
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE network_zone_suggestions
                SET status='pending', case_id=NULL, updated_at=NOW()
                WHERE id=%s AND status='rejected'
                RETURNING id, subnet_prefix, gateway_mac
            """, [sug_id])
            row = cur.fetchone()
        conn.commit(); conn.close()
        if not row:
            return jsonify({"error": "Suggestion not found or not in rejected state"}), 404
        auth_event(email, "network_zone_reopened",
                   f"Suggestion #{sug_id} re-opened ({row['subnet_prefix']} / {row['gateway_mac']})")
        return jsonify({"ok": True})
    except psycopg2.Error as exc:
        _log.error("zone_suggestion_reopen error: %s", exc)
        return jsonify({"error": "Database error"}), 500


@itam_bp.route("/network-zones/stats", methods=["GET", "OPTIONS"])
def zone_stats():
    """Summary counts for Network Zones dashboard widget (viewer+)."""
    if request.method == "OPTIONS":
        return add_cors_headers(make_response("", 204))
    if not session.get("user_email"):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        conn = _db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM network_zones WHERE status='approved'")
            approved = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM network_zone_suggestions WHERE status='pending'")
            pending = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM edr_agents WHERE arp_enabled=TRUE AND status='active'")
            arp_active = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM edr_agents WHERE arp_enabled=FALSE AND status='active'")
            arp_blocked = cur.fetchone()["n"]
        conn.close()
        return jsonify({
            "approved_zones":  approved,
            "pending_approval": pending,
            "agents_arp_active": arp_active,
            "agents_arp_blocked": arp_blocked,
        })
    except psycopg2.Error as exc:
        _log.error("zone_stats error: %s", exc)
        return jsonify({"error": "Database error"}), 500
