"""
blueprints/edr/policy_engine.py
=================================
CyEDR Policy Engine — policy definition, assignment, and enforcement delivery.

Supported policy types (mirrors SentinelOne / Sophos / Cortex XDR capabilities):
  threat_prevention  — real-time protection, behavioral AI, auto-quarantine, YARA
  device_control     — USB, Bluetooth, WiFi, removable media, CD-ROM
  app_control        — whitelist/blacklist/audit, hash rules, publisher rules, script control
  network_control    — host firewall, inbound/outbound defaults, DNS sinkhole, bandwidth
  exclusions         — scan exclusions by path, process, extension, hash
  update_policy      — auto-update, maintenance window, channel (stable/beta/lts)
  isolation_exceptions — IPs/ports that remain reachable during network isolation

Policies are assigned to individual agents or groups. The agent polls
GET /api/edr/response/<id>/pending; this engine embeds policy diffs in
command payloads using action=APPLY_POLICY so existing command machinery
delivers them without new agent code.

Tables: edr_policies, edr_policy_assignments, edr_agent_groups, edr_group_members
"""
from __future__ import annotations
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras

_log = logging.getLogger(__name__)

POLICY_TYPES = {
    "threat_prevention",
    "device_control",
    "app_control",
    "network_control",
    "exclusions",
    "update_policy",
    "isolation_exceptions",
    "network_probe",
}

# ── Default policy templates ──────────────────────────────────────────────────
POLICY_DEFAULTS: dict[str, dict] = {
    "threat_prevention": {
        "realtime_protection":     True,
        "behavioral_ai":           True,
        "ai_sensitivity":          "medium",     # low / medium / high / aggressive
        "scan_on_write":           True,
        "scan_on_execute":         True,
        "auto_quarantine":         True,
        "auto_remediate":          False,
        "ransomware_rollback":     True,
        "yara_enabled":            True,
        "yara_ruleset":            "default",
        "memory_protection":       True,
        "exploit_prevention":      True,
        "lsass_protection":        True,
        "script_control":          "audit",      # off / audit / block
        "deep_scan_schedule":      "weekly",     # off / daily / weekly / monthly
        "pua_detection":           True,         # Potentially Unwanted Applications
        "amsi_integration":        True,         # Windows AMSI hook
    },
    "device_control": {
        "usb_policy":              "read_only",  # allow / read_only / block / prompt
        "usb_encrypted_only":      False,        # allow only encrypted USB drives
        "usb_corporate_only":      False,        # allow only pre-approved device IDs
        "usb_approved_ids":        [],           # list of approved USB device IDs
        "bluetooth_policy":        "allow",      # allow / block / managed
        "bluetooth_file_transfer": "block",      # allow / block
        "wifi_policy":             "allow",      # allow / managed / block
        "wifi_approved_ssids":     [],           # if managed: restrict to these SSIDs
        "wifi_personal_hotspot":   "allow",      # allow / block
        "removable_media":         "read_only",  # allow / read_only / block
        "cdrom_policy":            "allow",      # allow / block
        "printer_local":           "allow",      # allow / block
        "printer_network":         "allow",      # allow / block
        "camera_policy":           "allow",      # allow / block
        "microphone_policy":       "allow",      # allow / block
        "clipboard_policy":        "allow",      # allow / block / monitor
        "screenshot_policy":       "allow",      # allow / block / monitor
    },
    "app_control": {
        "mode":                    "audit",      # off / audit / whitelist / blacklist
        "block_unsigned":          False,
        "block_unknown":           False,
        "allow_trusted_publishers": True,
        "script_engines_block":    False,        # block powershell/cmd/wscript when in whitelist mode
        "hash_rules":              [],           # [{hash, action, note}]
        "publisher_rules":         [],           # [{publisher, action, note}]
        "path_rules":              [],           # [{path_pattern, action, note}]
        "allowed_apps":            [],           # explicit allowlist entries
        "blocked_apps":            [],           # explicit blocklist entries
    },
    "network_control": {
        "host_firewall_enabled":   True,
        "default_inbound":         "block",      # allow / block
        "default_outbound":        "allow",      # allow / block
        "firewall_rules":          [],           # [{name, direction, protocol, port_range, action, src_ip}]
        "dns_sinkhole":            False,
        "dns_sinkhole_domains":    [],           # custom domains to sinkhole
        "block_malicious_dns":     True,
        "bandwidth_monitor":       True,
        "connection_logging":      "anomalies",  # off / anomalies / all
        "proxy_enforcement":       False,
        "proxy_host":              "",
    },
    "exclusions": {
        "paths":       [],           # path prefixes excluded from scanning
        "processes":   [],           # process image names excluded
        "extensions":  [],           # file extensions excluded (e.g. ".log")
        "hashes":      [],           # SHA-256 hashes excluded
        "network_ips": [],           # IPs excluded from network scanning
        "notes":       "",
    },
    "update_policy": {
        "auto_update":             True,
        "channel":                 "stable",     # stable / beta / lts
        "maintenance_window_start": "02:00",
        "maintenance_window_end":   "04:00",
        "maintenance_days":        ["saturday", "sunday"],
        "max_delay_days":          3,
        "reboot_required":         "prompt",     # auto / prompt / defer
    },
    "isolation_exceptions": {
        "allowed_ips":    [],           # IPs reachable during isolation (e.g. EDR collector IP)
        "allowed_ports":  [443, 8443],  # ports reachable during isolation
        "allow_dns":      True,
        "allow_dhcp":     True,
        "notes":          "",
    },
    "network_probe": {
        "enabled":                 False,
        "subnet":                  "",   # CIDR to scan; empty = auto-detect from agent IP
        "scan_interval_minutes":   60,   # 0 = on-demand only
        "scan_types":              ["subnet"],  # "subnet" | "snmp" (future)
        "ports":                   "22,23,80,443,554,631,8080,8883,9100,161,502,47808",
        "snmp_community":          "public",
        "snmp_port":               161,
        "dns_monitor":             False,
    },
}


def _db(db_url: str):
    return psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)


def ensure_policy_tables(db_url: str) -> None:
    ddl = """
    CREATE TABLE IF NOT EXISTS edr_agent_groups (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        description TEXT,
        created_by  TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        tags        JSONB DEFAULT '[]'::jsonb
    );

    CREATE TABLE IF NOT EXISTS edr_group_members (
        group_id    TEXT NOT NULL REFERENCES edr_agent_groups(id) ON DELETE CASCADE,
        agent_id    TEXT NOT NULL REFERENCES edr_agents(agent_id) ON DELETE CASCADE,
        added_at    TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (group_id, agent_id)
    );

    CREATE TABLE IF NOT EXISTS edr_policies (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        description TEXT,
        policy_type TEXT NOT NULL,
        config      JSONB NOT NULL DEFAULT '{}'::jsonb,
        is_default  BOOLEAN DEFAULT FALSE,
        created_by  TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        updated_at  TIMESTAMPTZ DEFAULT NOW(),
        enabled     BOOLEAN DEFAULT TRUE
    );
    CREATE INDEX IF NOT EXISTS idx_edr_pol_type ON edr_policies(policy_type);

    CREATE TABLE IF NOT EXISTS edr_policy_assignments (
        id          TEXT PRIMARY KEY,
        policy_id   TEXT NOT NULL REFERENCES edr_policies(id) ON DELETE CASCADE,
        target_type TEXT NOT NULL,   -- 'agent' | 'group'
        target_id   TEXT NOT NULL,
        assigned_by TEXT,
        assigned_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(policy_id, target_type, target_id)
    );
    CREATE INDEX IF NOT EXISTS idx_edr_pol_asgn_target ON edr_policy_assignments(target_type, target_id);

    CREATE TABLE IF NOT EXISTS edr_deployment_tokens (
        id          TEXT PRIMARY KEY,
        token       TEXT UNIQUE NOT NULL,
        created_by  TEXT,
        created_at  TIMESTAMPTZ DEFAULT NOW(),
        expires_at  TIMESTAMPTZ,
        used_count  INTEGER DEFAULT 0,
        max_uses    INTEGER DEFAULT 0,   -- 0 = unlimited
        label       TEXT,
        os_type     TEXT DEFAULT 'any',
        revoked     BOOLEAN DEFAULT FALSE
    );
    """
    try:
        conn = _db(db_url)
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()
        conn.close()
    except Exception as exc:
        _log.warning("EDR policy table init failed (non-fatal): %s", exc)


# ── Policy CRUD ───────────────────────────────────────────────────────────────

def create_policy(db_url: str, name: str, policy_type: str, config: dict,
                  description: str, created_by: str) -> dict:
    if policy_type not in POLICY_TYPES:
        raise ValueError(f"Invalid policy_type: {policy_type}. Valid: {sorted(POLICY_TYPES)}")
    # Merge with defaults so config is always complete
    merged = dict(POLICY_DEFAULTS.get(policy_type, {}))
    merged.update(config)
    pid = str(uuid.uuid4())
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO edr_policies (id, name, description, policy_type, config, created_by)
                VALUES (%s,%s,%s,%s,%s,%s) RETURNING *
                """,
                [pid, name, description, policy_type, json.dumps(merged), created_by],
            )
            row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    return row


def list_policies(db_url: str, policy_type: str = None) -> list[dict]:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            if policy_type:
                cur.execute("SELECT * FROM edr_policies WHERE policy_type=%s ORDER BY created_at DESC", [policy_type])
            else:
                cur.execute("SELECT * FROM edr_policies ORDER BY policy_type, name")
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
        r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
    return rows


def get_policy(db_url: str, policy_id: str) -> dict | None:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM edr_policies WHERE id=%s", [policy_id])
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    r = dict(row)
    r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
    r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
    return r


def update_policy(db_url: str, policy_id: str, updates: dict) -> dict:
    allowed_fields = {"name", "description", "config", "enabled"}
    sets, vals = [], []
    for k, v in updates.items():
        if k not in allowed_fields:
            continue
        sets.append(f"{k}=%s")
        vals.append(json.dumps(v) if k == "config" else v)
    if not sets:
        raise ValueError("No valid fields to update")
    sets.append("updated_at=NOW()")
    vals.append(policy_id)
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE edr_policies SET {','.join(sets)} WHERE id=%s RETURNING *", vals)
            row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    return row


def delete_policy(db_url: str, policy_id: str) -> None:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM edr_policies WHERE id=%s", [policy_id])
        conn.commit()
    finally:
        conn.close()


def assign_policy(db_url: str, policy_id: str, target_type: str,
                  target_ids: list[str], assigned_by: str) -> int:
    """Assign a policy to one or more agents/groups. Returns count assigned."""
    if target_type not in ("agent", "group"):
        raise ValueError("target_type must be 'agent' or 'group'")
    conn = _db(db_url)
    count = 0
    try:
        with conn.cursor() as cur:
            for tid in target_ids:
                cur.execute(
                    """
                    INSERT INTO edr_policy_assignments
                      (id, policy_id, target_type, target_id, assigned_by)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (policy_id, target_type, target_id) DO NOTHING
                    """,
                    [str(uuid.uuid4()), policy_id, target_type, tid, assigned_by],
                )
                count += cur.rowcount
            # Queue APPLY_POLICY command for each affected agent
            if target_type == "agent":
                agent_ids = target_ids
            else:
                cur.execute(
                    "SELECT agent_id FROM edr_group_members WHERE group_id=ANY(%s)", [target_ids]
                )
                agent_ids = [r["agent_id"] for r in cur.fetchall()]

            policy_row = None
            cur.execute("SELECT * FROM edr_policies WHERE id=%s", [policy_id])
            policy_row = cur.fetchone()

            if policy_row:
                for aid in agent_ids:
                    cur.execute(
                        """
                        INSERT INTO edr_response_commands
                          (id, agent_id, action, parameters, issued_by, auto_triggered)
                        VALUES (%s,%s,'APPLY_POLICY',%s,%s,FALSE)
                        """,
                        [
                            str(uuid.uuid4()), aid,
                            json.dumps({
                                "policy_id":   policy_id,
                                "policy_type": dict(policy_row)["policy_type"],
                                "config":      dict(policy_row)["config"],
                            }),
                            assigned_by,
                        ],
                    )
        conn.commit()
    finally:
        conn.close()
    return count


def get_agent_effective_policies(db_url: str, agent_id: str) -> list[dict]:
    """Return merged effective policies for an agent (direct + group assignments)."""
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT DISTINCT p.* FROM edr_policies p
                JOIN edr_policy_assignments a ON a.policy_id=p.id
                WHERE p.enabled=TRUE AND (
                    (a.target_type='agent' AND a.target_id=%s)
                    OR
                    (a.target_type='group' AND a.target_id IN (
                        SELECT group_id FROM edr_group_members WHERE agent_id=%s
                    ))
                )
                ORDER BY p.policy_type, p.created_at
                """,
                [agent_id, agent_id],
            )
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
        r["updated_at"] = r["updated_at"].isoformat() if r.get("updated_at") else None
    return rows


# ── Deployment tokens ─────────────────────────────────────────────────────────

def create_deployment_token(db_url: str, label: str, created_by: str,
                             os_type: str = "any", max_uses: int = 0,
                             expires_hours: int = 0) -> dict:
    import secrets as _secrets
    from datetime import timedelta
    token  = _secrets.token_urlsafe(32)
    tok_id = str(uuid.uuid4())
    expires_at = None
    if expires_hours > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO edr_deployment_tokens
                  (id, token, created_by, expires_at, max_uses, label, os_type)
                VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *
                """,
                [tok_id, token, created_by, expires_at, max_uses, label, os_type],
            )
            row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    for k in ("created_at", "expires_at"):
        if row.get(k):
            row[k] = row[k].isoformat()
    return row


def list_deployment_tokens(db_url: str) -> list[dict]:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id,token,label,os_type,created_by,created_at,expires_at,used_count,max_uses,revoked "
                "FROM edr_deployment_tokens ORDER BY created_at DESC"
            )
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    for r in rows:
        for k in ("created_at", "expires_at"):
            if r.get(k):
                r[k] = r[k].isoformat()
    return rows


def revoke_deployment_token(db_url: str, tok_id: str) -> None:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE edr_deployment_tokens SET revoked=TRUE WHERE id=%s", [tok_id])
        conn.commit()
    finally:
        conn.close()


def validate_deployment_token(db_url: str, token: str) -> bool:
    """Called during agent self-enrollment to validate a deployment token."""
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, expires_at, used_count, max_uses, revoked
                FROM edr_deployment_tokens WHERE token=%s
                """,
                [token],
            )
            row = cur.fetchone()
            if not row or row["revoked"]:
                return False
            if row["expires_at"] and row["expires_at"] < datetime.now(timezone.utc):
                return False
            if row["max_uses"] > 0 and row["used_count"] >= row["max_uses"]:
                return False
            cur.execute(
                "UPDATE edr_deployment_tokens SET used_count=used_count+1 WHERE id=%s",
                [row["id"]],
            )
        conn.commit()
    finally:
        conn.close()
    return True


# ── Group management ──────────────────────────────────────────────────────────

def create_group(db_url: str, name: str, description: str, created_by: str) -> dict:
    gid = str(uuid.uuid4())
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO edr_agent_groups (id,name,description,created_by) VALUES (%s,%s,%s,%s) RETURNING *",
                [gid, name, description, created_by],
            )
            row = dict(cur.fetchone())
        conn.commit()
    finally:
        conn.close()
    return row


def list_groups(db_url: str) -> list[dict]:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT g.*, COUNT(m.agent_id) as member_count
                FROM edr_agent_groups g
                LEFT JOIN edr_group_members m ON m.group_id=g.id
                GROUP BY g.id ORDER BY g.name
                """
            )
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    for r in rows:
        r["created_at"] = r["created_at"].isoformat() if r.get("created_at") else None
    return rows


def add_agents_to_group(db_url: str, group_id: str, agent_ids: list[str]) -> int:
    conn = _db(db_url)
    count = 0
    try:
        with conn.cursor() as cur:
            for aid in agent_ids:
                cur.execute(
                    "INSERT INTO edr_group_members (group_id,agent_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    [group_id, aid],
                )
                count += cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return count


def delete_group(db_url: str, group_id: str) -> bool:
    conn = _db(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM edr_group_members WHERE group_id=%s", [group_id])
            cur.execute("DELETE FROM edr_agent_groups WHERE id=%s", [group_id])
            deleted = cur.rowcount > 0
        conn.commit()
    finally:
        conn.close()
    return deleted
