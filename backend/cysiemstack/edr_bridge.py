"""
cysiemstack/edr_bridge.py
===========================
Bridges CyEDR normalised alert dicts into the existing SIEM correlation
pipeline by pushing them onto the Redis LIST that the ingestor.py reads from.

The ingestor already handles the `cysiemstack:alerts:raw` key — EDR events
are wrapped in a synthetic Wazuh-compatible envelope so the normaliser, grouper,
correlator, UEBA engine, risk scorer, MISP enricher, and LLM enricher all
process them without code changes.

EDR-sourced events are identifiable by:
  - rule_id in range 100300-100399
  - full_alert.edr == True
  - agent.name starting with the agent's hostname (set during enrollment)

High-confidence detections (score >= 80) are also auto-escalated to CyCases
via the existing cases_bp service layer.
"""
from __future__ import annotations
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)

# Redis LIST key — must match correlation_engine/config.py redis_alert_key default
_REDIS_KEY  = "cysiemstack:alerts:raw"
_REDIS_URL  = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

# Score threshold above which a CyCases ticket is auto-opened
_CASES_AUTO_THRESHOLD = 80.0

# Lazy Redis client (sync — Flask request context)
_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(_REDIS_URL, decode_responses=True)
        except Exception as exc:
            _log.error("EDR bridge: Redis connect failed: %s", exc)
    return _redis_client


def _wrap_as_wazuh(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Wrap a normalised EDR alert dict into the Wazuh JSON envelope format
    that ingestor.py / normaliser.py expects from the Redis queue.

    The normaliser already handles arbitrary rule IDs — EDR synthetic IDs
    (100300-100399) will be processed like any custom Wazuh rule.
    """
    ts = alert.get("timestamp")
    if isinstance(ts, datetime):
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    else:
        ts_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    process = alert.get("full_alert", {}).get("process") or {}

    return {
        "@timestamp": ts_str,
        "id":         alert.get("wazuh_id", ""),
        "agent": {
            "id":   alert.get("agent_id", "000"),
            "name": alert.get("agent_name", ""),
            "ip":   alert.get("agent_ip", ""),
        },
        "rule": {
            "id":          str(alert.get("rule_id", 100399)),
            "description": alert.get("rule_desc", "EDR behavioral detection"),
            "level":       alert.get("rule_level", 7),
            "mitre": {
                "id":     [alert.get("mitre_id", "")] if alert.get("mitre_id") else [],
                "tactic": [alert.get("mitre_tactic", "")] if alert.get("mitre_tactic") else [],
            },
        },
        "data": {
            "srcip":       alert.get("src_ip", ""),
            "dstip":       alert.get("dst_ip", ""),
            "win": {
                "eventdata": {
                    "commandLine":    process.get("command_line", ""),
                    "image":          process.get("executable_path", ""),
                    "parentImage":    (alert.get("full_alert", {}).get("parent_process") or {}).get("executable_path", ""),
                    "user":           process.get("user_sid_or_uid", ""),
                    "fileHashSha256": process.get("file_hash_sha256", ""),
                },
            },
            "edr": alert.get("full_alert", {}),
        },
        "syscheck": {
            "path": alert.get("file_path", ""),
        },
        "_raw_log": alert.get("raw_log", ""),
    }


def forward_to_siem(alert: dict[str, Any]) -> bool:
    """
    Push a normalised EDR alert into the SIEM Redis queue (the pipeline the
    correlation engine actually consumes today), and additively onto the
    Phase 2 Kafka bus if KAFKA_ENABLED (see kafka_bridge.py — CyDataLake
    migration; nothing consumes that topic yet, transport only).

    Returns True on success, False on failure (non-fatal — caller logs and continues).
    """
    envelope = _wrap_as_wazuh(alert)

    from . import kafka_bridge
    try:
        kafka_bridge.publish(kafka_bridge.TOPIC_EDR, envelope)
    except Exception as exc:
        _log.debug("EDR bridge: Kafka publish skipped: %s", exc)

    r = _get_redis()
    if r is None:
        _log.warning("EDR bridge: Redis unavailable — alert dropped from SIEM queue")
        return False

    try:
        r.rpush(_REDIS_KEY, json.dumps(envelope))
        _log.debug(
            "EDR→SIEM: agent=%s rule=%s score=%.1f",
            alert.get("agent_id"), alert.get("rule_id"), alert.get("_edr_score", 0),
        )
    except Exception as exc:
        _log.error("EDR bridge: Redis push failed: %s", exc)
        return False

    # Auto-escalate to CyCases for high-confidence detections
    score = float(alert.get("_edr_score", 0))
    if score >= _CASES_AUTO_THRESHOLD:
        _try_open_case(alert)

    return True


def _try_open_case(alert: dict[str, Any]) -> None:
    """
    Auto-open a CyCases case for a high-confidence EDR detection.

    open_case() in service.py operates on *existing* SIEM incidents —
    it takes (conn, incident_id, opened_by).  EDR events enter the pipeline
    via the Redis queue, get correlated into an Incident row by the engine,
    and that Incident is what open_case() must act on.

    Strategy: poll the incidents table for the SIEM incident that was just
    created from this wazuh_id, then open the case from it.  Use a short
    retry window (up to 10 s) to allow the async ingestor time to commit.
    Non-fatal: any failure is logged and swallowed.
    """
    import time
    try:
        import psycopg2
        import psycopg2.extras
        from blueprints.cases.service import open_case
        from core.config import CYCENTRA_DB_URL

        wazuh_id = alert.get("wazuh_id", "")
        if not wazuh_id:
            return

        conn = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        incident_id = None
        # Wait up to 10 s for the ingestor to create the incident from this alert
        for _ in range(5):
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT a.incident_id FROM alerts a
                    WHERE a.wazuh_id = %s AND a.incident_id IS NOT NULL
                    LIMIT 1
                    """,
                    [wazuh_id],
                )
                row = cur.fetchone()
            if row and row["incident_id"]:
                incident_id = row["incident_id"]
                break
            time.sleep(2)

        if not incident_id:
            _log.debug("EDR bridge: no incident found for %s within window", wazuh_id)
            conn.close()
            return

        open_case(conn, incident_id, opened_by="cyedr-auto", case_type="edr_detection")
        conn.commit()
        conn.close()
        _log.info(
            "EDR bridge: CyCases case opened incident=%s agent=%s score=%.1f",
            incident_id, alert.get("agent_id"), alert.get("_edr_score", 0),
        )
    except Exception as exc:
        _log.warning("EDR bridge: CyCases open failed (non-fatal): %s", exc)


def bulk_forward(alerts: list[dict[str, Any]]) -> int:
    """Push multiple alerts in a single Redis pipeline (plus an additive Kafka
    publish, see forward_to_siem). Returns success count."""
    r = _get_redis()
    if r is None:
        return 0
    envelopes = [_wrap_as_wazuh(alert) for alert in alerts]

    from . import kafka_bridge
    try:
        kafka_bridge.publish_many(kafka_bridge.TOPIC_EDR, envelopes)
    except Exception as exc:
        _log.debug("EDR bridge: Kafka bulk publish skipped: %s", exc)

    success = 0
    try:
        pipe = r.pipeline()
        for envelope in envelopes:
            pipe.rpush(_REDIS_KEY, json.dumps(envelope))
        pipe.execute()
        success = len(alerts)
    except Exception as exc:
        _log.error("EDR bridge bulk forward failed: %s", exc)
        # Fallback: push individually
        for alert in alerts:
            if forward_to_siem(alert):
                success += 1
    return success


# ── ASM / ITAM → SIEM bridge ──────────────────────────────────────────────────
#
# Rule ID allocation — synthetic IDs, never loaded into Wazuh.
# Range 200100-200199 (ASM) and 200200-200299 (ITAM) are unoccupied:
#   cy_cust_rules.xml uses 100100-101042 (Wazuh/kernel rules)
#   EDR synthetic uses 100300-100399 (confidence_matrix.py)
#   YARA synthetic uses 100210-100211 (routes.py _ingest_yara_scan_result)
#
# These IDs live ONLY in the cysiemstack alerts table (correlation DB).
# They never pass through the Wazuh rule engine. No XML entry is needed.
# They are NOT added by cycentra-setup.sh — recognised purely by normaliser.py
# via the ASM_RULE_IDS / ITAM_*_RULE_IDS sets checked in _classify_category().
#
#   200100  ASM critical finding    (level 15 → severity=critical)
#   200101  ASM high finding        (level 12 → severity=high)
#   200102  ASM medium finding      (level  7 → severity=medium)
#   200103  ASM finding escalated by analyst  (level 10 → severity=high)
#   200200  ITAM critical CVE on asset        (level 15 → severity=critical)
#   200201  ITAM high CVE on asset            (level 12 → severity=high)
#   200202  ITAM high-risk IoT device         (level 10 → severity=high)
#   200203  ITAM shadow-AI / rogue service    (level  9 → severity=high)

_ASM_RULE_IDS: dict[str, int] = {
    "critical":  200100,
    "high":      200101,
    "medium":    200102,
    "escalated": 200103,
}

_ITAM_RULE_IDS: dict[str, int] = {
    "cve_critical":  200200,
    "cve_high":      200201,
    "iot_high_risk": 200202,
    "shadow_ai":     200203,
}

# Wazuh rule level → these are consumed by normaliser._level_to_score()
# level 15 → 8.2 (critical), 12 → 7.6 (high), 10 → 7.1 (high), 9 → 7.0 (high), 7 → 6.2 (medium)
_ASM_RULE_LEVELS: dict[str, int] = {
    "critical":  15,
    "high":      12,
    "medium":     7,
    "escalated": 10,
}
_ITAM_RULE_LEVELS: dict[str, int] = {
    "cve_critical":  15,
    "cve_high":      12,
    "iot_high_risk": 10,
    "shadow_ai":      9,
}


def _build_asm_alert(finding: dict, domain: str, override_severity: str | None = None) -> dict[str, Any]:
    """
    Convert an ASM finding dict into the internal alert format that
    _wrap_as_wazuh() / forward_to_siem() expects.
    """
    raw_sev   = (override_severity or finding.get("severity", "medium") or "medium").lower()
    severity  = raw_sev if raw_sev in _ASM_RULE_IDS else "medium"
    rule_id   = _ASM_RULE_IDS[severity]
    level     = _ASM_RULE_LEVELS[severity]
    vuln      = str(finding.get("vulnerability") or finding.get("module") or "ASM Finding")[:200]
    desc      = str(finding.get("description") or "")

    return {
        "wazuh_id":   finding.get("asm_id") or finding.get("id") or "",
        "timestamp":  datetime.now(timezone.utc),
        "agent_id":   f"asm-{domain[:30]}",
        "agent_name": domain,
        "agent_ip":   None,
        "rule_id":    rule_id,
        "rule_desc":  f"[ASM] {vuln}"[:200],
        "rule_level": level,
        "category":   "asm",
        "mitre_id":   None,
        "mitre_tactic": None,
        "src_ip":     None,
        "raw_log":    desc[:2000],
        "full_alert": {
            "asm":    True,
            "domain": domain,
            "groups": ["asm"],
            **{k: v for k, v in finding.items()},
        },
    }


def push_asm_finding(finding: dict, domain: str, override_severity: str | None = None) -> bool:
    """
    Push a single ASM finding into the SIEM correlation pipeline.

    finding dict keys (all optional except vulnerability/module):
        asm_id, vulnerability, severity, module, description, recommendation, risk_score

    Returns True on success (Redis push). Non-fatal on failure.
    Automatically opens a CyCase for critical findings after the ingestor
    creates the incident row (same pattern as EDR high-confidence detections).
    """
    alert = _build_asm_alert(finding, domain, override_severity)
    ok    = forward_to_siem(alert)

    # Critical ASM findings → force-open a case (don't wait for alert_count ≥ 3)
    sev = (override_severity or finding.get("severity", "")).lower()
    if ok and sev == "critical":
        _try_open_case({"wazuh_id": alert["wazuh_id"],
                        "_edr_score": 100,
                        "agent_id": alert["agent_id"]})
    return ok


def push_asm_scan_findings(findings: list[dict], domain: str, min_severity: str = "high") -> int:
    """
    Push all findings from a completed ASM scan that meet min_severity.
    Called once per scan on first result read (guarded by a .siem_pushed marker).
    Returns number of alerts successfully pushed.
    """
    _SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0, "informational": -1}
    threshold = _SEV_RANK.get(min_severity.lower(), 2)

    r = _get_redis()
    if r is None:
        _log.warning("ASM bridge: Redis unavailable — scan findings not forwarded to SIEM")
        return 0

    pushed = 0
    try:
        pipe = r.pipeline()
        for finding in findings:
            sev = (finding.get("severity") or "low").lower()
            if _SEV_RANK.get(sev, 0) < threshold:
                continue
            alert    = _build_asm_alert(finding, domain)
            envelope = _wrap_as_wazuh(alert)
            pipe.rpush(_REDIS_KEY, json.dumps(envelope))
            pushed += 1
        if pushed:
            pipe.execute()
            _log.info("ASM bridge: pushed %d finding(s) for domain=%s to SIEM", pushed, domain)
    except Exception as exc:
        _log.error("ASM bridge: bulk push failed: %s", exc)
        # Fallback: push individually
        pushed = 0
        for finding in findings:
            sev = (finding.get("severity") or "low").lower()
            if _SEV_RANK.get(sev, 0) < threshold:
                continue
            if push_asm_finding(finding, domain):
                pushed += 1

    return pushed


def push_itam_anomaly(anomaly_type: str, asset: dict, details: dict) -> bool:
    """
    Push an ITAM anomaly into the SIEM correlation pipeline.

    anomaly_type: one of 'cve_critical', 'cve_high', 'iot_high_risk', 'shadow_ai'
    asset:  dict with at least {id, ip_address/ip, hostname} (from network_assets row)
    details: {description, cve_id, cvss_score, package, ai_tool, risk_score, ...}

    Returns True on success.
    """
    rule_id = _ITAM_RULE_IDS.get(anomaly_type, 200203)
    level   = _ITAM_RULE_LEVELS.get(anomaly_type, 9)

    _CATEGORY_MAP = {
        "cve_critical":  "vulnerability",
        "cve_high":      "vulnerability",
        "iot_high_risk": "asm",
        "shadow_ai":     "system",
    }
    category = _CATEGORY_MAP.get(anomaly_type, "system")

    ip       = str(asset.get("ip_address") or asset.get("ip") or "")
    hostname = (asset.get("hostname") or asset.get("agent_name") or ip or "unknown")[:80]
    desc     = str(details.get("description") or f"ITAM anomaly [{anomaly_type}] on {hostname}")

    wazuh_id = f"itam-{anomaly_type}-{asset.get('id', '0')}"

    alert: dict[str, Any] = {
        "wazuh_id":   wazuh_id,
        "timestamp":  datetime.now(timezone.utc),
        "agent_id":   f"itam-{hostname[:30]}",
        "agent_name": hostname,
        "agent_ip":   ip or None,
        "rule_id":    rule_id,
        "rule_desc":  desc[:200],
        "rule_level": level,
        "category":   category,
        "mitre_id":   None,
        "mitre_tactic": None,
        "src_ip":     None,
        "raw_log":    desc[:2000],
        "full_alert": {
            "itam":         True,
            "anomaly_type": anomaly_type,
            "asset":        asset,
            "groups":       [category, "itam"],
            **details,
        },
    }

    ok = forward_to_siem(alert)

    # Critical CVEs → force-open case immediately
    if ok and anomaly_type == "cve_critical":
        _try_open_case({"wazuh_id": wazuh_id, "_edr_score": 100, "agent_id": alert["agent_id"]})

    return ok
