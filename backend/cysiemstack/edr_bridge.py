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
    Push a normalised EDR alert into the SIEM Redis queue.

    Returns True on success, False on failure (non-fatal — caller logs and continues).
    """
    r = _get_redis()
    if r is None:
        _log.warning("EDR bridge: Redis unavailable — alert dropped from SIEM queue")
        return False

    try:
        envelope = _wrap_as_wazuh(alert)
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
    """Push multiple alerts in a single Redis pipeline. Returns success count."""
    r = _get_redis()
    if r is None:
        return 0
    success = 0
    try:
        pipe = r.pipeline()
        for alert in alerts:
            envelope = _wrap_as_wazuh(alert)
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
