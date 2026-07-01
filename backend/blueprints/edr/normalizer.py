"""
blueprints/edr/normalizer.py
==============================
Converts a raw EDR TelemetryEnvelope JSON payload (received via the agent
gRPC collector or HTTP ingest API) into the normalized alert dict that the
existing SIEM ingestor / correlation engine pipeline expects.

Output schema matches what normaliser.py emits for Wazuh events — the
downstream grouper, correlator, UEBA, MISP enricher, and risk scorer all
consume this format without modification.

EDR synthetic rule IDs occupy the 100300–100399 range to avoid collisions
with Wazuh rule IDs (1–99999) and the existing custom range (100200–100299).
"""
from __future__ import annotations
import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

from .confidence_matrix import compute_score, HEURISTIC_TABLE

# ── MITRE ATT&CK lookup (supplement confidence_matrix mappings) ───────────────
# Maps EDR event categories to default MITRE technique when no trigger fires
_CATEGORY_MITRE: dict[str, tuple[str, str]] = {
    "PROCESS":   ("T1059",  "Execution"),
    "NETWORK":   ("T1071",  "Command and Control"),
    "FILE":      ("T1565",  "Impact"),
    "REGISTRY":  ("T1112",  "Defense Evasion"),
    "MEMORY":    ("T1055",  "Defense Evasion"),
    "DNS":       ("T1071.004", "Command and Control"),
    "AUTH":      ("T1078",  "Initial Access"),
    "CyScan":    ("T1204",  "Execution"),
}

# Minimum confidence score to emit an alert into the SIEM pipeline
MIN_SCORE_THRESHOLD = 10.0


def _safe_ts(ts_epoch_ns: Optional[int]) -> datetime:
    """Convert nanosecond epoch to UTC datetime, fallback to now."""
    try:
        return datetime.fromtimestamp(ts_epoch_ns / 1e9, tz=timezone.utc)
    except Exception:
        return datetime.now(tz=timezone.utc)


def _derive_wazuh_id(event_uuid: str, endpoint_uuid: str) -> str:
    """Deterministic synthetic wazuh_id so duplicate events are deduplicated."""
    raw = f"edr:{endpoint_uuid}:{event_uuid}"
    return "edr-" + hashlib.sha1(raw.encode()).hexdigest()[:16]


def normalise_telemetry(envelope: dict[str, Any]) -> Optional[dict[str, Any]]:
    """
    Convert a CyEDR TelemetryEnvelope dict into a SIEM-compatible alert dict.

    Returns None if the event is below the minimum score threshold or
    missing required fields.

    Expected envelope keys (from Protobuf / JSON wire format):
        timestamp_epoch_ns, endpoint_uuid, os_type, event_uuid,
        event_category, process, parent_process, event_payload,
        triggers, ti_match, asset_type, hostname, agent_ip
    """
    event_uuid    = envelope.get("event_uuid", "")
    endpoint_uuid = envelope.get("endpoint_uuid", "")
    if not endpoint_uuid or not event_uuid:
        return None

    event_category = envelope.get("event_category", "PROCESS").upper()
    triggers       = envelope.get("triggers", [])       # list[str] heuristic keys
    ti_match       = bool(envelope.get("ti_match", False))
    asset_type     = envelope.get("asset_type", "unknown")
    hostname       = envelope.get("hostname", endpoint_uuid[:12])
    agent_ip       = envelope.get("agent_ip", "")

    # Score the detection
    scoring = compute_score(triggers, ti_match=ti_match, asset_type=asset_type)
    if scoring["score"] < MIN_SCORE_THRESHOLD:
        return None

    # Pull process actor fields
    process = envelope.get("process") or {}
    parent  = envelope.get("parent_process") or {}

    process_name = _extract_basename(process.get("executable_path", ""))
    username     = process.get("user_sid_or_uid", "")
    cmd_line     = process.get("command_line", "")

    # Extract network fields from event_payload if present
    payload: dict = {}
    raw_payload = envelope.get("event_payload")
    if isinstance(raw_payload, (bytes, str)):
        try:
            payload = json.loads(raw_payload) if isinstance(raw_payload, str) else json.loads(raw_payload.decode())
        except Exception:
            pass
    elif isinstance(raw_payload, dict):
        payload = raw_payload

    src_ip  = payload.get("src_ip") or agent_ip or ""
    dst_ip  = payload.get("dst_ip") or payload.get("remote_ip") or ""
    file_path = payload.get("file_path") or process.get("executable_path") or ""

    # MITRE from scoring engine; fallback to category default
    mitre_id    = scoring["mitre_id"]    or _CATEGORY_MITRE.get(event_category, ("", ""))[0]
    mitre_tactic = scoring["mitre_tactic"] or _CATEGORY_MITRE.get(event_category, ("", ""))[1]

    # Map severity → base_score on the normaliser's 0-15 scale
    sev_to_base = {"critical": 12.0, "high": 9.0, "medium": 6.0, "low": 4.0}
    base_score = sev_to_base.get(scoring["severity"], 4.0)

    # Build the full raw log string for SIEM storage
    raw_log = (
        f"[CyEDR] {event_category} | host={hostname} | pid={process.get('pid',0)} "
        f"| proc={process_name} | cmd={cmd_line[:120]} | score={scoring['score']} "
        f"| triggers={','.join(triggers)}"
    )

    return {
        "wazuh_id":     _derive_wazuh_id(event_uuid, endpoint_uuid),
        "timestamp":    _safe_ts(envelope.get("timestamp_epoch_ns")),
        "agent_id":     endpoint_uuid,
        "agent_name":   hostname,
        "agent_ip":     agent_ip,
        "rule_id":      scoring["rule_id"],
        "rule_desc":    scoring["rule_desc"],
        "rule_level":   scoring["rule_level"],
        "base_score":   base_score,
        "category":     event_category,
        "mitre_id":     mitre_id,
        "mitre_tactic": mitre_tactic,
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "username":     username,
        "process_name": process_name,
        "file_path":    file_path,
        "raw_log":      raw_log,
        "full_alert": {
            "edr":          True,
            "endpoint_uuid": endpoint_uuid,
            "event_uuid":   event_uuid,
            "event_category": event_category,
            "os_type":      envelope.get("os_type"),
            "hostname":     hostname,
            "process":      process,
            "parent_process": parent,
            "triggers":     triggers,
            "confidence_score": scoring["score"],
            "severity":     scoring["severity"],
            "asset_type":   asset_type,
            "ti_match":     ti_match,
            "payload":      payload,
            "story_id":     envelope.get("story_id", ""),
        },
        # EDR-specific extras consumed by edr_bridge.py
        "_edr_score":    scoring["score"],
        "_edr_severity": scoring["severity"],
        "_edr_triggers": triggers,
    }


def _extract_basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").split("/")[-1]
