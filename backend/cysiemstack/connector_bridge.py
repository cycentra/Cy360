"""
cysiemstack/connector_bridge.py
==================================
Normalizes multi-vendor SIEM connector output (see cysiemstack/connectors/)
into the same synthetic-Wazuh envelope shape proven by edr_bridge.py and
collector_bridge.py, and pushes it onto the existing Redis queue (plus,
additively, Kafka — see kafka_bridge.py). Zero changes needed to
ingestor.py/normaliser.py/grouper.py.

Unlike CyCollector's Phase 1 raw logs, these vendors already ran their own
detection — so unlike collector_bridge.py's flat level-3/"low" treatment,
each vendor's native severity is mapped to a real Wazuh level (see the
per-vendor _RULE_IDS / _RULE_LEVELS tables below), which the correlation
engine's existing grouper._score_to_severity() then turns into a real
incident severity.

Wazuh is the one exception: WazuhConnector already returns documents in the
native Wazuh envelope shape (see wazuh_connector.py docstring), so it is
pushed through unchanged — no _normalize_* function, no synthetic rule_id.

Rule ID allocation (extends the registry in docs/CYDATALAKE_MIGRATION_PLAN.md §10):
  101300-101303  Splunk      (critical/high/medium/low)
  101310-101313  QRadar      (critical/high/medium/low)
  101320-101323  SentinelOne (critical/high/medium/low)
  101330-101333  Palo Alto Cortex XDR/XSIAM (critical/high/medium/low)
  101340-101343  Office 365 (Management Activity API) (critical/high/medium/low)
  101350-101353  Azure AD / Entra ID (Graph sign-ins + directory audits)
  101360-101363  AWS CloudTrail
  101370-101373  GCP Cloud Audit Logs

Cloud connectors (office365/azure/aws/gcp) bypass Wazuh entirely — they are
the first ingestion path in this platform that doesn't need Wazuh installed
at all for cloud log coverage (previously 100% wazuh-wodle-mediated; see
docs/CYDATALAKE_MIGRATION_PLAN.md §0/§7). Their severity mappings are mostly
heuristics on operation/event names (O365, AWS) or partial risk signals
(Azure), not documented vendor severity taxonomies — GCP is the exception,
its LogSeverity enum is a real documented mapping. Expect to retune all four
once real tenant traffic is available.
"""
from __future__ import annotations
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

_log = logging.getLogger(__name__)

_REDIS_KEY = "cysiemstack:alerts:raw"
_REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

# level → base_score bucket, mirrors normaliser._level_to_score() / grouper._score_to_severity()
_LEVELS = {"critical": 15, "high": 12, "medium": 7, "low": 3}

_RULE_IDS = {
    "splunk":      {"critical": 101300, "high": 101301, "medium": 101302, "low": 101303},
    "qradar":      {"critical": 101310, "high": 101311, "medium": 101312, "low": 101313},
    "sentinelone": {"critical": 101320, "high": 101321, "medium": 101322, "low": 101323},
    "paloalto":    {"critical": 101330, "high": 101331, "medium": 101332, "low": 101333},
    "office365":   {"critical": 101340, "high": 101341, "medium": 101342, "low": 101343},
    "azure":       {"critical": 101350, "high": 101351, "medium": 101352, "low": 101353},
    "aws":         {"critical": 101360, "high": 101361, "medium": 101362, "low": 101363},
    "gcp":         {"critical": 101370, "high": 101371, "medium": 101372, "low": 101373},
}

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(_REDIS_URL, decode_responses=True)
        except Exception as exc:
            _log.error("Connector bridge: Redis connect failed: %s", exc)
    return _redis_client


def _envelope(vendor: str, severity: str, agent_name: str, description: str,
              raw: dict[str, Any], entity: str = "", rule_id_override: int | None = None) -> dict[str, Any]:
    rule_id = rule_id_override if rule_id_override is not None else _RULE_IDS[vendor][severity]
    level   = _LEVELS[severity]
    return {
        "@timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "id":         str(uuid.uuid4()),
        "agent": {"id": f"{vendor}-connector", "name": agent_name or vendor, "ip": entity},
        "rule": {
            "id":          str(rule_id),
            "description": f"[{vendor}] {description}"[:200],
            "level":       level,
            "groups":      ["connector", vendor],
        },
        "data": {"connector": {"vendor": vendor, "raw": raw}},
        "full_alert": {"connector": True, "vendor": vendor, "groups": ["connector", vendor]},
        "_raw_log": json.dumps(raw)[:4000],
    }


# ── Per-vendor normalization (native shape → severity bucket + envelope) ──────

def _normalize_splunk(event: dict[str, Any]) -> dict[str, Any]:
    urgency = str(event.get("urgency", event.get("severity", "low"))).lower()
    severity = urgency if urgency in _LEVELS else ("low" if urgency == "informational" else "medium")
    desc = event.get("rule_title") or event.get("search_name") or event.get("_raw", "Splunk event")
    return _envelope("splunk", severity, event.get("dest", ""), str(desc), event, entity=event.get("dest", ""))


def _normalize_qradar(offense: dict[str, Any]) -> dict[str, Any]:
    mag = int(offense.get("severity", 0) or 0)
    severity = "critical" if mag >= 8 else "high" if mag >= 6 else "medium" if mag >= 4 else "low"
    desc = offense.get("description") or f"QRadar offense #{offense.get('id')}"
    return _envelope("qradar", severity, "", str(desc), offense)


def _normalize_sentinelone(threat: dict[str, Any]) -> dict[str, Any]:
    info = threat.get("threatInfo") or {}
    confidence = str(info.get("confidenceLevel", "")).lower()
    severity = {"malicious": "critical", "suspicious": "high"}.get(confidence, "medium")
    desc = info.get("threatName") or "SentinelOne threat"
    agent = (threat.get("agentRealtimeInfo") or {}).get("agentComputerName", "")
    return _envelope("sentinelone", severity, agent, str(desc), threat)


def _normalize_paloalto(incident: dict[str, Any]) -> dict[str, Any]:
    severity = str(incident.get("severity", "low")).lower()
    if severity not in _LEVELS:
        severity = "medium"
    desc = incident.get("description") or incident.get("incident_name") or "Cortex incident"
    return _envelope("paloalto", severity, "", str(desc), incident)


# ── Sigma-first path for cloud connectors ─────────────────────────────────────
# office365/azure/aws/gcp have real, imported SigmaHQ rules covering exactly
# these sources (cysiemstack/detection/rules/imported/cloud/, .../identity/) —
# unlike CyCollector's raw.syslog, these events are already structured JSON, so
# match_raw() searches the actual record rather than a free-text haystack. A
# Sigma match takes priority over the vendor's own heuristic mapping below,
# since a real, sourced detection rule is more trustworthy than a hand-rolled
# operation-name guess.
def _sigma_envelope(vendor: str, raw: dict[str, Any], entity: str) -> Optional[dict[str, Any]]:
    try:
        from .detection.sigma_engine import get_engine, CONNECTOR_SIGMA_RULE_IDS
        matched = get_engine().match_raw(raw, logsource_hint={"product": vendor})
    except Exception as exc:
        _log.debug("Connector bridge: Sigma match skipped for %s: %s", vendor, exc)
        return None
    if not matched:
        return None
    return _envelope(vendor, matched.level, entity, f"[Sigma] {matched.title}", raw,
                      entity=entity, rule_id_override=CONNECTOR_SIGMA_RULE_IDS[matched.level])


# O365 Management Activity records have no native severity field — this is a
# starting heuristic on `Operation`, not a documented Microsoft taxonomy.
# Revisit once real tenant data shows which operations actually matter.
_O365_HIGH_RISK_OPS = {
    "New-InboxRule", "Set-InboxRule", "Add member to role", "Add app role assignment to service principal",
    "Consent to application", "New-TransportRule", "Set-Mailbox",
}


def _normalize_office365(record: dict[str, Any]) -> dict[str, Any]:
    user = record.get("UserId", "")
    sigma_hit = _sigma_envelope("office365", record, user)
    if sigma_hit:
        return sigma_hit
    op = str(record.get("Operation", ""))
    if op in _O365_HIGH_RISK_OPS:
        severity = "high"
    elif "Fail" in op or str(record.get("ResultStatus", "")).lower() == "failed":
        severity = "medium"
    else:
        severity = "low"
    desc = op or "O365 audit event"
    return _envelope("office365", severity, user, str(desc), record, entity=user)


def _normalize_azure(event: dict[str, Any]) -> dict[str, Any]:
    ts_field = event.get("_ts_field", "")
    if ts_field == "createdDateTime":  # sign-in event
        entity = event.get("userPrincipalName", "")
    else:  # directory audit
        entity = ((event.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName", "")
    sigma_hit = _sigma_envelope("azure", event, entity)
    if sigma_hit:
        return sigma_hit
    if ts_field == "createdDateTime":
        risk = str(event.get("riskLevelDuringSignIn", "none")).lower()
        error_code = ((event.get("status") or {}).get("errorCode") or 0)
        severity = risk if risk in _LEVELS else ("medium" if error_code else "low")
        desc = f"Sign-in: {entity}"
    else:
        failed = str(event.get("result", "")).lower() == "failure"
        severity = "medium" if failed else "low"
        desc = event.get("activityDisplayName", "Directory audit event")
    return _envelope("azure", severity, entity, str(desc), event, entity=entity)


# AWS CloudTrail events carry no severity — heuristic on high-risk management
# actions, same caveat as O365's operation-based mapping above.
_AWS_HIGH_RISK_EVENTS = {
    "CreateAccessKey", "PutBucketPolicy", "DeleteTrail", "StopLogging",
    "AuthorizeSecurityGroupIngress", "CreateUser", "AttachUserPolicy", "ConsoleLogin",
}


def _normalize_aws(event: dict[str, Any]) -> dict[str, Any]:
    user = (event.get("Username") or "")
    sigma_hit = _sigma_envelope("aws", event, user)
    if sigma_hit:
        return sigma_hit
    name = event.get("EventName", "")
    has_error = bool(event.get("ErrorCode"))
    severity = "high" if name in _AWS_HIGH_RISK_EVENTS else ("medium" if has_error else "low")
    return _envelope("aws", severity, user, str(name or "CloudTrail event"), event, entity=user)


# GCP Cloud Logging has a real native severity taxonomy (LogSeverity enum) —
# the only one of the four cloud connectors with a documented mapping rather
# than a heuristic.
_GCP_SEVERITY_MAP = {
    "EMERGENCY": "critical", "ALERT": "critical", "CRITICAL": "critical",
    "ERROR": "high", "WARNING": "medium", "NOTICE": "medium",
    "INFO": "low", "DEBUG": "low", "DEFAULT": "low",
}


def _normalize_gcp(entry: dict[str, Any]) -> dict[str, Any]:
    resource = entry.get("resource", "")
    sigma_hit = _sigma_envelope("gcp", entry, resource)
    if sigma_hit:
        return sigma_hit
    severity = _GCP_SEVERITY_MAP.get(str(entry.get("severity", "DEFAULT")).upper(), "low")
    desc = entry.get("log_name", "GCP audit log entry")
    return _envelope("gcp", severity, resource, str(desc), entry)


_NORMALIZERS = {
    "splunk":      _normalize_splunk,
    "qradar":      _normalize_qradar,
    "sentinelone": _normalize_sentinelone,
    "paloalto":    _normalize_paloalto,
    "office365":   _normalize_office365,
    "azure":       _normalize_azure,
    "aws":         _normalize_aws,
    "gcp":         _normalize_gcp,
}


def push_connector_events(vendor: str, events: list[dict[str, Any]]) -> int:
    """Normalize + push a batch of vendor-native events into the SIEM Redis
    queue and, additively, Kafka. Returns count pushed to Redis (0 if Redis
    unavailable — Kafka publish is best-effort and doesn't affect this)."""
    from . import kafka_bridge
    from . import dedup

    if vendor == "wazuh":
        envelopes = events  # already native Wazuh shape — see wazuh_connector.py
    else:
        normalize = _NORMALIZERS.get(vendor)
        if normalize is None:
            _log.error("Connector bridge: no normalizer for vendor=%s", vendor)
            return 0
        envelopes = [normalize(e) for e in events]

    deduped = []
    suppressed = 0
    for envelope in envelopes:
        key = dedup.envelope_dedup_key(vendor, envelope)
        if dedup.is_duplicate(key):
            suppressed += 1
            continue
        deduped.append(envelope)
    if suppressed:
        _log.info("Connector bridge: suppressed %d duplicate %s event(s)", suppressed, vendor)
    envelopes = deduped

    try:
        kafka_bridge.publish_many(kafka_bridge.VENDOR_TOPICS.get(vendor, f"raw.{vendor}"), envelopes)
    except Exception as exc:
        _log.debug("Connector bridge: Kafka publish skipped: %s", exc)

    r = _get_redis()
    if r is None:
        _log.warning("Connector bridge: Redis unavailable — %d %s event(s) dropped", len(events), vendor)
        return 0

    pushed = 0
    try:
        pipe = r.pipeline()
        for envelope in envelopes:
            pipe.rpush(_REDIS_KEY, json.dumps(envelope))
        pipe.execute()
        pushed = len(envelopes)
    except Exception as exc:
        _log.error("Connector bridge: pipeline push failed for %s: %s", vendor, exc)
        pushed = 0
        for envelope in envelopes:
            try:
                r.rpush(_REDIS_KEY, json.dumps(envelope))
                pushed += 1
            except Exception as inner_exc:
                _log.warning("Connector bridge: event dropped: %s", inner_exc)

    _log.debug("Connector→SIEM: vendor=%s pushed=%d/%d", vendor, pushed, len(events))
    return pushed
