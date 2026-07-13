"""
cysiemstack/collector_bridge.py
=================================
Bridges CyCollector generic log events into the existing SIEM correlation
pipeline by pushing them onto the same Redis LIST that the Wazuh-derived
ingestor.py reads from — the same integration pattern already proven by
cysiemstack/edr_bridge.py for CyEDR telemetry.

Phase 0/4 update: every event is now run through the Sigma-rule-subset
engine (cysiemstack/detection/sigma_engine.py) before wrapping. A match
upgrades the event to the matched rule's severity (rule_id 101150-101153,
see SIGMA_RULE_IDS); everything else falls back to the original Phase 1
treatment — a single undifferentiated low-severity "system" category alert
(rule_id 101100, level 3 — the lowest level the ingestor accepts; see
normaliser.MIN_RULE_LEVEL). This deliberately keeps unmatched noise out of
the HIGH/CRITICAL auto-case-open gate (grouper._score_to_severity: level
3-6 → 'low') while still making it searchable in the Alert Feed. The Sigma
engine only covers a handful of starter rules — do not expect Wazuh
rule-engine parity from this bridge.

Rule ID allocation (see also edr_bridge.py's registry comment):
  cy_cust_rules.xml (real Wazuh rules): 100100-101042, in used sub-blocks
  EDR synthetic:                        100300-100399
  YARA synthetic:                        100210-100211
  ASM synthetic:                         200100-200199
  ITAM synthetic:                        200200-200299
  CyCollector synthetic (this file):    101100-101109 (101100 = unmatched)
  Sigma-matched CyCollector events:     101150-101153 (critical/high/medium/low)
"""
from __future__ import annotations
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)

_REDIS_KEY = "cysiemstack:alerts:raw"
_REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

_RULE_ID    = 101100
_RULE_LEVEL = 3   # normaliser.MIN_RULE_LEVEL floor -> grouper maps this to 'low' severity

# level → rule_level, mirrors grouper._score_to_severity() thresholds
_SIGMA_LEVELS = {"critical": 15, "high": 12, "medium": 7, "low": 3}

_redis_client = None


def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis
            _redis_client = redis.from_url(_REDIS_URL, decode_responses=True)
        except Exception as exc:
            _log.error("Collector bridge: Redis connect failed: %s", exc)
    return _redis_client


def _wrap_as_wazuh(agent: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    """Wrap one raw CyCollector event into the Wazuh JSON envelope shape
    that ingestor.py / normaliser.py expect from the Redis queue. Runs the
    Sigma-rule-subset engine first — a match upgrades rule_id/level/
    description; no match falls back to the flat undetected bucket."""
    ts_raw = event.get("timestamp")
    if isinstance(ts_raw, str) and ts_raw:
        ts_str = ts_raw
    else:
        ts_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    source_type = str(event.get("source_type", "generic"))[:64]
    program     = str(event.get("program", ""))[:200]
    message     = str(event.get("message", ""))[:4000]

    rule_id, level, description = _RULE_ID, _RULE_LEVEL, f"[CyCollector] {program or source_type}"
    try:
        from .detection.sigma_engine import get_engine, SIGMA_RULE_IDS
        matched = get_engine().match(event)
        if matched:
            rule_id     = SIGMA_RULE_IDS[matched.level]
            level       = _SIGMA_LEVELS[matched.level]
            description = f"[CyCollector/Sigma] {matched.title}"
    except Exception as exc:
        _log.warning("Collector bridge: Sigma match skipped: %s", exc)

    return {
        "@timestamp": ts_str,
        "id":         str(uuid.uuid4()),
        "agent": {
            "id":   agent.get("agent_id", "000"),
            "name": agent.get("hostname", ""),
            "ip":   agent.get("agent_ip", ""),
        },
        "rule": {
            "id":          str(rule_id),
            "description": description[:200],
            "level":       level,
            "groups":      ["collector", source_type],
        },
        "data": {
            "collector": {
                "source_type": source_type,
                "program":     program,
                "metadata":    event.get("metadata") or {},
            },
        },
        "full_alert": {
            "collector":   True,
            "source_type": source_type,
            "groups":      ["collector", source_type],
        },
        "_raw_log": message or json.dumps(event.get("raw") or {})[:4000],
    }


def push_collector_events(agent: dict[str, Any], events: list[dict[str, Any]]) -> int:
    """Push a batch of raw CyCollector events into the SIEM Redis queue
    (the pipeline the correlation engine actually consumes today) and,
    additively, onto the Phase 2 Kafka bus if KAFKA_ENABLED (see
    kafka_bridge.py — nothing consumes that topic yet, this is transport
    only, and its success/failure never affects the Redis-based return value).
    Returns the number of events successfully pushed to Redis (0 if Redis
    unavailable)."""
    from . import kafka_bridge

    envelopes = [_wrap_as_wazuh(agent, event) for event in events]
    try:
        kafka_bridge.publish_many(kafka_bridge.TOPIC_SYSLOG, envelopes)
    except Exception as exc:
        _log.debug("Collector bridge: Kafka publish skipped: %s", exc)

    r = _get_redis()
    if r is None:
        _log.warning("Collector bridge: Redis unavailable — %d event(s) dropped", len(events))
        return 0

    pushed = 0
    try:
        pipe = r.pipeline()
        for envelope in envelopes:
            pipe.rpush(_REDIS_KEY, json.dumps(envelope))
        pipe.execute()
        pushed = len(events)
    except Exception as exc:
        _log.error("Collector bridge: pipeline push failed: %s", exc)
        # Fallback: push individually so one bad event doesn't drop the whole batch
        pushed = 0
        for envelope in envelopes:
            try:
                r.rpush(_REDIS_KEY, json.dumps(envelope))
                pushed += 1
            except Exception as inner_exc:
                _log.warning("Collector bridge: event dropped: %s", inner_exc)

    _log.debug("Collector→SIEM: agent=%s pushed=%d/%d", agent.get("agent_id"), pushed, len(events))
    return pushed
