"""
cysiemstack/kafka_bridge.py
=============================
CyDataLake — Phase 2 Kafka bus (see docs/CYDATALAKE_MIGRATION_PLAN.md).

Thin, best-effort Kafka producer wrapper. This is an ADDITIVE sink used by
collector_bridge.py and edr_bridge.py alongside their existing Redis push —
it never replaces the Redis-based ingestion pipeline, and a publish failure
here must never block or fail the caller's request. Disabled by default via
KAFKA_ENABLED (core/config.py); Phase 3's ingest workers are what will
actually consume these topics — nothing reads them yet.

Topic scheme (reserve, do not repurpose without updating the migration doc):
  raw.syslog      — CyCollector generic host log events
  raw.edr         — CyEDR telemetry/detections + WazuhConnector passthrough
  raw.network     — reserved for network/IoT probe data (not wired yet)
  raw.audit       — reserved for GRC/compliance evidence audit trail (not wired yet)
  raw.splunk      — Splunk connector (cysiemstack/connectors/splunk_connector.py)
  raw.qradar      — QRadar connector
  raw.sentinelone — SentinelOne connector
  raw.paloalto    — Palo Alto Cortex XDR/XSIAM connector
  raw.office365   — Office 365 Management Activity connector (bypasses Wazuh wodle)
  raw.azure       — Azure AD / Entra ID connector (Graph sign-ins + directory audits)
  raw.aws         — AWS CloudTrail connector
  raw.gcp         — GCP Cloud Audit Logs connector
"""
from __future__ import annotations
import json
import logging
from typing import Any

_log = logging.getLogger(__name__)

TOPIC_SYSLOG      = "raw.syslog"
TOPIC_EDR         = "raw.edr"
TOPIC_NETWORK     = "raw.network"
TOPIC_AUDIT       = "raw.audit"
TOPIC_SPLUNK      = "raw.splunk"
TOPIC_QRADAR      = "raw.qradar"
TOPIC_SENTINELONE = "raw.sentinelone"
TOPIC_PALOALTO    = "raw.paloalto"
TOPIC_OFFICE365   = "raw.office365"
TOPIC_AZURE       = "raw.azure"
TOPIC_AWS         = "raw.aws"
TOPIC_GCP         = "raw.gcp"

VENDOR_TOPICS = {
    "wazuh":       TOPIC_EDR,
    "splunk":      TOPIC_SPLUNK,
    "qradar":      TOPIC_QRADAR,
    "sentinelone": TOPIC_SENTINELONE,
    "paloalto":    TOPIC_PALOALTO,
    "office365":   TOPIC_OFFICE365,
    "azure":       TOPIC_AZURE,
    "aws":         TOPIC_AWS,
    "gcp":         TOPIC_GCP,
}

_producer = None
_producer_failed = False


def _get_producer():
    """Lazy singleton KafkaProducer. Returns None if disabled, the client
    library is missing, or the broker is unreachable — callers must treat
    that as "skip Kafka this time", never as a fatal error."""
    global _producer, _producer_failed
    from core.config import KAFKA_ENABLED, KAFKA_BROKERS

    if not KAFKA_ENABLED or _producer_failed:
        return None
    if _producer is not None:
        return _producer

    try:
        from kafka import KafkaProducer
        _producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKERS.split(","),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            request_timeout_ms=5000,
            max_block_ms=5000,
        )
    except Exception as exc:
        _log.warning("Kafka bridge: producer unavailable (%s) — Kafka publish disabled for this process", exc)
        _producer_failed = True
        return None
    return _producer


def publish(topic: str, payload: dict[str, Any]) -> bool:
    """Best-effort publish. Returns True if handed to the producer, False if
    Kafka is disabled/unavailable — the Redis-based pipeline is unaffected
    either way, so callers should not treat False as an error."""
    producer = _get_producer()
    if producer is None:
        return False
    try:
        producer.send(topic, value=payload)
        return True
    except Exception as exc:
        _log.warning("Kafka bridge: publish to %s failed: %s", topic, exc)
        return False


def publish_many(topic: str, payloads: list[dict[str, Any]]) -> int:
    """Best-effort batch publish. Returns count successfully handed to the producer."""
    producer = _get_producer()
    if producer is None:
        return 0
    sent = 0
    for payload in payloads:
        try:
            producer.send(topic, value=payload)
            sent += 1
        except Exception as exc:
            _log.warning("Kafka bridge: publish to %s failed: %s", topic, exc)
    return sent
