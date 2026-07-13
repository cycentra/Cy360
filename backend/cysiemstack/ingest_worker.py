#!/usr/bin/env python3
"""
cysiemstack/ingest_worker.py
==============================
CyDataLake — Phase 4 ingest worker. Standalone process (NOT part of the
Flask app — run via its own systemd unit, see
docs/CYDATALAKE_OPS_RUNBOOK.md), separate from the existing gunicorn/Flask
and cysiemstack-engine (correlation engine) services.

Job: consume every Kafka topic CyCollector/EDR/connectors publish to
(kafka_bridge.py's topic list) and write each event into the ClickHouse hot
store (clickhouse_store.py). This is a PURE fan-out storage consumer — it
does NOT re-run detection and does NOT re-push into the Redis
`cysiemstack:alerts:raw` queue. Detection already happened synchronously at
ingest time in collector_bridge.py (Sigma engine)/connector_bridge.py
(vendor severity mapping), and those same bridges already pushed the
correlation-engine copy onto Redis directly. This worker's only job is
giving CyDataLake a durable, searchable long-term store independent of the
incident-creation path — that's the whole reason Kafka exists as an
additive sink rather than a Redis replacement (see migration doc §2/§6).

Also runs the cold-storage export (Parquet archival of aged-out ClickHouse
rows) on a daily timer within the same process — no separate cron needed.

Requires KAFKA_ENABLED=true + a running broker (Phase 2) and
CLICKHOUSE_ENABLED=true + a running ClickHouse server (Phase 4) to do
anything at all. With either disabled, this process starts, logs that it
has nothing to consume/write, and idles — it will not crash a partially
provisioned environment.
"""
from __future__ import annotations
import json
import logging
import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # backend/ on path

from cysiemstack import kafka_bridge, clickhouse_store  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("cydatalake-ingest-worker")

_STOP = threading.Event()

_TOPICS = [
    kafka_bridge.TOPIC_SYSLOG, kafka_bridge.TOPIC_EDR,
    kafka_bridge.TOPIC_SPLUNK, kafka_bridge.TOPIC_QRADAR,
    kafka_bridge.TOPIC_SENTINELONE, kafka_bridge.TOPIC_PALOALTO,
    kafka_bridge.TOPIC_OFFICE365, kafka_bridge.TOPIC_AZURE,
    kafka_bridge.TOPIC_AWS, kafka_bridge.TOPIC_GCP,
    kafka_bridge.TOPIC_NETWORK, kafka_bridge.TOPIC_AUDIT,
]

_COLD_STORAGE_DAYS = int(os.environ.get("CYDATALAKE_COLD_STORAGE_DAYS", "90"))
_COLD_STORAGE_DIR  = os.environ.get("CYDATALAKE_COLD_STORAGE_DIR", "/var/lib/cycentra/cydatalake-archive")
_COLD_STORAGE_INTERVAL_SEC = 24 * 3600


def _topic_to_vendor(topic: str) -> str:
    return {
        kafka_bridge.TOPIC_SYSLOG:      "collector",
        kafka_bridge.TOPIC_EDR:         "edr",
        kafka_bridge.TOPIC_SPLUNK:      "splunk",
        kafka_bridge.TOPIC_QRADAR:      "qradar",
        kafka_bridge.TOPIC_SENTINELONE: "sentinelone",
        kafka_bridge.TOPIC_PALOALTO:    "paloalto",
        kafka_bridge.TOPIC_OFFICE365:   "office365",
        kafka_bridge.TOPIC_AZURE:       "azure",
        kafka_bridge.TOPIC_AWS:         "aws",
        kafka_bridge.TOPIC_GCP:         "gcp",
        kafka_bridge.TOPIC_NETWORK:     "network",
        kafka_bridge.TOPIC_AUDIT:       "audit",
    }.get(topic, topic)


def _consume_loop():
    from core.config import KAFKA_ENABLED, KAFKA_BROKERS
    if not KAFKA_ENABLED:
        log.warning("KAFKA_ENABLED=false — ingest worker has nothing to consume. Idling.")
        while not _STOP.is_set():
            _STOP.wait(60)
        return

    try:
        from kafka import KafkaConsumer
    except ImportError:
        log.error("kafka-python not installed — cannot consume. Idling.")
        while not _STOP.is_set():
            _STOP.wait(60)
        return

    try:
        consumer = KafkaConsumer(
            *_TOPICS,
            bootstrap_servers=KAFKA_BROKERS.split(","),
            group_id="cydatalake-ingest-worker",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
    except Exception as exc:
        log.error("Kafka consumer init failed: %s — idling, will not retry within this process", exc)
        while not _STOP.is_set():
            _STOP.wait(60)
        return

    log.info("Consuming topics: %s", _TOPICS)
    batch: dict[str, list] = {}
    last_flush = time.time()

    for msg in consumer:
        if _STOP.is_set():
            break
        vendor = _topic_to_vendor(msg.topic)
        batch.setdefault(vendor, []).append(msg.value)

        if time.time() - last_flush >= 5 or sum(len(v) for v in batch.values()) >= 500:
            for v, envs in batch.items():
                written = clickhouse_store.write_events(v, envs)
                log.debug("Ingest worker: wrote %d/%d %s event(s) to ClickHouse", written, len(envs), v)
            batch = {}
            last_flush = time.time()


def _cold_storage_loop():
    while not _STOP.is_set():
        try:
            exported = clickhouse_store.export_and_purge_older_than(_COLD_STORAGE_DAYS, _COLD_STORAGE_DIR)
            if exported:
                log.info("Cold storage: archived %d row(s) older than %d days", exported, _COLD_STORAGE_DAYS)
        except Exception as exc:
            log.error("Cold storage export failed (non-fatal): %s", exc)
        _STOP.wait(_COLD_STORAGE_INTERVAL_SEC)


def _handle_signal(signum, frame):
    log.info("Received signal %d — shutting down", signum)
    _STOP.set()


def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    threads = [
        threading.Thread(target=_consume_loop, name="KafkaConsumeLoop", daemon=True),
        threading.Thread(target=_cold_storage_loop, name="ColdStorageLoop", daemon=True),
    ]
    for t in threads:
        t.start()

    log.info("CyDataLake ingest worker started")
    while not _STOP.is_set():
        time.sleep(1)
    log.info("CyDataLake ingest worker stopped")


if __name__ == "__main__":
    main()
