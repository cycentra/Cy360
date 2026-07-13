"""
cysiemstack/clickhouse_store.py
==================================
CyDataLake — Phase 4 hot storage. Best-effort ClickHouse client, same
disabled-by-default/never-block convention as kafka_bridge.py: if
CLICKHOUSE_ENABLED is false, the client library is missing, or the server
is unreachable, every call here degrades to a no-op rather than raising —
callers (ingest_worker.py) must not crash the consumer loop over a storage
outage.

Schema: one flat table, `<database>.raw_events`. Deliberately no TTL clause
on the table itself — cold-storage export (export_and_purge_older_than())
explicitly SELECTs + Parquet-exports + DELETEs aged-out rows, so archival
is a visible, on-purpose operation rather than a silent background eviction.

NOT provisioned anywhere — see docs/CYDATALAKE_OPS_RUNBOOK.md for the
install/schema-setup steps. This module ships dormant, same as
kafka_bridge.py. `query_arrow()` (used by the cold-storage export) is
part of clickhouse-connect's documented API but has not been exercised
against a live server in this session — verify before relying on it.
"""
from __future__ import annotations
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

_log = logging.getLogger(__name__)

CLICKHOUSE_ENABLED  = os.environ.get("CLICKHOUSE_ENABLED", "false").lower() == "true"
CLICKHOUSE_HOST     = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
CLICKHOUSE_PORT     = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER     = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "cydatalake")

_TABLE_DDL = f"""
CREATE TABLE IF NOT EXISTS {CLICKHOUSE_DATABASE}.raw_events (
    event_id         String,
    vendor           String,
    rule_id          String,
    rule_level       UInt8,
    rule_description String,
    agent_name       String,
    agent_ip         String,
    event_time       DateTime64(3),
    ingested_at      DateTime64(3) DEFAULT now64(3),
    raw_json         String
) ENGINE = MergeTree()
ORDER BY (vendor, event_time)
"""

_client = None
_client_failed = False


def _get_client():
    global _client, _client_failed
    if not CLICKHOUSE_ENABLED or _client_failed:
        return None
    if _client is not None:
        return _client
    try:
        import clickhouse_connect
        _client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        )
        _client.command(f"CREATE DATABASE IF NOT EXISTS {CLICKHOUSE_DATABASE}")
        _client.command(_TABLE_DDL)
    except Exception as exc:
        _log.warning("ClickHouse store: client unavailable (%s) — storage disabled for this process", exc)
        _client_failed = True
        return None
    return _client


def write_events(vendor: str, envelopes: list[dict[str, Any]]) -> int:
    """Best-effort batch insert into the hot store. Returns rows written
    (0 if disabled/unavailable — never raises)."""
    client = _get_client()
    if client is None:
        return 0

    rows = []
    for env in envelopes:
        rule  = env.get("rule") or {}
        agent = env.get("agent") or {}
        ts_raw = str(env.get("@timestamp", ""))
        try:
            event_time = datetime.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            event_time = datetime.now(timezone.utc)
        rows.append([
            str(env.get("id", "")),
            vendor,
            str(rule.get("id", "")),
            int(rule.get("level", 0) or 0),
            str(rule.get("description", ""))[:500],
            agent.get("name", ""),
            agent.get("ip", ""),
            event_time,
            json.dumps(env)[:8000],
        ])

    try:
        client.insert(
            f"{CLICKHOUSE_DATABASE}.raw_events",
            rows,
            column_names=["event_id", "vendor", "rule_id", "rule_level", "rule_description",
                          "agent_name", "agent_ip", "event_time", "raw_json"],
        )
        return len(rows)
    except Exception as exc:
        _log.error("ClickHouse store: insert failed: %s", exc)
        return 0


def export_and_purge_older_than(days: int, export_dir: str) -> int:
    """Cold-storage step: export rows older than `days` to a Parquet file
    under `export_dir`, then delete them from the hot store. Returns rows
    exported (0 if disabled/unavailable/nothing to export — never raises)."""
    client = _get_client()
    if client is None:
        return 0

    try:
        import pyarrow.parquet as pq
        query = (
            f"SELECT * FROM {CLICKHOUSE_DATABASE}.raw_events "
            f"WHERE ingested_at < now() - INTERVAL {int(days)} DAY"
        )
        table = client.query_arrow(query)
        if table.num_rows == 0:
            return 0

        os.makedirs(export_dir, exist_ok=True)
        fname = os.path.join(export_dir, f"raw_events_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.parquet")
        pq.write_table(table, fname)

        client.command(
            f"ALTER TABLE {CLICKHOUSE_DATABASE}.raw_events "
            f"DELETE WHERE ingested_at < now() - INTERVAL {int(days)} DAY"
        )
        _log.info("ClickHouse store: exported %d row(s) to %s and purged from hot store", table.num_rows, fname)
        return table.num_rows
    except Exception as exc:
        _log.error("ClickHouse store: cold-storage export failed: %s", exc)
        return 0
