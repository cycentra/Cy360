"""
cysiemstack/connectors/wazuh_connector.py
============================================
Pulls alerts from the Wazuh indexer (OpenSearch) `wazuh-alerts-*` index via
its REST search API. This is a DIFFERENT path from the existing
`cysiem_to_redis.py` file-tail — that tailer keeps running unmodified; this
connector exists so Wazuh can be configured and polled through the same
multi-vendor connector framework as Splunk/QRadar/SentinelOne/Cortex,
per the CyDataLake architecture reframe. The two paths pulling the same
underlying alerts is redundant but harmless (the correlation engine
de-duplicates on Wazuh's own alert `id` — see ingestor.py); do not enable
both against the same Wazuh cluster in production without first confirming
that dedup path actually holds, since it was never exercised for this case.

Config fields (siem_connectors.config / secrets):
  base_url  — Wazuh indexer URL, e.g. https://wazuh-indexer.internal:9200
  username, password — indexer basic auth (NOT the Wazuh Manager API creds)
  index_pattern — default "wazuh-alerts-*"

Unlike every other connector here, `pull()` returns documents already in
the exact Wazuh JSON shape `normaliser.py` expects — no translation needed.
connector_bridge.py must special-case vendor == "wazuh" to push `_source`
through unchanged rather than calling a `_normalize_*` wrapper.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "wazuh"


class WazuhConnector(BaseConnector):
    vendor = "wazuh"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.username      = config.get("username", "")
        self.password      = config.get("password", "")
        self.index_pattern = config.get("index_pattern", "wazuh-alerts-*")

    def _auth(self):
        return (self.username, self.password) if self.username else None

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        since = cursor or datetime.now(timezone.utc).isoformat()
        query = {
            "size": 500,
            "sort": [{"@timestamp": "asc"}],
            "query": {"range": {"@timestamp": {"gt": since}}},
        }
        try:
            resp = self._session().post(
                f"{self.base_url}/{self.index_pattern}/_search",
                json=query, auth=self._auth(), timeout=self.timeout,
            )
            resp.raise_for_status()
        except Exception as exc:
            raise ConnectorError(f"Wazuh indexer search failed: {exc}") from exc

        hits = (resp.json().get("hits") or {}).get("hits") or []
        events = [h["_source"] for h in hits if "_source" in h]
        next_cursor = events[-1]["@timestamp"] if events else since
        return events, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = self._session().get(
                f"{self.base_url}/_cluster/health",
                auth=self._auth(), timeout=self.timeout,
            )
            if resp.ok:
                return True, f"Connected — cluster status: {resp.json().get('status', 'unknown')}"
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            return False, str(exc)
