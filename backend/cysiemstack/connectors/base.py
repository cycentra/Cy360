"""
cysiemstack/connectors/base.py
================================
CyDataLake — multi-vendor SIEM connector framework.

Architecture reframe (see docs/CYDATALAKE_MIGRATION_PLAN.md §0-3): CyDataLake
is not "replace Wazuh." Wazuh becomes ONE of several source SIEM/EDR
platforms it pulls from, alongside Splunk, QRadar, Palo Alto Cortex
XDR/XSIAM, SentinelOne, and CyCollector/CyEDR's own raw telemetry. Each
vendor already runs its own detection — CyDataLake's job for these sources
is aggregation, normalization, and cross-vendor correlation, not
reimplementing decoders/rules from scratch (that problem only still exists
for CyCollector's raw generic logs).

Every connector is a pull-based poller: given a cursor (an opaque string
bookmark — a timestamp, an offset, whatever the vendor's API uses for
incremental queries), fetch new events since that cursor and return the next
cursor. Connectors do NOT talk to Redis/Kafka directly — that's
connector_bridge.py's job — so a connector can be unit tested against a
mocked HTTP session with zero SIEM-pipeline knowledge.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional

import requests


class ConnectorError(Exception):
    """Raised for connector-fatal errors (auth failure, unreachable host).
    Transient/partial failures should be logged and swallowed by pull()
    returning whatever it could fetch — do not raise for "zero new events"."""


class BaseConnector(ABC):
    """One instance per configured `siem_connectors` row.

    Subclasses must set `vendor` and implement `pull()` + `test_connection()`.
    `config` holds whatever GET /api/connectors/<id> would return minus the
    masked secret sentinel — i.e. real credentials, since this runs
    server-side only, never sent to the browser.
    """

    vendor: str = "base"

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.base_url: str = (config.get("base_url") or "").rstrip("/")
        self.timeout: int = int(config.get("timeout", 30))

    def _session(self) -> requests.Session:
        sess = requests.Session()
        sess.verify = not self.config.get("insecure_skip_verify", False)
        return sess

    @abstractmethod
    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        """Fetch events newer than `cursor`. Returns (events, next_cursor).

        `events` are vendor-native dicts — normalization into the common
        shape happens in connector_bridge.py's per-vendor `_normalize_*`
        function, not here, so each connector stays a thin API client.

        `next_cursor` must always be returned even on a zero-event pull —
        return the input cursor unchanged rather than None, so a transient
        empty page doesn't reset the incremental bookmark to "pull everything".
        """
        raise NotImplementedError

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Cheap connectivity + auth check for the UI's "Test Connection"
        button. Returns (ok, message)."""
        raise NotImplementedError
