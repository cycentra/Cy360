"""
cysiemstack/connectors/qradar_connector.py
=============================================
Pulls offenses from IBM QRadar's REST API. QRadar already correlates raw
events into offenses on its own; this connector aggregates those offenses
into CyDataLake, it does not re-run QRadar's rule engine.

Config fields:
  base_url    — e.g. https://qradar.internal
  sec_token   — QRadar authorized service token, sent as `SEC: <token>` header
  api_version — QRadar REST API version header (default "20.0")

Cursor is `last_persisted_time` in epoch milliseconds (QRadar's native
offense timestamp field) — kept as a string so the generic connector
interface doesn't need to know it's numeric.

NOT verified against a live QRadar tenant — implemented against IBM's
publicly documented REST API (/api/siem/offenses). Confirm `api_version`
against the target deployment's actual QRadar release before relying on
field availability (QRadar's REST API is versioned per-endpoint).
"""
from __future__ import annotations
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "qradar"

_FIELDS = ("id,description,severity,magnitude,credibility,relevance,"
           "offense_type,status,last_persisted_time,start_time,"
           "source_network,destination_networks,offense_source,categories")


class QRadarConnector(BaseConnector):
    vendor = "qradar"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.sec_token   = config.get("sec_token", "")
        self.api_version = config.get("api_version", "20.0")

    def _headers(self):
        return {
            "SEC":     self.sec_token,
            "Version": self.api_version,
            "Accept":  "application/json",
        }

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        since_ms = cursor or "0"
        try:
            resp = self._session().get(
                f"{self.base_url}/api/siem/offenses",
                headers=self._headers(),
                params={
                    "filter": f"last_persisted_time>{since_ms}",
                    "sort":   "+last_persisted_time",
                    "fields": _FIELDS,
                },
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except Exception as exc:
            raise ConnectorError(f"QRadar offenses fetch failed: {exc}") from exc

        offenses = resp.json()
        if not isinstance(offenses, list):
            raise ConnectorError(f"QRadar unexpected response shape: {offenses}")

        next_cursor = since_ms
        if offenses:
            next_cursor = str(max(int(o.get("last_persisted_time", 0)) for o in offenses))
        return offenses, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = self._session().get(
                f"{self.base_url}/api/system/about",
                headers=self._headers(),
                timeout=self.timeout,
            )
            if resp.ok:
                return True, "Connected to QRadar REST API"
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            return False, str(exc)
