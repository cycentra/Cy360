"""
cysiemstack/connectors/splunk_connector.py
=============================================
Pulls search results from Splunk's REST Search API (management port, default
8089). Splunk already runs its own detection (notable events / correlation
searches in Enterprise Security, or raw index search otherwise) — this
connector aggregates its output into CyDataLake, it does not re-detect.

Config fields:
  base_url     — e.g. https://splunk.internal:8089
  api_token    — Splunk authentication token (Settings > Tokens), sent as
                 `Authorization: Bearer <token>`
  search_query — SPL, default "search index=notable" (Splunk ES notable
                 events index — override to e.g. "search index=main" for a
                 raw-index deployment without ES)
  poll_timeout_sec — how long to wait for the search job to finish (default 60)

NOT verified against a live Splunk tenant — implemented against Splunk's
publicly documented REST API (services/search/jobs). Confirm the exact
notable-event field names (search_query result columns referenced in
connector_bridge._normalize_splunk) against the target tenant's actual ES
version before relying on severity/category mapping.
"""
from __future__ import annotations
import time
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "splunk"


class SplunkConnector(BaseConnector):
    vendor = "splunk"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_token    = config.get("api_token", "")
        self.search_query = config.get("search_query") or "search index=notable"
        self.poll_timeout = int(config.get("poll_timeout_sec", 60))

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}"}

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        earliest = cursor or "-15m"
        sess = self._session()
        try:
            create = sess.post(
                f"{self.base_url}/services/search/jobs",
                headers=self._headers(),
                data={
                    "search":        self.search_query,
                    "earliest_time": earliest,
                    "latest_time":   "now",
                    "output_mode":   "json",
                },
                timeout=self.timeout,
            )
            create.raise_for_status()
            sid = create.json()["sid"]
        except Exception as exc:
            raise ConnectorError(f"Splunk search job creation failed: {exc}") from exc

        deadline = time.time() + self.poll_timeout
        while time.time() < deadline:
            try:
                status = sess.get(
                    f"{self.base_url}/services/search/jobs/{sid}",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                    timeout=self.timeout,
                )
                status.raise_for_status()
                state = status.json()["entry"][0]["content"]["dispatchState"]
                if state == "DONE":
                    break
                if state == "FAILED":
                    raise ConnectorError(f"Splunk search job {sid} failed")
            except ConnectorError:
                raise
            except Exception as exc:
                raise ConnectorError(f"Splunk job status poll failed: {exc}") from exc
            time.sleep(2)
        else:
            raise ConnectorError(f"Splunk search job {sid} did not finish within {self.poll_timeout}s")

        try:
            results = sess.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": 0},
                timeout=self.timeout,
            )
            results.raise_for_status()
            events = results.json().get("results", [])
        except Exception as exc:
            raise ConnectorError(f"Splunk results fetch failed: {exc}") from exc

        next_cursor = earliest
        times = [e["_time"] for e in events if e.get("_time")]
        if times:
            next_cursor = max(times)
        return events, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = self._session().get(
                f"{self.base_url}/services/server/info",
                headers=self._headers(),
                params={"output_mode": "json"},
                timeout=self.timeout,
            )
            if resp.ok:
                return True, "Connected to Splunk management API"
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            return False, str(exc)
