"""
cysiemstack/connectors/sentinelone_connector.py
==================================================
Pulls threats from SentinelOne's Management API. SentinelOne already
performs endpoint detection on its own agent; this connector aggregates its
threat verdicts into CyDataLake, it does not re-detect.

Config fields:
  base_url  — e.g. https://usea1-partners.sentinelone.net (tenant-specific)
  api_token — SentinelOne API token, sent as `Authorization: ApiToken <token>`

Cursor is the ISO8601 `createdAt` of the last threat seen. SentinelOne's own
page-to-page pagination (its `pagination.nextCursor`) is handled internally
within a single pull() call — capped at _MAX_PAGES per poll so one run can't
loop indefinitely against a very large backlog.

NOT verified against a live SentinelOne tenant — implemented against
SentinelOne's publicly documented Management API v2.1 (/web/api/v2.1/threats).
"""
from __future__ import annotations
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "sentinelone"

_MAX_PAGES = 10


class SentinelOneConnector(BaseConnector):
    vendor = "sentinelone"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_token = config.get("api_token", "")

    def _headers(self):
        return {"Authorization": f"ApiToken {self.api_token}"}

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        since = cursor or "1970-01-01T00:00:00.000000Z"
        sess = self._session()
        events: list[dict[str, Any]] = []
        page_cursor = None

        for _ in range(_MAX_PAGES):
            params = {
                "createdAt__gt": since,
                "limit":         1000,
                "sortBy":        "createdAt",
                "sortOrder":     "asc",
            }
            if page_cursor:
                params["cursor"] = page_cursor
            try:
                resp = sess.get(
                    f"{self.base_url}/web/api/v2.1/threats",
                    headers=self._headers(), params=params, timeout=self.timeout,
                )
                resp.raise_for_status()
            except Exception as exc:
                raise ConnectorError(f"SentinelOne threats fetch failed: {exc}") from exc

            body = resp.json()
            page = body.get("data", [])
            events.extend(page)
            page_cursor = (body.get("pagination") or {}).get("nextCursor")
            if not page_cursor or not page:
                break

        next_cursor = since
        created_ats = [e["createdAt"] for e in events if e.get("createdAt")]
        if created_ats:
            next_cursor = max(created_ats)
        return events, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = self._session().get(
                f"{self.base_url}/web/api/v2.1/system/status",
                headers=self._headers(), timeout=self.timeout,
            )
            if resp.ok:
                return True, "Connected to SentinelOne Management API"
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            return False, str(exc)
