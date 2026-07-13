"""
cysiemstack/connectors/paloalto_connector.py
===============================================
Pulls incidents from Palo Alto Cortex XDR / XSIAM's public API. Cortex
already correlates raw events into incidents on its own; this connector
aggregates those incidents into CyDataLake, it does not re-detect.

Config fields:
  base_url    — tenant API base, e.g. https://api-<tenant>.xdr.us.paloaltonetworks.com
  api_key_id  — numeric API Key ID (Cortex Settings > API Keys)
  api_key     — the API key secret itself

Uses Cortex's "Advanced" authentication scheme: a per-request SHA256 hash of
`api_key + nonce + timestamp`, sent via x-xdr-auth-id / x-xdr-nonce /
x-xdr-timestamp / Authorization headers. This is implemented from Palo
Alto's publicly documented auth scheme and has NOT been verified against a
live Cortex tenant — confirm header names/hash construction against the
target tenant's actual API version (XDR vs XSIAM base paths differ) before
relying on this in production.

Cursor is the epoch-millisecond `modification_time` of the last incident seen.
"""
from __future__ import annotations
import hashlib
import secrets
import string
import time
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "paloalto"


class PaloAltoConnector(BaseConnector):
    vendor = "paloalto"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.api_key_id = str(config.get("api_key_id", ""))
        self.api_key    = config.get("api_key", "")

    def _headers(self) -> dict[str, str]:
        nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        timestamp = str(int(time.time()) * 1000)
        auth_str = f"{self.api_key}{nonce}{timestamp}".encode("utf-8")
        auth_hash = hashlib.sha256(auth_str).hexdigest()
        return {
            "x-xdr-auth-id":   self.api_key_id,
            "x-xdr-nonce":     nonce,
            "x-xdr-timestamp": timestamp,
            "Authorization":   auth_hash,
            "Content-Type":    "application/json",
        }

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        since_ms = int(cursor) if cursor else 0
        body = {
            "request_data": {
                "filters": [
                    {"field": "modification_time", "operator": "gte", "value": since_ms},
                ],
                "sort":        {"field": "modification_time", "keyword": "asc"},
                "search_from": 0,
                "search_to":   500,
            }
        }
        try:
            resp = self._session().post(
                f"{self.base_url}/public_api/v1/incidents/get_incidents",
                headers=self._headers(), json=body, timeout=self.timeout,
            )
            resp.raise_for_status()
        except Exception as exc:
            raise ConnectorError(f"Cortex get_incidents failed: {exc}") from exc

        incidents = ((resp.json() or {}).get("reply") or {}).get("incidents") or []
        next_cursor = str(since_ms)
        mod_times = [int(i["modification_time"]) for i in incidents if i.get("modification_time")]
        if mod_times:
            next_cursor = str(max(mod_times))
        return incidents, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            resp = self._session().post(
                f"{self.base_url}/public_api/v1/incidents/get_incidents",
                headers=self._headers(),
                json={"request_data": {"search_from": 0, "search_to": 1}},
                timeout=self.timeout,
            )
            if resp.ok:
                return True, "Connected to Cortex XDR/XSIAM API"
            return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            return False, str(exc)
