"""
cysiemstack/connectors/gcp_connector.py
==========================================
Pulls Google Cloud Audit Logs via the Cloud Logging API. Uses
`google-cloud-logging` (lazy-imported so the rest of the connector
framework has no hard GCP SDK dependency).

Config fields:
  project_id          — GCP project to read audit logs from
  service_account_json — full JSON key content (as a string) for a service
    account with roles/logging.viewer

Cursor is the RFC3339 `timestamp` of the last entry seen.

NOT verified against a live GCP project — implemented against Google's
publicly documented Cloud Logging API (`google-cloud-logging` client,
`list_entries` with a timestamp filter).
"""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "gcp"

_MAX_ENTRIES_PER_PULL = 2000


class GCPConnector(BaseConnector):
    vendor = "gcp"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.project_id = config.get("project_id", "")
        self._sa_json    = config.get("service_account_json", "")

    def _client(self):
        try:
            from google.cloud import logging as gcp_logging
            from google.oauth2 import service_account
        except ImportError as exc:
            raise ConnectorError("google-cloud-logging not installed — pip install google-cloud-logging") from exc
        try:
            info = json.loads(self._sa_json)
            creds = service_account.Credentials.from_service_account_info(info)
        except Exception as exc:
            raise ConnectorError(f"Invalid service_account_json: {exc}") from exc
        return gcp_logging.Client(project=self.project_id, credentials=creds)

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        since = cursor or (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        try:
            client = self._client()
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorError(f"GCP logging client init failed: {exc}") from exc

        filter_str = (
            f'logName="projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity" '
            f'AND timestamp > "{since}"'
        )
        events: list[dict[str, Any]] = []
        try:
            for entry in client.list_entries(filter_=filter_str, order_by="timestamp asc",
                                              page_size=_MAX_ENTRIES_PER_PULL):
                events.append({
                    "timestamp":    entry.timestamp.isoformat() if entry.timestamp else "",
                    "severity":     entry.severity,
                    "log_name":     entry.log_name,
                    "resource":     entry.resource.type if entry.resource else "",
                    "payload":      entry.payload if isinstance(entry.payload, dict) else str(entry.payload),
                })
                if len(events) >= _MAX_ENTRIES_PER_PULL:
                    break
        except Exception as exc:
            raise ConnectorError(f"GCP list_entries failed: {exc}") from exc

        next_cursor = since
        timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
        if timestamps:
            next_cursor = max(timestamps)
        return events, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            client = self._client()
            list(client.list_entries(page_size=1))
            return True, "Connected to GCP Cloud Logging"
        except Exception as exc:
            return False, str(exc)
