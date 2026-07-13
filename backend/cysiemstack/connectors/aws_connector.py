"""
cysiemstack/connectors/aws_connector.py
==========================================
Pulls events from AWS CloudTrail via the `LookupEvents` API — chosen over
polling CloudTrail's S3 delivery bucket because it needs no S3 access
policy setup and covers the last 90 days out of the box, which is enough
for incremental polling. Uses `boto3` (lazy-imported so the rest of the
connector framework has no hard AWS SDK dependency).

Config fields:
  access_key_id, secret_access_key, region — IAM user/role credentials with
    cloudtrail:LookupEvents permission (read-only)

Cursor is the ISO8601 `EventTime` of the last event seen.

NOT verified against a live AWS account — implemented against AWS's
publicly documented CloudTrail API (boto3 `cloudtrail` client,
`lookup_events`).
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "aws"


class AWSConnector(BaseConnector):
    vendor = "aws"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.access_key_id     = config.get("access_key_id", "")
        self.secret_access_key = config.get("secret_access_key", "")
        self.region             = config.get("region", "us-east-1")

    def _client(self):
        try:
            import boto3
        except ImportError as exc:
            raise ConnectorError("boto3 not installed — pip install boto3") from exc
        return boto3.client(
            "cloudtrail",
            region_name=self.region,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
        )

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        now = datetime.now(timezone.utc)
        start = datetime.fromisoformat(cursor) if cursor else now - timedelta(hours=1)

        try:
            client = self._client()
        except ConnectorError:
            raise
        except Exception as exc:
            raise ConnectorError(f"boto3 CloudTrail client init failed: {exc}") from exc

        events: list[dict[str, Any]] = []
        next_token = None
        try:
            while True:
                kwargs = {"StartTime": start, "EndTime": now, "MaxResults": 50}
                if next_token:
                    kwargs["NextToken"] = next_token
                page = client.lookup_events(**kwargs)
                events.extend(page.get("Events", []))
                next_token = page.get("NextToken")
                if not next_token or len(events) >= 2000:  # safety cap per poll cycle
                    break
        except Exception as exc:
            raise ConnectorError(f"CloudTrail lookup_events failed: {exc}") from exc

        next_cursor = now.isoformat()
        event_times = [e["EventTime"] for e in events if e.get("EventTime")]
        if event_times:
            next_cursor = max(event_times).astimezone(timezone.utc).isoformat()

        # datetime objects in Event dicts aren't JSON-serializable downstream — stringify
        for e in events:
            if "EventTime" in e:
                e["EventTime"] = e["EventTime"].isoformat()

        return events, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            client = self._client()
            client.lookup_events(MaxResults=1)
            return True, "Connected to AWS CloudTrail (LookupEvents)"
        except Exception as exc:
            return False, str(exc)
