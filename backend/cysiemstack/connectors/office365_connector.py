"""
cysiemstack/connectors/office365_connector.py
================================================
Pulls audit records from Microsoft's Office 365 Management Activity API.
This bypasses the existing Wazuh O365 wodle entirely (see
docs/CYDATALAKE_MIGRATION_PLAN.md §0/§7) — it is the first cloud-log path
that doesn't require Wazuh to be installed at all.

Config fields:
  tenant_id, client_id, client_secret — Azure AD app registration with
    ActivityFeed.Read application permission, admin-consented
  content_types — comma-separated subset of Audit.AzureActiveDirectory,
    Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All
    (default: all five)

The Management Activity API is subscription-based: a tenant must be
"subscribed" per content type before any content is listed (idempotent —
subscribing twice is a no-op, not an error). `pull()` subscribes on first
run, then lists + fetches content blobs newer than the cursor.

Cursor is the ISO8601 end of the last time window successfully processed.

NOT verified against a live Microsoft 365 tenant — implemented against
Microsoft's publicly documented Management Activity API (learn.microsoft.com).
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "office365"

_DEFAULT_CONTENT_TYPES = [
    "Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint",
    "Audit.General", "DLP.All",
]


class Office365Connector(BaseConnector):
    vendor = "office365"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.tenant_id     = config.get("tenant_id", "")
        self.client_id     = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")
        ct = config.get("content_types", "")
        self.content_types = [c.strip() for c in ct.split(",") if c.strip()] or _DEFAULT_CONTENT_TYPES
        self._subscribed = False

    def _token(self) -> str:
        resp = self._session().post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "scope":         "https://manage.office.com/.default",
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _ensure_subscribed(self, sess, token: str):
        if self._subscribed:
            return
        for ct in self.content_types:
            sess.post(
                f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed/subscriptions/start",
                headers={"Authorization": f"Bearer {token}"},
                params={"contentType": ct},
                timeout=self.timeout,
            )  # idempotent — a 400 "already subscribed" is fine, ignore failures here
        self._subscribed = True

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        now = datetime.now(timezone.utc)
        start = datetime.fromisoformat(cursor) if cursor else now - timedelta(hours=24)
        end = min(now, start + timedelta(hours=24))  # API caps windows at 24h

        sess = self._session()
        try:
            token = self._token()
        except Exception as exc:
            raise ConnectorError(f"O365 OAuth token request failed: {exc}") from exc

        self._ensure_subscribed(sess, token)
        headers = {"Authorization": f"Bearer {token}"}
        events: list[dict[str, Any]] = []

        for ct in self.content_types:
            try:
                listing = sess.get(
                    f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed/subscriptions/content",
                    headers=headers,
                    params={"contentType": ct, "startTime": start.isoformat(), "endTime": end.isoformat()},
                    timeout=self.timeout,
                )
                listing.raise_for_status()
            except Exception as exc:
                raise ConnectorError(f"O365 content listing failed for {ct}: {exc}") from exc

            for item in listing.json():
                uri = item.get("contentUri")
                if not uri:
                    continue
                try:
                    blob = sess.get(uri, headers=headers, timeout=self.timeout)
                    blob.raise_for_status()
                    events.extend(blob.json())
                except Exception:
                    continue  # one bad blob shouldn't abort the whole pull

        return events, end.isoformat()

    def test_connection(self) -> tuple[bool, str]:
        try:
            self._token()
            return True, "Connected to Office 365 Management Activity API (token acquired)"
        except Exception as exc:
            return False, str(exc)
