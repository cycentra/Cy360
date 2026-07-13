"""
cysiemstack/connectors/azure_connector.py
============================================
Pulls Azure AD (Entra ID) sign-in and directory audit logs via Microsoft
Graph API. Same Azure AD app registration model as office365_connector.py
(a tenant could reuse one app registration with both API permission sets),
but kept as a separate connector since the two APIs and event shapes are
unrelated (management-plane audit vs. identity sign-in/audit events).

Config fields:
  tenant_id, client_id, client_secret — Azure AD app registration with
    AuditLog.Read.All + Directory.Read.All application permissions,
    admin-consented

Cursor is the ISO8601 `createdDateTime` of the last event seen. Both
sign-ins and directory audits are pulled per cycle and merged, sorted by
timestamp, so a single cursor covers both endpoints.

NOT verified against a live Azure AD tenant — implemented against
Microsoft Graph's publicly documented API (learn.microsoft.com/graph).
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Optional

from .base import BaseConnector, ConnectorError

vendor = "azure"


class AzureConnector(BaseConnector):
    vendor = "azure"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.tenant_id     = config.get("tenant_id", "")
        self.client_id     = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")

    def _token(self) -> str:
        resp = self._session().post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type":    "client_credentials",
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "scope":         "https://graph.microsoft.com/.default",
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def pull(self, cursor: Optional[str]) -> tuple[list[dict[str, Any]], str]:
        since = cursor or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        sess = self._session()
        try:
            token = self._token()
        except Exception as exc:
            raise ConnectorError(f"Azure AD OAuth token request failed: {exc}") from exc

        headers = {"Authorization": f"Bearer {token}"}
        events: list[dict[str, Any]] = []

        for path, ts_field in (("auditLogs/signIns", "createdDateTime"),
                                ("auditLogs/directoryAudits", "activityDateTime")):
            url = f"https://graph.microsoft.com/v1.0/{path}"
            params = {
                "$filter":  f"{ts_field} ge {since}",
                "$orderby": f"{ts_field} asc",
            }
            while url:
                try:
                    resp = sess.get(url, headers=headers, params=params, timeout=self.timeout)
                    resp.raise_for_status()
                except Exception as exc:
                    raise ConnectorError(f"Graph API fetch failed for {path}: {exc}") from exc
                body = resp.json()
                for item in body.get("value", []):
                    item.setdefault("_ts_field", ts_field)
                    events.append(item)
                url = body.get("@odata.nextLink")
                params = None  # nextLink already includes query params

        next_cursor = since
        timestamps = [e[e["_ts_field"]] for e in events if e.get(e.get("_ts_field", ""))]
        if timestamps:
            next_cursor = max(timestamps)
        return events, next_cursor

    def test_connection(self) -> tuple[bool, str]:
        try:
            self._token()
            return True, "Connected to Microsoft Graph API (token acquired)"
        except Exception as exc:
            return False, str(exc)
