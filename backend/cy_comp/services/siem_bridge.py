"""
cy_comp/services/siem_bridge.py
================================
Abstracted SIEM ingestion bridge for the GRC compliance module.

Architecture:
  BaseSIEMAdapter            — abstract base with fetch_compliance_alerts()
  CorrelationEngineAdapter   — calls SIEM_ENGINE_URL/alerts, filters compliance-relevant
  WazuhDirectAdapter         — direct Wazuh Indexer API
  SIEMBridgeService          — orchestrates adapters, deduplicates by alert_hash

Deduplication: SHA-256 hash of (external_id + source_type) stored in cy_comp_alerts.
"""

import hashlib
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

import requests

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.siem_bridge")

SIEM_ENGINE_URL  = os.environ.get("SIEM_ENGINE_URL",      "http://127.0.0.1:8100")
WAZUH_API_URL    = os.environ.get("WAZUH_API_URL",        "https://127.0.0.1:55000")
WAZUH_API_USER   = os.environ.get("WAZUH_API_USER",       "wazuh-wui")
WAZUH_API_PASS   = os.environ.get("WAZUH_API_PASSWORD",   "")

# Compliance-relevant Wazuh rule IDs / groups (extend as needed)
_COMPLIANCE_WAZUH_GROUPS = {
    "gdpr", "hipaa", "nist_800_53", "pci_dss", "tsc", "gpg13",
    "authentication_failures", "system_audit", "policy_changed",
}

# Compliance-relevant correlation engine alert categories
_COMPLIANCE_ENGINE_CATEGORIES = {
    "authentication", "compliance", "policy", "data_access",
    "privilege_escalation", "network_anomaly", "configuration_change",
}


def _alert_hash(external_id: str, source_type: str) -> str:
    raw = f"{external_id}|{source_type}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def _map_severity(raw_level) -> str:
    """Map numeric or string severity to critical/high/medium/low."""
    if isinstance(raw_level, int):
        if raw_level >= 14: return "critical"
        if raw_level >= 10: return "high"
        if raw_level >= 6:  return "medium"
        return "low"
    s = str(raw_level).lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    return "medium"


# ── Base Adapter ──────────────────────────────────────────────────────────────

class BaseSIEMAdapter(ABC):
    @abstractmethod
    def fetch_compliance_alerts(self) -> list[dict]:
        """
        Return a list of normalized alert dicts. Each dict must contain:
          external_id, source_type, severity, title, description,
          agent_name, agent_ip, raw_data, timestamp, framework (optional)
        """


# ── Correlation Engine Adapter ────────────────────────────────────────────────

class CorrelationEngineAdapter(BaseSIEMAdapter):
    """Calls the existing CySIEM Correlation Engine /alerts endpoint."""

    def fetch_compliance_alerts(self) -> list[dict]:
        alerts = []
        try:
            resp = requests.get(
                f"{SIEM_ENGINE_URL}/alerts",
                params={"limit": 200, "status": "open"},
                timeout=8,
            )
            if not resp.ok:
                log.warning("CorrelationEngineAdapter: non-200 (%s)", resp.status_code)
                return []
            data = resp.json()
            raw_list = data if isinstance(data, list) else data.get("alerts", [])

            for item in raw_list:
                category = (item.get("category") or item.get("type") or "").lower()
                if category not in _COMPLIANCE_ENGINE_CATEGORIES:
                    continue
                alerts.append({
                    "external_id":  str(item.get("id") or item.get("alert_id", "")),
                    "source_type":  "correlation_engine",
                    "severity":     _map_severity(item.get("severity") or item.get("level", 5)),
                    "title":        item.get("title") or item.get("description", "Compliance alert"),
                    "description":  item.get("description") or item.get("detail", ""),
                    "agent_name":   item.get("agent") or item.get("host", ""),
                    "agent_ip":     item.get("agent_ip") or item.get("src_ip", ""),
                    "raw_data":     item,
                    "timestamp":    item.get("timestamp") or item.get("created_at"),
                    "framework":    item.get("framework"),
                })
        except Exception as exc:
            log.error("CorrelationEngineAdapter.fetch_compliance_alerts: %s", exc)
        return alerts


# ── Wazuh Direct Adapter ──────────────────────────────────────────────────────

class WazuhDirectAdapter(BaseSIEMAdapter):
    """
    Direct Wazuh Indexer REST API adapter.
    Uses WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASS env vars.
    """

    def _get_token(self) -> Optional[str]:
        try:
            resp = requests.post(
                f"{WAZUH_API_URL}/security/user/authenticate",
                auth=(WAZUH_API_USER, WAZUH_API_PASS),
                verify=False,
                timeout=6,
            )
            if resp.ok:
                return resp.json().get("data", {}).get("token")
        except Exception as exc:
            log.warning("WazuhDirectAdapter._get_token: %s", exc)
        return None

    def fetch_compliance_alerts(self) -> list[dict]:
        if not WAZUH_API_PASS:
            log.debug("WazuhDirectAdapter: WAZUH_API_PASSWORD not set — skipping")
            return []

        token = self._get_token()
        if not token:
            return []

        alerts = []
        try:
            resp = requests.get(
                f"{WAZUH_API_URL}/alerts",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 100, "sort": "-timestamp"},
                verify=False,
                timeout=8,
            )
            if not resp.ok:
                log.warning("WazuhDirectAdapter: /alerts returned %s", resp.status_code)
                return []
            items = resp.json().get("data", {}).get("affected_items", [])
            for item in items:
                rule   = item.get("rule", {})
                groups = set(rule.get("groups", []))
                if not groups.intersection(_COMPLIANCE_WAZUH_GROUPS):
                    continue
                alerts.append({
                    "external_id":  item.get("id", ""),
                    "source_type":  "wazuh_direct",
                    "severity":     _map_severity(rule.get("level", 5)),
                    "title":        rule.get("description", "Wazuh compliance alert"),
                    "description":  item.get("full_log", rule.get("description", "")),
                    "agent_name":   item.get("agent", {}).get("name", ""),
                    "agent_ip":     item.get("agent", {}).get("ip", ""),
                    "raw_data":     item,
                    "timestamp":    item.get("timestamp"),
                    "framework":    next(iter(groups.intersection({"pci_dss", "gdpr", "nist_800_53", "hipaa", "tsc"})), None),
                })
        except Exception as exc:
            log.error("WazuhDirectAdapter.fetch_compliance_alerts: %s", exc)
        return alerts


# ── SIEM Bridge Service ───────────────────────────────────────────────────────

class SIEMBridgeService:
    """
    Orchestrates all SIEM adapters, deduplicates alerts by hash, and persists
    new compliance-relevant alerts to cy_comp_alerts.
    """

    def __init__(self):
        self._adapters: list[BaseSIEMAdapter] = [
            CorrelationEngineAdapter(),
            WazuhDirectAdapter(),
        ]

    def sync(self) -> dict:
        """Run all adapters, deduplicate, persist. Returns sync summary."""
        all_alerts: list[dict] = []
        for adapter in self._adapters:
            try:
                fetched = adapter.fetch_compliance_alerts()
                all_alerts.extend(fetched)
                log.info("%s fetched %d alerts", adapter.__class__.__name__, len(fetched))
            except Exception as exc:
                log.error("adapter %s failed: %s", adapter.__class__.__name__, exc)

        new_count = 0
        dup_count = 0

        try:
            with db() as conn:
                cur = conn.cursor()
                for alert in all_alerts:
                    h = _alert_hash(alert.get("external_id", ""), alert.get("source_type", ""))
                    # Check dedup
                    cur.execute(
                        "SELECT id FROM cy_comp_alerts WHERE alert_hash = %s;", (h,)
                    )
                    if cur.fetchone():
                        dup_count += 1
                        continue
                    # Insert
                    aid = str(uuid.uuid4())
                    cur.execute(
                        """
                        INSERT INTO cy_comp_alerts
                            (id, alert_hash, external_id, source_type, severity,
                             framework, title, description, agent_name, agent_ip,
                             raw_data, timestamp, created_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW());
                        """,
                        (
                            aid, h,
                            alert.get("external_id"),
                            alert.get("source_type"),
                            alert.get("severity"),
                            alert.get("framework"),
                            alert.get("title"),
                            alert.get("description"),
                            alert.get("agent_name"),
                            alert.get("agent_ip"),
                            json.dumps(alert.get("raw_data", {})),
                            alert.get("timestamp"),
                        )
                    )
                    new_count += 1
        except Exception as exc:
            log.error("SIEMBridgeService.sync persist failed: %s", exc)

        log.info("SIEM sync complete: new=%d, dup=%d", new_count, dup_count)
        return {
            "new":        new_count,
            "duplicates": dup_count,
            "total":      len(all_alerts),
        }


# Module-level singleton
_bridge: Optional[SIEMBridgeService] = None


def get_bridge() -> SIEMBridgeService:
    global _bridge
    if _bridge is None:
        _bridge = SIEMBridgeService()
    return _bridge
