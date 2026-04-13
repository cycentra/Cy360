"""
cysoar_connector.py
===================
Minimal CySOAR (Node-RED) integration for the CySIEM Correlation Engine.

Responsibilities
----------------
cysoar_trigger()  — POST incident metadata to the CySOAR webhook URL (Node-RED),
                    receive back an `actions_taken` list, attach it to the
                    incident's soar_actions field.

Configuration
-------------
  SOAR_WEBHOOK_URL  — set in cysiemstack.env or via portal System Settings.
                      Empty string → SOAR is not configured; call is a no-op.

Design choices
--------------
* Fire-and-forget compatible: caller wraps in asyncio.create_task if desired.
* All exceptions are caught and logged; never raises to the ingestor pipeline.
* Returns [] if SOAR is disabled or the call fails so callers can test truthiness.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from config import get_settings

log = structlog.get_logger()
settings = get_settings()


def _soar_webhook_url() -> str:
    """Resolve the CySOAR webhook URL from settings or ai_settings.json."""
    # Primary: env / config
    url = (settings.soar_webhook_url or "").strip()
    if url:
        return url

    # Secondary: ai_settings.json (portal-managed)
    try:
        from pathlib import Path
        import json as _json
        raw = Path("/opt/cycentra/ai_settings.json").read_text()
        stored = _json.loads(raw)
        url = (stored.get("soar", {}).get("webhookUrl") or "").strip()
    except Exception:
        pass
    return url


async def cysoar_trigger(db: Any, incident: Any) -> list[dict]:
    """
    POST incident metadata to the CySOAR webhook.

    Returns a list of action dicts received from Node-RED, or [] on failure /
    when SOAR is not configured.  Updates incident.soar_actions in place.
    """
    url = _soar_webhook_url()
    if not url:
        return []

    payload = {
        "incident_id":    incident.id,
        "severity":       incident.severity,
        "status":         incident.status,
        "alert_count":    incident.alert_count,
        "categories":     incident.categories or [],
        "mitre_ids":      incident.mitre_ids or [],
        "mitre_tactics":  incident.mitre_tactics or [],
        "affected_agents": incident.affected_agents or [],
        "affected_users":  incident.affected_users or [],
        "src_ips":         [str(ip) for ip in (incident.src_ips or [])],
        "correlated_rules": [
            r.get("rule_id") for r in (incident.correlated_rules or []) if r.get("rule_id")
        ],
        "kill_chain_stage_name": incident.kill_chain_stage_name,
        "risk_score":     float(incident.risk_score or 0),
        "fp_probability": float(incident.fp_probability or 0),
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(url, json=payload)

        if resp.status_code in (200, 201, 202, 204):
            # Node-RED may return a JSON list of action objects or a dict
            actions: list[dict] = []
            if resp.content:
                try:
                    body = resp.json()
                    if isinstance(body, list):
                        actions = body
                    elif isinstance(body, dict):
                        actions = body.get("actions_taken") or [body]
                except Exception:
                    pass

            # Persist actions to incident
            existing = list(incident.soar_actions or [])
            existing.extend(actions)
            incident.soar_actions = existing

            log.info("soar_triggered", incident_id=incident.id,
                     actions=len(actions))
            return actions

        log.warning("soar_trigger_failed",
                    incident_id=incident.id, status=resp.status_code,
                    body=resp.text[:200])
        return []

    except Exception as e:
        log.warning("soar_trigger_error", incident_id=incident.id, error=str(e))
        return []
