"""
cysoar_connector.py
===================
CySOAR (Node-RED) integration for the CySIEM Correlation Engine.

Responsibilities
----------------
cysoar_trigger()        — POST incident metadata to the CySOAR webhook (original).
dispatch_if_confident() — Phase 5: structured recommendation + confidence-gated dispatch.
get_soar_status()       — Phase 5: report installed/running state to the portal.

Configuration
-------------
  SOAR_WEBHOOK_URL  — set in cysiemstack.env or via portal System Settings.
                      Empty string → falls back to auto-detection.

Resolution order for webhook URL
---------------------------------
  1. settings.soar_webhook_url  (cysiemstack.env explicit override)
  2. ai_settings.json → soar.webhookUrl  (portal-managed explicit override)
  3. [Phase 5] Auto-detect: /opt/cycentra/modules/state.json shows
     cysoar.status == "running" → http://127.0.0.1:1880

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

# Confidence thresholds for SOAR gate (Phase 5)
_SOAR_AUTO_THRESHOLD     = 0.90   # ≥ 90%: auto-dispatch
_SOAR_APPROVAL_THRESHOLD = 0.70   # 70–89%: analyst approval required


def _tls_verify():
    """Return verify parameter for httpx: CA bundle path or system default."""
    return settings.tls_ca_bundle if settings.tls_ca_bundle else True


def _soar_webhook_url() -> tuple[str, str]:
    """Resolve the CySOAR webhook URL.

    Returns (url, source) where source is "env" | "config" | "auto" | "".
    """
    # Path 1: env / cysiemstack.env
    url = (settings.soar_webhook_url or "").strip()
    if url:
        return url, "env"

    # Path 2: ai_settings.json (portal-managed override)
    try:
        from pathlib import Path
        import json as _json
        raw = Path("/opt/cycentra/ai_settings.json").read_text()
        stored = _json.loads(raw)
        url = (stored.get("soar", {}).get("webhookUrl") or "").strip()
        if url:
            return url, "config"
    except Exception:
        pass

    # Path 3: auto-detect from modules/state.json (Phase 5)
    try:
        from pathlib import Path
        import json as _json
        state_raw = Path("/opt/cycentra/modules/state.json").read_text()
        state = _json.loads(state_raw)
        if (state.get("cysoar") or {}).get("status") == "running":
            return "http://127.0.0.1:1880", "auto"
    except Exception:
        pass

    return "", ""


def get_soar_status() -> dict:
    """Return CySOAR connection state for the portal status bar.

    Response: {installed, running, url, source}
    Never raises.
    """
    try:
        from pathlib import Path
        import json as _json
        state_raw = Path("/opt/cycentra/modules/state.json").read_text()
        state = _json.loads(state_raw)
        soar_state = state.get("cysoar") or {}
        installed = soar_state.get("installed", False)
        running   = soar_state.get("status") == "running"
    except Exception:
        installed = False
        running   = False

    url, source = _soar_webhook_url()
    return {
        "installed": installed,
        "running":   running,
        "url":       url if source != "auto" else "",  # don't expose internal URL
        "source":    source or "none",
    }


async def cysoar_trigger(db: Any, incident: Any) -> list[dict]:
    """
    POST incident metadata to the CySOAR webhook.

    Returns a list of action dicts received from Node-RED, or [] on failure /
    when SOAR is not configured.  Updates incident.soar_actions in place.
    """
    url, _ = _soar_webhook_url()
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
        async with httpx.AsyncClient(timeout=8.0, verify=_tls_verify()) as client:
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


async def dispatch_if_confident(
    db: Any,
    incident: Any,
    recommendation: dict,
    confidence_score: float,
    actor: str = "system",
) -> dict:
    """Phase 5: Confidence-gated SOAR dispatch.

    Gate logic:
      < 0.70  → no dispatch, status = "needs_review"
      0.70–0.89 → no auto-dispatch, status = "pending_approval"
      ≥ 0.90  → auto-dispatch to CySOAR, status = "auto_dispatched"

    Returns a dispatch_log entry dict. Never raises.
    Updates incident.soar_dispatched, soar_dispatched_at, soar_dispatch_log in place.
    """
    now = datetime.now(timezone.utc)
    pct = round(confidence_score * 100, 1)

    if confidence_score < _SOAR_APPROVAL_THRESHOLD:
        entry = {
            "timestamp":   now.isoformat(),
            "confidence":  pct,
            "actor":       actor,
            "status":      "needs_review",
            "reason":      f"Confidence {pct}% below approval threshold ({int(_SOAR_APPROVAL_THRESHOLD*100)}%)",
            "actions_sent": 0,
            "http_status":  None,
        }
        _append_dispatch_log(incident, entry)
        return entry

    if confidence_score < _SOAR_AUTO_THRESHOLD:
        entry = {
            "timestamp":   now.isoformat(),
            "confidence":  pct,
            "actor":       actor,
            "status":      "pending_approval",
            "reason":      f"Confidence {pct}% — analyst approval required",
            "actions_sent": 0,
            "http_status":  None,
        }
        _append_dispatch_log(incident, entry)
        return entry

    # Auto-dispatch at ≥ 90%
    url, source = _soar_webhook_url()
    if not url:
        entry = {
            "timestamp":   now.isoformat(),
            "confidence":  pct,
            "actor":       actor,
            "status":      "soar_not_configured",
            "reason":      "CySOAR not installed or webhook not configured",
            "actions_sent": 0,
            "http_status":  None,
        }
        _append_dispatch_log(incident, entry)
        return entry

    # Count total actions in recommendation
    rec = recommendation or {}
    actions_count = (
        len(rec.get("containment", []))
        + len(rec.get("eradication", []))
        + len(rec.get("recovery", []))
    )

    payload = {
        "incident_id":       incident.id,
        "confidence_score":  pct,
        "confidence_source": source,
        "severity":          incident.severity,
        "mitre_ids":         incident.mitre_ids or [],
        "kill_chain_stage":  incident.kill_chain_stage_name,
        "recommendation":    recommendation,
        "affected_agents":   incident.affected_agents or [],
        "affected_users":    incident.affected_users or [],
        "src_ips":           [str(ip) for ip in (incident.src_ips or [])],
        "timestamp":         now.isoformat(),
    }

    http_status = None
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=_tls_verify()) as client:
            resp = await client.post(url, json=payload)
        http_status = resp.status_code
        success = resp.status_code in (200, 201, 202, 204)
    except Exception as exc:
        log.warning("soar_dispatch_error", incident_id=incident.id, error=str(exc))
        success = False

    if success:
        incident.soar_dispatched    = True
        incident.soar_dispatched_at = now
        status_str = "auto_dispatched"
    else:
        status_str = "dispatch_failed"

    entry = {
        "timestamp":    now.isoformat(),
        "confidence":   pct,
        "actor":        actor,
        "status":       status_str,
        "reason":       f"Auto-dispatch at {pct}% confidence (source: {source})",
        "actions_sent": actions_count,
        "http_status":  http_status,
    }
    _append_dispatch_log(incident, entry)

    log.info("soar_confidence_dispatch", incident_id=incident.id,
             confidence=pct, status=status_str, http_status=http_status)
    return entry


def _append_dispatch_log(incident: Any, entry: dict) -> None:
    """Append a dispatch log entry to incident.soar_dispatch_log."""
    existing = list(incident.soar_dispatch_log or [])
    existing.append(entry)
    incident.soar_dispatch_log = existing
