"""
cytim_enricher.py
=================
Single threat intelligence enricher — replaces misp_enricher + ti_enricher.
All IOC lookups route through CyTIM (http://cytim-host:7443).

CyTIM handles: MISP, VirusTotal, AbuseIPDB, GreyNoise (and any future sources
added to CyTIM) behind a 30-day cache. The correlation engine needs no direct
connections to any TI source.

Populates:
  incident.ti_reputation   — full CyTIM verdict (verdict, confidence, ioc_hits)
  incident.misp_enrichment — MISP-specific hits extracted from CyTIM response
                             (kept for backward compat with existing DB schema / UI)

Falls back silently when CyTIM is not configured (CYTIM_URL empty).
"""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Incident, Alert
from config import get_settings

log     = structlog.get_logger()
settings = get_settings()

_TIMEOUT    = 15.0
_MAX_IOCS   = 15   # cap per-incident to avoid slow enrichment on noisy incidents
_FQDN_RE    = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
_SHA256_LEN = 64
_AI_SETTINGS = Path("/opt/cycentra/ai_settings.json")


def _load_cytim_config() -> tuple[str, str]:
    """Return (cytim_url, api_key) — checked at call time so UI changes take effect
    without restarting the correlation engine.

    Priority: cysiemstack.env / os.environ (already in settings object) →
              ai_settings.json (UI-configured, no env file entry needed).
    """
    url = settings.cytim_url
    key = settings.cytim_api_key
    if url and key:
        return url, key
    try:
        if _AI_SETTINGS.exists():
            d = json.loads(_AI_SETTINGS.read_text())
            cytim = d.get("cytim", {})
            url = url or (cytim.get("url") or "").strip().rstrip("/")
            key = key or (cytim.get("apiKey") or "").strip()
    except Exception:
        pass
    return url, key


def _cytim_headers(api_key: str) -> dict:
    return {
        "X-CyTIM-Key":  api_key,
        "Content-Type": "application/json",
    }


def _extract_iocs(alerts: list) -> list[dict]:
    """Extract unique IOCs from a list of Alert rows."""
    seen: set[str] = set()
    iocs: list[dict] = []

    def _add(ioc_type: str, value: str):
        key = f"{ioc_type}:{value}"
        if key in seen or len(iocs) >= _MAX_IOCS:
            return
        seen.add(key)
        iocs.append({"type": ioc_type, "value": value})

    for alert in alerts:
        if alert.src_ip:
            _add("ip", str(alert.src_ip))

        full = alert.full_alert or {}

        # SHA256 from FIM/syscheck events
        sha256 = (
            full.get("sha256")
            or full.get("syscheck", {}).get("sha256_after")
            or full.get("syscheck", {}).get("sha256_before")
            or getattr(alert, "sha256", None)
        )
        if sha256 and len(str(sha256)) == _SHA256_LEN:
            _add("hash_sha256", str(sha256).lower())

        # Domains from rule description
        if alert.rule_desc:
            for domain in _FQDN_RE.findall(alert.rule_desc):
                if "." in domain and len(domain) >= 4:
                    _add("domain", domain.lower())

        # URLs from web proxy categories
        url = full.get("url") or full.get("data", {}).get("url")
        if url:
            _add("url", str(url))

    return iocs


async def enrich_incident(db: AsyncSession, incident: Incident) -> dict:
    """
    Enrich an incident with CyTIM threat intelligence.
    Updates incident.ti_reputation and incident.misp_enrichment.
    Returns ti_reputation dict (or {} on failure/not-configured).
    """
    cytim_url, cytim_api_key = _load_cytim_config()
    if not cytim_url or not cytim_api_key:
        return {}

    # Load alerts for this incident
    alerts_q = await db.execute(select(Alert).where(Alert.incident_id == incident.id))
    alerts   = alerts_q.scalars().all()
    if not alerts:
        return {}

    iocs = _extract_iocs(alerts)
    if not iocs:
        return {}

    try:
        async with httpx.AsyncClient(
            base_url=cytim_url,
            headers=_cytim_headers(cytim_api_key),
            timeout=_TIMEOUT,
        ) as client:
            resp = await client.post(
                "/api/cytim/bulk-enrich",
                json={"iocs": iocs, "profile": "siem"},
            )
            if resp.status_code != 200:
                log.warning("cytim_enricher: bulk-enrich returned %s", resp.status_code)
                return {}
            data = resp.json()
    except Exception as e:
        log.warning("cytim_enricher: request failed", error=str(e))
        return {}

    # CyTIM bulk-enrich returns {"results": [list], "errors": []}.
    # Each list item: {ioc_type, ioc_value, score, confidence, tags, sources: {src_name: {...}}}
    raw_list = data.get("results", [])
    if not isinstance(raw_list, list):
        log.warning("cytim_enricher: unexpected results type %s", type(raw_list).__name__)
        return {}

    def _score_to_verdict(score: int) -> str:
        if score >= 60:
            return "malicious"
        if score >= 30:
            return "suspicious"
        return "unknown"

    ioc_hits: list[dict] = []
    sources_seen: set[str] = set()
    for result in raw_list:
        if not isinstance(result, dict):
            continue
        score  = result.get("score", 0)
        srcs   = result.get("sources", {})   # dict: {source_name: {score, confidence, tags, details}}
        # Skip IOCs with no reputation signal at all
        if score == 0 and not srcs:
            continue
        sources_seen.update(srcs.keys())
        hit = {
            "ioc":     result.get("ioc_value", ""),
            "type":    result.get("ioc_type", "unknown"),
            "score":   score,
            "verdict": _score_to_verdict(score),
            "sources": srcs,
            "tags":    result.get("tags", []),
        }
        ioc_hits.append(hit)

    # Derive overall incident verdict from worst IOC
    overall_verdict = "unknown"
    max_score = 0
    for hit in ioc_hits:
        if hit["score"] > max_score:
            max_score = hit["score"]
            overall_verdict = hit["verdict"]

    # Confidence: average of normalised scores
    confidence = round(min(max_score / 100, 1.0), 3) if ioc_hits else 0.0

    ti_reputation = {
        "verdict":      overall_verdict,
        "confidence":   round(confidence * 100),
        "ioc_hits":     ioc_hits,
        "sources_used": sorted(sources_seen),
        "checked_at":   datetime.now(timezone.utc).isoformat(),
    }

    # Backward-compat: populate misp_enrichment from the MISP-source hits
    misp_ioc_hits = []
    for hit in ioc_hits:
        misp_data = hit["sources"].get("misp")
        if misp_data and misp_data.get("score", 0) > 0:
            misp_ioc_hits.append({
                "ioc":          hit["ioc"],
                "type":         hit["type"],
                "threat_level": misp_data.get("raw_data", {}).get("threat_level", "unknown"),
                "tags":         misp_data.get("tags", []),
                "events":       misp_data.get("raw_data", {}).get("events", []),
            })

    misp_enrichment = {
        "ioc_hits":      misp_ioc_hits,
        "total_lookups": len(iocs),
        "tags":          list({t for h in misp_ioc_hits for t in h.get("tags", [])}),
    }

    incident.ti_reputation   = ti_reputation
    incident.misp_enrichment = misp_enrichment
    await db.flush()

    if ioc_hits:
        log.info("cytim_enrichment_complete",
                 incident_id=incident.id,
                 verdict=overall_verdict,
                 ioc_count=len(ioc_hits),
                 max_score=max_score)

    return ti_reputation
