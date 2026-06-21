"""
ti_enricher.py — Phase 1: Unified Threat Intelligence Enrichment Layer

Aggregates reputation data from multiple TI sources in parallel:
  - MISP            (existing plugin, unchanged)
  - VirusTotal v3   (IP + domain + file hash)
  - AbuseIPDB v2    (IP only)
  - GreyNoise       (IP only)

Result stored as `incident.ti_reputation` (JSONB) with shape:
  {
    "verdict":      "malicious" | "suspicious" | "benign" | "unknown",
    "confidence":   0-100,
    "ioc_hits":     [{"ioc", "type", "sources": [...], "verdict", "details": {...}}],
    "sources_used": ["misp", "virustotal", "abuseipdb", "greynoise"],
    "checked_at":   "<ISO timestamp>",
  }

Confidence weight model:
  MISP hit        → +35 (authoritative threat feed)
  VT malicious    → +25 (majority AV engines)
  VT suspicious   → +10
  AbuseIPDB ≥ 50  → +20
  AbuseIPDB ≥ 25  → +10
  GreyNoise riot  → -15 (known benign scanner)
  GreyNoise malicious → +20
"""
import asyncio
import re
from datetime import datetime, timezone
import httpx
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from models import Incident, Alert
from sqlalchemy import select
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

_TIMEOUT = 8.0


def _tls_verify():
    return settings.tls_ca_bundle if settings.tls_ca_bundle else True


# ── VirusTotal v3 ─────────────────────────────────────────────────────────────

async def _vt_lookup(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal v3 for IP, domain, or file hash."""
    if not settings.vt_api_key:
        return {}
    headers = {"x-apikey": settings.vt_api_key}
    if ioc_type in ("ip-src", "ip-dst", "ip"):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "sha256":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    else:
        return {}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=_tls_verify()) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return {"source": "virustotal", "verdict": "unknown"}
            if resp.status_code != 200:
                return {}
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            total       = sum(stats.values()) or 1
            verdict = "unknown"
            if malicious / total >= 0.1:
                verdict = "malicious"
            elif (malicious + suspicious) / total >= 0.05:
                verdict = "suspicious"
            else:
                verdict = "benign"
            return {
                "source":     "virustotal",
                "verdict":    verdict,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "community_score": data.get("reputation", 0),
            }
    except Exception as e:
        log.debug("vt_lookup_error", ioc=ioc, error=str(e))
        return {}


# ── AbuseIPDB v2 ──────────────────────────────────────────────────────────────

async def _abuseipdb_lookup(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation. Returns confidence score 0-100."""
    if not settings.abuseipdb_api_key:
        return {}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=_tls_verify()) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
            )
            if resp.status_code != 200:
                return {}
            d = resp.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return {
                "source":           "abuseipdb",
                "abuse_score":      score,
                "total_reports":    d.get("totalReports", 0),
                "country":          d.get("countryCode"),
                "isp":              d.get("isp"),
                "verdict":          "malicious" if score >= 50 else ("suspicious" if score >= 25 else "benign"),
            }
    except Exception as e:
        log.debug("abuseipdb_lookup_error", ip=ip, error=str(e))
        return {}


# ── GreyNoise ─────────────────────────────────────────────────────────────────

async def _greynoise_lookup(ip: str) -> dict:
    """Query GreyNoise Community API for IP classification."""
    if not settings.greynoise_api_key:
        return {}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=_tls_verify()) as client:
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": settings.greynoise_api_key},
            )
            if resp.status_code == 404:
                return {"source": "greynoise", "verdict": "unknown", "seen": False}
            if resp.status_code != 200:
                return {}
            d = resp.json()
            noise      = d.get("noise", False)
            riot       = d.get("riot", False)
            classifier = d.get("classification", "unknown")
            verdict = "benign" if riot else ("malicious" if classifier == "malicious" else ("suspicious" if noise else "unknown"))
            return {
                "source":      "greynoise",
                "verdict":     verdict,
                "noise":       noise,
                "riot":        riot,
                "classification": classifier,
                "name":        d.get("name"),
            }
    except Exception as e:
        log.debug("greynoise_lookup_error", ip=ip, error=str(e))
        return {}


# ── Confidence scorer ─────────────────────────────────────────────────────────

def _compute_ti_confidence(source_results: list[dict], misp_hits: int) -> tuple[int, str]:
    """Score 0–100 and derive verdict from aggregated source results."""
    score = 0
    if misp_hits > 0:
        score += min(35, misp_hits * 35)

    for r in source_results:
        src = r.get("source", "")
        v   = r.get("verdict", "unknown")
        if src == "virustotal":
            if v == "malicious":
                score += 25
            elif v == "suspicious":
                score += 10
        elif src == "abuseipdb":
            abuse = r.get("abuse_score", 0)
            if abuse >= 50:
                score += 20
            elif abuse >= 25:
                score += 10
        elif src == "greynoise":
            if r.get("riot"):
                score -= 15  # confirmed benign scanner
            elif v == "malicious":
                score += 20

    score = max(0, min(100, score))

    if score >= 60:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    elif score > 0:
        verdict = "benign"
    else:
        verdict = "unknown"
    return score, verdict


# ── Main enrichment entry point ───────────────────────────────────────────────

async def enrich_incident_ti(db: AsyncSession, incident: Incident) -> dict:
    """
    Enrich an incident with multi-source TI reputation.
    Updates incident.ti_reputation.  Returns the reputation dict.
    Runs MISP (via existing misp_enrichment) + external sources in parallel.
    """
    # Collect unique IPs, domains, hashes from incident alerts
    alerts_q = await db.execute(select(Alert).where(Alert.incident_id == incident.id))
    alerts   = alerts_q.scalars().all()

    ips:     set[str] = set()
    domains: set[str] = set()
    hashes:  set[str] = set()

    _FQDN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

    for alert in alerts:
        if alert.src_ip:
            ips.add(alert.src_ip)
        full = alert.full_alert or {}
        sha256 = (full.get("sha256") or
                  full.get("syscheck", {}).get("sha256_after") or
                  full.get("syscheck", {}).get("sha256_before"))
        if sha256 and len(str(sha256)) == 64:
            hashes.add(str(sha256).lower())
        if alert.rule_desc:
            for d in _FQDN_RE.findall(alert.rule_desc):
                if "." in d and len(d) >= 4:
                    domains.add(d.lower())

    # Build parallel task list — skip if no configured keys
    tasks: list = []
    ioc_meta: list[tuple[str, str]] = []   # (ioc_value, ioc_type) parallel with tasks

    any_external = settings.vt_api_key or settings.abuseipdb_api_key or settings.greynoise_api_key

    if any_external:
        for ip in list(ips)[:5]:   # cap per-incident external calls
            if settings.vt_api_key:
                tasks.append(_vt_lookup(ip, "ip-src"))
                ioc_meta.append((ip, "ip"))
            if settings.abuseipdb_api_key:
                tasks.append(_abuseipdb_lookup(ip))
                ioc_meta.append((ip, "ip"))
            if settings.greynoise_api_key:
                tasks.append(_greynoise_lookup(ip))
                ioc_meta.append((ip, "ip"))
        for domain in list(domains)[:3]:
            if settings.vt_api_key:
                tasks.append(_vt_lookup(domain, "domain"))
                ioc_meta.append((domain, "domain"))
        for h in list(hashes)[:3]:
            if settings.vt_api_key:
                tasks.append(_vt_lookup(h, "sha256"))
                ioc_meta.append((h, "sha256"))

    # Run all external lookups concurrently
    raw_results: list[dict] = []
    if tasks:
        raw_results = await asyncio.gather(*tasks, return_exceptions=False)

    # Aggregate per-IOC results
    ioc_map: dict[str, dict] = {}
    for meta, result in zip(ioc_meta, raw_results):
        if not result:
            continue
        ioc_val, ioc_type = meta
        key = f"{ioc_type}:{ioc_val}"
        if key not in ioc_map:
            ioc_map[key] = {"ioc": ioc_val, "type": ioc_type, "sources": []}
        src = result.get("source", "unknown")
        v   = result.get("verdict", "unknown")
        ioc_map[key]["sources"].append({"source": src, "verdict": v, "details": result})
        # Promote ioc verdict to worst observed
        cur = ioc_map[key].get("verdict", "unknown")
        _order = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}
        if _order.get(v, 0) > _order.get(cur, 0):
            ioc_map[key]["verdict"] = v

    ioc_hits = list(ioc_map.values())

    # Combine with MISP hits already on the incident
    misp_hits = len((incident.misp_enrichment or {}).get("ioc_hits", []))

    confidence, verdict = _compute_ti_confidence(raw_results, misp_hits)

    sources_used = ["misp"] if misp_hits else []
    if settings.vt_api_key:
        sources_used.append("virustotal")
    if settings.abuseipdb_api_key:
        sources_used.append("abuseipdb")
    if settings.greynoise_api_key:
        sources_used.append("greynoise")

    reputation = {
        "verdict":      verdict,
        "confidence":   confidence,
        "ioc_hits":     ioc_hits,
        "misp_hits":    misp_hits,
        "sources_used": sources_used,
        "checked_at":   datetime.now(timezone.utc).isoformat(),
    }

    incident.ti_reputation = reputation
    await db.flush()

    if ioc_hits or misp_hits:
        log.info("ti_enrichment_complete",
                 incident_id=incident.id,
                 verdict=verdict,
                 confidence=confidence,
                 ioc_count=len(ioc_hits),
                 misp_hits=misp_hits)

    return reputation
