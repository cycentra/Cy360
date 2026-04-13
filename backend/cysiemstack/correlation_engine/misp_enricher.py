"""
misp_enricher.py
Enriches incidents with MISP threat intelligence via cached IOC lookups.
Cache TTL: 4h for hits, 1h for misses — avoids hammering MISP API.
Extended lookups: IP, domain, SHA256, URL (in addition to src_ip).
"""
import re
import time
from datetime import datetime, timezone, timedelta
from typing import Optional
import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models import MISPIOCCache, Incident, Alert
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

CACHE_TTL_HIT  = timedelta(hours=4)
CACHE_TTL_MISS = timedelta(hours=1)

# ── In-memory IOC cache (fast path before DB) ─────────────────────────────────
# Key: "misp:{ioc_type}:{value}" → (epoch_float, result_dict)
_mem_cache: dict[str, tuple[float, dict]] = {}
_MEM_CACHE_HIT_TTL  = 4 * 3600   # 4 hours for hits
_MEM_CACHE_MISS_TTL = 1 * 3600   # 1 hour for misses

# ── FQDN regex for domain extraction from rule_desc ───────────────────────────
_FQDN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}\b'
)

def _tls_verify():
    """Return verify parameter for httpx: CA bundle path or system default."""
    return settings.tls_ca_bundle if settings.tls_ca_bundle else True


async def _lookup_misp(ioc_value: str, ioc_type: str) -> dict:
    """Direct MISP REST API call. Returns hit metadata or empty dict."""
    try:
        async with httpx.AsyncClient(
            base_url=settings.misp_url,
            headers={'Authorization': settings.misp_api_key, 'Accept': 'application/json'},
            timeout=8.0, verify=_tls_verify(),
        ) as client:
            resp = await client.post('/attributes/restSearch', json={
                'returnFormat': 'json',
                'value': ioc_value,
                'type': ioc_type,
                'to_ids': 1,
                'limit': 10,
            })
            if resp.status_code != 200:
                return {}
            data = resp.json()
            attrs = data.get('response', {}).get('Attribute', [])
            if not attrs:
                return {}
            events   = list({a['event_id'] for a in attrs})
            tags     = list({t['name'] for a in attrs for t in a.get('Tag', [])})
            level    = attrs[0].get('threat_level_id', '3')
            lvl_map  = {'1': 'high', '2': 'medium', '3': 'low', '4': 'undefined'}
            return {
                'hit':          True,
                'events':       events[:5],
                'tags':         tags[:10],
                'threat_level': lvl_map.get(str(level), 'unknown'),
            }
    except Exception as e:
        log.warning('misp_lookup_error', ioc=ioc_value, error=str(e))
        return {}


async def lookup_ioc(db: AsyncSession, ioc_value: str, ioc_type: str) -> dict:
    """Cached IOC lookup: check in-memory cache, then DB cache, then MISP API."""
    now = datetime.now(timezone.utc)
    now_ts = time.monotonic()

    # ── In-memory fast path ────────────────────────────────────────────────────
    mem_key = f"misp:{ioc_type}:{ioc_value}"
    cached_mem = _mem_cache.get(mem_key)
    if cached_mem:
        mem_ts, mem_result = cached_mem
        ttl = _MEM_CACHE_HIT_TTL if mem_result.get('hit') else _MEM_CACHE_MISS_TTL
        if now_ts - mem_ts < ttl:
            return mem_result

    # ── DB cache ───────────────────────────────────────────────────────────────
    result = await db.execute(
        select(MISPIOCCache).where(
            MISPIOCCache.ioc_value == ioc_value,
            MISPIOCCache.ioc_type  == ioc_type,
        )
    )
    cached = result.scalar_one_or_none()

    if cached and cached.expires_at and cached.expires_at > now:
        return {
            'hit':          cached.is_hit,
            'events':       cached.misp_events or [],
            'threat_level': cached.threat_level,
            'tags':         cached.tags or [],
        }

    # Live lookup
    misp_result = await _lookup_misp(ioc_value, ioc_type) if settings.misp_enabled else {}
    is_hit      = bool(misp_result.get('hit'))
    ttl         = CACHE_TTL_HIT if is_hit else CACHE_TTL_MISS

    if cached:
        cached.cached_at    = now
        cached.expires_at   = now + ttl
        cached.is_hit       = is_hit
        cached.misp_events  = misp_result.get('events', [])
        cached.threat_level = misp_result.get('threat_level')
        cached.tags         = misp_result.get('tags', [])
    else:
        cached = MISPIOCCache(
            ioc_value   = ioc_value,
            ioc_type    = ioc_type,
            cached_at   = now,
            expires_at  = now + ttl,
            is_hit      = is_hit,
            misp_events = misp_result.get('events', []),
            threat_level = misp_result.get('threat_level'),
            tags        = misp_result.get('tags', []),
        )
        db.add(cached)

    await db.flush()

    # Store result in in-memory cache
    out = {
        'hit':          is_hit,
        'events':       misp_result.get('events', []),
        'threat_level': misp_result.get('threat_level'),
        'tags':         misp_result.get('tags', []),
    }
    _mem_cache[mem_key] = (now_ts, out)
    return out if misp_result else out


async def enrich_incident(db: AsyncSession, incident: Incident) -> dict:
    """
    Look up all IOCs (IP, domain, SHA256, URL) from incident alerts in MISP.
    Updates incident.misp_enrichment and alert.misp_ioc_match.
    """
    if not settings.misp_enabled:
        return {}

    alerts_q = await db.execute(
        select(Alert).where(Alert.incident_id == incident.id)
    )
    alerts = alerts_q.scalars().all()

    enrichment = {'ioc_hits': [], 'total_lookups': 0, 'tags': []}
    seen: set[str] = set()   # "type:value" dedup key

    async def _check(ioc_value: str, ioc_type: str, alert: Alert):
        key = f"{ioc_type}:{ioc_value}"
        if not ioc_value or key in seen:
            return
        seen.add(key)
        enrichment['total_lookups'] += 1
        result = await lookup_ioc(db, ioc_value, ioc_type)
        if result.get('hit'):
            enrichment['ioc_hits'].append({
                'ioc':          ioc_value,
                'type':         ioc_type,
                'events':       result.get('events', []),
                'threat_level': result.get('threat_level'),
                'tags':         result.get('tags', []),
            })
            enrichment['tags'].extend(result.get('tags', []))
            alert.misp_ioc_match = True
            if not alert.misp_event_ids:
                alert.misp_event_ids = result.get('events', [])

    for alert in alerts:
        # ── IP addresses ──────────────────────────────────────────────────────
        if alert.src_ip:
            await _check(str(alert.src_ip), 'ip-src', alert)

        # ── Domains extracted from rule_desc ──────────────────────────────────
        if alert.rule_desc:
            for domain in _FQDN_RE.findall(alert.rule_desc):
                # Skip very short or clearly non-FQDN tokens
                if '.' not in domain or len(domain) < 4:
                    continue
                await _check(domain.lower(), 'domain', alert)

        # ── SHA256 hashes from FIM / syscheck events ──────────────────────────
        full = alert.full_alert or {}
        sha256 = (
            full.get('sha256')
            or full.get('syscheck', {}).get('sha256_after')
            or full.get('syscheck', {}).get('sha256_before')
            or getattr(alert, 'sha256', None)
        )
        if sha256 and len(str(sha256)) == 64:
            await _check(str(sha256).lower(), 'sha256', alert)

        # ── URLs from web proxy alert categories ──────────────────────────────
        url = full.get('url') or full.get('data', {}).get('url')
        if url:
            await _check(str(url), 'url', alert)

    enrichment['tags'] = list(set(enrichment['tags']))
    incident.misp_enrichment = enrichment
    await db.flush()

    if enrichment['ioc_hits']:
        log.info('misp_hits', incident_id=incident.id, hits=len(enrichment['ioc_hits']))

    return enrichment


async def push_iocs_to_misp(indicators: list[dict]) -> None:
    """Push confirmed TP IOCs back to MISP as sightings / new attributes.

    Each indicator dict: {'value': str, 'type': str, 'comment': str}
    Silently exits if MISP is not configured.  Designed for fire-and-forget.
    """
    if not settings.misp_enabled or not indicators:
        return
    try:
        async with httpx.AsyncClient(
            base_url=settings.misp_url,
            headers={'Authorization': settings.misp_api_key, 'Accept': 'application/json'},
            timeout=10.0, verify=_tls_verify(),
        ) as client:
            for ind in indicators:
                val  = ind.get('value', '')
                typ  = ind.get('type', 'other')
                note = ind.get('comment', 'CySIEM confirmed TP sighting')
                if not val:
                    continue
                # Try to record a sighting first (lightweight)
                await client.post('/sightings/add', json={
                    'value': val,
                    'type':  '0',  # 0 = sighting
                    'source': 'CySIEM',
                    'comment': note,
                })
        log.info('misp_iocs_pushed', count=len(indicators))
    except Exception as e:
        log.warning('misp_push_error', error=str(e))
