"""
misp_enricher.py
Enriches incidents with MISP threat intelligence via cached IOC lookups.
Cache TTL: 4h for hits, 1h for misses — avoids hammering MISP API.
"""
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


async def _lookup_misp(ioc_value: str, ioc_type: str) -> dict:
    """Direct MISP REST API call. Returns hit metadata or empty dict."""
    try:
        async with httpx.AsyncClient(
            base_url=settings.misp_url,
            headers={'Authorization': settings.misp_api_key, 'Accept': 'application/json'},
            timeout=8.0, verify=False,
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
    """Cached IOC lookup: check DB cache first, fall back to MISP API."""
    now = datetime.now(timezone.utc)

    # Cache lookup
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
    return misp_result


async def enrich_incident(db: AsyncSession, incident: Incident) -> dict:
    """
    Look up all src_ips from incident alerts in MISP.
    Updates incident.misp_enrichment and alert.misp_ioc_match.
    """
    if not settings.misp_enabled:
        return {}

    alerts_q = await db.execute(
        select(Alert).where(Alert.incident_id == incident.id)
    )
    alerts = alerts_q.scalars().all()

    enrichment = {'ioc_hits': [], 'total_lookups': 0, 'tags': []}
    seen_ips   = set()

    for alert in alerts:
        if not alert.src_ip or str(alert.src_ip) in seen_ips:
            continue
        seen_ips.add(str(alert.src_ip))
        enrichment['total_lookups'] += 1

        result = await lookup_ioc(db, str(alert.src_ip), 'ip-src')
        if result.get('hit'):
            enrichment['ioc_hits'].append({
                'ioc':          str(alert.src_ip),
                'type':         'ip-src',
                'events':       result.get('events', []),
                'threat_level': result.get('threat_level'),
                'tags':         result.get('tags', []),
            })
            enrichment['tags'].extend(result.get('tags', []))
            alert.misp_ioc_match = True
            alert.misp_event_ids = result.get('events', [])

    enrichment['tags'] = list(set(enrichment['tags']))
    incident.misp_enrichment = enrichment
    await db.flush()

    if enrichment['ioc_hits']:
        log.info('misp_hits', incident_id=incident.id, hits=len(enrichment['ioc_hits']))

    return enrichment
