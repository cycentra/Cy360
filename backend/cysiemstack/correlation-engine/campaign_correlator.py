"""
campaign_correlator.py  — ENH-1
Runs every 5 minutes. Scans all open incidents within CAMPAIGN_WINDOW_HOURS
and links those sharing src_ip(s) or username(s) under a shared campaign_id.
"""
import uuid
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Incident

log = structlog.get_logger()

CAMPAIGN_WINDOW_HOURS = 4


async def run_campaign_correlation(db: AsyncSession) -> int:
    """
    Link open incidents that share attacker infrastructure.
    Returns count of newly linked incidents.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CAMPAIGN_WINDOW_HOURS)

    result = await db.execute(
        select(Incident).where(
            Incident.status.in_(['open', 'investigating']),
            Incident.last_seen >= cutoff,
        )
    )
    incidents = result.scalars().all()

    if len(incidents) < 2:
        return 0

    # Build indicator → incident_id maps
    ip_map:   dict = defaultdict(list)
    user_map: dict = defaultdict(list)

    for inc in incidents:
        for ip in (inc.src_ips or []):
            if ip:
                ip_map[ip].append(inc.id)
        for user in (inc.affected_users or []):
            if user:
                user_map[user].append(inc.id)

    # Find groups of incidents sharing an attacker indicator
    groups: dict        = {}   # campaign_id -> set of incident ids
    inc_to_campaign: dict = {}

    for indicator_map in (ip_map, user_map):
        for indicator, inc_ids in indicator_map.items():
            if len(inc_ids) < 2:
                continue
            existing_campaign = None
            for iid in inc_ids:
                if iid in inc_to_campaign:
                    existing_campaign = inc_to_campaign[iid]
                    break
            if not existing_campaign:
                existing_campaign = f"CAM-{str(uuid.uuid4())[:8].upper()}"
                groups[existing_campaign] = set()
            for iid in inc_ids:
                groups[existing_campaign].add(iid)
                inc_to_campaign[iid] = existing_campaign

    if not groups:
        return 0

    # Build id → incident object lookup
    inc_lookup = {i.id: i for i in incidents}

    linked = 0
    for campaign_id, inc_ids in groups.items():
        peers = list(inc_ids)
        for iid in inc_ids:
            inc = inc_lookup.get(iid)
            if inc and inc.campaign_id != campaign_id:
                inc.campaign_id    = campaign_id
                inc.campaign_peers = [p for p in peers if p != iid]
                linked += 1

    if linked:
        await db.flush()
        log.info('campaign_linked', count=linked, campaigns=len(groups))

    return linked
