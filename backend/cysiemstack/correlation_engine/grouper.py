"""
grouper.py
Temporal + entity-based incident grouping.

Algorithm:
  1. Look for an OPEN incident on the same agent(s) within the correlation window.
  2. If found → merge the alert into it (update counters, severity, metadata).
  3. If not found → create a new incident.

Window: configurable via CORRELATION_WINDOW_MINUTES (default 15 min).
IDs: sequential INC-NNNNN format, padded to 5 digits.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from models import Alert, Incident
from config import get_settings

log = structlog.get_logger()
settings = get_settings()


# ── Severity mapping ───────────────────────────────────────────────────────────

def _score_to_severity(alerts: list) -> str:
    max_score = max((float(a.get('base_score', 0)) for a in alerts), default=0)
    if max_score >= 10:
        return 'critical'
    if max_score >= 7:
        return 'high'
    if max_score >= 4:
        return 'medium'
    return 'low'


def _merge_unique(existing: list, new_val) -> list:
    if new_val and new_val not in existing:
        return existing + [new_val]
    return existing or []


# ── ID generation ──────────────────────────────────────────────────────────────

async def _get_next_id(db: AsyncSession) -> str:
    prefix = settings.incident_id_prefix
    result = await db.execute(
        text("SELECT COUNT(*) FROM incidents WHERE id LIKE :prefix"),
        {"prefix": f"{prefix}-%"}
    )
    count = result.scalar() or 0
    return f"{prefix}-{str(count + 1).zfill(5)}"


# ── Find matching open incident ────────────────────────────────────────────────

async def find_matching_incident(
    db: AsyncSession,
    alert: dict,
) -> Optional[Incident]:
    """
    Find an open incident that this alert belongs to.
    Matching criteria (all must hold):
      - status = 'open' or 'investigating'
      - same agent_id in affected_agents
      - last_seen within correlation window
    """
    window = timedelta(minutes=settings.correlation_window_minutes)
    cutoff = alert['timestamp'] - window

    result = await db.execute(
        select(Incident).where(
            Incident.status.in_(['open', 'investigating']),
            Incident.last_seen >= cutoff,
        ).order_by(Incident.last_seen.desc()).limit(20)
    )
    candidates = result.scalars().all()

    for inc in candidates:
        # Same agent check
        if alert.get('agent_id') in (inc.affected_agents or []):
            return inc
        # Same src_ip — different agents, same attacker
        if alert.get('src_ip') and alert['src_ip'] in (inc.src_ips or []):
            return inc

    return None


# ── Create new incident ────────────────────────────────────────────────────────

async def create_incident(db: AsyncSession, alert: dict) -> Incident:
    inc_id = await _get_next_id(db)
    inc = Incident(
        id               = inc_id,
        first_seen       = alert['timestamp'],
        last_seen        = alert['timestamp'],
        status           = 'open',
        severity         = _score_to_severity([alert]),
        alert_count      = 1,
        affected_agents  = [alert['agent_id']] if alert.get('agent_id') else [],
        affected_users   = [alert['username']] if alert.get('username') else [],
        src_ips          = [alert['src_ip']] if alert.get('src_ip') else [],
        categories       = [alert['category']] if alert.get('category') else [],
        mitre_ids        = [alert['mitre_id']] if alert.get('mitre_id') else [],
        mitre_tactics    = [alert['mitre_tactic']] if alert.get('mitre_tactic') else [],
        correlated_rules = [],
        ueba_flags       = [],
        misp_enrichment  = {},
        risk_score       = alert.get('base_score', 0),
    )
    db.add(inc)
    await db.flush()
    log.info('incident_created', incident_id=inc_id, agent=alert.get('agent_name'))
    return inc


# ── Merge alert into existing incident ─────────────────────────────────────────

async def merge_alert_into_incident(
    db: AsyncSession,
    incident: Incident,
    alert: dict,
) -> None:
    incident.last_seen   = max(incident.last_seen, alert['timestamp'])
    incident.alert_count = (incident.alert_count or 0) + 1
    incident.updated_at  = datetime.now(timezone.utc)

    incident.affected_agents = _merge_unique(incident.affected_agents or [], alert.get('agent_id'))
    incident.affected_users  = _merge_unique(incident.affected_users  or [], alert.get('username'))
    incident.src_ips         = _merge_unique(incident.src_ips         or [], alert.get('src_ip'))
    incident.categories      = _merge_unique(incident.categories      or [], alert.get('category'))
    incident.mitre_ids       = _merge_unique(incident.mitre_ids       or [], alert.get('mitre_id'))
    incident.mitre_tactics   = _merge_unique(incident.mitre_tactics   or [], alert.get('mitre_tactic'))

    # Escalate severity only, never downgrade
    sev_order = ['low', 'medium', 'high', 'critical']
    new_sev = _score_to_severity([alert])
    if sev_order.index(new_sev) > sev_order.index(incident.severity or 'low'):
        incident.severity = new_sev

    await db.flush()


# ── Main entry point ───────────────────────────────────────────────────────────

async def group_alert(db: AsyncSession, alert: dict) -> Tuple[Incident, bool]:
    """
    Main entry point. Takes a normalised alert dict.
    Returns (incident, created) where created=True means a new incident was opened.
    Persists the alert to DB and links it to the incident.
    """
    # Persist the alert row
    db_alert = Alert(
        wazuh_id      = alert.get('wazuh_id'),
        timestamp     = alert['timestamp'],
        agent_id      = alert['agent_id'],
        agent_name    = alert.get('agent_name'),
        agent_ip      = alert.get('agent_ip'),
        rule_id       = alert['rule_id'],
        rule_desc     = alert.get('rule_desc'),
        rule_level    = alert.get('rule_level'),
        base_score    = alert.get('base_score'),
        category      = alert.get('category'),
        mitre_id      = alert.get('mitre_id'),
        mitre_tactic  = alert.get('mitre_tactic'),
        src_ip        = alert.get('src_ip'),
        username      = alert.get('username'),
        process_name  = alert.get('process_name'),
        file_path     = alert.get('file_path'),
        raw_log       = alert.get('raw_log'),
        full_alert    = alert.get('full_alert'),
    )
    db.add(db_alert)
    await db.flush()

    # Group into incident
    existing = await find_matching_incident(db, alert)

    if existing:
        await merge_alert_into_incident(db, existing, alert)
        db_alert.incident_id = existing.id
        await db.flush()
        return existing, False
    else:
        incident = await create_incident(db, alert)
        db_alert.incident_id = incident.id
        await db.flush()
        return incident, True
