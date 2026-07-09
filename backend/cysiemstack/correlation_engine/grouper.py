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
    """Map alert base_score to incident severity using Wazuh level conventions.

    _level_to_score() in normaliser.py maps Wazuh rule levels to these ranges:
      level  3 →  4.1   level  7 →  6.2   level 10 →  7.1   level 12 →  7.6
      level 13 →  7.8   level 14 →  8.0   level 15 →  8.2   (max)

    Threshold rationale:
      ≥ 8.2  critical  — level 15 only (Wazuh critical: DCSync, shadow copy delete, cred dump)
      ≥ 7.6  high      — level 12-14 (Wazuh high: LOLBAS, PtH, AV-disabled, encoded PS)
      ≥ 6.0  medium    — level 7-11 (Wazuh medium: recon, WMI, password spray, custom rules)
      else   low       — level 3-6 (Wazuh low: informational auth events)

    Previously the thresholds were >=10/7/4 which placed the >=10 branch
    unreachable (max possible score is 8.24) and promoted ALL level-10+ alerts
    to "high" at creation — the root cause of near-universal High incidents.
    """
    max_score = max((float(a.get('base_score', 0)) for a in alerts), default=0)
    if max_score >= 8.2:
        return 'critical'
    if max_score >= 7.6:
        return 'high'
    if max_score >= 6.0:
        return 'medium'
    return 'low'


def _merge_unique(existing: list, new_val) -> list:
    if new_val and new_val not in existing:
        return existing + [new_val]
    return existing or []


_SPECIFIC_CLOUD_SOURCES = frozenset({'o365', 'azure', 'aws', 'gcp', 'github'})

def _merge_categories(existing: list, new_cat) -> list:
    """Like _merge_unique but upgrades a legacy 'cloud' entry to the specific
    source (o365, azure, aws, gcp, github) when a more specific alert merges in."""
    if not new_cat:
        return existing or []
    cats = list(existing or [])
    if new_cat in _SPECIFIC_CLOUD_SOURCES and 'cloud' in cats:
        cats = [c for c in cats if c != 'cloud']
    if new_cat not in cats:
        cats.append(new_cat)
    return cats


# ── ID generation ──────────────────────────────────────────────────────────────

async def _get_next_id(db: AsyncSession) -> str:
    """
    Generate the next incident ID by finding the highest existing numeric suffix.
    The advisory lock (acquired in group_alert before this call) already serializes
    concurrent callers — this function just reads MAX and increments.
    """
    prefix = settings.incident_id_prefix
    result = await db.execute(
        text(
            "SELECT COALESCE(MAX(CAST(SPLIT_PART(id, '-', 2) AS INTEGER)), 0) "
            "FROM incidents WHERE id LIKE :prefix"
        ),
        {"prefix": f"{prefix}-%"},
    )
    max_num = result.scalar() or 0
    return f"{prefix}-{str(max_num + 1).zfill(5)}"


# ── Find matching open incident ────────────────────────────────────────────────

async def find_matching_incident(
    db: AsyncSession,
    alert: dict,
) -> Optional[Incident]:
    """
    Find an active incident that this alert belongs to.

    Eligible statuses: open, investigating, in_review, held.
    in_review and held are included because ingestor.py advances status within
    the same transaction that created the incident — without them, a second alert
    from the same agent (even seconds later) finds no eligible incident and
    creates a new one, resulting in single-alert incidents for every event.

    Two independent time guards must BOTH pass:
    1. Idle-gap  (last_seen >= activity_cutoff) — incident had activity within
       CORRELATION_WINDOW_MINUTES. Prevents linking alerts across quiet gaps.
    2. Hard ceiling (first_seen >= age_cutoff) — incident was opened within
       INCIDENT_MAX_AGE_MINUTES. Prevents continuous streams from growing unbounded.
    """
    window  = timedelta(minutes=settings.correlation_window_minutes)
    max_age = timedelta(minutes=settings.incident_max_age_minutes)
    now     = alert['timestamp']

    activity_cutoff = now - window   # idle-gap guard
    age_cutoff      = now - max_age  # hard-ceiling guard

    result = await db.execute(
        select(Incident).where(
            Incident.status.in_(['open', 'investigating', 'in_review', 'held']),
            Incident.last_seen  >= activity_cutoff,
            Incident.first_seen >= age_cutoff,
        ).order_by(Incident.last_seen.desc()).limit(20)
    )
    candidates = result.scalars().all()

    for inc in candidates:
        # Same agent — most specific: alerts from the same host always group
        if alert.get('agent_id') in (inc.affected_agents or []):
            return inc
        # Same src_ip — different agents, same attacker
        if alert.get('src_ip') and alert['src_ip'] in (inc.src_ips or []):
            return inc
        # Same category on same agent — catches FIM/process/auth bursts where
        # src_ip and username are absent (e.g. rootcheck, syscheck, FIM events)
        if (
            alert.get('category')
            and alert.get('category') not in _SPECIFIC_CLOUD_SOURCES
            and alert.get('category') in (inc.categories or [])
            and alert.get('agent_id') in (inc.affected_agents or [])
        ):
            return inc
        # Cloud-event correlation: same username + same cloud source category.
        # Runs AFTER agent/src_ip checks — only group cloud events per identity.
        if (
            alert.get('username')
            and alert.get('category') in _SPECIFIC_CLOUD_SOURCES
            and alert['username'] in (inc.affected_users or [])
            and alert.get('category') in (inc.categories or [])
        ):
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
        affected_agents      = [alert['agent_id']] if alert.get('agent_id') else [],
        affected_agent_names = [alert['agent_name']] if alert.get('agent_name') else [],
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

    incident.affected_agents      = _merge_unique(incident.affected_agents      or [], alert.get('agent_id'))
    incident.affected_agent_names = _merge_unique(incident.affected_agent_names or [], alert.get('agent_name'))
    incident.affected_users  = _merge_unique(incident.affected_users  or [], alert.get('username'))
    incident.src_ips         = _merge_unique(incident.src_ips         or [], alert.get('src_ip'))
    incident.categories      = _merge_categories(incident.categories or [], alert.get('category'))
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

    Advisory lock 20260617 covers the entire find→create path. Without it,
    concurrent tasks processing a batch of alerts all call find_matching_incident
    before any commits, all find nothing, and all create separate single-alert
    incidents for the same host. The lock ensures each task sees committed results
    from the previous task before deciding to create or merge.
    """
    # Serialize find+create across all concurrent alert tasks for this engine.
    # Transaction-level: released automatically on commit/rollback.
    await db.execute(text("SELECT pg_advisory_xact_lock(20260617)"))

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
