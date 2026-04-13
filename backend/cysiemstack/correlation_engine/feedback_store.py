"""
feedback_store.py  — ENH-6
Stores analyst verdicts on incidents and computes per-rule accuracy stats.
Includes apply_feedback_adjustments() for nightly rule confidence tuning.
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import asyncio
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import CorrelationFeedback, Incident, Alert

log = structlog.get_logger()


async def submit_feedback(
    db: AsyncSession,
    incident_id: str,
    verdict: str,
    rules_fired: list = None,
    analyst_email: str = None,
    notes: str = None,
) -> CorrelationFeedback:
    """
    Store an analyst verdict for an incident.
    verdict must be: 'true_positive' | 'false_positive' | 'benign'

    When verdict is 'true_positive', IOCs from the incident's correlated alerts
    are pushed back to MISP asynchronously (fire-and-forget).
    """
    fb = CorrelationFeedback(
        incident_id   = incident_id,
        analyst_email = analyst_email,
        verdict       = verdict,
        rules_fired   = rules_fired or [],
        notes         = notes,
    )
    db.add(fb)
    await db.flush()
    log.info('feedback_submitted',
             incident=incident_id, verdict=verdict, rules=rules_fired or [])

    # Push confirmed TPs back to MISP (fire-and-forget)
    if verdict == 'true_positive':
        asyncio.create_task(_push_tp_iocs(db, incident_id))

    return fb


async def _push_tp_iocs(db: AsyncSession, incident_id: str) -> None:
    """Extract IOCs from incident alerts and push them to MISP as sightings."""
    try:
        from misp_enricher import push_iocs_to_misp

        # Fetch incident for context
        inc_q = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = inc_q.scalar_one_or_none()

        # Fetch associated alerts
        alerts_q = await db.execute(
            select(Alert).where(Alert.incident_id == incident_id)
        )
        alerts = alerts_q.scalars().all()

        indicators: list[dict] = []
        seen: set[str] = set()

        for alert in alerts:
            if alert.src_ip:
                val = str(alert.src_ip)
                if val not in seen:
                    seen.add(val)
                    indicators.append({
                        'value':   val,
                        'type':    'ip-src',
                        'comment': f'CySIEM confirmed TP — incident {incident_id}',
                    })
            full = alert.full_alert or {}
            sha256 = (
                full.get('sha256')
                or full.get('syscheck', {}).get('sha256_after')
            )
            if sha256 and len(str(sha256)) == 64:
                val = str(sha256).lower()
                if val not in seen:
                    seen.add(val)
                    indicators.append({
                        'value':   val,
                        'type':    'sha256',
                        'comment': f'CySIEM confirmed TP — incident {incident_id}',
                    })
            url = full.get('url') or full.get('data', {}).get('url')
            if url:
                val = str(url)
                if val not in seen:
                    seen.add(val)
                    indicators.append({
                        'value':   val,
                        'type':    'url',
                        'comment': f'CySIEM confirmed TP — incident {incident_id}',
                    })

        if indicators:
            await push_iocs_to_misp(indicators)
    except Exception as e:
        log.warning('push_tp_iocs_error', incident_id=incident_id, error=str(e))


async def get_rule_accuracy(db: AsyncSession) -> dict:
    """
    Return per-rule TP/FP/benign counts and accuracy rate for the last 90 days.
    Accuracy = true_positive / (true_positive + false_positive + benign)
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    result = await db.execute(
        select(CorrelationFeedback)
        .where(CorrelationFeedback.submitted_at >= cutoff)
    )
    feedback_rows = result.scalars().all()

    stats: dict = defaultdict(lambda: {'true_positive': 0, 'false_positive': 0, 'benign': 0})
    for fb in feedback_rows:
        for rule_id in (fb.rules_fired or []):
            stats[rule_id][fb.verdict] = stats[rule_id].get(fb.verdict, 0) + 1

    output = {}
    for rule_id, counts in stats.items():
        total = sum(counts.values())
        output[rule_id] = {
            **counts,
            'total':    total,
            'accuracy': round(counts['true_positive'] / total, 3) if total else None,
        }
    return output


async def apply_feedback_adjustments(db: AsyncSession) -> None:
    """Nightly job: tune rule confidence based on analyst feedback.

    For any rule where the FP rate > 80% over the last 30 days:
      - Reduce its confidence in the correlator registry by 0.1 (floor 0.1)
      - Mark it suppressed_until = now + 24h (rule will be skipped during that window)
      - Log a SOC-visible structured alert
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    result = await db.execute(
        select(CorrelationFeedback)
        .where(CorrelationFeedback.submitted_at >= cutoff)
    )
    feedback_rows = result.scalars().all()

    # Aggregate per rule
    stats: dict = defaultdict(lambda: {'true_positive': 0, 'false_positive': 0, 'benign': 0})
    for fb in feedback_rows:
        for rule_id in (fb.rules_fired or []):
            stats[rule_id][fb.verdict] = stats[rule_id].get(fb.verdict, 0) + 1

    from correlator import ALL_RULES

    rules_by_id = {r.rule_id: r for r in ALL_RULES}

    suppressed_until = datetime.now(timezone.utc) + timedelta(hours=24)
    adjusted_count = 0

    for rule_id, counts in stats.items():
        total = counts['true_positive'] + counts['false_positive'] + counts['benign']
        if total < 5:
            continue  # not enough data to make a judgment
        fp_rate = (counts['false_positive'] + counts['benign']) / total
        if fp_rate <= 0.80:
            continue

        rule = rules_by_id.get(rule_id)
        if rule is None:
            continue

        old_conf = getattr(rule, 'confidence', 0.5)
        new_conf = max(0.1, round(old_conf - 0.1, 2))
        rule.confidence = new_conf

        # Attach suppressed_until marker directly to rule object (runtime only)
        rule._suppressed_until = suppressed_until

        adjusted_count += 1
        log.warning(
            'rule_suppressed_high_fp_rate',
            event='rule_suppressed_high_fp_rate',
            rule_id=rule_id,
            fp_rate=round(fp_rate, 3),
            old_confidence=old_conf,
            new_confidence=new_conf,
            suppressed_until=suppressed_until.isoformat(),
            total_feedback=total,
        )

    if adjusted_count:
        log.info('feedback_adjustments_applied', rules_adjusted=adjusted_count)
