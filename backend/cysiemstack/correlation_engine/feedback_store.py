"""
feedback_store.py  — ENH-6
Stores analyst verdicts on incidents and computes per-rule accuracy stats.
"""
from datetime import datetime, timezone, timedelta
from collections import defaultdict

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import CorrelationFeedback

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
    return fb


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
