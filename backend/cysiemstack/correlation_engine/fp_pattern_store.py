"""
fp_pattern_store.py
False-positive pattern memory — learns from repeated analyst FP closures and
suppresses matching alerts before they open new incidents.

Fingerprinting strategy:
  - For sudo/su alerts (rule_id in SUDO_RULE_IDS): extract COMMAND=/path from
    raw_log so the fingerprint is stable regardless of ENV vars or PWD.
  - For all other alerts: SHA256 of rule_id + first 200 chars of rule_desc.

Safety guards — pattern match is SKIPPED when:
  - The alert has a MISP IOC hit (confirmed IoC)
  - A critical high-fidelity correlation rule fired alongside (CR-003/013/014/025/026)
"""
import hashlib
import re
from datetime import datetime, timezone
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from models import FpPattern

log = structlog.get_logger()

# Wazuh rule IDs that produce sudo/su command events
SUDO_RULE_IDS = {5400, 5401, 5402, 5403, 5404, 5501, 5900, 18101, 18104}

# Correlation rules that override pattern suppression (high-fidelity, rarely FP)
CRITICAL_CORRELATION_RULES = {"CR-003", "CR-013", "CR-014", "CR-025", "CR-026"}


def _compute_fingerprint(alert: dict) -> str:
    """Return a stable SHA256 fingerprint for the alert."""
    rule_id = str(alert.get("rule_id", "0"))
    raw_log = alert.get("raw_log") or ""

    if int(alert.get("rule_id", 0)) in SUDO_RULE_IDS:
        # Extract the COMMAND= token so the fingerprint is independent of
        # PWD, USER env-vars and other noise in the sudo log line.
        match = re.search(r"COMMAND=(\S+)", raw_log)
        if match:
            key = f"{rule_id}:cmd:{match.group(1)}"
        else:
            key = f"{rule_id}:{(alert.get('rule_desc') or '')[:200]}"
    else:
        key = f"{rule_id}:{(alert.get('rule_desc') or '')[:200]}"

    return hashlib.sha256(key.encode()).hexdigest()


def _is_guarded(alert: dict) -> bool:
    """Return True when the alert should NOT be suppressed by pattern matching."""
    # Confirmed IOC — never suppress
    if alert.get("misp_ioc_match"):
        return True
    # Any critical correlation rule fired — let the pipeline decide
    rules_fired = alert.get("correlated_rules") or []
    if isinstance(rules_fired, list):
        for r in rules_fired:
            rule_key = r if isinstance(r, str) else r.get("rule_id", "")
            if rule_key in CRITICAL_CORRELATION_RULES:
                return True
    return False


async def check_fp_pattern(db: AsyncSession, alert: dict) -> Optional[FpPattern]:
    """
    Return an active FpPattern if this alert matches a learned auto-close pattern,
    or None if it should proceed through the normal pipeline.
    """
    if _is_guarded(alert):
        return None

    fp = _compute_fingerprint(alert)
    result = await db.execute(
        select(FpPattern).where(
            FpPattern.fingerprint == fp,
            FpPattern.auto_close == True,  # noqa: E712
        )
    )
    pattern = result.scalar_one_or_none()
    if pattern:
        log.info("fp_pattern_match", fingerprint=fp[:16], rule_id=alert.get("rule_id"),
                 pattern_id=pattern.id, close_count=pattern.close_count)
    return pattern


async def record_fp_closure(
    db: AsyncSession,
    alert: dict,
    analyst_email: str,
) -> FpPattern:
    """
    Upsert the pattern for this alert, increment close_count, and promote to
    auto_close when the threshold is reached.  Returns the updated FpPattern.
    """
    settings = get_settings()
    fp = _compute_fingerprint(alert)

    result = await db.execute(
        select(FpPattern).where(FpPattern.fingerprint == fp)
    )
    pattern = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)

    if pattern is None:
        pattern = FpPattern(
            fingerprint=fp,
            raw_sample=(alert.get("raw_log") or "")[:500],
            agent_id=alert.get("agent_id"),
            rule_id=alert.get("rule_id"),
            description=alert.get("rule_desc"),
            close_count=1,
            threshold=settings.fp_pattern_close_threshold,
            auto_close=False,
            last_seen=now,
            created_at=now,
            updated_at=now,
            created_by=analyst_email,
        )
        db.add(pattern)
    else:
        pattern.close_count += 1
        pattern.last_seen = now
        pattern.updated_at = now
        # Refresh threshold from settings in case the operator changed it
        pattern.threshold = settings.fp_pattern_close_threshold
        if not pattern.auto_close and pattern.close_count >= pattern.threshold:
            pattern.auto_close = True
            log.info(
                "fp_pattern_promoted",
                fingerprint=fp[:16],
                rule_id=pattern.rule_id,
                close_count=pattern.close_count,
                analyst=analyst_email,
            )

    await db.flush()
    return pattern
