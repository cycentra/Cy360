"""
audit_reporter.py
=================
Weekly audit reporter for auto-closed false-positive incidents.

Generates a structured JSON audit report for all incidents that were
automatically closed as false positives within a configurable period.

Responsibilities
----------------
generate_auto_close_audit()  — Query closed FP incidents, group by rule,
                               emit structured JSON, write to logs/ directory.

Called by the weekly scheduler in main.py.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Incident
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

# Report output directory (relative to repo root or absolute)
_LOGS_DIR = Path("/opt/cycentra/logs")
# Fallback when running in development without /opt/cycentra
_LOGS_DIR_FALLBACK = Path("logs")


def _resolve_logs_dir() -> Path:
    """Return the logs directory, creating it if necessary."""
    for candidate in (_LOGS_DIR, _LOGS_DIR_FALLBACK):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # Quick write test
            test = candidate / ".write_test"
            test.touch()
            test.unlink()
            return candidate
        except Exception:
            continue
    # Last resort: CWD
    fallback = Path(".")
    return fallback


async def generate_auto_close_audit(
    db: AsyncSession,
    period_days: int = 7,
) -> dict:
    """
    Query Incident for status='closed' with false_positive_reason IS NOT NULL
    in the last `period_days` days.

    Groups results by rule name (extracted from correlated_rules JSON).
    Emits a structured JSON report and writes it to logs/audit_auto_close_{date}.json.

    Returns the report dict.
    """
    now     = datetime.now(timezone.utc)
    cutoff  = now - timedelta(days=period_days)

    # Resolve FP threshold in effect
    fp_threshold = settings.iris_fp_threshold
    try:
        raw = Path("/opt/cycentra/ai_settings.json").read_text()
        stored = json.loads(raw)
        val = stored.get("iris", {}).get("fpThreshold")
        if val is not None:
            fp_threshold = float(val)
    except Exception:
        pass

    result = await db.execute(
        select(Incident).where(
            Incident.status                  == "closed",
            Incident.false_positive_reason.isnot(None),
            Incident.closed_at               >= cutoff,
        ).order_by(Incident.closed_at.desc())
    )
    incidents = result.scalars().all()

    total_count = len(incidents)
    by_rule: dict = defaultdict(lambda: {"count": 0, "incident_ids": []})

    for inc in incidents:
        rules = inc.correlated_rules or []
        if not rules:
            by_rule["(no rule)"]["count"] += 1
            by_rule["(no rule)"]["incident_ids"].append(inc.id)
        else:
            for r in rules:
                rule_label = r.get("rule_id", "unknown")
                by_rule[rule_label]["count"] += 1
                by_rule[rule_label]["incident_ids"].append(inc.id)

    report = {
        "report_type":    "auto_close_audit",
        "generated_at":   now.isoformat(),
        "period_days":    period_days,
        "period_start":   cutoff.isoformat(),
        "period_end":     now.isoformat(),
        "fp_threshold":   fp_threshold,
        "total_auto_closed": total_count,
        "by_rule": {
            rule_id: {
                "count":        data["count"],
                "incident_ids": data["incident_ids"][:20],  # cap for readability
            }
            for rule_id, data in sorted(
                by_rule.items(), key=lambda x: x[1]["count"], reverse=True
            )
        },
    }

    # Write to disk
    try:
        logs_dir = _resolve_logs_dir()
        date_str = now.strftime("%Y%m%d")
        report_path = logs_dir / f"audit_auto_close_{date_str}.json"
        report_path.write_text(json.dumps(report, indent=2))
        log.info("audit_report_written",
                 path=str(report_path), total=total_count, period_days=period_days)
    except Exception as e:
        log.warning("audit_report_write_error", error=str(e))

    return report
