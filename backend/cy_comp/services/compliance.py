"""
cy_comp/services/compliance.py
================================
Framework scoring and dashboard summary.

Derives posture scores from the real alerts + incidents tables
(compliance_* columns populated by siem_bridge.enrich_alerts_pass).
Also reads cy_comp_controls / cy_comp_findings for manual gap tracking.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.compliance")

SUPPORTED_FRAMEWORKS = ["nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss"]


def _compute_score_for_framework(cur, framework: str) -> dict:
    """
    Compute compliance posture score for a framework.

    Score = 100 − gap_penalty, capped to 0–100.
    Gap penalty = sum(weight × alert_count) per severity, normalised.

    Uses real alert data when cy_comp_controls is empty (no manual controls loaded).
    """
    total_controls  = 0
    passing         = 0
    failing         = 0
    critical_gaps   = 0

    # --- Manual controls from cy_comp_controls ---
    cur.execute(
        "SELECT COUNT(*) FROM cy_comp_controls WHERE framework = %s;", (framework,)
    )
    total_controls = (cur.fetchone() or [0])[0]

    if total_controls > 0:
        cur.execute(
            """
            SELECT COUNT(DISTINCT control_id)
            FROM cy_comp_findings
            WHERE framework = %s AND status IN ('open','in_progress') AND control_id IS NOT NULL;
            """,
            (framework,)
        )
        failing = (cur.fetchone() or [0])[0]
        passing = max(0, total_controls - failing)

        cur.execute(
            """
            SELECT COUNT(*) FROM cy_comp_findings
            WHERE framework = %s AND status IN ('open','in_progress')
              AND severity IN ('critical','high');
            """,
            (framework,)
        )
        critical_gaps = (cur.fetchone() or [0])[0]
        score = round((passing / total_controls * 100) if total_controls > 0 else 0.0, 1)

    else:
        # --- Derive score from real alert data ---
        # Count compliance-relevant alerts for this framework in last 30 days
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE rule_level >= 12) AS critical_count,
                COUNT(*) FILTER (WHERE rule_level >= 10 AND rule_level < 12) AS high_count,
                COUNT(*) FILTER (WHERE rule_level >= 7 AND rule_level < 10) AS medium_count,
                COUNT(*) FILTER (WHERE rule_level < 7) AS low_count,
                COUNT(*) AS total
            FROM alerts
            WHERE is_compliance_relevant = TRUE
              AND %s = ANY(compliance_frameworks)
              AND timestamp > NOW() - INTERVAL '30 days';
            """,
            (framework,)
        )
        row = cur.fetchone()
        crit, high, med, low, total_alerts = (row or (0, 0, 0, 0, 0))
        crit      = int(crit or 0)
        high      = int(high or 0)
        med       = int(med  or 0)
        low       = int(low  or 0)
        total_alerts = int(total_alerts or 0)

        critical_gaps  = crit + high
        total_controls = max(10, total_alerts)
        penalty        = min(100, crit * 10 + high * 5 + med * 2 + low * 1)
        score          = max(0.0, round(100.0 - penalty, 1))
        failing        = critical_gaps
        passing        = max(0, total_controls - failing)

    return {
        "framework":      framework,
        "score":          score,
        "total_controls": total_controls,
        "passing":        passing,
        "failing":        failing,
        "critical_gaps":  critical_gaps,
        "computed_at":    datetime.now(timezone.utc).isoformat(),
    }


def compute_framework_scores(frameworks: Optional[list] = None) -> list[dict]:
    targets = frameworks or SUPPORTED_FRAMEWORKS
    results = []
    try:
        with db() as conn:
            cur = conn.cursor()
            for fw in targets:
                score_dict = _compute_score_for_framework(cur, fw)
                try:
                    cur.execute(
                        """
                        INSERT INTO cy_comp_framework_scores
                            (framework, score, total_controls, passing, failing, critical_gaps, computed_at)
                        VALUES (%s,%s,%s,%s,%s,%s,NOW());
                        """,
                        (score_dict["framework"], score_dict["score"],
                         score_dict["total_controls"], score_dict["passing"],
                         score_dict["failing"], score_dict["critical_gaps"])
                    )
                except Exception:
                    pass
                results.append(score_dict)
    except Exception as exc:
        log.error("compute_framework_scores: %s", exc)
    return results


def get_latest_scores(frameworks: Optional[list] = None) -> list[dict]:
    targets = frameworks or SUPPORTED_FRAMEWORKS
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            for fw in targets:
                cur.execute(
                    """
                    SELECT framework, score, total_controls, passing, failing, critical_gaps, computed_at
                    FROM cy_comp_framework_scores WHERE framework = %s
                    ORDER BY computed_at DESC LIMIT 1;
                    """,
                    (fw,)
                )
                row = cur.fetchone()
                if row:
                    rows.append({
                        "framework": row[0], "score": row[1],
                        "total_controls": row[2], "passing": row[3],
                        "failing": row[4], "critical_gaps": row[5],
                        "computed_at": row[6].isoformat() if row[6] else None,
                    })
                else:
                    rows.append(_compute_score_for_framework(cur, fw))
    except Exception as exc:
        log.error("get_latest_scores: %s", exc)
    return rows


def get_dashboard_summary() -> dict:
    """
    Live dashboard data derived from alerts + incidents tables.
    Returns: overall_score, framework_scores, alert_by_severity,
             framework_breakdown, recent_incidents, active_alerts,
             breach_incidents, findings_summary.
    """
    scores  = get_latest_scores()
    overall = round(sum(s["score"] for s in scores) / len(scores), 1) if scores else 0.0

    alert_by_severity  = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    framework_breakdown = {}
    recent_incidents   = []
    active_alerts      = 0
    breach_incidents   = 0
    findings_summary   = {}

    try:
        with db() as conn:
            cur = conn.cursor()

            # Active compliance alerts by severity
            cur.execute(
                """
                SELECT
                    SUM(CASE WHEN rule_level >= 12 THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN rule_level >= 10 AND rule_level < 12 THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN rule_level >= 7 AND rule_level < 10 THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN rule_level < 7 THEN 1 ELSE 0 END) AS low,
                    COUNT(*) AS total
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  AND timestamp > NOW() - INTERVAL '7 days';
                """
            )
            row = cur.fetchone()
            if row:
                alert_by_severity = {
                    "critical": int(row[0] or 0),
                    "high":     int(row[1] or 0),
                    "medium":   int(row[2] or 0),
                    "low":      int(row[3] or 0),
                }
                active_alerts = int(row[4] or 0)

            # Framework breakdown — alerts per framework (last 7 days)
            cur.execute(
                """
                SELECT unnest(compliance_frameworks) AS fw, COUNT(*) AS cnt
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  AND timestamp > NOW() - INTERVAL '7 days'
                GROUP BY fw ORDER BY cnt DESC;
                """
            )
            for fw, cnt in cur.fetchall():
                framework_breakdown[fw] = int(cnt)

            # Recent compliance-breaching incidents
            cur.execute(
                """
                SELECT id, severity, risk_score, compliance_confidence,
                       compliance_frameworks, last_seen, status, alert_count
                FROM incidents
                WHERE compliance_breach = TRUE
                ORDER BY last_seen DESC
                LIMIT 10;
                """
            )
            for r in cur.fetchall():
                recent_incidents.append({
                    "id":         r[0],
                    "severity":   r[1],
                    "risk_score": float(r[2] or 0),
                    "confidence": float(r[3] or 0),
                    "frameworks": r[4] or [],
                    "last_seen":  r[5].isoformat() if r[5] else None,
                    "status":     r[6],
                    "alert_count": r[7],
                })
            breach_incidents = len(recent_incidents)

            # Open findings by severity (manual findings)
            cur.execute(
                """
                SELECT severity, COUNT(*) FROM cy_comp_findings
                WHERE status IN ('open','in_progress') GROUP BY severity;
                """
            )
            for sev, cnt in cur.fetchall():
                findings_summary[sev] = int(cnt)

    except Exception as exc:
        log.error("get_dashboard_summary: %s", exc)

    return {
        "overall_score":      overall,
        "framework_scores":   scores,
        "alert_by_severity":  alert_by_severity,
        "framework_breakdown": framework_breakdown,
        "recent_incidents":   recent_incidents,
        "active_alerts":      active_alerts,
        "breach_incidents":   breach_incidents,
        "findings_summary":   findings_summary,
    }
