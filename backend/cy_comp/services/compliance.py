"""
cy_comp/services/compliance.py
================================
Framework scoring engine.

Computes compliance posture scores per framework from cy_comp_controls vs
cy_comp_findings, then caches results in cy_comp_framework_scores.

Supported frameworks: NIS2, DORA, ISO 27001, SOC 2, NIST CSF, PCI DSS
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.compliance")

SUPPORTED_FRAMEWORKS = ["nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss"]

# Severity weights for gap scoring
_SEVERITY_WEIGHT = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}


def _compute_score_for_framework(cur, framework: str) -> dict:
    """
    Compute compliance score for a single framework.

    Score = (passing / total_controls) * 100 capped to 0–100.
    A control is "passing" if no open/in-progress finding references it.
    Critical gaps = open findings with severity in (critical, high).
    """
    # Total controls defined for this framework
    cur.execute(
        "SELECT COUNT(*) FROM cy_comp_controls WHERE framework = %s;",
        (framework,)
    )
    total = (cur.fetchone() or [0])[0]

    # Controls that have at least one open finding (failing)
    cur.execute(
        """
        SELECT COUNT(DISTINCT control_id)
        FROM cy_comp_findings
        WHERE framework = %s
          AND status IN ('open', 'in_progress')
          AND control_id IS NOT NULL;
        """,
        (framework,)
    )
    failing = (cur.fetchone() or [0])[0]
    passing = max(0, total - failing)

    # Critical gaps
    cur.execute(
        """
        SELECT COUNT(*)
        FROM cy_comp_findings
        WHERE framework = %s
          AND status IN ('open', 'in_progress')
          AND severity IN ('critical', 'high');
        """,
        (framework,)
    )
    critical_gaps = (cur.fetchone() or [0])[0]

    score = round((passing / total * 100) if total > 0 else 0.0, 1)
    return {
        "framework":      framework,
        "score":          score,
        "total_controls": total,
        "passing":        passing,
        "failing":        failing,
        "critical_gaps":  critical_gaps,
        "computed_at":    datetime.now(timezone.utc).isoformat(),
    }


def compute_framework_scores(frameworks: Optional[list[str]] = None) -> list[dict]:
    """
    Compute and cache scores for all (or specified) frameworks.
    Returns list of score dicts.
    """
    targets = frameworks or SUPPORTED_FRAMEWORKS
    results = []

    try:
        with db() as conn:
            cur = conn.cursor()
            for fw in targets:
                score_dict = _compute_score_for_framework(cur, fw)
                # Upsert into cache table (insert new row; keep history)
                cur.execute(
                    """
                    INSERT INTO cy_comp_framework_scores
                        (framework, score, total_controls, passing, failing, critical_gaps, computed_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW());
                    """,
                    (
                        score_dict["framework"],
                        score_dict["score"],
                        score_dict["total_controls"],
                        score_dict["passing"],
                        score_dict["failing"],
                        score_dict["critical_gaps"],
                    )
                )
                results.append(score_dict)
    except Exception as exc:
        log.error("compute_framework_scores failed: %s", exc)

    return results


def get_latest_scores(frameworks: Optional[list[str]] = None) -> list[dict]:
    """
    Return the most recently cached score per framework.
    Falls back to computing on-the-fly if no cached row exists.
    """
    targets = frameworks or SUPPORTED_FRAMEWORKS
    rows = []

    try:
        with db() as conn:
            cur = conn.cursor()
            for fw in targets:
                cur.execute(
                    """
                    SELECT framework, score, total_controls, passing, failing, critical_gaps, computed_at
                    FROM cy_comp_framework_scores
                    WHERE framework = %s
                    ORDER BY computed_at DESC
                    LIMIT 1;
                    """,
                    (fw,)
                )
                row = cur.fetchone()
                if row:
                    rows.append({
                        "framework":      row[0],
                        "score":          row[1],
                        "total_controls": row[2],
                        "passing":        row[3],
                        "failing":        row[4],
                        "critical_gaps":  row[5],
                        "computed_at":    row[6].isoformat() if row[6] else None,
                    })
                else:
                    # No cached score — compute now
                    score_dict = _compute_score_for_framework(cur, fw)
                    rows.append(score_dict)
    except Exception as exc:
        log.error("get_latest_scores failed: %s", exc)

    return rows


def get_dashboard_summary() -> dict:
    """
    Aggregate dashboard data: overall posture score, per-framework scores,
    recent finding counts, active alert count.
    """
    scores = get_latest_scores()
    overall = round(sum(s["score"] for s in scores) / len(scores), 1) if scores else 0.0

    findings_summary = {}
    alert_count = 0

    try:
        with db() as conn:
            cur = conn.cursor()
            # Finding counts by severity
            cur.execute(
                """
                SELECT severity, COUNT(*) FROM cy_comp_findings
                WHERE status IN ('open', 'in_progress')
                GROUP BY severity;
                """
            )
            for sev, cnt in cur.fetchall():
                findings_summary[sev] = cnt

            # Active alerts
            cur.execute(
                "SELECT COUNT(*) FROM cy_comp_alerts WHERE acknowledged = FALSE;"
            )
            alert_count = (cur.fetchone() or [0])[0]
    except Exception as exc:
        log.error("get_dashboard_summary failed: %s", exc)

    return {
        "overall_score":    overall,
        "framework_scores": scores,
        "findings_summary": findings_summary,
        "active_alerts":    alert_count,
    }
