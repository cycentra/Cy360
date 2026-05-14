"""
cy_comp/services/compliance.py
================================
Framework scoring and dashboard summary.

Scoring hierarchy (in priority order):
  1. Questionnaire responses  — primary control evidence
  2. Alert-based penalty      — secondary signal (deducts from score)
  3. Fallback                 — 100% when no data, not 0%

Control denominator = questionnaire question count per framework.
This prevents the critical bug of using alert count as "total controls".
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.compliance")

SUPPORTED_FRAMEWORKS = ["nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss"]

# Canonical question/control count per framework (matches questionnaire data)
# Used as total_controls denominator when no manual controls exist
FRAMEWORK_CONTROL_COUNTS = {
    "nis2":     20,
    "dora":     19,
    "iso27001": 19,
    "soc2":     16,
    "nist_csf": 17,
    "pci_dss":  17,
}


def _compute_score_for_framework(cur, framework: str) -> dict:
    """
    Score = blended questionnaire + alert signal, capped 0–100.
    total_controls = questionnaire question count (never alert count).
    """
    # ── 1. Questionnaire baseline ───────────────────────────────────────────
    cur.execute(
        "SELECT COUNT(*) FROM cy_comp_questionnaire_templates WHERE framework = %s;",
        (framework,)
    )
    q_total = (cur.fetchone() or [0])[0] or FRAMEWORK_CONTROL_COUNTS.get(framework, 20)

    cur.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE r.score >= 2)  AS passing,
            COUNT(*) FILTER (WHERE r.score = 0)   AS failing,
            COUNT(*) FILTER (WHERE r.score = 1)   AS partial
        FROM cy_comp_questionnaire_responses r
        JOIN cy_comp_questionnaire_templates t ON t.question_id = r.question_id
        WHERE t.framework = %s;
        """,
        (framework,)
    )
    row = cur.fetchone() or (0, 0, 0)
    q_pass, q_fail, q_partial = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)
    q_answered = q_pass + q_fail + q_partial

    # ── 2. Alert-based penalty ──────────────────────────────────────────────
    cur.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE rule_level >= 12)              AS crit,
            COUNT(*) FILTER (WHERE rule_level >= 10 AND rule_level < 12) AS high,
            COUNT(*) FILTER (WHERE rule_level >= 7  AND rule_level < 10) AS med,
            COUNT(*) FILTER (WHERE rule_level < 7)                AS low
        FROM alerts
        WHERE is_compliance_relevant = TRUE
          AND %s = ANY(compliance_frameworks)
          AND timestamp > NOW() - INTERVAL '30 days';
        """,
        (framework,)
    )
    ar = cur.fetchone() or (0, 0, 0, 0)
    a_crit, a_high, a_med, a_low = (int(x or 0) for x in ar)

    # Raw penalty (0-100 scale), capped at 40 so alerts alone can't zero a score
    alert_penalty = min(40, a_crit * 8 + a_high * 4 + a_med * 1)

    # ── 3. Compute score ────────────────────────────────────────────────────
    if q_answered > 0:
        # Questionnaire-driven: weight partial answers at 50%
        earned = q_pass + q_partial * 0.5
        q_score = round((earned / q_total) * 100, 1)
        # Alert penalty reduces questionnaire score by up to 40 pts
        score = max(0.0, round(q_score - alert_penalty, 1))
        passing  = q_pass
        failing  = q_fail
        critical_gaps = q_fail + a_crit + a_high
    else:
        # No questionnaire data yet — use alert-only penalty against fixed denominator
        score         = max(0.0, round(100.0 - alert_penalty, 1))
        passing       = max(0, q_total - (a_crit + a_high))
        failing       = a_crit + a_high
        critical_gaps = a_crit + a_high

    return {
        "framework":       framework,
        "score":           score,
        "total_controls":  q_total,
        "passing":         min(passing, q_total),
        "failing":         min(failing, q_total),
        "critical_gaps":   critical_gaps,
        "q_answered":      q_answered,
        "q_total":         q_total,
        "alert_penalty":   alert_penalty,
        "computed_at":     datetime.now(timezone.utc).isoformat(),
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
                        "framework":      row[0],
                        "score":          row[1],
                        "total_controls": row[2],
                        "passing":        row[3],
                        "failing":        row[4],
                        "critical_gaps":  row[5],
                        "computed_at":    row[6].isoformat() if row[6] else None,
                    })
                else:
                    rows.append(_compute_score_for_framework(cur, fw))
    except Exception as exc:
        log.error("get_latest_scores: %s", exc)
    return rows


def get_score_history(framework: Optional[str] = None, limit: int = 10) -> list[dict]:
    """Last N score snapshots per framework, for trend line chart."""
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            if framework:
                cur.execute(
                    """
                    SELECT framework, score, computed_at
                    FROM cy_comp_framework_scores
                    WHERE framework = %s
                    ORDER BY computed_at DESC LIMIT %s;
                    """,
                    (framework, limit)
                )
            else:
                # Last 8 per framework
                cur.execute(
                    """
                    SELECT framework, score, computed_at FROM (
                        SELECT framework, score, computed_at,
                               ROW_NUMBER() OVER (PARTITION BY framework ORDER BY computed_at DESC) AS rn
                        FROM cy_comp_framework_scores
                    ) x WHERE rn <= 8
                    ORDER BY framework, computed_at ASC;
                    """
                )
            for r in cur.fetchall():
                rows.append({
                    "framework":   r[0],
                    "score":       float(r[1] or 0),
                    "computed_at": r[2].isoformat() if r[2] else None,
                })
    except Exception as exc:
        log.error("get_score_history: %s", exc)
    return rows


def get_alerts_by_day(days: int = 14) -> list[dict]:
    """Alert counts per day for the last N days, for bar chart."""
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    DATE(timestamp AT TIME ZONE 'UTC') AS day,
                    COUNT(*)                           AS total,
                    COUNT(*) FILTER (WHERE rule_level >= 12)              AS critical,
                    COUNT(*) FILTER (WHERE rule_level >= 10 AND rule_level < 12) AS high,
                    COUNT(*) FILTER (WHERE rule_level >= 7  AND rule_level < 10) AS medium,
                    COUNT(*) FILTER (WHERE rule_level < 7)                AS low
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  AND timestamp > NOW() - INTERVAL '%s days'
                GROUP BY day
                ORDER BY day ASC;
                """ % int(days)  # safe — days is always int()
            )
            for r in cur.fetchall():
                rows.append({
                    "date":     str(r[0]),
                    "total":    int(r[1] or 0),
                    "critical": int(r[2] or 0),
                    "high":     int(r[3] or 0),
                    "medium":   int(r[4] or 0),
                    "low":      int(r[5] or 0),
                })
    except Exception as exc:
        log.error("get_alerts_by_day: %s", exc)
    return rows


def get_controls_view(framework: str) -> list[dict]:
    """
    Controls list for a framework — merges questionnaire + auto-findings + alerts.
    Returns one row per unique control_ref (or question_id as fallback).
    """
    rows: dict[str, dict] = {}
    try:
        with db() as conn:
            cur = conn.cursor()

            # 1. All questionnaire questions as control skeleton
            cur.execute(
                """
                SELECT t.question_id, t.control_ref, t.section, t.question,
                       t.weight, r.response, r.score, r.notes
                FROM cy_comp_questionnaire_templates t
                LEFT JOIN cy_comp_questionnaire_responses r
                       ON r.question_id = t.question_id AND r.framework = t.framework
                WHERE t.framework = %s
                ORDER BY t.order_idx, t.question_id;
                """,
                (framework,)
            )
            for r in cur.fetchall():
                cref = r[1] or r[0]
                sc   = r[6]
                if sc is None:
                    status = "not_assessed"
                elif sc >= 2:
                    status = "compliant"
                elif sc == 1:
                    status = "partial"
                else:
                    status = "gap"
                rows[cref] = {
                    "control_ref":  cref,
                    "section":      r[2],
                    "question":     r[3],
                    "weight":       r[4],
                    "status":       status,
                    "response":     r[5],
                    "score":        sc,
                    "notes":        r[7],
                    "sources":      ["questionnaire"],
                    "alert_count":  0,
                    "findings":     [],
                }

            # 2. Overlay auto-generated findings
            cur.execute(
                """
                SELECT control_id, severity, verdict, alert_count, title
                FROM cy_comp_findings
                WHERE framework = %s AND auto_generated = TRUE AND status = 'open';
                """,
                (framework,)
            )
            for r in cur.fetchall():
                cref = r[0] or "UNKNOWN"
                if cref in rows:
                    rows[cref]["alert_count"] = int(r[3] or 0)
                    rows[cref]["findings"].append({
                        "verdict": r[2], "severity": r[1], "title": r[4]
                    })
                    # Escalate status if alert verdict is breach
                    if r[2] == "breach" and rows[cref]["status"] not in ("gap",):
                        rows[cref]["status"] = "breach"
                    if "automated" not in rows[cref]["sources"]:
                        rows[cref]["sources"].append("automated")
                else:
                    # Control from alerts only (no questionnaire question mapped)
                    rows[cref] = {
                        "control_ref": cref,
                        "section":     "Alert-detected",
                        "question":    r[4] or cref,
                        "weight":      2,
                        "status":      r[2] or "warning",
                        "response":    None,
                        "score":       None,
                        "notes":       None,
                        "sources":     ["automated"],
                        "alert_count": int(r[3] or 0),
                        "findings":    [{"verdict": r[2], "severity": r[1], "title": r[4]}],
                    }

    except Exception as exc:
        log.error("get_controls_view(%s): %s", framework, exc)

    return list(rows.values())


def get_dashboard_summary() -> dict:
    """
    Live dashboard data: scores, alerts distribution, breach incidents, findings.
    """
    scores  = get_latest_scores()
    overall = round(sum(s["score"] for s in scores) / len(scores), 1) if scores else 0.0

    alert_by_severity   = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    framework_breakdown = {}
    recent_incidents    = []
    active_alerts       = 0
    breach_incidents    = 0
    findings_summary    = {}

    try:
        with db() as conn:
            cur = conn.cursor()

            # Active compliance alerts by severity (last 7 days)
            cur.execute(
                """
                SELECT
                    SUM(CASE WHEN rule_level >= 12 THEN 1 ELSE 0 END)              AS critical,
                    SUM(CASE WHEN rule_level >= 10 AND rule_level < 12 THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN rule_level >= 7  AND rule_level < 10 THEN 1 ELSE 0 END) AS medium,
                    SUM(CASE WHEN rule_level < 7 THEN 1 ELSE 0 END)                AS low,
                    COUNT(*)                                                        AS total
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  AND timestamp > NOW() - INTERVAL '7 days';
                """
            )
            row = cur.fetchone()
            if row:
                alert_by_severity = {
                    "critical": int(row[0] or 0), "high":   int(row[1] or 0),
                    "medium":   int(row[2] or 0), "low":    int(row[3] or 0),
                }
                active_alerts = int(row[4] or 0)

            # Framework breakdown (last 7 days)
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

            # Recent breach incidents
            cur.execute(
                """
                SELECT id, severity, risk_score, compliance_confidence,
                       compliance_frameworks, last_seen, status, alert_count
                FROM incidents
                WHERE compliance_breach = TRUE
                ORDER BY last_seen DESC LIMIT 10;
                """
            )
            for r in cur.fetchall():
                recent_incidents.append({
                    "id":          r[0], "severity":    r[1],
                    "risk_score":  float(r[2] or 0),
                    "confidence":  float(r[3] or 0),
                    "frameworks":  r[4] or [],
                    "last_seen":   r[5].isoformat() if r[5] else None,
                    "status":      r[6], "alert_count": r[7],
                })
            breach_incidents = len(recent_incidents)

            # Findings by severity
            cur.execute(
                """
                SELECT severity, COUNT(*) FROM cy_comp_findings
                WHERE status IN ('open','in_progress') GROUP BY severity;
                """
            )
            for sev, cnt in cur.fetchall():
                findings_summary[sev] = int(cnt)

            # Findings by verdict
            cur.execute(
                """
                SELECT verdict, COUNT(*) FROM cy_comp_findings
                WHERE status IN ('open','in_progress') GROUP BY verdict;
                """
            )
            findings_by_verdict = {}
            for verdict, cnt in cur.fetchall():
                findings_by_verdict[verdict or "open"] = int(cnt)

    except Exception as exc:
        log.error("get_dashboard_summary: %s", exc)
        findings_by_verdict = {}

    return {
        "overall_score":       overall,
        "framework_scores":    scores,
        "alert_by_severity":   alert_by_severity,
        "framework_breakdown": framework_breakdown,
        "recent_incidents":    recent_incidents,
        "active_alerts":       active_alerts,
        "breach_incidents":    breach_incidents,
        "findings_summary":    findings_summary,
        "findings_by_verdict": findings_by_verdict,
        "alerts_by_day":       get_alerts_by_day(14),
        "score_history":       get_score_history(),
    }
