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

SUPPORTED_FRAMEWORKS = ["nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss", "gdpr"]

# Canonical question/control count per framework (matches questionnaire data)
# Used as total_controls denominator when no manual controls exist
FRAMEWORK_CONTROL_COUNTS = {
    "nis2":     28,   # 28 questions across all 10 Art.21 measures + governance + reporting
    "dora":     28,   # 28 questions covering Art.5–49
    "iso27001": 45,   # 45 questions mapping all 93 Annex A controls across 4 themes + ISMS clauses
    "soc2":     28,   # 28 questions covering CC1-CC9 + A, C, PI, P criteria
    "nist_csf": 26,   # 26 questions covering all 6 CSF 2.0 functions (GV, ID, PR, DE, RS, RC)
    "pci_dss":  30,   # 30 questions covering all 12 PCI DSS v4 requirements
    "gdpr":     30,   # 30 questions covering key GDPR articles (Art.5-49, Art.83)
}


def _compute_score_for_framework(cur, framework: str) -> dict:
    """
    Score = blended questionnaire (weight-based) + alert signal, capped 0–100.

    Scoring formula — identical to questionnaire.py → score_framework() so that
    every page shows the same number:
        q_score = (pass_weight + partial_weight × 0.5) / total_weight × 100

    Weights come from cy_comp_questionnaire_templates.weight (default 2; critical = 3).
    total_controls = question count (not alert count) — used for the denominator label.
    """
    # ── 1. Questionnaire baseline (weight-based, mirrors score_framework()) ─
    cur.execute(
        """
        SELECT
            COUNT(t.question_id)                                          AS q_total,
            COALESCE(SUM(t.weight), 0)                                    AS total_weight,
            COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2),   0)      AS pass_weight,
            COALESCE(SUM(t.weight) FILTER (WHERE r.score = 0),    0)      AS fail_weight,
            COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1),    0)      AS partial_weight,
            COUNT(r.question_id)                                          AS q_answered,
            COUNT(r.question_id) FILTER (WHERE r.score >= 2)             AS q_pass,
            COUNT(r.question_id) FILTER (WHERE r.score = 0)              AS q_fail
        FROM cy_comp_questionnaire_templates t
        LEFT JOIN cy_comp_questionnaire_responses r
               ON r.question_id = t.question_id AND r.framework = t.framework
        WHERE t.framework = %s;
        """,
        (framework,)
    )
    row       = cur.fetchone() or (0, 0, 0, 0, 0, 0, 0, 0)
    q_total       = int(row[0] or 0) or FRAMEWORK_CONTROL_COUNTS.get(framework, 20)
    total_weight  = float(row[1] or 0) or (q_total * 2)   # fallback: 2 pts per question
    pass_weight   = float(row[2] or 0)
    fail_weight   = float(row[3] or 0)
    partial_weight = float(row[4] or 0)
    q_answered    = int(row[5] or 0)
    q_pass        = int(row[6] or 0)
    q_fail        = int(row[7] or 0)

    # ── 2. Alert-based penalty ──────────────────────────────────────────────
    try:
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE rule_level >= 12)                       AS crit,
                COUNT(*) FILTER (WHERE rule_level >= 10 AND rule_level < 12)   AS high,
                COUNT(*) FILTER (WHERE rule_level >= 7  AND rule_level < 10)   AS med
            FROM alerts
            WHERE is_compliance_relevant = TRUE
              AND %s = ANY(compliance_frameworks)
              AND timestamp > NOW() - INTERVAL '30 days';
            """,
            (framework,)
        )
        ar = cur.fetchone() or (0, 0, 0)
    except Exception:
        ar = (0, 0, 0)
    a_crit, a_high, a_med = (int(x or 0) for x in ar)
    # Capped at 40 so alerts alone can't zero a score
    alert_penalty = min(40, a_crit * 8 + a_high * 4 + a_med * 1)

    # ── 3. Compute final score (weight-based, same formula as score_framework) ─
    if q_answered > 0:
        earned   = pass_weight + partial_weight * 0.5
        q_score  = round((earned / total_weight) * 100, 1)
        score    = max(0.0, round(q_score - alert_penalty, 1))
        passing  = q_pass
        failing  = q_fail
        critical_gaps = q_fail + a_crit + a_high
    else:
        # No responses yet — use alert penalty against fixed baseline (100 % clean start)
        score         = max(0.0, round(100.0 - alert_penalty, 1))
        passing       = 0
        failing       = 0
        critical_gaps = a_crit + a_high

    return {
        "framework":      framework,
        "score":          score,
        "total_controls": q_total,
        "passing":        min(passing, q_total),
        "failing":        min(failing, q_total),
        "critical_gaps":  critical_gaps,
        "q_answered":     q_answered,
        "q_total":        q_total,
        "alert_penalty":  alert_penalty,
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
                except Exception as exc:
                    log.error("compute_framework_scores INSERT [%s]: %s", fw, exc)
                results.append(score_dict)
    except Exception as exc:
        log.error("compute_framework_scores: %s", exc)
    return results


def get_latest_scores(frameworks: Optional[list] = None) -> list[dict]:
    """
    Return latest score snapshot per framework, enriched with two live metrics:
      - alert_penalty : current 30-day alert penalty (always fresh, not cached)
      - q_answered    : current answered questionnaire question count (always fresh)

    These two metrics are batch-queried once and merged into every row so the
    frontend always sees up-to-date values without a full score recompute.
    """
    targets = frameworks or SUPPORTED_FRAMEWORKS
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()

            # ── Batch: alert penalties (live, last 30 days) ───────────────────
            alert_penalties: dict[str, int] = {fw: 0 for fw in targets}
            try:
                cur.execute(
                    """
                    SELECT fw,
                           LEAST(40, SUM(
                               CASE WHEN rule_level >= 12 THEN 8
                                    WHEN rule_level >= 10 THEN 4
                                    WHEN rule_level >= 7  THEN 1
                                    ELSE 0 END)) AS penalty
                    FROM alerts,
                         UNNEST(compliance_frameworks) AS fw
                    WHERE is_compliance_relevant = TRUE
                      AND timestamp > NOW() - INTERVAL '30 days'
                    GROUP BY fw;
                    """
                )
                for fw_name, pen in cur.fetchall():
                    alert_penalties[fw_name] = int(pen or 0)
            except Exception as exc:
                log.warning("get_latest_scores: alert_penalties batch: %s", exc)

            # ── Batch: questionnaire answered counts (live) ────────────────────
            q_answered_map: dict[str, int] = {fw: 0 for fw in targets}
            try:
                cur.execute(
                    """
                    SELECT t.framework, COUNT(r.question_id) AS answered
                    FROM cy_comp_questionnaire_templates t
                    LEFT JOIN cy_comp_questionnaire_responses r
                           ON r.question_id = t.question_id AND r.framework = t.framework
                    GROUP BY t.framework;
                    """
                )
                for fw_name, answered in cur.fetchall():
                    q_answered_map[fw_name] = int(answered or 0)
            except Exception as exc:
                log.warning("get_latest_scores: q_answered batch: %s", exc)

            # ── Per-framework cache lookup ─────────────────────────────────────
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
                penalty = alert_penalties.get(fw, 0)
                q_ans   = q_answered_map.get(fw, 0)

                if row and (row[2] or 0) > 0:
                    rows.append({
                        "framework":      row[0],
                        "score":          float(row[1] or 0),
                        "total_controls": int(row[2] or 0),
                        "passing":        int(row[3] or 0),
                        "failing":        int(row[4] or 0),
                        "critical_gaps":  int(row[5] or 0),
                        "alert_penalty":  penalty,   # live
                        "q_answered":     q_ans,     # live
                        "computed_at":    row[6].isoformat() if row[6] else None,
                    })
                else:
                    # Stale cache (total_controls=0): recompute and persist
                    fresh = _compute_score_for_framework(cur, fw)
                    fresh["alert_penalty"] = penalty
                    fresh["q_answered"]    = q_ans
                    try:
                        cur.execute(
                            """
                            INSERT INTO cy_comp_framework_scores
                                (framework, score, total_controls, passing, failing, critical_gaps, computed_at)
                            VALUES (%s,%s,%s,%s,%s,%s,NOW());
                            """,
                            (fresh["framework"], fresh["score"], fresh["total_controls"],
                             fresh["passing"], fresh["failing"], fresh["critical_gaps"])
                        )
                        log.info("get_latest_scores: repaired stale cache for %s (tc=%s, pen=%s)",
                                 fw, fresh["total_controls"], penalty)
                    except Exception as exc:
                        log.warning("get_latest_scores: cache repair INSERT [%s]: %s", fw, exc)
                    rows.append(fresh)
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


def get_dashboard_summary(frameworks: Optional[list] = None) -> dict:
    """
    Full GRC posture dashboard: scores, alerts, incidents, findings, risks, questionnaire completion.
    Every widget on ComplianceDashboardPage.jsx reads from this one endpoint.

    When ``frameworks`` is provided (list of framework IDs), all widget queries are scoped to those
    frameworks only. This makes the Overall Posture donut, alert counters, findings charts, and risk
    summary all respond to the global framework selector in the portal.
    """
    targets = frameworks or SUPPORTED_FRAMEWORKS
    scores  = get_latest_scores(frameworks=targets)
    overall = round(sum(s["score"] for s in scores) / len(scores), 1) if scores else 0.0

    alert_by_severity    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    framework_breakdown  = {}
    recent_incidents     = []
    active_alerts        = 0
    breach_incidents     = 0
    findings_summary     = {}
    findings_by_verdict  = {}
    risk_summary         = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0}
    questionnaire_hub    = []   # [{framework, total, answered, pct}]

    try:
        with db() as conn:
            cur = conn.cursor()

            # ── Active compliance alerts by severity (last 7 days) ────────────
            cur.execute(
                """
                SELECT
                    SUM(CASE WHEN rule_level >= 12 THEN 1 ELSE 0 END)                      AS critical,
                    SUM(CASE WHEN rule_level >= 10 AND rule_level < 12 THEN 1 ELSE 0 END)  AS high,
                    SUM(CASE WHEN rule_level >= 7  AND rule_level < 10 THEN 1 ELSE 0 END)  AS medium,
                    SUM(CASE WHEN rule_level < 7 THEN 1 ELSE 0 END)                        AS low,
                    COUNT(*)                                                                AS total
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  AND timestamp > NOW() - INTERVAL '7 days'
                  AND compliance_frameworks && %s::text[];
                """,
                (targets,)
            )
            row = cur.fetchone()
            if row:
                alert_by_severity = {
                    "critical": int(row[0] or 0), "high":   int(row[1] or 0),
                    "medium":   int(row[2] or 0), "low":    int(row[3] or 0),
                }
                active_alerts = int(row[4] or 0)

            # ── Alert framework breakdown (last 7 days) ───────────────────────
            cur.execute(
                """
                SELECT unnest(compliance_frameworks) AS fw, COUNT(*) AS cnt
                FROM alerts
                WHERE is_compliance_relevant = TRUE
                  AND timestamp > NOW() - INTERVAL '7 days'
                  AND compliance_frameworks && %s::text[]
                GROUP BY fw ORDER BY cnt DESC;
                """,
                (targets,)
            )
            for fw, cnt in cur.fetchall():
                framework_breakdown[fw] = int(cnt)

            # ── Recent breach incidents ───────────────────────────────────────
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
                    "id":         r[0], "severity":    r[1],
                    "risk_score": float(r[2] or 0),
                    "confidence": float(r[3] or 0),
                    "frameworks": r[4] or [],
                    "last_seen":  r[5].isoformat() if r[5] else None,
                    "status":     r[6], "alert_count": r[7],
                })
            breach_incidents = len(recent_incidents)

            # ── Findings by severity (open/in-progress, scoped to selected frameworks) ─
            cur.execute(
                """
                SELECT severity, COUNT(*) FROM cy_comp_findings
                WHERE status IN ('open','in_progress')
                  AND framework = ANY(%s::text[])
                GROUP BY severity;
                """,
                (targets,)
            )
            for sev, cnt in cur.fetchall():
                findings_summary[sev] = int(cnt)

            # ── Findings by verdict (scoped to selected frameworks) ───────────
            cur.execute(
                """
                SELECT COALESCE(verdict,'open') AS verdict, COUNT(*) FROM cy_comp_findings
                WHERE status IN ('open','in_progress')
                  AND framework = ANY(%s::text[])
                GROUP BY 1;
                """,
                (targets,)
            )
            for verdict, cnt in cur.fetchall():
                findings_by_verdict[verdict] = int(cnt)

            # ── Risk register summary (scoped to selected frameworks) ─────────
            # cy_comp_risks.frameworks is jsonb (e.g. ["nis2","gdpr"]).
            # Include a risk when at least one of its frameworks overlaps with targets.
            cur.execute(
                """
                SELECT
                    COUNT(*)                                                           AS total,
                    COUNT(*) FILTER (WHERE risk_score >= 20)                          AS critical,
                    COUNT(*) FILTER (WHERE risk_score >= 12 AND risk_score < 20)      AS high,
                    COUNT(*) FILTER (WHERE risk_score >= 6  AND risk_score < 12)      AS medium,
                    COUNT(*) FILTER (WHERE risk_score < 6)                             AS low,
                    COUNT(*) FILTER (WHERE status = 'open')                           AS open_count
                FROM cy_comp_risks
                WHERE status != 'closed'
                  AND EXISTS (
                      SELECT 1 FROM jsonb_array_elements_text(cy_comp_risks.frameworks) AS elem
                      WHERE elem = ANY(%s::text[])
                  );
                """,
                (targets,)
            )
            rr = cur.fetchone()
            if rr:
                risk_summary = {
                    "total":    int(rr[0] or 0),
                    "critical": int(rr[1] or 0),
                    "high":     int(rr[2] or 0),
                    "medium":   int(rr[3] or 0),
                    "low":      int(rr[4] or 0),
                    "open":     int(rr[5] or 0),
                }

            # ── Questionnaire completion per framework (scoped) ───────────────
            cur.execute(
                """
                SELECT
                    t.framework,
                    COUNT(t.question_id)          AS total,
                    COUNT(r.question_id)          AS answered,
                    COALESCE(SUM(t.weight),0)     AS total_weight,
                    COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2), 0)  AS pass_weight,
                    COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1),  0)  AS partial_weight
                FROM cy_comp_questionnaire_templates t
                LEFT JOIN cy_comp_questionnaire_responses r
                       ON r.question_id = t.question_id AND r.framework = t.framework
                WHERE t.framework = ANY(%s::text[])
                GROUP BY t.framework;
                """,
                (targets,)
            )
            for row in cur.fetchall():
                fw, total, answered, tw, pw, partw = row
                pct_answered = round((answered / total * 100) if total else 0, 1)
                score_pct    = round(((pw + partw * 0.5) / tw * 100) if tw else 0, 1)
                questionnaire_hub.append({
                    "framework": fw,
                    "total":     int(total),
                    "answered":  int(answered),
                    "pct":       pct_answered,
                    "score":     score_pct,
                })

    except Exception as exc:
        log.error("get_dashboard_summary: %s", exc)

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
        "risk_summary":        risk_summary,
        "questionnaire_hub":   questionnaire_hub,
        "alerts_by_day":       get_alerts_by_day(14),
        "score_history":       get_score_history(),
    }
