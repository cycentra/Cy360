"""
cy_comp/services/risk.py
=========================
Risk management service: CRUD, scoring, appetite evaluation, heatmap data.

Risk score = likelihood (1-5) * impact (1-5).  Range: 1–25.
Severity:
  >= 20 → critical
  >= 12 → high
  >= 6  → medium
  < 6   → low
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.risk")


# ── Severity helpers ──────────────────────────────────────────────────────────

def score_risk(likelihood: int, impact: int) -> int:
    """Compute risk score as likelihood * impact (1-25)."""
    return max(1, min(25, int(likelihood) * int(impact)))


def severity_label(score: int) -> str:
    if score >= 20: return "critical"
    if score >= 12: return "high"
    if score >= 6:  return "medium"
    return "low"


def _row_to_risk(row: tuple) -> dict:
    """Convert a DB row tuple to a risk dict."""
    (rid, title, description, category, owner, likelihood, impact, risk_score,
     appetite, status, treatment, due_date, frameworks, controls, ai_analysis,
     ai_mapped_controls, created_by, created_at, updated_at) = row
    return {
        "id":                 rid,
        "title":              title,
        "description":        description,
        "category":           category,
        "owner":              owner,
        "likelihood":         likelihood,
        "impact":             impact,
        "risk_score":         risk_score,
        "severity":           severity_label(risk_score or 0),
        "appetite":           appetite,
        "status":             status,
        "treatment":          treatment,
        "due_date":           due_date.isoformat() if due_date else None,
        "frameworks":         frameworks or [],
        "controls":           controls or [],
        "ai_analysis":        ai_analysis,
        "ai_mapped_controls": ai_mapped_controls or {},
        "created_by":         created_by,
        "created_at":         created_at.isoformat() if created_at else None,
        "updated_at":         updated_at.isoformat() if updated_at else None,
    }


_SELECT_RISK = """
    SELECT id, title, description, category, owner, likelihood, impact,
           risk_score, appetite, status, treatment, due_date, frameworks,
           controls, ai_analysis, ai_mapped_controls, created_by, created_at, updated_at
    FROM cy_comp_risks
"""


# ── CRUD ─────────────────────────────────────────────────────────────────────

def list_risks(category: Optional[str] = None, status: Optional[str] = None) -> list[dict]:
    risks = []
    try:
        with db() as conn:
            cur = conn.cursor()
            where, params = [], []
            if category:
                where.append("category = %s"); params.append(category)
            if status:
                where.append("status = %s"); params.append(status)
            clause = ("WHERE " + " AND ".join(where)) if where else ""
            cur.execute(f"{_SELECT_RISK} {clause} ORDER BY risk_score DESC NULLS LAST;", params)
            risks = [_row_to_risk(r) for r in cur.fetchall()]
    except Exception as exc:
        log.error("list_risks: %s", exc)
    return risks


def get_risk(risk_id: str) -> Optional[dict]:
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(f"{_SELECT_RISK} WHERE id = %s;", (risk_id,))
            row = cur.fetchone()
            return _row_to_risk(row) if row else None
    except Exception as exc:
        log.error("get_risk(%s): %s", risk_id, exc)
        return None


def create_risk(data: dict, created_by: str) -> dict:
    likelihood = int(data.get("likelihood", 3))
    impact     = int(data.get("impact", 3))
    rs         = score_risk(likelihood, impact)
    rid        = str(uuid.uuid4())

    with db() as conn:
        cur = conn.cursor()
        import json as _json
        cur.execute(
            """
            INSERT INTO cy_comp_risks
                (id, title, description, category, owner, likelihood, impact,
                 risk_score, appetite, status, treatment, due_date, frameworks,
                 controls, created_by, created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW())
            RETURNING id;
            """,
            (
                rid,
                data.get("title"),
                data.get("description"),
                data.get("category", "IT"),
                data.get("owner"),
                likelihood, impact, rs,
                data.get("appetite", "medium"),
                data.get("status", "open"),
                data.get("treatment", "mitigate"),
                data.get("due_date"),
                _json.dumps(data.get("frameworks", [])),
                _json.dumps(data.get("controls", [])),
                created_by,
            )
        )
    return get_risk(rid)


def update_risk(risk_id: str, data: dict) -> Optional[dict]:
    existing = get_risk(risk_id)
    if not existing:
        return None

    import json as _json
    fields, params = [], []

    for col in ("title", "description", "category", "owner", "appetite",
                "status", "treatment", "due_date"):
        if col in data:
            fields.append(f"{col} = %s"); params.append(data[col])

    for col in ("frameworks", "controls", "ai_mapped_controls"):
        if col in data:
            fields.append(f"{col} = %s"); params.append(_json.dumps(data[col]))

    # Recalculate score if likelihood or impact changed
    likelihood = int(data.get("likelihood", existing["likelihood"] or 3))
    impact     = int(data.get("impact",     existing["impact"]     or 3))
    if "likelihood" in data or "impact" in data:
        fields.append("likelihood = %s"); params.append(likelihood)
        fields.append("impact = %s");     params.append(impact)
        rs = score_risk(likelihood, impact)
        fields.append("risk_score = %s"); params.append(rs)

    if "ai_analysis" in data:
        fields.append("ai_analysis = %s"); params.append(data["ai_analysis"])

    if not fields:
        return existing

    fields.append("updated_at = NOW()")
    params.append(risk_id)

    with db() as conn:
        cur = conn.cursor()
        cur.execute(
            f"UPDATE cy_comp_risks SET {', '.join(fields)} WHERE id = %s;",
            params
        )
    return get_risk(risk_id)


def delete_risk(risk_id: str) -> bool:
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM cy_comp_risks WHERE id = %s;", (risk_id,))
            return cur.rowcount > 0
    except Exception as exc:
        log.error("delete_risk(%s): %s", risk_id, exc)
        return False


def auto_populate_from_findings(created_by: Optional[str] = None) -> dict:
    """
    Create cy_comp_risks entries from open breach/warning findings that have no risk yet.
    Dedup: checks title similarity to avoid exact duplicates.
    Returns {created, skipped}.
    """
    created = 0
    skipped = 0
    SEV_TO_LI = {"critical": (5, 5), "high": (4, 4), "medium": (3, 3), "low": (2, 2)}
    VERDICT_TO_TREATMENT = {"breach": "mitigate", "warning": "mitigate", "compliant": "accept"}

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, framework, control_id, severity, title, description, verdict
                FROM cy_comp_findings
                WHERE status IN ('open','in_progress')
                  AND verdict IN ('breach','warning')
                  AND auto_generated = TRUE
                ORDER BY
                    CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END
                LIMIT 50;
                """
            )
            findings = cur.fetchall()
            for f in findings:
                fid, fw, cid, sev, title, desc, verdict = f
                likelihood, impact = SEV_TO_LI.get(sev, (3, 3))
                risk_score = likelihood * impact

                # Dedup by title prefix
                short = title[:60]
                cur.execute(
                    "SELECT id FROM cy_comp_risks WHERE title LIKE %s LIMIT 1;",
                    (f"{short}%",)
                )
                if cur.fetchone():
                    skipped += 1
                    continue

                rid = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO cy_comp_risks
                        (id, title, description, category, owner, likelihood, impact,
                         risk_score, appetite, status, treatment, frameworks, created_by)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'medium','open',%s,%s,%s);
                    """,
                    (
                        rid,
                        title[:200],
                        (desc or "")[:500] + f"\n\nSource: {fw} finding ({cid})",
                        "IT",
                        created_by or "system",
                        likelihood, impact, risk_score,
                        VERDICT_TO_TREATMENT.get(verdict, "mitigate"),
                        [fw] if fw else [],
                        created_by,
                    )
                )
                created += 1
    except Exception as exc:
        log.error("auto_populate_from_findings: %s", exc)
        raise

    return {"created": created, "skipped": skipped}


# ── Heatmap ───────────────────────────────────────────────────────────────────

def get_heatmap() -> dict:
    """
    Build a 5x5 heatmap grid.
    grid[impact_idx][likelihood_idx] = list of {id, title, score} dicts.
    Indices are 0-based (impact_idx 0 = impact level 1, etc.).
    """
    risks = list_risks(status=None)
    # Exclude closed risks from heatmap
    active = [r for r in risks if r.get("status") != "closed"]

    grid = [[[] for _ in range(5)] for _ in range(5)]
    for r in active:
        li = max(0, min(4, (r.get("likelihood") or 1) - 1))
        im = max(0, min(4, (r.get("impact")     or 1) - 1))
        grid[im][li].append({"id": r["id"], "title": r["title"], "score": r["risk_score"]})

    scores    = [r["risk_score"] or 0 for r in active]
    by_cat    = {}
    for r in active:
        cat = r.get("category") or "Other"
        by_cat[cat] = by_cat.get(cat, 0) + 1

    return {
        "grid": grid,
        "risks": active,
        "summary": {
            "total":    len(active),
            "critical": sum(1 for s in scores if s >= 20),
            "high":     sum(1 for s in scores if 12 <= s < 20),
            "medium":   sum(1 for s in scores if 6  <= s < 12),
            "low":      sum(1 for s in scores if s < 6),
            "by_category": by_cat,
        }
    }


# ── Risk Appetite ─────────────────────────────────────────────────────────────

# Default thresholds (overridden by cy_comp_risk_appetite table rows)
_DEFAULT_THRESHOLDS = {
    "low":    4,
    "medium": 9,
    "high":   19,
}


def get_appetite() -> dict:
    """
    Return appetite thresholds and the list of risks currently exceeding their
    tolerance level.
    """
    import json as _json

    thresholds = dict(_DEFAULT_THRESHOLDS)
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT category, appetite_label, score_threshold FROM cy_comp_risk_appetite;"
            )
            for cat, label, thr in cur.fetchall():
                thresholds[label] = thr
    except Exception as exc:
        log.warning("get_appetite — could not read cy_comp_risk_appetite: %s", exc)

    risks = list_risks(status=None)
    active = [r for r in risks if r.get("status") not in ("closed", "accepted")]

    exceeding = []
    for r in active:
        label     = r.get("appetite") or "medium"
        threshold = thresholds.get(label, thresholds["medium"])
        if (r.get("risk_score") or 0) > threshold:
            exceeding.append(r)

    return {
        "appetite_thresholds":  thresholds,
        "total_risks":          len(active),
        "exceeding_appetite":   len(exceeding),
        "risks_exceeding":      exceeding,
    }


def update_appetite(updates: dict, updated_by: str) -> dict:
    """
    Update appetite thresholds in cy_comp_risk_appetite.
    `updates` = {category_or_label: score_threshold, ...}
    """
    import json as _json

    with db() as conn:
        cur = conn.cursor()
        for label, threshold in updates.items():
            cur.execute(
                """
                INSERT INTO cy_comp_risk_appetite
                    (id, category, appetite_label, score_threshold, updated_by, updated_at)
                VALUES (gen_random_uuid()::TEXT, %s, %s, %s, %s, NOW())
                ON CONFLICT (category, framework)
                DO UPDATE SET score_threshold = EXCLUDED.score_threshold,
                              updated_by = EXCLUDED.updated_by,
                              updated_at = NOW();
                """,
                (label, label, int(threshold), updated_by)
            )
    return get_appetite()
