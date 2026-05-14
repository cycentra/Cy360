"""
cy_comp/services/soa.py
========================
Statement of Applicability (SoA) service for ISO 27001:2022.

Implements ISO 27001 Cl.6.1.3(d): each of the 93 Annex A controls must be
listed with an inclusion decision, justification, and implementation status.

Status derivation (priority order):
  1. excluded      — analyst explicitly marked included=False
  2. breach        — open auto-finding with verdict='breach' for this control
  3. gap           — questionnaire question answered with score=0 (NO/failing)
  4. partial       — questionnaire question answered with score=1 (partial)
  5. compliant     — questionnaire question answered with score>=2 (passing)
  6. not_assessed  — no questionnaire answer yet (default for new deployments)
"""

import logging
from datetime import datetime, timezone

from cy_comp.models import db
from cy_comp.data.annex_a_controls import ANNEX_A_CONTROLS, THEME_ORDER

log = logging.getLogger("cycentra.cy_comp.soa")

FRAMEWORK = "iso27001"


def get_soa() -> dict:
    """
    Return the full SoA for ISO 27001: all 93 controls with derived status,
    analyst include/exclude decision, justification, and covering question link.

    Returns:
        {
          "controls": [...],      # list of 93 control dicts
          "summary": {...},       # theme-level and overall counts
          "generated_at": "..."
        }
    """
    # ── 1. Load questionnaire responses keyed by question_id ─────────────────
    q_responses: dict[str, dict] = {}
    # ── 2. Load auto-findings (breach verdict) keyed by control_id ──────────
    breach_controls: set[str] = set()
    # ── 3. Load analyst SoA entries (include/exclude + justification) ────────
    soa_entries: dict[str, dict] = {}

    try:
        with db() as conn:
            cur = conn.cursor()

            cur.execute(
                """
                SELECT question_id, score, response, notes, responded_by, responded_at
                FROM cy_comp_questionnaire_responses
                WHERE framework = %s;
                """,
                (FRAMEWORK,)
            )
            for row in cur.fetchall():
                q_responses[row[0]] = {
                    "score":        row[1],
                    "response":     row[2],
                    "notes":        row[3],
                    "responded_by": row[4],
                    "responded_at": row[5].isoformat() if row[5] else None,
                }

            cur.execute(
                """
                SELECT control_id
                FROM cy_comp_findings
                WHERE framework = %s AND auto_generated = TRUE
                  AND verdict = 'breach' AND status = 'open';
                """,
                (FRAMEWORK,)
            )
            breach_controls = {r[0] for r in cur.fetchall()}

            cur.execute(
                """
                SELECT control_id, included, justification, updated_by, updated_at
                FROM cy_comp_soa_entries
                WHERE framework = %s;
                """,
                (FRAMEWORK,)
            )
            for row in cur.fetchall():
                soa_entries[row[0]] = {
                    "included":      row[1],
                    "justification": row[2],
                    "updated_by":    row[3],
                    "updated_at":    row[4].isoformat() if row[4] else None,
                }

    except Exception as exc:
        log.error("get_soa: DB error: %s", exc)

    # ── 4. Build per-control dicts ────────────────────────────────────────────
    controls = []
    theme_stats: dict[str, dict] = {
        t: {"total": 0, "compliant": 0, "partial": 0, "gap": 0,
            "not_assessed": 0, "excluded": 0, "breach": 0}
        for t in THEME_ORDER
    }

    for ctrl in ANNEX_A_CONTROLS:
        cid     = ctrl["control_id"]
        theme   = ctrl["theme"]
        qid     = ctrl.get("question_id")
        entry   = soa_entries.get(cid, {})
        included = entry.get("included", True)   # default: included

        # Derive status
        if not included:
            status = "excluded"
        elif cid in breach_controls:
            status = "breach"
        elif qid and qid in q_responses:
            sc = q_responses[qid].get("score")
            if sc is None:
                status = "not_assessed"
            elif sc >= 2:
                status = "compliant"
            elif sc == 1:
                status = "partial"
            else:
                status = "gap"
        else:
            status = "not_assessed"

        q_data = q_responses.get(qid, {}) if qid else {}

        controls.append({
            "control_id":    cid,
            "theme":         theme,
            "section":       ctrl["section"],
            "title":         ctrl["title"],
            "description":   ctrl["description"],
            "question_id":   qid,
            "status":        status,
            "included":      included,
            "justification": entry.get("justification"),
            "updated_by":    entry.get("updated_by"),
            "updated_at":    entry.get("updated_at"),
            "q_score":       q_data.get("score"),
            "q_response":    q_data.get("response"),
            "q_notes":       q_data.get("notes"),
        })

        # Theme counters
        ts = theme_stats[theme]
        ts["total"] += 1
        ts[status if status in ts else "not_assessed"] += 1

    # ── 5. Overall summary ────────────────────────────────────────────────────
    total      = len(controls)
    compliant  = sum(1 for c in controls if c["status"] == "compliant")
    partial    = sum(1 for c in controls if c["status"] == "partial")
    gap        = sum(1 for c in controls if c["status"] == "gap")
    excluded   = sum(1 for c in controls if c["status"] == "excluded")
    breach     = sum(1 for c in controls if c["status"] == "breach")
    assessed   = sum(1 for c in controls if c["status"] not in ("not_assessed", "excluded"))
    coverage_pct = round((assessed / (total - excluded)) * 100, 1) if (total - excluded) > 0 else 0.0

    return {
        "controls":     controls,
        "summary": {
            "total":          total,
            "compliant":      compliant,
            "partial":        partial,
            "gap":            gap + breach,
            "excluded":       excluded,
            "not_assessed":   total - assessed - excluded,
            "coverage_pct":   coverage_pct,
            "by_theme":       theme_stats,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def update_soa_entry(
    control_id: str,
    included: bool,
    justification: str | None,
    updated_by: str,
) -> dict:
    """
    Upsert an analyst SoA decision (include/exclude + justification) for one control.
    Returns the updated entry dict.
    """
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_soa_entries
                    (framework, control_id, included, justification, updated_by, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (framework, control_id) DO UPDATE
                    SET included      = EXCLUDED.included,
                        justification = EXCLUDED.justification,
                        updated_by    = EXCLUDED.updated_by,
                        updated_at    = NOW();
                """,
                (FRAMEWORK, control_id, included, justification, updated_by)
            )
        return {
            "framework":     FRAMEWORK,
            "control_id":    control_id,
            "included":      included,
            "justification": justification,
            "updated_by":    updated_by,
        }
    except Exception as exc:
        log.error("update_soa_entry(%s): %s", control_id, exc)
        raise
