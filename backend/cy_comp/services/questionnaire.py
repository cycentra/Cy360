"""
cy_comp/services/questionnaire.py
===================================
Questionnaire assessment engine.

Responsibilities:
  - seed_templates()       : populate cy_comp_questionnaire_templates from questionnaires.py data
  - get_templates(fw)      : fetch questions for a framework
  - get_responses(fw)      : fetch saved answers for a framework
  - save_response(...)     : upsert a single answer
  - save_bulk_responses()  : upsert many answers at once
  - score_framework(fw)    : compute numeric score + gap list from saved answers
  - get_completion(fw)     : fraction answered / total for progress display
  - generate_gap_findings(): create cy_comp_findings rows for unanswered/failing questions
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.questionnaire")


# ── Seed ──────────────────────────────────────────────────────────────────────

def seed_templates(force: bool = False) -> dict:
    """
    Populate cy_comp_questionnaire_templates from the embedded questionnaire data.
    Safe to call at startup — skips existing question_ids unless force=True.
    Returns {inserted, skipped, framework_counts}.
    """
    from cy_comp.data.questionnaires import ALL_QUESTIONNAIRES
    inserted = 0
    skipped  = 0
    fw_counts: dict[str, int] = {}

    try:
        with db() as conn:
            cur = conn.cursor()
            for framework, questions in ALL_QUESTIONNAIRES.items():
                count = 0
                for q in questions:
                    if force:
                        cur.execute(
                            """
                            INSERT INTO cy_comp_questionnaire_templates
                                (framework, section, question_id, question, guidance,
                                 control_ref, weight, question_type, options, order_idx)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (question_id) DO UPDATE SET
                                question     = EXCLUDED.question,
                                guidance     = EXCLUDED.guidance,
                                control_ref  = EXCLUDED.control_ref,
                                weight       = EXCLUDED.weight,
                                question_type= EXCLUDED.question_type,
                                options      = EXCLUDED.options,
                                order_idx    = EXCLUDED.order_idx;
                            """,
                            (
                                framework,
                                q.get("section", "General"),
                                q["qid"],
                                q["question"],
                                q.get("guidance"),
                                q.get("control_ref"),
                                q.get("weight", 2),
                                q.get("question_type", "yes_no"),
                                json.dumps(q.get("options", [])),
                                q.get("order_idx", 0),
                            )
                        )
                        inserted += 1
                        count += 1
                    else:
                        cur.execute(
                            "SELECT 1 FROM cy_comp_questionnaire_templates WHERE question_id = %s;",
                            (q["qid"],)
                        )
                        if cur.fetchone():
                            skipped += 1
                        else:
                            cur.execute(
                                """
                                INSERT INTO cy_comp_questionnaire_templates
                                    (framework, section, question_id, question, guidance,
                                     control_ref, weight, question_type, options, order_idx)
                                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);
                                """,
                                (
                                    framework,
                                    q.get("section", "General"),
                                    q["qid"],
                                    q["question"],
                                    q.get("guidance"),
                                    q.get("control_ref"),
                                    q.get("weight", 2),
                                    q.get("question_type", "yes_no"),
                                    json.dumps(q.get("options", [])),
                                    q.get("order_idx", 0),
                                )
                            )
                            inserted += 1
                            count += 1
                fw_counts[framework] = count
        log.info("questionnaire seed: inserted=%d skipped=%d", inserted, skipped)
    except Exception as exc:
        log.error("seed_templates: %s", exc)
        raise

    return {"inserted": inserted, "skipped": skipped, "framework_counts": fw_counts}


# ── Read ──────────────────────────────────────────────────────────────────────

def get_templates(framework: str) -> list[dict]:
    """Return ordered list of questions for a framework."""
    rows = []
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT question_id, section, question, guidance, control_ref,
                       weight, question_type, options, order_idx
                FROM cy_comp_questionnaire_templates
                WHERE framework = %s
                ORDER BY order_idx, question_id;
                """,
                (framework,)
            )
            for r in cur.fetchall():
                rows.append({
                    "question_id":   r[0],
                    "section":       r[1],
                    "question":      r[2],
                    "guidance":      r[3],
                    "control_ref":   r[4],
                    "weight":        r[5],
                    "question_type": r[6],
                    "options":       r[7] if isinstance(r[7], list) else [],
                    "order_idx":     r[8],
                })
    except Exception as exc:
        log.error("get_templates(%s): %s", framework, exc)
    return rows


def get_responses(framework: str) -> dict[str, dict]:
    """Return saved responses keyed by question_id."""
    out: dict[str, dict] = {}
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT question_id, response, score, notes, evidence_refs,
                       responded_by, responded_at, reviewed_by, reviewed_at
                FROM cy_comp_questionnaire_responses
                WHERE framework = %s;
                """,
                (framework,)
            )
            for r in cur.fetchall():
                out[r[0]] = {
                    "question_id":  r[0],
                    "response":     r[1],
                    "score":        r[2],
                    "notes":        r[3],
                    "evidence_refs": r[4] if isinstance(r[4], list) else [],
                    "responded_by": r[5],
                    "responded_at": r[6].isoformat() if r[6] else None,
                    "reviewed_by":  r[7],
                    "reviewed_at":  r[8].isoformat() if r[8] else None,
                }
    except Exception as exc:
        log.error("get_responses(%s): %s", framework, exc)
    return out


# ── Write ─────────────────────────────────────────────────────────────────────

def _auto_score(response: str, question_type: str) -> int:
    """Derive a numeric score from a raw response string."""
    if question_type == "yes_no":
        return 2 if str(response).lower() in ("yes", "true", "1") else 0
    if question_type == "score_1_5":
        try:
            v = int(response)
            return 2 if v >= 4 else (1 if v == 3 else 0)
        except (ValueError, TypeError):
            return 0
    return 1  # text / multi_choice: neutral until reviewed


def save_response(
    framework: str,
    question_id: str,
    response: str,
    notes: Optional[str] = None,
    evidence_refs: Optional[list] = None,
    responded_by: Optional[str] = None,
) -> dict:
    """Upsert a single questionnaire answer. Returns the saved record."""
    # Lookup question_type for auto-scoring
    question_type = "yes_no"
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT question_type FROM cy_comp_questionnaire_templates WHERE question_id = %s;",
                (question_id,)
            )
            row = cur.fetchone()
            if row:
                question_type = row[0]
    except Exception:
        pass

    score = _auto_score(response, question_type)

    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_questionnaire_responses
                    (framework, question_id, response, score, notes, evidence_refs, responded_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (framework, question_id) DO UPDATE SET
                    response     = EXCLUDED.response,
                    score        = EXCLUDED.score,
                    notes        = EXCLUDED.notes,
                    evidence_refs= EXCLUDED.evidence_refs,
                    responded_by = EXCLUDED.responded_by,
                    responded_at = NOW();
                """,
                (
                    framework, question_id, response, score,
                    notes, json.dumps(evidence_refs or []), responded_by,
                )
            )
    except Exception as exc:
        log.error("save_response: %s", exc)
        raise

    return {
        "framework": framework, "question_id": question_id,
        "response": response, "score": score, "notes": notes,
    }


def save_bulk_responses(
    framework: str,
    answers: list[dict],
    responded_by: Optional[str] = None,
) -> dict:
    """
    Bulk-upsert answers.
    Each answer: {question_id, response, notes?, evidence_refs?}
    Returns {saved, errors}.
    """
    saved  = 0
    errors = 0
    for ans in answers:
        try:
            save_response(
                framework=framework,
                question_id=ans["question_id"],
                response=ans.get("response", ""),
                notes=ans.get("notes"),
                evidence_refs=ans.get("evidence_refs"),
                responded_by=responded_by,
            )
            saved += 1
        except Exception as exc:
            log.warning("bulk save error qid=%s: %s", ans.get("question_id"), exc)
            errors += 1
    return {"saved": saved, "errors": errors}


# ── Scoring ───────────────────────────────────────────────────────────────────

def score_framework(framework: str) -> dict:
    """
    Compute assessment score for a framework from saved responses.

    Returns:
        score         : 0–100 weighted score
        total         : total question count
        answered      : questions with a saved response
        passing       : score >= 2 (weighted)
        gaps          : question_ids where response = NO / score = 0
        partial       : question_ids where score = 1
    """
    templates  = get_templates(framework)
    responses  = get_responses(framework)

    if not templates:
        return {"score": 0, "total": 0, "answered": 0, "passing": 0, "gaps": [], "partial": []}

    total_weight = 0
    earned_weight = 0
    gaps: list[dict] = []
    partial: list[dict] = []
    answered = 0

    for t in templates:
        qid    = t["question_id"]
        weight = t.get("weight", 2)
        total_weight += weight
        resp = responses.get(qid)

        if not resp:
            gaps.append({"question_id": qid, "section": t["section"], "question": t["question"],
                          "control_ref": t["control_ref"], "weight": weight})
            continue

        answered += 1
        sc = resp.get("score", 0) or 0

        if sc >= 2:
            earned_weight += weight
        elif sc == 1:
            earned_weight += weight * 0.5
            partial.append({"question_id": qid, "section": t["section"],
                             "question": t["question"], "control_ref": t["control_ref"],
                             "response": resp.get("response"), "weight": weight})
        else:
            gaps.append({"question_id": qid, "section": t["section"],
                          "question": t["question"], "control_ref": t["control_ref"],
                          "response": resp.get("response"), "weight": weight})

    score = round((earned_weight / total_weight * 100) if total_weight > 0 else 0, 1)
    return {
        "framework": framework,
        "score":     score,
        "total":     len(templates),
        "answered":  answered,
        "passing":   len(templates) - len(gaps) - len(partial),
        "gaps":      gaps,
        "partial":   partial,
    }


def get_completion(framework: str) -> dict:
    """Lightweight progress check — fraction answered / total."""
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM cy_comp_questionnaire_templates WHERE framework = %s;",
                (framework,)
            )
            total = (cur.fetchone() or [0])[0]
            cur.execute(
                "SELECT COUNT(*) FROM cy_comp_questionnaire_responses WHERE framework = %s;",
                (framework,)
            )
            answered = (cur.fetchone() or [0])[0]
        pct = round((answered / total * 100) if total > 0 else 0, 1)
        return {"framework": framework, "total": total, "answered": answered, "pct": pct}
    except Exception as exc:
        log.error("get_completion(%s): %s", framework, exc)
        return {"framework": framework, "total": 0, "answered": 0, "pct": 0}


def get_all_completions() -> list[dict]:
    """Completion stats for all frameworks — used by the hub page."""
    from cy_comp.data.questionnaires import ALL_QUESTIONNAIRES, FRAMEWORK_META
    results = []
    for fw in ALL_QUESTIONNAIRES:
        c = get_completion(fw)
        s = score_framework(fw)
        meta = FRAMEWORK_META.get(fw, {})
        results.append({
            "framework":   fw,
            "label":       meta.get("label", fw.upper()),
            "color":       meta.get("color", "#6378ff"),
            "total":       c["total"],
            "answered":    c["answered"],
            "pct":         c["pct"],
            "score":       s["score"],
            "gap_count":   len(s["gaps"]),
            "partial_count": len(s["partial"]),
        })
    return results


# ── Gap → Findings ────────────────────────────────────────────────────────────

def generate_gap_findings(framework: str, created_by: Optional[str] = None) -> dict:
    """
    Create cy_comp_findings rows for questions where response is NO / score=0.
    Idempotent: uses questionnaire_gap=TRUE + control_ref as dedup key.
    Returns {created, skipped}.
    """
    scored = score_framework(framework)
    gaps   = scored["gaps"]
    created = 0
    skipped = 0

    try:
        with db() as conn:
            cur = conn.cursor()
            for gap in gaps:
                # Skip if a questionnaire-gap finding already exists for this control
                control_ref = gap.get("control_ref") or gap["question_id"]
                cur.execute(
                    """
                    SELECT id FROM cy_comp_findings
                    WHERE framework = %s AND control_id = %s AND questionnaire_gap = TRUE
                    LIMIT 1;
                    """,
                    (framework, control_ref)
                )
                if cur.fetchone():
                    skipped += 1
                    continue

                severity = "high" if gap.get("weight", 2) >= 3 else "medium"
                cur.execute(
                    """
                    INSERT INTO cy_comp_findings
                        (framework, control_id, control_name, severity, title, description,
                         status, source_type, auto_generated, questionnaire_gap,
                         verdict, created_by)
                    VALUES (%s,%s,%s,%s,%s,%s,'open','questionnaire',TRUE,TRUE,'warning',%s);
                    """,
                    (
                        framework,
                        control_ref,
                        gap.get("section", ""),
                        severity,
                        f"Gap: {gap['question'][:120]}",
                        f"Questionnaire assessment identified a gap: {gap['question']}\n"
                        f"Control reference: {control_ref}\n"
                        f"Section: {gap.get('section', 'N/A')}",
                        created_by,
                    )
                )
                created += 1
    except Exception as exc:
        log.error("generate_gap_findings(%s): %s", framework, exc)
        raise

    return {"framework": framework, "created": created, "skipped": skipped}
