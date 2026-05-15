"""
cy_comp/services/policy_analysis.py
=====================================
Policy Analysis Pipeline — bridges RAG-indexed policy documents to questionnaire responses.

Flow per framework:
  1. Load all questionnaire templates for the framework
  2. For each question, query org-policies RAG collection for relevant chunks
  3. If chunks found (above confidence threshold), call CyMind LLM to score:
       2 = Pass  (policy explicitly covers the control)
       1 = Partial (partially addressed)
       0 = Fail  (no evidence found)
  4. UPSERT cy_comp_questionnaire_responses with source="policy_rag"
  5. Return job summary: {answered, skipped, errors}

Job lifecycle:  pending → running → complete | failed
Progress tracked in-memory (same pattern as report.py).
Each job runs in a daemon thread — no APScheduler required for short jobs.
"""

import logging
import threading
import time
import uuid
from datetime import datetime, timezone

from cy_comp.services.policy_rag   import query_for_question
from cy_comp.services.ai_analysis  import score_question_from_policy
from cy_comp.services.questionnaire import get_templates, get_responses, save_response

log = logging.getLogger("cycentra.cy_comp.policy_analysis")

# In-memory job store (process-scoped, survives gunicorn worker restarts via sticky sessions)
_jobs: dict[str, dict] = {}
_lock = threading.Lock()

# How long between LLM calls (seconds) — avoids hammering CyMind under load
_CALL_DELAY = 0.25


# ── Job state helpers ─────────────────────────────────────────────────────────

def _set(job_id: str, **kwargs) -> None:
    with _lock:
        if job_id not in _jobs:
            _jobs[job_id] = {}
        _jobs[job_id].update(kwargs)


def get_job(job_id: str) -> dict | None:
    with _lock:
        return dict(_jobs[job_id]) if job_id in _jobs else None


# ── Public API ────────────────────────────────────────────────────────────────

def start_analysis_job(framework: str, overwrite: bool, user_email: str) -> str:
    """
    Kick off a background policy analysis job.
    Returns job_id immediately; caller polls GET /analyze-jobs/{job_id}.
    """
    job_id = str(uuid.uuid4())[:8]
    _set(job_id,
         job_id=job_id, framework=framework, overwrite=overwrite,
         status="pending", progress=0, total=0,
         answered=0, skipped=0, errors=0,
         message="Queued",
         started_at=datetime.now(timezone.utc).isoformat(),
    )
    t = threading.Thread(
        target=_run, args=(job_id, framework, overwrite, user_email), daemon=True
    )
    t.start()
    return job_id


# ── Background worker ─────────────────────────────────────────────────────────

def _run(job_id: str, framework: str, overwrite: bool, user_email: str) -> None:
    try:
        _set(job_id, status="running", message="Loading questionnaire templates…")

        templates = get_templates(framework)
        if not templates:
            _set(job_id, status="failed",
                 message=f"No questionnaire templates found for '{framework}'. "
                         "Run Seed Templates first.")
            return

        # Load existing responses so we can skip already-answered questions
        existing = {} if overwrite else get_responses(framework)

        total = len(templates)
        _set(job_id, total=total, progress=0,
             message=f"Analysing {total} controls against uploaded policy documents…")

        answered = skipped = errors = 0

        for idx, tmpl in enumerate(templates):
            qid         = tmpl["question_id"]
            question    = tmpl["question"]
            control_ref = tmpl.get("control_ref") or qid
            progress    = round(((idx + 1) / total) * 100)

            # Skip if already answered and overwrite=False
            if not overwrite and qid in existing:
                existing_score = existing[qid].get("score")
                if existing_score is not None:
                    skipped += 1
                    _set(job_id, progress=progress, skipped=skipped,
                         message=f"[{idx+1}/{total}] {qid} — skipped (already answered)")
                    continue

            try:
                # 1. RAG: find relevant policy chunks
                chunks = query_for_question(question, top_k=5)

                if not chunks:
                    # No relevant policy content — record as unanswered, don't write a zero
                    skipped += 1
                    _set(job_id, progress=progress, skipped=skipped,
                         message=f"[{idx+1}/{total}] {qid} — no policy evidence found")
                    time.sleep(_CALL_DELAY)
                    continue

                # 2. LLM: score question against chunks
                result    = score_question_from_policy(question, control_ref, framework, chunks)
                score     = result["score"]
                justif    = result["justification"]
                evidence  = result["evidence_snippet"]

                # Map numeric score → human-readable response string
                response_str = {2: "yes", 1: "partial", 0: "no"}.get(score, "no")

                notes = f"[Policy Analysis — auto-scored {score}/2]\n{justif}"
                if evidence:
                    notes += f'\n\nPolicy evidence: "{evidence}"'

                # 3. Save to questionnaire responses
                save_response(
                    framework=framework,
                    question_id=qid,
                    response=response_str,
                    notes=notes,
                    evidence_refs=["policy_rag"],
                    responded_by=f"policy_analysis:{user_email}",
                )
                answered += 1

            except Exception as exc:
                log.error("policy_analysis[%s] %s: %s", framework, qid, exc)
                errors += 1

            _set(job_id, progress=progress, answered=answered,
                 skipped=skipped, errors=errors,
                 message=f"[{idx+1}/{total}] {qid} — score {result.get('score', '?') if 'result' in dir() else 'err'}/2")

            time.sleep(_CALL_DELAY)

        _set(job_id,
             status="complete", progress=100,
             answered=answered, skipped=skipped, errors=errors,
             message=(
                 f"Analysis complete — {answered} questions answered from policy, "
                 f"{skipped} skipped (no evidence or already answered), "
                 f"{errors} errors."
             ),
             finished_at=datetime.now(timezone.utc).isoformat(),
        )
        log.info("policy_analysis[%s] job %s: %d answered / %d skipped / %d errors",
                 framework, job_id, answered, skipped, errors)

    except Exception as exc:
        log.error("policy_analysis job %s crashed: %s", job_id, exc)
        _set(job_id, status="failed", message=str(exc))
