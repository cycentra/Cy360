"""
cy_comp/services/report.py
============================
Report generation service — runs as an APScheduler background job.

NOT called directly by the request handler. The route creates a
cy_comp_report_jobs row and schedules a one-off APScheduler job that calls
generate_report_job(job_id).

Output:
  - JSON report written to /var/log/cycentra/cy-comp/reports/<job_id>.json
  - PDF written to   /var/log/cycentra/cy-comp/reports/<job_id>.pdf (if reportlab available)
  - cy_comp_report_jobs.status updated to 'complete' or 'failed'
  - cy_comp_reports row inserted on success
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cy_comp.models import db
from cy_comp.services.compliance import get_latest_scores

log = logging.getLogger("cycentra.cy_comp.report")

REPORTS_DIR = Path(os.environ.get("COMP_REPORTS_DIR", "/var/log/cycentra/cy-comp/reports"))


def _update_job(job_id: str, status: str, progress: int = 0,
                result_path: str = None, error: str = None) -> None:
    """Update cy_comp_report_jobs row. Never raises."""
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE cy_comp_report_jobs
                SET status=%s, progress=%s, result_path=%s, error=%s, updated_at=NOW()
                WHERE job_id=%s;
                """,
                (status, progress, result_path, error, job_id)
            )
    except Exception as exc:
        log.error("_update_job(%s): %s", job_id, exc)


def _get_job(job_id: str) -> dict:
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT job_id, status, requested_by, framework,
                       period_start, period_end, progress, result_path, error, created_at
                FROM cy_comp_report_jobs WHERE job_id = %s;
                """,
                (job_id,)
            )
            row = cur.fetchone()
            if row:
                return {
                    "job_id":       row[0],
                    "status":       row[1],
                    "requested_by": row[2],
                    "framework":    row[3],
                    "period_start": row[4],
                    "period_end":   row[5],
                    "progress":     row[6],
                    "result_path":  row[7],
                    "error":        row[8],
                    "created_at":   row[9].isoformat() if row[9] else None,
                }
    except Exception as exc:
        log.error("_get_job(%s): %s", job_id, exc)
    return {}


def create_report_job(framework: str, period_start: str, period_end: str,
                      requested_by: str) -> str:
    """
    Insert a pending report job row and return the job_id.
    Called by the route handler before scheduling the APScheduler job.
    """
    job_id = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_report_jobs
                    (job_id, status, requested_by, framework,
                     period_start, period_end, progress, created_at, updated_at)
                VALUES (%s,'pending',%s,%s,%s,%s,0,NOW(),NOW());
                """,
                (job_id, requested_by, framework, period_start, period_end)
            )
    except Exception as exc:
        log.error("create_report_job: %s", exc)
    return job_id


def generate_report_job(job_id: str) -> None:
    """
    Entry point called by APScheduler.
    Generates JSON report (+ PDF if reportlab is available),
    persists result, updates job status.
    """
    log.info("generate_report_job: starting job_id=%s", job_id)
    _update_job(job_id, "running", progress=5)

    try:
        job = _get_job(job_id)
        if not job:
            log.error("generate_report_job: job_id=%s not found", job_id)
            return

        framework = job.get("framework") or "all"
        requested_by = job.get("requested_by")

        # Phase 1 — gather framework scores (30%)
        _update_job(job_id, "running", progress=30)
        from cy_comp.services.compliance import get_latest_scores
        scores = get_latest_scores(
            frameworks=[framework] if framework != "all" else None
        )

        # Phase 2 — gather findings (60%)
        _update_job(job_id, "running", progress=60)
        findings = []
        try:
            with db() as conn:
                cur = conn.cursor()
                q = "SELECT id, framework, control_id, severity, title, status FROM cy_comp_findings"
                params = []
                if framework != "all":
                    q += " WHERE framework = %s"
                    params.append(framework)
                q += " ORDER BY severity, created_at DESC LIMIT 500;"
                cur.execute(q, params)
                for row in cur.fetchall():
                    findings.append({
                        "id": row[0], "framework": row[1], "control_id": row[2],
                        "severity": row[3], "title": row[4], "status": row[5],
                    })
        except Exception as exc:
            log.warning("generate_report_job: findings query: %s", exc)

        # Phase 3 — build report content (80%)
        _update_job(job_id, "running", progress=80)
        report_content = {
            "job_id":          job_id,
            "framework":       framework,
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "generated_by":    requested_by,
            "framework_scores": scores,
            "findings_count":  len(findings),
            "findings":        findings[:100],  # top 100 in JSON
        }

        # Phase 4 — write JSON file
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        json_path = REPORTS_DIR / f"{job_id}.json"
        json_path.write_text(json.dumps(report_content, indent=2, default=str))

        # Phase 5 — write PDF if reportlab available
        pdf_path = None
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet

            pdf_file = REPORTS_DIR / f"{job_id}.pdf"
            doc    = SimpleDocTemplate(str(pdf_file), pagesize=A4)
            styles = getSampleStyleSheet()
            story  = [
                Paragraph(f"CyCentra GRC Compliance Report — {framework.upper()}", styles["Title"]),
                Spacer(1, 12),
                Paragraph(f"Generated: {report_content['generated_at']}", styles["Normal"]),
                Spacer(1, 12),
            ]
            for score in scores:
                story.append(Paragraph(
                    f"{score['framework'].upper()}: {score['score']}% "
                    f"({score['passing']}/{score['total_controls']} controls passing)",
                    styles["Normal"]
                ))
            doc.build(story)
            pdf_path = str(pdf_file)
        except ImportError:
            log.info("generate_report_job: reportlab not installed — JSON only")
        except Exception as exc:
            log.warning("generate_report_job: PDF generation failed: %s", exc)

        # Phase 6 — persist report record and update job
        report_id = str(uuid.uuid4())
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO cy_comp_reports
                        (id, title, framework, overall_score, content_json, pdf_path,
                         generated_by, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,NOW());
                    """,
                    (
                        report_id,
                        f"Compliance Report — {framework.upper()}",
                        framework,
                        scores[0]["score"] if scores else 0.0,
                        json.dumps(report_content),
                        pdf_path,
                        requested_by,
                    )
                )
        except Exception as exc:
            log.warning("generate_report_job: report DB insert: %s", exc)

        _update_job(job_id, "complete", progress=100, result_path=str(json_path))
        log.info("generate_report_job: completed job_id=%s", job_id)

    except Exception as exc:
        log.error("generate_report_job: FATAL job_id=%s: %s", job_id, exc)
        _update_job(job_id, "failed", error=str(exc)[:500])


def poll_job(job_id: str) -> dict:
    """Return the current state of a report job."""
    return _get_job(job_id)
