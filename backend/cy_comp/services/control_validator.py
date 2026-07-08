"""
cy_comp/services/control_validator.py
==========================================
Technical Control Validation Engine — runs 10 automated validators against live
system data without requiring manual questionnaire input.

Validators are read-only — they query existing tables (alerts, incidents, cases,
cy_comp_exposure, cy_comp_questionnaire_*) and write ONLY to
cy_comp_control_validations. Critical failures auto-generate cy_comp_findings.

Registration pattern: decorate a function with @_validator(...) and it is
automatically included in VALIDATORS list.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

from cy_comp.models import db

log = logging.getLogger("cycentra.cy_comp.control_validator")

# Registry populated by @_validator decorator
VALIDATORS: list[dict] = []


def _validator(vid: str, title: str, category: str, frameworks: list[str]):
    """Decorator that registers a check function into VALIDATORS."""
    def decorator(fn):
        VALIDATORS.append({
            "id":        vid,
            "title":     title,
            "category":  category,
            "frameworks": frameworks,
            "check":     fn,
        })
        return fn
    return decorator


# ── Validator Implementations ────────────────────────────────────────────────

@_validator(
    "cv-vuln-01", "Critical Vulnerability Currency", "vulnerability_management",
    ["nis2", "iso27001", "nist_csf", "pci_dss"],
)
def _check_vuln_currency(cur):
    try:
        cur.execute(
            """
            SELECT COUNT(*) FROM cy_comp_exposure
            WHERE severity = 'critical' AND status = 'open'
              AND created_at < NOW() - INTERVAL '30 days';
            """
        )
        overdue = int(cur.fetchone()[0] or 0)
        cur.execute(
            "SELECT COUNT(*) FROM cy_comp_exposure WHERE severity IN ('critical','high') AND status = 'open';"
        )
        total_open = int(cur.fetchone()[0] or 0)

        if overdue == 0 and total_open == 0:
            return {"status": "pass", "score": 100,
                    "detail": "No critical/high vulnerabilities open",
                    "evidence": {"open_critical": 0}}
        if overdue > 0:
            return {"status": "fail", "score": max(0, 100 - overdue * 15),
                    "detail": f"{overdue} critical vulnerabilities open >30 days (SLA breach)",
                    "evidence": {"overdue_critical": overdue, "open_total": total_open}}
        return {"status": "warning", "score": 70,
                "detail": f"{total_open} critical/high vulnerabilities open (within SLA)",
                "evidence": {"open_total": total_open}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-siem-01", "SIEM Monitoring Coverage", "monitoring",
    ["nis2", "dora", "iso27001", "soc2", "nist_csf"],
)
def _check_siem_coverage(cur):
    try:
        cur.execute(
            """
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS recent,
                   COUNT(DISTINCT agent_name) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS agents
            FROM alerts;
            """
        )
        row = cur.fetchone() or (0, 0, 0)
        total, recent, agents = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)

        if total == 0:
            return {"status": "warning", "score": 40,
                    "detail": "No SIEM alerts in database — SIEM connectivity may be broken",
                    "evidence": {"total_alerts": 0}}
        if recent == 0:
            return {"status": "fail", "score": 20,
                    "detail": "No SIEM alerts in last 24 hours — possible agent outage",
                    "evidence": {"total_alerts": total, "recent_24h": 0}}
        return {"status": "pass", "score": 90,
                "detail": f"{agents} agents active, {recent} alerts in last 24 h",
                "evidence": {"active_agents": agents, "recent_24h": recent}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-ir-01", "Incident Response Practice", "incident_management",
    ["nis2", "dora", "iso27001", "soc2", "nist_csf"],
)
def _check_incident_response(cur):
    try:
        cur.execute(
            """
            SELECT COUNT(*) FROM cases
            WHERE status = 'resolved' AND resolved_at > NOW() - INTERVAL '90 days';
            """
        )
        resolved = int(cur.fetchone()[0] or 0)
        cur.execute("SELECT COUNT(*) FROM cases WHERE status IN ('open','in_progress');")
        open_cases = int(cur.fetchone()[0] or 0)

        if resolved >= 5:
            return {"status": "pass", "score": 95,
                    "detail": f"{resolved} cases resolved in last 90 days — IR process evidenced",
                    "evidence": {"resolved_90d": resolved, "open": open_cases}}
        if resolved > 0:
            return {"status": "warning", "score": 65,
                    "detail": f"Only {resolved} cases resolved in 90 days — limited IR evidence",
                    "evidence": {"resolved_90d": resolved, "open": open_cases}}
        return {"status": "warning", "score": 35,
                "detail": "No resolved cases in 90 days — IR practice not evidenced in system",
                "evidence": {"resolved_90d": 0, "open": open_cases}}
    except Exception as exc:
        # cases table may not exist on all deployments
        return {"status": "unknown", "score": None,
                "detail": "Incident case data unavailable",
                "evidence": {}}


@_validator(
    "cv-sc-01", "Supply Chain Risk Management", "supply_chain",
    ["nis2", "dora", "iso27001", "nist_csf"],
)
def _check_supply_chain(cur):
    try:
        cur.execute(
            """
            SELECT COUNT(*),
                   COUNT(*) FILTER (WHERE status = 'open'),
                   COUNT(*) FILTER (WHERE severity = 'critical' AND status = 'open')
            FROM cy_comp_exposure WHERE exposure_type = 'supply_chain';
            """
        )
        row = cur.fetchone() or (0, 0, 0)
        total, open_count, crit_open = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)

        if total == 0:
            return {"status": "warning", "score": 50,
                    "detail": "No supply chain risk data — import ASM scan to populate",
                    "evidence": {"supply_chain_items": 0}}
        if crit_open > 0:
            return {"status": "fail", "score": max(0, 60 - crit_open * 10),
                    "detail": f"{crit_open} critical supply chain risks unresolved",
                    "evidence": {"total": total, "open": open_count, "critical_open": crit_open}}
        if open_count > 0:
            return {"status": "warning", "score": 75,
                    "detail": f"{open_count} supply chain items require remediation",
                    "evidence": {"total": total, "open": open_count}}
        return {"status": "pass", "score": 100,
                "detail": f"All {total} supply chain risks addressed",
                "evidence": {"total": total, "open": 0}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-log-01", "Log Retention Continuity", "logging_monitoring",
    ["dora", "iso27001", "soc2", "pci_dss"],
)
def _check_log_retention(cur):
    try:
        cur.execute(
            """
            SELECT MIN(timestamp), MAX(timestamp),
                   EXTRACT(DAY FROM MAX(timestamp) - MIN(timestamp)) AS span_days,
                   COUNT(*)
            FROM alerts WHERE timestamp IS NOT NULL;
            """
        )
        row = cur.fetchone()
        if not row or not row[0]:
            return {"status": "warning", "score": 30,
                    "detail": "No timestamped alerts — log retention cannot be verified",
                    "evidence": {}}
        span = float(row[2] or 0)
        total = int(row[3] or 0)

        if span >= 90:
            return {"status": "pass", "score": 100,
                    "detail": f"Alert data spans {span:.0f} days — strong log retention",
                    "evidence": {"span_days": span, "total_alerts": total}}
        if span >= 30:
            return {"status": "pass", "score": 78,
                    "detail": f"Alert data spans {span:.0f} days (minimum met)",
                    "evidence": {"span_days": span, "total_alerts": total}}
        return {"status": "warning", "score": 45,
                "detail": f"Alert data spans only {span:.0f} days — retention below 30-day minimum",
                "evidence": {"span_days": span, "total_alerts": total}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-ai-01", "Shadow AI Governance", "ai_governance",
    ["eu_ai_act", "iso42001"],
)
def _check_shadow_ai(cur):
    try:
        cur.execute(
            "SELECT COUNT(*) FROM itam_shadow_ai_findings WHERE status = 'open';"
        )
        open_shadow = int(cur.fetchone()[0] or 0)
        if open_shadow == 0:
            return {"status": "pass", "score": 90,
                    "detail": "No unresolved shadow AI detections",
                    "evidence": {"open_shadow_ai": 0}}
        return {"status": "warning", "score": max(30, 80 - open_shadow * 5),
                "detail": f"{open_shadow} unresolved shadow AI tools detected",
                "evidence": {"open_shadow_ai": open_shadow}}
    except Exception:
        return {"status": "unknown", "score": None,
                "detail": "Shadow AI data unavailable (ITAM Shadow AI module may not be enabled)",
                "evidence": {}}


@_validator(
    "cv-patch-01", "Patch Management Currency", "vulnerability_management",
    ["nis2", "iso27001", "pci_dss", "nist_csf"],
)
def _check_patch_management(cur):
    try:
        cur.execute(
            """
            SELECT COUNT(*) FROM cy_comp_exposure
            WHERE exposure_type = 'vulnerability'
              AND severity IN ('critical','high')
              AND status = 'open'
              AND created_at < NOW() - INTERVAL '30 days';
            """
        )
        overdue = int(cur.fetchone()[0] or 0)
        cur.execute(
            "SELECT COUNT(*) FROM cy_comp_exposure WHERE exposure_type = 'vulnerability' AND status = 'open';"
        )
        open_vulns = int(cur.fetchone()[0] or 0)

        if overdue == 0 and open_vulns == 0:
            return {"status": "pass", "score": 100,
                    "detail": "No overdue vulnerability exposures",
                    "evidence": {"open_vulns": 0}}
        if overdue > 0:
            return {"status": "fail", "score": max(0, 100 - overdue * 10),
                    "detail": f"{overdue} high/critical vulns unpatched >30 days",
                    "evidence": {"overdue": overdue, "open_total": open_vulns}}
        return {"status": "warning", "score": 75,
                "detail": f"{open_vulns} vulnerabilities open (within patch SLA)",
                "evidence": {"open_vulns": open_vulns}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-backup-01", "Backup & Recovery Controls", "resilience",
    ["dora", "iso27001", "soc2", "nist_csf"],
)
def _check_backup_controls(cur):
    try:
        cur.execute(
            """
            SELECT COALESCE(SUM(t.weight), 0),
                   COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2), 0),
                   COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1), 0),
                   COUNT(t.question_id)
            FROM cy_comp_questionnaire_templates t
            LEFT JOIN cy_comp_questionnaire_responses r
                   ON r.question_id = t.question_id AND r.framework = t.framework
            WHERE t.section ILIKE '%bcp%' OR t.section ILIKE '%continuity%'
               OR t.section ILIKE '%backup%' OR t.section ILIKE '%recovery%'
               OR t.section ILIKE '%availability%';
            """
        )
        row = cur.fetchone() or (0, 0, 0, 0)
        tw, pw, pw2, total_q = float(row[0] or 0), float(row[1] or 0), float(row[2] or 0), int(row[3] or 0)

        if tw == 0:
            return {"status": "unknown", "score": None,
                    "detail": "No backup/BCP questionnaire data available",
                    "evidence": {"questions": 0}}
        score = round((pw + pw2 * 0.5) / tw * 100, 1)
        status = "pass" if score >= 80 else "warning" if score >= 50 else "fail"
        return {"status": status, "score": score,
                "detail": f"Backup/recovery controls: {score:.1f}% ({total_q} questions)",
                "evidence": {"q_score": score, "questions": total_q}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-access-01", "Access Control & IAM", "access_management",
    ["nis2", "iso27001", "soc2", "pci_dss"],
)
def _check_access_management(cur):
    try:
        cur.execute(
            """
            SELECT COALESCE(SUM(t.weight), 0),
                   COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2), 0),
                   COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1), 0),
                   COUNT(t.question_id)
            FROM cy_comp_questionnaire_templates t
            LEFT JOIN cy_comp_questionnaire_responses r
                   ON r.question_id = t.question_id AND r.framework = t.framework
            WHERE t.section ILIKE '%access%' OR t.section ILIKE '%identity%'
               OR t.section ILIKE '%iam%'    OR t.section ILIKE '%authentication%'
               OR t.section ILIKE '%privilege%';
            """
        )
        row = cur.fetchone() or (0, 0, 0, 0)
        tw, pw, pw2, total_q = float(row[0] or 0), float(row[1] or 0), float(row[2] or 0), int(row[3] or 0)

        if tw == 0:
            return {"status": "unknown", "score": None,
                    "detail": "No access management questionnaire data",
                    "evidence": {"questions": 0}}
        score = round((pw + pw2 * 0.5) / tw * 100, 1)
        status = "pass" if score >= 80 else "warning" if score >= 50 else "fail"
        return {"status": status, "score": score,
                "detail": f"Access management controls: {score:.1f}% ({total_q} questions)",
                "evidence": {"q_score": score, "questions": total_q}}
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


@_validator(
    "cv-comp-01", "Assessment Completion Rate", "compliance_assessment",
    ["nis2", "dora", "iso27001", "soc2", "nist_csf", "pci_dss", "gdpr", "eu_ai_act", "iso42001"],
)
def _check_questionnaire_completion(cur):
    try:
        cur.execute(
            """
            SELECT COUNT(t.question_id)                                        AS total,
                   COUNT(r.question_id)                                        AS answered,
                   COUNT(r.question_id) FILTER (WHERE r.score >= 2)            AS passed
            FROM cy_comp_questionnaire_templates t
            LEFT JOIN cy_comp_questionnaire_responses r
                   ON r.question_id = t.question_id AND r.framework = t.framework;
            """
        )
        row = cur.fetchone() or (0, 0, 0)
        total, answered, passed = int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)

        if total == 0:
            return {"status": "unknown", "score": None,
                    "detail": "Questionnaire templates not seeded — call POST /api/comp/questionnaire/seed",
                    "evidence": {}}
        pct = round(answered / total * 100, 1)
        status = "pass" if pct >= 80 else "warning" if pct >= 40 else "fail"
        return {
            "status": status, "score": pct,
            "detail": f"{pct:.1f}% of assessment questions answered ({answered}/{total})",
            "evidence": {"total": total, "answered": answered, "passed": passed},
        }
    except Exception as exc:
        return {"status": "unknown", "score": None, "detail": str(exc), "evidence": {}}


# ── Runner ────────────────────────────────────────────────────────────────────

def run_all_validators(auto_finding: bool = True) -> dict:
    """
    Execute all registered validators, write results to cy_comp_control_validations,
    and optionally create cy_comp_findings for critical failures.

    Returns a summary dict with run_id, counts (pass/fail/warning/unknown), and results list.
    """
    results: list[dict] = []
    pass_c = fail_c = warn_c = unk_c = 0
    run_id = str(uuid.uuid4())
    run_at = datetime.now(timezone.utc)

    try:
        with db() as conn:
            cur = conn.cursor()
            for v in VALIDATORS:
                try:
                    result = v["check"](cur)
                except Exception as exc:
                    result = {"status": "unknown", "score": None,
                              "detail": f"Validator error: {exc}", "evidence": {}}

                status   = result.get("status", "unknown")
                score    = result.get("score")
                detail   = result.get("detail", "")
                evidence = result.get("evidence", {})

                if status == "pass":    pass_c += 1
                elif status == "fail":  fail_c += 1
                elif status == "warning": warn_c += 1
                else:                   unk_c += 1

                try:
                    cur.execute(
                        """
                        INSERT INTO cy_comp_control_validations
                            (id, run_id, validator_id, title, category, frameworks,
                             status, score, detail, evidence_json, validated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (validator_id) DO UPDATE SET
                            run_id        = EXCLUDED.run_id,
                            status        = EXCLUDED.status,
                            score         = EXCLUDED.score,
                            detail        = EXCLUDED.detail,
                            evidence_json = EXCLUDED.evidence_json,
                            validated_at  = EXCLUDED.validated_at;
                        """,
                        (
                            str(uuid.uuid4()), run_id,
                            v["id"], v["title"], v["category"], v["frameworks"],
                            status, score, detail,
                            json.dumps(evidence),
                            run_at,
                        ),
                    )
                except Exception as db_exc:
                    log.warning("control_validator: DB write skipped for %s: %s", v["id"], db_exc)

                if auto_finding and status == "fail" and score is not None and score < 60:
                    try:
                        _auto_finding(cur, v, detail)
                    except Exception as f_exc:
                        log.warning("control_validator: auto_finding failed for %s: %s", v["id"], f_exc)

                results.append({
                    "validator_id": v["id"],
                    "title":        v["title"],
                    "category":     v["category"],
                    "frameworks":   v["frameworks"],
                    "status":       status,
                    "score":        score,
                    "detail":       detail,
                })
    except Exception as exc:
        log.error("run_all_validators: %s", exc)
        return {"error": str(exc), "run_id": run_id}

    log.info("control_validator run %s: pass=%d fail=%d warning=%d unknown=%d",
             run_id[:8], pass_c, fail_c, warn_c, unk_c)

    return {
        "run_id":       run_id,
        "validated_at": run_at.isoformat(),
        "total":        len(VALIDATORS),
        "pass":         pass_c,
        "fail":         fail_c,
        "warning":      warn_c,
        "unknown":      unk_c,
        "results":      results,
    }


def _auto_finding(cur, validator: dict, detail: str) -> None:
    """Create a finding for a FAIL validator — idempotent (skips if open finding exists)."""
    fw = validator["frameworks"][0] if validator["frameworks"] else "nis2"
    cur.execute(
        """
        SELECT id FROM cy_comp_findings
        WHERE control_id = %s AND framework = %s
          AND auto_generated = TRUE AND status IN ('open','in_progress')
        LIMIT 1;
        """,
        (validator["id"], fw),
    )
    if cur.fetchone():
        return
    cur.execute(
        """
        INSERT INTO cy_comp_findings
            (id, framework, control_id, control_name, severity, title, description,
             source_type, auto_generated, status, verdict, created_at, updated_at)
        VALUES (%s,%s,%s,%s,'high',%s,%s,'auto_validator',TRUE,'open','open',NOW(),NOW());
        """,
        (
            str(uuid.uuid4()), fw, validator["id"], validator["title"],
            f"Control Validation Failure: {validator['title']}",
            detail,
        ),
    )


def get_validation_summary() -> list[dict]:
    """Return latest result per validator, ordered by severity (fail first)."""
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT validator_id, title, category, frameworks,
                       status, score, detail, evidence_json, validated_at
                FROM cy_comp_control_validations
                ORDER BY
                    CASE status WHEN 'fail' THEN 0 WHEN 'warning' THEN 1
                                WHEN 'unknown' THEN 2 ELSE 3 END,
                    score ASC NULLS LAST;
                """
            )
            rows = cur.fetchall()
            return [
                {
                    "validator_id": r[0],
                    "title":        r[1],
                    "category":     r[2],
                    "frameworks":   r[3] or [],
                    "status":       r[4],
                    "score":        r[5],
                    "detail":       r[6],
                    "evidence":     r[7] or {},
                    "validated_at": r[8].isoformat() if r[8] else None,
                }
                for r in rows
            ]
    except Exception as exc:
        log.error("get_validation_summary: %s", exc)
        return []


def register_validator_scheduler(scheduler) -> None:
    """Register daily control validation job at 03:00 UTC."""
    try:
        from apscheduler.triggers.cron import CronTrigger
        scheduler.add_job(
            lambda: run_all_validators(auto_finding=True),
            trigger=CronTrigger(hour=3, minute=0),
            id="control_validation_daily",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        log.info("[compliance] Daily control validation job registered (03:00 UTC)")
    except Exception as exc:
        log.warning("[compliance] Could not register control validation job: %s", exc)
