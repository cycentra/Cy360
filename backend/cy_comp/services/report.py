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

FRAMEWORK_LABELS = {
    "nis2":      "NIS2",
    "dora":      "DORA",
    "iso27001":  "ISO 27001",
    "soc2":      "SOC 2",
    "nist_csf":  "NIST CSF",
    "pci_dss":   "PCI DSS",
    "gdpr":      "GDPR",
    "eu_ai_act": "EU AI Act",
    "iso42001":  "ISO 42001",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _score_grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def _score_label(score: float) -> str:
    if score >= 80: return "Compliant"
    if score >= 60: return "Partial"
    if score >= 40: return "At Risk"
    return "Non-Compliant"


# ─── Job helpers ──────────────────────────────────────────────────────────────

def _update_job(job_id: str, status: str, progress: int = 0,
                result_path: str = None, error: str = None) -> None:
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


# ─── Data collection ──────────────────────────────────────────────────────────

def _collect_findings(cur, framework: str) -> list:
    q = """
        SELECT id, framework, control_id, severity, verdict, title, status, created_at
        FROM cy_comp_findings
    """
    params = []
    if framework != "all":
        q += " WHERE framework = %s"
        params.append(framework)
    q += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC LIMIT 200;"
    cur.execute(q, params)
    results = []
    for row in cur.fetchall():
        results.append({
            "id": row[0], "framework": row[1], "control_id": row[2],
            "severity": row[3], "verdict": row[4], "title": row[5],
            "status": row[6],
            "created_at": row[7].strftime("%Y-%m-%d") if row[7] else "",
        })
    return results


def _collect_risks(cur, framework: str) -> list:
    q = """
        SELECT id, title, risk_score, probability, impact,
               status, owner, created_at
        FROM cy_comp_risks
    """
    params = []
    if framework != "all":
        q += " WHERE %s = ANY(frameworks)"
        params.append(framework)
    q += " ORDER BY risk_score DESC NULLS LAST LIMIT 100;"
    cur.execute(q, params)
    results = []
    for row in cur.fetchall():
        rs = float(row[2] or 0)
        if rs >= 20:   sev = "Critical"
        elif rs >= 12: sev = "High"
        elif rs >= 6:  sev = "Medium"
        else:          sev = "Low"
        results.append({
            "id": row[0], "title": row[1], "risk_score": rs,
            "severity": sev, "probability": row[3], "impact": row[4],
            "status": row[5], "owner": row[6] or "Unassigned",
            "created_at": row[7].strftime("%Y-%m-%d") if row[7] else "",
        })
    return results


def _collect_questionnaire(cur, framework: str) -> list:
    frameworks = [framework] if framework != "all" else None
    query = """
        SELECT
            t.framework,
            COUNT(t.question_id)                                          AS total,
            COUNT(r.question_id)                                          AS answered,
            COALESCE(SUM(t.weight), 0)                                    AS total_weight,
            COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2), 0)        AS pass_weight,
            COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1),  0)        AS partial_weight
        FROM cy_comp_questionnaire_templates t
        LEFT JOIN cy_comp_questionnaire_responses r
               ON r.question_id = t.question_id AND r.framework = t.framework
    """
    if frameworks:
        query += " WHERE t.framework = ANY(%s)"
        cur.execute(query + " GROUP BY t.framework ORDER BY t.framework;", (frameworks,))
    else:
        cur.execute(query + " GROUP BY t.framework ORDER BY t.framework;")
    results = []
    for row in cur.fetchall():
        fw        = row[0]
        total     = int(row[1] or 0)
        answered  = int(row[2] or 0)
        tw        = float(row[3] or 1)
        pw        = float(row[4] or 0)
        part_w    = float(row[5] or 0)
        pct       = round((answered / total * 100)) if total else 0
        score     = round(((pw + part_w * 0.5) / tw) * 100, 1) if tw and answered else 0.0
        results.append({
            "framework": fw,
            "label": FRAMEWORK_LABELS.get(fw, fw.upper()),
            "total": total,
            "answered": answered,
            "pct": pct,
            "score": score,
        })
    return results


def _collect_alerts_summary(cur, framework: str) -> dict:
    try:
        q = """
            SELECT
                COUNT(*) FILTER (WHERE rule_level >= 12)                     AS crit,
                COUNT(*) FILTER (WHERE rule_level >= 10 AND rule_level < 12) AS high,
                COUNT(*) FILTER (WHERE rule_level >= 7  AND rule_level < 10) AS med,
                COUNT(*)                                                       AS total
            FROM alerts
            WHERE is_compliance_relevant = TRUE
              AND timestamp > NOW() - INTERVAL '30 days'
        """
        params = []
        if framework != "all":
            q += " AND %s = ANY(compliance_frameworks)"
            params.append(framework)
        cur.execute(q, params)
        row = cur.fetchone() or (0, 0, 0, 0)
        return {"critical": int(row[0] or 0), "high": int(row[1] or 0),
                "medium": int(row[2] or 0), "total": int(row[3] or 0)}
    except Exception:
        return {"critical": 0, "high": 0, "medium": 0, "total": 0}


# ─── PDF builder ──────────────────────────────────────────────────────────────

def _build_pdf(pdf_path: str, report_content: dict) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm, cm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics import renderPDF

    # ── Colour palette ──────────────────────────────────────────────────────
    C_NAVY      = colors.HexColor("#0f2044")
    C_TEAL      = colors.HexColor("#00b4d8")
    C_ACCENT    = colors.HexColor("#0077b6")
    C_GREEN     = colors.HexColor("#22c55e")
    C_AMBER     = colors.HexColor("#f59e0b")
    C_RED       = colors.HexColor("#ef4444")
    C_LIGHT_BG  = colors.HexColor("#f0f4f8")
    C_ROW_ODD   = colors.HexColor("#f8fafc")
    C_ROW_EVEN  = colors.white
    C_HEADER_BG = colors.HexColor("#1e3a5f")
    C_MUTED     = colors.HexColor("#64748b")
    C_BORDER    = colors.HexColor("#cbd5e1")

    W, H = A4

    # ── Custom styles ───────────────────────────────────────────────────────
    base_styles = getSampleStyleSheet()

    def S(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    style_cover_title = S("CoverTitle",
        fontSize=28, leading=36, textColor=colors.white, alignment=TA_CENTER,
        fontName="Helvetica-Bold")
    style_cover_sub = S("CoverSub",
        fontSize=13, leading=18, textColor=colors.HexColor("#90caf9"), alignment=TA_CENTER,
        fontName="Helvetica")
    style_cover_meta = S("CoverMeta",
        fontSize=10, leading=14, textColor=colors.HexColor("#b0c4de"), alignment=TA_CENTER,
        fontName="Helvetica")
    style_h1 = S("H1",
        fontSize=16, leading=22, textColor=C_NAVY, fontName="Helvetica-Bold",
        spaceAfter=6)
    style_h2 = S("H2",
        fontSize=12, leading=16, textColor=C_ACCENT, fontName="Helvetica-Bold",
        spaceAfter=4, spaceBefore=10)
    style_body = S("Body",
        fontSize=9, leading=13, textColor=colors.HexColor("#334155"),
        fontName="Helvetica")
    style_body_bold = S("BodyBold",
        fontSize=9, leading=13, textColor=colors.HexColor("#1e293b"),
        fontName="Helvetica-Bold")
    style_small = S("Small",
        fontSize=8, leading=11, textColor=C_MUTED, fontName="Helvetica")
    style_caption = S("Caption",
        fontSize=8, leading=11, textColor=C_MUTED, fontName="Helvetica",
        alignment=TA_CENTER, spaceBefore=2)
    style_rec = S("Rec",
        fontSize=9, leading=13, textColor=colors.HexColor("#1e3a5f"),
        fontName="Helvetica", leftIndent=12)

    def sev_color(sev: str) -> colors.Color:
        sev = (sev or "").lower()
        if sev == "critical": return C_RED
        if sev == "high":     return colors.HexColor("#f97316")
        if sev == "medium":   return C_AMBER
        return colors.HexColor("#3b82f6")

    def score_color(s: float) -> colors.Color:
        if s >= 80: return C_GREEN
        if s >= 60: return C_AMBER
        return C_RED

    # ── Shared table style helpers ───────────────────────────────────────────
    def base_table_style(col_count: int, header_rows: int = 1) -> list:
        cmds = [
            ("BACKGROUND",  (0, 0), (-1, header_rows - 1), C_HEADER_BG),
            ("TEXTCOLOR",   (0, 0), (-1, header_rows - 1), colors.white),
            ("FONTNAME",    (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, header_rows - 1), 8),
            ("ROWBACKGROUNDS", (0, header_rows), (-1, -1), [C_ROW_ODD, C_ROW_EVEN]),
            ("FONTNAME",    (0, header_rows), (-1, -1), "Helvetica"),
            ("FONTSIZE",    (0, header_rows), (-1, -1), 8),
            ("ALIGN",       (0, 0), (-1, -1), "LEFT"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("GRID",        (0, 0), (-1, -1), 0.3, C_BORDER),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]
        return cmds

    # ── Document setup ───────────────────────────────────────────────────────
    fw        = report_content.get("framework", "all")
    fw_label  = FRAMEWORK_LABELS.get(fw, fw.upper()) if fw != "all" else "All Frameworks"
    gen_at    = report_content.get("generated_at", "")
    gen_by    = report_content.get("generated_by", "System")
    scores    = report_content.get("framework_scores", [])
    findings  = report_content.get("findings", [])
    risks     = report_content.get("risks", [])
    q_data    = report_content.get("questionnaire", [])
    alerts    = report_content.get("alerts_summary", {})

    gen_date_str = ""
    try:
        gen_date_str = datetime.fromisoformat(gen_at).strftime("%d %B %Y, %H:%M UTC")
    except Exception:
        gen_date_str = gen_at[:19] if gen_at else ""

    overall_score = 0.0
    if scores:
        overall_score = round(sum(s.get("score", 0) for s in scores) / len(scores), 1)
    grade = _score_grade(overall_score)
    label = _score_label(overall_score)

    def header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        # Footer line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.3)
        canvas.line(15*mm, 12*mm, W - 15*mm, 12*mm)
        canvas.drawString(15*mm, 8*mm, "CyCentra 360 — Confidential GRC Report")
        canvas.drawRightString(W - 15*mm, 8*mm,
            f"Page {doc.page}  |  Generated {gen_date_str}")
        canvas.restoreState()

    def cover_page(canvas, doc):
        canvas.saveState()
        # Navy background
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Teal accent bar
        canvas.setFillColor(C_TEAL)
        canvas.rect(0, H * 0.52, W, 4, fill=1, stroke=0)
        canvas.rect(0, H * 0.48 - 2, W, 2, fill=1, stroke=0)
        # Score circle
        cx, cy, r = W / 2, H * 0.72, 48
        canvas.setFillColor(colors.HexColor("#1e3a5f"))
        canvas.circle(cx, cy, r, fill=1, stroke=0)
        sc = score_color(overall_score)
        canvas.setStrokeColor(sc)
        canvas.setLineWidth(4)
        canvas.circle(cx, cy, r, fill=0, stroke=1)
        canvas.setFillColor(sc)
        canvas.setFont("Helvetica-Bold", 24)
        canvas.drawCentredString(cx, cy + 6, f"{overall_score:.0f}%")
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#90caf9"))
        canvas.drawCentredString(cx, cy - 14, grade + " — " + label)
        # Footer strip
        canvas.setFillColor(colors.HexColor("#0a1628"))
        canvas.rect(0, 0, W, 28*mm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.setFont("Helvetica", 8)
        canvas.drawCentredString(W / 2, 12*mm,
            f"Generated: {gen_date_str}  |  Prepared by: {gen_by}  |  CONFIDENTIAL")
        canvas.restoreState()

    story = []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # COVER PAGE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Spacer(1, H * 0.12))
    story.append(Paragraph("CyCentra 360", style_cover_sub))
    story.append(Spacer(1, 6))
    story.append(Paragraph("GRC Compliance Report", style_cover_title))
    story.append(Spacer(1, 8))
    story.append(Paragraph(fw_label, style_cover_sub))
    story.append(Spacer(1, H * 0.26))
    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 1 — EXECUTIVE SUMMARY
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Executive Summary", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=12))

    total_findings   = len(findings)
    crit_findings    = sum(1 for f in findings if (f.get("severity") or "").lower() == "critical")
    high_findings    = sum(1 for f in findings if (f.get("severity") or "").lower() == "high")
    open_risks       = sum(1 for r in risks if (r.get("status") or "open") in ("open", "accepted"))
    crit_risks       = sum(1 for r in risks if r.get("severity") == "Critical")
    total_q          = sum(q.get("total", 0) for q in q_data)
    answered_q       = sum(q.get("answered", 0) for q in q_data)
    completion_pct   = round(answered_q / total_q * 100) if total_q else 0

    exec_data = [
        ["Metric", "Value", "Status"],
        ["Overall Posture Score",    f"{overall_score:.1f}%",   grade + " — " + label],
        ["Frameworks Assessed",      str(len(scores)),          ""],
        ["Questionnaire Completion", f"{answered_q}/{total_q} ({completion_pct}%)", ""],
        ["Total Findings",           str(total_findings),       f"{crit_findings} Critical / {high_findings} High"],
        ["Open Risks",               str(open_risks),           f"{crit_risks} Critical"],
        ["Compliance Alerts (30d)",  str(alerts.get("total", 0)), f"{alerts.get('critical', 0)} Critical"],
    ]
    exec_table = Table(exec_data, colWidths=[65*mm, 45*mm, 65*mm])
    exec_style = base_table_style(3)
    exec_style += [
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (1, 1), (1, 1), score_color(overall_score)),
    ]
    exec_table.setStyle(TableStyle(exec_style))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # Context paragraph
    status_word = label.lower()
    story.append(Paragraph(
        f"This report covers the compliance posture for <b>{fw_label}</b> as of {gen_date_str}. "
        f"The overall score of <b>{overall_score:.1f}%</b> indicates a <b>{status_word}</b> posture. "
        f"The assessment is based on {answered_q} questionnaire responses, {total_findings} "
        f"active findings, {open_risks} open risks, and {alerts.get('total', 0)} compliance-relevant "
        f"security alerts in the last 30 days.",
        style_body))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Immediate attention is required</b> for any framework scoring below 60% and for all "
        "Critical-severity findings. Review the Gap Analysis section for prioritised remediation steps.",
        style_body))

    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 2 — FRAMEWORK POSTURE SCORES
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Framework Posture Scores", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    if scores:
        # Scores table
        score_tbl_data = [
            ["Framework", "Score", "Grade", "Passing/Total", "Critical Gaps",
             "Alert Penalty", "Status"]
        ]
        for s in sorted(scores, key=lambda x: x.get("score", 0), reverse=True):
            fw_n    = s.get("framework", "")
            sc      = float(s.get("score", 0))
            g       = _score_grade(sc)
            passing = s.get("passing", 0)
            total   = s.get("total_controls", 0)
            gaps    = s.get("critical_gaps", 0)
            penalty = s.get("alert_penalty", 0)
            lbl     = _score_label(sc)
            score_tbl_data.append([
                FRAMEWORK_LABELS.get(fw_n, fw_n.upper()),
                f"{sc:.1f}%", g,
                f"{passing}/{total}",
                str(gaps),
                f"-{penalty}" if penalty else "0",
                lbl,
            ])
        st = Table(score_tbl_data, colWidths=[30*mm, 20*mm, 14*mm, 28*mm, 26*mm, 26*mm, 30*mm])
        st_style = base_table_style(7)
        st_style += [("ALIGN", (1, 0), (-1, -1), "CENTER")]
        for i, s in enumerate(scores, start=1):
            sc = float(s.get("score", 0))
            st_style.append(("TEXTCOLOR", (1, i), (1, i), score_color(sc)))
            st_style.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))
        st.setStyle(TableStyle(st_style))
        story.append(st)
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "Score formula: (Questionnaire weighted pass score) − Alert Penalty. "
            "Alert Penalty = min(40, critical×8 + high×4 + medium×1).",
            style_small))

        # Score bar chart
        story.append(Spacer(1, 14))
        story.append(Paragraph("Posture Score by Framework", style_h2))

        chart_w, chart_h = 160*mm, max(40*mm, len(scores) * 11*mm)
        d = Drawing(chart_w, chart_h)
        bc = HorizontalBarChart()
        bc.x     = 45*mm
        bc.y     = 5*mm
        bc.width  = 110*mm
        bc.height = chart_h - 10*mm
        bc.data  = [[s.get("score", 0) for s in scores]]
        bc.categoryAxis.categoryNames = [
            FRAMEWORK_LABELS.get(s.get("framework", ""), s.get("framework", "").upper())
            for s in scores
        ]
        bc.categoryAxis.labels.fontSize    = 8
        bc.categoryAxis.labels.fontName    = "Helvetica"
        bc.valueAxis.valueMin              = 0
        bc.valueAxis.valueMax              = 100
        bc.valueAxis.valueStep             = 20
        bc.valueAxis.labels.fontSize       = 8
        bc.bars[0].fillColor               = C_ACCENT
        bc.barSpacing                      = 2
        d.add(bc)
        story.append(d)
        story.append(Paragraph("Figure 1 — Framework posture scores (0–100%)", style_caption))

    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 3 — QUESTIONNAIRE COMPLETION
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Questionnaire Completion", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    if q_data:
        q_tbl_data = [["Framework", "Questions Answered", "Completion %", "Weighted Score"]]
        for q in q_data:
            q_tbl_data.append([
                q.get("label", q.get("framework", "")),
                f"{q.get('answered', 0)} / {q.get('total', 0)}",
                f"{q.get('pct', 0)}%",
                f"{q.get('score', 0):.1f}%",
            ])
        qt = Table(q_tbl_data, colWidths=[50*mm, 50*mm, 40*mm, 40*mm])
        qt_style = base_table_style(4)
        qt_style += [("ALIGN", (1, 0), (-1, -1), "CENTER")]
        for i, q in enumerate(q_data, start=1):
            pct = q.get("pct", 0)
            qt_style.append(("TEXTCOLOR", (2, i), (2, i), score_color(pct)))
        qt.setStyle(TableStyle(qt_style))
        story.append(qt)
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "Completion % is the proportion of questionnaire questions answered. "
            "Weighted Score accounts for question weights (critical controls weighted 3×, "
            "standard controls 2×).",
            style_small))
    else:
        story.append(Paragraph("No questionnaire data available for the selected period.", style_body))

    story.append(Spacer(1, 16))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 4 — COMPLIANCE ALERTS (30-day)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Compliance-Relevant Security Alerts (Last 30 Days)", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    al_data = [
        ["Severity", "Count", "Impact on Score"],
        ["Critical (level ≥ 12)", str(alerts.get("critical", 0)), "−8 pts per alert (capped)"],
        ["High (level 10–11)",    str(alerts.get("high", 0)),     "−4 pts per alert (capped)"],
        ["Medium (level 7–9)",    str(alerts.get("medium", 0)),   "−1 pt per alert (capped)"],
        ["Total",                 str(alerts.get("total", 0)),    "Max combined penalty: −40 pts"],
    ]
    al_table = Table(al_data, colWidths=[55*mm, 30*mm, 90*mm])
    al_style = base_table_style(3)
    al_style += [
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), C_LIGHT_BG),
        ("TEXTCOLOR", (1, 1), (1, 1), C_RED if alerts.get("critical", 0) > 0 else colors.black),
    ]
    al_table.setStyle(TableStyle(al_style))
    story.append(al_table)
    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 5 — FINDINGS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Top Compliance Findings", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    if findings:
        top_findings = findings[:50]
        f_data = [["Framework", "Control", "Severity", "Verdict", "Title", "Status", "Date"]]
        for f in top_findings:
            f_data.append([
                FRAMEWORK_LABELS.get(f.get("framework", ""), f.get("framework", "").upper()),
                f.get("control_id", "")[:12],
                (f.get("severity") or "").capitalize(),
                (f.get("verdict")  or "").capitalize(),
                Paragraph(f.get("title", "")[:80], style_small),
                (f.get("status")   or "").capitalize(),
                f.get("created_at", ""),
            ])
        ft = Table(f_data, colWidths=[22*mm, 20*mm, 18*mm, 18*mm, 60*mm, 18*mm, 19*mm])
        ft_style = base_table_style(7)
        ft_style += [("ALIGN", (2, 1), (3, -1), "CENTER"),
                     ("ALIGN", (5, 1), (6, -1), "CENTER")]
        for i, f in enumerate(top_findings, start=1):
            c = sev_color(f.get("severity", ""))
            ft_style.append(("TEXTCOLOR", (2, i), (2, i), c))
            ft_style.append(("FONTNAME",  (2, i), (2, i), "Helvetica-Bold"))
        ft.setStyle(TableStyle(ft_style))
        story.append(ft)
        if len(findings) > 50:
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"Showing top 50 of {len(findings)} findings. Full list available in the JSON export.",
                style_small))
    else:
        story.append(Paragraph("No compliance findings recorded for the selected scope.", style_body))

    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 6 — RISK REGISTER
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Risk Register Summary", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    if risks:
        # Summary counts
        sev_counts = {}
        for r in risks:
            sev_counts[r.get("severity", "Low")] = sev_counts.get(r.get("severity", "Low"), 0) + 1

        sev_sum = [["Severity", "Count"]]
        for sev in ["Critical", "High", "Medium", "Low"]:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                sev_sum.append([sev, str(cnt)])
        sev_sum.append(["Total", str(len(risks))])
        sev_t = Table(sev_sum, colWidths=[50*mm, 30*mm])
        sev_style = base_table_style(2)
        sev_style += [
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("BACKGROUND", (0, -1), (-1, -1), C_LIGHT_BG),
        ]
        for i, row in enumerate(sev_sum[1:], start=1):
            if row[0] == "Critical":
                sev_style.append(("TEXTCOLOR", (0, i), (0, i), C_RED))
            elif row[0] == "High":
                sev_style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor("#f97316")))
        sev_t.setStyle(TableStyle(sev_style))
        story.append(sev_t)
        story.append(Spacer(1, 10))

        # Top risks table
        story.append(Paragraph("Top Risks by Score", style_h2))
        top_risks = risks[:30]
        r_data = [["Title", "Severity", "Score", "Probability", "Impact", "Owner", "Status"]]
        for r in top_risks:
            r_data.append([
                Paragraph(r.get("title", "")[:60], style_small),
                r.get("severity", ""),
                f"{r.get('risk_score', 0):.0f}",
                str(r.get("probability") or ""),
                str(r.get("impact") or ""),
                r.get("owner", "")[:18],
                (r.get("status") or "").capitalize(),
            ])
        rt = Table(r_data, colWidths=[52*mm, 20*mm, 14*mm, 20*mm, 16*mm, 28*mm, 25*mm])
        rt_style = base_table_style(7)
        rt_style += [("ALIGN", (1, 0), (-1, -1), "CENTER")]
        for i, r in enumerate(top_risks, start=1):
            c = sev_color(r.get("severity", ""))
            rt_style.append(("TEXTCOLOR", (1, i), (1, i), c))
            rt_style.append(("FONTNAME",  (1, i), (1, i), "Helvetica-Bold"))
        rt.setStyle(TableStyle(rt_style))
        story.append(rt)
    else:
        story.append(Paragraph("No risks recorded in the register for the selected scope.", style_body))

    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 7 — GAP ANALYSIS & RECOMMENDATIONS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Gap Analysis & Recommendations", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    story.append(Paragraph(
        "Recommendations are listed in priority order based on score impact, critical finding "
        "count, and open risk exposure. Address Critical items before the next assessment cycle.",
        style_body))
    story.append(Spacer(1, 8))

    rec_counter = 1
    for s in sorted(scores, key=lambda x: x.get("score", 100)):
        sc      = float(s.get("score", 0))
        fw_n    = s.get("framework", "")
        fw_lbl  = FRAMEWORK_LABELS.get(fw_n, fw_n.upper())
        gaps    = int(s.get("critical_gaps", 0))
        penalty = int(s.get("alert_penalty", 0))
        passing = int(s.get("passing", 0))
        total   = int(s.get("total_controls", 0))
        failing = int(s.get("failing", 0))
        q_inf   = next((q for q in q_data if q.get("framework") == fw_n), {})
        pct     = q_inf.get("pct", 0)

        if sc >= 85 and gaps == 0:
            continue  # No gaps to report

        items = []
        if pct < 100 and total > 0:
            remaining = total - (q_inf.get("answered", 0))
            items.append(
                f"Complete the questionnaire ({remaining} questions unanswered). "
                f"Unanswered controls are treated as a gap and depress the score.")
        if failing > 0:
            items.append(
                f"Remediate {failing} failing control{'s' if failing != 1 else ''}. "
                f"Each failing control lowers the weighted score proportionally.")
        if gaps > 0:
            items.append(
                f"Address {gaps} critical gap{'s' if gaps != 1 else ''} flagged by findings "
                f"and alerts. Critical gaps carry the highest remediation priority.")
        if penalty >= 8:
            items.append(
                f"Reduce compliance-relevant alert volume (current penalty: {penalty} pts). "
                f"Harden configurations, patch known CVEs, and review SIEM correlation rules.")
        if sc < 60:
            items.append(
                f"Schedule an internal audit for {fw_lbl}. Score is below 60% — "
                f"regulatory non-compliance risk is elevated.")

        if not items:
            items.append(f"Continue monitoring. Score is {sc:.0f}% — maintain current controls.")

        story.append(KeepTogether([
            Paragraph(f"REC-{rec_counter:02d}  {fw_lbl}  [{sc:.0f}%  Grade {_score_grade(sc)}]",
                      style_h2),
        ] + [Paragraph(f"• {item}", style_rec) for item in items]
          + [Spacer(1, 6)]))
        rec_counter += 1

    if rec_counter == 1:
        story.append(Paragraph(
            "All assessed frameworks meet the 85% threshold. Maintain current control posture "
            "and schedule the next review in 90 days.",
            style_body))

    story.append(PageBreak())

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SECTION 8 — CONCLUSION
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    story.append(Paragraph("Conclusion & Next Steps", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=C_TEAL, spaceAfter=10))

    low_fw  = [FRAMEWORK_LABELS.get(s["framework"], s["framework"])
               for s in scores if float(s.get("score", 0)) < 60]
    mid_fw  = [FRAMEWORK_LABELS.get(s["framework"], s["framework"])
               for s in scores if 60 <= float(s.get("score", 0)) < 80]
    high_fw = [FRAMEWORK_LABELS.get(s["framework"], s["framework"])
               for s in scores if float(s.get("score", 0)) >= 80]

    story.append(Paragraph(
        f"As of {gen_date_str}, the organisation's overall compliance posture score is "
        f"<b>{overall_score:.1f}%</b> (Grade <b>{grade}</b>).",
        style_body))
    story.append(Spacer(1, 4))

    if high_fw:
        story.append(Paragraph(
            f"<b>Compliant frameworks (≥80%):</b> {', '.join(high_fw)}. "
            f"Continue monitoring and complete any remaining questionnaire items.",
            style_body))
    if mid_fw:
        story.append(Paragraph(
            f"<b>Partially compliant frameworks (60–79%):</b> {', '.join(mid_fw)}. "
            f"Focus on completing questionnaire responses and closing high-priority findings.",
            style_body))
    if low_fw:
        story.append(Paragraph(
            f"<b>Non-compliant frameworks (&lt;60%):</b> {', '.join(low_fw)}. "
            f"Immediate remediation required. Schedule an internal audit and engage relevant "
            f"control owners.",
            style_body))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Recommended Next Steps", style_h2))

    next_steps = [
        "Assign all open Critical and High findings to named control owners with a 30-day SLA.",
        "Complete any unanswered questionnaire sections — partial data under-states the posture.",
        "Run 'Auto Populate from Findings' after each Wazuh / SIEM alert batch to keep the "
        "risk register current.",
        "Schedule a remediation review in 30 days and a full assessment review in 90 days.",
        "For frameworks below 60%, engage external auditors or a vCISO to support rapid uplift.",
        "Ensure the SIEM alert enrichment pipeline is active so compliance-relevant alerts "
        "are tagged automatically.",
    ]
    for step in next_steps:
        story.append(Paragraph(f"• {step}", style_rec))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"This report was generated automatically by CyCentra 360 GRC on {gen_date_str}. "
        f"It is confidential and intended solely for the organisation's internal compliance team. "
        f"Report ID: {report_content.get('job_id', '')}",
        style_small))

    # ── Build ────────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=20*mm, bottomMargin=20*mm,
        title=f"CyCentra GRC Report — {fw_label}",
        author="CyCentra 360",
        subject="GRC Compliance Report",
    )
    doc.build(
        story,
        onFirstPage=cover_page,
        onLaterPages=header_footer,
    )


# ─── Public API ───────────────────────────────────────────────────────────────

def create_report_job(framework: str, period_start: str, period_end: str,
                      requested_by: str) -> str:
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
    log.info("generate_report_job: starting job_id=%s", job_id)
    _update_job(job_id, "running", progress=5)

    try:
        job = _get_job(job_id)
        if not job:
            log.error("generate_report_job: job_id=%s not found", job_id)
            return

        framework    = job.get("framework") or "all"
        requested_by = job.get("requested_by")

        # Phase 1 — framework scores (20%)
        _update_job(job_id, "running", progress=20)
        scores = get_latest_scores(
            frameworks=[framework] if framework != "all" else None
        )

        # Phase 2 — gather all report data (60%)
        _update_job(job_id, "running", progress=40)
        findings = []
        risks    = []
        q_data   = []
        alerts   = {}
        try:
            with db() as conn:
                cur = conn.cursor()
                findings = _collect_findings(cur, framework)
                _update_job(job_id, "running", progress=50)
                risks    = _collect_risks(cur, framework)
                _update_job(job_id, "running", progress=60)
                q_data   = _collect_questionnaire(cur, framework)
                alerts   = _collect_alerts_summary(cur, framework)
        except Exception as exc:
            log.warning("generate_report_job: data collection: %s", exc)

        _update_job(job_id, "running", progress=70)

        # Phase 3 — build report content dict
        report_content = {
            "job_id":           job_id,
            "framework":        framework,
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "generated_by":     requested_by,
            "framework_scores": scores,
            "findings_count":   len(findings),
            "findings":         findings,
            "risks":            risks,
            "questionnaire":    q_data,
            "alerts_summary":   alerts,
        }

        # Phase 4 — write JSON
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        json_path = REPORTS_DIR / f"{job_id}.json"
        json_path.write_text(json.dumps(report_content, indent=2, default=str))
        _update_job(job_id, "running", progress=80)

        # Phase 5 — write PDF
        pdf_path = None
        try:
            pdf_file = REPORTS_DIR / f"{job_id}.pdf"
            _build_pdf(str(pdf_file), report_content)
            pdf_path = str(pdf_file)
            log.info("generate_report_job: PDF written to %s", pdf_path)
        except ImportError:
            log.info("generate_report_job: reportlab not installed — JSON only")
        except Exception as exc:
            log.warning("generate_report_job: PDF generation failed: %s", exc)

        _update_job(job_id, "running", progress=90)

        # Phase 6 — persist report record
        report_id = str(uuid.uuid4())
        overall   = round(sum(s.get("score", 0) for s in scores) / len(scores), 1) if scores else 0.0
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
                        f"Compliance Report — {FRAMEWORK_LABELS.get(framework, framework.upper()) if framework != 'all' else 'All Frameworks'}",
                        framework,
                        overall,
                        json.dumps(report_content, default=str),
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
    return _get_job(job_id)


# ── Unified Board-Ready Report ────────────────────────────────────────────────

def create_board_report_job(requested_by: str, period_start: str, period_end: str) -> str:
    """Create a board report job record. Returns job_id."""
    job_id = str(uuid.uuid4())
    try:
        with db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cy_comp_report_jobs
                    (job_id, status, requested_by, framework,
                     period_start, period_end, progress, created_at, updated_at)
                VALUES (%s,'pending',%s,'board',%s,%s,0,NOW(),NOW());
                """,
                (job_id, requested_by, period_start, period_end)
            )
    except Exception as exc:
        log.error("create_board_report_job: %s", exc)
    return job_id


def generate_board_report_job(job_id: str) -> None:
    """
    Generate a unified board-ready report that aggregates:
      - All framework compliance scores with trend
      - Top critical/high risks (by financial_impact_eur if set)
      - Open critical findings per framework
      - 30-day compliance alert trend
      - Resilience score
      - Supply chain exposure items (top 10 open)

    Output: JSON + PDF in REPORTS_DIR. The PDF is designed to be
    attached to board pack emails — executive language, no technical jargon.
    """
    log.info("generate_board_report_job: starting job_id=%s", job_id)
    _update_job(job_id, "running", progress=5)

    try:
        job = _get_job(job_id)
        if not job:
            log.error("generate_board_report_job: job_id=%s not found", job_id)
            return

        requested_by = job.get("requested_by")
        _update_job(job_id, "running", progress=15)

        # ── 1. Framework scores ───────────────────────────────────────────────
        scores = get_latest_scores()  # all frameworks
        overall = round(sum(s.get("score", 0) for s in scores) / len(scores), 1) if scores else 0.0

        _update_job(job_id, "running", progress=30)

        # ── 2. Risk register summary + top risks ─────────────────────────────
        top_risks    = []
        risk_summary = {}
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT COUNT(*), COUNT(*) FILTER (WHERE risk_score >= 20),
                           COUNT(*) FILTER (WHERE risk_score >= 12 AND risk_score < 20),
                           COUNT(*) FILTER (WHERE status = 'open')
                    FROM cy_comp_risks;
                    """
                )
                row = cur.fetchone() or (0, 0, 0, 0)
                risk_summary = {
                    "total": int(row[0] or 0),
                    "critical": int(row[1] or 0),
                    "high": int(row[2] or 0),
                    "open": int(row[3] or 0),
                }
                cur.execute(
                    """
                    SELECT title, risk_score, status, treatment, frameworks,
                           financial_impact, financial_impact_eur, business_unit
                    FROM cy_comp_risks
                    WHERE status IN ('open','in_progress')
                    ORDER BY risk_score DESC NULLS LAST, financial_impact_eur DESC NULLS LAST
                    LIMIT 10;
                    """
                )
                for r in cur.fetchall():
                    top_risks.append({
                        "title":               r[0],
                        "risk_score":          r[1],
                        "status":              r[2],
                        "treatment":           r[3],
                        "frameworks":          r[4] or [],
                        "financial_impact":    r[5],
                        "financial_impact_eur": r[6],
                        "business_unit":       r[7],
                    })
        except Exception as exc:
            log.warning("generate_board_report_job: risk query: %s", exc)

        _update_job(job_id, "running", progress=45)

        # ── 3. Open critical/high findings per framework ───────────────────────
        critical_findings = []
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT framework, severity, COUNT(*) AS cnt
                    FROM cy_comp_findings
                    WHERE status IN ('open','in_progress')
                      AND severity IN ('critical','high')
                    GROUP BY framework, severity
                    ORDER BY framework, severity;
                    """
                )
                for fw, sev, cnt in cur.fetchall():
                    critical_findings.append({"framework": fw, "severity": sev, "count": int(cnt)})
        except Exception as exc:
            log.warning("generate_board_report_job: findings query: %s", exc)

        _update_job(job_id, "running", progress=55)

        # ── 4. 30-day compliance alert trend ──────────────────────────────────
        alert_trend = []
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT DATE_TRUNC('week', timestamp) AS week,
                           COUNT(*) FILTER (WHERE rule_level >= 12) AS critical,
                           COUNT(*) FILTER (WHERE rule_level >= 10 AND rule_level < 12) AS high,
                           COUNT(*) AS total
                    FROM alerts
                    WHERE is_compliance_relevant = TRUE
                      AND timestamp > NOW() - INTERVAL '30 days'
                    GROUP BY week ORDER BY week;
                    """
                )
                for row in cur.fetchall():
                    alert_trend.append({
                        "week":     row[0].isoformat() if row[0] else None,
                        "critical": int(row[1] or 0),
                        "high":     int(row[2] or 0),
                        "total":    int(row[3] or 0),
                    })
        except Exception as exc:
            log.warning("generate_board_report_job: alert trend: %s", exc)

        _update_job(job_id, "running", progress=65)

        # ── 5. Cyber resilience score ─────────────────────────────────────────
        resilience = {}
        try:
            from cy_comp.services.compliance import get_resilience_score
            resilience = get_resilience_score()
        except Exception as exc:
            log.warning("generate_board_report_job: resilience score: %s", exc)

        _update_job(job_id, "running", progress=75)

        # ── 6. Top open exposure items (supply chain + vulnerabilities) ────────
        top_exposures = []
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT asset, exposure_type, severity, title, cvss_score, status
                    FROM cy_comp_exposure
                    WHERE status = 'open'
                    ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                             cvss_score DESC NULLS LAST
                    LIMIT 10;
                    """
                )
                for r in cur.fetchall():
                    top_exposures.append({
                        "asset": r[0], "type": r[1], "severity": r[2],
                        "title": r[3], "cvss": r[4], "status": r[5],
                    })
        except Exception as exc:
            log.debug("generate_board_report_job: exposure query: %s", exc)

        _update_job(job_id, "running", progress=80)

        # ── 7. Build report content dict ──────────────────────────────────────
        report_content = {
            "job_id":              job_id,
            "report_type":         "board",
            "generated_at":        datetime.now(timezone.utc).isoformat(),
            "generated_by":        requested_by,
            "period_start":        job.get("period_start"),
            "period_end":          job.get("period_end"),
            "overall_score":       overall,
            "score_label":         _score_label(overall),
            "score_grade":         _score_grade(overall),
            "framework_scores":    [
                {**s, "label": FRAMEWORK_LABELS.get(s.get("framework", ""), s.get("framework", ""))}
                for s in scores
            ],
            "risk_summary":        risk_summary,
            "top_risks":           top_risks,
            "critical_findings":   critical_findings,
            "alert_trend":         alert_trend,
            "resilience":          resilience,
            "top_exposures":       top_exposures,
        }

        # ── 8. Write JSON ─────────────────────────────────────────────────────
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        json_path = REPORTS_DIR / f"board_{job_id}.json"
        json_path.write_text(json.dumps(report_content, indent=2, default=str))
        _update_job(job_id, "running", progress=88)

        # ── 9. Write PDF (board-optimised layout) ─────────────────────────────
        pdf_path = None
        try:
            pdf_file = REPORTS_DIR / f"board_{job_id}.pdf"
            _build_board_pdf(str(pdf_file), report_content)
            pdf_path = str(pdf_file)
        except ImportError:
            log.info("generate_board_report_job: reportlab not installed — JSON only")
        except Exception as exc:
            log.warning("generate_board_report_job: PDF error: %s", exc)

        # ── 10. Persist report record ─────────────────────────────────────────
        report_id = str(uuid.uuid4())
        try:
            with db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO cy_comp_reports
                        (id, title, framework, overall_score, content_json, pdf_path,
                         generated_by, created_at)
                    VALUES (%s,%s,'board',%s,%s,%s,%s,NOW());
                    """,
                    (
                        report_id,
                        "Board Risk & Compliance Report",
                        overall,
                        json.dumps(report_content, default=str),
                        pdf_path,
                        requested_by,
                    )
                )
        except Exception as exc:
            log.warning("generate_board_report_job: DB insert: %s", exc)

        _update_job(job_id, "complete", progress=100, result_path=str(json_path))
        log.info("generate_board_report_job: completed job_id=%s", job_id)

    except Exception as exc:
        log.error("generate_board_report_job: FATAL job_id=%s: %s", job_id, exc)
        _update_job(job_id, "failed", error=str(exc)[:500])


def _build_board_pdf(pdf_path: str, data: dict) -> None:
    """Generate a concise executive PDF — one page executive summary + framework table."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm

    doc  = SimpleDocTemplate(pdf_path, pagesize=A4,
                             leftMargin=20*mm, rightMargin=20*mm,
                             topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Title
    title_style = ParagraphStyle("BoardTitle", parent=styles["Title"],
                                 fontSize=20, spaceAfter=4*mm)
    story.append(Paragraph("Board Risk &amp; Compliance Report", title_style))
    story.append(Paragraph(
        f"Generated: {data.get('generated_at','')[:10]}  |  "
        f"Period: {data.get('period_start','N/A')} – {data.get('period_end','N/A')}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 6*mm))

    # Overall posture box
    overall = data.get("overall_score", 0)
    grade   = data.get("score_grade", "?")
    clr_map = {"A": colors.HexColor("#00c875"), "B": colors.HexColor("#fdad4b"),
                "C": colors.HexColor("#e8697d"), "D": colors.HexColor("#d0021b"),
                "F": colors.HexColor("#770000")}
    box_clr = clr_map.get(grade, colors.grey)

    posture_table = Table(
        [[Paragraph(f"<b>Overall Posture: {overall:.1f}%  [{grade}]</b>", styles["Heading2"])]],
        colWidths=[170*mm],
    )
    posture_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), box_clr),
        ("TEXTCOLOR",  (0, 0), (-1, -1), colors.white),
        ("ROWPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(posture_table)
    story.append(Spacer(1, 5*mm))

    # Framework scores table
    story.append(Paragraph("<b>Compliance Framework Scores</b>", styles["Heading3"]))
    fw_rows = [["Framework", "Score", "Grade", "Controls", "Critical Gaps"]]
    for s in data.get("framework_scores", []):
        fw_rows.append([
            s.get("label") or s.get("framework", "").upper(),
            f"{s.get('score', 0):.1f}%",
            _score_grade(s.get("score", 0)),
            str(s.get("total_controls", "")),
            str(s.get("critical_gaps", "")),
        ])
    fw_table = Table(fw_rows, colWidths=[60*mm, 25*mm, 20*mm, 30*mm, 35*mm])
    fw_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(fw_table)
    story.append(Spacer(1, 5*mm))

    # Risk summary
    rs = data.get("risk_summary", {})
    story.append(Paragraph(
        f"<b>Risk Register:</b> {rs.get('total',0)} total | "
        f"<font color='red'>{rs.get('critical',0)} critical</font> | "
        f"{rs.get('high',0)} high | {rs.get('open',0)} open",
        styles["Normal"]
    ))
    story.append(Spacer(1, 3*mm))

    # Top risks
    if data.get("top_risks"):
        story.append(Paragraph("<b>Top Open Risks</b>", styles["Heading3"]))
        risk_rows = [["Risk", "Score", "Treatment", "Financial Impact", "Business Unit"]]
        for r in data["top_risks"][:8]:
            eur = f"€{r['financial_impact_eur']:,}" if r.get("financial_impact_eur") else r.get("financial_impact") or "—"
            risk_rows.append([
                Paragraph(r.get("title","")[:60], styles["Normal"]),
                str(r.get("risk_score","")),
                r.get("treatment",""),
                eur,
                r.get("business_unit","—"),
            ])
        r_table = Table(risk_rows, colWidths=[60*mm, 20*mm, 25*mm, 35*mm, 30*mm])
        r_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(r_table)
        story.append(Spacer(1, 5*mm))

    # Resilience score
    res = data.get("resilience", {})
    if res.get("overall_score") is not None:
        story.append(Paragraph(
            f"<b>Cyber Resilience Score:</b> {res['overall_score']:.1f}% ({res.get('rating','').title()})",
            styles["Normal"]
        ))
        story.append(Spacer(1, 3*mm))

    doc.build(story)
