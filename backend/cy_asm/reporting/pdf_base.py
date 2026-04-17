"""
reporting/pdf_base.py
CyCentra ASM — PDF Base Builder
Shared document structure, fonts, styles, headers, footers, cover page,
and helper components used by both Executive and Technical reports.
"""
from __future__ import annotations

import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)
from reportlab.platypus.flowables import Flowable

# ── Colour constants (hex → ReportLab Color) ─────────────────────────────────
C_NAVY    = colors.HexColor("#0B1F3A")
C_BLUE    = colors.HexColor("#1E40FF")
C_SKY     = colors.HexColor("#4FB6FF")
C_TEAL    = colors.HexColor("#00C9C8")
C_RED     = colors.HexColor("#E53E3E")
C_ORANGE  = colors.HexColor("#F6AD55")
C_YELLOW  = colors.HexColor("#ECC94B")
C_GREEN   = colors.HexColor("#48BB78")
C_PURPLE  = colors.HexColor("#805AD5")
C_LIGHT   = colors.HexColor("#F7FAFC")
C_MID     = colors.HexColor("#EBF4FF")
C_BORDER  = colors.HexColor("#CBD5E0")
C_TEXT    = colors.HexColor("#1A202C")
C_SUBTLE  = colors.HexColor("#718096")

SEV_COLOR = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_YELLOW,
    "Low":      C_GREEN,
    "Info":     C_SKY,
}

W, H = A4   # 595 x 842 pts
MARGIN = 2 * cm
BODY_W = W - 2 * MARGIN


# ── Style sheet ───────────────────────────────────────────────────────────────

def build_styles() -> dict:
    base = getSampleStyleSheet()
    s = {}

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    s["cover_title"] = ps("cover_title",
        fontName="Helvetica-Bold", fontSize=36, textColor=colors.white,
        leading=42, alignment=TA_LEFT, spaceAfter=6)

    s["cover_sub"] = ps("cover_sub",
        fontName="Helvetica", fontSize=14, textColor=C_SKY,
        leading=18, alignment=TA_LEFT, spaceAfter=4)

    s["cover_meta"] = ps("cover_meta",
        fontName="Helvetica", fontSize=10, textColor=colors.white,
        leading=14, alignment=TA_LEFT)

    s["h1"] = ps("h1",
        fontName="Helvetica-Bold", fontSize=16, textColor=C_NAVY,
        leading=20, spaceBefore=18, spaceAfter=6)

    s["h2"] = ps("h2",
        fontName="Helvetica-Bold", fontSize=12, textColor=C_BLUE,
        leading=16, spaceBefore=12, spaceAfter=4)

    s["h3"] = ps("h3",
        fontName="Helvetica-Bold", fontSize=10, textColor=C_NAVY,
        leading=14, spaceBefore=8, spaceAfter=3)

    s["body"] = ps("body",
        fontName="Helvetica", fontSize=9, textColor=C_TEXT,
        leading=13, spaceAfter=4, alignment=TA_JUSTIFY)

    s["body_small"] = ps("body_small",
        fontName="Helvetica", fontSize=8, textColor=C_SUBTLE,
        leading=11, spaceAfter=3)

    s["bullet"] = ps("bullet",
        fontName="Helvetica", fontSize=9, textColor=C_TEXT,
        leading=12, leftIndent=12, spaceAfter=2,
        bulletIndent=0, bulletText="•")

    s["finding_title"] = ps("finding_title",
        fontName="Helvetica-Bold", fontSize=9.5, textColor=C_NAVY,
        leading=13, spaceAfter=2)

    s["tag"] = ps("tag",
        fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
        alignment=TA_CENTER)

    s["footer"] = ps("footer",
        fontName="Helvetica", fontSize=7, textColor=C_SUBTLE,
        alignment=TA_CENTER)

    s["toc"] = ps("toc",
        fontName="Helvetica", fontSize=9.5, textColor=C_NAVY,
        leading=14, spaceAfter=2)

    s["caption"] = ps("caption",
        fontName="Helvetica-Oblique", fontSize=7.5, textColor=C_SUBTLE,
        alignment=TA_CENTER, spaceAfter=6)

    s["metric_num"] = ps("metric_num",
        fontName="Helvetica-Bold", fontSize=28, textColor=C_NAVY,
        alignment=TA_CENTER, leading=32)

    s["metric_label"] = ps("metric_label",
        fontName="Helvetica", fontSize=7.5, textColor=C_SUBTLE,
        alignment=TA_CENTER, leading=10)

    return s


STYLES = build_styles()


# ── Reusable Flowables ────────────────────────────────────────────────────────

def rule(color=C_BORDER, thickness=0.5, width=BODY_W, space_before=4, space_after=8):
    return HRFlowable(width=width, thickness=thickness,
                      color=color, spaceAfter=space_after, spaceBefore=space_before)


def img_from_bytes(buf: io.BytesIO, width: float, height: Optional[float] = None) -> Image:
    buf.seek(0)
    if height:
        return Image(buf, width=width, height=height)
    return Image(buf, width=width)


def severity_badge(sev: str) -> Table:
    """Inline coloured severity badge."""
    col = SEV_COLOR.get(sev, C_SKY)
    cell = Paragraph(f"<b>{sev.upper()}</b>", STYLES["tag"])
    t = Table([[cell]], colWidths=[1.8 * cm], rowHeights=[0.42 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), col),
        ("ROUNDEDCORNERS", [3]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def metric_card(value: str, label: str, color=C_NAVY) -> Table:
    """KPI card for the executive summary strip."""
    val_style = ParagraphStyle("mv", fontName="Helvetica-Bold", fontSize=24,
                               textColor=color, alignment=TA_CENTER, leading=28)
    lbl_style = ParagraphStyle("ml", fontName="Helvetica", fontSize=7.5,
                               textColor=C_SUBTLE, alignment=TA_CENTER, leading=10)
    t = Table([
        [Paragraph(str(value), val_style)],
        [Paragraph(label, lbl_style)],
    ], colWidths=[3.8 * cm], rowHeights=[1.1 * cm, 0.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (0, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def section_header(title: str, subtitle: str = "") -> List:
    items = [
        rule(C_BLUE, thickness=2, space_before=10, space_after=2),
        Paragraph(title, STYLES["h1"]),
    ]
    if subtitle:
        items.append(Paragraph(subtitle, STYLES["body_small"]))
    items.append(rule(C_BORDER, thickness=0.5, space_before=0, space_after=10))
    return items


def finding_table(rows: List[List], col_widths: List[float],
                  header: List[str], zebra: bool = True) -> Table:
    """Standard data table with branded header."""
    data = [header] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 8),
        ("ALIGN",      (0, 0), (-1, 0), "CENTER"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME",   (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",   (0, 1), (-1, -1), 7.5),
        ("TEXTCOLOR",  (0, 1), (-1, -1), C_TEXT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [C_LIGHT, colors.white] if zebra else [colors.white]),
        ("GRID",       (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    t.setStyle(TableStyle(style))
    return t


# ── Page Templates ────────────────────────────────────────────────────────────

class CyCentraDocTemplate(BaseDocTemplate):
    """Custom doc template with branded header/footer on content pages."""

    def __init__(self, filename: str, report_type: str = "Executive",
                 domain: str = "", scan_id: str = "", **kw):
        super().__init__(filename, **kw)
        self.report_type = report_type
        self.domain      = domain
        self.scan_id     = scan_id
        self._build_templates()

    def _build_templates(self):
        # Cover page — full bleed, no margin frame
        cover_frame = Frame(0, 0, W, H, leftPadding=0, rightPadding=0,
                            topPadding=0, bottomPadding=0, id="cover")
        cover_tpl = PageTemplate(id="Cover", frames=[cover_frame],
                                 onPage=self._no_header_footer)

        # Content pages
        content_frame = Frame(MARGIN, 1.8 * cm, BODY_W, H - MARGIN - 2.4 * cm,
                              id="content")
        content_tpl = PageTemplate(id="Content", frames=[content_frame],
                                   onPage=self._draw_header_footer)

        self.addPageTemplates([cover_tpl, content_tpl])

    def _no_header_footer(self, canvas, doc):
        pass

    def _draw_header_footer(self, canvas, doc):
        canvas.saveState()
        # Header bar
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, H - 1.1 * cm, W, 1.1 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_SKY)
        canvas.rect(0, H - 1.1 * cm, 4 * mm, 1.1 * cm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(MARGIN, H - 0.7 * cm, "CyCentra ASM")
        canvas.setFont("Helvetica", 8)
        canvas.drawCentredString(W / 2, H - 0.7 * cm,
                                 f"{self.report_type} Report  |  {self.domain}")
        canvas.drawRightString(W - MARGIN, H - 0.7 * cm,
                               datetime.now().strftime("%d %b %Y"))
        # Footer line
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 1.4 * cm, W - MARGIN, 1.4 * cm)
        canvas.setFillColor(C_SUBTLE)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 0.9 * cm,
                          f"CONFIDENTIAL  |  Scan ID: {self.scan_id}")
        canvas.drawRightString(W - MARGIN, 0.9 * cm, f"Page {doc.page}")
        canvas.restoreState()


# ── Cover Page ────────────────────────────────────────────────────────────────

def build_cover(report_type: str, domain: str, org: str,
                scan_id: str, scan_date: str,
                posture_score: int, posture_grade: str) -> List:
    """Returns a list of flowables that form the full cover page."""

    class CoverCanvas(Flowable):
        """Draw the gradient cover background + branding."""
        def __init__(self, w, h, rt, domain_, org_, scan_id_, scan_date_,
                     score_, grade_):
            super().__init__()
            self.w = w
            self.h = h
            self.rt = rt
            self.domain_  = domain_
            self.org_     = org_
            self.scan_id_ = scan_id_
            self.scan_date_ = scan_date_
            self.score_   = score_
            self.grade_   = grade_

        def draw(self):
            c = self.canv
            # Full dark background
            c.setFillColor(C_NAVY)
            c.rect(0, 0, self.w, self.h, fill=1, stroke=0)
            # Accent panel left strip
            c.setFillColor(C_BLUE)
            c.rect(0, 0, 6 * mm, self.h, fill=1, stroke=0)
            # Diagonal accent top-right
            from reportlab.graphics import renderPDF
            c.setFillColor(colors.HexColor("#162d52"))
            p = c.beginPath()
            p.moveTo(self.w, self.h)
            p.lineTo(self.w - 200, self.h)
            p.lineTo(self.w, self.h - 200)
            p.close()
            c.drawPath(p, fill=1, stroke=0)

            # Logo area: CY monogram text
            c.setFillColor(C_SKY)
            c.setFont("Helvetica-Bold", 52)
            c.drawString(2 * cm, self.h - 3.2 * cm, "CY")
            c.setFillColor(colors.white)
            c.setFont("Helvetica", 52)
            c.drawString(2 * cm + 62, self.h - 3.2 * cm, "CENTRA")
            c.setFillColor(C_SKY)
            c.setFont("Helvetica", 9)
            c.drawString(2 * cm, self.h - 3.7 * cm, "FROM SIGNALS TO STRENGTH")

            # Horizontal divider
            c.setStrokeColor(C_SKY)
            c.setLineWidth(0.8)
            c.line(2 * cm, self.h - 4.1 * cm, self.w - 2 * cm, self.h - 4.1 * cm)

            # Report type label
            c.setFillColor(C_SKY)
            c.setFont("Helvetica-Bold", 13)
            c.drawString(2 * cm, self.h - 4.9 * cm,
                         f"ATTACK SURFACE MANAGEMENT  |  {self.rt.upper()} REPORT")

            # Domain big
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 38)
            c.drawString(2 * cm, self.h - 6.8 * cm, self.domain_)

            # Organisation
            c.setFillColor(C_SKY)
            c.setFont("Helvetica", 11)
            c.drawString(2 * cm, self.h - 7.6 * cm, f"Organisation: {self.org_}")

            # Meta block
            meta_y = self.h - 9.2 * cm
            for label, val in [("Scan ID", self.scan_id_), ("Scan Date", self.scan_date_),
                                ("Prepared By", "CyCentra ASM Engine")]:
                c.setFillColor(C_SKY)
                c.setFont("Helvetica-Bold", 8.5)
                c.drawString(2 * cm, meta_y, label + ":")
                c.setFillColor(colors.white)
                c.setFont("Helvetica", 8.5)
                c.drawString(5.5 * cm, meta_y, val)
                meta_y -= 0.55 * cm

            # Score box
            score_x, score_y = self.w - 6.5 * cm, self.h - 10 * cm
            grade_col = (
                colors.HexColor("#E53E3E") if self.score_ < 30 else
                colors.HexColor("#F6AD55") if self.score_ < 55 else
                colors.HexColor("#ECC94B") if self.score_ < 75 else
                colors.HexColor("#00C9C8") if self.score_ < 90 else
                colors.HexColor("#48BB78")
            )
            c.setFillColor(colors.HexColor("#162d52"))
            c.roundRect(score_x - 0.3 * cm, score_y - 1.8 * cm,
                        4.5 * cm, 3.5 * cm, 8, fill=1, stroke=0)
            c.setFillColor(grade_col)
            c.setFont("Helvetica-Bold", 48)
            c.drawCentredString(score_x + 2 * cm, score_y - 0.3 * cm,
                                str(self.score_))
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 9)
            c.drawCentredString(score_x + 2 * cm, score_y - 0.85 * cm,
                                "SECURITY POSTURE SCORE")
            c.setFillColor(grade_col)
            c.setFont("Helvetica-Bold", 14)
            c.drawCentredString(score_x + 2 * cm, score_y - 1.4 * cm,
                                f"Grade: {self.grade_}")

            # Bottom bar
            c.setFillColor(colors.HexColor("#0d1b2e"))
            c.rect(0, 0, self.w, 1.5 * cm, fill=1, stroke=0)
            c.setFillColor(C_SUBTLE)
            c.setFont("Helvetica", 7)
            c.drawCentredString(self.w / 2, 0.55 * cm,
                                "CONFIDENTIAL — FOR AUTHORISED RECIPIENTS ONLY")

        def wrap(self, aw, ah):
            return (self.w, self.h)

    return [
        CoverCanvas(W, H, report_type, domain, org, scan_id, scan_date,
                    posture_score, posture_grade),
        PageBreak(),
    ]


# ── Score Helpers ─────────────────────────────────────────────────────────────

def compute_posture_score(all_findings: List[Dict], subdomain_count: int,
                          ssl_ok: bool, email_status: str) -> Tuple[int, str]:
    """
    Compute a 0-100 external security posture score.
    Deductions:
      - Critical finding: -12 each (max -48)
      - High finding:     -6  each (max -30)
      - Medium finding:   -2  each (max -16)
      - Low finding:      -0.5 each (max -5)
      - SSL issues:       -10
      - Email weak:       -5
    Bonuses:
      - SSL OK:           +5
      - Email elite/robust: +3
    """
    score = 80  # baseline

    crit  = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "critical")
    high  = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "high")
    med   = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "medium")
    low   = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "low")

    score -= min(crit * 12, 48)
    score -= min(high * 6,  30)
    score -= min(med  * 2,  16)
    score -= min(int(low * 0.5), 5)

    if not ssl_ok:
        score -= 10
    else:
        score += 5

    if email_status == "elite":
        score += 3
    elif email_status in ("basic", "none", ""):
        score -= 5

    score = max(0, min(100, score))

    grade = (
        "A+" if score >= 90 else
        "A"  if score >= 80 else
        "B"  if score >= 70 else
        "C"  if score >= 55 else
        "D"  if score >= 35 else
        "F"
    )
    return score, grade


def extract_domain_scores(results: Dict[str, Any]) -> Dict[str, float]:
    """Derive per-domain scores for the radar chart (0-100, higher = better)."""
    def ok(v): return 100 if v else 30

    email_r = results.get("email_sec", {}).get("results", {})
    ssl_r   = results.get("crypto", {}).get("results", {}).get("ssl", {})
    cloud_r = results.get("cloud", {}).get("results", {})
    dns_r   = results.get("dns",   {}).get("results", {})

    spf_ok   = email_r.get("spf", {}).get("present", False)
    dmarc_ok = email_r.get("dmarc", {}).get("present", False)
    dkim_ok  = bool(email_r.get("dkim", []))
    ssl_ok   = ssl_r.get("ssl_enabled", False)
    buckets  = len(cloud_r.get("buckets", []))
    typos    = len(dns_r.get("typos", {}).get("registered", []))

    return {
        "Email":      min(100, (int(spf_ok) + int(dmarc_ok) + int(dkim_ok)) / 3 * 100),
        "SSL/TLS":    ok(ssl_ok),
        "DNS":        max(10, 100 - typos * 15),
        "Cloud":      max(10, 100 - buckets * 20),
        "Subdomains": max(10, 100 - len(results.get("subdomains", {}).get("results", [])) * 2),
        "Web":        70,  # placeholder; refined by vuln data
    }
