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
# Modern dark-theme palette — inspired by SecuPulse-style reporting
C_NAVY    = colors.HexColor("#0A1628")   # deep navy — primary dark bg
C_DARK2   = colors.HexColor("#0E1E35")   # slightly lighter card bg
C_DARK3   = colors.HexColor("#132847")   # section header bg
C_BLUE    = colors.HexColor("#1A56DB")   # primary accent blue
C_SKY     = colors.HexColor("#00C8FF")   # bright cyan accent
C_TEAL    = colors.HexColor("#00E5A0")   # teal/green accent (CyCentra brand)
C_RED     = colors.HexColor("#E53E3E")   # critical
C_ORANGE  = colors.HexColor("#F97316")   # high
C_YELLOW  = colors.HexColor("#F5A623")   # medium
C_GREEN   = colors.HexColor("#22C55E")   # low / good
C_PURPLE  = colors.HexColor("#8B5CF6")   # info / decorative
C_LIGHT   = colors.HexColor("#0F1F38")   # card background (dark)
C_MID     = colors.HexColor("#16284A")   # alternating row bg
C_BORDER  = colors.HexColor("#1E3A5F")   # border colour (dark theme)
C_TEXT    = colors.HexColor("#E2E8F0")   # primary text (near white)
C_SUBTLE  = colors.HexColor("#7A9DBF")   # secondary text (steel blue-grey)

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
    s = {}

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    s["cover_title"] = ps("cover_title",
        fontName="Helvetica-Bold", fontSize=38, textColor=colors.white,
        leading=44, alignment=TA_LEFT, spaceAfter=8)

    s["cover_sub"] = ps("cover_sub",
        fontName="Helvetica", fontSize=14, textColor=C_TEAL,
        leading=18, alignment=TA_LEFT, spaceAfter=4)

    s["cover_meta"] = ps("cover_meta",
        fontName="Helvetica", fontSize=10, textColor=C_TEXT,
        leading=14, alignment=TA_LEFT)

    # Content headings — light text for dark background
    s["h1"] = ps("h1",
        fontName="Helvetica-Bold", fontSize=15, textColor=C_TEAL,
        leading=20, spaceBefore=20, spaceAfter=6)

    s["h2"] = ps("h2",
        fontName="Helvetica-Bold", fontSize=11.5, textColor=C_SKY,
        leading=16, spaceBefore=12, spaceAfter=4)

    s["h3"] = ps("h3",
        fontName="Helvetica-Bold", fontSize=9.5, textColor=C_TEXT,
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
        bulletIndent=0, bulletText="▸")

    s["finding_title"] = ps("finding_title",
        fontName="Helvetica-Bold", fontSize=9.5, textColor=C_SKY,
        leading=13, spaceAfter=2)

    s["tag"] = ps("tag",
        fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
        alignment=TA_CENTER)

    s["footer"] = ps("footer",
        fontName="Helvetica", fontSize=7, textColor=C_SUBTLE,
        alignment=TA_CENTER)

    s["toc"] = ps("toc",
        fontName="Helvetica", fontSize=9.5, textColor=C_TEXT,
        leading=14, spaceAfter=2)

    s["caption"] = ps("caption",
        fontName="Helvetica-Oblique", fontSize=7.5, textColor=C_SUBTLE,
        alignment=TA_CENTER, spaceAfter=6)

    s["metric_num"] = ps("metric_num",
        fontName="Helvetica-Bold", fontSize=28, textColor=C_TEAL,
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
    """Embed a BytesIO PNG into the PDF.

    Always sets both width AND height explicitly so ReportLab never
    stretches the image to fill an unconstrained table cell.
    """
    buf.seek(0)
    if height is not None:
        return Image(buf, width=width, height=height)
    # Compute proportional height from the image's actual pixel dimensions.
    reader = ImageReader(buf)
    w_px, h_px = reader.getSize()
    computed_height = width * h_px / w_px if w_px else width
    buf.seek(0)
    return Image(buf, width=width, height=computed_height)


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


def metric_card(value: str, label: str, color=C_TEAL) -> Table:
    """KPI card for the executive summary strip — dark theme."""
    val_style = ParagraphStyle("mv", fontName="Helvetica-Bold", fontSize=26,
                               textColor=color, alignment=TA_CENTER, leading=30)
    lbl_style = ParagraphStyle("ml", fontName="Helvetica", fontSize=7,
                               textColor=C_SUBTLE, alignment=TA_CENTER, leading=10)
    t = Table([
        [Paragraph(str(value), val_style)],
        [Paragraph(label, lbl_style)],
    ], colWidths=[3.8 * cm], rowHeights=[1.1 * cm, 0.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_DARK2),
        ("BOX",           (0, 0), (-1, -1), 1.0, color),
        ("LINEBELOW",     (0, 0), (-1, 0),  2.0, color),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (0, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]))
    return t


def section_header(title: str, subtitle: str = "") -> List:
    """Modern dark-theme section header with teal accent bar."""
    items = [
        rule(C_TEAL, thickness=2.5, space_before=14, space_after=0),
        Paragraph(title, STYLES["h1"]),
    ]
    if subtitle:
        items.append(Paragraph(subtitle, STYLES["body_small"]))
    items.append(rule(C_BORDER, thickness=0.3, space_before=2, space_after=12))
    return items


def finding_table(rows: List[List], col_widths: List[float],
                  header: List[str], zebra: bool = True) -> Table:
    """Dark-theme data table with teal/dark branded header."""
    data = [header] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        # Header row
        ("BACKGROUND", (0, 0), (-1, 0), C_DARK3),
        ("TEXTCOLOR",  (0, 0), (-1, 0), C_TEAL),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, 0), 8),
        ("ALIGN",      (0, 0), (-1, 0), "CENTER"),
        ("LINEBELOW",  (0, 0), (-1, 0), 1.5, C_TEAL),
        # Data rows
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME",   (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",   (0, 1), (-1, -1), 7.5),
        ("TEXTCOLOR",  (0, 1), (-1, -1), C_TEXT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [C_LIGHT, C_MID] if zebra else [C_LIGHT]),
        ("GRID",       (0, 0), (-1, -1), 0.25, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
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
        canvas.saveState()
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.restoreState()

    def _draw_header_footer(self, canvas, doc):
        canvas.saveState()
        # Dark page background
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # ── Header bar (dark navy + teal accent) ──────────────────────────────
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, H - 1.15 * cm, W, 1.15 * cm, fill=1, stroke=0)
        # Teal left accent strip
        canvas.setFillColor(C_TEAL)
        canvas.rect(0, H - 1.15 * cm, 5 * mm, 1.15 * cm, fill=1, stroke=0)
        # Sky blue right accent strip
        canvas.setFillColor(C_SKY)
        canvas.rect(W - 5 * mm, H - 1.15 * cm, 5 * mm, 1.15 * cm, fill=1, stroke=0)

        canvas.setFillColor(C_TEAL)
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(MARGIN + 2 * mm, H - 0.72 * cm, "CyCentra ASM")
        canvas.setFillColor(C_SUBTLE)
        canvas.setFont("Helvetica", 8)
        canvas.drawCentredString(W / 2, H - 0.72 * cm,
                                 f"{self.report_type} Report  ·  {self.domain}")
        canvas.setFillColor(C_SKY)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(W - MARGIN - 2 * mm, H - 0.72 * cm,
                               datetime.now().strftime("%d %b %Y"))

        # ── Footer (dark background + teal separator line) ────────────────────
        canvas.setFillColor(C_NAVY)
        canvas.rect(0, 0, W, 1.5 * cm, fill=1, stroke=0)
        canvas.setStrokeColor(C_TEAL)
        canvas.setLineWidth(0.8)
        canvas.line(MARGIN, 1.42 * cm, W - MARGIN, 1.42 * cm)
        canvas.setFillColor(C_SUBTLE)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 0.72 * cm,
                          f"CONFIDENTIAL  |  Scan ID: {self.scan_id}")
        canvas.setFillColor(C_TEAL)
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawRightString(W - MARGIN, 0.72 * cm, f"Page {doc.page}")
        canvas.restoreState()


# ── Logo resolver — tries known paths in preference order ────────────────────
_LOGO_CANDIDATES = [
    "/var/www/cycentra360/logo.png",
    "/var/www/cycentra360/logo-light.png",
    "/opt/cycentra/logo.png",
    "/var/www/cycentra360/favicon-192.png",
    "/var/www/cycentra360/favicon-96.png",
    "/var/www/cycentra360/favicon-32x32.png",
    "/var/www/cycentra360/favicon.ico",
]


def _resolve_logo() -> Optional[str]:
    """Return the first usable logo path, or None if none found."""
    for p in _LOGO_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


# ── Cover Page ────────────────────────────────────────────────────────────────

def build_cover(report_type: str, domain: str, org: str,
                scan_id: str, scan_date: str,
                posture_score: int, posture_grade: str) -> List:
    """Returns a list of flowables that form the full cover page."""

    _logo_path = _resolve_logo()

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
            # ── Background: deep navy ────────────────────────────────────────
            c.setFillColor(C_NAVY)
            c.rect(0, 0, self.w, self.h, fill=1, stroke=0)

            # Subtle diagonal gradient panel (top-right) — dark accent
            c.setFillColor(colors.HexColor("#0E1E35"))
            p = c.beginPath()
            p.moveTo(self.w, self.h)
            p.lineTo(self.w - 280, self.h)
            p.lineTo(self.w, self.h - 280)
            p.close()
            c.drawPath(p, fill=1, stroke=0)

            # Bottom dark bar
            c.setFillColor(colors.HexColor("#060e1c"))
            c.rect(0, 0, self.w, 2.2 * cm, fill=1, stroke=0)

            # Left teal accent strip
            c.setFillColor(C_TEAL)
            c.rect(0, 0, 7 * mm, self.h, fill=1, stroke=0)

            # Secondary cyan thin strip
            c.setFillColor(C_SKY)
            c.rect(7 * mm, 0, 2 * mm, self.h, fill=1, stroke=0)

            # Decorative dot-grid pattern (top-right corner)
            c.setFillColor(colors.HexColor("#1A3060"))
            dot_size, dot_gap = 2, 14
            for xi in range(15):
                for yi in range(12):
                    cx = self.w - 240 + xi * dot_gap
                    cy = self.h - 150 + yi * dot_gap
                    if cx < self.w and cy < self.h:
                        c.circle(cx, cy, dot_size / 2, fill=1, stroke=0)

            # ── Logo / branding area ──────────────────────────────────────────
            logo_top_y  = self.h - 1.8 * cm
            logo_height = 1.4 * cm
            branding_x  = 1.8 * cm

            if _logo_path:
                try:
                    if _logo_path.lower().endswith(".ico"):
                        from PIL import Image as PILImage
                        import io as _io
                        pil_img = PILImage.open(_logo_path)
                        if hasattr(pil_img, "sizes") and pil_img.sizes:
                            best = max(pil_img.sizes, key=lambda s: s[0])
                            pil_img.size = best
                        pil_img = pil_img.convert("RGBA")
                        buf = _io.BytesIO()
                        pil_img.save(buf, format="PNG")
                        buf.seek(0)
                        logo_src = buf
                    else:
                        logo_src = _logo_path

                    reader = ImageReader(logo_src)
                    w_px, h_px = reader.getSize()
                    logo_w = logo_height * w_px / h_px if h_px else logo_height

                    if _logo_path.lower().endswith(".ico"):
                        logo_src.seek(0)

                    c.drawImage(
                        logo_src if _logo_path.lower().endswith(".ico") else _logo_path,
                        branding_x,
                        logo_top_y - logo_height,
                        width=logo_w, height=logo_height, mask="auto",
                    )
                    wordmark_x = branding_x + logo_w + 0.4 * cm
                    c.setFillColor(C_TEAL)
                    c.setFont("Helvetica-Bold", 26)
                    c.drawString(wordmark_x, logo_top_y - 0.85 * cm, "CY")
                    c.setFillColor(colors.white)
                    c.setFont("Helvetica", 26)
                    c.drawString(wordmark_x + 32, logo_top_y - 0.85 * cm, "CENTRA")
                except Exception:
                    c.setFillColor(C_TEAL)
                    c.setFont("Helvetica-Bold", 48)
                    c.drawString(branding_x, self.h - 3.2 * cm, "CY")
                    c.setFillColor(colors.white)
                    c.setFont("Helvetica", 48)
                    c.drawString(branding_x + 58, self.h - 3.2 * cm, "CENTRA")
            else:
                c.setFillColor(C_TEAL)
                c.setFont("Helvetica-Bold", 48)
                c.drawString(branding_x, self.h - 3.2 * cm, "CY")
                c.setFillColor(colors.white)
                c.setFont("Helvetica", 48)
                c.drawString(branding_x + 58, self.h - 3.2 * cm, "CENTRA")

            # Tagline
            c.setFillColor(C_SUBTLE)
            c.setFont("Helvetica", 8)
            c.drawString(branding_x, self.h - 3.7 * cm, "FROM SIGNALS TO STRENGTH")

            # Horizontal divider — teal
            c.setStrokeColor(C_TEAL)
            c.setLineWidth(1.2)
            c.line(branding_x, self.h - 4.0 * cm, self.w - branding_x, self.h - 4.0 * cm)

            # Report type pill label
            c.setFillColor(C_DARK3)
            pill_y = self.h - 4.9 * cm
            c.roundRect(branding_x, pill_y - 0.3 * cm, 9.5 * cm, 0.65 * cm, 4,
                        fill=1, stroke=0)
            c.setFillColor(C_TEAL)
            c.setFont("Helvetica-Bold", 9.5)
            c.drawString(branding_x + 0.25 * cm, pill_y - 0.05 * cm,
                         f"ATTACK SURFACE MANAGEMENT  ·  {self.rt.upper()} REPORT")

            # Domain name — large, white
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 40)
            c.drawString(branding_x, self.h - 6.9 * cm, self.domain_)

            # Organisation + period
            c.setFillColor(C_SKY)
            c.setFont("Helvetica", 11)
            c.drawString(branding_x, self.h - 7.65 * cm, f"Organisation: {self.org_}")

            # ── Meta info block ───────────────────────────────────────────────
            meta_y = self.h - 9.1 * cm
            for label_, val_ in [
                ("Scan ID",     self.scan_id_),
                ("Scan Date",   self.scan_date_),
                ("Prepared By", "CyCentra ASM Engine"),
            ]:
                c.setFillColor(C_SUBTLE)
                c.setFont("Helvetica-Bold", 8)
                c.drawString(branding_x, meta_y, f"{label_}:")
                c.setFillColor(C_TEXT)
                c.setFont("Helvetica", 8)
                c.drawString(branding_x + 3.5 * cm, meta_y, val_)
                meta_y -= 0.55 * cm

            # ── Score box (right side) ────────────────────────────────────────
            grade_col = (
                C_RED    if self.score_ < 30 else
                C_ORANGE if self.score_ < 55 else
                C_YELLOW if self.score_ < 75 else
                C_TEAL   if self.score_ < 90 else
                C_GREEN
            )
            box_x, box_y = self.w - 7 * cm, self.h - 9.8 * cm
            box_w, box_h = 4.8 * cm, 4.0 * cm
            # Shadow effect
            c.setFillColor(colors.HexColor("#040c18"))
            c.roundRect(box_x + 3, box_y - 3, box_w, box_h, 8, fill=1, stroke=0)
            # Main box
            c.setFillColor(C_DARK2)
            c.roundRect(box_x, box_y, box_w, box_h, 8, fill=1, stroke=0)
            # Coloured top border accent
            c.setFillColor(grade_col)
            c.roundRect(box_x, box_y + box_h - 0.3 * cm, box_w, 0.3 * cm, 4,
                        fill=1, stroke=0)
            # Score number
            c.setFillColor(grade_col)
            c.setFont("Helvetica-Bold", 54)
            c.drawCentredString(box_x + box_w / 2, box_y + box_h * 0.44,
                                str(self.score_))
            # Label
            c.setFillColor(C_SUBTLE)
            c.setFont("Helvetica-Bold", 7.5)
            c.drawCentredString(box_x + box_w / 2, box_y + 0.7 * cm,
                                "SECURITY POSTURE SCORE")
            # Grade pill
            c.setFillColor(grade_col)
            c.roundRect(box_x + box_w / 2 - 1.2 * cm, box_y + 0.15 * cm,
                        2.4 * cm, 0.5 * cm, 4, fill=1, stroke=0)
            c.setFillColor(C_NAVY)
            c.setFont("Helvetica-Bold", 9)
            c.drawCentredString(box_x + box_w / 2, box_y + 0.4 * cm,
                                f"Grade  {self.grade_}")

            # ── Bottom confidentiality bar ─────────────────────────────────────
            c.setFillColor(C_SUBTLE)
            c.setFont("Helvetica", 7)
            c.drawCentredString(self.w / 2, 0.72 * cm,
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
