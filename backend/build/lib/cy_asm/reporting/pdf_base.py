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
# Primary brand palette — kept in sync with portal CSS variables
C_NAVY    = colors.HexColor("#0d1b2a")   # deep navy background / headers
C_BLUE    = colors.HexColor("#1565c0")   # section headers
C_SKY     = colors.HexColor("#4FB6FF")   # accent info / captions
C_TEAL    = colors.HexColor("#00C9C8")   # teal accent
C_RED     = colors.HexColor("#e53935")   # critical severity
C_ORANGE  = colors.HexColor("#ff8c00")   # high severity
C_YELLOW  = colors.HexColor("#ECC94B")   # medium severity
C_GREEN   = colors.HexColor("#00e5a0")   # brand green / low severity / positive
C_PURPLE  = colors.HexColor("#805AD5")   # purple accent
C_LIGHT   = colors.HexColor("#F7FAFC")   # card background
C_MID     = colors.HexColor("#EBF4FF")   # mid-tone fill
C_BORDER  = colors.HexColor("#CBD5E0")   # subtle borders
C_TEXT    = colors.HexColor("#1A202C")   # body text
C_SUBTLE  = colors.HexColor("#718096")   # muted / footer text

SEV_COLOR = {
    "Critical":     C_RED,
    "High":         C_ORANGE,
    "Medium":       C_YELLOW,
    "Low":          C_GREEN,
    "Info":         C_SKY,
    "Informational": C_SKY,
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
        fontName="Helvetica-Bold", fontSize=28, textColor=colors.white,
        leading=34, alignment=TA_LEFT, spaceAfter=6)

    s["cover_sub"] = ps("cover_sub",
        fontName="Helvetica", fontSize=16, textColor=C_SKY,
        leading=20, alignment=TA_LEFT, spaceAfter=4)

    s["cover_meta"] = ps("cover_meta",
        fontName="Helvetica", fontSize=10, textColor=colors.white,
        leading=14, alignment=TA_LEFT)

    # Section h1: uppercase with extra space — companion to section_header() colored bar
    s["h1"] = ps("h1",
        fontName="Helvetica-Bold", fontSize=14, textColor=C_NAVY,
        leading=18, spaceBefore=16, spaceAfter=4, textTransform="uppercase")

    s["h2"] = ps("h2",
        fontName="Helvetica-Bold", fontSize=11, textColor=C_BLUE,
        leading=15, spaceBefore=10, spaceAfter=3)

    s["h3"] = ps("h3",
        fontName="Helvetica-Bold", fontSize=10, textColor=C_NAVY,
        leading=14, spaceBefore=8, spaceAfter=3)

    # Body: 10pt with 1.4 line-height (14pt leading)
    s["body"] = ps("body",
        fontName="Helvetica", fontSize=10, textColor=C_TEXT,
        leading=14, spaceAfter=4, alignment=TA_JUSTIFY)

    s["body_small"] = ps("body_small",
        fontName="Helvetica", fontSize=8.5, textColor=C_SUBTLE,
        leading=12, spaceAfter=3)

    s["bullet"] = ps("bullet",
        fontName="Helvetica", fontSize=9, textColor=C_TEXT,
        leading=13, leftIndent=14, spaceAfter=2,
        bulletIndent=0, bulletText="•")

    # Finding title: bold 10pt
    s["finding_title"] = ps("finding_title",
        fontName="Helvetica-Bold", fontSize=10, textColor=C_NAVY,
        leading=14, spaceAfter=2)

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

    # Callout box text (used for scan-type upsell notices)
    s["callout"] = ps("callout",
        fontName="Helvetica-Oblique", fontSize=9, textColor=C_BLUE,
        leading=13, spaceAfter=4, alignment=TA_LEFT)

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


class _LeftBarFlowable(Flowable):
    """A colored left-border bar rendered behind the section title text."""
    def __init__(self, title: str, bar_color=None, width: float = None):
        super().__init__()
        self.title     = title
        self.bar_color = bar_color or C_GREEN
        self._width    = width or BODY_W
        self._height   = 0.55 * cm

    def wrap(self, aw, ah):
        self.width  = min(aw, self._width)
        self.height = self._height
        return self.width, self.height

    def draw(self):
        c = self.canv
        # Left accent bar
        c.setFillColor(self.bar_color)
        c.rect(0, 0, 4, self.height, fill=1, stroke=0)
        # Light background
        c.setFillColor(colors.HexColor("#F0F4F8"))
        c.rect(4, 0, self.width - 4, self.height, fill=1, stroke=0)
        # Title text
        c.setFillColor(C_NAVY)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(10, 0.14 * cm, self.title.upper())


def section_header(title: str, subtitle: str = "", accent=None) -> List:
    """Returns flowables for a branded section header with a colored left bar."""
    bar_color = accent or C_GREEN
    items: List = [
        Spacer(1, 8),
        _LeftBarFlowable(title, bar_color=bar_color),
    ]
    if subtitle:
        items.append(Paragraph(subtitle, STYLES["body_small"]))
    items.append(Spacer(1, 6))
    return items


def callout_box(text: str, accent=None) -> Table:
    """A bordered callout box for upsell notices or scan-type notes."""
    _color = accent or C_BLUE
    cell = Paragraph(text, STYLES["callout"])
    t = Table([[cell]], colWidths=[BODY_W])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#EBF4FF")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("BOX",          (0, 0), (-1, -1), 1, _color),
        ("LINEAFTER",    (0, 0), (0, -1),  3, _color),
    ]))
    return t


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


# ── Logo resolver — tries known paths in preference order ────────────────────
_LOGO_CANDIDATES = [
    "/var/www/cycentra360/logo.png",
    "/var/www/cycentra360/logo-light.png",
    "/opt/cycentra/logo.png",
    "/var/www/cycentra360/favicon-192.png",
    "/var/www/cycentra360/favicon-96.png",
    "/var/www/cycentra360/favicon-32x32.png",
    # Bundled fallback — always present in the source tree after deployment
    "/opt/cycentra/backend/cy_asm/modules/cylogo/favicons/android-chrome-192x192.png",
    "/opt/cycentra/backend/cy_asm/modules/cylogo/favicons/apple-touch-icon.png",
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
            # Full dark background
            c.setFillColor(C_NAVY)
            c.rect(0, 0, self.w, self.h, fill=1, stroke=0)
            # Accent panel left strip
            c.setFillColor(C_BLUE)
            c.rect(0, 0, 6 * mm, self.h, fill=1, stroke=0)
            # Diagonal accent top-right
            c.setFillColor(colors.HexColor("#162d52"))
            p = c.beginPath()
            p.moveTo(self.w, self.h)
            p.lineTo(self.w - 200, self.h)
            p.lineTo(self.w, self.h - 200)
            p.close()
            c.drawPath(p, fill=1, stroke=0)

            # ── Logo area ─────────────────────────────────────────────────────
            logo_top_y   = self.h - 1.8 * cm   # top of logo zone
            logo_height  = 1.4 * cm             # target height for the logo image
            text_label_y = self.h - 3.7 * cm   # tagline below logo

            if _logo_path:
                try:
                    # Load logo; convert ICO → PNG bytes if needed
                    if _logo_path.lower().endswith(".ico"):
                        from PIL import Image as PILImage
                        import io as _io
                        pil_img = PILImage.open(_logo_path)
                        # Use the largest size in the ICO if available
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
                        2 * cm,
                        logo_top_y - logo_height,
                        width=logo_w,
                        height=logo_height,
                        mask="auto",
                    )
                    # "CYCENTRA" wordmark next to logo
                    wordmark_x = 2 * cm + logo_w + 0.35 * cm
                    c.setFillColor(C_SKY)
                    c.setFont("Helvetica-Bold", 28)
                    c.drawString(wordmark_x, logo_top_y - 0.85 * cm, "CY")
                    c.setFillColor(colors.white)
                    c.setFont("Helvetica", 28)
                    c.drawString(wordmark_x + 34, logo_top_y - 0.85 * cm, "CENTRA")
                except Exception:
                    # Fall back to text-only branding on any logo load error
                    c.setFillColor(C_SKY)
                    c.setFont("Helvetica-Bold", 52)
                    c.drawString(2 * cm, self.h - 3.2 * cm, "CY")
                    c.setFillColor(colors.white)
                    c.setFont("Helvetica", 52)
                    c.drawString(2 * cm + 62, self.h - 3.2 * cm, "CENTRA")
            else:
                # Text-only branding
                c.setFillColor(C_SKY)
                c.setFont("Helvetica-Bold", 52)
                c.drawString(2 * cm, self.h - 3.2 * cm, "CY")
                c.setFillColor(colors.white)
                c.setFont("Helvetica", 52)
                c.drawString(2 * cm + 62, self.h - 3.2 * cm, "CENTRA")

            c.setFillColor(C_SKY)
            c.setFont("Helvetica", 9)
            c.drawString(2 * cm, text_label_y, "FROM SIGNALS TO STRENGTH")

            # Horizontal divider
            c.setStrokeColor(C_SKY)
            c.setLineWidth(0.8)
            c.line(2 * cm, self.h - 4.1 * cm, self.w - 2 * cm, self.h - 4.1 * cm)

            # Report type label — "CyCentra 360" primary title
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 28)
            c.drawString(2 * cm, self.h - 4.9 * cm, "CyCentra 360")

            # Subtitle — "Attack Surface Management Report"
            c.setFillColor(C_SKY)
            c.setFont("Helvetica", 16)
            c.drawString(2 * cm, self.h - 5.7 * cm,
                         f"Attack Surface Management Report  |  {self.rt.upper()}")

            # Domain big
            c.setFillColor(colors.white)
            c.setFont("Helvetica-Bold", 36)
            # Truncate long domains so they don't overflow the page
            _domain_display = self.domain_ if len(self.domain_) <= 38 else self.domain_[:35] + "..."
            c.drawString(2 * cm, self.h - 7.2 * cm, _domain_display)

            # Organisation
            c.setFillColor(C_SKY)
            c.setFont("Helvetica", 11)
            c.drawString(2 * cm, self.h - 8.0 * cm, f"Organisation: {self.org_}")

            # Meta block
            meta_y = self.h - 9.6 * cm
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
# Single source of truth: cy_asm/posture_score.py
# Uses try/except import chain because pdf_base.py is loaded in two different
# sys.path contexts:
#   - via cycentra_scan.py / generate_reports.py: sys.path has backend/cy_asm/
#     so posture_score is importable directly as 'posture_score'
#   - via Flask benchmark blueprint: sys.path has backend/
#     so it is importable as 'cy_asm.posture_score'
try:
    from posture_score import compute_posture_score          # cycentra_scan context
except ImportError:
    from cy_asm.posture_score import compute_posture_score   # Flask context

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
