"""
reporting/charts.py
CyCentra ASM — Chart & Visualisation Engine
Generates in-memory PNG images (BytesIO) used by both report types.
All functions return BytesIO objects ready to embed into ReportLab PDFs.
"""
from __future__ import annotations

import io
import math
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")  # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
import numpy as np

# ── Brand palette ─────────────────────────────────────────────────────────────
NAVY        = "#0B1F3A"
BLUE        = "#1E40FF"
SKY         = "#4FB6FF"
TEAL        = "#00C9C8"
RED         = "#E53E3E"
ORANGE      = "#F6AD55"
YELLOW      = "#F6E05E"
GREEN       = "#48BB78"
PURPLE      = "#805AD5"
LIGHT_BG    = "#F7FAFC"
MID_BG      = "#EBF4FF"
GRID_COL    = "#CBD5E0"
TEXT_DARK   = "#1A202C"
TEXT_LIGHT  = "#718096"

SEV_COLORS = {
    "Critical": RED,
    "High":     ORANGE,
    "Medium":   YELLOW,
    "Low":      GREEN,
    "Info":     SKY,
}

def _fig_to_bytes(fig: plt.Figure, dpi: int = 150) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return buf


# ── 1. Security Posture Gauge ─────────────────────────────────────────────────

def posture_gauge(score: int, label: str = "Security Posture") -> io.BytesIO:
    """Half-donut gauge 0-100 with colour zones."""
    fig, ax = plt.subplots(figsize=(5, 3), facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)

    # Background arc
    theta = np.linspace(np.pi, 0, 300)
    r_out, r_in = 1.0, 0.62
    ax.fill_between(np.cos(theta) * r_out, np.sin(theta) * r_out,
                    np.cos(theta) * r_in,  np.sin(theta) * r_in,
                    color=GRID_COL, zorder=1)

    # Colour zones
    zones = [(0, 30, RED), (30, 55, ORANGE), (55, 75, YELLOW), (75, 90, TEAL), (90, 100, GREEN)]
    for lo, hi, col in zones:
        t0 = np.pi * (1 - lo / 100)
        t1 = np.pi * (1 - hi / 100)
        th = np.linspace(t0, t1, 60)
        ax.fill_between(np.cos(th) * r_out, np.sin(th) * r_out,
                        np.cos(th) * r_in,  np.sin(th) * r_in,
                        color=col, zorder=2, alpha=0.85)

    # Needle
    angle = np.pi * (1 - score / 100)
    ax.plot([0, 0.78 * np.cos(angle)], [0, 0.78 * np.sin(angle)],
            color=NAVY, lw=3, zorder=5)
    ax.add_patch(plt.Circle((0, 0), 0.06, color=NAVY, zorder=6))

    # Score text
    grade_col = RED if score < 30 else ORANGE if score < 55 else YELLOW if score < 75 else TEAL if score < 90 else GREEN
    ax.text(0, -0.25, str(score), ha="center", va="center",
            fontsize=34, fontweight="bold", color=grade_col)
    ax.text(0, -0.52, label, ha="center", va="center",
            fontsize=9, color=TEXT_LIGHT)

    ax.set_xlim(-1.15, 1.15)
    ax.set_ylim(-0.65, 1.15)
    ax.axis("off")
    return _fig_to_bytes(fig, dpi=150)


# ── 2. Severity Pie Chart ─────────────────────────────────────────────────────

def severity_pie(counts: Dict[str, int]) -> io.BytesIO:
    labels = [k for k, v in counts.items() if v > 0]
    values = [v for v in counts.values() if v > 0]
    colors = [SEV_COLORS.get(l, SKY) for l in labels]

    fig, ax = plt.subplots(figsize=(4.5, 3.5), facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)
    wedges, texts, autotexts = ax.pie(
        values, labels=None, colors=colors,
        autopct="%1.0f%%", startangle=140,
        wedgeprops=dict(width=0.55, edgecolor="white", linewidth=2),
        pctdistance=0.77, textprops=dict(fontsize=9, color=TEXT_DARK),
    )
    for at in autotexts:
        at.set_fontweight("bold")
    ax.legend(wedges, [f"{l} ({v})" for l, v in zip(labels, values)],
              loc="lower center", bbox_to_anchor=(0.5, -0.18), ncol=3,
              fontsize=8, frameon=False)
    ax.set_title("Findings by Severity", fontsize=10, fontweight="bold",
                 color=NAVY, pad=8)
    return _fig_to_bytes(fig)


# ── 3. Module Bar Chart ───────────────────────────────────────────────────────

def module_bar(module_counts: Dict[str, int]) -> io.BytesIO:
    if not module_counts:
        module_counts = {"No data": 0}
    modules = list(module_counts.keys())
    counts  = list(module_counts.values())
    # Gradient colours
    cols = [plt.cm.Blues(0.4 + 0.5 * i / max(len(modules) - 1, 1)) for i in range(len(modules))]

    fig, ax = plt.subplots(figsize=(6, max(3, len(modules) * 0.45 + 0.8)), facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)
    bars = ax.barh(modules, counts, color=cols, edgecolor="white", linewidth=0.8, height=0.6)
    for bar, val in zip(bars, counts):
        ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=8, color=TEXT_DARK)
    ax.set_xlabel("Issue Count", fontsize=8, color=TEXT_LIGHT)
    ax.set_title("Issues by Module", fontsize=10, fontweight="bold", color=NAVY)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(labelsize=8, colors=TEXT_DARK)
    ax.xaxis.label.set_color(TEXT_LIGHT)
    ax.grid(axis="x", color=GRID_COL, linewidth=0.5, linestyle="--")
    ax.set_axisbelow(True)
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 4. Risk Score Timeline ────────────────────────────────────────────────────

def risk_timeline(findings: List[Dict[str, Any]]) -> io.BytesIO:
    """Scatter plot of risk score per finding, coloured by severity."""
    scores = [f.get("risk_score", 5) for f in findings]
    labels = [f.get("vulnerability", "?")[:18] for f in findings]
    sevs   = [f.get("severity", "Medium") for f in findings]
    cols   = [SEV_COLORS.get(s, SKY) for s in sevs]

    fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)
    x = list(range(len(scores)))
    ax.plot(x, scores, color=SKY, linewidth=1.2, zorder=1, alpha=0.6)
    ax.scatter(x, scores, c=cols, s=60, zorder=2, edgecolors="white", linewidths=0.5)
    ax.axhline(7, color=RED, linestyle="--", linewidth=0.8, alpha=0.7, label="High threshold")
    ax.axhline(4, color=YELLOW, linestyle="--", linewidth=0.8, alpha=0.7, label="Medium threshold")
    ax.set_ylim(0, 10.5)
    ax.set_ylabel("Risk Score (1-10)", fontsize=8, color=TEXT_LIGHT)
    ax.set_title("Risk Score per Finding", fontsize=10, fontweight="bold", color=NAVY)
    ax.set_xticks([])
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color=GRID_COL, linewidth=0.5)
    ax.legend(fontsize=7, frameon=False)
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 5. Subdomain Live/Historical Stacked Bar ──────────────────────────────────

def subdomain_bar(live: int, historical: int, new: int) -> io.BytesIO:
    cats   = ["Live", "Historical", "New"]
    values = [live, historical, new]
    colors = [GREEN, SKY, ORANGE]

    fig, ax = plt.subplots(figsize=(4, 2.8), facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)
    bars = ax.bar(cats, values, color=colors, width=0.45,
                  edgecolor="white", linewidth=1.2)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                str(val), ha="center", fontsize=9, fontweight="bold", color=NAVY)
    ax.set_title("Subdomain Summary", fontsize=10, fontweight="bold", color=NAVY)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.set_ylim(0, max(values + [1]) * 1.25)
    ax.tick_params(labelsize=8)
    ax.yaxis.set_visible(False)
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 6. Security Domain Radar ─────────────────────────────────────────────────

def radar_chart(scores: Dict[str, float]) -> io.BytesIO:
    cats = list(scores.keys())
    vals = [scores[c] for c in cats]
    N = len(cats)
    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]
    vals_plot = vals + vals[:1]

    fig, ax = plt.subplots(figsize=(4.5, 4.5), subplot_kw=dict(polar=True),
                           facecolor=LIGHT_BG)
    ax.set_facecolor(MID_BG)
    ax.plot(angles, vals_plot, color=BLUE, linewidth=2, zorder=3)
    ax.fill(angles, vals_plot, color=SKY, alpha=0.25, zorder=2)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(cats, fontsize=7.5, color=NAVY, fontweight="bold")
    ax.set_ylim(0, 100)
    ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(["25", "50", "75", "100"], fontsize=6, color=TEXT_LIGHT)
    ax.grid(color=GRID_COL, linewidth=0.6)
    ax.spines["polar"].set_visible(False)
    ax.set_title("Security Domain Scores", fontsize=10, fontweight="bold",
                 color=NAVY, pad=18)
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 7. World Map (IP / Cloud Presence) ───────────────────────────────────────

def world_map(country_counts: Dict[str, int]) -> io.BytesIO:
    """Simple world dot-map using matplotlib. No geopandas dependency."""
    COUNTRY_COORDS: Dict[str, Tuple[float, float]] = {
        "US": (-95, 38), "DE": (10, 51), "NL": (5, 52), "GB": (-2, 54),
        "FR": (2, 47), "JP": (138, 36), "CN": (104, 35), "SG": (104, 1),
        "AU": (134, -25), "BR": (-51, -14), "IN": (78, 21), "CA": (-96, 60),
        "RU": (60, 60), "ZA": (25, -29), "NG": (8, 10), "KR": (128, 37),
        "SE": (15, 62), "CH": (8, 47), "IE": (-8, 53), "IT": (12, 43),
        "ES": (-4, 40), "PL": (20, 52), "UA": (32, 49), "TR": (35, 39),
        "MX": (-102, 24), "AR": (-64, -34), "CL": (-71, -35), "CO": (-74, 4),
        "EG": (30, 27), "SA": (45, 24), "AE": (54, 24), "IL": (35, 31),
        "HK": (114, 22), "TW": (121, 24), "ID": (118, -5), "MY": (110, 4),
        "PH": (122, 13), "TH": (101, 15), "VN": (108, 16), "PK": (70, 30),
        "BD": (90, 24), "NZ": (174, -41), "FI": (26, 64), "NO": (10, 62),
        "DK": (10, 56), "AT": (14, 47), "BE": (4, 51), "CZ": (15, 50),
        "PT": (-8, 39), "RO": (25, 46), "HU": (19, 47), "GR": (22, 39),
    }

    fig, ax = plt.subplots(figsize=(8, 4), facecolor=NAVY)
    ax.set_facecolor(NAVY)

    # Simple land outline using rectangular patches (approximation)
    ax.set_xlim(-180, 180)
    ax.set_ylim(-90, 90)

    # Draw a subtle grid as "ocean"
    ax.set_aspect("equal")
    ax.spines[:].set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])

    max_count = max(country_counts.values()) if country_counts else 1
    for code, (lon, lat) in COUNTRY_COORDS.items():
        count = country_counts.get(code, 0)
        if count > 0:
            size  = 80 + 300 * (count / max_count)
            alpha = 0.6 + 0.4 * (count / max_count)
            ax.scatter(lon, lat, s=size, c=SKY, alpha=alpha, zorder=3,
                       edgecolors=BLUE, linewidths=0.8)
            ax.text(lon, lat + 5, code, ha="center", fontsize=5.5,
                    color="white", zorder=4)
        else:
            ax.scatter(lon, lat, s=8, c="#1a3a5c", alpha=0.4, zorder=2)

    ax.set_title("Infrastructure Geographic Distribution", fontsize=9,
                 fontweight="bold", color="white", pad=6)
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 8. SSL / TLS Donut ────────────────────────────────────────────────────────

def ssl_donut(ssl_ok: bool, days_left: Optional[int],
              chain_valid: bool, san_valid: bool) -> io.BytesIO:
    checks = {
        "SSL Valid":   ssl_ok,
        "Chain Valid": chain_valid,
        "SAN Valid":   san_valid,
        "Not Expired": (days_left or 0) > 0,
    }
    pass_n = sum(1 for v in checks.values() if v)
    fail_n = len(checks) - pass_n

    fig, (ax_pie, ax_list) = plt.subplots(1, 2, figsize=(5.5, 3),
                                          facecolor=LIGHT_BG)
    ax_pie.set_facecolor(LIGHT_BG)
    ax_list.set_facecolor(LIGHT_BG)

    ax_pie.pie([pass_n, fail_n], colors=[GREEN, RED],
               wedgeprops=dict(width=0.5, edgecolor="white"),
               startangle=90)
    ax_pie.text(0, 0, f"{pass_n}/{len(checks)}", ha="center", va="center",
                fontsize=18, fontweight="bold",
                color=GREEN if fail_n == 0 else (ORANGE if fail_n <= 1 else RED))
    ax_pie.set_title("SSL Checks", fontsize=9, fontweight="bold", color=NAVY)

    for i, (name, ok) in enumerate(checks.items()):
        sym = "✓" if ok else "✗"
        col = GREEN if ok else RED
        ax_list.text(0.05, 0.8 - i * 0.2, f"{sym}  {name}",
                     fontsize=9, color=col, transform=ax_list.transAxes)
    if days_left is not None:
        ax_list.text(0.05, -0.05, f"Days to expiry: {days_left}",
                     fontsize=8, color=TEXT_LIGHT, transform=ax_list.transAxes)
    ax_list.axis("off")
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 9. Email Security Score Bar ───────────────────────────────────────────────

def email_score_bar(score_str: str, checks: Dict[str, bool]) -> io.BytesIO:
    """Horizontal bar chart for email security checks."""
    names  = list(checks.keys())
    values = [1 if v else 0 for v in checks.values()]
    colors = [GREEN if v else RED for v in values]

    fig, ax = plt.subplots(figsize=(5, max(2.5, len(names) * 0.38 + 0.6)),
                           facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)
    bars = ax.barh(names, [1] * len(names), color=[GRID_COL] * len(names),
                   height=0.5, edgecolor="white")
    for bar, col, val in zip(bars, colors, values):
        ax.barh(bar.get_y() + bar.get_height() / 4,
                val, height=0.5, left=bar.get_x(),
                color=col, alpha=0.85)
        ax.text(1.05, bar.get_y() + bar.get_height() / 2,
                "PASS" if val else "FAIL",
                va="center", fontsize=7.5,
                color=GREEN if val else RED, fontweight="bold")
    ax.set_xlim(0, 1.4)
    ax.set_title(f"Email Security Controls  [{score_str}]",
                 fontsize=9, fontweight="bold", color=NAVY)
    ax.axis("off")
    plt.tight_layout()
    return _fig_to_bytes(fig)


# ── 10. CVSS Distribution Histogram ──────────────────────────────────────────

def cvss_histogram(findings: List[Dict[str, Any]]) -> io.BytesIO:
    scores = [f.get("cvss", f.get("risk_score", 5)) for f in findings if f]
    if not scores:
        scores = [0]
    fig, ax = plt.subplots(figsize=(5.5, 3), facecolor=LIGHT_BG)
    ax.set_facecolor(LIGHT_BG)

    bins = np.arange(0, 11, 1)
    n, _, patches = ax.hist(scores, bins=bins, color=BLUE, edgecolor="white",
                            linewidth=0.8, alpha=0.85)
    # Colour by severity zone
    for patch, left_edge in zip(patches, bins[:-1]):
        if left_edge >= 9:
            patch.set_facecolor(RED)
        elif left_edge >= 7:
            patch.set_facecolor(ORANGE)
        elif left_edge >= 4:
            patch.set_facecolor(YELLOW)
        else:
            patch.set_facecolor(GREEN)
    ax.axvline(np.mean(scores), color=NAVY, linestyle="--", linewidth=1.2,
               label=f"Mean {np.mean(scores):.1f}")
    ax.set_xlabel("CVSS / Risk Score", fontsize=8, color=TEXT_LIGHT)
    ax.set_ylabel("Count", fontsize=8, color=TEXT_LIGHT)
    ax.set_title("CVSS Score Distribution", fontsize=10, fontweight="bold", color=NAVY)
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(labelsize=8)
    ax.legend(fontsize=7.5, frameon=False)
    plt.tight_layout()
    return _fig_to_bytes(fig)
