"""
cy_asm/posture_score.py
========================
CyCentra ASM — Single source of truth for the external security posture score.

No ReportLab / matplotlib dependencies. Safe to import from anywhere:
  - cycentra_scan.py              (embeds score in scan JSON)
  - cy_asm/reporting/pdf_base.py  (PDF cover, gauge, KPI strip)
  - blueprints/benchmark/         (CSPI benchmark widget)
  - any future REST endpoint

Formula
-------
Start at 80. Deduct for findings / SSL / weak email. Clamp 0-100.

| Signal                    | Points    | Cap |
|---------------------------|-----------|-----|
| Critical finding          | -12 each  | -48 |
| High finding              | -6 each   | -30 |
| Medium finding            | -2 each   | -16 |
| Low finding               | -0.5 each |  -5 |
| SSL not enabled           | -10       |  —  |
| SSL enabled               | +5        |  —  |
| Email weak / basic / none | -5        |  —  |
| Email elite or robust     | +3        |  —  |

Grades: A+≥90 · A≥80 · B≥70 · C≥55 · D≥35 · F<35
"""
from __future__ import annotations
from typing import Any, Dict, List, Tuple


def compute_posture_score(
    all_findings: List[Dict[str, Any]],
    subdomain_count: int,
    ssl_ok: bool,
    email_status: str,
) -> Tuple[int, str]:
    """Return (score 0-100, grade A+/A/B/C/D/F)."""
    score = 80

    crit = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "critical")
    high = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "high")
    med  = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "medium")
    low  = sum(1 for f in all_findings if str(f.get("severity","")).lower() == "low")

    score -= min(crit * 12, 48)
    score -= min(high * 6,  30)
    score -= min(med  * 2,  16)
    score -= min(int(low * 0.5), 5)

    if not ssl_ok:
        score -= 10
    else:
        score += 5

    status = str(email_status or "").lower()
    if status in ("elite", "robust"):
        score += 3
    elif status in ("basic", "none", ""):
        score -= 5

    score = max(0, min(100, score))
    grade = ("A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70
             else "C" if score >= 55 else "D" if score >= 35 else "F")
    return score, grade


def score_from_portal_json(data: Dict[str, Any]) -> Tuple[int, str]:
    """
    Derive (score, grade) from a portal scan JSON dict.

    Fast path: returns meta.posture_score/grade if already embedded
               (post-patch scans written by cycentra_scan.py).
    Slow path: recomputes from raw data for pre-patch scans on disk.
    """
    meta = data.get("meta") or {}
    cached_score = meta.get("posture_score")
    cached_grade = meta.get("posture_grade")
    if cached_score is not None and cached_grade:
        return int(cached_score), str(cached_grade)

    assets   = data.get("assets") or [{}]
    asset    = assets[0] if assets else {}
    findings = asset.get("vulnerabilities") or []
    if not findings:
        findings = data.get("findings") or data.get("all_findings") or []

    raw       = asset.get("raw_results") or data.get("results") or {}
    ssl_r     = (raw.get("crypto")    or {}).get("results", {}).get("ssl", {})
    email_r   = (raw.get("email_sec") or {}).get("results", {})
    cert_info = ssl_r.get("cert_info", {})
    # Belt-and-suspenders: treat SSL as enabled if the TLS protocol field is
    # populated, even when ssl_enabled was recorded as False in older scan JSONs
    # (pre-patch scans that used the chain_valid && san_valid logic).
    _proto = cert_info.get("protocol", "")
    ssl_ok    = bool(ssl_r.get("ssl_enabled", False)) or bool(
        _proto and _proto not in ("Unknown", "", None)
    )
    email_st  = str(email_r.get("elite_status", "")).lower()
    sub_count = int((data.get("subdomain_summary") or {}).get("total", 0))

    return compute_posture_score(findings, sub_count, ssl_ok, email_st)
