"""
PATCH 5 (FINAL) — Single source of truth for ASM posture score
===============================================================
Cross-checked against post-git-sync repo state. All search strings verified.

KEY FIX vs previous version
-----------------------------
pdf_base.py lives at backend/cy_asm/reporting/pdf_base.py and uses relative
imports. The import of posture_score must therefore also be relative:
    from ..posture_score import compute_posture_score

cycentra_scan.py runs from backend/cy_asm/ so the import there is simply:
    from posture_score import score_from_portal_json

benchmark/routes.py runs in Flask context (sys.path = backend/) so:
    from cy_asm.posture_score import score_from_portal_json

Run from repo root:
    python3 benchmark-patch/PATCH_5_asm_posture_refactor.py
"""

import pathlib, sys

ROOT = pathlib.Path(".")

# ── FILE 1: posture_score.py ──────────────────────────────────────────────────

POSTURE_SCORE_PY = '''\
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
    ssl_ok    = bool(ssl_r.get("ssl_enabled", False))
    email_st  = str(email_r.get("elite_status", "")).lower()
    sub_count = int((data.get("subdomain_summary") or {}).get("total", 0))

    return compute_posture_score(findings, sub_count, ssl_ok, email_st)
'''

# ── FILE 2: pdf_base.py — relative import replaces local def ─────────────────

PDF_BASE_IMPORT_BLOCK = """\
# ── Score Helpers ─────────────────────────────────────────────────────────────
# Single source of truth: cy_asm/posture_score.py
# Relative import works from all callers (cycentra_scan.py, Flask, CLI).
from ..posture_score import compute_posture_score

"""

# ── FILE 3: cycentra_scan.py — embed score before json.dump ──────────────────
# Import is plain 'from posture_score import ...' because cycentra_scan.py
# runs from inside backend/cy_asm/ where posture_score.py lives directly.

SCAN_FIND = """\
        with open(portal_file, "w") as pf:
            json.dump(portal_payload, pf, indent=2)

        logger.info(f"\u2705 Portal JSON saved \u2192 {portal_file}")"""

SCAN_REPLACE = """\
        # ── Embed posture score in scan JSON before writing to disk ──────────
        # Single source of truth: cy_asm/posture_score.py
        try:
            from posture_score import score_from_portal_json as _score_fn
            _pscore, _pgrade = _score_fn(portal_payload)
            portal_payload["meta"]["posture_score"] = _pscore
            portal_payload["meta"]["posture_grade"] = _pgrade
            logger.info(f"\u2705 [Posture] Score embedded: {_pscore} ({_pgrade})")
        except Exception as _score_err:
            logger.warning(f"\u26a0\ufe0f [Posture] Score embedding skipped (scan unaffected): {_score_err}")

        with open(portal_file, "w") as pf:
            json.dump(portal_payload, pf, indent=2)

        logger.info(f"\u2705 Portal JSON saved \u2192 {portal_file}")"""

# ── FILE 4: benchmark/routes.py — read from meta, fallback to import ─────────
# Flask sys.path = backend/ so absolute import: from cy_asm.posture_score import ...

BENCHMARK_FIND = """\
def _collect_asm_score() -> dict:
    \"\"\"
    External attack surface score (0-100).
    Reads posture_score from the newest scan JSON across user + scheduler dirs.
    \"\"\"
    latest = _latest_asm_scan_file()
    if not latest:
        return {
            "score":  None,
            "stale":  False,
            "detail": "No ASM scan found \u2014 run a scan first",
        }

    try:
        mtime = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)
        stale = (datetime.now(timezone.utc) - mtime) > timedelta(hours=48)
        data  = json.loads(latest.read_text())

        # posture_score lives at top level in the portal JSON
        score = data.get("posture_score")
        if score is None:
            score = data.get("score")
        if score is None:
            score = (data.get("summary") or {}).get("posture_score")

        grade = data.get("posture_grade", "\u2014")
        domain = (data.get("meta") or {}).get("domain", latest.parent.name)

        return {
            "score":  int(score) if score is not None else None,
            "stale":  stale,
            "detail": f"{domain} \u2014 scanned {mtime.strftime('%Y-%m-%d %H:%M UTC')}",
            "grade":  grade,
            "source_file": str(latest),
        }
    except Exception as exc:
        log.warning("[benchmark] ASM score parse error: %s", exc)
        return {"score": None, "stale": False, "detail": f"Parse error: {exc}"}"""

BENCHMARK_REPLACE = """\
def _collect_asm_score() -> dict:
    \"\"\"
    External attack surface score (0-100).

    Primary:  reads meta.posture_score embedded by cycentra_scan.py
              (post-patch scans — available immediately after this patch).
    Fallback: calls score_from_portal_json() for pre-patch scans on disk.

    Single source of truth: backend/cy_asm/posture_score.py
    \"\"\"
    latest = _latest_asm_scan_file()
    if not latest:
        return {
            "score":  None,
            "stale":  False,
            "detail": "No ASM scan found \u2014 run a scan first",
        }

    try:
        mtime  = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)
        stale  = (datetime.now(timezone.utc) - mtime) > timedelta(hours=48)
        data   = json.loads(latest.read_text())
        meta   = data.get("meta") or {}
        domain = meta.get("domain", latest.parent.name)

        score = meta.get("posture_score")
        grade = meta.get("posture_grade", "\u2014")

        if score is None:
            try:
                from cy_asm.posture_score import score_from_portal_json
                score, grade = score_from_portal_json(data)
            except Exception as _fb:
                log.warning("[benchmark] ASM score fallback failed: %s", _fb)

        return {
            "score":  int(score) if score is not None else None,
            "stale":  stale,
            "grade":  grade,
            "detail": f"{domain} \u2014 grade {grade} \u2014 scanned {mtime.strftime('%Y-%m-%d %H:%M UTC')}",
        }
    except Exception as exc:
        log.warning("[benchmark] ASM score parse error: %s", exc)
        return {"score": None, "stale": False, "detail": f"Parse error: {exc}"}"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _str_replace(path, find, replace, label):
    content = path.read_text()
    if find not in content:
        print(f"  \u2717  {label} \u2014 search string not found")
        for i, line in enumerate(content.splitlines(), 1):
            if "posture_score" in line or "json.dump" in line:
                print(f"     line {i}: {line[:100]}")
        return False
    path.write_text(content.replace(find, replace, 1))
    print(f"  \u2713  {label}")
    return True


def _patch_pdf_base(path):
    content = path.read_text()
    if "from ..posture_score import compute_posture_score" in content:
        print("  \u2713  pdf_base.py already patched")
        return True
    lines = content.splitlines(keepends=True)
    header_idx = next((i for i, l in enumerate(lines) if "# \u2500\u2500 Score Helpers" in l), None)
    if header_idx is None:
        print("  \u2717  pdf_base.py: Score Helpers header not found")
        return False
    func_start = next((i for i in range(header_idx, len(lines))
                       if lines[i].startswith("def compute_posture_score")), None)
    if func_start is None:
        print("  \u2717  pdf_base.py: def compute_posture_score not found")
        return False
    func_end = next((i for i in range(func_start + 1, len(lines))
                     if lines[i] and (lines[i].startswith("def ") or lines[i].startswith("class "))),
                    len(lines))
    path.write_text("".join(lines[:header_idx]) + PDF_BASE_IMPORT_BLOCK + "".join(lines[func_end:]))
    print("  \u2713  pdf_base.py: replaced local def with relative import")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ok = True

    print("\n\u2500\u2500 Step 1: Create backend/cy_asm/posture_score.py")
    dest = ROOT / "backend/cy_asm/posture_score.py"
    if not dest.parent.exists():
        print(f"  \u2717  {dest.parent} not found \u2014 run from repo root"); sys.exit(1)
    dest.write_text(POSTURE_SCORE_PY)
    print(f"  \u2713  {dest}")

    print("\n\u2500\u2500 Step 2: Patch backend/cy_asm/reporting/pdf_base.py")
    pdf = ROOT / "backend/cy_asm/reporting/pdf_base.py"
    ok &= _patch_pdf_base(pdf) if pdf.exists() else (print(f"  \u2717  not found: {pdf}") or False)

    print("\n\u2500\u2500 Step 3: Patch backend/cy_asm/cycentra_scan.py")
    scan = ROOT / "backend/cy_asm/cycentra_scan.py"
    if scan.exists():
        ok &= (print("  \u2713  Already patched") or True) if "score_from_portal_json" in scan.read_text() \
              else _str_replace(scan, SCAN_FIND, SCAN_REPLACE, "embed score before json.dump")
    else:
        print(f"  \u2717  not found: {scan}"); ok = False

    print("\n\u2500\u2500 Step 4: Patch backend/blueprints/benchmark/routes.py")
    bench = ROOT / "backend/blueprints/benchmark/routes.py"
    if bench.exists():
        ok &= (print("  \u2713  Already patched") or True) if "score_from_portal_json" in bench.read_text() \
              else _str_replace(bench, BENCHMARK_FIND, BENCHMARK_REPLACE, "read from meta, fallback import")
    else:
        print(f"  \u2717  not found: {bench}"); ok = False

    print()
    if ok:
        print("\u2705  All patches applied.")
        print()
        print("  Single source of truth:  backend/cy_asm/posture_score.py")
        print()
        print("  \u250c\u2500 cycentra_scan.py      computes + embeds in every scan JSON")
        print("  \u251c\u2500 reporting/pdf_base.py imports via ..posture_score (relative)")
        print("  \u2514\u2500 benchmark/routes.py   reads meta field, fallback to cy_asm.posture_score")
        print()
        print("  To change scoring: edit posture_score.py only.")
        print()
        print("  Restart: pkill -f 'python3 app.py'; cd backend && python3 app.py &")
    else:
        print("\u274c  Some patches failed \u2014 check output above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
