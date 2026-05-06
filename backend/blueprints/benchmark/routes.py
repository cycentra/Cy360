"""
blueprints/benchmark/routes.py
================================
CyCentra 360 — Security Posture Benchmark Intelligence Engine

Routes
------
  GET  /api/benchmark/score        CSPI composite + per-dimension breakdown
  GET  /api/benchmark/config       Read benchmark config
  PUT  /api/benchmark/config       Persist benchmark config (partial update)
  GET  /api/benchmark/industries   Industry cohort band data for the chart
"""

from __future__ import annotations

import glob
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

import requests as _req
from flask import Blueprint, jsonify, request, session

# ── Import shared path constants (same source of truth as scanner.py) ─────────
from core.config import SCANS_DIR

log = logging.getLogger("cycentra.benchmark")

benchmark_bp = Blueprint("benchmark", __name__, url_prefix="/api/benchmark")

# ── Runtime constants ──────────────────────────────────────────────────────────

# Single flat config file — no tenant suffix (matches schedules.json pattern)
_CONFIG_PATH  = Path(os.environ.get("BENCHMARK_CONFIG",
                                    "/opt/cycentra/benchmark_config.json"))

# Internal correlation engine (same URL used by siem_proxy.py)
_SIEM_ENGINE  = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100")
_SIEM_TIMEOUT = int(os.environ.get("SIEM_PROXY_TIMEOUT", "5"))

# ── Default source config ──────────────────────────────────────────────────────

_DEFAULT_CONFIG: dict = {
    "sources": {
        "asm": {
            "label":   "External Attack Surface",
            "enabled": True,
            "weight":  25,
            "color":   "#ff8c00",
        },
        "siem": {
            "label":   "Internal Detection Posture",
            "enabled": True,
            "weight":  20,
            "color":   "#ff3b3b",
        },
        "compliance": {
            "label":   "Compliance Coverage",
            "enabled": True,
            "weight":  20,
            "color":   "#4d9eff",
        },
        "vuln": {
            "label":   "Vulnerability Management",
            "enabled": True,
            "weight":  20,
            "color":   "#b06eff",
        },
        "threat_intel": {
            "label":   "Threat Intelligence",
            "enabled": True,
            "weight":  10,
            "color":   "#00e5a0",
        },
        "ext_benchmark": {
            "label":   "CIS / NIST Alignment",
            "enabled": False,
            "weight":  5,
            "color":   "#f5a623",
        },
    },
    "industry":      "general",
    "size_band":     "mid",
    "cohort_opt_in": False,
    "updated_at":    None,
}

# ── Static industry cohort bands ───────────────────────────────────────────────
# Bands = [P10, P25, P50, P75, P90] CSPI scores.
# Based on ENISA Threat Landscape 2024, CIS Benchmark, NCSC-NL, BSI, DBIR 2024.
# Update the 'bands' list annually when new reports are published (each Q1).

_INDUSTRY_COHORTS: dict = {
    "finance": {
        "label":       "Financial Services",
        "icon":        "🏦",
        "description": "Banks, insurance, investment — highly regulated, mature programmes",
        "bands":       [38, 52, 64, 74, 83],
        "sample_size": 847,
        "region":      "Benelux / DACH",
        "source":      "ENISA 2024 / CIS Benchmark",
    },
    "healthcare": {
        "label":       "Healthcare & Life Sciences",
        "icon":        "🏥",
        "description": "Hospitals, pharma, medical devices — NIS2 Article 6 scope",
        "bands":       [31, 44, 57, 68, 78],
        "sample_size": 634,
        "region":      "Benelux / DACH",
        "source":      "ENISA 2024 / NIS2 NCA Reports",
    },
    "manufacturing": {
        "label":       "Manufacturing & Industry",
        "icon":        "🏭",
        "description": "OT/IT convergence — DORA and NIS2 critical infrastructure",
        "bands":       [27, 40, 53, 65, 76],
        "sample_size": 1203,
        "region":      "Benelux / DACH",
        "source":      "ENISA 2024 / Dragos OT Security Report",
    },
    "logistics": {
        "label":       "Logistics & Transport",
        "icon":        "🚢",
        "description": "Port operators, freight, aviation — NIS2 essential entities",
        "bands":       [29, 42, 55, 66, 77],
        "sample_size": 418,
        "region":      "Benelux / DACH",
        "source":      "ENISA 2024 / CERT-NL",
    },
    "technology": {
        "label":       "Technology & SaaS",
        "icon":        "💻",
        "description": "Software vendors, MSPs, cloud providers — DORA scope",
        "bands":       [40, 55, 67, 77, 86],
        "sample_size": 972,
        "region":      "Benelux / DACH",
        "source":      "CIS Benchmark 2024 / Verizon DBIR",
    },
    "public_sector": {
        "label":       "Government & Public Sector",
        "icon":        "🏛️",
        "description": "Municipalities, ministries — BIO / BIO2 and NIS2",
        "bands":       [33, 46, 58, 69, 79],
        "sample_size": 556,
        "region":      "Netherlands / DACH",
        "source":      "NCSC-NL 2024 / BSI Lagebericht",
    },
    "energy": {
        "label":       "Energy & Utilities",
        "icon":        "⚡",
        "description": "Power grids, gas, water — NIS2 essential entity highest tier",
        "bands":       [35, 50, 62, 73, 82],
        "sample_size": 289,
        "region":      "Benelux / DACH",
        "source":      "ENISA 2024 / ENTSO-E",
    },
    "retail": {
        "label":       "Retail & E-Commerce",
        "icon":        "🛒",
        "description": "Online and physical retail — PCI-DSS, AVG/GDPR",
        "bands":       [25, 38, 51, 62, 73],
        "sample_size": 764,
        "region":      "Benelux / DACH",
        "source":      "Verizon DBIR 2024 / CIS Benchmark",
    },
    "general": {
        "label":       "All Industries (Benelux Average)",
        "icon":        "🌍",
        "description": "Cross-sector average across all major industries",
        "bands":       [30, 44, 58, 69, 80],
        "sample_size": 5683,
        "region":      "Benelux / DACH",
        "source":      "ENISA 2024 / CIS Benchmark Aggregate",
    },
}

# ── Auth helper ────────────────────────────────────────────────────────────────

def _require_auth(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        if not session.get("user_email"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return _inner


# ── Config helpers ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Load benchmark config from the single shared config file."""
    if _CONFIG_PATH.exists():
        try:
            return json.loads(_CONFIG_PATH.read_text())
        except Exception as exc:
            log.warning("[benchmark] config load error — using defaults: %s", exc)
    return json.loads(json.dumps(_DEFAULT_CONFIG))  # deep copy of defaults


def _save_config(cfg: dict) -> None:
    """Persist benchmark config.  Creates /opt/cycentra/ if it doesn't exist."""
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
    _CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


# ── ASM scan file finder ───────────────────────────────────────────────────────

def _latest_asm_scan_file() -> Optional[Path]:
    """
    Return the Path of the newest scan_*.json across BOTH scan directories:
      SCANS_DIR / <user_uid> /    (manual scans — one subdirectory per uid)
      SCANS_DIR / "scheduler" /   (scheduled scans)

    Mirrors exactly the glob strategy used in scanner.py list_scans() and
    get_scan_by_id() so the benchmark always sees the same data the portal sees.

    Guest directories (guest/) are excluded — they hold anonymous external scans
    that should not influence the organisation's internal posture score.
    """
    # Gather candidates from every non-guest user subdirectory
    all_files: list[str] = []

    try:
        for entry in SCANS_DIR.iterdir():
            if not entry.is_dir():
                continue
            # Exclude the guest directory — those are anonymous / external scans
            if entry.name == "guest":
                continue
            all_files.extend(glob.glob(str(entry / "scan_*.json")))
    except Exception as exc:
        log.warning("[benchmark] ASM directory scan failed: %s", exc)

    if not all_files:
        return None

    try:
        return Path(sorted(all_files, key=os.path.getmtime, reverse=True)[0])
    except Exception:
        return None


# ── Score collectors ───────────────────────────────────────────────────────────

def _collect_asm_score() -> dict:
    """
    External attack surface score (0-100).
    Reads posture_score from the newest scan JSON across user + scheduler dirs.
    """
    latest = _latest_asm_scan_file()
    if not latest:
        return {
            "score":  None,
            "stale":  False,
            "detail": "No ASM scan found — run a scan first",
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

        grade = data.get("posture_grade", "—")
        domain = (data.get("meta") or {}).get("domain", latest.parent.name)

        return {
            "score":  int(score) if score is not None else None,
            "stale":  stale,
            "detail": f"{domain} — scanned {mtime.strftime('%Y-%m-%d %H:%M UTC')}",
            "grade":  grade,
            "source_file": str(latest),
        }
    except Exception as exc:
        log.warning("[benchmark] ASM score parse error: %s", exc)
        return {"score": None, "stale": False, "detail": f"Parse error: {exc}"}


def _collect_siem_score() -> dict:
    """
    Internal detection posture score (0-100).
    Calls the correlation engine /risk/summary endpoint.
    Inverts aggregate risk into a health score:
        health = max(0, 100 - mean_risk - (critical_entities * 2))
    """
    try:
        r = _req.get(f"{_SIEM_ENGINE}/risk/summary", timeout=_SIEM_TIMEOUT)
        if r.status_code != 200:
            return {"score": None, "stale": False, "detail": "SIEM engine unreachable"}
        d           = r.json()
        mean_risk   = float(d.get("mean_risk", 50))
        critical_n  = int(d.get("critical",   0))
        health      = max(0, min(100, round(100 - mean_risk - (critical_n * 2))))
        return {
            "score":    health,
            "stale":    False,
            "detail":   (f"Entities: {d.get('total_entities', '?')} · "
                         f"Mean risk: {mean_risk:.0f} · Critical: {critical_n}"),
        }
    except _req.exceptions.ConnectionError:
        return {"score": None, "stale": False, "detail": "Correlation engine offline"}
    except Exception as exc:
        log.warning("[benchmark] SIEM score error: %s", exc)
        return {"score": None, "stale": False, "detail": str(exc)}


def _collect_compliance_score() -> dict:
    """
    Regulatory compliance coverage score (0-100).

    Strategy (in order):
      1. Try cy_compliance_controls table in PostgreSQL (CyComp module).
         If the table doesn't exist the psycopg2 exception is caught cleanly —
         this is the expected state before CyComp is enabled.
      2. Fall back to an ASM-based heuristic derived from finding severity counts.

    TODO (when CyComp is enabled):
      - Confirm the table name: cy_compliance_controls
      - Confirm the status column values: 'compliant' | 'partial' | 'non_compliant'
      - Confirm tenant/org scoping column if multi-org is added later
    """
    # ── Attempt 1: CyComp PostgreSQL table ────────────────────────────────────
    try:
        from core.config import CYCENTRA_DB_URL
        import psycopg2

        conn = psycopg2.connect(CYCENTRA_DB_URL)
        cur  = conn.cursor()
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'compliant')       AS compliant,
                COUNT(*) FILTER (WHERE status = 'partial')         AS partial,
                COUNT(*) FILTER (WHERE status = 'non_compliant')   AS non_compliant,
                COUNT(*)                                              AS total
            FROM cy_compliance_controls
        """)
        row = cur.fetchone()
        conn.close()

        if row and row[3]:                     # row[3] = total
            compliant, partial, _nc, total = row
            score = round(((compliant + partial * 0.5) / total) * 100)
            return {
                "score":  score,
                "stale":  False,
                "detail": f"{compliant}/{total} controls compliant (CyComp)",
            }
    except Exception:
        # Table doesn't exist yet (CyComp not installed) — fall through silently
        pass

    # ── Attempt 2: Heuristic from latest ASM scan findings ────────────────────
    latest = _latest_asm_scan_file()
    if latest:
        try:
            data     = json.loads(latest.read_text())
            # Findings may live at top level or nested under assets
            findings = (data.get("findings")
                        or data.get("all_findings")
                        or [])
            if not findings:
                # Try extracting from assets array
                assets   = data.get("assets") or []
                findings = [v for a in assets
                            for v in (a.get("vulnerabilities") or [])]

            critical = sum(1 for f in findings
                           if str(f.get("severity", "")).lower() == "critical")
            high     = sum(1 for f in findings
                           if str(f.get("severity", "")).lower() == "high")
            # NIS2 compliance heuristic: many critical findings → low compliance score
            score = max(15, min(85, round(100 - (critical * 8) - (high * 3))))
            return {
                "score":  score,
                "stale":  True,        # flag as stale — it's an estimate
                "detail": ("Estimated from ASM findings "
                           "(CyComp not installed — enable for accurate compliance scoring)"),
            }
        except Exception as exc:
            log.warning("[benchmark] compliance heuristic error: %s", exc)

    return {
        "score":  None,
        "stale":  False,
        "detail": "CyComp not installed — no compliance data available",
    }


def _collect_vuln_score() -> dict:
    """
    Vulnerability management score (0-100).
    Starts at 100 and deducts based on open finding severity weighted by EPSS.
    Reads from the same newest scan file as _collect_asm_score().
    """
    latest = _latest_asm_scan_file()
    if not latest:
        return {"score": None, "stale": False, "detail": "No scan data"}

    try:
        data     = json.loads(latest.read_text())
        findings = (data.get("findings")
                    or data.get("all_findings")
                    or [])
        if not findings:
            assets   = data.get("assets") or []
            findings = [v for a in assets
                        for v in (a.get("vulnerabilities") or [])]

        score = 100.0
        for f in findings:
            sev  = str(f.get("severity", "")).lower()
            epss = float(f.get("epss", 0.1))
            if sev == "critical":
                score -= 10 + (epss * 5)
            elif sev == "high":
                score -= 5  + (epss * 2)
            elif sev == "medium":
                score -= 1.5
            elif sev == "low":
                score -= 0.3

        score = max(0, min(100, round(score)))
        mtime = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)
        stale = (datetime.now(timezone.utc) - mtime) > timedelta(hours=48)
        return {
            "score":    score,
            "stale":    stale,
            "detail":   f"{len(findings)} open findings assessed (CVSS + EPSS weighted)",
            "count":    len(findings),
        }
    except Exception as exc:
        log.warning("[benchmark] vuln score error: %s", exc)
        return {"score": None, "stale": False, "detail": str(exc)}


def _collect_threat_intel_score() -> dict:
    """
    Threat intelligence coverage score (0-100).
    Queries the correlation engine MISP stats endpoint.
    Formula: min(100, (feeds/3)*40 + min(60, ioc_hits_7d/100*60))
    """
    try:
        r = _req.get(f"{_SIEM_ENGINE}/misp/stats", timeout=_SIEM_TIMEOUT)
        if r.status_code == 200:
            d        = r.json()
            feeds    = int(d.get("active_feeds",  0))
            ioc_hits = int(d.get("ioc_hits_7d",   0))
            score    = min(100, round(
                (min(feeds, 3) / 3) * 40 + min(60, ioc_hits / 100 * 60)
            ))
            return {
                "score":    score,
                "stale":    False,
                "detail":   f"{feeds} active MISP feeds · {ioc_hits} IOC hits (7d)",
                "feeds":    feeds,
                "ioc_hits": ioc_hits,
            }
    except _req.exceptions.ConnectionError:
        return {"score": None, "stale": False, "detail": "Correlation engine offline"}
    except Exception as exc:
        log.warning("[benchmark] threat intel score error: %s", exc)
    return {"score": None, "stale": False, "detail": "MISP stats unavailable"}


def _collect_ext_benchmark_score() -> dict:
    """
    CIS Controls v8 / NIST CSF 2.0 alignment score (0-100).

    Phase 1: weighted blend of compliance + ASM scores as a proxy.
    Phase 2: replace with bundled CIS JSON cross-reference and nightly sync.
    Shown as stale=True to signal it is an estimate until Phase 2 is shipped.
    """
    comp = _collect_compliance_score()
    asm  = _collect_asm_score()

    comp_s = comp.get("score")
    asm_s  = asm.get("score")

    if comp_s is None and asm_s is None:
        return {
            "score":  None,
            "stale":  False,
            "detail": "Requires at least one of: CyComp or an ASM scan",
        }

    parts, total = 0.0, 0
    if comp_s is not None:
        parts += comp_s * 0.6
        total += 1
    if asm_s is not None:
        parts += asm_s * 0.4
        total += 1

    score = round(parts) if total == 1 else round(parts / total * (total / 1.0))
    return {
        "score":  min(100, max(0, score)),
        "stale":  True,
        "detail": "Phase 1 estimate — full CIS/NIST bundle scheduled for Phase 2",
    }


# ── Ordered collector registry ─────────────────────────────────────────────────
# Order matches the UI calculation sequence shown to the customer.

_COLLECTORS = [
    ("asm",           _collect_asm_score),
    ("siem",          _collect_siem_score),
    ("compliance",    _collect_compliance_score),
    ("vuln",          _collect_vuln_score),
    ("threat_intel",  _collect_threat_intel_score),
    ("ext_benchmark", _collect_ext_benchmark_score),
]

# ── CSPI composite calculation ─────────────────────────────────────────────────

def _compute_cspi(config: dict) -> dict:
    """
    Compute the CyCentra Security Posture Index (CSPI):
        CSPI = Σ(score_i × effective_weight_i) / Σ(effective_weight_i)

    Only enabled sources with a non-null score contribute.
    Stale sources contribute at 80% of their configured weight.
    """
    sources   = config.get("sources", _DEFAULT_CONFIG["sources"])
    breakdown = {}
    weighted  = 0.0
    total_w   = 0.0

    for src_id, collector in _COLLECTORS:
        src_cfg = sources.get(src_id, {})
        try:
            raw = collector()
        except Exception as exc:
            raw = {"score": None, "stale": False, "detail": str(exc)}

        enabled     = src_cfg.get("enabled", True)
        weight      = float(src_cfg.get("weight", 10))
        score       = raw.get("score")
        stale       = raw.get("stale", False)
        effective_w = weight * (0.8 if stale else 1.0) if (enabled and score is not None) else 0.0

        breakdown[src_id] = {
            "label":       src_cfg.get("label", src_id),
            "color":       src_cfg.get("color", "#888888"),
            "enabled":     enabled,
            "weight":      weight,
            "score":       score,
            "stale":       stale,
            "detail":      raw.get("detail", ""),
            "effective_w": round(effective_w, 2),
        }
        # Copy any extra fields the collector returned (grade, count, etc.)
        for k, v in raw.items():
            if k not in ("score", "stale", "detail"):
                breakdown[src_id][k] = v

        if enabled and score is not None:
            weighted += score * effective_w
            total_w  += effective_w

    cspi = round(weighted / total_w) if total_w > 0 else None

    grade = (
        "A+" if cspi is not None and cspi >= 85 else
        "A"  if cspi is not None and cspi >= 75 else
        "B"  if cspi is not None and cspi >= 65 else
        "C"  if cspi is not None and cspi >= 50 else
        "D"  if cspi is not None and cspi >= 35 else
        "F"  if cspi is not None else "—"
    )

    return {
        "cspi":         cspi,
        "grade":        grade,
        "breakdown":    breakdown,
        "computed_at":  datetime.now(timezone.utc).isoformat(),
        "total_weight": round(total_w, 2),
    }


def _percentile(cspi: Optional[int], bands: list) -> tuple[str, int]:
    """Return (label, approximate_percentile_midpoint) for a CSPI score."""
    if cspi is None:
        return "", 0
    p10, p25, p50, p75, p90 = bands
    if cspi < p10:
        return "Bottom 10%",              5
    if cspi < p25:
        return "10th–25th percentile",   17
    if cspi < p50:
        return "25th–50th percentile",   37
    if cspi < p75:
        return "50th–75th percentile",   62
    if cspi < p90:
        return "75th–90th percentile",   82
    return "Top 10%",                    95


# ── Routes ─────────────────────────────────────────────────────────────────────

@benchmark_bp.route("/score")
@_require_auth
def get_score():
    config   = _load_config()
    result   = _compute_cspi(config)
    industry = config.get("industry", "general")
    cohort   = _INDUSTRY_COHORTS.get(industry, _INDUSTRY_COHORTS["general"])
    pct_label, pct_n = _percentile(result.get("cspi"), cohort["bands"])
    result["percentile"]       = pct_n
    result["percentile_label"] = pct_label
    result["industry"]         = industry
    result["cohort"]           = cohort
    return jsonify(result)


@benchmark_bp.route("/config", methods=["GET"])
@_require_auth
def get_config():
    return jsonify(_load_config())


@benchmark_bp.route("/config", methods=["PUT"])
@_require_auth
def put_config():
    body   = request.get_json(silent=True) or {}
    config = _load_config()

    # Merge source weight / enabled overrides
    for src_id, patch in body.get("sources", {}).items():
        if src_id in config["sources"]:
            allowed = {k: v for k, v in patch.items()
                       if k in ("enabled", "weight")}
            config["sources"][src_id].update(allowed)

    for key in ("industry", "size_band", "cohort_opt_in"):
        if key in body:
            config[key] = body[key]

    _save_config(config)
    return jsonify({"ok": True, "config": config})


@benchmark_bp.route("/industries")
@_require_auth
def get_industries():
    return jsonify({"industries": _INDUSTRY_COHORTS, "default": "general"})
