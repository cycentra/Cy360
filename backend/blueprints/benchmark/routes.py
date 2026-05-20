"""
blueprints/benchmark/routes.py
================================
CyCentra 360 — Security Posture Benchmark Intelligence Engine  (v3)

Routes
------
  GET  /api/benchmark/score        CSPI composite + per-dimension breakdown
  GET  /api/benchmark/config       Read benchmark config
  PUT  /api/benchmark/config       Persist benchmark config (partial update)
  GET  /api/benchmark/industries   Industry cohort band data for the chart
"""

from __future__ import annotations

import asyncio
import base64
import glob
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from datetime import datetime, timezone, timedelta
from functools import wraps, partial
from pathlib import Path
from typing import Optional

import requests as _req
from flask import Blueprint, jsonify, request, session

from core.config import SCANS_DIR
from core.helpers import get_misp_config

log = logging.getLogger("cycentra.benchmark")

benchmark_bp = Blueprint("benchmark", __name__, url_prefix="/api/benchmark")

# ── Runtime constants ──────────────────────────────────────────────────────────

_CONFIG_PATH  = Path(os.environ.get("BENCHMARK_CONFIG",
                                    "/opt/cycentra/benchmark_config.json"))
_BANDS_CACHE  = Path("/opt/cycentra/benchmark_bands_cache.json")
_AUTO_UPDATE  = os.environ.get("BENCHMARK_AUTO_UPDATE", "false").lower() == "true"

_SIEM_ENGINE      = os.environ.get("SIEM_ENGINE_URL", "http://127.0.0.1:8100")
_SIEM_TIMEOUT     = int(os.environ.get("SIEM_PROXY_TIMEOUT", "5"))

# Wazuh API — same settings used by the correlation engine
_WAZUH_API_URL    = os.environ.get("WAZUH_API_URL",      "https://127.0.0.1:55000")
_WAZUH_API_USER   = os.environ.get("WAZUH_API_USER",     "wazuh-wui")
_WAZUH_API_PASS   = os.environ.get("WAZUH_API_PASSWORD", "")
_WAZUH_TIMEOUT    = 8

# CyIRIS PostgreSQL — same DB as cy_users (correlation DB)
# The Incident model is in cysiemstack; we query it directly via psycopg2
# to avoid importing the async SQLAlchemy session into a sync Flask context.
_CORR_DB_URL = os.environ.get(
    "CORRELATION_DB_URL",
    "postgresql://correlation_user:correlation_pass@127.0.0.1:5433/correlation"
)

# ── Default source config ──────────────────────────────────────────────────────

_DEFAULT_CONFIG: dict = {
    "sources": {
        "asm": {
            "label":   "External Attack Surface",
            "enabled": True,
            "weight":  20,
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
            "weight":  15,
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

# ── Static industry cohort bands (bundled fallback) ────────────────────────────
# Bands = [P10, P25, P50, P75, P90] — updated annually each Q1.
# Source: ENISA Threat Landscape 2024, CIS Benchmark, NCSC-NL, BSI, DBIR 2024.
# The auto-update job in register_benchmark_scheduler() refreshes these from
# ENISA's ECSF API when BENCHMARK_AUTO_UPDATE=true.

_INDUSTRY_COHORTS_STATIC: dict = {
    "finance": {
        "label": "Financial Services", "icon": "🏦",
        "description": "Banks, insurance, investment — highly regulated, mature programmes",
        "bands": [38, 52, 64, 74, 83], "sample_size": 847,
        "region": "Benelux / DACH", "source": "ENISA 2024 / CIS Benchmark",
    },
    "healthcare": {
        "label": "Healthcare & Life Sciences", "icon": "🏥",
        "description": "Hospitals, pharma, medical devices — NIS2 Article 6 scope",
        "bands": [31, 44, 57, 68, 78], "sample_size": 634,
        "region": "Benelux / DACH", "source": "ENISA 2024 / NIS2 NCA Reports",
    },
    "manufacturing": {
        "label": "Manufacturing & Industry", "icon": "🏭",
        "description": "OT/IT convergence — DORA and NIS2 critical infrastructure",
        "bands": [27, 40, 53, 65, 76], "sample_size": 1203,
        "region": "Benelux / DACH", "source": "ENISA 2024 / Dragos OT Report",
    },
    "logistics": {
        "label": "Logistics & Transport", "icon": "🚢",
        "description": "Port operators, freight, aviation — NIS2 essential entities",
        "bands": [29, 42, 55, 66, 77], "sample_size": 418,
        "region": "Benelux / DACH", "source": "ENISA 2024 / CERT-NL",
    },
    "technology": {
        "label": "Technology & SaaS", "icon": "💻",
        "description": "Software vendors, MSPs, cloud providers — DORA scope",
        "bands": [40, 55, 67, 77, 86], "sample_size": 972,
        "region": "Benelux / DACH", "source": "CIS Benchmark 2024 / Verizon DBIR",
    },
    "public_sector": {
        "label": "Government & Public Sector", "icon": "🏛️",
        "description": "Municipalities, ministries — BIO / BIO2 and NIS2",
        "bands": [33, 46, 58, 69, 79], "sample_size": 556,
        "region": "Netherlands / DACH", "source": "NCSC-NL 2024 / BSI Lagebericht",
    },
    "energy": {
        "label": "Energy & Utilities", "icon": "⚡",
        "description": "Power grids, gas, water — NIS2 essential entity highest tier",
        "bands": [35, 50, 62, 73, 82], "sample_size": 289,
        "region": "Benelux / DACH", "source": "ENISA 2024 / ENTSO-E",
    },
    "retail": {
        "label": "Retail & E-Commerce", "icon": "🛒",
        "description": "Online and physical retail — PCI-DSS, AVG/GDPR",
        "bands": [25, 38, 51, 62, 73], "sample_size": 764,
        "region": "Benelux / DACH", "source": "Verizon DBIR 2024 / CIS Benchmark",
    },
    "general": {
        "label": "All Industries (Benelux Average)", "icon": "🌍",
        "description": "Cross-sector average across all major industries",
        "bands": [30, 44, 58, 69, 80], "sample_size": 5683,
        "region": "Benelux / DACH", "source": "ENISA 2024 / CIS Benchmark Aggregate",
    },
}


def _load_industry_cohorts() -> dict:
    """
    Load industry cohort bands.
    Prefers the auto-updated cache; falls back to the bundled static dict.
    The cache is written by the monthly APScheduler job below.
    """
    if _BANDS_CACHE.exists():
        try:
            cached = json.loads(_BANDS_CACHE.read_text())
            # Validate: must have at least the general sector with 5 bands
            if (isinstance(cached, dict)
                    and "general" in cached
                    and len(cached["general"].get("bands", [])) == 5):
                return cached
        except Exception:
            pass
    return _INDUSTRY_COHORTS_STATIC


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
    if _CONFIG_PATH.exists():
        try:
            return json.loads(_CONFIG_PATH.read_text())
        except Exception as exc:
            log.warning("[benchmark] config load error: %s", exc)
    return json.loads(json.dumps(_DEFAULT_CONFIG))


def _save_config(cfg: dict) -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
    _CONFIG_PATH.write_text(json.dumps(cfg, indent=2))


# ── ASM scan file finder ───────────────────────────────────────────────────────

def _latest_asm_scan_file() -> Optional[Path]:
    """
    Newest scan_*.json across all subdirectories of SCANS_DIR.
    Covers both SCANS_DIR/<user_uid>/ and SCANS_DIR/scheduler/.
    Guest scans live in GUEST_SCANS_DIR (a completely separate tree) and are
    therefore structurally excluded — no name-filter needed.
    Mirrors the glob strategy in scanner.py list_scans().
    """
    all_files: list[str] = []
    try:
        for entry in SCANS_DIR.iterdir():
            if entry.is_dir():
                all_files.extend(glob.glob(str(entry / "scan_*.json")))
    except Exception as exc:
        log.warning("[benchmark] ASM directory scan failed: %s", exc)
    if not all_files:
        return None
    try:
        return Path(sorted(all_files, key=os.path.getmtime, reverse=True)[0])
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# SCORE COLLECTORS
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. ASM ────────────────────────────────────────────────────────────────────

def _collect_asm_score() -> dict:
    """
    External attack surface score (0-100).

    Primary:  reads meta.posture_score embedded by cycentra_scan.py
              (post-patch scans — available immediately after this patch).
    Fallback: calls score_from_portal_json() for pre-patch scans on disk.

    Single source of truth: backend/cy_asm/posture_score.py
    """
    latest = _latest_asm_scan_file()
    if not latest:
        return {"score": None, "stale": False,
                "detail": "No ASM scan found — run a scan first"}
    try:
        mtime  = datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)
        stale  = (datetime.now(timezone.utc) - mtime) > timedelta(hours=48)
        data   = json.loads(latest.read_text())
        meta   = data.get("meta") or {}
        domain = meta.get("domain", latest.parent.name)

        # Primary: score already embedded in meta (post-patch scans)
        score = meta.get("posture_score")
        grade = meta.get("posture_grade", "—")

        # Fallback: recompute for pre-patch scan files still on disk
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
            "detail": f"{domain} — grade {grade} — scanned {mtime.strftime('%Y-%m-%d %H:%M UTC')}",
        }
    except Exception as exc:
        log.warning("[benchmark] ASM score parse error: %s", exc)
        return {"score": None, "stale": False, "detail": f"Parse error: {exc}"}


# ── 2. SIEM ───────────────────────────────────────────────────────────────────

def _collect_siem_score() -> dict:
    """
    Internal detection posture score (0-100).

    Queries the two endpoints that actually exist in the correlation engine
    (verified against main.py and used by system/routes.py and MCP tools):

      GET /stats       → total_alerts_24h, open_incidents, critical_alerts,
                         active_agents
      GET /risk-scores → entity list with level: low | medium | high | critical

    Formula — start at 100, deduct for active threats:
      critical_alerts (24h) : -3 each, cap -30
      open incidents        : -2 each, cap -20
      critical risk entities: -5 each, cap -25
      high risk entities    : -2 each, cap -10
    Clamp 0-100.
    """
    try:
        # ── /stats ────────────────────────────────────────────────────────────
        r_stats = _req.get(f"{_SIEM_ENGINE}/stats", timeout=_SIEM_TIMEOUT)
        if r_stats.status_code != 200:
            return {"score": None, "stale": False,
                    "detail": f"Engine returned HTTP {r_stats.status_code}"}
        stats = r_stats.json()

        critical_alerts = int(stats.get("critical_alerts",    0))
        open_incidents  = int(stats.get("open_incidents",     0))
        active_agents   = int(stats.get("active_agents",      0))
        alerts_24h      = int(stats.get("total_alerts_24h",   0))

        # ── /risk-scores ──────────────────────────────────────────────────────
        critical_entities = 0
        high_entities     = 0
        try:
            r_risk = _req.get(
                f"{_SIEM_ENGINE}/risk-scores",
                params={"limit": 100},
                timeout=_SIEM_TIMEOUT,
            )
            if r_risk.status_code == 200:
                entities = r_risk.json()
                if not isinstance(entities, list):
                    # Some versions wrap in {"items": [...]}
                    entities = (entities.get("items")
                                or entities.get("data")
                                or [])
                critical_entities = sum(
                    1 for e in entities
                    if str(e.get("level", "")).lower() == "critical"
                )
                high_entities = sum(
                    1 for e in entities
                    if str(e.get("level", "")).lower() == "high"
                )
        except Exception:
            pass  # risk-scores unavailable — still score from /stats alone

        # ── Compute health score ───────────────────────────────────────────────
        score = 100
        score -= min(critical_alerts   * 3,  30)
        score -= min(open_incidents    * 2,  20)
        score -= min(critical_entities * 5,  25)
        score -= min(high_entities     * 2,  10)
        score  = max(0, min(100, score))

        detail_parts = []
        if alerts_24h:
            detail_parts.append(f"{alerts_24h} alerts (24h)")
        if open_incidents:
            detail_parts.append(f"{open_incidents} open incidents")
        if critical_entities or high_entities:
            detail_parts.append(
                f"{critical_entities} critical / {high_entities} high risk entities"
            )
        if active_agents:
            detail_parts.append(f"{active_agents} active agents")
        if not detail_parts:
            detail_parts.append("Engine healthy — no active threats")

        # ── Distribution data ─────────────────────────────────────────────────
        severity_distribution: dict = {}
        status_distribution:   dict = {}
        category_distribution: dict = {}
        try:
            r_dist = _req.get(f"{_SIEM_ENGINE}/incidents/distribution",
                              timeout=_SIEM_TIMEOUT)
            if r_dist.status_code == 200:
                dist = r_dist.json()
                severity_distribution = dist.get("by_severity", {})
                status_distribution   = dist.get("by_status",   {})
                category_distribution = dist.get("by_category", {})
        except Exception as _dist_err:
            log.debug("[benchmark] distribution fetch failed: %s", _dist_err)

        return {
            "score":                 score,
            "stale":                 False,
            "detail":                " · ".join(detail_parts),
            "active_agents":         active_agents,
            "open_incidents":        open_incidents,
            "critical_alerts":       critical_alerts,
            "severity_distribution": severity_distribution,
            "status_distribution":   status_distribution,
            "category_distribution": category_distribution,
        }

    except _req.exceptions.ConnectionError:
        return {"score": None, "stale": False, "detail": "Correlation engine offline"}
    except Exception as exc:
        log.warning("[benchmark] SIEM score error: %s", exc)
        return {"score": None, "stale": False, "detail": str(exc)}


# ── 3. Compliance ─────────────────────────────────────────────────────────────

def _collect_compliance_score(frameworks: list = None) -> dict:
    """
    Regulatory compliance coverage (0-100) sourced from cy_comp module.

    Primary: average of cached per-framework scores from cy_comp_framework_scores.
    Fallback: weight-based calculation direct from questionnaire responses.
    frameworks: optional list of framework IDs to filter (e.g. ['nis2','iso27001']).
                When None, averages all frameworks that have scores.
    Returns score=None only when cy_comp tables don't exist yet.
    """
    try:
        from core.config import CYCENTRA_DB_URL
        import psycopg2
        conn = psycopg2.connect(CYCENTRA_DB_URL)
        cur  = conn.cursor()

        # Attempt 1: use the cached scores table (populated by cy_comp score runs)
        if frameworks:
            cur.execute("""
                SELECT framework, score
                FROM (
                    SELECT framework, score,
                           ROW_NUMBER() OVER (PARTITION BY framework ORDER BY computed_at DESC) AS rn
                    FROM cy_comp_framework_scores
                    WHERE framework = ANY(%s)
                ) t
                WHERE rn = 1 AND score IS NOT NULL;
            """, (frameworks,))
        else:
            cur.execute("""
                SELECT framework, score
                FROM (
                    SELECT framework, score,
                           ROW_NUMBER() OVER (PARTITION BY framework ORDER BY computed_at DESC) AS rn
                    FROM cy_comp_framework_scores
                ) t
                WHERE rn = 1 AND score IS NOT NULL;
            """)
        rows = cur.fetchall()
        if rows:
            avg_score = round(sum(float(r[1]) for r in rows) / len(rows), 1)
            fw_labels = ", ".join(r[0].upper() for r in rows)
            conn.close()
            return {
                "score":  avg_score,
                "stale":  False,
                "detail": f"CyComp: avg {avg_score}% across {len(rows)} frameworks ({fw_labels})",
            }

        # Attempt 2: derive from questionnaire responses directly
        if frameworks:
            cur.execute("""
                SELECT
                    t.framework,
                    COALESCE(SUM(t.weight), 0)                                AS total_weight,
                    COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2), 0)    AS pass_weight,
                    COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1),  0)    AS partial_weight,
                    COUNT(r.question_id)                                       AS answered
                FROM cy_comp_questionnaire_templates t
                LEFT JOIN cy_comp_questionnaire_responses r
                       ON r.question_id = t.question_id AND r.framework = t.framework
                WHERE t.framework = ANY(%s)
                GROUP BY t.framework
                HAVING COUNT(r.question_id) > 0;
            """, (frameworks,))
        else:
            cur.execute("""
                SELECT
                    t.framework,
                    COALESCE(SUM(t.weight), 0)                                AS total_weight,
                    COALESCE(SUM(t.weight) FILTER (WHERE r.score >= 2), 0)    AS pass_weight,
                    COALESCE(SUM(t.weight) FILTER (WHERE r.score = 1),  0)    AS partial_weight,
                    COUNT(r.question_id)                                       AS answered
                FROM cy_comp_questionnaire_templates t
                LEFT JOIN cy_comp_questionnaire_responses r
                       ON r.question_id = t.question_id AND r.framework = t.framework
                GROUP BY t.framework
                HAVING COUNT(r.question_id) > 0;
            """)
        rows = cur.fetchall()
        conn.close()
        if rows:
            scores = []
            for row in rows:
                tw = float(row[1] or 1)
                pw = float(row[2] or 0)
                pa = float(row[3] or 0)
                scores.append(round(((pw + pa * 0.5) / tw) * 100, 1))
            avg_score = round(sum(scores) / len(scores), 1)
            return {
                "score":  avg_score,
                "stale":  False,
                "detail": f"CyComp (questionnaire): avg {avg_score}% across {len(scores)} frameworks",
            }
    except Exception:
        pass  # cy_comp tables don't exist yet

    # cy_comp not yet set up — omit from CSPI weighted average
    return {
        "score":  None,
        "stale":  False,
        "detail": "CyComp not configured — run a compliance assessment to populate scores.",
    }


# ── 4. Vulnerability Management (enterprise-grade) ────────────────────────────

def _wazuh_token() -> Optional[str]:
    """
    Obtain a Wazuh API JWT using Basic auth. Returns None on failure.
    Credentials are read from /opt/cycentra/.env (EnvironmentFile for Flask).
    setup.sh propagates WAZUH_API_PASSWORD from cysiemstack.env into .env at
    install and update time, so .env is always the single source of truth.
    """
    wazuh_pass = _WAZUH_API_PASS
    wazuh_user = _WAZUH_API_USER

    if not wazuh_pass:
        log.debug("[benchmark] WAZUH_API_PASSWORD not set in /opt/cycentra/.env")
        return None
    try:
        creds = base64.b64encode(
            f"{wazuh_user}:{wazuh_pass}".encode()
        ).decode()
        r = _req.get(
            f"{_WAZUH_API_URL}/security/user/authenticate",
            headers={"Authorization": f"Basic {creds}"},
            timeout=_WAZUH_TIMEOUT,
            verify=False,  # Wazuh self-signed cert
        )
        r.raise_for_status()
        return r.json()["data"]["token"]
    except Exception as exc:
        log.debug("[benchmark] Wazuh token error: %s", exc)
        return None


def _wazuh_get(path: str, token: str, params: Optional[dict] = None) -> Optional[dict]:
    """Authenticated GET against the Wazuh API. Returns None on failure."""
    try:
        r = _req.get(
            f"{_WAZUH_API_URL}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
            timeout=_WAZUH_TIMEOUT,
            verify=False,
        )
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        log.debug("[benchmark] Wazuh GET %s error: %s", path, exc)
    return None


def _collect_wazuh_vuln_subscore(token: str) -> tuple[Optional[float], str]:
    """
    Sub-score from Wazuh vulnerability detector (0-100).

    Fetches all active agents, then collects vulnerability severity counts
    across all agents.  Score formula:
        start = 100
        deduct 12 per critical CVE (cap -60)
        deduct  6 per high CVE    (cap -36)
        deduct  2 per medium CVE  (cap -20)
    """
    agents_data = _wazuh_get("/agents", token, {"status": "active", "limit": 500,
                                                  "select": "id,name"})
    if not agents_data:
        return None, "Wazuh agent list unavailable"

    agents = agents_data.get("data", {}).get("affected_items", [])
    if not agents:
        return None, "No active Wazuh agents"

    totals = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    agents_checked = 0

    for agent in agents[:50]:  # cap at 50 agents to keep response time under 10 s
        agent_id = agent.get("id")
        if not agent_id:
            continue
        # status=Active filters out already-patched CVEs (Solved/Inactive).
        # Wazuh vulnerability detector status values: Active | Solved | Inactive.
        vuln_data = _wazuh_get(f"/vulnerability/{agent_id}", token,
                               {"limit": 500, "select": "severity", "status": "Active"})
        if not vuln_data:
            continue
        for vuln in vuln_data.get("data", {}).get("affected_items", []):
            sev = vuln.get("severity", "")
            if sev in totals:
                totals[sev] += 1
        agents_checked += 1

    if agents_checked == 0:
        return None, "Wazuh vuln detector returned no data"

    score = 100.0
    score -= min(60, totals["Critical"] * 12)
    score -= min(36, totals["High"]     *  6)
    score -= min(20, totals["Medium"]   *  2)
    score  = max(0, min(100, round(score)))
    detail = (f"Wazuh vuln detector: {totals['Critical']} critical, "
              f"{totals['High']} high, {totals['Medium']} medium "
              f"across {agents_checked} agents")
    return float(score), detail


def _collect_wazuh_sca_subscore(token: str) -> tuple[Optional[float], str]:
    """
    Sub-score from Wazuh SCA (Security Configuration Assessment) pass rate (0-100).

    Formula: (passed_checks / total_checks) * 100
    Averaged across all active agents.
    """
    agents_data = _wazuh_get("/agents", token, {"status": "active", "limit": 500,
                                                  "select": "id,name"})
    if not agents_data:
        return None, "Wazuh agent list unavailable"

    agents = agents_data.get("data", {}).get("affected_items", [])
    if not agents:
        return None, "No active agents"

    total_pass  = 0
    total_fail  = 0
    total_error = 0
    agents_checked = 0

    for agent in agents[:30]:  # SCA results are larger — cap at 30
        agent_id = agent.get("id")
        if not agent_id:
            continue
        sca_data = _wazuh_get(f"/sca/{agent_id}", token, {"limit": 1})
        if not sca_data:
            continue
        for policy in sca_data.get("data", {}).get("affected_items", []):
            total_pass  += int(policy.get("pass",  0))
            total_fail  += int(policy.get("fail",  0))
            total_error += int(policy.get("error", 0))
        agents_checked += 1

    total_checks = total_pass + total_fail + total_error
    if total_checks == 0:
        return None, "No SCA checks found"

    score  = round((total_pass / total_checks) * 100)
    detail = (f"SCA: {total_pass}/{total_checks} checks passed "
              f"across {agents_checked} agents")
    return float(score), detail


def _collect_iris_mttr_subscore() -> tuple[Optional[float], str]:
    """
    Sub-score from CyIRIS mean time to remediate (MTTR), derived from the
    Incident table's first_seen and closed_at columns.

    Scoring (lower MTTR = higher score):
        Critical MTTR < 24 h  → 100
        Critical MTTR < 72 h  → 80
        Critical MTTR < 168 h → 60
        Critical MTTR < 336 h → 40
        Critical MTTR >= 336 h → 20
        No closed incidents    → None (not scored)
    Blended across Critical + High.
    """
    try:
        import psycopg2
        conn = psycopg2.connect(_CORR_DB_URL)
        cur  = conn.cursor()

        # Mean hours to resolve per severity (last 90 days)
        cur.execute("""
            SELECT
                severity,
                AVG(EXTRACT(EPOCH FROM (closed_at - first_seen)) / 3600) AS avg_hours,
                COUNT(*) AS count
            FROM incidents
            WHERE closed_at IS NOT NULL
              AND first_seen IS NOT NULL
              AND closed_at  > NOW() - INTERVAL '90 days'
              AND severity   IN ('critical', 'high', 'medium')
            GROUP BY severity
        """)
        rows = cur.fetchall()
        conn.close()

        if not rows:
            return None, "No resolved incidents in last 90 days"

        mttr_map = {row[0]: float(row[1]) for row in rows}
        count_map = {row[0]: int(row[2]) for row in rows}

        # Score each severity band
        def _band_score(hours: Optional[float]) -> float:
            if hours is None:   return 50.0
            if hours < 24:      return 100.0
            if hours < 72:      return 80.0
            if hours < 168:     return 60.0
            if hours < 336:     return 40.0
            return 20.0

        # Weighted blend: critical counts 3×, high 2×, medium 1×
        weights     = {"critical": 3, "high": 2, "medium": 1}
        total_w     = 0.0
        weighted_s  = 0.0
        detail_parts = []

        for sev, hours in mttr_map.items():
            w          = weights.get(sev, 1)
            s          = _band_score(hours)
            weighted_s += s * w
            total_w    += w
            detail_parts.append(f"{sev}: {hours:.0f}h avg ({count_map[sev]} cases)")

        score = round(weighted_s / total_w) if total_w > 0 else None
        return (float(score) if score else None,
                "MTTR — " + ", ".join(detail_parts))

    except Exception as exc:
        log.debug("[benchmark] IRIS MTTR query failed: %s", exc)
        return None, "CyIRIS not configured or no incident data"


def _collect_internal_posture_subscore() -> tuple[Optional[float], str, dict]:
    """
    Read the aggregated internal host posture from host_posture_cache.

    Returns (score_0_100, detail_string, component_breakdown).
    Uses psycopg2 (sync) to avoid importing the async engine into Flask context.
    Falls back to (None, reason, {}) if the cache is empty or DB unavailable.
    """
    try:
        import psycopg2
        conn = psycopg2.connect(_CORR_DB_URL)
        cur  = conn.cursor()
        cur.execute("""
            SELECT
              agent_id, posture_score, asset_tier,
              sca_score, vuln_score, siem_risk,
              fim_event_count, malware_count, compliance_score,
              posture_grade, wazuh_status
            FROM host_posture_cache
            WHERE computed_at > NOW() - INTERVAL '2 hours'
        """)
        rows = cur.fetchall()
        conn.close()
    except Exception as exc:
        log.debug("[benchmark] host_posture_cache unavailable: %s", exc)
        return None, "Host posture cache unavailable (cache not yet populated)", {}

    if not rows:
        return None, "Host posture cache empty — run /api/siem/hosts/refresh", {}

    tier_weight = {1: 3.0, 2: 2.0, 3: 1.0}
    weighted_sum  = 0.0
    total_weight  = 0.0
    comp_sums     = {"sca": 0.0, "vuln": 0.0, "siem_risk": 0.0, "compliance": 0.0}
    comp_weights  = {k: 0.0 for k in comp_sums}
    active_count  = critical_grade = total = 0

    for row in rows:
        agent_id, posture_score, asset_tier, sca_score, vuln_score, siem_risk, \
            fim_count, malware_count, compliance_score, grade, status = row

        if posture_score is None:
            continue
        total += 1
        w  = tier_weight.get(asset_tier or 3, 1.0)
        weighted_sum += float(posture_score) * w
        total_weight += w

        comps = {
            "sca":        float(sca_score)        if sca_score        is not None else 50.0,
            "vuln":       float(vuln_score)        if vuln_score       is not None else 50.0,
            "siem_risk":  max(0, 100 - float(siem_risk)) if siem_risk is not None else 50.0,
            "compliance": float(compliance_score)  if compliance_score is not None else 50.0,
        }
        for k in comp_sums:
            comp_sums[k]    += comps[k] * w
            comp_weights[k] += w

        if status == "active":
            active_count += 1
        if grade in ("F", "D"):
            critical_grade += 1

    if total_weight == 0:
        return None, "No scored hosts in posture cache", {}

    overall  = round(weighted_sum / total_weight, 1)
    breakdown = {k: round(comp_sums[k] / comp_weights[k], 1)
                 for k in comp_sums if comp_weights[k] > 0}

    detail = (f"Internal posture: {total} hosts · "
              f"SCA {breakdown.get('sca', '?')} · "
              f"Vuln {breakdown.get('vuln', '?')} · "
              f"{critical_grade} critical-grade hosts")
    return float(overall), detail, breakdown


def _collect_vuln_score() -> dict:
    """
    Enterprise-grade vulnerability management score (0-100).

    Primary:  reads from host_posture_cache (5-component posture model)
              which covers SCA, vulnerability CVEs, FIM, malware, compliance.
    Fallback: direct Wazuh API calls (original 3-component model).
    Blended with CyIRIS MTTR.

    Sub-score weights (primary path):
      50% — Internal host posture (SCA + CVE + FIM/malware + compliance)
      25% — Wazuh vulnerability detector (CVE severity counts)
      25% — CyIRIS mean time to remediate by severity
    """
    token = _wazuh_token()

    sub_scores   = {}
    sub_details  = {}

    # ── Primary: host posture cache (richer, already computed) ───────────────
    posture_score, posture_detail, posture_breakdown = _collect_internal_posture_subscore()
    sub_scores["host_posture"]  = posture_score
    sub_details["host_posture"] = posture_detail

    # ── Wazuh vulnerability detector (direct, per-CVE) ────────────────────────
    if token:
        score, detail = _collect_wazuh_vuln_subscore(token)
        sub_scores["wazuh_vuln"]  = score
        sub_details["wazuh_vuln"] = detail
    else:
        sub_scores["wazuh_vuln"]  = None
        sub_details["wazuh_vuln"] = "Wazuh API credentials not configured"

    # ── Wazuh SCA (direct) — only used when host posture cache is unavailable ─
    if posture_score is None and token:
        score, detail = _collect_wazuh_sca_subscore(token)
        sub_scores["wazuh_sca"]  = score
        sub_details["wazuh_sca"] = detail

    # ── CyIRIS MTTR ───────────────────────────────────────────────────────────
    score, detail = _collect_iris_mttr_subscore()
    sub_scores["iris_mttr"]  = score
    sub_details["iris_mttr"] = detail

    # ── Blend weights — prefer host_posture when available ────────────────────
    if posture_score is not None:
        sub_weights = {"host_posture": 0.50, "wazuh_vuln": 0.25, "iris_mttr": 0.25}
    else:
        sub_weights = {"wazuh_vuln": 0.40, "wazuh_sca": 0.35, "iris_mttr": 0.25}

    weighted_sum = 0.0
    weight_sum   = 0.0
    for key, w in sub_weights.items():
        s = sub_scores.get(key)
        if s is not None:
            weighted_sum += s * w
            weight_sum   += w

    if weight_sum == 0:
        return {
            "score":      None,
            "stale":      False,
            "detail":     "Wazuh API unavailable — ensure WAZUH_API_PASSWORD is set in "
                          "/opt/cycentra/cysiemstack.env and the Wazuh service is running.",
            "sub_scores": sub_scores,
        }

    composite = round(weighted_sum / weight_sum)
    available = [k for k, v in sub_scores.items() if v is not None]
    detail_lines = [sub_details[k] for k in available]

    return {
        "score":              composite,
        "stale":              False,
        "detail":             " | ".join(detail_lines),
        "sub_scores":         sub_scores,
        "host_posture_breakdown": posture_breakdown,
    }


# ── 5. Threat Intelligence — direct MISP API ──────────────────────────────────

def _read_cysiemstack_env() -> dict:
    """Parse /opt/cycentra/cysiemstack.env → key/value dict. Mirrors iris_connector pattern."""
    env: dict = {}
    env_file = Path("/opt/cycentra/cysiemstack.env")
    if not env_file.exists():
        return env
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return env


def _read_misp_config() -> dict | None:
    """
    Resolve MISP credentials using a four-level fallback chain.

    Priority (first source with both url AND apiKey wins):
      1. /opt/cycentra/ai_settings.json  → misp.url / misp.apiKey
      2. os.environ CLOUD_MISP_*         → set by EnvironmentFile=/opt/cycentra/.env
      3. /opt/cycentra/cysiemstack.env   → MISP_URL / MISP_API_KEY
      4. os.environ MISP_*               → MISP_URL / MISP_API_KEY

    CLOUD_MISP_* (Source 2) is checked before cysiemstack.env because the .env
    file is updated by the UI and always carries the current key, whereas
    cysiemstack.env may hold a stale key written during initial install.

    Returns dict(url, apiKey, mode) or None if disabled/unconfigured.
    """
    import os as _os
    url     = ""
    api_key = ""
    mode    = "disabled"

    # Source 1: ai_settings.json
    ai_file = Path("/opt/cycentra/ai_settings.json")
    try:
        if ai_file.exists():
            stored  = json.loads(ai_file.read_text())
            misp    = stored.get("misp") or {}
            mode    = str(misp.get("mode", "disabled")).lower()
            url     = str(misp.get("url",    "")).strip().rstrip("/")
            api_key = str(misp.get("apiKey", "")).strip()
    except Exception as exc:
        log.warning("[benchmark] ai_settings.json read error: %s", exc)

    # Source 2: os.environ CLOUD_MISP_* (written by UI to /opt/cycentra/.env)
    if not url or not api_key:
        cloud_url = _os.environ.get("CLOUD_MISP_URL", "").strip().rstrip("/")
        cloud_key = _os.environ.get("CLOUD_MISP_API_KEY", "").strip()
        if cloud_url and cloud_key:
            url     = url     or cloud_url
            api_key = api_key or cloud_key
            if not mode or mode == "disabled":
                mode = _os.environ.get("CLOUD_MISP_MODE", "cloud").lower()

    # Source 3: cysiemstack.env
    if not url or not api_key:
        siem_env = _read_cysiemstack_env()
        url      = url      or siem_env.get("MISP_URL",     "").strip().rstrip("/")
        api_key  = api_key  or siem_env.get("MISP_API_KEY", "").strip()
        if not mode or mode == "disabled":
            mode = siem_env.get("MISP_MODE", "local").lower()
        if siem_env.get("MISP_ENABLED", "true").lower() == "false":
            return None

    # Source 4: os.environ MISP_*
    if not url or not api_key:
        url     = url     or _os.environ.get("MISP_URL",     "").strip().rstrip("/")
        api_key = api_key or _os.environ.get("MISP_API_KEY", "").strip()
        if not mode or mode == "disabled":
            mode = _os.environ.get("MISP_MODE", "local").lower()

    if mode == "disabled":
        return None
    if not url or not api_key:
        log.debug("[benchmark] MISP url/apiKey not found in any config source")
        return None

    return {"url": url, "apiKey": api_key, "mode": mode}


def _collect_threat_intel_score() -> dict:
    """
    Threat intelligence coverage score (0-100).

    Reads MISP credentials from /opt/cycentra/ai_settings.json directly
    (same source as iris_connector.py — ai_settings.json is written by the
    System Settings UI and is available to the Flask backend process).

    Sub-signals:
      a) Enabled feed count        → 0-40 pts  (3+ feeds = full 40)
      b) Total IOC attribute count → 0-30 pts  (10,000+ attrs = full 30)
      c) Actionable ratio (to_ids) → 0-30 pts
    """
    misp_cfg = _read_misp_config()
    if not misp_cfg:
        return {"score": None, "stale": False,
                "detail": "MISP disabled or not configured — enable in System Settings → CyMISP"}

    url     = misp_cfg["url"]
    api_key = misp_cfg["apiKey"]
    headers = {
        "Authorization": api_key,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }
    timeout = 8
    verify  = False   # MISP commonly uses self-signed certs

    # ── a) Feed count — GET /feeds/index ──────────────────────────────────────
    feed_score  = 0
    feed_detail = "feeds unavailable"
    enabled_n   = 0
    try:
        r = _req.get(f"{url}/feeds/index", headers=headers,
                     timeout=timeout, verify=verify)
        if r.status_code == 200:
            feeds     = r.json() if isinstance(r.json(), list) else []
            # MISP wraps each feed under a "Feed" key: [{"Feed": {...}}, ...]
            # Unwrap before reading "enabled" so the field is always accessible.
            enabled_n = sum(1 for f in feeds if f.get("Feed", f).get("enabled"))
            total_n   = len(feeds)
            # 3+ enabled feeds = full 40 pts; proportional below 3
            feed_score  = min(40, round((enabled_n / max(3, 1)) * 40))
            feed_detail = f"{enabled_n}/{total_n} feeds enabled"
        else:
            log.debug("[benchmark] MISP /feeds/index returned HTTP %s", r.status_code)
    except Exception as exc:
        log.debug("[benchmark] MISP feeds error: %s", exc)

    # ── b) Total attribute count — POST /attributes/statistics/type ───────────
    attr_score  = 0
    attr_detail = "attribute count unavailable"
    total_attrs = 0
    try:
        r = _req.post(f"{url}/attributes/statistics/type",
                      headers=headers, json={},
                      timeout=timeout, verify=verify)
        if r.status_code == 200:
            stats = r.json()
            # Response is {type_name: count_str, ...}
            total_attrs = sum(
                int(v) for v in stats.values()
                if str(v).isdigit()
            )
            # 10,000 attributes = full 30 pts
            attr_score  = min(30, round((total_attrs / 10_000) * 30))
            attr_detail = f"{total_attrs:,} IOC attributes"
        else:
            log.debug("[benchmark] MISP /attributes/statistics returned HTTP %s",
                      r.status_code)
    except Exception as exc:
        log.debug("[benchmark] MISP attribute statistics error: %s", exc)

    # ── c) Actionable ratio — to_ids=1 vs total ───────────────────────────────
    active_score  = 0
    active_detail = ""
    try:
        r_active = _req.post(
            f"{url}/attributes/restSearch",
            headers=headers,
            json={"returnFormat": "count", "to_ids": 1},
            timeout=timeout, verify=verify,
        )
        r_total = _req.post(
            f"{url}/attributes/restSearch",
            headers=headers,
            json={"returnFormat": "count"},
            timeout=timeout, verify=verify,
        )
        if r_active.status_code == 200 and r_total.status_code == 200:
            active_n = int(r_active.json().get("response", {}).get("count", 0))
            total_n  = int(r_total.json().get("response",  {}).get("count", 1))
            ratio    = active_n / max(total_n, 1)
            active_score  = min(30, round(ratio * 30))
            active_detail = f"{ratio*100:.0f}% actionable"
    except Exception as exc:
        log.debug("[benchmark] MISP active ratio error: %s", exc)

    composite = min(100, feed_score + attr_score + active_score)
    parts     = [p for p in [feed_detail, attr_detail, active_detail] if p]

    return {
        "score":        composite,
        "stale":        False,
        "detail":       " · ".join(parts),
        "mode":         misp_cfg.get("mode", "unknown"),
        "feeds_enabled": enabled_n,
        "total_attrs":  total_attrs,
    }


# ── 6. External benchmark (Phase 1 estimate) ──────────────────────────────────

def _collect_ext_benchmark_score(
    _pre_comp: Optional[dict] = None,
    _pre_asm:  Optional[dict] = None,
    _asm_enabled:  bool = True,
    _comp_enabled: bool = True,
) -> dict:
    """
    CIS Controls v8 / NIST CSF 2.0 alignment (0-100).
    Phase 1: weighted blend of compliance + ASM scores as a proxy.
    Phase 2: replace with bundled CIS JSON and nightly NVD/MITRE sync.

    Source-overlap guard: if both ASM and Compliance dimensions are enabled
    and independently scored, this dimension is suppressed to prevent their
    data being re-weighted a second time inside the CSPI composite.
    ext_benchmark only activates when one or both source dimensions are
    disabled or unavailable (e.g. CyComp not installed, no ASM scan run).

    Accepts pre-computed results from the parallel collector run to avoid
    calling _collect_compliance_score / _collect_asm_score a second time.
    """
    comp   = _pre_comp if _pre_comp is not None else _collect_compliance_score()
    asm    = _pre_asm  if _pre_asm  is not None else _collect_asm_score()
    comp_s, asm_s = comp.get("score"), asm.get("score")

    # Source-overlap guard: both dimensions are active and scored independently.
    # Allowing ext_benchmark to score here would re-weight the same data a
    # second time — suppress it until one of the source dimensions is disabled.
    if _asm_enabled and _comp_enabled and asm_s is not None and comp_s is not None:
        return {
            "score":  None,
            "stale":  False,
            "detail": "Suppressed — ASM and Compliance are both active. "
                      "CIS/NIST would re-weight those same inputs. "
                      "Enable only when one of the source dimensions is disabled.",
        }

    if comp_s is None and asm_s is None:
        return {"score": None, "stale": False,
                "detail": "Requires CyComp or an ASM scan"}

    weighted, w = 0.0, 0
    if comp_s is not None: weighted += comp_s * 0.6; w += 1
    if asm_s  is not None: weighted += asm_s  * 0.4; w += 1
    return {
        "score":  min(100, max(0, round(weighted / w if w == 1 else weighted))),
        "stale":  True,
        "detail": "Phase 1 estimate — full CIS/NIST bundle in Phase 2",
    }


# ── Ordered collector registry (matches UI display order) ─────────────────────
# ext_benchmark is excluded here — it is computed last, using pre-collected
# asm + compliance results to avoid running those collectors twice.

_COLLECTORS = [
    ("asm",          _collect_asm_score),
    ("siem",         _collect_siem_score),
    ("compliance",   _collect_compliance_score),
    ("vuln",         _collect_vuln_score),
    ("threat_intel", _collect_threat_intel_score),
]

# Per-source wall-clock timeout (seconds).  Any collector that exceeds this
# budget is abandoned and returns {score: None} rather than blocking the whole
# response.  These are intentionally generous — adjust down if needed.
_COLLECTOR_TIMEOUT = int(os.environ.get("BENCHMARK_COLLECTOR_TIMEOUT", "15"))

# ── In-memory TTL cache for _compute_cspi ─────────────────────────────────────
# The score changes at most every few minutes; re-running all collectors on
# every page refresh is wasteful.  Cache the result for BENCHMARK_CACHE_TTL
# seconds (default 120 s) and invalidate on explicit PUT /config saves.

_CSPI_CACHE_TTL  = int(os.environ.get("BENCHMARK_CACHE_TTL", "120"))
_cspi_cache_lock = threading.Lock()
_cspi_cache: dict = {"result": None, "computed_at": 0.0, "config_hash": None}


def _config_hash(config: dict) -> str:
    """Cheap fingerprint of the config to detect changes that should bust the cache."""
    import hashlib
    return hashlib.md5(
        json.dumps(config, sort_keys=True).encode(), usedforsecurity=False
    ).hexdigest()


def invalidate_cspi_cache() -> None:
    """Call after PUT /config to force the next GET /score to recompute."""
    with _cspi_cache_lock:
        _cspi_cache["result"] = None
        _cspi_cache["computed_at"] = 0.0

# ── CSPI composite ─────────────────────────────────────────────────────────────

def _compute_cspi(config: dict, frameworks: list = None) -> dict:
    """
    Compute the CSPI composite score.

    All five primary collectors run **in parallel** via a ThreadPoolExecutor
    capped at _COLLECTOR_TIMEOUT seconds each.  Collectors that time out or
    raise return {score: None} without blocking the others.

    The ext_benchmark score is derived last from the already-collected
    compliance + asm results (no duplicate HTTP/DB calls).

    Results are cached for _CSPI_CACHE_TTL seconds and returned on subsequent
    calls unless the config has changed or the cache is explicitly invalidated.

    frameworks: optional list of framework IDs from the GRC Posture page filter.
                Passed only to the compliance collector; other collectors are unaffected.
                When set, the cache key includes the sorted framework list.
    """
    sources = config.get("sources", _DEFAULT_CONFIG["sources"])

    # ── TTL cache check (keyed on config + active framework filter) ────────────
    fw_key = ",".join(sorted(frameworks)) if frameworks else ""
    chash  = _config_hash(config) + "|" + fw_key
    with _cspi_cache_lock:
        cached = _cspi_cache["result"]
        if (
            cached is not None
            and _cspi_cache["config_hash"] == chash
            and (time.monotonic() - _cspi_cache["computed_at"]) < _CSPI_CACHE_TTL
        ):
            return cached

    breakdown = {}
    weighted  = 0.0
    total_w   = 0.0

    # Build collector list — swap compliance for a framework-filtered variant when needed
    collectors = [
        (src_id, partial(_collect_compliance_score, frameworks=frameworks) if src_id == "compliance" else fn)
        for src_id, fn in _COLLECTORS
    ]

    # ── Parallel collection ────────────────────────────────────────────────────
    raw_results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(collectors), thread_name_prefix="bench") as pool:
        futures = {pool.submit(collector): src_id for src_id, collector in collectors}
        for fut in as_completed(futures, timeout=_COLLECTOR_TIMEOUT + 2):
            src_id = futures[fut]
            try:
                raw_results[src_id] = fut.result(timeout=_COLLECTOR_TIMEOUT)
            except FuturesTimeout:
                raw_results[src_id] = {"score": None, "stale": False,
                                       "detail": f"Collector timed out ({_COLLECTOR_TIMEOUT}s)"}
            except Exception as exc:
                raw_results[src_id] = {"score": None, "stale": False, "detail": str(exc)}

    # Ensure all collectors have an entry even if as_completed timed out globally
    for src_id, _ in collectors:
        raw_results.setdefault(src_id, {"score": None, "stale": False, "detail": "Collector did not complete"})

    # ── ext_benchmark — reuse already-collected asm + compliance (no re-call) ─
    # Pass enabled flags so the source-overlap guard can suppress ext_benchmark
    # when both its source dimensions are active and independently scored.
    raw_results["ext_benchmark"] = _collect_ext_benchmark_score(
        _pre_comp=raw_results.get("compliance"),
        _pre_asm=raw_results.get("asm"),
        _asm_enabled=sources.get("asm", {}).get("enabled", True),
        _comp_enabled=sources.get("compliance", {}).get("enabled", True),
    )

    # ── Assemble breakdown ────────────────────────────────────────────────────
    all_src_ids = [s for s, _ in _COLLECTORS] + ["ext_benchmark"]

    for src_id in all_src_ids:
        src_cfg = sources.get(src_id, {})
        raw     = raw_results[src_id]

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
        # Pass through extra fields (grade, sub_scores, mode, etc.)
        for k, v in raw.items():
            if k not in ("score", "stale", "detail"):
                breakdown[src_id][k] = v

        if enabled and score is not None:
            weighted += score * effective_w
            total_w  += effective_w

    cspi  = round(weighted / total_w) if total_w > 0 else None
    grade = ("A+" if cspi is not None and cspi >= 85 else
             "A"  if cspi is not None and cspi >= 75 else
             "B"  if cspi is not None and cspi >= 65 else
             "C"  if cspi is not None and cspi >= 50 else
             "D"  if cspi is not None and cspi >= 35 else
             "F"  if cspi is not None else "—")

    result = {
        "cspi":         cspi,
        "grade":        grade,
        "breakdown":    breakdown,
        "computed_at":  datetime.now(timezone.utc).isoformat(),
        "total_weight": round(total_w, 2),
        "cached":       False,
    }

    # ── Store in TTL cache ─────────────────────────────────────────────────────
    with _cspi_cache_lock:
        _cspi_cache["result"]      = result
        _cspi_cache["computed_at"] = time.monotonic()
        _cspi_cache["config_hash"] = chash

    return result


def _percentile(cspi: Optional[int], bands: list) -> tuple:
    if cspi is None:    return "", 0
    p10, p25, p50, p75, p90 = bands
    if cspi < p10:      return "Bottom 10%",            5
    if cspi < p25:      return "10th–25th percentile", 17
    if cspi < p50:      return "25th–50th percentile", 37
    if cspi < p75:      return "50th–75th percentile", 62
    if cspi < p90:      return "75th–90th percentile", 82
    return               "Top 10%",                    95


# ══════════════════════════════════════════════════════════════════════════════
# BANDS AUTO-UPDATE SCHEDULER JOB
# ══════════════════════════════════════════════════════════════════════════════

def _fetch_enisa_bands() -> Optional[dict]:
    """
    Fetch maturity / scores from ENISA's publicly available NIS2 NCA reports.

    ENISA does not (yet) publish machine-readable percentile band JSON, so
    this function polls the ENISA ECSF (European Cybersecurity Skills Framework)
    API which returns sector-level maturity data, then maps it to CSPI bands.

    If the fetch fails for any reason the function returns None and the caller
    retains the last cached values.

    Mapping from ENISA maturity levels (1-5) to approximate CSPI bands:
        Level 1 (Initial)   → 10-25
        Level 2 (Developing)→ 25-45
        Level 3 (Defined)   → 45-60
        Level 4 (Managed)   → 60-75
        Level 5 (Optimising)→ 75-90

    NOTE: When ENISA publishes a machine-readable annual dataset, update the
    URL below.  Until then, the job checks the ENISA open-data portal and
    returns None (retaining cached/static bands) if nothing parseable is found.
    """
    # ENISA open data portal — check for JSON publication of NIS2 statistics
    # This URL will return 404 until ENISA publishes the dataset; we catch that.
    ENISA_URL = "https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024"
    try:
        r = _req.head(ENISA_URL, timeout=10, allow_redirects=True)
        # Currently ENISA only publishes PDF — return None to keep static values.
        # When a JSON API becomes available, parse it here and return the bands dict.
        log.info("[benchmark] ENISA bands fetch: page exists (%s) — no JSON API yet, "
                 "retaining static values.", r.status_code)
        return None
    except Exception as exc:
        log.warning("[benchmark] ENISA bands fetch failed: %s", exc)
        return None


def run_bands_update_job() -> None:
    """
    Monthly job: fetch updated cohort bands and write to cache.
    Registered by register_benchmark_scheduler() into APScheduler.
    Only runs when BENCHMARK_AUTO_UPDATE=true.
    """
    log.info("[benchmark] Running monthly bands update job")
    new_bands = _fetch_enisa_bands()
    if new_bands is None:
        log.info("[benchmark] No updated bands available — retaining current cache/static values")
        return

    # Merge new bands into the static dict (only update sectors that were returned)
    cohorts = _load_industry_cohorts()
    for sector, data in new_bands.items():
        if sector in cohorts and "bands" in data:
            cohorts[sector]["bands"]        = data["bands"]
            cohorts[sector]["source"]       = data.get("source", cohorts[sector]["source"])
            cohorts[sector]["sample_size"]  = data.get("sample_size", cohorts[sector]["sample_size"])

    _BANDS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _BANDS_CACHE.write_text(json.dumps(cohorts, indent=2))
    log.info("[benchmark] Bands cache updated: %d sectors", len(cohorts))


def register_benchmark_scheduler(scheduler) -> None:
    """
    Register the monthly bands update job into the platform APScheduler instance.
    Call this from blueprints/scheduler/routes.py init_scheduler() if
    BENCHMARK_AUTO_UPDATE=true.

    Usage in blueprints/scheduler/routes.py:
        from blueprints.benchmark.routes import register_benchmark_scheduler, _AUTO_UPDATE
        if _AUTO_UPDATE:
            register_benchmark_scheduler(scheduler)
    """
    if not _AUTO_UPDATE:
        return
    try:
        from apscheduler.triggers.cron import CronTrigger
        scheduler.add_job(
            run_bands_update_job,
            trigger=CronTrigger(day=1, hour=3, minute=0),  # 1st of each month, 03:00
            id="benchmark_bands_update",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        log.info("[benchmark] Monthly bands update job registered (runs 1st of month, 03:00)")
    except Exception as exc:
        log.warning("[benchmark] Could not register bands update job: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@benchmark_bp.route("/score")
@_require_auth
def get_score():
    config     = _load_config()
    fw_param   = request.args.get("frameworks", "")
    frameworks = [f.strip() for f in fw_param.split(",") if f.strip()] or None
    result     = _compute_cspi(config, frameworks=frameworks)
    industry   = config.get("industry", "general")
    cohorts  = _load_industry_cohorts()
    cohort   = cohorts.get(industry, cohorts["general"])
    pct_label, pct_n = _percentile(result.get("cspi"), cohort["bands"])
    result.update({
        "percentile":       pct_n,
        "percentile_label": pct_label,
        "industry":         industry,
        "cohort":           cohort,
    })
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
    for src_id, patch in body.get("sources", {}).items():
        if src_id in config["sources"]:
            config["sources"][src_id].update(
                {k: v for k, v in patch.items() if k in ("enabled", "weight")}
            )
    for key in ("industry", "size_band", "cohort_opt_in"):
        if key in body:
            config[key] = body[key]
    _save_config(config)
    # Invalidate the CSPI cache so the next GET /score recomputes with the
    # new weights/sources.  Industry-only changes do NOT need a score recompute
    # (bands are applied client-side) but it is safe to bust the cache here.
    score_affecting = set(body.keys()) - {"industry", "size_band", "cohort_opt_in"}
    if score_affecting or body.get("sources"):
        invalidate_cspi_cache()
    return jsonify({"ok": True, "config": config})


@benchmark_bp.route("/industries")
@_require_auth
def get_industries():
    return jsonify({"industries": _load_industry_cohorts(), "default": "general"})
