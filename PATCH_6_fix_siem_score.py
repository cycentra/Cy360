"""
PATCH 6 — Fix SIEM score collector + widget status clarity
===========================================================
File patched: backend/blueprints/benchmark/routes.py

ROOT CAUSE — SIEM showing 0 / "Engine unreachable"
---------------------------------------------------
_collect_siem_score() calls GET /risk/summary — this endpoint does NOT exist
in the correlation engine. The engine exposes:
  GET /stats            → total_alerts_24h, open_incidents, active_agents, critical_alerts
  GET /incidents        → paginated incident list with severity, risk_score
  GET /risk-scores      → entity risk scores with level (low/medium/high/critical)

The fix queries /stats + /risk-scores (same endpoints used by system/routes.py
_fetch_siem_context_block() and the MCP tools) and derives a health score from
real data the engine actually provides.

SCORE FORMULA (derived from real engine data)
---------------------------------------------
Start at 100.
  /stats:
    - critical_alerts_24h  → -3 each (cap -30)
    - open_incidents        → -2 each (cap -20)
  /risk-scores:
    - critical entities     → -5 each (cap -25)
    - high entities         → -2 each (cap -10)
Clamp 0-100.

OTHER WIDGETS — status explanation (no code change needed)
----------------------------------------------------------
Compliance (stale 85):  Correct. CyComp not installed → ASM heuristic.
                        Stale flag is honest. No fix needed.
Vuln Mgmt (92 ASM):    Correct. WAZUH_API_PASSWORD not set → ASM fallback.
                        Set the env var to unlock real Wazuh scoring.
CIS/NIST (stale 73):   Correct. Phase 1 estimate. Stale flag is honest.
                        Full bundle planned for Phase 2.

Run from repo root:
    python3 benchmark-patch/PATCH_6_fix_siem_score.py
"""

import pathlib, sys

TARGET = pathlib.Path("backend/blueprints/benchmark/routes.py")

# ── Find the exact live function (verified from project knowledge) ─────────────

FIND = '''\
def _collect_siem_score() -> dict:
    """Internal detection posture from the correlation engine /risk/summary."""
    try:
        r = _req.get(f"{_SIEM_ENGINE}/risk/summary", timeout=_SIEM_TIMEOUT)
        if r.status_code != 200:
            return {"score": None, "stale": False, "detail": "Engine unreachable"}
        d          = r.json()
        mean_risk  = float(d.get("mean_risk", 50))
        critical_n = int(d.get("critical", 0))
        health     = max(0, min(100, round(100 - mean_risk - (critical_n * 2))))
        return {
            "score":  health,
            "stale":  False,
            "detail": (f"Entities: {d.get('total_entities','?')} · "
                       f"Mean risk: {mean_risk:.0f} · Critical: {critical_n}"),
        }
    except _req.exceptions.ConnectionError:
        return {"score": None, "stale": False, "detail": "Correlation engine offline"}
    except Exception as exc:
        return {"score": None, "stale": False, "detail": str(exc)}'''

# ── Replacement — uses only endpoints that actually exist in the engine ────────

REPLACE = '''\
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

        return {
            "score":            score,
            "stale":            False,
            "detail":           " · ".join(detail_parts),
            "active_agents":    active_agents,
            "open_incidents":   open_incidents,
            "critical_alerts":  critical_alerts,
        }

    except _req.exceptions.ConnectionError:
        return {"score": None, "stale": False, "detail": "Correlation engine offline"}
    except Exception as exc:
        log.warning("[benchmark] SIEM score error: %s", exc)
        return {"score": None, "stale": False, "detail": str(exc)}'''


def main():
    if not TARGET.exists():
        print(f"✗  {TARGET} not found — run from repo root.")
        sys.exit(1)

    content = TARGET.read_text()

    if "GET /stats" in content and "GET /risk-scores" in content:
        print("✓  Already patched — SIEM collector already uses correct endpoints.")
        sys.exit(0)

    if FIND not in content:
        print("✗  Search string not found. Printing all SIEM-related lines for diagnosis:")
        for i, line in enumerate(content.splitlines(), 1):
            if "siem" in line.lower() or "risk/summary" in line or "mean_risk" in line:
                print(f"   line {i}: {line}")
        sys.exit(1)

    TARGET.write_text(content.replace(FIND, REPLACE, 1))
    print(f"✓  Patched {TARGET}")
    print()
    print("SIEM score now derived from real engine endpoints:")
    print("  GET /stats       → alerts, incidents, agents")
    print("  GET /risk-scores → critical / high entity counts")
    print()
    print("OTHER WIDGETS — no code change needed:")
    print("  Compliance (stale 85)  : correct — CyComp not installed, ASM heuristic")
    print("  Vuln Mgmt (92 ASM)     : correct — add WAZUH_API_PASSWORD to .env for")
    print("                           real Wazuh CVE + SCA scoring")
    print("  CIS/NIST (stale 73)    : correct — Phase 1 estimate, Phase 2 brings")
    print("                           full CIS bundle")
    print()
    print("Restart backend:")
    print("  Local:      pkill -f 'python3 app.py'; cd backend && python3 app.py &")
    print("  Production: sudo systemctl restart cycentra-backend")


if __name__ == "__main__":
    main()
