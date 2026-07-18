"""
cysiemstack/host_service.py
============================
Host inventory aggregation and per-host security posture scoring.

Data sources per host:
  - edr_agents / collector_agents : agent list, OS info (CyEDR/CyCollector's
    own registries — no Wazuh Manager API call, see docs/SIEM_PROXY_AUDIT.md)
  - edr_sca_results                : SCA findings (the agent's ScaScanner thread)
  - network_assets / software_inventory : per-CVE vulnerability severity
  - correlation DB                 : alerts (FIM/malware/SCA counts), incidents,
                                      risk_scores

Posture score formula (0–100):
  Component              Weight  Source
  SCA pass rate           30%   edr_sca_results (passed / total checks)
  Vulnerability severity  25%   software_inventory CVEs (inverse severity score)
  SIEM risk (inverted)    25%   risk_scores table  (100 - entity_risk)
  FIM + Malware impact    10%   alert count, severity-weighted, last 30 days
  Compliance gap rate     10%   SCA failures mapped to framework controls

Grades: A+(≥90) A(≥80) B(≥70) C(≥55) D(≥35) F(<35)

The refresh_all_hosts() coroutine is called by the scheduler every hour and
writes results to the host_posture_cache table.  Flask routes in siem_proxy.py
read from that cache so responses are instant (no per-request fan-out).
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger("cysiemstack.host_service")

# Cache TTL: posture re-computed if older than this many seconds
CACHE_TTL_SECONDS = 3600  # 1 hour

_STALE_AFTER = timedelta(minutes=5)
_HOSTNAME_STEM_RE = re.compile(
    r"\.(lan|local|home|internal|localdomain|corp|office|intranet|priv)$", re.I
)


def _liveness(last_seen) -> str:
    if not last_seen:
        return "never_connected"
    try:
        now = datetime.now(timezone.utc)
        ls = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        return "active" if (now - ls) < _STALE_AFTER else "disconnected"
    except Exception:
        return "unknown"


# ── Grade mapping ─────────────────────────────────────────────────────────────

def _score_to_grade(score: float) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 55: return "C"
    if score >= 35: return "D"
    return "F"


# ── Per-host posture computation ──────────────────────────────────────────────

async def _compute_host_posture(
    agent_id: str,
    session: AsyncSession,
) -> dict:
    """Compute the 5-component posture score for a single host."""

    # ── Component 1: SCA pass rate (weight 30%), EDR-native first ────────────
    sca_row = await session.execute(
        text("""
            SELECT COUNT(*) FILTER (WHERE result = 'passed') AS passed,
                   COUNT(*) FILTER (WHERE result = 'failed') AS failed
            FROM edr_sca_results WHERE agent_id = :aid
        """),
        {"aid": agent_id},
    )
    row = sca_row.fetchone()
    sca_passed = int(row.passed or 0) if row else 0
    sca_failed = int(row.failed or 0) if row else 0
    sca_total  = sca_passed + sca_failed
    sca_score  = round((sca_passed / sca_total) * 100, 1) if sca_total else None

    if sca_total == 0:
        # Fall back to historical SCA alerts (older connector-sourced events).
        sca_row = await session.execute(
            text("""
                SELECT
                  COUNT(*) FILTER (WHERE full_alert->'data'->'sca'->'check'->>'result' = 'passed') AS passed,
                  COUNT(*) FILTER (WHERE full_alert->'data'->'sca'->'check'->>'result' = 'failed') AS failed
                FROM alerts
                WHERE agent_id = :aid
                  AND category = 'sca'
                  AND timestamp > NOW() - INTERVAL '7 days'
            """),
            {"aid": agent_id},
        )
        row = sca_row.fetchone()
        if row and (row.passed + row.failed) > 0:
            sca_passed = row.passed
            sca_failed = row.failed
            sca_total  = row.passed + row.failed
            sca_score  = round((sca_passed / sca_total) * 100, 1)

    # ── Component 2: Vulnerability severity score (weight 25%), ITAM-native ──
    vuln_critical = vuln_high = vuln_medium = vuln_low = 0
    vuln_score = None
    vuln_row = await session.execute(
        text("""
            SELECT elem->>'severity' AS severity, COUNT(*) AS cnt
            FROM network_assets na
            JOIN software_inventory si ON si.asset_id = na.id
            CROSS JOIN LATERAL jsonb_array_elements(si.cves) elem
            WHERE na.edr_agent_id = :aid
            GROUP BY elem->>'severity'
        """),
        {"aid": agent_id},
    )
    for r in vuln_row.fetchall():
        sev = (r.severity or "").lower()
        n = int(r.cnt)
        if sev == "critical":   vuln_critical = n
        elif sev == "high":     vuln_high     = n
        elif sev == "medium":   vuln_medium   = n
        elif sev == "low":      vuln_low      = n
    if vuln_critical + vuln_high + vuln_medium + vuln_low > 0:
        raw = 100.0
        raw -= min(60, vuln_critical * 12)
        raw -= min(36, vuln_high     *  6)
        raw -= min(20, vuln_medium   *  2)
        vuln_score = max(0, min(100, round(raw, 1)))

    # ── Analyst acknowledgement adjustments ───────────────────────────────────
    # Items marked false_positive or resolved are excluded from score penalty.
    # The host_item_acks table is owned by siem_proxy.py and may not exist on
    # first boot — the try/except silently skips the adjustment in that case.
    try:
        ack_res = await session.execute(
            text("""
                SELECT item_type, COUNT(*) AS n
                FROM host_item_acks
                WHERE agent_id = :aid
                  AND status IN ('false_positive', 'resolved')
                  AND item_type IN ('sca', 'vulnerability')
                GROUP BY item_type
            """),
            {"aid": agent_id},
        )
        _acks = {r.item_type: int(r.n) for r in ack_res.fetchall()}

        # Adjust SCA: each acked item shifts one failure → pass
        acked_sca = _acks.get("sca", 0)
        if acked_sca > 0 and sca_total > 0 and sca_failed > 0:
            adj_failed = max(0, sca_failed - acked_sca)
            sca_passed = sca_passed + (sca_failed - adj_failed)
            sca_failed = adj_failed
            sca_score  = round((sca_passed / sca_total) * 100, 1)

        # Adjust Vuln: treat each acked CVE as ~medium removal (+4 pts)
        acked_vulns = _acks.get("vulnerability", 0)
        if acked_vulns > 0 and vuln_score is not None:
            vuln_score = min(100.0, round(vuln_score + acked_vulns * 4, 1))
    except Exception:
        pass  # table not yet created or query failed — use unadjusted scores

    # ── Component 3: SIEM risk score inverted (weight 25%) ───────────────────
    risk_row = await session.execute(
        text("""
            SELECT score FROM risk_scores
            WHERE entity_id = :eid AND entity_type = 'host'
            LIMIT 1
        """),
        {"eid": agent_id},
    )
    risk_row_data = risk_row.fetchone()
    siem_risk_raw = float(risk_row_data.score) if risk_row_data else 0.0
    siem_risk_inverted = max(0, min(100, round(100 - siem_risk_raw, 1)))

    # ── Component 4: FIM + malware alert impact (weight 10%) ─────────────────
    fim_malware_row = await session.execute(
        text("""
            SELECT
              COUNT(*) FILTER (WHERE category = 'fim')     AS fim_count,
              COUNT(*) FILTER (WHERE category = 'malware') AS malware_count,
              COALESCE(SUM(base_score)::float, 0)          AS total_score
            FROM alerts
            WHERE agent_id = :aid
              AND category IN ('fim','malware')
              AND timestamp > NOW() - INTERVAL '30 days'
        """),
        {"aid": agent_id},
    )
    fm_row = fim_malware_row.fetchone()
    fim_count     = int(fm_row.fim_count)     if fm_row else 0
    malware_count = int(fm_row.malware_count) if fm_row else 0
    fm_total_score = float(fm_row.total_score) if fm_row else 0.0
    # Penalise up to 100 points worth of severity; a score of 100 → component 0
    fim_malware_component = max(0, min(100, round(100 - min(100, fm_total_score), 1)))

    # ── Component 5: Compliance gap (SCA failures → controls failing, weight 10%) ─
    # Simple proxy: SCA fail rate on this host
    if sca_total > 0:
        compliance_score = round((sca_passed / sca_total) * 100, 1)
    else:
        compliance_score = 100.0  # no SCA data → neutral assumption

    # ── Active incidents ──────────────────────────────────────────────────────
    inc_row = await session.execute(
        text("""
            SELECT COUNT(*) FROM incidents
            WHERE :aid = ANY(affected_agents)
              AND status NOT IN ('closed','false_positive')
        """),
        {"aid": agent_id},
    )
    incident_count = inc_row.scalar() or 0

    # ── Recent MITRE techniques ───────────────────────────────────────────────
    mitre_row = await session.execute(
        text("""
            SELECT ARRAY_AGG(DISTINCT mitre_id) AS techniques
            FROM alerts
            WHERE agent_id = :aid
              AND mitre_id IS NOT NULL
              AND timestamp > NOW() - INTERVAL '30 days'
        """),
        {"aid": agent_id},
    )
    mitre_techniques = mitre_row.scalar() or []

    # ── Composite score ───────────────────────────────────────────────────────
    weights = {
        "sca":        0.30,
        "vuln":       0.25,
        "siem_risk":  0.25,
        "fim_malware":0.10,
        "compliance": 0.10,
    }
    # Use neutral 50 for any component where data is unavailable
    components = {
        "sca":         sca_score         if sca_score   is not None else 50.0,
        "vuln":        vuln_score        if vuln_score  is not None else 50.0,
        "siem_risk":   siem_risk_inverted,
        "fim_malware": fim_malware_component,
        "compliance":  compliance_score,
    }
    composite = sum(components[k] * weights[k] for k in weights)
    composite  = round(composite, 1)

    return {
        "sca_passed":        sca_passed,
        "sca_failed":        sca_failed,
        "sca_total":         sca_total,
        "sca_score":         sca_score,
        "vuln_critical":     vuln_critical,
        "vuln_high":         vuln_high,
        "vuln_medium":       vuln_medium,
        "vuln_low":          vuln_low,
        "vuln_score":        vuln_score,
        "siem_risk":         siem_risk_raw,
        "fim_event_count":   fim_count,
        "malware_count":     malware_count,
        "compliance_score":  compliance_score,
        "mitre_techniques":  mitre_techniques,
        "incident_count":    int(incident_count),
        "posture_score":     composite,
        "posture_grade":     _score_to_grade(composite),
        "score_breakdown":   components,
    }


# ── Agent list fetch ──────────────────────────────────────────────────────────

async def _fetch_registry_agents(session: AsyncSession) -> list[dict]:
    """Return agent dicts from CyEDR/CyCollector's own registries — no Wazuh
    Manager API call. Agent enrollment/connection state is Manager-side state
    with no Kafka/data-lake equivalent, so it has to come from an agent
    registry table (see docs/SIEM_PROXY_AUDIT.md)."""
    rows = await session.execute(
        text("""
            SELECT agent_id, hostname, agent_ip, os_type, last_seen
            FROM edr_agents WHERE status <> 'removed'
            UNION ALL
            SELECT agent_id, hostname, agent_ip, os_type, last_seen
            FROM collector_agents WHERE status <> 'removed'
        """)
    )
    return [
        {
            "id": r.agent_id, "name": r.hostname or r.agent_id, "ip": r.agent_ip,
            "status": _liveness(r.last_seen), "os_platform": r.os_type,
            "os_version": None,
            "last_keepalive": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows.fetchall()
    ]


async def _db_agent_ids(session: AsyncSession) -> list[dict]:
    """Agent IDs known from the alerts table (catches connector-sourced
    entities with no registry row of their own)."""
    rows = await session.execute(
        text("""
            SELECT DISTINCT agent_id, agent_name, agent_ip
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '90 days'
        """)
    )
    return [{"id": r.agent_id, "name": r.agent_name, "ip": r.agent_ip} for r in rows.fetchall()]


# ── Main refresh coroutine (called by scheduler) ──────────────────────────────

async def refresh_all_hosts(session: AsyncSession) -> int:
    """Refresh host_posture_cache for all known agents. Returns count refreshed."""
    from cysiemstack.correlation_engine.models import HostPostureCache

    # Merge CyEDR/CyCollector registry agents with alerts-table-only stragglers
    registry_agents = {a["id"]: a for a in await _fetch_registry_agents(session)}
    db_agents        = await _db_agent_ids(session)

    all_agents: dict[str, dict] = {}
    for a in db_agents:
        all_agents[a["id"]] = {
            "id":           a["id"],
            "name":         a.get("name") or a["id"],
            "ip":           a.get("ip"),
            "status":       "unknown",
            "os_platform":  None,
            "os_version":   None,
            "last_keepalive": None,
        }
    for aid, a in registry_agents.items():
        all_agents[aid] = a

    # Hostname-stem dedup: same physical host re-enrolled under a new name
    # (roaming laptops, hostname changes across networks). CyEDR/CyCollector
    # already dedupe by hardware_uuid at enrollment time, so this only remains
    # a safety net for alerts-table-only ghost entries with no registry row.
    _stem_seen: dict[str, str] = {}
    _stem_deduped: dict[str, dict] = {}
    for _aid, _info in all_agents.items():
        _plat = (_info.get("os_platform") or "").lower()
        _stem = _HOSTNAME_STEM_RE.sub("", (_info.get("name") or _aid).lower()).strip()
        _sk   = f"{_stem}|{_plat}"
        if not _plat:
            _stem_deduped[_aid] = _info
            continue
        if _sk not in _stem_seen:
            _stem_seen[_sk] = _aid
            _stem_deduped[_aid] = _info
        else:
            _prev_aid = _stem_seen[_sk]
            if (_info.get("last_keepalive") or "") > (all_agents[_prev_aid].get("last_keepalive") or ""):
                del _stem_deduped[_prev_aid]
                _stem_seen[_sk] = _aid
                _stem_deduped[_aid] = _info
    all_agents = _stem_deduped

    refreshed = 0
    for agent_id, agent_info in all_agents.items():
        try:
            async with session.begin_nested():
                posture = await _compute_host_posture(agent_id, session)

                # Upsert into host_posture_cache
                existing = await session.get(HostPostureCache, agent_id)
                if existing is None:
                    existing = HostPostureCache(agent_id=agent_id)
                    session.add(existing)

                existing.agent_name      = agent_info["name"]
                existing.agent_ip        = agent_info["ip"]
                existing.os_platform     = agent_info["os_platform"]
                existing.os_version      = agent_info["os_version"]
                existing.wazuh_status    = agent_info["status"]
                existing.last_keepalive  = (
                    datetime.fromisoformat(agent_info["last_keepalive"].replace("Z", "+00:00"))
                    if agent_info.get("last_keepalive") else None
                )
                existing.posture_score   = posture["posture_score"]
                existing.posture_grade   = posture["posture_grade"]
                existing.sca_score       = posture["sca_score"]
                existing.sca_passed      = posture["sca_passed"]
                existing.sca_failed      = posture["sca_failed"]
                existing.sca_total       = posture["sca_total"]
                existing.vuln_score      = posture["vuln_score"]
                existing.vuln_critical   = posture["vuln_critical"]
                existing.vuln_high       = posture["vuln_high"]
                existing.vuln_medium     = posture["vuln_medium"]
                existing.vuln_low        = posture["vuln_low"]
                existing.siem_risk       = posture["siem_risk"]
                existing.fim_event_count = posture["fim_event_count"]
                existing.malware_count   = posture["malware_count"]
                existing.incident_count  = posture["incident_count"]
                existing.compliance_score= posture["compliance_score"]
                existing.mitre_techniques= posture["mitre_techniques"]
                existing.score_breakdown = posture["score_breakdown"]
                existing.computed_at     = datetime.now(timezone.utc)
            refreshed += 1
        except Exception as exc:
            log.warning("[host_service] posture compute failed for %s: %s", agent_id, exc)

    await session.commit()
    log.info("[host_service] refreshed posture for %d hosts", refreshed)

    # Evict cache rows whose agent_id was removed by name-based deduplication
    surviving_ids = list(all_agents.keys())
    if surviving_ids:
        from cysiemstack.correlation_engine.models import HostPostureCache
        from sqlalchemy import delete as _sa_delete
        result = await session.execute(
            _sa_delete(HostPostureCache).where(
                ~HostPostureCache.agent_id.in_(surviving_ids)
            )
        )
        if result.rowcount:
            log.info("[host_service] evicted %d stale duplicate cache rows", result.rowcount)
        await session.commit()

    return refreshed


# ── Query helpers used by Flask routes ────────────────────────────────────────

async def get_all_hosts_summary(
    session: AsyncSession,
    status_filter: Optional[str] = None,
    sort_by: str = "posture_score",
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Return paginated host list with posture summary + overall internal posture."""
    from cysiemstack.correlation_engine.models import HostPostureCache

    stmt = select(HostPostureCache)
    if status_filter and status_filter != "all":
        stmt = stmt.where(HostPostureCache.wazuh_status == status_filter)

    sort_col = {
        "posture_score": HostPostureCache.posture_score,
        "risk":          HostPostureCache.siem_risk,
        "name":          HostPostureCache.agent_name,
    }.get(sort_by, HostPostureCache.posture_score)
    stmt = stmt.order_by(sort_col)

    count_stmt = select(func.count()).select_from(HostPostureCache)
    total = (await session.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * per_page
    stmt = stmt.offset(offset).limit(per_page)
    rows = (await session.execute(stmt)).scalars().all()

    hosts = []
    for h in rows:
        hosts.append({
            "agent_id":      h.agent_id,
            "agent_name":    h.agent_name,
            "agent_ip":      h.agent_ip,
            "os_platform":   h.os_platform,
            "wazuh_status":  h.wazuh_status,
            "last_keepalive": h.last_keepalive.isoformat() if h.last_keepalive else None,
            "posture_score":  float(h.posture_score) if h.posture_score is not None else None,
            "posture_grade":  h.posture_grade,
            "siem_risk":      float(h.siem_risk)     if h.siem_risk     is not None else None,
            "vuln_critical":  h.vuln_critical,
            "vuln_high":      h.vuln_high,
            "incident_count": h.incident_count,
            "asset_tier":     h.asset_tier,
            "computed_at":    h.computed_at.isoformat() if h.computed_at else None,
        })

    internal_posture = await get_internal_posture(session)

    return {
        "hosts":            hosts,
        "total":            total,
        "page":             page,
        "per_page":         per_page,
        "internal_posture": internal_posture,
    }


async def get_host_detail(agent_id: str, session: AsyncSession) -> Optional[dict]:
    """Return full host profile from cache + recent alerts by category."""
    from cysiemstack.correlation_engine.models import HostPostureCache

    host = await session.get(HostPostureCache, agent_id)
    if not host:
        return None

    # Recent alerts grouped by category (last 30 days)
    cat_rows = await session.execute(
        text("""
            SELECT category, COUNT(*) AS cnt,
                   MAX(timestamp) AS last_seen,
                   MAX(rule_level) AS max_level
            FROM alerts
            WHERE agent_id = :aid
              AND timestamp > NOW() - INTERVAL '30 days'
            GROUP BY category
            ORDER BY cnt DESC
        """),
        {"aid": agent_id},
    )
    alerts_by_category = {
        r.category: {
            "count":     int(r.cnt),
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "max_level": r.max_level,
        }
        for r in cat_rows.fetchall()
    }

    # Active incidents
    inc_rows = await session.execute(
        text("""
            SELECT id, severity, status, first_seen, last_seen,
                   llm_summary, mitre_ids, case_opened_at
            FROM incidents
            WHERE :aid = ANY(affected_agents)
              AND status NOT IN ('closed','false_positive')
            ORDER BY last_seen DESC
            LIMIT 10
        """),
        {"aid": agent_id},
    )
    active_incidents = [
        {
            "id":             r.id,
            "severity":       r.severity,
            "status":         r.status,
            "first_seen":     r.first_seen.isoformat() if r.first_seen else None,
            "last_seen":      r.last_seen.isoformat()  if r.last_seen  else None,
            "summary":        r.llm_summary,
            "mitre_ids":      r.mitre_ids or [],
            "case_opened_at": r.case_opened_at.isoformat() if r.case_opened_at else None,
        }
        for r in inc_rows.fetchall()
    ]

    # Top MITRE techniques with counts
    mitre_rows = await session.execute(
        text("""
            SELECT mitre_id, mitre_tactic, COUNT(*) AS cnt
            FROM alerts
            WHERE agent_id = :aid
              AND mitre_id IS NOT NULL
              AND timestamp > NOW() - INTERVAL '30 days'
            GROUP BY mitre_id, mitre_tactic
            ORDER BY cnt DESC
            LIMIT 15
        """),
        {"aid": agent_id},
    )
    mitre_breakdown = [
        {"mitre_id": r.mitre_id, "tactic": r.mitre_tactic, "count": int(r.cnt)}
        for r in mitre_rows.fetchall()
    ]

    # Compliance gaps from SCA failures
    sca_alert_rows = await session.execute(
        text("""
            SELECT
              full_alert->'data'->'sca'->'check'->>'title'    AS title,
              full_alert->'data'->'sca'->'check'->>'result'   AS result,
              full_alert->'data'->'sca'->'check'->>'rationale' AS rationale,
              full_alert->'data'->'sca'->>'policy_id'         AS policy_id,
              timestamp
            FROM alerts
            WHERE agent_id = :aid
              AND category = 'sca'
              AND (full_alert->'data'->'sca'->'check'->>'result') = 'failed'
              AND timestamp > NOW() - INTERVAL '7 days'
            ORDER BY timestamp DESC
            LIMIT 20
        """),
        {"aid": agent_id},
    )
    sca_failures = [
        {
            "title":     r.title,
            "result":    r.result,
            "rationale": r.rationale,
            "policy_id": r.policy_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in sca_alert_rows.fetchall()
    ]

    return {
        "agent_id":      host.agent_id,
        "agent_name":    host.agent_name,
        "agent_ip":      host.agent_ip,
        "os_platform":   host.os_platform,
        "os_version":    host.os_version,
        "wazuh_status":  host.wazuh_status,
        "last_keepalive": host.last_keepalive.isoformat() if host.last_keepalive else None,
        "asset_tier":    host.asset_tier,
        "posture": {
            "score":      float(host.posture_score) if host.posture_score is not None else None,
            "grade":      host.posture_grade,
            "breakdown":  host.score_breakdown or {},
            "computed_at": host.computed_at.isoformat() if host.computed_at else None,
        },
        "sca": {
            "passed": host.sca_passed,
            "failed": host.sca_failed,
            "total":  host.sca_total,
            "score":  float(host.sca_score) if host.sca_score is not None else None,
            "recent_failures": sca_failures,
        },
        "vulnerabilities": {
            "critical": host.vuln_critical,
            "high":     host.vuln_high,
            "medium":   host.vuln_medium,
            "low":      host.vuln_low,
            "score":    float(host.vuln_score) if host.vuln_score is not None else None,
        },
        "siem": {
            "risk_score":   float(host.siem_risk)     if host.siem_risk     is not None else None,
            "fim_events":   host.fim_event_count,
            "malware_detections": host.malware_count,
            "active_incidents":   active_incidents,
            "incident_count":     host.incident_count,
        },
        "mitre": {
            "techniques":  host.mitre_techniques or [],
            "breakdown":   mitre_breakdown,
        },
        "compliance": {
            "score":       float(host.compliance_score) if host.compliance_score is not None else None,
            "sca_failures": len(sca_failures),
        },
        "alerts_by_category": alerts_by_category,
    }


async def get_internal_posture(session: AsyncSession) -> dict:
    """Compute overall internal security posture score across all hosts.

    Weights hosts by asset_tier: tier-1 (crown jewel) = 3x, tier-2 = 2x, tier-3 = 1x.
    Returns 0-100 score, grade, component breakdown, trend direction, worst hosts.
    """
    from cysiemstack.correlation_engine.models import HostPostureCache

    rows = (await session.execute(select(HostPostureCache))).scalars().all()
    if not rows:
        return {"score": None, "grade": "—", "host_count": 0, "components": {}, "worst_hosts": []}

    tier_weight = {1: 3.0, 2: 2.0, 3: 1.0}
    weighted_sum   = 0.0
    total_weight   = 0.0
    comp_sums      = {"sca": 0.0, "vuln": 0.0, "siem_risk": 0.0, "fim_malware": 0.0, "compliance": 0.0}
    comp_weights   = {k: 0.0 for k in comp_sums}

    active_count = critical_grade = 0

    for h in rows:
        if h.posture_score is None:
            continue
        w  = tier_weight.get(h.asset_tier or 3, 1.0)
        weighted_sum += float(h.posture_score) * w
        total_weight += w
        bd = h.score_breakdown or {}
        for k in comp_sums:
            if k in bd:
                comp_sums[k]    += float(bd[k]) * w
                comp_weights[k] += w
        if h.wazuh_status == "active":
            active_count += 1
        if h.posture_grade in ("F", "D"):
            critical_grade += 1

    if total_weight == 0:
        return {"score": None, "grade": "—", "host_count": len(rows), "components": {}, "worst_hosts": []}

    overall = round(weighted_sum / total_weight, 1)

    components = {}
    for k in comp_sums:
        if comp_weights[k] > 0:
            components[k] = {
                "score":  round(comp_sums[k] / comp_weights[k], 1),
                "weight": {"sca": 0.30, "vuln": 0.25, "siem_risk": 0.25,
                           "fim_malware": 0.10, "compliance": 0.10}[k],
            }

    worst = sorted(
        [h for h in rows if h.posture_score is not None],
        key=lambda h: float(h.posture_score),
    )[:5]
    worst_hosts = [
        {
            "agent_id":   h.agent_id,
            "agent_name": h.agent_name,
            "score":      float(h.posture_score),
            "grade":      h.posture_grade,
            "siem_risk":  float(h.siem_risk) if h.siem_risk is not None else None,
        }
        for h in worst
    ]

    return {
        "score":        overall,
        "grade":        _score_to_grade(overall),
        "host_count":   {"total": len(rows), "active": active_count, "critical_grade": critical_grade},
        "components":   components,
        "worst_hosts":  worst_hosts,
    }


async def set_host_asset_tier(agent_id: str, tier: int, session: AsyncSession) -> bool:
    """Update the asset criticality tier for a host (1=crown jewel, 2=biz critical, 3=standard)."""
    from cysiemstack.correlation_engine.models import HostPostureCache

    if tier not in (1, 2, 3):
        return False
    host = await session.get(HostPostureCache, agent_id)
    if not host:
        return False
    host.asset_tier = tier
    await session.commit()
    return True
