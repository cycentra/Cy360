"""
risk_scorer.py
Composite 0–100 risk scoring per entity (host or user).

Score breakdown (max 100):
  alert_severity    35   log-scale aggregation of base_scores
  incident_severity 30   weighted by severity level + correlated rules
  ueba_anomalies    25   sum of anomaly risk contributions (users only)
  misp_ioc_hits     10   confirmed threat actor infrastructure

Time decay: score decays linearly over RISK_DECAY_HOURS without new activity.
Trend: rising / stable / falling based on previous score comparison.
"""
import math
from datetime import datetime, timezone, timedelta
from typing import Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from models import Alert, Incident, UEBAAnomaly, RiskScore, MISPIOCCache, IncidentPattern
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

SEV_WEIGHTS = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

# Named constants for compute_fp_score() and _asset_score()
DEFAULT_ASSET_TIER = 3          # treat unknown/None tier as dev/low

# Cloud integration service entities — tracked as separate risk entities
# entity_id = category string, entity_name = human-readable label
CLOUD_ENTITY_NAMES: dict[str, str] = {
    'o365':   'Microsoft 365',
    'azure':  'Microsoft Azure',
    'aws':    'AWS',
    'gcp':    'Google Cloud',
    'github': 'GitHub',
}


def _alert_severity_score(alerts: list, max_points: float = 35.0) -> float:
    """Log-scale aggregation: many medium alerts ≠ one critical."""
    if not alerts:
        return 0.0
    total = sum(float(a.base_score or 0) for a in alerts)
    raw   = math.log1p(total) * 3.5
    return round(min(raw, max_points), 1)


def _incident_severity_score(incidents: list, max_points: float = 30.0) -> float:
    """Weighted by severity + correlated rule count + ENH-7: confidence weighting."""
    if not incidents:
        return 0.0
    total = 0.0
    for inc in incidents:
        w     = SEV_WEIGHTS.get(inc.severity, 1)
        rules = inc.correlated_rules or []
        # ENH-7: sum rule confidence values (default 0.5 for rules without confidence)
        rule_weight = sum(float(r.get('confidence', 0.5)) for r in rules) if rules else 0
        contrib = w * (1 + rule_weight)
        total  += contrib
    raw = math.log1p(total) * 5
    return round(min(raw, max_points), 1)


def _ueba_score(anomalies: list, max_points: float = 25.0) -> float:
    """Sum of anomaly risk_contribution values, capped."""
    total = sum(a.risk_contribution or 0 for a in anomalies)
    return round(min(float(total), max_points), 1)


def _misp_score(alerts: list, max_points: float = 10.0) -> float:
    """Bonus for confirmed MISP IOC hits."""
    hits = sum(1 for a in alerts if a.misp_ioc_match)
    return round(min(hits * 2.5, max_points), 1)


def _apply_decay(score: float, last_seen: datetime, decay_hours: int) -> float:
    """Linear decay to 0 over decay_hours with no new activity."""
    if not last_seen:
        return score
    age_hours = (datetime.now(timezone.utc) - last_seen).total_seconds() / 3600
    if age_hours <= 0:
        return score
    factor = max(0.0, 1.0 - (age_hours / decay_hours))
    return round(score * factor, 1)


def _level_for_score(score: float) -> str:
    if score >= 75:
        return 'critical'
    if score >= 50:
        return 'high'
    if score >= 25:
        return 'medium'
    return 'low'


def _asset_score(asset_tier: Optional[int], max_points: float = 20.0) -> float:
    """Bonus risk points for high-value asset tiers.

    tier 1 (crown jewel)      → +20 pts (max)
    tier 2 (business critical)→ +10 pts
    tier 3 (dev/low)          →   0 pts
    None / unknown            →   0 pts
    """
    if asset_tier == 1:
        return max_points
    if asset_tier == 2:
        return max_points / 2
    return 0.0


def compute_fp_score(
    avg_conf: float,
    ueba_anomaly_count: int,
    misp_ioc_hits: int,
    kill_chain_stage_name: Optional[str],
    asset_tier: Optional[int],
) -> float:
    """Multi-factor false-positive probability (0–100, high = likely FP).

    Factors (applied in order):
      1. Base: (1 − avg_rule_confidence) × 100
      2. UEBA penalty: each anomaly reduces FP probability by 8 pts (cap 30)
      3. MISP IOC hit multiplier: ×0.6 per batch of hits; floor 5 if any hit
      4. Kill-chain stage cap/floor
      5. Asset criticality cap/floor
    """
    base: float = (1.0 - max(0.0, min(1.0, avg_conf))) * 100.0

    # UEBA anomalies are evidence of a real threat → lower FP probability
    ueba_penalty = min(ueba_anomaly_count * 8, 30)
    base -= ueba_penalty

    # MISP IOC hit multiplier
    if misp_ioc_hits > 0:
        base *= 0.6
        base = max(base, 5.0)

    # Kill-chain stage cap/floor
    kc = (kill_chain_stage_name or "").lower().replace(" ", "-")
    if kc in ("exfiltration", "c2", "command-and-control", "actions-on-objectives",
              "command and control"):
        base = min(base, 30.0)
    elif kc in ("reconnaissance", "weaponization"):
        base = max(base, 65.0)

    # Asset criticality
    tier = asset_tier if asset_tier is not None else DEFAULT_ASSET_TIER
    if tier == 1:
        base = min(base, 20.0)
    elif tier == 3:
        # Tier-3 (dev/low) assets have a slightly elevated FP floor — they are
        # less likely to be targeted and less likely to warrant immediate action.
        # Floor is 30, NOT 40: a floor of 40 would keep every tier-3 incident
        # permanently in Band 2 (fp >= 40 → investigating) and prevent Band 3
        # (fp < 40 → in_review + case) from ever triggering — since most assets
        # have no explicit tier (DEFAULT_ASSET_TIER=3), this blocked all auto
        # case creation.
        base = max(base, 30.0)

    return round(max(0.0, min(100.0, base)), 1)


# ── Phase 4: Investigation Confidence Engine ──────────────────────────────────
# Component weights (sum = 1.0 when all active)
_CONF_WEIGHTS: dict[str, float] = {
    "rule":        0.30,
    "ti":          0.25,
    "historical":  0.20,
    "asset":       0.10,
    "llm":         0.15,
}

_TI_VERDICT_SCORES: dict[str, float] = {
    "malicious":  1.0,
    "suspicious": 0.6,
    "clean":      0.0,
    "benign":     0.0,
}


def _rule_confidence_score(incident) -> float:
    """Rule contribution score 0–1 from correlated_rules confidence values.

    Uses average confidence of fired rules — matches component intent in the
    confidence model (high-confidence rules → genuine threat → high confidence).
    Falls back to severity-derived score when no rules fired.
    """
    rules = incident.correlated_rules or []
    if rules:
        confs = [float(r.get("confidence", 0.5)) for r in rules]
        return max(0.0, min(1.0, sum(confs) / len(confs)))
    # Severity fallback
    sev_map = {"critical": 0.9, "high": 0.75, "medium": 0.5, "low": 0.25}
    return sev_map.get((incident.severity or "low").lower(), 0.25)


def _ti_confidence_score(ti_reputation: dict | None) -> float:
    """TI verdict → 0–1 score.  Missing TI contributes 0.3 (neutral, not zero)."""
    if not ti_reputation:
        return 0.3
    verdict = (ti_reputation.get("verdict") or "unknown").lower()
    if verdict in _TI_VERDICT_SCORES:
        return _TI_VERDICT_SCORES[verdict]
    # Partial signal: use raw confidence percentage if present
    raw_conf = ti_reputation.get("confidence")
    if raw_conf is not None:
        return max(0.0, min(1.0, float(raw_conf) / 100.0)) * 0.6
    return 0.3


def _asset_confidence_score(asset_tier: Optional[int]) -> float:
    """Asset criticality → 0–1 normalized confidence contribution.

    Tier 1 (crown jewel)   → 1.0  — high-value targets warrant high attention
    Tier 2 (biz critical)  → 0.6
    Tier 3 / unknown       → 0.2  — dev/low tier = less likely genuine attack
    """
    if asset_tier == 1:
        return 1.0
    if asset_tier == 2:
        return 0.6
    return 0.2


def compute_investigation_confidence(
    incident,
    ti_reputation: dict | None,
    top_hypothesis_prob: Optional[int],
    asset_tier: Optional[int],
    historical_similarity: float = 0.0,
) -> tuple[float, dict]:
    """Compute 5-component investigation confidence score (0–1).

    Until Phase 6 deploys historical_similarity data, historical weight is
    redistributed proportionally across the other four components so the
    achievable maximum remains 1.0.

    Returns:
        (confidence_0_to_1, breakdown_dict)  — breakdown keyed by component
        name with {score, weight, contribution} sub-dicts.
    """
    scores = {
        "rule":       _rule_confidence_score(incident),
        "ti":         _ti_confidence_score(ti_reputation),
        "historical": max(0.0, min(1.0, historical_similarity)),
        "asset":      _asset_confidence_score(asset_tier),
        "llm":        max(0.0, min(1.0, (top_hypothesis_prob or 0) / 100.0)),
    }

    # Build effective weights: drop historical from denominator if 0 (Phase 6 not active)
    effective_weights: dict[str, float] = {}
    for name, base_w in _CONF_WEIGHTS.items():
        if name == "historical" and scores["historical"] == 0.0:
            effective_weights[name] = 0.0
        else:
            effective_weights[name] = base_w

    denom = sum(effective_weights.values())
    if denom == 0.0:
        return 0.0, {}

    weighted_sum = sum(scores[k] * effective_weights[k] for k in scores)
    confidence = round(weighted_sum / denom, 4)

    breakdown = {
        k: {
            "score":        round(scores[k], 4),
            "weight":       round(effective_weights[k], 4),
            "contribution": round(scores[k] * effective_weights[k] / denom, 4),
            "label":        {
                "rule":       "Rule Contribution",
                "ti":         "Threat Intelligence",
                "historical": "Historical Similarity",
                "asset":      "Asset Criticality",
                "llm":        "LLM Reasoning",
            }[k],
        }
        for k in scores
    }

    return confidence, breakdown


async def compute_historical_similarity(
    db: AsyncSession,
    technique: Optional[str],
    kill_chain_stage: Optional[str],
) -> float:
    """Phase 6: Score 0–1 representing how closely this incident matches resolved patterns.

    Query strategy:
      1. Find up to 10 patterns with matching technique OR kill-chain stage.
      2. Score each match: technique match = 0.6, kill-chain match = 0.4.
      3. Return max score across all matches (0.0 if no patterns exist yet).

    Returns 0.0 when no patterns have been stored yet — the Phase 4 confidence engine
    redistributes that weight automatically via the zero-check in compute_investigation_confidence().
    Never raises.
    """
    if not technique and not kill_chain_stage:
        return 0.0

    try:
        from sqlalchemy import or_
        filters = []
        if technique:
            filters.append(IncidentPattern.technique == technique)
        if kill_chain_stage:
            filters.append(IncidentPattern.kill_chain_stage == kill_chain_stage)

        result = await db.execute(
            select(IncidentPattern.technique, IncidentPattern.kill_chain_stage)
            .where(or_(*filters))
            .limit(10)
        )
        rows = result.all()

        if not rows:
            return 0.0

        best = 0.0
        for row in rows:
            score = 0.0
            if technique and row[0] == technique:
                score += 0.60
            if kill_chain_stage and row[1] == kill_chain_stage:
                score += 0.40
            if score > best:
                best = score

        return round(min(1.0, best), 4)

    except Exception as exc:
        log.debug("historical_similarity_error", error=str(exc))
        return 0.0


def _trend(current: float, previous: Optional[float]) -> str:
    if previous is None:
        return 'stable'
    delta = current - previous
    if delta >= 5:
        return 'rising'
    if delta <= -5:
        return 'falling'
    return 'stable'


async def calculate_entity_risk(
    db: AsyncSession,
    entity_id: str,
    entity_name: str,
    entity_type: str,  # 'host' or 'user'
) -> RiskScore:
    """
    Recalculate risk score for a single entity.
    Creates or updates the risk_scores row.
    """
    now     = datetime.now(timezone.utc)
    cutoff  = now - timedelta(hours=settings.risk_decay_hours * 2)

    # Fetch recent alerts for this entity
    if entity_type == 'host':
        alerts_q = await db.execute(
            select(Alert).where(
                Alert.agent_id == entity_id,
                Alert.timestamp >= cutoff,
            )
        )
    elif entity_type == 'cloud':
        # Cloud service entities — alerts are identified by category (e.g. 'o365')
        alerts_q = await db.execute(
            select(Alert).where(
                Alert.category == entity_id,
                Alert.timestamp >= cutoff,
            )
        )
    else:  # user
        alerts_q = await db.execute(
            select(Alert).where(
                Alert.username == entity_id,
                Alert.timestamp >= cutoff,
            )
        )
    alerts = alerts_q.scalars().all()

    # Fetch open/recent incidents
    if entity_type == 'host':
        inc_q = await db.execute(
            select(Incident).where(
                Incident.affected_agents.any(entity_id),
                Incident.last_seen >= cutoff,
            ).limit(20)
        )
    elif entity_type == 'cloud':
        # Cloud entities — incidents where any category matches the cloud source
        inc_q = await db.execute(
            select(Incident).where(
                Incident.categories.any(entity_id),
                Incident.last_seen >= cutoff,
            ).limit(20)
        )
    else:
        inc_q = await db.execute(
            select(Incident).where(
                Incident.affected_users.any(entity_id),
                Incident.last_seen >= cutoff,
            ).limit(20)
        )
    incidents = inc_q.scalars().all()

    # Fetch UEBA anomalies (users only)
    anomalies = []
    if entity_type == 'user':
        anon_q = await db.execute(
            select(UEBAAnomaly).where(
                UEBAAnomaly.username == entity_id,
                UEBAAnomaly.resolved == False,
                UEBAAnomaly.detected_at >= cutoff,
            )
        )
        anomalies = anon_q.scalars().all()

    # Calculate components
    alert_sev  = _alert_severity_score(alerts)
    inc_sev    = _incident_severity_score(incidents)
    ueba       = _ueba_score(anomalies)
    misp       = _misp_score(alerts)

    # Asset criticality component (uses the most critical tier found in incidents)
    min_tier = min(
        (inc.asset_tier for inc in incidents if inc.asset_tier is not None),
        default=None
    )
    asset = _asset_score(min_tier)

    raw_score  = alert_sev + inc_sev + ueba + misp + asset

    # Apply time decay
    last_seen = max((a.timestamp for a in alerts), default=None) if alerts else None
    decayed   = _apply_decay(raw_score, last_seen, settings.risk_decay_hours)

    # Fetch or create record
    result = await db.execute(
        select(RiskScore).where(
            RiskScore.entity_id   == entity_id,
            RiskScore.entity_type == entity_type,
        )
    )
    record = result.scalar_one_or_none()

    prev_score = float(record.score) if record else None

    if record:
        record.prev_score       = prev_score
        record.score            = decayed
        record.level            = _level_for_score(decayed)
        record.trend            = _trend(decayed, prev_score)
        record.last_calculated  = now
        record.entity_name      = entity_name
        record.score_breakdown  = {
            'alert_severity':    alert_sev,
            'incident_severity': inc_sev,
            'ueba_anomalies':    ueba,
            'misp_ioc_hits':     misp,
            'asset_criticality': asset,
        }
    else:
        record = RiskScore(
            entity_id       = entity_id,
            entity_name     = entity_name,
            entity_type     = entity_type,
            score           = decayed,
            level           = _level_for_score(decayed),
            trend           = 'stable',
            last_calculated = now,
            score_breakdown = {
                'alert_severity':    alert_sev,
                'incident_severity': inc_sev,
                'ueba_anomalies':    ueba,
                'misp_ioc_hits':     misp,
                'asset_criticality': asset,
            },
        )
        db.add(record)

    await db.flush()
    return record


async def recalculate_all(db: AsyncSession) -> int:
    """Recalculate risk scores for entities seen in the last 24 h.
    Capped at 200 entities per run to prevent CPU saturation on high-volume deployments.
    Called every 600 s by the scheduler (was 300 s).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)   # was 48 h
    count  = 0
    CAP    = 200   # safety cap — protects 8 GB / 4 CPU servers under alert storms

    # All active hosts (most recent first, so highest-priority entities are scored)
    host_q = await db.execute(
        select(Alert.agent_id, Alert.agent_name)
        .where(Alert.timestamp >= cutoff)
        .distinct()
        .limit(CAP)
    )
    for agent_id, agent_name in host_q.all():
        await calculate_entity_risk(db, agent_id, agent_name or agent_id, 'host')
        count += 1
        if count >= CAP:
            break

    # All active users (within remaining cap headroom)
    if count < CAP:
        user_q = await db.execute(
            select(Alert.username)
            .where(Alert.timestamp >= cutoff, Alert.username.isnot(None))
            .distinct()
            .limit(CAP - count)
        )
        for (username,) in user_q.all():
            await calculate_entity_risk(db, username, username, 'user')
            count += 1

    # All active cloud integration sources
    cloud_q = await db.execute(
        select(Alert.category)
        .where(Alert.category.in_(CLOUD_ENTITY_NAMES.keys()), Alert.timestamp >= cutoff)
        .distinct()
        .limit(CAP - count)
    )
    for (cat,) in cloud_q.all():
        await calculate_entity_risk(db, cat, CLOUD_ENTITY_NAMES[cat], 'cloud')
        count += 1
        if count >= CAP:
            break

    await db.commit()
    log.info('risk_recalc_complete', entities=count)
    return count
