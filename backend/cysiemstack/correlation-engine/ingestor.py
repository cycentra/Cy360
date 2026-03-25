"""
ingestor.py
Reads raw Wazuh alerts from Redis LIST (populated by Filebeat),
normalises them, and drives the full pipeline:
  normalise → group → correlate → UEBA → risk_score → MISP → LLM → WebSocket push
"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
import redis.asyncio as aioredis
import structlog
from sqlalchemy import select
from models import AsyncSessionLocal, Alert
from normaliser import normalise
from grouper import group_alert
from correlator import run_correlation
from ueba import analyse_alert
from risk_scorer import calculate_entity_risk
from misp_enricher import enrich_incident
from llm_enricher import enrich_incident as llm_enrich_incident
from ueba_ml import ml_analyse_alert
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

UEBA_CONTEXT_WINDOW   = timedelta(hours=2)
LLM_TRIGGER_SEVERITY  = {"critical", "high"}
LLM_TRIGGER_MIN_ALERTS = 3


async def _get_recent_user_alerts(db, username: str, cutoff: datetime) -> list[dict]:
    result = await db.execute(
        select(Alert).where(
            Alert.username  == username,
            Alert.timestamp >= cutoff,
        ).order_by(Alert.timestamp.desc()).limit(100)
    )
    return [
        {
            'rule_id':  a.rule_id,
            'agent_id': a.agent_id,
            'timestamp': a.timestamp,
            'src_ip':   str(a.src_ip) if a.src_ip else None,
        }
        for a in result.scalars().all()
    ]


async def _process_alert(raw_bytes: bytes, pubsub: aioredis.Redis):
    try:
        raw = json.loads(raw_bytes)
    except json.JSONDecodeError:
        log.warning("alert_json_decode_error", raw=raw_bytes[:200])
        return

    alert = normalise(raw)
    if not alert:
        return

    async with AsyncSessionLocal() as db:
        try:
            # 1. Group → Incident
            incident, created = await group_alert(db, alert)

            # 2. Correlation rules
            new_rules = await run_correlation(db, incident, alert)

            # 3. UEBA
            ueba_anomalies = []
            if alert.get("username"):
                cutoff = alert["timestamp"] - UEBA_CONTEXT_WINDOW
                recent = await _get_recent_user_alerts(db, alert["username"], cutoff)
                ueba_anomalies  = await analyse_alert(db, alert, recent, incident.id)
                ml_anomalies    = await ml_analyse_alert(db, alert, recent, incident.id)
                ueba_anomalies.extend(ml_anomalies)

            # 4. Risk scoring
            await calculate_entity_risk(
                db, alert["agent_id"],
                alert.get("agent_name", alert["agent_id"]), "host"
            )
            if alert.get("username"):
                await calculate_entity_risk(db, alert["username"], alert["username"], "user")

            # 5. MISP enrichment (new incidents or new correlation rules)
            misp_result = {}
            if created or new_rules:
                misp_result = await enrich_incident(db, incident)

            # 6. LLM enrichment (critical/high with ≥3 alerts, throttled)
            llm_result = {}
            if (incident.severity in LLM_TRIGGER_SEVERITY and
                    incident.alert_count >= LLM_TRIGGER_MIN_ALERTS and
                    not incident.llm_summary):
                llm_result = await llm_enrich_incident(db, incident)

            await db.commit()

            # 7. Push live event to WebSocket clients
            event = {
                "type":              "alert_processed",
                "timestamp":         datetime.now(timezone.utc).isoformat(),
                "incident_id":       incident.id,
                "incident_severity": incident.severity,
                "incident_status":   incident.status,
                "alert_count":       incident.alert_count,
                "created":           created,
                "new_rules":         [r["rule_id"] for r in new_rules],
                "ueba_anomalies":    len(ueba_anomalies),
                "misp_hits":         len(misp_result.get("ioc_hits", [])),
                "llm_ready":         bool(llm_result),
                "agent_name":        alert.get("agent_name"),
                "rule_desc":         alert.get("rule_desc"),
            }
            await pubsub.publish("cysiemstack:live", json.dumps(event, default=str))

            log.info("alert_processed",
                     incident=incident.id, severity=incident.severity,
                     new_rules=len(new_rules), ueba=len(ueba_anomalies))

        except Exception as e:
            await db.rollback()
            log.error("alert_processing_error", error=str(e), exc_info=True)


async def run_ingestor():
    """Main ingestor loop — blocks on Redis BLPOP."""
    redis       = aioredis.from_url(settings.redis_url, decode_responses=False)
    pubsub_redis = aioredis.from_url(settings.redis_url, decode_responses=True)

    log.info("ingestor_started", key=settings.redis_alert_key)

    while True:
        try:
            result = await redis.blpop(settings.redis_alert_key, timeout=2)
            if result:
                _, raw_bytes = result
                await _process_alert(raw_bytes, pubsub_redis)
        except asyncio.CancelledError:
            log.info("ingestor_stopped")
            break
        except Exception as e:
            log.error("ingestor_loop_error", error=str(e))
            await asyncio.sleep(1)

    await redis.aclose()
    await pubsub_redis.aclose()
