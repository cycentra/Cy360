"""
ingestor.py
Reads raw Wazuh alerts from Redis LIST (populated by Filebeat),
normalises them, and drives the full pipeline:
  normalise → group → correlate → UEBA → risk_score → MISP → LLM → WebSocket push
"""
import asyncio
import time
try:
    import orjson as _json   # 5-10x faster than stdlib json; handles bytes natively
    _DUMPS = lambda obj: _json.dumps(obj, option=_json.OPT_NON_STR_KEYS).decode()
except ImportError:
    import json as _json
    _DUMPS = lambda obj: _json.dumps(obj, default=str)
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
from iris_connector import create_iris_case, auto_close_fp
from ueba_ml import ml_analyse_alert
from config import get_settings

log = structlog.get_logger()
settings = get_settings()

UEBA_CONTEXT_WINDOW   = timedelta(hours=2)
LLM_TRIGGER_SEVERITY  = {"critical", "high"}
LLM_TRIGGER_MIN_ALERTS = 3

# ── Performance optimisation: limit concurrent alert processing ──────────────
# On a 4-CPU / 8 GB server, processing every alert in parallel with full DB
# query chains causes memory and CPU saturation. Limit to 6 concurrent tasks.
_PROCESS_SEM = asyncio.Semaphore(6)

# ── UEBA context cache (per-username, 30 s TTL) ──────────────────────────────
# _get_recent_user_alerts is called on EVERY alert with a username — this saves
# the DB round-trip for high-frequency users generating bursts of events.
_ueba_ctx_cache: dict[str, tuple[float, list]] = {}   # username → (ts, rows)
_UEBA_CTX_TTL = 30.0   # seconds

# ── Per-entity risk scoring throttle ─────────────────────────────────────────
# calculate_entity_risk runs for every alert (host + optional user = up to 8 DB
# queries per alert). Throttle to once per entity per 60 s — the risk scheduler
# at 600 s handles batch recalculation for everything else.
_last_risk_calc: dict[str, float] = {}   # entity_id → epoch seconds
_RISK_CALC_MIN_INTERVAL = 60.0  # seconds


async def _get_recent_user_alerts(db, username: str, cutoff: datetime) -> list[dict]:
    # Return cached result if fresh enough — avoids a DB query on every alert burst
    now_ts = time.monotonic()
    cached = _ueba_ctx_cache.get(username)
    if cached and (now_ts - cached[0]) < _UEBA_CTX_TTL:
        return cached[1]

    result = await db.execute(
        select(Alert).where(
            Alert.username  == username,
            Alert.timestamp >= cutoff,
        ).order_by(Alert.timestamp.desc()).limit(100)
    )
    rows = [
        {
            'rule_id':  a.rule_id,
            'agent_id': a.agent_id,
            'timestamp': a.timestamp,
            'src_ip':   str(a.src_ip) if a.src_ip else None,
        }
        for a in result.scalars().all()
    ]
    _ueba_ctx_cache[username] = (now_ts, rows)
    return rows


async def _process_alert(raw_bytes: bytes, pubsub: aioredis.Redis):
    async with _PROCESS_SEM:   # limit concurrent processing to 6 tasks
        await _do_process_alert(raw_bytes, pubsub)


async def _do_process_alert(raw_bytes: bytes, pubsub: aioredis.Redis):
    try:
        raw = _json.loads(raw_bytes)   # orjson accepts bytes directly — no decode step
    except (ValueError, TypeError):
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

            # 4. Risk scoring — throttled per entity to avoid 8 DB queries per alert
            now_ts = time.monotonic()
            host_key = f"host:{alert['agent_id']}"
            if now_ts - _last_risk_calc.get(host_key, 0) >= _RISK_CALC_MIN_INTERVAL:
                await calculate_entity_risk(
                    db, alert["agent_id"],
                    alert.get("agent_name", alert["agent_id"]), "host"
                )
                _last_risk_calc[host_key] = now_ts
            if alert.get("username"):
                user_key = f"user:{alert['username']}"
                if now_ts - _last_risk_calc.get(user_key, 0) >= _RISK_CALC_MIN_INTERVAL:
                    await calculate_entity_risk(db, alert["username"], alert["username"], "user")
                    _last_risk_calc[user_key] = now_ts

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

            # 7. CyIRIS integration — false-positive auto-close OR ticket creation
            iris_result = {}
            iris_auto_closed = False
            # Use correlated rule confidence values to derive an FP score.
            # A simple heuristic: average rule confidence inverted (high rule
            # confidence = low FP probability).  Incidents with no rules or
            # very low severity get a higher FP score.
            if incident.status not in ("closed", "false_positive"):
                rules = incident.correlated_rules or []
                if rules:
                    avg_conf = sum(
                        float(r.get("confidence", 0.5)) for r in rules
                    ) / len(rules)
                    fp_score = round((1.0 - avg_conf) * 100, 1)
                else:
                    # No correlation rules fired → likely noise → higher FP score
                    fp_score = 70.0 if incident.severity in ("low", "medium") else 30.0

                iris_auto_closed = await auto_close_fp(db, incident, fp_score)

                if not iris_auto_closed and (created or new_rules):
                    iris_result = await create_iris_case(db, incident)

            await db.commit()

            # 8. Push live event to WebSocket clients
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
                "iris_case_id":      iris_result.get("iris_case_id"),
                "iris_auto_closed":  iris_auto_closed,
                "agent_name":        alert.get("agent_name"),
                "rule_desc":         alert.get("rule_desc"),
            }
            await pubsub.publish("cysiemstack:live", _DUMPS(event))

            log.info("alert_processed",
                     incident=incident.id, severity=incident.severity,
                     new_rules=len(new_rules), ueba=len(ueba_anomalies))

        except Exception as e:
            await db.rollback()
            log.error("alert_processing_error", error=str(e), exc_info=True)


async def run_ingestor():
    """Main ingestor loop — batch drain up to 10 alerts per cycle.

    Uses BLPOP to block until at least one alert is available, then immediately
    drains up to 9 more with non-blocking LPOP in a single pipeline call.
    This amortizes per-iteration overhead (event loop scheduling, Redis round
    trips) across a batch rather than paying it for every single alert.

    Each alert is spawned as an asyncio task; _PROCESS_SEM caps concurrency at 6.
    """
    redis        = aioredis.from_url(settings.redis_url, decode_responses=False)
    pubsub_redis = aioredis.from_url(settings.redis_url, decode_responses=True)

    log.info("ingestor_started", key=settings.redis_alert_key)
    BATCH_SIZE = 9   # additional alerts to drain after the blocking pop

    while True:
        try:
            # Block until at least one alert is ready (2 s timeout)
            result = await redis.blpop(settings.redis_alert_key, timeout=2)
            if not result:
                continue
            _, first = result
            batch = [first]

            # Non-blocking: drain up to BATCH_SIZE more in one pipeline round-trip
            if BATCH_SIZE > 0:
                pipe = redis.pipeline()
                for _ in range(BATCH_SIZE):
                    pipe.lpop(settings.redis_alert_key)
                extras = await pipe.execute()
                batch.extend(b for b in extras if b is not None)

            for raw_bytes in batch:
                asyncio.create_task(_process_alert(raw_bytes, pubsub_redis))

            if len(batch) > 1:
                log.debug("ingestor_batch", size=len(batch))

        except asyncio.CancelledError:
            log.info("ingestor_stopped")
            break
        except Exception as e:
            log.error("ingestor_loop_error", error=str(e))
            await asyncio.sleep(1)

    await redis.aclose()
    await pubsub_redis.aclose()
