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
from risk_scorer import calculate_entity_risk, compute_fp_score
from misp_enricher import enrich_incident
from llm_enricher import enrich_incident as llm_enrich_incident
from iris_connector import create_iris_case, auto_close_fp
from ueba_ml import ml_analyse_alert
from cysoar_connector import cysoar_trigger
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

            # 3. UEBA — user-based and host-based paths
            ueba_anomalies = []
            if alert.get("username"):
                cutoff = alert["timestamp"] - UEBA_CONTEXT_WINDOW
                recent = await _get_recent_user_alerts(db, alert["username"], cutoff)
                ueba_anomalies  = await analyse_alert(db, alert, recent, incident.id,
                                                      entity_type="user")
                ml_anomalies    = await ml_analyse_alert(db, alert, recent, incident.id)
                ueba_anomalies.extend(ml_anomalies)
            else:
                # Host-based UEBA when no username is present
                host_entity = alert.get("agent_name") or alert.get("agent_id", "unknown")
                if host_entity:
                    cutoff = alert["timestamp"] - UEBA_CONTEXT_WINDOW
                    # Reuse per-user cache infrastructure for host entities
                    cache_key = f"host:{alert['agent_id']}"
                    now_ts_cache = time.monotonic()
                    cached_host = _ueba_ctx_cache.get(cache_key)
                    if cached_host and (now_ts_cache - cached_host[0]) < _UEBA_CTX_TTL:
                        recent_host = cached_host[1]
                    else:
                        result_host = await db.execute(
                            select(Alert).where(
                                Alert.agent_id  == alert['agent_id'],
                                Alert.timestamp >= cutoff,
                            ).order_by(Alert.timestamp.desc()).limit(100)
                        )
                        recent_host = [
                            {
                                'rule_id':   a.rule_id,
                                'agent_id':  a.agent_id,
                                'timestamp': a.timestamp,
                                'src_ip':    str(a.src_ip) if a.src_ip else None,
                            }
                            for a in result_host.scalars().all()
                        ]
                        _ueba_ctx_cache[cache_key] = (now_ts_cache, recent_host)

                    ueba_anomalies = await analyse_alert(db, alert, recent_host, incident.id,
                                                         entity_type="host")

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

            # ── Compute multi-factor FP probability ──────────────────────────
            def _fp_score_for(inc, ueba_anoms, misp_res) -> float:
                rules = inc.correlated_rules or []
                if rules:
                    avg_conf = sum(
                        float(r.get("confidence", 0.5)) for r in rules
                    ) / len(rules)
                else:
                    # No correlation rules → likely noise
                    avg_conf = 0.3 if inc.severity in ("low", "medium") else 0.7
                return compute_fp_score(
                    avg_conf          = avg_conf,
                    ueba_anomaly_count= len(ueba_anoms),
                    misp_ioc_hits     = len(misp_res.get("ioc_hits", [])),
                    kill_chain_stage_name = inc.kill_chain_stage_name,
                    asset_tier        = inc.asset_tier,
                )

            fp_score = _fp_score_for(incident, ueba_anomalies, misp_result)

            # Re-score AFTER enrichment completes with updated incident state
            # (MISP may have set ioc_hits; LLM may have updated stage info)
            fp_score = _fp_score_for(incident, ueba_anomalies,
                                     incident.misp_enrichment or {})

            # 6b. CySOAR trigger (after LLM, before IRIS)
            await cysoar_trigger(db, incident)

            # 7. CyIRIS integration — false-positive auto-close OR ticket creation
            #    Watch-zone: mid-range FP scores get "held" for re-enrichment.
            iris_result = {}
            iris_auto_closed = False

            if incident.status not in ("closed", "false_positive", "held"):
                # Read watch-zone upper threshold from ai_settings.json or config
                watch_zone_upper = _get_watch_zone_upper()
                iris_threshold   = _get_fp_threshold()

                incident.fp_probability = fp_score

                if fp_score > watch_zone_upper:
                    # High FP score → auto-close
                    iris_auto_closed = await auto_close_fp(db, incident, fp_score)
                elif fp_score > iris_threshold and fp_score <= watch_zone_upper:
                    # Mid-range → hold for re-enrichment
                    incident.status     = "held"
                    incident.updated_at = datetime.now(timezone.utc)
                    await db.flush()
                    asyncio.create_task(_reenrich_held_incident(incident.id))
                    log.info("incident_held_for_reenrichment",
                             incident_id=incident.id, fp_score=fp_score)
                else:
                    # Low FP score → create IRIS ticket
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
                "fp_probability":    fp_score,
                "agent_name":        alert.get("agent_name"),
                "rule_desc":         alert.get("rule_desc"),
            }
            await pubsub.publish("cysiemstack:live", _DUMPS(event))

            log.info("alert_processed",
                     incident=incident.id, severity=incident.severity,
                     new_rules=len(new_rules), ueba=len(ueba_anomalies),
                     fp_probability=fp_score)

        except Exception as e:
            await db.rollback()
            log.error("alert_processing_error", error=str(e), exc_info=True)


def _get_watch_zone_upper() -> float:
    """Read fpWatchZoneUpper from ai_settings.json or fall back to config."""
    try:
        from pathlib import Path
        import json as _j
        raw = Path("/opt/cycentra/ai_settings.json").read_text()
        stored = _j.loads(raw)
        val = stored.get("iris", {}).get("fpWatchZoneUpper")
        if val is not None:
            return float(val)
    except Exception:
        pass
    return settings.fp_watch_zone_upper


def _get_fp_threshold() -> float:
    """Read fpThreshold from ai_settings.json or fall back to config."""
    try:
        from pathlib import Path
        import json as _j
        raw = Path("/opt/cycentra/ai_settings.json").read_text()
        stored = _j.loads(raw)
        val = stored.get("iris", {}).get("fpThreshold")
        if val is not None:
            return float(val)
    except Exception:
        pass
    return settings.iris_fp_threshold


async def _reenrich_held_incident(incident_id: str) -> None:
    """Re-enrich a held incident after 30 minutes and promote/close it."""
    await asyncio.sleep(30 * 60)   # 30-minute hold window
    try:
        from sqlalchemy import select as sa_select
        async with AsyncSessionLocal() as db:
            from models import Incident as _Incident
            inc_q = await db.execute(
                sa_select(_Incident).where(
                    _Incident.id     == incident_id,
                    _Incident.status == "held",
                )
            )
            incident = inc_q.scalar_one_or_none()
            if not incident:
                return   # already handled by analyst

            # Re-run MISP enrichment with fresh data
            misp_result = await enrich_incident(db, incident)

            # Re-score with updated enrichment
            rules = incident.correlated_rules or []
            avg_conf = (
                sum(float(r.get("confidence", 0.5)) for r in rules) / len(rules)
                if rules else 0.3
            )
            ueba_count = len(incident.ueba_flags or [])
            fp_score = compute_fp_score(
                avg_conf            = avg_conf,
                ueba_anomaly_count  = ueba_count,
                misp_ioc_hits       = len(misp_result.get("ioc_hits", [])),
                kill_chain_stage_name = incident.kill_chain_stage_name,
                asset_tier          = incident.asset_tier,
            )
            incident.fp_probability = fp_score

            iris_threshold   = _get_fp_threshold()
            watch_zone_upper = _get_watch_zone_upper()

            if fp_score > watch_zone_upper:
                await auto_close_fp(db, incident, fp_score)
            else:
                # Promote to open so IRIS ticket gets created
                incident.status     = "open"
                incident.updated_at = datetime.now(timezone.utc)
                await db.flush()
                await create_iris_case(db, incident)

            await db.commit()
            log.info("held_incident_reprocessed",
                     incident_id=incident_id, fp_score=fp_score)
    except Exception as e:
        log.error("reenrich_held_incident_error",
                  incident_id=incident_id, error=str(e))


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
