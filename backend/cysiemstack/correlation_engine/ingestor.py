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
from risk_scorer import calculate_entity_risk, compute_fp_score, CLOUD_ENTITY_NAMES
from misp_enricher import enrich_incident
from ti_enricher import enrich_incident_ti
from llm_enricher import enrich_incident as llm_enrich_incident
from models import write_audit
from ueba_ml import ml_analyse_alert
from cysoar_connector import cysoar_trigger
from fp_pattern_store import check_fp_pattern
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
            'rule_id':    a.rule_id,
            'agent_id':   a.agent_id,
            'timestamp':  a.timestamp,
            'src_ip':     str(a.src_ip) if a.src_ip else None,
            # username and category are required by ueba.py detectors:
            #   token_theft heuristic filters distinct_ips by username
            #   data_staging, activity_volume_spike count category='fim' events
            #   ueba_ml._feature_vector computes recent_fim from category
            'username':   a.username,
            'category':   a.category,
            'rule_level': a.rule_level,
            'mitre_id':   a.mitre_id,
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
            # 0. FP Pattern check — suppress alert before pipeline if it matches
            #    a learned auto-close pattern (e.g. known-benign sudo commands).
            fp_match = await check_fp_pattern(db, alert)
            if fp_match:
                log.info(
                    "alert_suppressed_fp_pattern",
                    rule_id=alert.get("rule_id"),
                    agent_id=alert.get("agent_id"),
                    pattern_id=fp_match.id,
                    close_count=fp_match.close_count,
                )
                await write_audit(
                    db, "incident", "suppressed",
                    action="auto_fp",
                    actor="system",
                    comment=(
                        f"Alert suppressed by FP pattern #{fp_match.id} "
                        f"(rule {alert.get('rule_id')}, seen {fp_match.close_count}×)"
                    ),
                    extra={"fingerprint": fp_match.fingerprint[:16],
                           "rule_id": alert.get("rule_id")},
                )
                await db.commit()
                return

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
            # Cloud service entities (o365, azure, aws, gcp, github)
            cloud_name = CLOUD_ENTITY_NAMES.get(alert.get("category", ""))
            if cloud_name:
                cloud_key = f"cloud:{alert['category']}"
                if now_ts - _last_risk_calc.get(cloud_key, 0) >= _RISK_CALC_MIN_INTERVAL:
                    await calculate_entity_risk(db, alert["category"], cloud_name, "cloud")
                    _last_risk_calc[cloud_key] = now_ts

            # 1b. New incident → set initial status to "investigating" + audit entry
            if created:
                incident.status = "investigating"
                await db.flush()
                await write_audit(
                    db, "incident", incident.id,
                    action="status_change",
                    actor="system",
                    from_status="open",
                    to_status="investigating",
                    comment="Incident created automatically by correlation engine",
                    extra={"alert_count": incident.alert_count,
                           "severity": incident.severity},
                )

            # 5. MISP enrichment (new incidents or new correlation rules)
            misp_result = {}
            if created or new_rules:
                misp_result = await enrich_incident(db, incident)
                # Phase 1: follow up with unified TI enrichment (VT + AbuseIPDB + GreyNoise)
                await enrich_incident_ti(db, incident)

            # 6. LLM enrichment (critical/high with ≥3 alerts, throttled)
            # NOTE: LLM runs BEFORE SOAR — SOAR uses the enriched narrative.
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
                    avg_conf = 0.3 if inc.severity in ("low", "medium") else 0.7
                return compute_fp_score(
                    avg_conf          = avg_conf,
                    ueba_anomaly_count= len(ueba_anoms),
                    misp_ioc_hits     = len(misp_res.get("ioc_hits", [])),
                    kill_chain_stage_name = inc.kill_chain_stage_name,
                    asset_tier        = inc.asset_tier,
                )

            # Re-score with final enrichment state (MISP IOC hits may have updated)
            fp_score = _fp_score_for(incident, ueba_anomalies,
                                     incident.misp_enrichment or {})
            incident.fp_probability = fp_score

            # Soft severity cap: when FP probability is ≥ 75 the incident is more
            # likely noise than signal — drop one severity band so analysts do not
            # triage it before genuine high-confidence threats.
            # This does NOT auto-close (that happens below at fp_threshold); it only
            # reduces the displayed severity to reflect analytic confidence.
            if fp_score >= 75.0:
                _sev_order = ['low', 'medium', 'high', 'critical']
                cur_idx = _sev_order.index(incident.severity or 'low')
                if cur_idx > 0:
                    old_sev = incident.severity
                    incident.severity = _sev_order[cur_idx - 1]
                    log.info('severity_downgraded_by_fp',
                             incident_id=incident.id,
                             fp_score=fp_score,
                             from_severity=old_sev,
                             to_severity=incident.severity)

            # 6b. CySOAR trigger (after AI enrichment, before case decision)
            soar_actions = await cysoar_trigger(db, incident)
            if soar_actions:
                await write_audit(
                    db, "incident", incident.id,
                    action="soar_triggered",
                    actor="system",
                    comment=f"CySOAR triggered: {len(soar_actions)} action(s) taken",
                    extra={"soar_actions": soar_actions},
                )

            # 7. Confidence-score-based status advancement + native case opening
            fp_threshold = _get_fp_threshold()
            prev_status  = incident.status

            if fp_score >= fp_threshold:
                # Band 1: high FP probability → auto-close
                if incident.status not in ("closed",):
                    incident.status               = "closed"
                    incident.closed_at            = datetime.now(timezone.utc)
                    incident.updated_at           = datetime.now(timezone.utc)
                    incident.false_positive_reason = (
                        f"Auto-closed: FP probability {fp_score:.1f} ≥ threshold {fp_threshold:.1f}"
                    )
                    await db.flush()
                    await write_audit(
                        db, "incident", incident.id,
                        action="auto_close",
                        actor="system",
                        from_status=prev_status,
                        to_status="closed",
                        comment=incident.false_positive_reason,
                        extra={"fp_score": fp_score, "threshold": fp_threshold},
                    )
            elif fp_score >= 40.0:
                # Band 2: moderate FP → keep investigating
                if incident.status not in ("closed", "false_positive", "in_review", "resolved"):
                    new_s = "investigating"
                    if incident.status != new_s:
                        incident.status     = new_s
                        incident.updated_at = datetime.now(timezone.utc)
                        await db.flush()
                        await write_audit(
                            db, "incident", incident.id,
                            action="status_change",
                            actor="system",
                            from_status=prev_status,
                            to_status=new_s,
                            comment=f"Under investigation: FP probability {fp_score:.1f}",
                            extra={"fp_score": fp_score},
                        )
            else:
                # Band 3: low FP + conditions met → open case natively
                if incident.status not in ("closed", "false_positive", "resolved", "in_review"):
                    incident.status     = "in_review"
                    incident.updated_at = datetime.now(timezone.utc)
                    await db.flush()
                    await write_audit(
                        db, "incident", incident.id,
                        action="status_change",
                        actor="system",
                        from_status=prev_status,
                        to_status="in_review",
                        comment=f"Advanced to review: FP probability {fp_score:.1f} below threshold {fp_threshold:.1f}",
                        extra={"fp_score": fp_score},
                    )

                if (incident.case_opened_at is None
                        and incident.severity in ("high", "critical")
                        and incident.alert_count >= 3):
                    now_ts = datetime.now(timezone.utc)
                    incident.case_opened_at = now_ts
                    incident.case_type = _infer_case_type(
                        incident.categories or [], incident.mitre_tactics or []
                    )
                    if incident.first_seen:
                        incident.case_mttd_seconds = int(
                            (now_ts - incident.first_seen).total_seconds()
                        )
                    await db.flush()
                    from sqlalchemy import text as _text
                    await db.execute(
                        _text("""INSERT INTO case_comments
                                 (incident_id, author_email, body, is_system)
                                 VALUES (:iid, 'system', :body, TRUE)"""),
                        {"iid": incident.id,
                         "body": (
                             f"Case auto-opened by correlation engine. "
                             f"Severity: {incident.severity}. "
                             f"Tactics: {', '.join(incident.mitre_tactics or []) or 'none'}. "
                             f"Kill chain stage: {incident.kill_chain_stage_name or 'unknown'}."
                         )},
                    )
                    await write_audit(
                        db, "incident", incident.id,
                        action="case_auto_opened",
                        actor="system",
                        to_status="open",
                        extra={"case_type": incident.case_type},
                    )

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
                "case_opened":       incident.case_opened_at is not None,
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


def _get_fp_threshold() -> float:
    """Read fpThreshold from ai_settings.json or fall back to config."""
    try:
        from pathlib import Path
        import json as _j
        raw = Path("/opt/cycentra/ai_settings.json").read_text()
        stored = _j.loads(raw)
        val = stored.get("system", {}).get("fpThreshold")
        if val is not None:
            return float(val)
    except Exception:
        pass
    return getattr(settings, "fp_threshold", 90.0)


def _infer_case_type(categories: list, tactics: list) -> str:
    combined = " ".join(categories + tactics).lower()
    if "ransomware" in combined:   return "ransomware"
    if "phishing"   in combined:   return "phishing"
    if "brute"      in combined:   return "brute_force"
    if "exfil"      in combined:   return "data_exfil"
    if "lateral"    in combined:   return "lateral_movement"
    return "generic"


async def _reenrich_held_incident(incident_id: str) -> None:
    """Re-enrich a held incident after the configured hold window and re-advance status."""
    await asyncio.sleep(settings.hold_window_minutes * 60)
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

            misp_result = await enrich_incident(db, incident)
            await enrich_incident_ti(db, incident)

            rules = incident.correlated_rules or []
            avg_conf = (
                sum(float(r.get("confidence", 0.5)) for r in rules) / len(rules)
                if rules else 0.3
            )
            fp_score = compute_fp_score(
                avg_conf            = avg_conf,
                ueba_anomaly_count  = len(incident.ueba_flags or []),
                misp_ioc_hits       = len(misp_result.get("ioc_hits", [])),
                kill_chain_stage_name = incident.kill_chain_stage_name,
                asset_tier          = incident.asset_tier,
            )
            incident.fp_probability = fp_score

            # Temporarily reset to investigating so band logic can promote
            incident.status = "investigating"
            await db.flush()

            fp_threshold = _get_fp_threshold()
            if fp_score >= fp_threshold:
                incident.status               = "closed"
                incident.closed_at            = datetime.now(timezone.utc)
                incident.updated_at           = datetime.now(timezone.utc)
                incident.false_positive_reason = (
                    f"Auto-closed: FP probability {fp_score:.1f} ≥ threshold {fp_threshold:.1f}"
                )
            elif fp_score < 40.0:
                incident.status     = "in_review"
                incident.updated_at = datetime.now(timezone.utc)
                if (incident.case_opened_at is None
                        and incident.severity in ("high", "critical")
                        and incident.alert_count >= 3):
                    incident.case_opened_at = datetime.now(timezone.utc)
                    incident.case_type = _infer_case_type(
                        incident.categories or [], incident.mitre_tactics or []
                    )
                    if incident.first_seen:
                        incident.case_mttd_seconds = int(
                            (incident.case_opened_at - incident.first_seen).total_seconds()
                        )
            await db.flush()
            await db.commit()
            log.info("held_incident_reprocessed",
                     incident_id=incident_id, fp_score=fp_score,
                     new_status=incident.status)
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
