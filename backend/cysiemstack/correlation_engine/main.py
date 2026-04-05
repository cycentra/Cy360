"""
main.py — CySIEM Correlation Engine  (FastAPI)

Endpoints:
  GET   /health
  GET   /stats
  GET   /incidents
  GET   /incidents/{id}
  PATCH /incidents/{id}
  GET   /risk-scores
  GET   /ueba/users
  GET   /ueba/{username}
  GET   /alerts
  POST  /alerts/ingest
  WS    /ws/live
"""
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import structlog
import redis.asyncio as aioredis
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel

from config import get_settings
from models import get_db, init_db, Alert, Incident, UEBABaseline, UEBAAnomaly, RiskScore
from ingestor import run_ingestor
from risk_scorer import recalculate_all
from normaliser import normalise

log = structlog.get_logger()
settings = get_settings()

ingestor_task:      Optional[asyncio.Task] = None
risk_sched_task:    Optional[asyncio.Task] = None
_start_time = datetime.now(timezone.utc)
_alert_count = 0


async def _risk_scheduler():
    # Run every 600 s (was 300 s) — per-alert throttle in ingestor.py handles
    # fresh entities; this batch pass catches everything else with time decay.
    while True:
        await asyncio.sleep(600)
        try:
            from models import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                await recalculate_all(db)
        except Exception as e:
            log.error("risk_scheduler_error", error=str(e))


async def _ml_retrain_scheduler():
    from ueba_ml import retrain_all_models
    from models import AsyncSessionLocal
    await asyncio.sleep(600)
    while True:
        try:
            async with AsyncSessionLocal() as db:
                await retrain_all_models(db)
        except Exception as e:
            log.error("ml_retrain_error", error=str(e))
        await asyncio.sleep(7 * 24 * 3600)

# ENH-1: campaign correlation scheduler
async def _campaign_scheduler():
    from campaign_correlator import run_campaign_correlation
    from models import AsyncSessionLocal
    await asyncio.sleep(30)
    while True:
        try:
            async with AsyncSessionLocal() as db:
                linked = await run_campaign_correlation(db)
                await db.commit()
                if linked:
                    await manager.broadcast(json.dumps({
                        'type': 'campaign_detected',
                        'linked_count': linked,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    }))
        except Exception as e:
            log.error('campaign_scheduler_error', error=str(e))
        await asyncio.sleep(300)



@asynccontextmanager
async def lifespan(app: FastAPI):
    global ingestor_task, risk_sched_task
    await init_db()
    log.info("database_ready")
    ingestor_task   = asyncio.create_task(run_ingestor())
    log.info("ingestor_started")
    risk_sched_task = asyncio.create_task(_risk_scheduler())
    log.info("risk_scheduler_started")
    asyncio.create_task(_ml_retrain_scheduler())
    asyncio.create_task(redis_listener())
    log.info("ws_listener_started")
    asyncio.create_task(_campaign_scheduler())   # ENH-1
    log.info("campaign_scheduler_started")
    yield
    if ingestor_task:
        ingestor_task.cancel()
        try:
            await ingestor_task
        except asyncio.CancelledError:
            pass
    if risk_sched_task:
        risk_sched_task.cancel()


app = FastAPI(
    title="CySIEM Correlation Engine",
    description="Incident grouping, UEBA, and risk scoring for Wazuh — integrated with CyCentra 360",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5252", "http://localhost:5252"],  # Flask proxy only
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket manager ──────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active = [c for c in self.active if c != ws]

    async def broadcast(self, message: str):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def redis_listener():
    redis  = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe("cysiemstack:live")
    async for message in pubsub.listen():
        if message["type"] == "message":
            await manager.broadcast(message["data"])
    await redis.aclose()


# ── Serialisers ────────────────────────────────────────────────────────────────

def _incident_to_dict(i: Incident) -> dict:
    return {
        "id":                i.id,
        "first_seen":        i.first_seen.isoformat() if i.first_seen else None,
        "last_seen":         i.last_seen.isoformat()  if i.last_seen  else None,
        "status":            i.status,
        "severity":          i.severity,
        "alert_count":       i.alert_count,
        "affected_agents":   i.affected_agents or [],
        "affected_users":    i.affected_users  or [],
        "src_ips":           [str(ip) for ip in (i.src_ips or [])],
        "categories":        i.categories   or [],
        "mitre_ids":         i.mitre_ids    or [],
        "mitre_tactics":     i.mitre_tactics or [],
        "correlated_rules":  i.correlated_rules or [],
        "ueba_flags":        i.ueba_flags   or [],
        "misp_enrichment":   i.misp_enrichment or {},
        "llm_summary":       i.llm_summary,
        "llm_remediation":   i.llm_remediation,
        "risk_score":        float(i.risk_score or 0),
        "assigned_to":       i.assigned_to,
        "kill_chain_stage":      i.kill_chain_stage or 0,
        "kill_chain_stage_name": i.kill_chain_stage_name,
        "notes":             i.notes,
    }


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id":           a.id,
        "timestamp":    a.timestamp.isoformat() if a.timestamp else None,
        "agent_id":     a.agent_id,
        "agent_name":   a.agent_name,
        "rule_id":      a.rule_id,
        "rule_desc":    a.rule_desc,
        "rule_level":   a.rule_level,
        "base_score":   float(a.base_score or 0),
        "category":     a.category,
        "mitre_id":     a.mitre_id,
        "src_ip":       str(a.src_ip) if a.src_ip else None,
        "username":     a.username,
        "file_path":    a.file_path,
        "misp_ioc_match": a.misp_ioc_match,
        "incident_id":  a.incident_id,
    }


def _risk_to_dict(r: RiskScore) -> dict:
    return {
        "entity_id":      r.entity_id,
        "entity_name":    r.entity_name,
        "entity_type":    r.entity_type,
        "score":          float(r.score or 0),
        "level":          r.level,
        "breakdown":      r.score_breakdown or {},
        "trend":          r.trend,
        "last_calculated": r.last_calculated.isoformat() if r.last_calculated else None,
    }


# ── User classification ────────────────────────────────────────────────────────
_SYSTEM_ACCOUNTS = frozenset({
    # Standard POSIX/Linux system users
    "root", "bin", "daemon", "adm", "lp", "sync", "shutdown", "halt", "mail",
    "operator", "games", "ftp", "nobody", "systemd-network", "systemd-resolve",
    "systemd-timesync", "systemd-journal", "systemd-bus-proxy", "syslog",
    "messagebus", "uuidd", "dnsmasq", "usbmux", "rtkit", "cups-pk-helper",
    "speech-dispatcher", "avahi", "kernoops", "saned", "pulse", "colord",
    "hplip", "geoclue", "gnome-initial-setup", "gdm", "whoopsie", "lightdm",
    "backup", "list", "irc", "gnats", "man", "news", "proxy", "www-data",
    "at", "uucp", "libuuid", "sshd", "oprofile", "tcpdump", "suse-ncc",
    "beagleindex", "mockbuild", "statd", "rpc", "rpcuser", "nfsnobody",
    "postfix", "dovecot", "dovenull", "smmta", "smmsp",
})

_SERVICE_ACCOUNTS = frozenset({
    # Web servers
    "apache", "nginx", "www", "http", "lighttpd", "caddy", "traefik",
    # Databases
    "postgres", "postgresql", "mysql", "mariadb", "mongo", "mongodb",
    "redis", "cassandra", "couchdb", "db2inst2",
    # DevOps / CI
    "jenkins", "gitlab", "gitlab-runner", "gitlab-psql", "gitlab-prometheus",
    "gitlab_ci", "gitlab_ci_runner", "docker", "dockeradmin", "runner",
    # App servers
    "tomcat", "jboss", "wildfly", "weblogic", "glassfish", "artemis",
    "activemq", "openmeetings", "ejbca", "liferay", "solr", "sphinxsearch",
    "confluence", "jira", "youtrack", "nagios", "grafana", "influxdb",
    "kibana", "elasticsearch", "logstash", "filebeat", "prometheus",
    # FTP
    "ftp", "ftpuser", "ftpuser2", "ftpadmin", "ftptest", "ftpznz",
    "ftpayu", "ftpweb", "ftpup", "ftpkakou", "FTPapache", "FTPguest",
    "uftp", "sftpPS",
    # System services
    "qmails", "qmailr", "qmailq", "qmailp", "qmaill", "qmaild",
    "mailman", "cyrus", "postmaster", "squid", "net", "snort", "ossec",
    # Crypto / blockchain (service bots)
    "ethereum", "eth", "btc", "bitcoin", "monero", "solana", "sol",
    "polkadot", "filecoin", "lotus", "dogecoin", "blockchain", "miner",
    "xmrig", "pool", "gwei", "web3", "uniswap", "raydium", "eigenlayer",
    "eigen", "euler", "solnode", "soltech", "soldev", "solscript", "solv",
    "validator", "node", "staking", "delegate",
    # Monitoring / automation
    "ansible", "puppet", "chef", "terraform", "packer", "vagrant",
    "zabbix", "cacti", "ntopng", "rundeck", "oxidized", "tiler",
    "consul", "vault", "nomad", "kong", "blackfire",
    # Dev tools
    "composer", "git", "svn", "cvs", "cvsuser",
    # Game servers
    "csgo", "csgoserver", "gmod", "gmodserver", "l4d2", "minecraft",
    "mcserver1", "teraria", "terrariaserver", "terraria", "samp",
    "arkserver", "ark",
    # Web/app frameworks
    "laravel", "django", "rails", "wordpress", "drupal", "joomla",
    "magento", "odoo8", "apinizer",
    # Misc service patterns
    "plex", "emby", "jellyfin", "teamspeak", "discordbot", "musicbot",
    "telegram", "telegramapi", "bot", "Bot", "nsbot", "scanner",
    "downloader", "tradebot", "trade-bot", "trade.bot", "evmbot",
    "traffic_monitor", "audit", "squid", "bungeecord", "pi",
    "nginx", "redis", "grafana", "influx", "netdata",
})

_SERVICE_PREFIXES = (
    "svc_", "svc-", "srv_", "srv-", "bot_", "bot-",
    "ftp", "sftp", "nfs", "rpc", "db_", "db-",
)

_SERVICE_SUFFIXES = (
    "_svc", "-svc", "_daemon", "_service", "_bot", "_worker",
    "_agent", "_runner", "_server",
)


def _classify_user(username: str) -> tuple[str, str]:
    """
    Returns (category, description) where category is one of:
      'system'  — OS-level system/daemon account
      'service' — Application or infrastructure service account
      'human'   — Likely a real interactive user
    """
    lname = username.lower()

    if lname in _SYSTEM_ACCOUNTS:
        return ("system", "Linux/POSIX system account — not an interactive user")

    if lname in _SERVICE_ACCOUNTS:
        return ("service", "Application or infrastructure service account")

    for pfx in _SERVICE_PREFIXES:
        if lname.startswith(pfx):
            return ("service", "Application or infrastructure service account")

    for sfx in _SERVICE_SUFFIXES:
        if lname.endswith(sfx):
            return ("service", "Application or infrastructure service account")

    # Names that look like pure system patterns (e.g. "1", "2", "4leo")
    if lname.isdigit():
        return ("system", "Numeric placeholder system account")

    return ("human", "Interactive user account")


def _baseline_to_dict(b: UEBABaseline) -> dict:
    category, description = _classify_user(b.username)
    return {
        "username":         b.username,
        "category":         category,
        "description":      description,
        "typical_hours":    b.typical_hours or [],
        "typical_agents":   b.typical_agents or [],
        "avg_daily_events": float(b.avg_daily_events or 0),
        "avg_fail_rate":    float(b.avg_fail_rate or 0),
        "updated_at":       b.updated_at.isoformat() if b.updated_at else None,
        # anomaly counts injected separately by list_ueba_users
        "active_anomalies": 0,
        "total_anomalies":  0,
    }


def _anomaly_to_dict(a: UEBAAnomaly, alert_ctx: dict = None) -> dict:
    """Serialise anomaly; optionally enrich with the triggering alert's context."""
    ctx = alert_ctx or {}
    return {
        "id":               a.id,
        "detected_at":      a.detected_at.isoformat() if a.detected_at else None,
        "username":         a.username,
        "anomaly_type":     a.anomaly_type,
        "description":      a.description,
        "risk_contribution": a.risk_contribution,
        "alert_ids":        a.alert_ids or [],
        "incident_id":      a.incident_id,
        "resolved":         a.resolved,
        # ── Triggering alert context (enriched at query time) ──────────────────
        "agent_name":       ctx.get("agent_name"),
        "agent_ip":         ctx.get("agent_ip"),
        "src_ip":           ctx.get("src_ip"),
        "rule_id":          ctx.get("rule_id"),
        "rule_desc":        ctx.get("rule_desc"),
        "rule_level":       ctx.get("rule_level"),
        "process_name":     ctx.get("process_name"),
        "file_path":        ctx.get("file_path"),
        "raw_log":          ctx.get("raw_log"),
        "mitre_id":         ctx.get("mitre_id"),
        "category":         ctx.get("category"),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/stats")
async def stats(db: AsyncSession = Depends(get_db)):
    total_alerts    = (await db.execute(select(func.count()).select_from(Alert))).scalar()
    total_incidents = (await db.execute(select(func.count()).select_from(Incident))).scalar()
    open_incidents  = (await db.execute(
        select(func.count()).select_from(Incident).where(Incident.status == "open")
    )).scalar()
    uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()
    return {
        "total_alerts":     total_alerts,
        "total_incidents":  total_incidents,
        "open_incidents":   open_incidents,
        "ws_clients":       len(manager.active),
        "uptime_seconds":   int(uptime),
    }


@app.get("/incidents")
async def list_incidents(
    status:   Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident).order_by(desc(Incident.last_seen))
    if status:
        q = q.where(Incident.status == status)
    if severity:
        q = q.where(Incident.severity == severity)

    total = (await db.execute(
        select(func.count()).select_from(Incident)
        .where(*([Incident.status == status] if status else []))
    )).scalar()

    q = q.offset(offset).limit(limit)
    incidents = (await db.execute(q)).scalars().all()
    return {"total": total, "incidents": [_incident_to_dict(i) for i in incidents]}


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = (await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
        .order_by(desc(Alert.timestamp)).limit(50)
    )).scalars().all()

    result = _incident_to_dict(inc)
    result["alerts"] = [_alert_to_dict(a) for a in alerts]
    return result


class IncidentPatch(BaseModel):
    status:                Optional[str] = None
    assigned_to:           Optional[str] = None
    notes:                 Optional[str] = None
    false_positive_reason: Optional[str] = None


@app.patch("/incidents/{incident_id}")
async def patch_incident(
    incident_id: str,
    body: IncidentPatch,
    db: AsyncSession = Depends(get_db),
):
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if body.status is not None:
        inc.status = body.status
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
    if body.notes is not None:
        inc.notes = body.notes
    if body.false_positive_reason is not None:
        inc.false_positive_reason = body.false_positive_reason

    inc.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return _incident_to_dict(inc)


@app.get("/risk-scores")
async def get_risk_scores(
    entity_type: Optional[str] = None,
    min_score: float = 0,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = select(RiskScore).where(RiskScore.score >= min_score).order_by(desc(RiskScore.score))
    if entity_type:
        q = q.where(RiskScore.entity_type == entity_type)
    q = q.limit(limit)
    scores = (await db.execute(q)).scalars().all()
    return [_risk_to_dict(r) for r in scores]


@app.get("/ueba/users")
async def list_ueba_users(
    category:         Optional[str] = None,   # system | service | human
    has_anomaly:      Optional[bool] = None,  # true = only users with active anomalies
    top_activity:     Optional[int] = None,   # top N by avg_daily_events
    db: AsyncSession = Depends(get_db),
):
    q = select(UEBABaseline).order_by(UEBABaseline.updated_at.desc())
    baselines = (await db.execute(q)).scalars().all()

    # Build anomaly-count lookup in one query
    anomaly_rows = (await db.execute(
        select(
            UEBAAnomaly.username,
            func.count().label("total"),
            func.sum(
                func.cast(~UEBAAnomaly.resolved, type_=func.count().type)
            ).label("active"),
        )
        .group_by(UEBAAnomaly.username)
    )).all()
    # Re-query simpler: two separate aggregates
    total_map: dict = {}
    active_map: dict = {}
    all_anomaly_rows = (await db.execute(
        select(UEBAAnomaly.username, UEBAAnomaly.resolved)
    )).all()
    for row in all_anomaly_rows:
        total_map[row.username] = total_map.get(row.username, 0) + 1
        if not row.resolved:
            active_map[row.username] = active_map.get(row.username, 0) + 1

    result = []
    for b in baselines:
        d = _baseline_to_dict(b)
        d["total_anomalies"]  = total_map.get(b.username, 0)
        d["active_anomalies"] = active_map.get(b.username, 0)

        # Filter by category
        if category and d["category"] != category:
            continue
        # Filter to users with active anomalies only
        if has_anomaly is True and d["active_anomalies"] == 0:
            continue

        result.append(d)

    # Sort by activity (avg_daily_events) for top_activity view, else keep updated_at order
    if top_activity:
        result.sort(key=lambda x: x["avg_daily_events"], reverse=True)
        result = result[:top_activity]

    return result


@app.get("/ueba/{username}")
async def get_ueba_user(username: str, db: AsyncSession = Depends(get_db)):
    baseline = (await db.execute(
        select(UEBABaseline).where(UEBABaseline.username == username)
    )).scalar_one_or_none()

    anomalies = (await db.execute(
        select(UEBAAnomaly)
        .where(UEBAAnomaly.username == username)
        .order_by(desc(UEBAAnomaly.detected_at))
        .limit(100)
    )).scalars().all()

    # Batch-fetch the triggering alert for each anomaly (first wazuh_id per anomaly)
    wazuh_ids = [
        ids[0] for a in anomalies
        if (ids := (a.alert_ids or [])) and ids[0]
    ]
    alert_by_wazuh: dict[str, Alert] = {}
    if wazuh_ids:
        rows = (await db.execute(
            select(Alert).where(Alert.wazuh_id.in_(wazuh_ids))
        )).scalars().all()
        alert_by_wazuh = {r.wazuh_id: r for r in rows}

    def _enrich(a: UEBAAnomaly) -> dict:
        ids = a.alert_ids or []
        alert = alert_by_wazuh.get(ids[0]) if ids else None
        ctx = {
            "agent_name":   alert.agent_name  if alert else None,
            "agent_ip":     alert.agent_ip    if alert else None,
            "src_ip":       alert.src_ip      if alert else None,
            "rule_id":      alert.rule_id     if alert else None,
            "rule_desc":    alert.rule_desc   if alert else None,
            "rule_level":   alert.rule_level  if alert else None,
            "process_name": alert.process_name if alert else None,
            "file_path":    alert.file_path   if alert else None,
            "raw_log":      alert.raw_log     if alert else None,
            "mitre_id":     alert.mitre_id    if alert else None,
            "category":     alert.category    if alert else None,
        } if alert else {}
        return _anomaly_to_dict(a, ctx)

    return {
        "username":  username,
        "baseline":  _baseline_to_dict(baseline) if baseline else None,
        "anomalies": [_enrich(a) for a in anomalies],
    }


@app.get("/alerts")
async def list_alerts(
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    alerts = (await db.execute(
        select(Alert).order_by(desc(Alert.timestamp)).offset(offset).limit(limit)
    )).scalars().all()
    return [_alert_to_dict(a) for a in alerts]


@app.post("/alerts/ingest")
async def ingest_alert(alert: dict):
    """
    Manual alert push for testing / external ingestion.
    Pushes to the Redis ingest queue; the ingestor picks it up within 2 seconds.
    """
    redis_conn = aioredis.from_url(settings.redis_url, decode_responses=False)
    await redis_conn.rpush(settings.redis_alert_key, json.dumps(alert).encode())
    await redis_conn.aclose()
    return {"status": "queued", "key": settings.redis_alert_key}



# ── ENH-6: Analyst feedback endpoints ────────────────────────────────────────
from feedback_store import submit_feedback, get_rule_accuracy
from models import CorrelationFeedback


class FeedbackBody(BaseModel):
    incident_id:   str
    verdict:       str
    rules_fired:   list = []
    analyst_email: str  = None
    notes:         str  = None


@app.post("/feedback")
async def post_feedback(body: FeedbackBody, db: AsyncSession = Depends(get_db)):
    """Store analyst verdict for an incident."""
    fb = await submit_feedback(
        db,
        incident_id   = body.incident_id,
        verdict       = body.verdict,
        rules_fired   = body.rules_fired,
        analyst_email = body.analyst_email,
        notes         = body.notes,
    )
    await db.commit()
    return {"status": "recorded", "id": fb.id}


@app.get("/feedback/accuracy")
async def rule_accuracy(db: AsyncSession = Depends(get_db)):
    """Per-rule TP/FP/accuracy stats for the last 90 days."""
    return await get_rule_accuracy(db)


@app.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(ws)
