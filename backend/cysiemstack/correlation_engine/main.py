"""
main.py — CySIEM Correlation Engine  (FastAPI)

Endpoints:
  GET   /health
  GET   /stats
  GET   /incidents
  GET   /incidents/{id}
  PATCH /incidents/{id}
  DELETE /incidents
  GET   /risk-scores
  GET   /ueba/users
  GET   /ueba/{username}
  GET   /alerts
  POST  /alerts/ingest
  WS    /ws/live

  MCP   /mcp/sse   — Security MCP bridge (SSE transport, MCP_ENABLED=true to activate)
"""
import asyncio
import base64
import json as _stdlib_json
from contextlib import asynccontextmanager
try:
    import orjson as _json
    _DUMPS = lambda obj: _json.dumps(obj, option=_json.OPT_NON_STR_KEYS).decode()
except ImportError:
    import json as _json
    _DUMPS = lambda obj: _json.dumps(obj, default=str)
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog
import redis.asyncio as aioredis
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, delete
from pydantic import BaseModel

from config import get_settings
from models import get_db, init_db, Alert, Incident, UEBABaseline, UEBAAnomaly, RiskScore, AuditLog
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
                    await manager.broadcast(_DUMPS({
                        'type': 'campaign_detected',
                        'linked_count': linked,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    }))
        except Exception as e:
            log.error('campaign_scheduler_error', error=str(e))
        await asyncio.sleep(300)


# ── FP auto-close scheduler ──────────────────────────────────────────────────
# Every 6 hours, advance false_positive incidents that have sat in that status
# for more than FP_AUTO_CLOSE_DAYS to "closed".  This bridges the lifecycle gap:
#   auto-FP (day 0)  →  auto-closed (day 7)  →  auto-archived (day 30)
# Analysts can still reopen from "closed" → "investigating" if needed.
FP_AUTO_CLOSE_DAYS = 7

async def _fp_auto_close_scheduler():
    from models import AsyncSessionLocal
    from iris_connector import write_audit
    await asyncio.sleep(120)  # let engine fully boot before first check
    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=FP_AUTO_CLOSE_DAYS)
            async with AsyncSessionLocal() as db:
                stale = list((await db.execute(
                    select(Incident)
                    .where(Incident.status == "false_positive")
                    .where(Incident.updated_at < cutoff)
                )).scalars().all())
                closed_count = 0
                now_ts = datetime.now(timezone.utc)
                for inc in stale:
                    inc.status     = "closed"
                    inc.closed_at  = now_ts
                    inc.updated_at = now_ts
                    await db.flush()
                    try:
                        await write_audit(
                            db, "incident", inc.id,
                            action="status_change",
                            actor="system",
                            from_status="false_positive",
                            to_status="closed",
                            comment=f"Auto-closed: classified as false_positive for {FP_AUTO_CLOSE_DAYS}+ days without analyst review",
                        )
                    except Exception:
                        pass  # audit failure must not block the batch
                    closed_count += 1
                if closed_count:
                    await db.commit()
                    log.info("fp_auto_close_complete", closed=closed_count,
                             cutoff_days=FP_AUTO_CLOSE_DAYS)
        except Exception as e:
            log.error("fp_auto_close_error", error=str(e))
        await asyncio.sleep(6 * 3600)


# ── Auto-archive scheduler ────────────────────────────────────────────────────
# Every 6 hours, hard-delete CLOSED incidents that haven't been updated in more
# than ARCHIVE_AFTER_DAYS days, plus any stale "resolved" incidents that never
# went through the close step.  "false_positive" no longer lands here directly —
# the FP auto-close scheduler above advances them to "closed" first.
ARCHIVE_AFTER_DAYS = 30

async def _auto_archive_scheduler():
    from datetime import timedelta
    from models import AsyncSessionLocal
    await asyncio.sleep(60)  # let the engine fully boot before first check
    while True:
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=ARCHIVE_AFTER_DAYS)
            async with AsyncSessionLocal() as db:
                stale_ids = list((await db.execute(
                    select(Incident.id)
                    .where(Incident.status.in_(["closed", "resolved"]))
                    .where(Incident.updated_at < cutoff)
                )).scalars().all())
                if stale_ids:
                    await db.execute(delete(Alert).where(Alert.incident_id.in_(stale_ids)))
                    await db.execute(delete(Incident).where(Incident.id.in_(stale_ids)))
                    await db.commit()
                    log.info("auto_archive_complete", deleted=len(stale_ids),
                             cutoff_days=ARCHIVE_AFTER_DAYS)
        except Exception as e:
            log.error("auto_archive_error", error=str(e))
        await asyncio.sleep(6 * 3600)

# CyIRIS sync scheduler: poll open-linked incidents every 5 minutes
async def _iris_sync_scheduler():
    from iris_connector import sync_closed_cases
    from models import AsyncSessionLocal
    await asyncio.sleep(60)   # initial delay — let ingestor settle
    while True:
        try:
            async with AsyncSessionLocal() as db:
                closed = await sync_closed_cases(db)
                await db.commit()
                if closed:
                    await manager.broadcast(_DUMPS({
                        'type':      'iris_cases_synced',
                        'closed':    closed,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    }))
        except Exception as e:
            log.error('iris_sync_scheduler_error', error=str(e))
        await asyncio.sleep(300)  # every 5 minutes


# ── Nightly feedback-adjustment scheduler ─────────────────────────────────────
# Runs once per day.  Consumes analyst verdicts to tune rule confidence scores.
async def _feedback_adjustment_scheduler():
    from feedback_store import apply_feedback_adjustments
    from models import AsyncSessionLocal
    await asyncio.sleep(3600)   # first run: 1 h after startup
    while True:
        try:
            async with AsyncSessionLocal() as db:
                await apply_feedback_adjustments(db)
        except Exception as e:
            log.error('feedback_adjustment_error', error=str(e))
        await asyncio.sleep(24 * 3600)   # every 24 hours


# ── Weekly auto-close audit scheduler ────────────────────────────────────────
async def _weekly_audit_scheduler():
    from audit_reporter import generate_auto_close_audit
    from models import AsyncSessionLocal
    await asyncio.sleep(7200)   # first run: 2 h after startup
    while True:
        try:
            async with AsyncSessionLocal() as db:
                report = await generate_auto_close_audit(db, period_days=7)
                await db.commit()
                log.info('weekly_audit_complete',
                         total_auto_closed=report.get('total_auto_closed', 0))
        except Exception as e:
            log.error('weekly_audit_error', error=str(e))
        await asyncio.sleep(7 * 24 * 3600)   # every 7 days


# ── Host posture refresh scheduler ───────────────────────────────────────────
async def _host_refresh_scheduler():
    """Populate / refresh host_posture_cache every hour from Wazuh + alert DB.

    First run at 30 s after startup so the ingestor has time to settle.
    The cache is what the Flask host-intelligence routes read from — without
    this task running, the Host & Posture tab stays empty even when Wazuh
    reports active agents.
    """
    import sys, os as _os
    # host_service lives one directory above (cysiemstack/), not in engine/
    _svc_path = _os.path.join(_os.path.dirname(__file__), "..")
    if _svc_path not in sys.path:
        sys.path.insert(0, _svc_path)
    from host_service import refresh_all_hosts
    from models import AsyncSessionLocal
    await asyncio.sleep(30)   # wait for ingestor / DB to be ready
    while True:
        try:
            async with AsyncSessionLocal() as db:
                refreshed = await refresh_all_hosts(db)
                await db.commit()
                log.info("host_posture_refresh_done", host_count=refreshed)
        except Exception as e:
            log.error("host_refresh_scheduler_error", error=str(e))
        await asyncio.sleep(3600)  # hourly



@asynccontextmanager
async def lifespan(app: FastAPI):
    global ingestor_task, risk_sched_task
    await init_db()
    log.info("database_ready")

    # ── Startup migrations (idempotent — safe to re-run on every restart) ────
    try:
        from models import AsyncSessionLocal as _ASL
        from sqlalchemy import text as _text
        async with _ASL() as _db:

            # Migration 1: upgrade legacy 'cloud' → 'o365' in incidents.categories
            # Incidents ingested before the _CLOUD_SOURCE_MAP normaliser fix have
            # categories=['cloud']. Identify by querying linked alert rule groups.
            await _db.execute(_text("""
                UPDATE incidents i
                SET categories = array_replace(categories, 'cloud', 'o365')
                WHERE 'cloud' = ANY(categories)
                  AND EXISTS (
                      SELECT 1 FROM alerts a
                      WHERE a.incident_id = i.id
                        AND (
                            a.full_alert->'rule'->'groups' ? 'office365'
                            OR a.full_alert->'data'->>'integration' = 'office365'
                        )
                  )
            """))
            log.info("migration_1_incidents_cloud_to_o365_complete")

            # Migration 2: upgrade alerts.category from 'cloud' → 'o365' for O365 alerts
            # Alerts ingested before the normaliser fix have category='cloud' even when
            # the rule groups include 'office365'. This blocks risk_scorer.recalculate_all()
            # from finding cloud entities (it queries Alert.category='o365').
            await _db.execute(_text("""
                UPDATE alerts
                SET category = 'o365'
                WHERE category = 'cloud'
                  AND (
                      full_alert->'rule'->'groups' ? 'office365'
                      OR full_alert->'data'->>'integration' = 'office365'
                  )
            """))
            log.info("migration_2_alerts_cloud_to_o365_complete")

            # Migration 3: backfill alerts.username from O365 MailboxOwnerUPN
            # Alerts ingested before the _extract_username O365 fix have username=NULL.
            # Backfill from data.office365.MailboxOwnerUPN (email address, not GUID).
            await _db.execute(_text("""
                UPDATE alerts
                SET username = full_alert->'data'->'office365'->>'MailboxOwnerUPN'
                WHERE username IS NULL
                  AND full_alert->'data'->'office365'->>'MailboxOwnerUPN' LIKE '%@%'
            """))
            # Also try UserId if MailboxOwnerUPN not present (some O365 events)
            await _db.execute(_text("""
                UPDATE alerts
                SET username = full_alert->'data'->'office365'->>'UserId'
                WHERE username IS NULL
                  AND full_alert->'data'->'office365'->>'UserId' LIKE '%@%'
            """))
            log.info("migration_3_alerts_username_backfill_complete")

            # Migration 4: close stale false_positive incidents where fp >= threshold
            # Incidents created before the advance_incident_status fix were set to
            # 'false_positive' by the old code. The scheduler promotes them only after
            # 7 days. Immediately close any whose fp_probability >= fpThreshold.
            try:
                import json as _json
                from pathlib import Path as _Path
                _ai = _Path("/opt/cycentra/ai_settings.json")
                _raw = _ai.read_text() if _ai.exists() else "{}"
                _fp_thresh = float(_json.loads(_raw).get("iris", {}).get("fpThreshold", 90.0))
            except Exception:
                _fp_thresh = 90.0
            await _db.execute(_text(f"""
                UPDATE incidents
                SET status    = 'closed',
                    closed_at = NOW(),
                    updated_at = NOW(),
                    false_positive_reason = COALESCE(
                        false_positive_reason,
                        'Auto-closed by startup migration: FP probability >= threshold {_fp_thresh:.1f}'
                    )
                WHERE status = 'false_positive'
                  AND fp_probability >= {_fp_thresh}
            """))
            log.info("migration_4_fp_incidents_closed_complete", threshold=_fp_thresh)

            # Migration 5: backfill affected_agent_names for all incidents that
            # predate the host-column feature (v1.0.xxx).
            await _db.execute(_text("""
                UPDATE incidents i
                SET affected_agent_names = sub.names
                FROM (
                    SELECT incident_id,
                           array_agg(DISTINCT agent_name)
                               FILTER (WHERE agent_name IS NOT NULL AND agent_name <> '') AS names
                    FROM alerts
                    WHERE incident_id IS NOT NULL
                    GROUP BY incident_id
                ) sub
                WHERE i.id = sub.incident_id
                  AND (i.affected_agent_names IS NULL OR i.affected_agent_names = '{}')
                  AND sub.names IS NOT NULL
            """))
            log.info("migration_5_host_name_backfill_complete")

            await _db.commit()
            log.info("all_startup_migrations_complete")
    except Exception as _e:
        log.warning("startup_migration_skipped", error=str(_e))
    # ─────────────────────────────────────────────────────────────────────────
    ingestor_task   = asyncio.create_task(run_ingestor())
    log.info("ingestor_started")
    risk_sched_task = asyncio.create_task(_risk_scheduler())
    log.info("risk_scheduler_started")
    asyncio.create_task(_ml_retrain_scheduler())
    asyncio.create_task(redis_listener())
    log.info("ws_listener_started")
    asyncio.create_task(_campaign_scheduler())   # ENH-1
    log.info("campaign_scheduler_started")
    asyncio.create_task(_iris_sync_scheduler())
    log.info("iris_sync_scheduler_started")
    asyncio.create_task(_fp_auto_close_scheduler())
    log.info("fp_auto_close_scheduler_started")
    asyncio.create_task(_auto_archive_scheduler())
    log.info("auto_archive_scheduler_started")
    asyncio.create_task(_feedback_adjustment_scheduler())
    log.info("feedback_adjustment_scheduler_started")
    asyncio.create_task(_weekly_audit_scheduler())
    log.info("weekly_audit_scheduler_started")
    asyncio.create_task(_host_refresh_scheduler())
    log.info("host_refresh_scheduler_started")
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
        "affected_agents":       i.affected_agents      or [],
        "affected_agent_names":  i.affected_agent_names or [],
        "affected_users":        i.affected_users       or [],
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
        "iris_case_id":      i.iris_case_id,
        "iris_case_status":  i.iris_case_status,
        "iris_case_url":     i.iris_case_url,
        "fp_probability":    float(i.fp_probability) if i.fp_probability is not None else None,
        "asset_tier":        i.asset_tier,
        "soar_actions":      i.soar_actions or [],
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
    uptime = (datetime.now(timezone.utc) - _start_time).total_seconds()

    # Per-status counts for the dashboard widget
    _STATUS_NAMES = ("open", "investigating", "in_review", "held",
                     "resolved", "false_positive", "closed")
    status_counts: dict[str, int] = {}
    for stat in _STATUS_NAMES:
        cnt = (await db.execute(
            select(func.count()).select_from(Incident).where(Incident.status == stat)
        )).scalar()
        status_counts[stat] = cnt or 0

    open_incidents = status_counts.get("open", 0) + status_counts.get("investigating", 0)
    return {
        "total_alerts":     total_alerts,
        "total_incidents":  total_incidents,
        "open_incidents":   open_incidents,
        "status_counts":    status_counts,
        "ws_clients":       len(manager.active),
        "uptime_seconds":   int(uptime),
    }


@app.get("/incidents")
async def list_incidents(
    status:   Optional[str] = None,
    severity: Optional[str] = None,
    user:     Optional[str] = None,
    agent:    Optional[str] = None,
    src_ip:   Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    filters = []
    if status:   filters.append(Incident.status   == status)
    if severity: filters.append(Incident.severity == severity)
    if user:     filters.append(func.array_to_string(Incident.affected_users,  ',').ilike(f'%{user}%'))
    if agent:    filters.append(func.array_to_string(Incident.affected_agents, ',').ilike(f'%{agent}%'))
    if src_ip:   filters.append(func.array_to_string(Incident.src_ips,         ',').ilike(f'%{src_ip}%'))

    q = select(Incident).order_by(desc(Incident.last_seen))
    if filters:
        q = q.where(*filters)

    total = (await db.execute(
        select(func.count()).select_from(Incident).where(*filters)
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


@app.post("/incidents/{incident_id}/escalate")
async def escalate_incident_to_iris(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Manually escalate an incident to DFIR IRIS (CyIRIS).

    Bypasses the automatic FP-threshold logic so an analyst can raise a ticket
    for any incident regardless of confidence score.  If the incident already
    has a CyIRIS case this returns the existing ticket info rather than creating
    a duplicate.
    """
    from iris_connector import create_iris_case, _load_iris_config
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Already has a ticket — return existing info
    if inc.iris_case_id:
        return {
            "iris_case_id":     inc.iris_case_id,
            "iris_case_url":    inc.iris_case_url,
            "iris_case_status": inc.iris_case_status,
            "already_existed":  True,
        }

    if not _load_iris_config():
        raise HTTPException(
            status_code=422,
            detail="CyIRIS is not configured. Enable it in System Settings → Integrations → CyIRIS."
        )

    result = await create_iris_case(db, inc)
    if not result:
        raise HTTPException(status_code=422, detail="IRIS case creation failed — check CyIRIS connectivity and API key.")

    return {**result, "already_existed": False}


class IncidentPatch(BaseModel):
    status:                Optional[str] = None
    assigned_to:           Optional[str] = None
    notes:                 Optional[str] = None
    false_positive_reason: Optional[str] = None
    iris_case_id:          Optional[str] = None
    iris_case_url:         Optional[str] = None
    iris_case_status:      Optional[str] = None


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
    if body.iris_case_id is not None:
        inc.iris_case_id = body.iris_case_id
    if body.iris_case_url is not None:
        inc.iris_case_url = body.iris_case_url
    if body.iris_case_status is not None:
        inc.iris_case_status = body.iris_case_status

    inc.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return _incident_to_dict(inc)


# ── Audit log ─────────────────────────────────────────────────────────────────

def _audit_to_dict(a: AuditLog) -> dict:
    return {
        "id":          a.id,
        "entity_type": a.entity_type,
        "entity_id":   a.entity_id,
        "action":      a.action,
        "from_status": a.from_status,
        "to_status":   a.to_status,
        "comment":     a.comment,
        "actor":       a.actor,
        "created_at":  a.created_at.isoformat() if a.created_at else None,
        "extra":       a.extra or {},
    }


@app.get("/incidents/{incident_id}/audit")
async def get_incident_audit(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Return the full chronological audit trail for an incident."""
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    entries = (await db.execute(
        select(AuditLog)
        .where(AuditLog.entity_type == "incident", AuditLog.entity_id == incident_id)
        .order_by(AuditLog.created_at.asc())
    )).scalars().all()
    return [_audit_to_dict(e) for e in entries]


# ── Status transition (analyst-initiated, with mandatory audit comment) ───────

# Valid analyst-driven transitions
_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "open":          {"investigating", "in_review", "resolved", "false_positive", "closed"},
    "investigating": {"in_review", "resolved", "false_positive", "closed"},
    "in_review":     {"resolved", "false_positive", "closed", "investigating"},
    "held":          {"investigating", "in_review", "resolved", "false_positive", "closed"},
    "resolved":      {"investigating", "in_review", "closed"},
    "false_positive":{"investigating", "closed"},
    "closed":        {"investigating"},
}


class StatusTransition(BaseModel):
    to_status: str
    comment:   str
    actor:     Optional[str] = "analyst"


class BatchCloseReq(BaseModel):
    comment: str = "Archived via analyst action"
    actor:   Optional[str] = "analyst"


@app.post("/incidents/batch-close")
async def batch_close_incidents(req: BatchCloseReq, db: AsyncSession = Depends(get_db)):
    """Soft-close all 'false_positive' and 'resolved' incidents in one operation.
    Transitions each to 'closed' with an audit entry — does not delete any rows.
    Returns counts for each source status.
    """
    from iris_connector import write_audit
    targets = list((await db.execute(
        select(Incident).where(Incident.status.in_(["false_positive", "resolved"]))
    )).scalars().all())
    if not targets:
        return {"closed": 0, "from_fp": 0, "from_resolved": 0}

    now_ts = datetime.now(timezone.utc)
    from_fp = from_resolved = 0
    for inc in targets:
        prev = inc.status
        inc.status     = "closed"
        inc.closed_at  = now_ts
        inc.updated_at = now_ts
        await db.flush()
        try:
            await write_audit(
                db, "incident", inc.id,
                action="status_change",
                actor=req.actor or "analyst",
                from_status=prev,
                to_status="closed",
                comment=req.comment.strip(),
            )
        except Exception:
            pass
        if prev == "false_positive":
            from_fp += 1
        else:
            from_resolved += 1

    await db.commit()
    total = from_fp + from_resolved
    log.info("batch_close_complete", total=total, from_fp=from_fp, from_resolved=from_resolved)
    return {"closed": total, "from_fp": from_fp, "from_resolved": from_resolved}


@app.post("/incidents/{incident_id}/transition")
async def transition_incident(
    incident_id: str,
    body: StatusTransition,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyst-initiated status transition with mandatory audit comment.
    Validates the transition is allowed and records an immutable audit entry.
    """
    if not body.comment or not body.comment.strip():
        raise HTTPException(status_code=422,
                            detail="Audit comment is required for status transitions.")

    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    from_st = inc.status or "open"
    to_st   = body.to_status

    allowed = _ALLOWED_TRANSITIONS.get(from_st, set())
    if to_st not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"Transition '{from_st}' → '{to_st}' is not allowed. "
                   f"Allowed: {sorted(allowed)}",
        )

    from iris_connector import write_audit
    inc.status     = to_st
    inc.updated_at = datetime.now(timezone.utc)
    if to_st in ("resolved", "closed", "false_positive"):
        inc.closed_at = datetime.now(timezone.utc)
    if to_st == "false_positive" and body.comment:
        inc.false_positive_reason = body.comment.strip()

    await db.flush()
    await write_audit(
        db, "incident", incident_id,
        action="status_change",
        actor=body.actor or "analyst",
        from_status=from_st,
        to_status=to_st,
        comment=body.comment.strip(),
    )

    # Auto-submit feedback and record FP pattern when analyst marks as false_positive
    if to_st == "false_positive":
        rules = [
            r.get("rule_id") if isinstance(r, dict) else r
            for r in (inc.correlated_rules or [])
        ]
        await submit_feedback(
            db,
            incident_id   = incident_id,
            verdict       = "false_positive",
            rules_fired   = rules,
            analyst_email = body.actor,
            notes         = body.comment.strip(),
        )

    await db.commit()
    return _incident_to_dict(inc)


@app.delete("/incidents")
async def purge_incidents(
    status: Optional[str] = Query(
        None,
        description="Comma-separated statuses to purge, e.g. 'resolved,false_positive'. "
                    "Omit to purge ALL incidents.",
    ),
    db: AsyncSession = Depends(get_db),
):
    """Hard-delete incidents (and their child alerts) filtered by status.
    This is an admin-only destructive operation — the proxy layer enforces RBAC.
    """
    statuses = [s.strip() for s in status.split(",") if s.strip()] if status else None
    # Collect IDs first so we can clean child alerts
    id_q = select(Incident.id)
    if statuses:
        id_q = id_q.where(Incident.status.in_(statuses))
    incident_ids = list((await db.execute(id_q)).scalars().all())
    if not incident_ids:
        return {"deleted": 0}
    await db.execute(delete(Alert).where(Alert.incident_id.in_(incident_ids)))
    await db.execute(delete(Incident).where(Incident.id.in_(incident_ids)))
    await db.commit()
    log.info("incidents_purged", count=len(incident_ids), status_filter=statuses)
    return {"deleted": len(incident_ids)}


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
    await redis_conn.rpush(settings.redis_alert_key, _json.dumps(alert))
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


# ── On-demand AI analysis endpoint ────────────────────────────────────────────

@app.post("/incidents/{incident_id}/analyse")
async def analyse_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    """Trigger LLM enrichment on demand for any incident regardless of severity/age."""
    inc = (await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )).scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    from llm_enricher import enrich_incident as llm_enrich_incident
    result = await llm_enrich_incident(db, inc, on_demand=True)
    await db.commit()

    if not result:
        raise HTTPException(status_code=503,
                            detail="LLM enrichment failed or is disabled. "
                                   "Check AI settings in the portal.")
    return {
        "ok":               True,
        "llm_summary":      inc.llm_summary,
        "llm_remediation":  inc.llm_remediation,
        "llm_generated_at": inc.llm_generated_at.isoformat() if inc.llm_generated_at else None,
    }


# ── FP Pattern management endpoints ───────────────────────────────────────────
from fp_pattern_store import check_fp_pattern as _check_fp_pattern
from models import FpPattern


class FpPatternPatch(BaseModel):
    auto_close:  Optional[bool] = None
    threshold:   Optional[int]  = None
    description: Optional[str]  = None


@app.get("/fp-patterns")
async def list_fp_patterns(db: AsyncSession = Depends(get_db)):
    """List all learned FP patterns."""
    result = await db.execute(
        select(FpPattern).order_by(desc(FpPattern.close_count))
    )
    patterns = result.scalars().all()
    return [
        {
            "id":          p.id,
            "fingerprint": p.fingerprint[:16] + "…",
            "rule_id":     p.rule_id,
            "description": p.description,
            "agent_id":    p.agent_id,
            "close_count": p.close_count,
            "threshold":   p.threshold,
            "auto_close":  p.auto_close,
            "last_seen":   p.last_seen.isoformat() if p.last_seen else None,
            "created_at":  p.created_at.isoformat() if p.created_at else None,
            "created_by":  p.created_by,
            "raw_sample":  p.raw_sample,
        }
        for p in patterns
    ]


@app.patch("/fp-patterns/{pattern_id}")
async def patch_fp_pattern(
    pattern_id: int,
    body: FpPatternPatch,
    db: AsyncSession = Depends(get_db),
):
    """Toggle auto_close, adjust threshold, or update description."""
    p = (await db.execute(
        select(FpPattern).where(FpPattern.id == pattern_id)
    )).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Pattern not found")

    if body.auto_close is not None:
        p.auto_close = body.auto_close
    if body.threshold is not None:
        p.threshold = body.threshold
    if body.description is not None:
        p.description = body.description
    p.updated_at = datetime.now(timezone.utc)

    await db.commit()
    return {"ok": True, "id": p.id, "auto_close": p.auto_close, "threshold": p.threshold}


@app.delete("/fp-patterns/{pattern_id}")
async def delete_fp_pattern(pattern_id: int, db: AsyncSession = Depends(get_db)):
    """Remove a learned FP pattern entirely."""
    p = (await db.execute(
        select(FpPattern).where(FpPattern.id == pattern_id)
    )).scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Pattern not found")
    await db.delete(p)
    await db.commit()
    return {"ok": True, "deleted_id": pattern_id}


@app.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Agentic action endpoints ───────────────────────────────────────────────────
# These are called by the CyCentra Flask layer when an analyst confirms a chat action.
# The Flask proxy enforces analyst+ RBAC before forwarding here.

class ActiveResponseReq(BaseModel):
    agent_id:  str
    command:   str
    arguments: Optional[list[str]] = []

@app.post("/active-response")
async def engine_active_response(req: ActiveResponseReq):
    """Execute a Wazuh active-response command on a specific agent.
    Requires Wazuh API credentials to be configured in cysiemstack.env.
    Called by the CyCentra agentic chat layer — never exposed publicly.
    """
    if not settings.wazuh_api_user or not settings.wazuh_api_password:
        raise HTTPException(status_code=503,
                            detail="Wazuh API credentials not configured in cysiemstack.env")
    try:
        creds = base64.b64encode(
            f"{settings.wazuh_api_user}:{settings.wazuh_api_password}".encode()
        ).decode()
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            tr = await c.get(
                f"{settings.wazuh_api_url}/security/user/authenticate",
                headers={"Authorization": f"Basic {creds}"},
            )
            tr.raise_for_status()
            token = tr.json()["data"]["token"]

        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            r = await c.put(
                f"{settings.wazuh_api_url}/active-response",
                headers={"Authorization": f"Bearer {token}"},
                json={"command": req.command, "arguments": req.arguments or []},
                params={"agents_list": req.agent_id},
            )
            r.raise_for_status()
            log.info("active_response_triggered",
                     agent_id=req.agent_id, command=req.command, arguments=req.arguments)
            return {"status": "triggered", "agent_id": req.agent_id,
                    "command": req.command, "wazuh": r.json()}
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code,
                            detail=f"Wazuh API error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh unreachable: {e}")


class BulkFPReq(BaseModel):
    incident_ids: list[str]
    comment:      str
    actor:        Optional[str] = "analyst"

@app.post("/incidents/bulk-false-positive")
async def bulk_false_positive(req: BulkFPReq, db: AsyncSession = Depends(get_db)):
    """Mark multiple incidents as false_positive in one call.
    Used by the agentic chat 'close all false positives' action.
    """
    from iris_connector import write_audit
    results = []
    for iid in req.incident_ids:
        inc = (await db.execute(
            select(Incident).where(Incident.id == iid)
        )).scalar_one_or_none()
        if not inc:
            results.append({"id": iid, "success": False, "error": "not_found"})
            continue
        from_status = inc.status or "open"
        # Only transition if the incident is not already closed/archived
        if from_status in ("resolved", "false_positive", "closed"):
            results.append({"id": iid, "success": False, "error": "already_closed"})
            continue
        inc.status               = "false_positive"
        inc.updated_at           = datetime.now(timezone.utc)
        inc.closed_at            = datetime.now(timezone.utc)
        inc.false_positive_reason = req.comment.strip()
        await db.flush()
        try:
            await write_audit(
                db, "incident", iid,
                action="status_change",
                actor=req.actor or "analyst",
                from_status=from_status,
                to_status="false_positive",
                comment=req.comment.strip(),
            )
        except Exception:
            pass  # audit write failure must not block the bulk operation
        results.append({"id": iid, "success": True})
    await db.commit()
    success_count = sum(1 for r in results if r["success"])
    log.info("bulk_false_positive_complete", success=success_count, total=len(req.incident_ids))
    return {"results": results, "success_count": success_count, "total": len(req.incident_ids)}


# ── Audit write endpoint (used by external callers: Flask proxy agentic actions) ─
class AuditWriteReq(BaseModel):
    entity_type: str
    entity_id:   str
    action:      str
    comment:     Optional[str] = None
    actor:       str = "analyst"
    from_status: Optional[str] = None
    to_status:   Optional[str] = None
    extra:       Optional[dict] = None


@app.post("/audit")
async def write_audit_entry(req: AuditWriteReq, db: AsyncSession = Depends(get_db)):
    """Write an audit log entry for an externally-confirmed action.

    Called by the CyCentra 360 Flask proxy after every confirmed agentic action
    (assign, note, escalate, SOAR trigger, enrich, etc.) so that all chat-driven
    operations have a persisted audit trail in the correlation engine DB.

    This endpoint accepts any entity_type but validation is intentionally loose —
    the Flask proxy is trusted loopback; it never accepts user-controlled payloads
    directly without session authentication.
    """
    from iris_connector import write_audit
    try:
        await write_audit(
            db,
            entity_type = req.entity_type,
            entity_id   = req.entity_id,
            action      = req.action,
            actor       = req.actor,
            from_status = req.from_status,
            to_status   = req.to_status,
            comment     = req.comment,
            extra       = req.extra or {},
        )
        await db.commit()
        log.info("audit_entry_written", entity=req.entity_id, action=req.action, actor=req.actor)
        return {"ok": True}
    except Exception as e:
        log.error("audit_entry_failed", error=str(e))
        return {"ok": False, "error": str(e)}


# ── Incident distribution endpoint (severity / status / category) ──────────────

@app.get("/incidents/distribution")
async def get_incident_distribution(db: AsyncSession = Depends(get_db)):
    """
    Return pre-aggregated incident counts grouped by severity, status, and
    category.  Used by the Benchmark Intelligence Engine to populate the
    distribution charts on the Posture Benchmark page.

    Response:
      {
        "by_severity": {"critical": N, "high": N, "medium": N, "low": N},
        "by_status":   {"open": N, "investigating": N, "in_review": N, ...},
        "by_category": {"Malware": N, "Brute Force": N, ...},  // top 15
        "total":       N
      }
    """
    from sqlalchemy import func, text as sa_text

    # ── Severity distribution ─────────────────────────────────────────────────
    sev_rows = (await db.execute(
        select(Incident.severity, func.count().label("n"))
        .group_by(Incident.severity)
    )).all()
    by_severity: dict[str, int] = {}
    for sev, n in sev_rows:
        by_severity[str(sev or "unknown").lower()] = int(n)

    # ── Status distribution ───────────────────────────────────────────────────
    sta_rows = (await db.execute(
        select(Incident.status, func.count().label("n"))
        .group_by(Incident.status)
    )).all()
    by_status: dict[str, int] = {}
    for sta, n in sta_rows:
        by_status[str(sta or "unknown").lower()] = int(n)

    # ── Category distribution (unnest ARRAY column, top 15) ──────────────────
    cat_rows = (await db.execute(sa_text("""
        SELECT cat, COUNT(*) AS n
        FROM incidents, UNNEST(categories) AS cat
        WHERE categories IS NOT NULL
          AND array_length(categories, 1) > 0
        GROUP BY cat
        ORDER BY n DESC
        LIMIT 15
    """))).all()
    by_category: dict[str, int] = {str(cat): int(n) for cat, n in cat_rows}

    total = sum(by_severity.values())
    log.info("incident_distribution_fetched", total=total,
             severities=list(by_severity.keys()), statuses=list(by_status.keys()))

    return {
        "by_severity": by_severity,
        "by_status":   by_status,
        "by_category": by_category,
        "total":       total,
    }


# ── Security MCP bridge (mounted at /mcp) ─────────────────────────────────────
# Always enabled when the mcp package is installed (installed alongside the engine).
# AI clients connect to: http://127.0.0.1:8100/mcp/sse
try:
    from mcp.server.fastmcp import FastMCP as _FastMCP

    if True:
        _mcp = _FastMCP(
            "CySIEM Security MCP",
            instructions=(
                "You are a security operations assistant with live access to CyCentra 360. "
                "Use the provided tools to investigate incidents, inspect UEBA behavioural "
                "anomalies, query entity risk scores, enumerate Wazuh endpoints, and trigger "
                "active-response containment actions. Always confirm agent IDs before running "
                "active-response commands."
            ),
        )

        # ── Wazuh auth helpers ─────────────────────────────────────────────────

        async def _wazuh_token() -> str:
            creds = base64.b64encode(
                f"{settings.wazuh_api_user}:{settings.wazuh_api_password}".encode()
            ).decode()
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                r = await c.get(
                    f"{settings.wazuh_api_url}/security/user/authenticate",
                    headers={"Authorization": f"Basic {creds}"},
                )
                r.raise_for_status()
                return r.json()["data"]["token"]

        async def _wazuh_get(path: str, params: dict | None = None) -> dict:
            token = await _wazuh_token()
            async with httpx.AsyncClient(verify=False, timeout=15) as c:
                r = await c.get(
                    f"{settings.wazuh_api_url}{path}",
                    headers={"Authorization": "Bearer " + token},
                    params=params or {},
                )
                r.raise_for_status()
                return r.json()

        async def _wazuh_put(path: str, body: dict | None = None, params: dict | None = None) -> dict:
            token = await _wazuh_token()
            async with httpx.AsyncClient(verify=False, timeout=15) as c:
                r = await c.put(
                    f"{settings.wazuh_api_url}{path}",
                    headers={"Authorization": "Bearer " + token},
                    json=body or {},
                    params=params or {},
                )
                r.raise_for_status()
                return r.json()

        # ── MCP tools — correlation engine ─────────────────────────────────────

        @_mcp.tool()
        async def get_stats() -> str:
            """Return high-level SIEM statistics: total incidents, alerts processed,
            active anomalies, and engine uptime."""
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get("http://127.0.0.1:8100/stats")
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def list_incidents(
            status: Optional[str] = None,
            severity: Optional[str] = None,
            limit: int = 20,
        ) -> str:
            """List security incidents from the correlation engine.

            Args:
                status:   Filter by lifecycle status.
                          Values: open | investigating | resolved | false_positive
                severity: Filter by severity level.
                          Values: low | medium | high | critical
                limit:    Maximum number of incidents to return (1–100, default 20).
            """
            params: dict = {"limit": max(1, min(limit, 100))}
            if status:
                params["status"] = status
            if severity:
                params["severity"] = severity
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/incidents", params=params)
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def search_incidents(
            user:     Optional[str] = None,
            agent:    Optional[str] = None,
            src_ip:   Optional[str] = None,
            status:   Optional[str] = None,
            severity: Optional[str] = None,
            limit: int = 20,
        ) -> str:
            """Search incidents by affected user, agent/host, source IP, severity, or status.

            Use this for questions like:
            - "how many incidents are related to user shibu"
            - "list incidents for user john.doe"
            - "incidents involving host DESKTOP-ABC"
            - "open incidents from IP 10.0.0.1"

            CRITICAL GROUNDING RULE: The `total` field is the EXACT database count.
            The `incidents` array contains REAL records only.
            Do NOT invent, guess, or add any incident IDs, descriptions, usernames,
            timestamps, or counts beyond what this tool returns.
            If total is 0 — say "No incidents found" and nothing else.

            Args:
                user:     Partial username (case-insensitive) to search in affected_users.
                agent:    Partial agent/hostname to search in affected_agents.
                src_ip:   Partial IP address to search in src_ips.
                status:   Filter by status: open | investigating | in_review | resolved | false_positive
                severity: Filter by severity: low | medium | high | critical
                limit:    Max results to return (1-100, default 20).
            """
            params: dict = {"limit": max(1, min(limit, 100))}
            if user:     params["user"]     = user
            if agent:    params["agent"]    = agent
            if src_ip:   params["src_ip"]   = src_ip
            if status:   params["status"]   = status
            if severity: params["severity"] = severity
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/incidents", params=params)
                r.raise_for_status()
                data = r.json()
            total     = data.get("total", 0)
            incidents = data.get("incidents", [])
            return _stdlib_json.dumps({
                "total":     total,
                "incidents": incidents,
                "_note":     (
                    f"EXACT database result: {total} incident(s) matched your query. "
                    "These are real records. Do NOT add, invent, or modify any detail. "
                    "If total is 0, tell the user no incidents were found — never fabricate."
                ),
            }, indent=2)

        @_mcp.tool()
        async def get_incident(incident_id: str) -> str:
            """Get full details for a specific security incident.

            Returns correlated rules, UEBA flags, MITRE ATT&CK tactic/kill-chain
            mapping, LLM-generated summary, and recommended remediation steps.

            Args:
                incident_id: Incident identifier (e.g. INC-0042).
            """
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"http://127.0.0.1:8100/incidents/{incident_id}")
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def list_alerts(
            incident_id: Optional[str] = None,
            limit: int = 50,
        ) -> str:
            """List raw Wazuh alerts ingested by the correlation engine.

            Args:
                incident_id: Restrict to alerts belonging to a specific incident.
                limit:       Maximum number of alerts to return (1–200, default 50).
            """
            params: dict = {"limit": max(1, min(limit, 200))}
            if incident_id:
                params["incident_id"] = incident_id
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/alerts", params=params)
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def list_risk_scores(
            entity_type: Optional[str] = None,
            level: Optional[str] = None,
            limit: int = 20,
        ) -> str:
            """Return entity risk scores ranked by current threat level.

            Args:
                entity_type: Filter by entity type. Values: user | host | ip
                level:       Filter by risk band. Values: low | medium | high | critical
                limit:       Maximum number of results (1–100, default 20).
            """
            params: dict = {"limit": max(1, min(limit, 100))}
            if entity_type:
                params["entity_type"] = entity_type
            if level:
                params["level"] = level
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/risk-scores", params=params)
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def list_ueba_users(
            category: Optional[str] = None,
            has_anomaly: Optional[bool] = None,
            top_activity: Optional[int] = None,
        ) -> str:
            """List users tracked by UEBA with their behavioural baseline profiles.

            Args:
                category:     Filter by account type. Values: system | service | human
                has_anomaly:  If true, return only users with at least one active anomaly.
                top_activity: If set, return the top N users by average daily event count.
            """
            params: dict = {}
            if category:
                params["category"] = category
            if has_anomaly is not None:
                params["has_anomaly"] = str(has_anomaly).lower()
            if top_activity is not None:
                params["top_activity"] = top_activity
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/ueba/users", params=params)
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def get_ueba_anomalies(username: str) -> str:
            """Get the UEBA baseline and full anomaly history for a specific user.

            Returns the behavioural baseline (typical hours, agents, fail rates) and
            a list of detected anomalies with severity, type, and triggering alert context.

            Args:
                username: Exact username to investigate (case-sensitive).
            """
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(f"http://127.0.0.1:8100/ueba/{username}")
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        # ── MCP tools — Wazuh Manager API ──────────────────────────────────────

        @_mcp.tool()
        async def wazuh_list_agents(
            status: Optional[str] = None,
            limit: int = 25,
        ) -> str:
            """List Wazuh agents (monitored endpoints) registered with the manager.

            Args:
                status: Filter by connection status.
                        Values: active | disconnected | never_connected | pending
                limit:  Maximum number of agents to return (1–500, default 25).
            """
            params: dict = {
                "limit": max(1, min(limit, 500)),
                "select": "id,name,ip,status,os,version,lastKeepAlive",
            }
            if status:
                params["status"] = status
            data = await _wazuh_get("/agents", params=params)
            agents = data.get("data", {}).get("affected_items", [])
            return _stdlib_json.dumps({"agents": agents, "total": len(agents)}, indent=2)

        @_mcp.tool()
        async def wazuh_active_response(
            agent_id: str,
            command: str,
            arguments: Optional[list[str]] = None,
        ) -> str:
            """Trigger a Wazuh active-response action on a specific endpoint.

            Use this to contain threats — for example block a source IP, disable a
            compromised account, or restart the Wazuh agent process.

            Common commands: firewall-drop, disable-account, restart-wazuh

            Args:
                agent_id:  Wazuh agent ID (e.g. "001"). Use wazuh_list_agents to look up IDs.
                command:   Active-response command name (must match ossec.conf definition).
                arguments: Optional list of command arguments (e.g. ["192.168.1.100"]).
            """
            body = {"command": command, "arguments": arguments or []}
            data = await _wazuh_put(
                "/active-response",
                body=body,
                params={"agents_list": agent_id},
            )
            log.info("wazuh_active_response_triggered",
                     agent_id=agent_id, command=command, arguments=arguments)
            return _stdlib_json.dumps(data, indent=2)

        @_mcp.tool()
        async def wazuh_get_agent_vulnerabilities(
            agent_id: str,
            severity: Optional[str] = None,
            limit: int = 25,
        ) -> str:
            """Get known vulnerabilities detected on a specific Wazuh-monitored endpoint.

            Args:
                agent_id: Wazuh agent ID (e.g. "001").
                severity: Filter by severity. Values: Critical | High | Medium | Low
                limit:    Maximum number of results (1–100, default 25).
            """
            params: dict = {"limit": max(1, min(limit, 100))}
            if severity:
                params["severity"] = severity
            data = await _wazuh_get(f"/vulnerability/{agent_id}", params=params)
            return _stdlib_json.dumps(data.get("data", {}), indent=2)

        # ── MCP tools — extended read tools ────────────────────────────────────

        @_mcp.tool()
        async def get_alert(alert_id: str) -> str:
            """Get full details for a single alert by its internal ID.

            Returns agent, rule, MITRE mapping, MISP IOC match flag, risk score,
            source IP, username, file path, and the incident it belongs to.

            Args:
                alert_id: Internal alert ID (integer as string, e.g. "4821").
            """
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get("http://127.0.0.1:8100/alerts",
                                params={"limit": 500})
                r.raise_for_status()
                data = r.json()
                alerts = data if isinstance(data, list) else data.get("alerts", data)
                for a in alerts:
                    if str(a.get("id")) == str(alert_id):
                        return _stdlib_json.dumps(a, indent=2)
                return _stdlib_json.dumps({"error": f"Alert {alert_id} not found"}, indent=2)

        @_mcp.tool()
        async def search_alerts(
            agent_id: Optional[str] = None,
            rule_id: Optional[str] = None,
            severity_min: Optional[int] = None,
            has_misp_match: Optional[bool] = None,
            limit: int = 30,
        ) -> str:
            """Search alerts with multiple filter criteria.

            Filters are applied client-side against the most recent alerts.
            Useful for hunting across rule IDs or specific endpoints.

            Args:
                agent_id:       Filter alerts from this Wazuh agent ID.
                rule_id:        Filter alerts matching this Wazuh rule ID.
                severity_min:   Minimum rule_level (Wazuh severity, 1–15).
                has_misp_match: If true, return only alerts with a MISP IOC match.
                limit:          Maximum results to return (1–200, default 30).
            """
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/alerts",
                                params={"limit": 500})
                r.raise_for_status()
                data = r.json()
                alerts = data if isinstance(data, list) else data.get("alerts", data)

            results = []
            for a in alerts:
                if agent_id and str(a.get("agent_id")) != str(agent_id):
                    continue
                if rule_id and str(a.get("rule_id")) != str(rule_id):
                    continue
                if severity_min is not None and (a.get("rule_level") or 0) < severity_min:
                    continue
                if has_misp_match is True and not a.get("misp_ioc_match"):
                    continue
                results.append(a)
                if len(results) >= max(1, min(limit, 200)):
                    break
            return _stdlib_json.dumps({"alerts": results, "total": len(results)}, indent=2)

        @_mcp.tool()
        async def update_incident(
            incident_id: str,
            assigned_to: Optional[str] = None,
            notes: Optional[str] = None,
            severity: Optional[str] = None,
        ) -> str:
            """Update an incident's assignee, analyst notes, or severity.

            Use this to assign incidents to analysts, add investigation notes,
            or change severity when initial auto-classification was incorrect.
            This is a write operation — analyst confirmation is required.

            Args:
                incident_id: Incident identifier (e.g. INC-0042).
                assigned_to: Email or username of the analyst to assign.
                notes:       Free-text analyst notes to append (replaces existing notes).
                severity:    New severity level. Values: low | medium | high | critical
            """
            body: dict = {}
            if assigned_to is not None:
                body["assigned_to"] = assigned_to
            if notes is not None:
                body["notes"] = notes
            # severity is stored as part of the patch on the incident model
            if severity is not None:
                body["severity"] = severity
            if not body:
                return _stdlib_json.dumps({"error": "No fields to update — provide at least one of assigned_to, notes, or severity"}, indent=2)
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.patch(
                    f"http://127.0.0.1:8100/incidents/{incident_id}",
                    json=body,
                )
                r.raise_for_status()
                return _stdlib_json.dumps(r.json(), indent=2)

        @_mcp.tool()
        async def list_campaigns(limit: int = 10) -> str:
            """List correlated attack campaigns — groups of open incidents that share
            attacker infrastructure (common source IPs or affected users).

            Each campaign entry shows its campaign_id, the linked incident IDs,
            shared indicators, and the earliest/latest activity timestamps.

            Args:
                limit: Maximum number of campaigns to return (1–50, default 10).
            """
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get("http://127.0.0.1:8100/incidents",
                                params={"limit": 200, "status": "open"})
                r.raise_for_status()
                data = r.json()
                incidents = data if isinstance(data, list) else data.get("incidents", [])

            # Group by campaign_id
            campaigns: dict[str, dict] = {}
            ungrouped = []
            for inc in incidents:
                cid = inc.get("campaign_id")
                if not cid:
                    ungrouped.append(inc.get("id"))
                    continue
                if cid not in campaigns:
                    campaigns[cid] = {
                        "campaign_id":      cid,
                        "incident_count":   0,
                        "incident_ids":     [],
                        "severities":       [],
                        "earliest_seen":    inc.get("first_seen"),
                        "latest_seen":      inc.get("last_seen"),
                    }
                entry = campaigns[cid]
                entry["incident_count"] += 1
                entry["incident_ids"].append(inc.get("id"))
                entry["severities"].append(inc.get("severity"))
                if inc.get("first_seen") and (not entry["earliest_seen"] or inc["first_seen"] < entry["earliest_seen"]):
                    entry["earliest_seen"] = inc["first_seen"]
                if inc.get("last_seen") and (not entry["latest_seen"] or inc["last_seen"] > entry["latest_seen"]):
                    entry["latest_seen"] = inc["last_seen"]

            result = sorted(campaigns.values(), key=lambda x: x["incident_count"], reverse=True)
            return _stdlib_json.dumps({
                "campaigns":          result[:max(1, min(limit, 50))],
                "total_campaigns":    len(campaigns),
                "ungrouped_incidents": len(ungrouped),
            }, indent=2)

        @_mcp.tool()
        async def get_threat_intel(
            ioc_value: str,
            ioc_type: Optional[str] = None,
        ) -> str:
            """Look up a threat indicator (IP, domain, SHA256 hash) against MISP
            and the entity risk score database.

            Returns MISP event matches, threat level, associated tags, and the
            entity's current risk score from the correlation engine.

            Args:
                ioc_value: The indicator value to look up (IP address, domain, or SHA256 hash).
                ioc_type:  Optional type hint. Values: ip | domain | sha256
                           If omitted the type is inferred from the value format.
            """
            from models import AsyncSessionLocal, MISPIOCCache, RiskScore
            from sqlalchemy import select as _select
            result: dict = {"ioc_value": ioc_value, "ioc_type": ioc_type, "misp": None, "risk_score": None}

            # Infer type if not provided
            if not ioc_type:
                import re as _re
                if _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ioc_value):
                    ioc_type = "ip"
                elif _re.match(r'^[0-9a-fA-F]{64}$', ioc_value):
                    ioc_type = "sha256"
                else:
                    ioc_type = "domain"
                result["ioc_type"] = ioc_type

            async with AsyncSessionLocal() as db:
                # MISP cache lookup
                row = (await db.execute(
                    _select(MISPIOCCache)
                    .where(MISPIOCCache.ioc_value == ioc_value,
                           MISPIOCCache.ioc_type == ioc_type)
                )).scalar_one_or_none()
                if row:
                    result["misp"] = {
                        "is_hit":      row.is_hit,
                        "threat_level": row.threat_level,
                        "tags":        row.tags or [],
                        "events":      row.misp_events or [],
                        "cached_at":   row.cached_at.isoformat() if row.cached_at else None,
                    }

                # Risk score lookup (IP or hostname)
                if ioc_type in ("ip", "domain"):
                    rs = (await db.execute(
                        _select(RiskScore).where(RiskScore.entity_id == ioc_value)
                    )).scalar_one_or_none()
                    if rs:
                        result["risk_score"] = {
                            "score":     float(rs.score or 0),
                            "level":     rs.level,
                            "trend":     rs.trend,
                            "breakdown": rs.score_breakdown or {},
                        }

            return _stdlib_json.dumps(result, indent=2)

        @_mcp.tool()
        async def get_vuln_summary(
            severity: Optional[str] = None,
            limit: int = 10,
        ) -> str:
            """Return an aggregated vulnerability summary across all Wazuh agents.

            Groups CVEs by severity, counts affected agents, and surfaces the
            top open findings. Useful for understanding overall exposure at a glance.

            Args:
                severity: Filter results. Values: Critical | High | Medium | Low
                limit:    Maximum number of top findings to return (1–50, default 10).
            """
            # Pull all active agents
            try:
                agents_data = await _wazuh_get("/agents", params={
                    "status": "active", "limit": 500,
                    "select": "id,name",
                })
                agent_ids = [
                    a["id"]
                    for a in agents_data.get("data", {}).get("affected_items", [])
                ]
            except Exception:
                agent_ids = ["000"]

            counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            top_findings: list[dict] = []

            for aid in agent_ids[:20]:  # cap at 20 agents to avoid timeout
                try:
                    params: dict = {"limit": 100}
                    if severity:
                        params["severity"] = severity
                    data = await _wazuh_get(f"/vulnerability/{aid}", params=params)
                    vulns = data.get("data", {}).get("affected_items", [])
                    for v in vulns:
                        sev = v.get("severity", "Unknown")
                        if sev in counts:
                            counts[sev] += 1
                        top_findings.append({
                            "agent_id": aid,
                            "cve":      v.get("cve"),
                            "severity": sev,
                            "cvss3":    v.get("cvss3_score"),
                            "package":  v.get("name"),
                            "version":  v.get("version"),
                        })
                except Exception:
                    continue

            # Sort by severity weight
            _weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            top_findings.sort(key=lambda x: _weight.get(x["severity"], 0), reverse=True)

            return _stdlib_json.dumps({
                "summary_by_severity": counts,
                "total_findings":      sum(counts.values()),
                "agents_scanned":      len(agent_ids[:20]),
                "top_findings":        top_findings[:max(1, min(limit, 50))],
            }, indent=2)

        @_mcp.tool()
        async def get_compliance_status() -> str:
            """Return the current compliance posture across all active control frameworks.

            Reads from the CyCentra 360 compliance controls database and returns
            pass/fail counts, overall compliance percentage, and the top failing
            control areas by framework (NIS2, ISO 27001, DORA, GDPR, CIS).

            Falls back to an ASM-derived estimate if the compliance DB is unavailable.
            """
            try:
                import asyncpg as _asyncpg
                from config import get_settings as _gs
                s = _gs()
                conn = await _asyncpg.connect(
                    host=s.postgres_host,
                    port=int(s.postgres_port or 5432),
                    database=s.postgres_db,
                    user=s.postgres_user,
                    password=s.postgres_password,
                )
                rows = await conn.fetch(
                    "SELECT framework, control_id, title, status, last_checked "
                    "FROM cy_compliance_controls ORDER BY framework, control_id"
                )
                await conn.close()

                by_framework: dict[str, dict] = {}
                for row in rows:
                    fw = row["framework"] or "General"
                    if fw not in by_framework:
                        by_framework[fw] = {"pass": 0, "fail": 0, "total": 0, "failing_controls": []}
                    entry = by_framework[fw]
                    entry["total"] += 1
                    if row["status"] == "pass":
                        entry["pass"] += 1
                    else:
                        entry["fail"] += 1
                        if len(entry["failing_controls"]) < 5:
                            entry["failing_controls"].append({
                                "id":    row["control_id"],
                                "title": row["title"],
                            })

                total_pass  = sum(v["pass"]  for v in by_framework.values())
                total_total = sum(v["total"] for v in by_framework.values())
                pct = round(100 * total_pass / total_total, 1) if total_total else 0

                return _stdlib_json.dumps({
                    "overall_compliance_pct": pct,
                    "total_controls":         total_total,
                    "passing":                total_pass,
                    "failing":                total_total - total_pass,
                    "by_framework":           by_framework,
                }, indent=2)

            except Exception as exc:
                return _stdlib_json.dumps({
                    "error":   f"Compliance DB unavailable: {exc}",
                    "message": "Run the compliance scanner or check the cy_compliance_controls table.",
                }, indent=2)


        @_mcp.tool()
        async def get_incident_distribution() -> str:
            """Return the real count of incidents broken down by severity, status, and category.

            Use this tool whenever the analyst asks about:
            - how many critical/high/medium/low incidents there are
            - incident severity distribution or breakdown
            - incident status split (open, investigating, resolved, false positive, etc.)
            - which attack categories or incident types are most common
            - any question containing 'distribution', 'breakdown', 'how many', 'count by',
              'by severity', 'by status', 'by category', 'by type'

            Returns exact database counts — never estimate or guess when this tool is available.
            """
            from sqlalchemy import func, text as _sa_text
            async with AsyncSessionLocal() as db:
                # Severity
                sev_rows = (await db.execute(
                    select(Incident.severity, func.count().label("n"))
                    .group_by(Incident.severity)
                )).all()
                by_severity = {str(s or "unknown").lower(): int(n) for s, n in sev_rows}

                # Status
                sta_rows = (await db.execute(
                    select(Incident.status, func.count().label("n"))
                    .group_by(Incident.status)
                )).all()
                by_status = {str(s or "unknown").lower(): int(n) for s, n in sta_rows}

                # Category (unnest ARRAY, top 15)
                cat_rows = (await db.execute(_sa_text("""
                    SELECT cat, COUNT(*) AS n
                    FROM incidents, UNNEST(categories) AS cat
                    WHERE categories IS NOT NULL
                      AND array_length(categories, 1) > 0
                    GROUP BY cat
                    ORDER BY n DESC
                    LIMIT 15
                """))).all()
                by_category = {str(c): int(n) for c, n in cat_rows}

            total = sum(by_severity.values())
            return _stdlib_json.dumps({
                "total_incidents":  total,
                "by_severity":      by_severity,
                "by_status":        by_status,
                "by_category":      by_category,
                "note": (
                    "These are exact database counts. "
                    "Use them directly — do not guess or estimate."
                ),
            }, indent=2)


        # Mount the MCP sub-application — SSE endpoint: /mcp/sse
        # FastMCP >=1.6 removed get_application(); fall back to the ASGI app directly.
        _mcp_asgi = (
            _mcp.get_application() if hasattr(_mcp, "get_application")
            else getattr(_mcp, "get_asgi_app", lambda: _mcp)()
        )
        app.mount("/mcp", _mcp_asgi)
        log.info("security_mcp_mounted", path="/mcp/sse")

except ImportError:
    log.info("mcp_package_not_installed", hint="pip install 'mcp[cli]' to enable the Security MCP bridge")


# ── CyMind MCP access-control (ASGI-level, streaming-safe) ───────────────────
# Wraps the FastAPI app so that /mcp/* requests are rejected unless the caller
# presents a valid API key.  Uses raw ASGI to avoid BaseHTTPMiddleware's
# response-buffering, which would break SSE streaming.
#
# Valid keys: the CyMind M2M master key (CYMIND_API_KEY from env) PLUS any
# 3rd-party cymk_... keys stored in ai_settings.json → cymind_integration.mcp_api_keys.
# Keys are loaded at request time so new keys take effect without a restart.
_cymind_key = str(getattr(settings, "cymind_api_key", "") or "").strip()


def _load_valid_mcp_keys() -> set:
    """Return the set of all currently valid MCP bearer tokens."""
    keys = set()
    if _cymind_key:
        keys.add(_cymind_key)
    try:
        import json as _json
        from pathlib import Path as _Path
        data = _json.loads(_Path("/opt/cycentra/ai_settings.json").read_text())
        for entry in data.get("cymind_integration", {}).get("mcp_api_keys", []):
            k = str(entry.get("key", "")).strip()
            if k:
                keys.add(k)
    except Exception:
        pass
    return keys


if _cymind_key:
    _inner_app = app  # keep reference before shadowing

    async def app(scope, receive, send):  # noqa: F811 — intentional ASGI replacement
        if scope.get("type") == "http" and scope.get("path", "").startswith("/mcp"):
            raw_headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth_header = raw_headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
            provided = auth_header.removeprefix("Bearer ").strip()
            if not provided:
                provided = raw_headers.get(b"x-cymind-key", b"").decode("utf-8", errors="ignore")
            if provided not in _load_valid_mcp_keys():
                body = b'{"error":"Unauthorized - valid MCP API key required"}'
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(body)).encode()],
                    ],
                })
                await send({"type": "http.response.body", "body": body, "more_body": False})
                return
        await _inner_app(scope, receive, send)

    log.info("mcp_key_guard_active", hint="Master CyMind key + 3rd-party keys accepted for /mcp/* access")
