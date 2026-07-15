"""
blueprints/scheduler/routes.py
================================
Scan & task scheduler for CyCentra 360 agentic chat.

Job store: /opt/cycentra/schedules.json  (created if absent)
Execution: APScheduler BackgroundScheduler (runs in Flask process)
           Protected by a fcntl file-lock so only one gunicorn worker fires jobs.

Routes:
  GET    /api/scheduler/jobs          — list all jobs (viewer+)
  POST   /api/scheduler/jobs          — create a new job (analyst+)
  DELETE /api/scheduler/jobs/<id>     — remove a job (analyst+)
  PATCH  /api/scheduler/jobs/<id>     — enable/disable (analyst+)
  OPTIONS /api/scheduler/jobs         — CORS preflight
  OPTIONS /api/scheduler/jobs/<id>    — CORS preflight

Supported job types:
  asm_scan  — params: {domain, scan_type, include_subdomains}

Supported schedule types:
  cron     — {minute, hour, day, month, day_of_week}  (APScheduler CronTrigger)
  interval — {seconds}                                (APScheduler IntervalTrigger)
"""

import fcntl
import json
import logging
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request, session, make_response
from core.helpers import add_cors_headers

log = logging.getLogger("cycentra.scheduler")

scheduler_bp = Blueprint("scheduler", __name__)

# ── Job store ─────────────────────────────────────────────────────────────────

_STORE_PATH = Path(os.environ.get("SCHEDULES_FILE", "/opt/cycentra/schedules.json"))
_LOCK_PATH  = Path("/tmp/cycentra-scheduler.lock")

_scheduler       = None   # APScheduler BackgroundScheduler instance
_scheduler_owner = False  # True only in the worker that acquired the lock


def _normalise_legacy_job(jid: str, jdata: dict) -> dict:
    """Convert the legacy flat-dict schedules.json schema to the nested job schema."""
    frequency = jdata.get("frequency", "hourly")
    if frequency == "interval":
        schedule = {"type": "interval", "seconds": int(jdata.get("seconds", 3600))}
    else:
        schedule = {
            "type":        "cron",
            "minute":      str(jdata.get("minute", "0")),
            "hour":        str(jdata.get("hour",   "0")),
            "day":         str(jdata.get("day",    "*")),
            "month":       str(jdata.get("month",  "*")),
            "day_of_week": str(jdata.get("day_of_week", "*")),
        }

    if jid == "asm_scan" or jdata.get("type") == "asm_scan":
        jtype = "asm_scan"
        params = {
            "domain":             jdata.get("domain", ""),
            "scan_type":          jdata.get("scan_type", "standard"),
            "include_subdomains": bool(jdata.get("include_subdomains", True)),
            "actor_uid":          "scheduler",
        }
    else:
        jtype = jdata.get("type", jid)
        params = dict(jdata.get("params", {}))
        # Capture command/log from legacy flat-dict format into params
        if "command" not in params and jdata.get("command") is not None:
            params["command"] = jdata.get("command")
        if "log" not in params and jdata.get("log"):
            params["log"] = jdata.get("log")

    return {
        "id":        jdata.get("id", jid),
        "type":      jtype,
        "name":      jdata.get("label", jdata.get("name", jid)),
        "enabled":   bool(jdata.get("enabled", True)),
        "params":    params,
        "schedule":  schedule,
        "label":     jdata.get("label", jid),
        "desc":      jdata.get("desc", ""),
        "log":       jdata.get("log", ""),
        "frequency": frequency,
    }


def _load_jobs() -> list[dict]:
    try:
        if _STORE_PATH.exists():
            raw = json.loads(_STORE_PATH.read_text())
            if isinstance(raw, dict):
                # Legacy format: {"job_id": {...}, ...} — normalise to list
                return [
                    _normalise_legacy_job(k, v)
                    for k, v in raw.items()
                    if isinstance(v, dict)
                ]
            return raw or []
    except Exception:
        pass
    return []


def _save_jobs(jobs: list[dict]) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STORE_PATH.write_text(json.dumps(jobs, indent=2, default=str))


def _upsert_job(job: dict) -> None:
    jobs = _load_jobs()
    jobs = [j for j in jobs if j.get("id") != job.get("id")]
    jobs.append(job)
    _save_jobs(jobs)


def _remove_job_from_store(job_id: str) -> bool:
    jobs = _load_jobs()
    new_jobs = [j for j in jobs if j.get("id") != job_id]
    if len(new_jobs) == len(jobs):
        return False
    _save_jobs(new_jobs)
    return True


# ── Wordlist auto-sync helper ─────────────────────────────────────────────────

# Fixed ID for the wordlist auto-refresh job that mirrors Continuous Sync interval.
_WORDLIST_AUTOSYNC_ID = "asm_wordlist_autosync"


def _sync_wordlist_schedule(interval_seconds: int | None) -> None:
    """Upsert or remove the auto-wordlist-refresh job.

    Called whenever a Continuous Sync (asm_scan interval) job is created,
    deleted, or enabled/disabled so the subdomain wordlist stays current on
    the same cadence as the scans that consume it.

    Pass ``None`` to remove the job (no active Continuous Sync jobs remain).
    """
    if interval_seconds is None:
        _remove_job_from_store(_WORDLIST_AUTOSYNC_ID)
        if _scheduler and _scheduler_owner:
            try:
                _scheduler.remove_job(_WORDLIST_AUTOSYNC_ID)
            except Exception:
                pass
        log.info("wordlist_autosync_removed: no active Continuous Sync jobs")
        return

    wl_job = {
        "id":         _WORDLIST_AUTOSYNC_ID,
        "type":       "asm_wordlist",
        "name":       "ASM Wordlist Auto-Sync (Continuous Sync)",
        "enabled":    True,
        "params":     {"log": "/var/log/cycentra/wordlist-update.log"},
        "schedule":   {"type": "interval", "seconds": interval_seconds},
        "created_by": "system",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_run":   None,
        "next_run":   None,
    }
    _upsert_job(wl_job)
    if _scheduler and _scheduler_owner:
        _add_to_apscheduler(_scheduler, wl_job)
    log.info("wordlist_autosync_updated interval_seconds=%d", interval_seconds)


def _recalc_wordlist_schedule() -> None:
    """Recompute the wordlist auto-sync interval from all remaining active
    Continuous Sync jobs and call _sync_wordlist_schedule accordingly.
    Uses the shortest (most frequent) interval so the wordlist is never stale."""
    active = [
        j for j in _load_jobs()
        if j.get("type") == "asm_scan"
        and j.get("enabled", True)
        and j.get("schedule", {}).get("type") == "interval"
        and j.get("id") != _WORDLIST_AUTOSYNC_ID
    ]
    if active:
        min_sec = min(int(j["schedule"].get("seconds", 3600)) for j in active)
        _sync_wordlist_schedule(min_sec)
    else:
        _sync_wordlist_schedule(None)


# ── Scheduler init (called once per worker; only one acquires lock) ────────────

def _run_command(command: str, log_path: str):
    """APScheduler job callback — run a shell command, append output to log_path."""
    if not command:
        log.warning("scheduler: command job has no command set — skipping")
        return
    log.info("scheduler_command_start: %s", command)
    try:
        from blueprints.audit.routes import record_event as _audit
        _audit("scheduler_job_start", email="scheduler", resource=command[:120],
               detail="Scheduled command started")
    except Exception:
        pass
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as lf:
            lf.write(f"\n[{datetime.now(timezone.utc).isoformat()}] scheduler run: {command}\n")
            result = subprocess.run(
                command, shell=True, stdout=lf, stderr=lf, timeout=3600,
            )
        log.info("scheduler_command_done: %s rc=%d", command, result.returncode)
        try:
            from blueprints.audit.routes import record_event as _audit
            _audit("scheduler_job_success" if result.returncode == 0 else "scheduler_job_failed",
                   email="scheduler", resource=command[:120],
                   result="success" if result.returncode == 0 else "failure",
                   detail=f"exit code {result.returncode}")
        except Exception:
            pass
    except Exception as e:
        log.error("scheduler_command_error: %s err=%s", command, e)
        try:
            from blueprints.audit.routes import record_event as _audit
            _audit("scheduler_job_failed", email="scheduler", resource=command[:120],
                   result="error", detail=str(e))
        except Exception:
            pass


def _run_asm_scan(domain: str, scan_type: str, include_subdomains: bool, actor_uid: str):
    """APScheduler job callback — mirrors ASM blueprint trigger logic."""
    from core.config import SCANS_DIR, ASM_LOGS, ASM_DIR
    user_dir = SCANS_DIR / actor_uid
    user_dir.mkdir(parents=True, exist_ok=True)
    ASM_LOGS.mkdir(parents=True, exist_ok=True)
    scan_script = ASM_DIR / "cycentra_scan.py"
    if not scan_script.exists():
        log.error("scheduler_scan_failed: scan script not found at %s", scan_script)
        return
    env = os.environ.copy()
    env["CYCENTRA_OUTPUT_DIR"]         = str(user_dir)
    env["CYCENTRA_USER_ID"]            = actor_uid
    env["CYCENTRA_INCLUDE_SUBDOMAINS"] = "true" if include_subdomains else "false"
    try:
        subprocess.Popen(
            [str(Path(sys.executable)), str(scan_script), domain, actor_uid, scan_type],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        log.info("scheduler_scan_triggered domain=%s type=%s", domain, scan_type)
        try:
            from blueprints.audit.routes import record_event as _audit
            _audit("scan_triggered", email=actor_uid, resource=domain,
                   detail=f"Scheduled {scan_type} scan started",
                   metadata={"scan_type": scan_type, "scheduled": True})
        except Exception:
            pass
    except Exception as e:
        log.error("scheduler_scan_launch_error: %s", e)
        try:
            from blueprints.audit.routes import record_event as _audit
            _audit("scan_failed", email=actor_uid, resource=domain,
                   result="error", detail=str(e), metadata={"scheduled": True})
        except Exception:
            pass


def _add_to_apscheduler(sched, job: dict) -> None:
    """Register one job dict into a running APScheduler instance."""
    from apscheduler.triggers.cron     import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger

    jtype  = job.get("type", "asm_scan")
    params = job.get("params", {})
    sched_cfg = job.get("schedule", {})
    stype  = sched_cfg.get("type", "cron")

    if jtype == "asm_scan":
        fn        = _run_asm_scan
        fn_kwargs = {
            "domain":             params.get("domain", ""),
            "scan_type":          params.get("scan_type", "standard"),
            "include_subdomains": bool(params.get("include_subdomains", True)),
            "actor_uid":          params.get("actor_uid", "scheduler"),
        }
    elif jtype == "integration_health":
        from blueprints.integrations.health import run_all_checks as _run_health
        fn        = _run_health
        fn_kwargs = {}
    elif jtype in ("docker_maintenance", "backup", "asm_wordlist"):
        command  = params.get("command") or ""
        log_path = params.get("log", f"/opt/cycentra/{jtype}.log")
        if not command:
            if jtype == "asm_wordlist":
                # Built-in Python wordlist updater — no shell script needed
                from core.config import ASM_DIR
                wl_script = ASM_DIR / "modules" / "Utils" / "update_wordlist.py"
                command = f"{sys.executable} {wl_script}"
            else:
                log.warning("scheduler: job '%s' type='%s' has no command — skipping", job.get("id"), jtype)
                return
        fn        = _run_command
        fn_kwargs = {"command": command, "log_path": log_path}
    else:
        log.warning("scheduler: unknown job type '%s' — skipping", jtype)
        return

    try:
        if stype == "interval":
            trigger = IntervalTrigger(seconds=int(sched_cfg.get("seconds", 3600)))
        else:
            trigger = CronTrigger(
                minute=sched_cfg.get("minute", "0"),
                hour=sched_cfg.get("hour", "0"),
                day=sched_cfg.get("day", "*"),
                month=sched_cfg.get("month", "*"),
                day_of_week=sched_cfg.get("day_of_week", "*"),
            )
        sched.add_job(
            fn,
            trigger=trigger,
            id=job["id"],
            name=job.get("name", job["id"]),
            kwargs=fn_kwargs,
            replace_existing=True,
            misfire_grace_time=600,
        )
    except Exception as e:
        log.error("scheduler: failed to register job %s: %s", job.get("id"), e)


def _register_itam_phase3_jobs(sched) -> None:
    """Register all ITAM Phase 3 background maintenance jobs."""
    from apscheduler.triggers.cron     import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    from core.config import (CYCENTRA_DB_URL, NVD_API_KEY,
                             ITAM_DEEP_SCAN_INTERVAL_DAYS, ITAM_CVE_REFRESH_INTERVAL_DAYS,
                             AWS_ACCESS_KEY_ID, AWS_REGIONS, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
                             AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID,
                             ITAM_SNMP_COMMUNITY, ITAM_SNMP_PORT)

    def _nvd_incremental():
        import psycopg2, psycopg2.extras
        try:
            from blueprints.itam.nvd_mirror import sync_nvd_incremental, ensure_nvd_tables
            c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            ensure_nvd_tables(c)
            n = sync_nvd_incremental(c, NVD_API_KEY)
            log.info("[NVD-SCHED] incremental: %d CVEs upserted", n)
            c.close()
        except Exception as e:
            log.warning("[NVD-SCHED] incremental error: %s", e)

    def _nvd_full():
        import psycopg2, psycopg2.extras
        try:
            from blueprints.itam.nvd_mirror import sync_nvd_full, ensure_nvd_tables
            c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            ensure_nvd_tables(c)
            n = sync_nvd_full(c, NVD_API_KEY, start_year=2020)
            log.info("[NVD-SCHED] full sync: %d CVEs upserted", n)
            c.close()
        except Exception as e:
            log.warning("[NVD-SCHED] full sync error: %s", e)

    def _kev_sync():
        import psycopg2, psycopg2.extras
        try:
            from blueprints.itam.exploit_intel import sync_kev_catalog, ensure_exploit_tables
            c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            ensure_exploit_tables(c)
            n = sync_kev_catalog(c)
            log.info("[KEV-SCHED] synced %d entries", n)
            c.close()
        except Exception as e:
            log.warning("[KEV-SCHED] sync error: %s", e)

    def _cve_refresh():
        """Re-enrich assets where CVE data is stale (cve_count=0 and last_scanned > N days)."""
        import psycopg2, psycopg2.extras
        try:
            from blueprints.itam.software_inventory import enrich_asset_cves
            c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            with c.cursor() as cur:
                cur.execute("""
                    SELECT DISTINCT asset_id FROM software_inventory
                    WHERE cve_count = 0
                      AND last_scanned < NOW() - INTERVAL '1 day'
                    LIMIT 20
                """)
                asset_ids = [r["asset_id"] for r in cur.fetchall()]
            for aid in asset_ids:
                try:
                    enrich_asset_cves(c, aid, NVD_API_KEY)
                except Exception:
                    pass
            log.info("[CVE-SCHED] refreshed %d assets", len(asset_ids))
            c.close()
        except Exception as e:
            log.warning("[CVE-SCHED] refresh error: %s", e)

    def _cloud_sync():
        import psycopg2, psycopg2.extras
        try:
            c = psycopg2.connect(CYCENTRA_DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
            if AWS_ACCESS_KEY_ID and AWS_REGIONS:
                from blueprints.itam.cloud_discovery import sync_aws_assets
                r = sync_aws_assets(c, AWS_REGIONS, AWS_ACCESS_KEY_ID,
                                    AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
                log.info("[CLOUD-SCHED] AWS: %s", r)
            if AZURE_SUBSCRIPTION_ID:
                from blueprints.itam.cloud_discovery import sync_azure_assets
                r = sync_azure_assets(c, AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID,
                                      AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
                log.info("[CLOUD-SCHED] Azure: %s", r)
            c.close()
        except Exception as e:
            log.warning("[CLOUD-SCHED] sync error: %s", e)

    try:
        # NVD incremental — daily at 03:00 UTC
        sched.add_job(_nvd_incremental, CronTrigger(hour=3, minute=0),
                      id="itam_nvd_incremental", name="NVD CVE Incremental Sync",
                      replace_existing=True, misfire_grace_time=3600)

        # NVD full — weekly on Sunday at 01:00 UTC
        sched.add_job(_nvd_full, CronTrigger(day_of_week="sun", hour=1, minute=0),
                      id="itam_nvd_full_sync", name="NVD CVE Full Sync (Weekly)",
                      replace_existing=True, misfire_grace_time=7200)

        # CISA KEV — daily at 01:30 UTC
        sched.add_job(_kev_sync, CronTrigger(hour=1, minute=30),
                      id="itam_kev_sync", name="CISA KEV Catalog Sync",
                      replace_existing=True, misfire_grace_time=1800)

        # CVE re-enrichment — nightly at 02:00 UTC
        sched.add_job(_cve_refresh, CronTrigger(hour=2, minute=0),
                      id="itam_cve_refresh", name="ITAM CVE Re-Enrichment",
                      replace_existing=True, misfire_grace_time=3600)

        # Cloud sync — every 4 hours (only if cloud credentials configured)
        if AWS_ACCESS_KEY_ID or AZURE_SUBSCRIPTION_ID:
            sched.add_job(_cloud_sync, IntervalTrigger(hours=4),
                          id="itam_cloud_sync", name="Cloud Asset Discovery Sync",
                          replace_existing=True, misfire_grace_time=600)
            log.info("scheduler: ITAM cloud sync registered (every 4h)")

        # IEEE OUI vendor DB refresh — re-reads installed CSV file weekly on Sunday 03:30 UTC
        def _oui_refresh_job():
            try:
                from blueprints.itam.iot_classifier import reload_oui_db, _OUI_CSV_CANDIDATES
                for csv_path in _OUI_CSV_CANDIDATES:
                    if csv_path.exists():
                        count = reload_oui_db(csv_path.read_text(encoding="utf-8", errors="replace"))
                        log.info("scheduler: OUI DB reloaded — %d entries from %s", count, csv_path)
                        return
                log.warning("scheduler: OUI CSV not found — skipping reload")
            except Exception as exc:
                log.error("scheduler: OUI DB reload failed: %s", exc)

        sched.add_job(_oui_refresh_job, CronTrigger(day_of_week="sun", hour=3, minute=30),
                      id="itam_oui_refresh", name="IEEE OUI Vendor DB Refresh (Weekly)",
                      replace_existing=True, misfire_grace_time=3600)

        log.info("scheduler: ITAM Phase 3 jobs registered (NVD/KEV/CVE/Cloud/OUI)")
    except Exception as e:
        log.warning("scheduler: ITAM Phase 3 job registration failed: %s", e)


def init_scheduler(app) -> None:
    """Called from app factory. Tries to acquire the lock and start scheduler."""
    global _scheduler, _scheduler_owner
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        log.warning("APScheduler not installed — scheduled jobs disabled. "
                    "Run: pip install APScheduler>=3.10.0")
        return

    # Only one gunicorn worker runs the scheduler (first to get the lock wins).
    try:
        lock_fh = open(_LOCK_PATH, "w")
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _scheduler_owner = True
        log.info("scheduler: this worker acquired the scheduler lock")
    except (IOError, OSError):
        log.info("scheduler: another worker owns the lock — skipping scheduler init")
        return

    _scheduler = BackgroundScheduler(
        job_defaults={"coalesce": True, "max_instances": 1},
        timezone="UTC",
    )

    # Load persisted jobs
    for job in _load_jobs():
        if job.get("enabled", True):
            _add_to_apscheduler(_scheduler, job)

    # ── Benchmark bands auto-update (monthly, opt-in) ─────────────────────────
    # Reads BENCHMARK_AUTO_UPDATE from env — set in /opt/cycentra/.env.
    # Fires on the 1st of each month at 03:00 UTC.
    # Safe no-op when _AUTO_UPDATE is False or the import fails.
    try:
        from blueprints.benchmark.routes import register_benchmark_scheduler, _AUTO_UPDATE
        if _AUTO_UPDATE:
            register_benchmark_scheduler(_scheduler)
    except Exception as _bench_exc:
        log.warning("scheduler: benchmark job registration failed: %s", _bench_exc)

    try:
        from cy_comp.services.siem_bridge import register_compliance_scheduler
        register_compliance_scheduler(_scheduler)
    except Exception as _comp_exc:
        log.warning("scheduler: compliance enrichment job registration failed: %s", _comp_exc)

    try:
        from cy_comp.services.itam_bridge import register_itam_scheduler
        register_itam_scheduler(_scheduler)
    except Exception as _itam_exc:
        log.warning("scheduler: ITAM compliance sync job registration failed: %s", _itam_exc)

    try:
        from blueprints.itam.routes import _start_dns_monitor_if_enabled
        _start_dns_monitor_if_enabled()
    except Exception as _dns_exc:
        log.warning("scheduler: ITAM DNS monitor startup failed: %s", _dns_exc)

    # ── ITAM Phase 3 background jobs ──────────────────────────────────────────
    _register_itam_phase3_jobs(_scheduler)

    # ── mDNS passive discovery (startup, if enabled) ──────────────────────────
    try:
        from core.config import ITAM_MDNS_ENABLED
        if ITAM_MDNS_ENABLED:
            from blueprints.itam.mdns_discovery import start_mdns_discovery
            start_mdns_discovery()
            log.info("scheduler: mDNS passive discovery started")
    except Exception as _mdns_exc:
        log.warning("scheduler: mDNS discovery startup failed: %s", _mdns_exc)

    # ── SIEM connector polling (CyDataLake multi-vendor connectors) ───────────
    try:
        from blueprints.connectors.routes import register_connector_scheduler
        register_connector_scheduler(_scheduler)
    except Exception as _conn_exc:
        log.warning("scheduler: SIEM connector poll dispatcher registration failed: %s", _conn_exc)

    # ── Detection rule corpus refresh (Sigma + YARA, weekly) ──────────────────
    try:
        from cysiemstack.detection.rule_corpus_refresh import register_rule_corpus_scheduler
        register_rule_corpus_scheduler(_scheduler)
    except Exception as _rules_exc:
        log.warning("scheduler: rule corpus refresh job registration failed: %s", _rules_exc)

    # ── Integration health monitor (always on, interval from env/config) ───────
    try:
        from blueprints.integrations.health import run_all_checks as _health_check
        from apscheduler.triggers.interval import IntervalTrigger as _IT
        _health_interval = int(os.environ.get("INTEGRATION_HEALTH_INTERVAL", "300"))
        _scheduler.add_job(
            _health_check,
            trigger=_IT(seconds=_health_interval),
            id="integration_health_monitor",
            name="Integration Health Monitor",
            replace_existing=True,
            misfire_grace_time=120,
        )
        log.info("scheduler: integration health monitor registered (every %ds)", _health_interval)
    except Exception as _health_exc:
        log.warning("scheduler: integration health monitor registration failed: %s", _health_exc)

    _scheduler.start()
    log.info("scheduler: started with %d jobs", len(_scheduler.get_jobs()))

    # Ensure clean shutdown when Flask exits
    import atexit
    atexit.register(_scheduler.shutdown)


# ── RBAC helpers ──────────────────────────────────────────────────────────────

def _require_auth():
    if not session.get("user_email"):
        return jsonify({"error": "Authentication required"}), 401
    return None


def _require_analyst():
    err = _require_auth()
    if err:
        return err
    from blueprints.rbac.manager import get_user_role
    if get_user_role(session["user_email"]) not in ("admin", "analyst"):
        return jsonify({"error": "Analyst or admin role required"}), 403
    return None


# ── Routes ────────────────────────────────────────────────────────────────────

@scheduler_bp.route("/api/scheduler/jobs", methods=["OPTIONS"])
def scheduler_jobs_options():
    return add_cors_headers(make_response('', 204))


@scheduler_bp.route("/api/scheduler/jobs/<job_id>", methods=["OPTIONS"])
def scheduler_job_options(job_id):
    return add_cors_headers(make_response('', 204))


@scheduler_bp.route("/api/scheduler/jobs", methods=["GET"])
def scheduler_jobs_list():
    err = _require_auth()
    if err:
        return err

    jobs = _load_jobs()

    # Augment with APScheduler next-run info when available
    if _scheduler and _scheduler_owner:
        sched_map = {j.id: j for j in _scheduler.get_jobs()}
        for job in jobs:
            sj = sched_map.get(job["id"])
            job["next_run"] = sj.next_run_time.isoformat() if sj and sj.next_run_time else None

    return jsonify({"jobs": jobs, "count": len(jobs)})


@scheduler_bp.route("/api/scheduler/jobs", methods=["POST"])
def scheduler_jobs_create():
    err = _require_analyst()
    if err:
        return err

    data = request.get_json() or {}

    # Required fields
    job_type  = data.get("type", "asm_scan")
    params    = data.get("params", {})
    schedule  = data.get("schedule", {})
    name      = data.get("name", "").strip() or f"{job_type} — {params.get('domain','?')}"

    # Validate type
    if job_type != "asm_scan":
        return jsonify({"error": f"Unknown job type '{job_type}'. Only 'asm_scan' is supported."}), 400

    # Validate domain
    domain = params.get("domain", "").strip()
    if not domain or "." not in domain:
        return jsonify({"error": "Invalid or missing domain in params"}), 400

    # Validate scan_type
    scan_type = params.get("scan_type", "standard").lower()
    if scan_type not in ("standard", "deep", "passive"):
        return jsonify({"error": "scan_type must be standard, deep, or passive"}), 400

    # Validate schedule
    stype = schedule.get("type", "cron")
    if stype == "interval":
        seconds = int(schedule.get("seconds", 0))
        if seconds < 300:
            return jsonify({"error": "Interval must be at least 300 seconds (5 minutes)"}), 400
    elif stype == "cron":
        # Basic sanity — just check required hour/minute present
        pass
    else:
        return jsonify({"error": "schedule.type must be 'cron' or 'interval'"}), 400

    actor_email = session["user_email"]
    # Scheduled jobs always write to the shared 'scheduler' directory so results
    # are visible to all authenticated users on the dashboard, regardless of which
    # user created the job.  'created_by' still records the originating user.
    actor_uid   = "scheduler"

    job = {
        "id":          str(uuid.uuid4()),
        "name":        name,
        "type":        job_type,
        "params":      {
            "domain":             domain,
            "scan_type":          scan_type,
            "include_subdomains": bool(params.get("include_subdomains", True)),
            "actor_uid":          actor_uid,
        },
        "schedule":    schedule,
        "created_by":  actor_email,
        "created_at":  datetime.now(timezone.utc).isoformat(),
        "enabled":     True,
        "last_run":    None,
        "next_run":    None,
    }

    _upsert_job(job)

    # Register in running scheduler if this worker owns it
    if _scheduler and _scheduler_owner:
        _add_to_apscheduler(_scheduler, job)
        sj = _scheduler.get_job(job["id"])
        job["next_run"] = sj.next_run_time.isoformat() if sj and sj.next_run_time else None

    # Auto-sync the wordlist refresh to the same interval as Continuous Sync
    if stype == "interval":
        _sync_wordlist_schedule(int(schedule.get("seconds", 3600)))

    log.info("scheduler_job_created id=%s name=%s by=%s", job["id"], job["name"], actor_email)
    return jsonify(job), 201


@scheduler_bp.route("/api/scheduler/jobs/<job_id>", methods=["DELETE"])
def scheduler_jobs_delete(job_id):
    err = _require_analyst()
    if err:
        return err

    # Load job before removal so we can inspect its type/schedule
    all_jobs  = _load_jobs()
    dying_job = next((j for j in all_jobs if j.get("id") == job_id), None)

    removed = _remove_job_from_store(job_id)
    if not removed:
        return jsonify({"error": "Job not found"}), 404

    if _scheduler and _scheduler_owner:
        try:
            _scheduler.remove_job(job_id)
        except Exception:
            pass

    # If a Continuous Sync (asm_scan interval) job was deleted, recalculate
    # the wordlist auto-sync — use shortest remaining interval or remove it.
    if dying_job and dying_job.get("type") == "asm_scan" \
            and dying_job.get("schedule", {}).get("type") == "interval":
        _recalc_wordlist_schedule()

    log.info("scheduler_job_deleted id=%s by=%s", job_id, session.get("user_email"))
    return jsonify({"deleted": job_id})


@scheduler_bp.route("/api/scheduler/jobs/<job_id>", methods=["PATCH"])
def scheduler_jobs_patch(job_id):
    err = _require_analyst()
    if err:
        return err

    data = request.get_json() or {}
    jobs = _load_jobs()
    job  = next((j for j in jobs if j.get("id") == job_id), None)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    if "enabled" in data:
        job["enabled"] = bool(data["enabled"])
        _save_jobs(jobs)

        if _scheduler and _scheduler_owner:
            if job["enabled"]:
                _add_to_apscheduler(_scheduler, job)
            else:
                try:
                    _scheduler.remove_job(job_id)
                except Exception:
                    pass

        # Recalculate wordlist auto-sync when a Continuous Sync job is toggled
        if job.get("type") == "asm_scan" \
                and job.get("schedule", {}).get("type") == "interval":
            _recalc_wordlist_schedule()

    return jsonify(job)


# ── Internal callable from agentic action executor ────────────────────────────

def add_job_internal(params: dict, actor_email: str) -> dict:
    """
    Called by system/routes.py _execute_agentic_action when a user confirms
    an 'add_schedule' action via the CyMind chat overlay.
    Returns {success, message, data}.
    """
    domain         = params.get("domain", "").strip()
    scan_type      = params.get("scan_type", "standard").lower()
    schedule       = params.get("schedule", {"type": "cron", "hour": "2", "minute": "0"})
    name           = params.get("name", f"Scheduled scan — {domain}")
    # Always write to the shared scheduler directory — same as scheduler_jobs_create()
    actor_uid      = "scheduler"

    if not domain or "." not in domain:
        return {"success": False, "message": "Invalid domain"}

    if scan_type not in ("standard", "deep", "passive"):
        scan_type = "standard"

    job = {
        "id":         str(uuid.uuid4()),
        "name":       name,
        "type":       "asm_scan",
        "params":     {
            "domain":             domain,
            "scan_type":          scan_type,
            "include_subdomains": bool(params.get("include_subdomains", True)),
            "actor_uid":          actor_uid,
        },
        "schedule":   schedule,
        "created_by": actor_email,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "enabled":    True,
        "last_run":   None,
        "next_run":   None,
    }

    _upsert_job(job)

    if _scheduler and _scheduler_owner:
        _add_to_apscheduler(_scheduler, job)
        sj = _scheduler.get_job(job["id"])
        job["next_run"] = sj.next_run_time.isoformat() if sj and sj.next_run_time else None

    sched_desc = _describe_schedule(schedule)
    return {
        "success": True,
        "message": f"Scheduled {scan_type} scan of {domain} — {sched_desc}",
        "data":    job,
    }


def _describe_schedule(schedule: dict) -> str:
    """Return a human-readable schedule description."""
    if schedule.get("type") == "interval":
        s = int(schedule.get("seconds", 3600))
        if s >= 86400:
            return f"every {s // 86400} day(s)"
        if s >= 3600:
            return f"every {s // 3600} hour(s)"
        return f"every {s // 60} minute(s)"
    # cron
    hour   = schedule.get("hour", "0")
    minute = schedule.get("minute", "0")
    dow    = schedule.get("day_of_week", "*")
    if dow != "*":
        _DAYS = {"0": "Sun","1": "Mon","2": "Tue","3": "Wed","4": "Thu","5": "Fri","6": "Sat",
                 "mon":"Mon","tue":"Tue","wed":"Wed","thu":"Thu","fri":"Fri","sat":"Sat","sun":"Sun"}
        day_str = ",".join(_DAYS.get(d.strip(), d.strip()) for d in dow.split(","))
        return f"every {day_str} at {hour.zfill(2)}:{minute.zfill(2)} UTC"
    return f"daily at {str(hour).zfill(2)}:{str(minute).zfill(2)} UTC"
