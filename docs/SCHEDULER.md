# CyCentra 360 — Scheduler Reference

## Overview

CyCentra 360 uses **two separate scheduling mechanisms** for different job categories.
These are completely independent — jobs from one system never appear in the other.

| System | Location | How to view |
|--------|----------|-------------|
| APScheduler (in-process) | `/opt/cycentra/schedules.json` | Portal → Scan Operations, or `GET /api/scheduler/jobs` |
| System cron | `/etc/cron.monthly/`, user crontab | `crontab -l` and `ls /etc/cron.monthly/` |

---

## System 1 — APScheduler (in-process)

### What it runs

| Job type | Description | Created via |
|----------|-------------|-------------|
| `asm_scan` | **Continuous Sync** — triggers `cycentra_scan.py` for a domain on a repeating interval or cron schedule | `POST /api/scheduler/jobs` or Portal → Scan Operations |
| `asm_wordlist` | Refreshes the ASM subdomain wordlist from threat-intel feeds | Auto-created alongside `asm_scan` jobs |
| `docker_maintenance` | Prunes stopped containers, unused images/volumes, build cache | `PUT /api/system/schedules` only (Portal → System → Scheduled Tasks) |
| `backup` | Snapshots configs, env files, license and DB to `/opt/cycentra/backups/` | `PUT /api/system/schedules` only (Portal → System → Scheduled Tasks) |

> **Note:** `POST /api/scheduler/jobs` accepts only `asm_scan` as the job type. `docker_maintenance` and `backup` jobs are managed exclusively through `PUT /api/system/schedules` (System routes), which writes them to the user crontab — not to the APScheduler in-process queue.

### How it works

- Runs inside the Flask process as a `BackgroundScheduler` (APScheduler 3.x).
- At startup (`init_scheduler` in `blueprints/scheduler/routes.py`) the process tries to acquire an **fcntl exclusive lock** at `/tmp/cycentra-scheduler.lock`. Only the first worker to acquire the lock runs the scheduler; all other gunicorn workers skip it silently.
- Jobs are persisted to `/opt/cycentra/schedules.json`. On each restart, all enabled jobs are reloaded from this file and re-registered with APScheduler.
- `_scheduler_owner = True` only in the worker that holds the lock.

### Job store — `/opt/cycentra/schedules.json`

```json
[
  {
    "id": "7bb875a3-...",
    "name": "CTEM Continuous Sync — cycentra.com",
    "type": "asm_scan",
    "params": {
      "domain": "cycentra.com",
      "scan_type": "deep",
      "include_subdomains": true,
      "actor_uid": "cyadmin_cycentra_com"
    },
    "schedule": { "type": "interval", "seconds": 14400 },
    "enabled": true,
    "last_run": null,
    "next_run": null
  }
]
```

Two schedule types are supported:
- `"type": "interval"` — fires every N `seconds` (e.g. `14400` = every 4 hours). Used for Continuous Sync.
- `"type": "cron"` — fires on a fixed schedule using `minute`, `hour`, `day`, `month`, `day_of_week` fields. Used for backup, docker maintenance.

### Wordlist Auto-Sync

When a Continuous Sync (`asm_scan` interval) job is created, a companion `asm_wordlist_autosync` job is automatically created with the same interval. When the Continuous Sync job is deleted or disabled, the auto-sync job is removed too. The auto-sync uses the **shortest** interval across all active Continuous Sync jobs.

### Managing jobs

**Via portal:** Scan Operations → Continuous Sync section.

**Via API:**
```bash
# List all jobs
curl -s http://127.0.0.1:5252/api/scheduler/jobs \
  -H "Cookie: <session>" | python3 -m json.tool

# Create a Continuous Sync job (interval — every 4 hours)
curl -s -X POST http://127.0.0.1:5252/api/scheduler/jobs \
  -H "Cookie: <session>" -H "Content-Type: application/json" \
  -d '{"name":"CTEM Sync","type":"asm_scan","params":{"domain":"example.com","scan_type":"deep","include_subdomains":true},"schedule":{"type":"interval","seconds":14400}}'

# Delete a job
curl -s -X DELETE http://127.0.0.1:5252/api/scheduler/jobs/<job_id> \
  -H "Cookie: <session>"

# Enable/disable a job
curl -s -X PATCH http://127.0.0.1:5252/api/scheduler/jobs/<job_id> \
  -H "Cookie: <session>" -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### Checking if APScheduler is running

```bash
# On the server
grep -i "scheduler" /opt/cycentra/flask.log | tail -20

# APScheduler version installed
pip3 show APScheduler

# Inspect the lock file (only exists while Flask is running)
ls -la /tmp/cycentra-scheduler.lock
```

### Gotchas

- **Jobs are NOT in `crontab -l`** — this is correct behaviour. APScheduler runs inside the Flask process, not through the OS cron daemon.
- **Lock is process-scoped** — if Flask restarts, the lock is re-acquired on startup and all enabled jobs from `schedules.json` are reloaded automatically.
- **`next_run` in `schedules.json` is a snapshot** — it shows the next run at the time the job was last created/updated. After Flask restarts, APScheduler recalculates and the real next_run is returned via the API (not persisted until the job fires).
- **Single-worker mode** — CyCentra 360 runs gunicorn with `-w 1` (one worker). The lock is still important as a safeguard against any future multi-worker deployments.

---

## System 2 — System Cron

### What it runs

| File | Schedule | Purpose |
|------|----------|---------|
| `/etc/cron.monthly/cycentra-geoip-refresh` | Monthly (crond) | Downloads updated `GeoLite2-City.mmdb` from MaxMind, restarts `cycentra-siem` |
| User crontab (`crontab -l`) | Configured per-server | `docker-maintenance.sh`, `run_backup.sh` — managed by `PUT /api/system/schedules` |

### MaxMind GeoIP refresh

Installed by `cycentra-setup.sh` when `MAXMIND_KEY` is present in `/opt/cycentra/.env`.
Location: `/etc/cron.monthly/cycentra-geoip-refresh`

The script:
1. Reads `MAXMIND_KEY` from `/opt/cycentra/.env`
2. Downloads the latest `GeoLite2-City.tar.gz` from MaxMind
3. Extracts to `/opt/cycentra/geoip/GeoLite2-City.mmdb`
4. Restarts `cycentra-siem` so the correlation engine reloads the DB

To verify it exists:
```bash
cat /etc/cron.monthly/cycentra-geoip-refresh
grep MAXMIND_KEY /opt/cycentra/.env
```

**Why it doesn't appear in `crontab -l`:** System cron directories (`/etc/cron.monthly/`, `/etc/cron.daily/`, etc.) are run by the OS cron daemon directly and are never listed in any user's personal crontab. `crontab -l` only shows user-crontab entries.

### Schedules managed via portal

The portal's **System → Scheduled Tasks** page (`PUT /api/system/schedules`) manages a separate set of tasks that ARE written to `crontab`. These use the `_apply_schedules()` function in `blueprints/system/routes.py` which:
1. Reads `crontab -l`
2. Strips all lines containing cycentra markers (`docker-maintenance.sh`, `update_wordlist`, `asm-scan-cron`, `cycentra-backup-cron`)
3. Rebuilds the affected entries from the schedule config in `/opt/cycentra/schedules.json` (the `_DEFAULT_SCHEDULES` schema)
4. Writes the new crontab back with `crontab -`

These DO appear in `crontab -l`.

---

## Which scheduler to check for a given job?

```
Job came from Scan Operations / Continuous Sync?
  └─ APScheduler — check /opt/cycentra/schedules.json or GET /api/scheduler/jobs

Job came from System → Scheduled Tasks in portal?
  └─ System cron — check crontab -l

MaxMind GeoIP refresh?
  └─ System cron — check /etc/cron.monthly/cycentra-geoip-refresh
```

---

## Known Issues Fixed

### v1.0.414 — CLOUD_IRIS_URL duplicate in `.env` (May 2026)

**Symptom:** `/opt/cycentra/.env` contained `CLOUD_IRIS_URL=http://127.0.0.1:4433` twice (lines 67 and 93).

**Root cause:** `blueprints/platform/routes.py` used append-if-missing logic for `CLOUD_IRIS_URL`. When CyIRIS was installed or the activation flow ran more than once, a second entry was appended.

**Fix applied (platform/routes.py):** Changed to strip-all-then-append-one using `re.sub()` — idempotent across any number of reinstalls.

**Fix applied (cycentra-setup.sh `--update`):** Added a dedup step in the `.env` patch section that detects and collapses multiple `CLOUD_IRIS_URL` entries down to one (keeping the last value).
