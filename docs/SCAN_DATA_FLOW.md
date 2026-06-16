# ASM Scan Data Flow — CyCentra 360

**Last updated:** v1.0.418  
**Covers:** scan storage layout, user/guest mapping, scheduled scans, dashboard visibility, benchmark scoring

---

## 1. Directory Layout

```
/var/log/cycentra/
├── cy-asm/                          ← INTERNAL TREE (authenticated users only)
│   ├── scans/
│   │   ├── <user_uid>/              ← per-user manual scans
│   │   │   └── scan_<domain>_<unix_ts>.json
│   │   ├── scheduler/               ← shared scheduled/automated scans (all users see these)
│   │   │   └── scan_<domain>_<unix_ts>.json
│   │   └── local_cyadmin@cycentra.com/   ← example: manual scans by local admin
│   ├── reports/
│   │   ├── <user_uid>/              ← per-user PDF reports
│   │   └── scheduler/               ← shared PDF reports from scheduled jobs
│   └── logs/
│       └── cycentra_engine.log      ← live progress log (overwritten on each scan trigger)
│
└── cy-asm-guest/                    ← GUEST TREE (completely separate, no authenticated endpoint touches this)
    ├── scans/                       ← guest scan results
    └── reports/                     ← guest PDF reports
```

**Config constants** (`backend/core/config.py`):

| Constant | Path |
|---|---|
| `SCANS_DIR` | `/var/log/cycentra/cy-asm/scans` |
| `ASM_REPORTS_DIR` | `/var/log/cycentra/cy-asm/reports` |
| `ASM_LOGS` | `/var/log/cycentra/cy-asm/logs` |
| `GUEST_SCANS_DIR` | `/var/log/cycentra/cy-asm-guest/scans` |
| `GUEST_REPORTS_DIR` | `/var/log/cycentra/cy-asm-guest/reports` |

---

## 2. User UID Mapping

The `uid` passed to the scan engine determines which directory results are written into.

### Manual scans (portal UI — `POST /api/scan/trigger`)

The portal sends the session's `user_uid` (OAuth provider UID) as the `uid` field. For local/password users it falls back to the email.

| Login method | Example uid sent | Scan directory |
|---|---|---|
| Google OAuth | `google_abc123` | `SCANS_DIR/google_abc123/` |
| Local/password login | `local_admin@cycentra.com` | `SCANS_DIR/local_admin@cycentra.com/` |
| Guest (public free scan page) | `guest_<random>` | `GUEST_SCANS_DIR/` |

> **UID is NOT stored inside the JSON file itself.** It is only encoded in the directory path. The scan file contains `scan_id`, `domain`, `scan_type`, `last_scan`, `posture_score`, `posture_grade`, and all module findings — but no `uid` field in `meta`.

### Scheduled scans (Continuous Sync — `POST /api/scheduler/jobs`)

Regardless of which authenticated user creates the job, the scheduler always uses `actor_uid = "scheduler"`.

- Results save to `SCANS_DIR/scheduler/`
- `created_by` field in `schedules.json` still records the email of the user who created the job (for audit purposes)
- All authenticated dashboard users see `scheduler/` scan results in their history list

**Why:** Before v1.0.417, `actor_uid` was derived from the creator's email (e.g. `cyadmin_cycentra_com`). Results went to that user's private folder and were invisible to everyone else on the dashboard. Fixed in v1.0.417.

### Agentic-chat-created jobs (`add_job_internal`)

The internal API path (used when CyCentra's AI assistant creates a schedule) also defaults to `actor_uid = "scheduler"`. Same behaviour as portal-UI-created jobs.

---

## 3. Scan File Format

Every completed scan writes one JSON file:

```
scan_<domain>_<unix_timestamp>.json
```

Example: `scan_cycentra.com_1778652590.json`

**Top-level keys:**

| Key | Description |
|---|---|
| `meta.scan_id` | Deterministic ID, e.g. `ASM-1778652590` |
| `meta.domain` | Target domain |
| `meta.scan_type` | `standard`, `deep`, or `passive` |
| `meta.last_scan` | ISO 8601 timestamp of scan completion |
| `meta.posture_score` | Integer 0–100 |
| `meta.posture_grade` | Letter grade: A+ / A / B / C / D / F |
| `assets[]` | Array of discovered assets with findings |
| `subdomain_summary.total` | Count of discovered subdomains |

---

## 4. Guest Isolation (v1.0.418)

Guest scans are **structurally isolated** — not just filtered by name.

**Before v1.0.418:** Guest results were stored at `SCANS_DIR/guest/` (a subdirectory inside the internal tree). The authenticated dashboard's wildcard glob `SCANS_DIR/**/scan_*.json` could return a guest scan as "latest" if it happened to be the newest file.

**After v1.0.418:**
- Guest writes to `GUEST_SCANS_DIR` (`/var/log/cycentra/cy-asm-guest/scans`) — a completely different path, not a subdirectory of `SCANS_DIR`
- Every authenticated endpoint (`list_scans`, `get_latest_scan`, `get_scan_by_id`, `list_pdf_reports`, `download_pdf_report`, `_latest_asm_scan_file`) operates on `SCANS_DIR` only — it is physically impossible for the glob to reach `GUEST_SCANS_DIR`
- The old `entry.name != "guest"` name-filter was removed from the benchmark because it is no longer needed

**How guest detection works:**  
Any `uid` beginning with `guest_` is routed to the guest tree. The scan trigger sets `CYCENTRA_IS_GUEST=true` in the subprocess environment.

> **Caveat — direct invocation fallback:** When `cycentra_scan.py` is invoked directly (bypassing the `scanner.py` API) and `CYCENTRA_OUTPUT_DIR` is not set, the guest scan falls back to `/var/log/cycentra/cy-asm/scans/guest` — a subdirectory of the internal `SCANS_DIR` tree rather than `GUEST_SCANS_DIR`. This only matters for tooling that shells out to `cycentra_scan.py` directly; all API-driven scans go through `scanner.py` which always passes `CYCENTRA_OUTPUT_DIR` explicitly. See `cycentra_scan.py` lines 1166–1172.

---

## 5. Dashboard Visibility Rules

### `GET /api/scans/list` (scan history panel)

| Caller | Directories searched |
|---|---|
| Authenticated user, uid provided | `SCANS_DIR/<uid>/` + `SCANS_DIR/scheduler/` |
| Authenticated user, no uid | `SCANS_DIR/<session_email>/` + `SCANS_DIR/scheduler/` |
| Unauthenticated (no session, no uid) | Returns `[]` (empty) |
| Guest uid (`guest_*`) | `GUEST_SCANS_DIR/` only — never shown on internal dashboard |

Returns last 15 files sorted by modification time. Never cross-user (each user sees only their own scans + the shared scheduler scans).

### `GET /api/scans/latest?uid=<uid>`

| `uid` parameter | Directory searched |
|---|---|
| `guest_*` | `GUEST_SCANS_DIR/scan_*.json` |
| Specific authenticated uid | `SCANS_DIR/<uid>/scan_*.json` |
| Not provided | `SCANS_DIR/**/scan_*.json` (all internal users + scheduler, newest overall) |

> The no-uid wildcard is called by the authenticated dashboard to show the "most recent scan across the platform" — it stays within `SCANS_DIR` and cannot reach `GUEST_SCANS_DIR`.

### `GET /api/scans/<scan_id>` (fetch a specific scan)

Scoped to `SCANS_DIR/<uid>/` + `SCANS_DIR/scheduler/`. Cross-user lookup is not possible unless the requesting user owns the file or the scan is in `scheduler/`.

---

## 6. Benchmark Scoring

Benchmark scores are **platform-wide** — they are NOT scoped to the requesting user.

**Function:** `_latest_asm_scan_file()` in `backend/blueprints/benchmark/routes.py`

**Logic:**
```python
for entry in SCANS_DIR.iterdir():       # walks internal tree only
    if entry.is_dir():
        all_files.extend(glob.glob(str(entry / "scan_*.json")))
# Returns the file with the highest mtime across all dirs
```

- Iterates **every subdirectory** in `SCANS_DIR` (user dirs + `scheduler/`)
- Returns the single newest `scan_*.json` regardless of which user or job produced it
- `GUEST_SCANS_DIR` is a sibling path — structurally unreachable from this loop

**Design intent:** The benchmark posture score represents the platform's current external attack surface, not an individual user's view. The newest completed scan — whether triggered manually or by the scheduler — is always used as the source of truth.

---

## 7. Scheduled Scan Lifecycle (Continuous Sync)

The Continuous Sync job is managed by **APScheduler 3.x** running in-process inside the Flask app. It is **not** a cron job and will **not** appear in `crontab -l`.

### Verification commands

```bash
# Check if the scheduled scan has run — new files appear here
ls -lat /var/log/cycentra/cy-asm/scans/scheduler/

# View the live engine log (updated during each scan run)
cat /var/log/cycentra/cy-asm/logs/cycentra_engine.log

# Inspect the job store — confirm actor_uid and next_run
cat /opt/cycentra/schedules.json | python3 -m json.tool

# API: list all scheduled jobs
curl -s http://127.0.0.1:7070/api/scheduler/jobs | python3 -m json.tool
```

### Job store schema (`/opt/cycentra/schedules.json`)

```json
[
  {
    "id": "<uuid>",
    "name": "CTEM Continuous Sync — cycentra.com",
    "type": "asm_scan",
    "params": {
      "domain": "cycentra.com",
      "scan_type": "deep",
      "include_subdomains": true,
      "actor_uid": "scheduler"
    },
    "schedule": { "type": "interval", "seconds": 14400 },
    "created_by": "cyadmin@cycentra.com",
    "created_at": "2026-05-13T...",
    "enabled": true,
    "last_run": "...",
    "next_run": "..."
  }
]
```

### Lock mechanism

APScheduler acquires an exclusive `fcntl` lock on `/tmp/cycentra-scheduler.lock` before running jobs. Only one gunicorn worker ever executes jobs even when multiple workers are running. The lock is released after each job fires.

---

## 8. MaxMind GeoIP Refresh

The MaxMind database refresh is a **system cron job** — not an APScheduler job. It is therefore invisible to `crontab -l` (which only shows the root user crontab).

```bash
# Find it here:
cat /etc/cron.monthly/cycentra-geoip-refresh

# Verify the key is set:
grep MAXMIND /opt/cycentra/.env
```

Fires once per month (via `/etc/cron.monthly/`). Downloads the latest GeoLite2-City database to the location expected by the ASM scanner.

---

## 9. Change History

| Version | Change |
|---|---|
| v1.0.417 | Fixed: scheduled jobs now use `actor_uid = "scheduler"`. Before this, results saved to the job creator's private folder, invisible to other users. Live `schedules.json` and existing scan file migrated at deploy time. |
| v1.0.418 | Fixed: guest scans moved to completely separate `GUEST_SCANS_DIR` tree. Before this, a guest scan at `SCANS_DIR/guest/` could appear as "latest" on the authenticated dashboard. Benchmark `_latest_asm_scan_file()` name-filter removed (no longer needed — structural isolation is sufficient). |
