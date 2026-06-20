# Benchmark Cohort Opt-In — Data Flow & Implementation Status

## What the UI Shows

On the **Security Posture Benchmark** page (`/benchmark`), inside the **COHORT CONTEXT** panel, there is a toggle button with the following label:

> **Contribute to anonymised cohort pool**
> Share your anonymised CSPI snapshot (no identifiable data) to improve the industry benchmarks. Your score appears as one anonymous data point in the cohort.

---

## Current Implementation Status: Consent Capture Only

**No data is sent externally today.** The feature is a UI stub — it captures and persists the user's opt-in preference locally, but there is no outbound HTTP call, telemetry pipeline, or submission endpoint wired up in the current codebase.

---

## Complete Data Flow (as-built)

### 1. React Component — Toggle Rendered

**File:** `portal/src/pages/benchmark/BenchmarkPage.jsx`  
**Component:** `CohortSelector` (line 580)

The toggle is a `<button>` element (line 665) that flips local state `optIn` between `true` and `false`. It is visually styled in blue when active.

```jsx
// BenchmarkPage.jsx:583
const [optIn, setOptIn] = useState(config?.cohort_opt_in || false);
```

The toggle is pre-populated from the backend config on mount (line 588) and whenever the config object changes.

---

### 2. User Saves — Frontend PUT Request

When the user clicks **"Save Cohort Settings"** (line 693), the `CohortSelector` calls:

```jsx
// BenchmarkPage.jsx:694
onSave({ industry, size_band: sizeBand, cohort_opt_in: optIn }, { reloadScores: false })
```

`onSave` resolves to `handleSaveConfig` in the parent `BenchmarkPage` (line 1074), which issues:

```
PUT /api/benchmark/config
Content-Type: application/json

{ "industry": "...", "size_band": "...", "cohort_opt_in": true | false }
```

The `reloadScores: false` flag means the page does **not** re-run all score collectors (ASM, SIEM, MISP, Wazuh, etc.) after saving cohort settings. It only re-fetches `/api/benchmark/config` to sync displayed values.

---

### 3. Flask Route — Backend Receives PUT

**File:** `backend/blueprints/benchmark/routes.py`  
**Route:** `PUT /api/benchmark/config` (line 1591)

```python
# routes.py:1601
for key in ("industry", "size_band", "cohort_opt_in"):
    if key in body:
        config[key] = body[key]
_save_config(config)
```

The `cohort_opt_in` field is merged into the config dict alongside `industry` and `size_band`.

The route also determines whether to bust the CSPI score cache (line 1608):

```python
score_affecting = set(body.keys()) - {"industry", "size_band", "cohort_opt_in"}
```

`cohort_opt_in` is explicitly excluded from score-affecting keys — changing the toggle never triggers a score recompute.

---

### 4. Config Persisted to Disk

**File:** `backend/blueprints/benchmark/routes.py`  
**Function:** `_save_config()` (line 236)

```python
def _save_config(cfg: dict) -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    cfg["updated_at"] = datetime.now(timezone.utc).isoformat()
    _CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
```

The config is written to:

```
/opt/cycentra/benchmark_config.json
```

Path is controlled by env var `BENCHMARK_CONFIG` (defaults to the above).

The saved JSON will contain:

```json
{
  "cohort_opt_in": true,
  "industry": "finance",
  "size_band": "mid",
  "updated_at": "2026-06-20T10:00:00+00:00",
  "sources": { ... }
}
```

---

### 5. The Flag Is Never Read for Outbound Transmission

A codebase-wide search (`grep -rn "cohort_opt_in"`) confirms:

| File | Line | Purpose |
|------|------|---------|
| `blueprints/benchmark/routes.py` | 127 | Default config: `"cohort_opt_in": False` |
| `blueprints/benchmark/routes.py` | 1601 | Write: merge field into config on PUT |
| `blueprints/benchmark/routes.py` | 1608 | Exclude from score-cache invalidation logic |
| `BenchmarkPage.jsx` | 583, 588, 593, 694 | Read from config; control toggle state |

There is no code anywhere in the backend that:
- Reads `cohort_opt_in` from the saved config
- Sends any data to an external URL
- Queues a background job to submit CSPI data
- Calls a cohort pool API

---

## Full Implementation Specification (Future Work)

This section is a complete engineering specification. All file paths, env var names, function names, and hook points are chosen to match existing platform conventions exactly so future implementation requires minimal decision-making.

---

### Part 1 — Environment Variables

Add the following to `backend/core/config.py`, following the pattern of the existing `BENCHMARK_AUTO_UPDATE` var:

```python
# ── Benchmark cohort submission ────────────────────────────────────────────────
BENCHMARK_COHORT_URL    = os.environ.get(
    "BENCHMARK_COHORT_URL", ""
)  # e.g. https://cohort.cycentra.com/api/v1/submit
BENCHMARK_COHORT_SECRET = os.environ.get(
    "BENCHMARK_COHORT_SECRET", ""
)  # shared HMAC secret issued per-install at license activation
BENCHMARK_COHORT_ENABLED = (
    os.environ.get("BENCHMARK_COHORT_ENABLED", "false").lower() == "true"
)
```

Add to `/opt/cycentra/.env` (the Flask `EnvironmentFile`):

```ini
# Cohort contribution — set by CyCentra license activation script
BENCHMARK_COHORT_URL=https://cohort.cycentra.com/api/v1/submit
BENCHMARK_COHORT_SECRET=<per-install secret from license provisioning>
BENCHMARK_COHORT_ENABLED=false        # operator sets to true; user toggles in UI
```

`BENCHMARK_COHORT_ENABLED` is the **operator-level gate** (set during deployment).  
`cohort_opt_in` in `benchmark_config.json` is the **end-user consent gate**.  
Both must be `true` for any data to leave the machine.

---

### Part 2 — Anonymized Tenant Identifier

The submission must be linkable across days (so the cohort API can de-duplicate a tenant's submissions) but must not expose `BASE_DOMAIN` in plaintext.

Add this helper inside `blueprints/benchmark/routes.py`, below the existing `_config_hash()` function:

```python
def _tenant_token() -> str:
    """
    Stable, non-reversible per-install identifier for cohort submissions.

    Uses HMAC-SHA256 of BASE_DOMAIN with BENCHMARK_COHORT_SECRET as the key,
    then truncates to 16 hex chars.  The same input always produces the same
    token, but the token cannot be reversed to discover the domain.

    Falls back to a random UUID when the cohort secret is not set, which
    produces a token that is unique per process restart — acceptable for
    testing but breaks cross-day de-duplication.
    """
    import hmac, hashlib
    from core.config import BASE_DOMAIN
    secret = os.environ.get("BENCHMARK_COHORT_SECRET", "")
    if not secret:
        import uuid
        return str(uuid.uuid4()).replace("-", "")[:16]
    return hmac.new(
        secret.encode(), BASE_DOMAIN.encode(), hashlib.sha256
    ).hexdigest()[:16]
```

---

### Part 3 — Anonymized Payload Specification

The submission body sent to the cohort API must contain **only** these fields:

```json
{
  "token":      "a3f8c21d09e4b712",
  "cspi":       68,
  "grade":      "B",
  "industry":   "finance",
  "size_band":  "mid",
  "date":       "2026-06-20",
  "schema":     1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token` | string (16 hex) | HMAC-derived tenant token — stable, non-reversible |
| `cspi` | integer 0–100 | Composite score only |
| `grade` | string | Letter grade derived from CSPI |
| `industry` | string | Sector key from `_INDUSTRY_COHORTS_STATIC` |
| `size_band` | string | One of: micro / small / mid / large / enterprise |
| `date` | string (YYYY-MM-DD) | UTC date of the submission (one per day, deduplicated) |
| `schema` | integer | Payload version — increment when fields are added |

**Fields that must never appear in the payload:**
- `user_email`, `actor`, or any user identity
- `BASE_DOMAIN` in plaintext
- IP address or hostname
- Individual dimension scores (`asm`, `siem`, `compliance`, `vuln`, `threat_intel`)
- Sub-scores, findings counts, CVE counts, or MISP data
- The `sources` weight configuration
- The `breakdown` dict from `_compute_cspi()`

---

### Part 4 — Submission Function

Add to `blueprints/benchmark/routes.py`, after `_tenant_token()`:

```python
_COHORT_SUBMIT_LOCK = threading.Lock()
_last_cohort_submit: dict = {}   # {date_str: bool} — tracks today's submission


def _submit_cohort_snapshot(cspi: int, grade: str, config: dict) -> bool:
    """
    POST an anonymized CSPI snapshot to the cohort pool API.

    Called by the nightly APScheduler job and (optionally) by
    _append_history_snapshot() when a new day's score is recorded.

    Returns True on success, False on any failure.
    Logs at INFO on success, WARNING on failure — never raises.
    Both BENCHMARK_COHORT_ENABLED (operator gate) and config["cohort_opt_in"]
    (user consent) must be true for a submission to proceed.
    """
    from core.config import BENCHMARK_COHORT_URL, BENCHMARK_COHORT_ENABLED

    if not BENCHMARK_COHORT_ENABLED:
        return False
    if not config.get("cohort_opt_in"):
        return False
    if not BENCHMARK_COHORT_URL:
        log.warning("[benchmark/cohort] BENCHMARK_COHORT_URL not set — skipping submission")
        return False

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with _COHORT_SUBMIT_LOCK:
        if _last_cohort_submit.get(today):
            return True   # already submitted today
        payload = {
            "token":     _tenant_token(),
            "cspi":      int(cspi),
            "grade":     grade,
            "industry":  config.get("industry",  "general"),
            "size_band": config.get("size_band", "mid"),
            "date":      today,
            "schema":    1,
        }
        try:
            r = _req.post(
                BENCHMARK_COHORT_URL,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            if r.status_code in (200, 201, 204):
                _last_cohort_submit[today] = True
                log.info("[benchmark/cohort] Snapshot submitted: CSPI=%d grade=%s date=%s",
                         cspi, grade, today)
                return True
            log.warning("[benchmark/cohort] Submission rejected HTTP %d: %s",
                        r.status_code, r.text[:200])
            return False
        except Exception as exc:
            log.warning("[benchmark/cohort] Submission failed: %s", exc)
            return False
```

---

### Part 5 — Hook into `_append_history_snapshot()`

Modify the existing `_append_history_snapshot()` function (line 260 in `routes.py`) to trigger a submission immediately after recording a new day's score. This is the lowest-friction hook because it already fires once per day on the first `GET /score` call:

```python
def _append_history_snapshot(score: float) -> None:
    today   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entries = _load_history()
    if any(e.get("date") == today for e in entries):
        return   # already recorded today — no submission needed either
    entries.append({"date": today, "score": round(float(score), 1)})
    entries = sorted(entries, key=lambda e: e.get("date", ""))[-400:]
    try:
        _save_history(entries)
    except Exception as exc:
        log.warning("[benchmark] history append error: %s", exc)
        return

    # ── Cohort submission (fires once per day, same gate as history write) ──
    grade = ("A+" if score >= 85 else "A" if score >= 75 else "B" if score >= 65
             else "C" if score >= 50 else "D" if score >= 35 else "F")
    cfg = _load_config()
    threading.Thread(
        target=_submit_cohort_snapshot,
        args=(round(score), grade, cfg),
        daemon=True,
        name="cohort-submit",
    ).start()
```

The submission runs in a daemon thread so it never delays the `GET /score` response. If the thread fails, the next day's history write will retry.

---

### Part 6 — Nightly APScheduler Job (Belt-and-Suspenders)

The `_append_history_snapshot()` hook fires on the first page load of each day. Add a dedicated nightly job as a belt-and-suspenders fallback for installations where no one opens the benchmark page daily.

Add to `blueprints/benchmark/routes.py` alongside `run_bands_update_job()`:

```python
def run_cohort_submit_job() -> None:
    """
    Nightly job (02:00 UTC): submit today's CSPI snapshot to the cohort pool
    if opt-in is enabled and a score has been computed today.

    Registered by register_benchmark_scheduler() when BENCHMARK_COHORT_ENABLED=true.
    This is a belt-and-suspenders fallback — _append_history_snapshot() already
    fires a submission on the first GET /score call of each day.
    """
    log.info("[benchmark/cohort] Nightly submission job running")
    cfg = _load_config()
    if not cfg.get("cohort_opt_in"):
        log.info("[benchmark/cohort] cohort_opt_in=false — skipping")
        return

    # Find today's score from history
    today   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entries = _load_history()
    today_entry = next((e for e in entries if e.get("date") == today), None)
    if not today_entry:
        log.info("[benchmark/cohort] No score recorded today — running collectors now")
        result = _compute_cspi(cfg)
        cspi   = result.get("cspi")
        grade  = result.get("grade", "—")
        if cspi is None:
            log.warning("[benchmark/cohort] Could not compute CSPI — skipping submission")
            return
        _append_history_snapshot(float(cspi))   # also triggers thread submission
    else:
        cspi  = today_entry["score"]
        grade = ("A+" if cspi >= 85 else "A" if cspi >= 75 else "B" if cspi >= 65
                 else "C" if cspi >= 50 else "D" if cspi >= 35 else "F")
        _submit_cohort_snapshot(int(cspi), grade, cfg)
```

Extend `register_benchmark_scheduler()` to register this job:

```python
def register_benchmark_scheduler(scheduler) -> None:
    from core.config import BENCHMARK_COHORT_ENABLED
    from apscheduler.triggers.cron import CronTrigger

    # Existing: monthly bands update
    if _AUTO_UPDATE:
        scheduler.add_job(
            run_bands_update_job,
            trigger=CronTrigger(day=1, hour=3, minute=0),
            id="benchmark_bands_update",
            replace_existing=True,
            misfire_grace_time=3600,
        )

    # New: nightly cohort submission
    if BENCHMARK_COHORT_ENABLED:
        scheduler.add_job(
            run_cohort_submit_job,
            trigger=CronTrigger(hour=2, minute=0),   # 02:00 UTC nightly
            id="benchmark_cohort_submit",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        log.info("[benchmark] Nightly cohort submission job registered (02:00 UTC)")
```

The scheduler is already wired in `blueprints/scheduler/routes.py` at line 372 — no changes needed there.

---

### Part 7 — Cohort API (Server-Side Specification)

This is the CyCentra-operated cloud endpoint. It does not live in this repo but is documented here for the API contract.

#### Ingest endpoint

```
POST https://cohort.cycentra.com/api/v1/submit
Content-Type: application/json
```

**Request body:** the payload defined in Part 3.

**Response codes:**

| Code | Meaning |
|------|---------|
| 201 | Accepted — first submission for this `token` + `date` pair |
| 200 | Duplicate — already received this `token` + `date` pair; idempotent accept |
| 400 | Schema validation failure — body logged server-side; client should not retry |
| 429 | Rate-limited — client should back off for 24 hours |
| 503 | Cohort API unavailable — client should silently drop (not retry) |

#### Bands refresh endpoint

```
GET https://cohort.cycentra.com/api/v1/bands?schema=1
```

**Response:** the same structure as `_INDUSTRY_COHORTS_STATIC` — a JSON object keyed by sector, each with `bands`, `sample_size`, `source`, `label`.

This is what the monthly `run_bands_update_job()` should call instead of the current `_fetch_enisa_bands()` stub. When the cohort API is live, replace the `_fetch_enisa_bands()` function body:

```python
def _fetch_enisa_bands() -> Optional[dict]:
    from core.config import BENCHMARK_COHORT_URL
    base = BENCHMARK_COHORT_URL.rsplit("/submit", 1)[0]
    try:
        r = _req.get(f"{base}/bands", params={"schema": 1}, timeout=15)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        log.warning("[benchmark] Bands refresh failed: %s", exc)
    return None
```

#### Server-side storage and band computation

The cohort API backend should:

1. Accept `POST /submit` — validate schema, store `{token, cspi, industry, size_band, date}` in a time-series table; reject duplicates on `(token, date)`.
2. Nightly (03:00 UTC): recompute percentile bands per `(industry, size_band)` from the last 90 days of submissions. Publish to `GET /bands`.
3. Never store or log anything other than the five fields above. No IP logging on the ingest endpoint.

---

### Part 8 — UI Feedback (Portal Changes)

The current UI gives no feedback on whether a submission succeeded. Add a status indicator to `CohortSelector` in `BenchmarkPage.jsx`.

#### New backend route

Add to `blueprints/benchmark/routes.py`:

```python
@benchmark_bp.route("/cohort/status")
@_require_auth
def get_cohort_status():
    """
    Returns the date and result of the last cohort submission attempt.
    Reads from the in-memory _last_cohort_submit dict.
    """
    today     = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    submitted = _last_cohort_submit.get(today, False)
    cfg       = _load_config()
    return jsonify({
        "opt_in":        cfg.get("cohort_opt_in", False),
        "submitted_today": submitted,
        "date":          today,
    })
```

#### Frontend changes in `CohortSelector`

After the "Save Cohort Settings" button, add a small status chip that fetches `GET /api/benchmark/cohort/status` on mount and after save:

```jsx
// Inside CohortSelector, new state:
const [submitStatus, setSubmitStatus] = useState(null);

useEffect(() => {
  fetch(`${API}/cohort/status`, { credentials: "include" })
    .then(r => r.ok ? r.json() : null)
    .then(d => d && setSubmitStatus(d))
    .catch(() => {});
}, []);

// Render (below the save button):
{submitStatus?.opt_in && (
  <div style={{ marginTop: 10, fontSize: 10, fontFamily: "monospace",
    color: submitStatus.submitted_today ? C.accent : C.muted }}>
    {submitStatus.submitted_today
      ? `✓ Snapshot submitted to cohort pool — ${submitStatus.date}`
      : `Snapshot will be submitted tonight (02:00 UTC) — ${submitStatus.date}`}
  </div>
)}
```

---

### Part 9 — Privacy & GDPR Compliance Checklist

Before enabling this feature in any EU deployment (all current installs are Benelux/DACH):

- [ ] **Lawful basis**: User consent is the lawful basis (Art. 6(1)(a) GDPR). The toggle is the consent mechanism. Log the consent event via `auth_event()` in `core/helpers.py` when `cohort_opt_in` flips to `true`.
- [ ] **Data minimisation**: The payload (Part 3) contains no personal data as defined by Art. 4(1) GDPR — a CSPI integer and sector key are not identifiable. Legal should confirm the `token` (HMAC of domain) does not constitute personal data in the customer's context.
- [ ] **Withdrawal**: When the user toggles off and saves, submissions must stop immediately. The `_submit_cohort_snapshot()` function already gates on `config.get("cohort_opt_in")` at call time — no further work needed.
- [ ] **Transparency**: The existing UI label accurately describes the data shared. No change required.
- [ ] **Data retention (server-side)**: The cohort API must purge submissions older than 90 days (the band recomputation window).
- [ ] **DPA / processor agreement**: If the cohort API is hosted outside the EU, a DPA is required between the customer (controller) and CyCentra (processor). If hosted in the EU (e.g. AMS region), this simplifies significantly.

---

### Part 10 — Implementation Order

Build in this sequence to keep each step independently deployable:

| Step | What | Files touched |
|------|------|---------------|
| 1 | Add env vars | `core/config.py`, `/opt/cycentra/.env` template in `cycentra-setup.sh` |
| 2 | Add `_tenant_token()` and `_submit_cohort_snapshot()` | `blueprints/benchmark/routes.py` |
| 3 | Hook into `_append_history_snapshot()` | `blueprints/benchmark/routes.py` |
| 4 | Register nightly APScheduler job | `blueprints/benchmark/routes.py` |
| 5 | Add `GET /api/benchmark/cohort/status` route | `blueprints/benchmark/routes.py` |
| 6 | Add submission status chip to `CohortSelector` | `portal/src/pages/benchmark/BenchmarkPage.jsx` |
| 7 | Build cohort ingest + bands API (separate repo) | `cohort-api/` service |
| 8 | Update `_fetch_enisa_bands()` to call live bands API | `blueprints/benchmark/routes.py` |

Steps 1–6 can be shipped before step 7 — the submission function is a no-op when `BENCHMARK_COHORT_URL` is empty.

---

## Summary

| Aspect | Detail |
|--------|--------|
| Toggle location | `CohortSelector` component, `BenchmarkPage.jsx:665` |
| User action | Flip toggle → click "Save Cohort Settings" |
| Frontend call | `PUT /api/benchmark/config` with `cohort_opt_in: true/false` |
| Backend handler | `blueprints/benchmark/routes.py:put_config()` |
| Persistence | `/opt/cycentra/benchmark_config.json` |
| Outbound data | **None — not yet implemented** |
| Flag consumed by | Nothing in current code |
| Feature status | Consent UI complete; submission pipeline specced but not built |
| Operator gate | `BENCHMARK_COHORT_ENABLED=true` in `/opt/cycentra/.env` |
| User gate | `cohort_opt_in: true` in `benchmark_config.json` |
| Submission trigger | `_append_history_snapshot()` (same-day hook) + nightly job at 02:00 UTC |
| Anonymization | HMAC-SHA256 of `BASE_DOMAIN` truncated to 16 hex chars |
| Payload | `{token, cspi, grade, industry, size_band, date, schema}` — 7 fields only |
| Retry policy | No retry — silent drop on failure; next day's job retries naturally |
