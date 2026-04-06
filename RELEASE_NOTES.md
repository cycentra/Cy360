# CyCentra 360 — Release Notes

---

## v1.0.53 — 2026-04-06

### Enhancements

**Release notes in every git push (git-push.sh, RELEASE_NOTES.md)**
- `git-push.sh` rewritten to extract the `## vX.X.X` section from `RELEASE_NOTES.md` and
  use it as the full git commit message body.
- Tags are now **annotated** (previously lightweight) — meaning `git show <tag>` and the
  GitHub Releases page both display the full change description.
- If no release notes section is found for the new version, the script warns and falls back
  to a timestamp-only message so pushes never silently break.
- `RELEASE_NOTES.md` created with full history from v1.0.43 through v1.0.52.
- **Workflow going forward**: add a `## vX.X.X — YYYY-MM-DD` section to `RELEASE_NOTES.md`
  before running `bash git-push.sh`. The section content becomes the commit message and tag annotation automatically.

---

## v1.0.52 — 2026-04-06

### Bug Fixes

**Subdomain deduplication (subdomain_enum.py)**
- crt.sh returns multiple SANs (Subject Alternative Names) joined by `\n` in a single `name_value` field.
  The code was never splitting on `\n`, causing entire multi-subdomain strings like
  `cy360.cycentra.com cyiris.cycentra.com cymisp.cycentra.com` to appear as a single asset entry.
- Fix: `name_value` is now split with `.splitlines()` and each SAN is validated and added individually.

**Asset status preservation across scans (useAppState.js)**
- Every rescan replaced the asset list with fresh adapter output, which always defaults to `status: "open"`.
  Any statuses set by the user (In Review / Resolved) were silently discarded.
- Fix: Added `_mergeStatuses()` helper that builds a `host → status` map from the previous asset list
  and merges non-default statuses back after each scan. Applied to all three load paths:
  scan complete, initial page load, and manual import.
- Newly discovered assets still default to `open`. Status is keyed by hostname (stable across scans).

---

## v1.0.51 — 2026-04-05 _(tag skipped by git-push.sh; content released as v1.0.52)_

> Internal: git-push.sh detected v1.0.51 already existed and auto-incremented to v1.0.52.

---

## v1.0.50 — 2026-04-05

### Performance Enhancements

**orjson replaces stdlib json (ingestor.py, main.py)**
- `orjson` is 5–10x faster than stdlib `json` and accepts `bytes` natively (Wazuh payloads arrive
  as bytes from Redis BLPOP — stdlib `json.loads` required an implicit decode step first).
- `orjson.dumps()` returns `bytes` directly — removed unnecessary `.encode()` calls before Redis push.
- Graceful fallback to stdlib `json` if `orjson` is not installed.

**Batch ingest from Redis (ingestor.py)**
- Replaced single-alert BLPOP loop with batch drain: blocks on BLPOP for the first alert,
  then drains up to 9 more with a single Redis pipeline call.
- At 100 alerts/min: ~10 Redis round trips/min instead of 100. Burst performance significantly improved.
- Each alert in the batch is still spawned as an independent asyncio task, bounded by `_PROCESS_SEM = 6`.

---

## v1.0.49 — 2026-04-05

### Performance Enhancements

**ML model in-memory cache (ueba_ml.py)**
- `pickle.load()` was called from disk for every alert with a username.
- Added `_model_cache` dict keyed by `(username, file_mtime)`. Disk read only occurs when the
  model file changes (weekly retrains). Cache is automatically invalidated on `_save_model()`.

**UEBA context cache with 30s TTL (ingestor.py)**
- `_get_recent_user_alerts()` issued a DB query on every alert. Now results are cached per-username
  for 30 seconds. A user generating 50 alerts in a burst uses 1 DB query instead of 50.

**Per-entity risk scoring throttle — 60s minimum interval (ingestor.py)**
- `calculate_entity_risk()` ran for every alert (up to 8 DB queries per alert for host + user).
- Now throttled to once per entity per 60 seconds via `_last_risk_calc` dict.

**Concurrency semaphore — max 6 concurrent alert tasks (ingestor.py)**
- Each alert is now spawned as an asyncio task (non-blocking loop).
- `_PROCESS_SEM = asyncio.Semaphore(6)` caps concurrent processing to match the 4-CPU server
  without stampeding memory on alert bursts.

**Risk scheduler tuning (main.py, risk_scorer.py)**
- `_risk_scheduler` interval: 300s → 600s.
- `recalculate_all`: lookback window 48h → 24h; added 200-entity cap per run to prevent
  unbounded DB loops during alert storms.

---

## v1.0.48 — 2026-04-04

### Bug Fixes

**Dashboard empty when AI enrichment fails (cycentra_scan.py)**
- `portal JSON vulnerabilities` was set to `enriched_issues`, which is always `[]` when
  CyMind + Gemini both fail or time out.
- Fix: added `_normalise_issue()` helper and `final_vulns` fallback — raw scan findings from all
  modules are normalised and used when AI enrichment returns nothing. Dashboard widgets always
  have data regardless of AI provider availability.

**Wordlist path fix (subdomain_enum.py)**
- Hardcoded path `/opt/cycentra/backend/cy-asm/modules/wordlists/subdomains.txt` only worked in
  source checkout, never in wheel-installed packages.
- Fix: path now resolved relative to `__file__` using `os.path.dirname(os.path.abspath(__file__))`.

**Subdomain Intel section in Asset Modal (AssetModal.jsx)**
- Subdomain assets showed no detail when clicked.
- Added "Subdomain Intel" panel showing: DNS Status (LIVE / Not Resolving), Change badge,
  Resolved IP, CNAME, and Discovery Source tags (crt.sh, brute_force, etc.).

---

## v1.0.47 — 2026-04-03

### Bug Fixes

**Scan data not loading — Gemini timeout (cycentra_scan.py)**
- Gemini API call had no timeout, hanging indefinitely and preventing portal JSON from being written.
- Fix: wrapped in `asyncio.wait_for(..., timeout=90.0)`, switched model to `gemini-2.0-flash`.

**Ollama config bleed (cycentra_scan.py)**
- `_get_ollama_config` was reading CyMind fields even when provider was not `local`.
- Fix: guarded CyMind field reads behind `if provider == "local"` check.

**Scan status mtime threshold (scanner.py)**
- Threshold was 600s — scans taking longer than 10 min were falsely reported as stale.
- Fix: threshold increased to 1800s.

**Added log markers**
- `[AI Enrichment] Starting...` and `[Portal JSON] Saving...` added for real-time progress visibility.

---

## v1.0.46 — 2026-04-02

### Bug Fixes

**Subdomain adapter parsing (adapter.js)**
- v1.0.45 changed subdomain results from strings to enriched dicts, but adapter still filtered
  with `typeof s === "string"`, discarding all dict entries.
- Fix: adapter now handles both string (legacy) and dict (v1.0.45+) formats.

**CyMind API key overwrite prevention (routes.py)**
- Saving AI settings with an empty or masked (`••••••••`) API key was overwriting the stored key with blank.
- Fix: `ai_settings_post` now preserves the existing key when incoming value is empty or masked.

---

## v1.0.45 — 2026-04-01

### Enhancements

**Subdomain live validation and cross-scan state tracking**
- `gather_subdomains` rewritten to return enriched dicts:
  `{subdomain, live, resolved_ips, cname, sources, is_new, change}`.
- State management added to `cycentra_scan.py`: `_load_subdomain_state`, `_save_subdomain_state`,
  `_annotate_subdomains` — persisted at `/var/log/cycentra/cy-asm/state/<tenant>/<domain>_subdomains.json`.
- Each subdomain now carries `is_new` / `change` (NEW / PERSISTED / APPEARED / DISAPPEARED) across scans.

---

## v1.0.43 – v1.0.44 — 2026-03-31

### Enhancements

- Rich UEBA anomaly cards in the SIEM dashboard.
- IRIS case escalation from UEBA anomalies.
- Wazuh deep-link integration from incident cards.
- Normaliser suppression rules for Wazuh rule IDs 5710, 5711, 5702, 5703.
