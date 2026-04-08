# CyCentra 360 — Release Notes

---
## v1.0.82 — 2026-04-09

### Fix — Migrated setup script from Cloudsmith to GitHub Packages

`cycentra-setup.sh` fully updated to replace all Cloudsmith references:

- **Token**: `CS_TOKEN` replaced by `GH_TOKEN` (GitHub personal access token) — run with `GH_TOKEN=your_token sudo -E bash cycentra-setup.sh`
- **Bundle URL**: `dl.cloudsmith.io/.../raw/versions/...` → `maven.pkg.github.com/cycentra/cycentra360/cycentra/bundle/${VER}/bundle-${VER}.tar.gz`; "latest" resolved live via GitHub Releases API
- **Wheel**: No longer installed via `--index-url` (pip).  Wheel downloaded directly from `maven.pkg.github.com/.../cycentra/backend/${VER}/cycentra_backend-${VER}-py3-none-any.whl` with `Authorization: Bearer ${GH_TOKEN}`, then installed as a local file
- **Manifest parsing**: Updated for new GitHub manifest schema — reads `version` + `ver_number` directly; `PKG_NAME` is hardcoded to `cycentra-backend` (no longer read from manifest)
- **Header comment** updated: `Cloudsmith → cycentra-backend wheel` → `GitHub Packages → cycentra-backend wheel`

---
## v1.0.81 — 2026-04-09

### Feature — MISP threat intelligence for ASM + incident list intel badges

**`backend/cy_asm/cycentra_scan.py`:**
- Fixed `GOOGLE_GEMINI_KEY` NameError bug — variable was used but never defined; now reads `os.environ.get("GOOGLE_GEMINI_KEY", "")`
- Added `_get_misp_config()` — reads `ai_settings.json["misp"]` block for `{ enabled, url, apiKey }`
- Added `lookup_misp_iocs(ips)` — async MISP `/attributes/restSearch` lookup; fire-safe, never raises
- MISP IOC lookup runs in `main()` after subdomain save, **before** AI enrichment so the AI narrative is MISP-aware
- `misp_hits` list attached to findings whose IP matches a MISP attribute; `misp_threat_intel` summary passed to all other findings

**`backend/blueprints/system/routes.py`:**
- `misp` added to allowed POST keys (alongside `provider`, `fields`, `prompts`, `cymind_memory`)
- `misp.apiKey` masked in GET responses; preserved on masked POST (same guard pattern as `cymind_memory.apiKey`)

**`portal/src/pages/ai/AISettingsPage.jsx`:**
- New "🔴 MISP Threat Intelligence" card — enable toggle, MISP Server URL, API Key (password), inline status indicator
- Saved as `misp` key in `ai_settings.json`; configure once, runs on every Deep ASM scan

**`portal/src/siem/SiemIncidentsPage.jsx`:**
- Added **INTEL** column to incident list table (grid widened from 7 to 8 columns)
- `🤖 AI` badge (green) when `llm_summary` is present — AI narrative has been generated
- `🔴 IOC` badge (red) when MISP IOC hits are present — shows hit count in tooltip
- Dash shown when neither enrichment has run

---
## v1.0.80 — 2026-04-08

### Fix — CyMind episodic memory works with any active AI provider

Previously, ASM and SIEM incidents were only stored in CyMind memory when CyMind was the active LLM provider. If Gemini, Anthropic, Ollama, or DeepSeek was selected, the `store_to_cymind_memory` calls silently skipped because they tried to extract CyMind credentials from the active provider's `fields` block.

**Changes:**
- `ai_settings.json` gains a dedicated `cymind_memory: { baseUrl, apiKey }` block, stored independently of the active `provider`/`fields` keys
- `backend/blueprints/system/routes.py`: `cymind_memory` added to allowed POST keys; `apiKey` within it is masked in GET responses; key-preservation guard also applies to `cymind_memory.apiKey`
- `portal/src/pages/ai/AISettingsPage.jsx`: New "CyMind Episodic Memory" card below Module URL Overrides — purple-themed, shows configured/not-configured status inline. State saved as `cymind_memory` key alongside `provider`/`fields`/`prompts`
- `backend/cy_asm/cycentra_scan.py`: New `_get_cymind_memory_config()` helper — checks `cymind_memory` block first, falls back to active cymind provider fields. `store_to_cymind_memory()` uses this instead of `_get_cymind_config()`
- `backend/cysiemstack/correlation_engine/llm_enricher.py`: `_store_to_cymind_memory()` uses same priority logic — `cymind_memory` block first, then falls back to active provider fields only when `provider == "cymind"`

**Result:** Set CyMind URL + API key once in the new Memory Integration card — incidents flow into CyMind memory regardless of whether the active LLM is Gemini, Anthropic, Ollama, or CyMind itself.

---
## v1.0.79 — 2026-06-13

### Feature — cy360 → CyMind episodic memory integration

Both the ASM enrichment pipeline and the SIEM correlation engine now automatically forward enriched findings into CyMind's episodic memory (`soc-episodic-memory` Qdrant collection) so analysts can query all incidents from the CyMind chat window.

**`cycentra_scan.py` changes:**
- Added `store_to_cymind_memory(findings, domain, provider)` async helper
- Called after each successful enrichment provider (CyMind, Gemini, Ollama)
- Maps ASM finding fields to CyMind `IncidentMemory` schema with `incident_id = ASM-{domain}-{module}-{i}`
- Tags include `["asm", domain, module, provider]`; outcome set to `"open"`
- Fire-and-forget — never blocks scan results

**`llm_enricher.py` changes:**
- Added `_store_to_cymind_memory(incident, summary, remediation)` async helper
- Called after `db.flush()` in `enrich_incident()` for every enriched correlation engine incident
- Reads CyMind `baseUrl`/`apiKey` from `/opt/cycentra/ai_settings.json` via `_load_ai_settings()`
- Maps Wazuh incident fields: MITRE IDs → ttps, correlated rules → rule_ids, mitre_tactics → tags
- Silently skips if CyMind is not configured; never blocks incident processing

---

## v1.0.78 — 2026-04-08

### Feature — ASM scan levels (Standard / Deep / Passive) + subdomain toggle

**Backend changes to align with the Scan UI:**

Three configurable scan profiles are now enforced end-to-end:

| Profile | Subdomains | Modules | AI Enrichment |
|---|:---:|---|:---:|
| **Passive** (~20 s) | ✗ | DNS, Email Security, WHOIS, OSINT, Dark Web | ✗ |
| **Standard** (~45 s) | ✓ | DNS, Subdomains, Web, Crypto & SSL, Email Security, Cloud, WHOIS, OSINT | ✗ |
| **Deep** (~90 s) | ✓ | Full suite (Standard + Dark Web, Supply Chain, Social Engineering, Mobile & API) | ✓ |

`POST /api/scan/trigger` now accepts two new body fields:
- `scan_type` — `"standard"` (default) | `"deep"` | `"passive"`. Returns HTTP 400 for unknown values.
- `include_subdomains` — boolean (default `true`). When `false`, subdomain enumeration is skipped regardless of profile.

Both parameters are forwarded to the scan engine; `scan_type` via CLI argv, `include_subdomains` via
the `CYCENTRA_INCLUDE_SUBDOMAINS` environment variable. The portal JSON `meta` block now includes
both `scan_type` and `include_subdomains` for auditability.

`cycentra_scan.py` changes:
- `SCAN_PROFILES` dict is the single source of truth for module lists and AI enrichment flag.
- `run_full_scan()` accepts `scan_type` + `include_subdomains`; Stage 2 and Stage 3 are filtered accordingly.
- `main()` accepts optional 3rd arg `[scan_type]` (backward-compatible — defaults to `standard`).
- AI enrichment chain (CyMind → Gemini → Ollama) only executes for Deep scan.

---



### Fix — CyIRIS/CySOAR install: clear stale ghcr.io credentials before pulling images

Docker sends stored credentials for a registry with every pull request. When the
Docker credential store holds an expired/invalid ghcr.io token, the registry
returns `unauthorized` even for fully public images — it does not fall back to
anonymous access. The install thread now runs `docker logout ghcr.io` before
`docker compose pull` whenever the compose template references `ghcr.io`, clearing
any stale credential and allowing anonymous pulls to succeed. If a `GHCR_TOKEN`
env var is set (e.g. for private images or rate-limit bypass), it performs a proper
`docker login` via stdin instead. No manual server-side changes required.

---

## v1.0.75 — 2026-04-06

### Fix — suppress pip root-user warning during setup

Both `pip3 install` calls in `cycentra-setup.sh` now prepend `PIP_ROOT_USER_ACTION=ignore`,
which is pip's own env-var mechanism for suppressing the "Running pip as root" advisory.
Installing into system Python as root is intentional here (required for the Flask systemd
service), so the warning was noise. No virtualenv or separate user is introduced — the
service architecture requires root-owned system Python packages.

---

## v1.0.74 — 2026-04-06

### Bug Fix — "Setup script not found on server" error in portal UI update

The portal's `/api/system/update` endpoint checks for `/opt/cycentra/cycentra-setup.sh`
before triggering `--update`. The file was never deployed there — `cycentra-setup.sh`
copied config files, the release notes, and the cysiem bridge but never itself.

Fixed by adding a self-copy step in `cycentra-setup.sh` immediately after the version
file and release notes are written (runs in both `full` and `update` modes):

```bash
_SELF="$(realpath "$0")"
cp "$_SELF" /opt/cycentra/cycentra-setup.sh
chmod 750  /opt/cycentra/cycentra-setup.sh
```

**Immediate fix for existing servers (no full reinstall needed):**
```bash
sudo cp /path/to/cycentra-setup.sh /opt/cycentra/cycentra-setup.sh
sudo chmod 750 /opt/cycentra/cycentra-setup.sh
```

---

## v1.0.73 — 2026-04-06

### Bug Fix — wizard version header now auto-stamps on every release; GHCR auth removed

- `cycentra-setup.sh` lines 3 and 117 had the version string hardcoded as `v1.0.69` instead
  of the `_WIZARD_VERSION_` placeholder that `git-push.sh` replaces on each release. The
  placeholder is now restored so every push correctly stamps the header comment and the
  boot banner with the current tag and UTC timestamp.

- Reverted the GHCR auth wizard step, `.env` entries (`GHCR_USER`, `GHCR_TOKEN`), and
  `docker login` block in `routes.py` added in v1.0.72. The GHCR packages
  (`ghcr.io/cycentra/cysoar`, `ghcr.io/cycentra/cyiris`) are public — authentication is
  not required and the extra prompts in the setup wizard added unnecessary friction.
  The `SESSION_SECRET` → `CYSOAR_SESSION_SECRET` rename from v1.0.72 is kept.

---

## v1.0.72 — 2026-04-06

### Bug Fix — CySOAR / CyIRIS installation failing with "unauthorized" on new servers

**Root cause:** Module installs called `docker compose pull` against private GHCR images
(`ghcr.io/cycentra/cysoar:latest`, `ghcr.io/cycentra/cyiris:latest`) without first
authenticating to the registry. New servers have no cached Docker credentials.

**Secondary issue:** The CySOAR module `.env` wrote `SESSION_SECRET` but the compose
template referenced `${CYSOAR_SESSION_SECRET}`, causing a blank-string warning from
Docker Compose on every install.

**Changes:**

- `backend/blueprints/platform/routes.py`
  - Added `import subprocess` (stdlib).
  - Added GHCR login block (using `--password-stdin` via subprocess stdin — token never
    exposed in process list) before `docker compose pull` for `cysoar` and `cyiris` modules.
    Logs `"GHCR login successful"` on success; warns but continues if credentials missing.
  - Renamed `"SESSION_SECRET"` → `"CYSOAR_SESSION_SECRET"` in the CySOAR `.env` dict to
    match the compose template variable.

- `cycentra-setup.sh`
  - Added a **GITHUB CONTAINER REGISTRY** setup step (defaulting to `y`) that prompts for
    `GHCR_USER` (GitHub username) and `GHCR_TOKEN` (PAT with `read:packages` scope).
  - Writes `GHCR_USER` and `GHCR_TOKEN` to `/opt/cycentra/.env`.
  - Shows GHCR user in the Review & Confirm summary.

**How to fix existing servers without re-running setup:**
```
echo "GHCR_USER=<github-username>" >> /opt/cycentra/.env
echo "GHCR_TOKEN=<pat-with-read-packages>" >> /opt/cycentra/.env
sudo systemctl restart cycentra
```
Then re-install CySOAR / CyIRIS from the portal.

---

## v1.0.71 — 2026-04-06

### Bug Fix

**cysiemstack correlation_engine/config.py — engine no longer crashes on startup**
- `pydantic-settings` v2 defaults `BaseSettings` to `extra='forbid'`, causing an immediate
  `ValidationError` for `Settings` because the `cysiemstack.env` file contains a
  `POSTGRES_PASSWORD` convenience key (used by `--update` mode) that is not a declared field.
- Fixed by migrating `class Config` to `SettingsConfigDict(extra='ignore')` so unrecognised
  env-file keys are silently discarded instead of causing a crash.

---

## v1.0.70 — 2026-04-06

### Enhancements

**cycentra-setup.sh — engine.log automatically printed when cysiemstack-engine fails to start**
- When the engine health-check times out, the last 30 lines of `/opt/cycentra/engine.log` are
  now printed inline so the exact Python traceback is visible immediately without needing to
  SSH and run `tail` manually.

**cysiemstack correlation_engine/models.py — init_db surfaces clear error on DB connection failure**
- `init_db()` now wraps the `engine.begin()` call in a try/except that logs a `CRITICAL`
  message explicitly stating "DATABASE CONNECTION FAILED — check DATABASE_URL in
  /opt/cycentra/cysiemstack.env" before re-raising, making the root cause immediately visible
  in `engine.log` instead of a raw asyncpg traceback.

---

## v1.0.69 — 2026-04-06

### Bug Fixes

**cycentra-setup.sh — CRON JOBS step no longer aborts setup**
- The cron registration used `crontab -l 2>/dev/null || true | grep -v "update_wordlist"`.
  Due to bash operator precedence, `||` binds more loosely than `|`, so this parsed as
  `crontab -l 2>/dev/null || (true | grep -v "update_wordlist")`. When `crontab -l` failed
  (empty crontab on fresh server), `grep -v` received empty input and exited 1. With
  `set -euo pipefail` active this aborted setup at Step 25.
- Fixed: replaced the subshell pipeline with a tempfile approach — no operator-precedence
  ambiguity, no pipefail interaction, and idempotent (deduplicates existing entries).

### Enhancements

**cycentra-setup.sh — wizard version and date auto-stamped by git-push.sh**
- The banner comment (`# CyCentra 360 — Setup & Update Wizard v7.1 - March 25, ...`) and the
  printed banner line were hardcoded and never updated after the initial commit.
- Replaced with a `_WIZARD_VERSION_` placeholder that `git-push.sh` stamps with the release
  tag and UTC timestamp on every push (e.g. `v1.0.69 — 2026-04-06 20:30 UTC`).

---

## v1.0.68 — 2026-04-06

### Enhancements

**cycentra-setup.sh / deploy.yml / git-push.sh — RELEASE_NOTES.md shipped as bundle file**
- The full `RELEASE_NOTES.md` content was previously embedded as a ~400-line heredoc inside
  `cycentra-setup.sh` and regenerated by `git-push.sh` on every push. This caused the script
  to grow by ~20 KB per release cycle and became unmanageable.
- `RELEASE_NOTES.md` is now copied directly into `cycentra-release.tar.gz` by the CI bundle
  build step (`deploy.yml`) alongside `cycentra-setup.sh`, `portal/dist/`, `db/`, etc.
- `cycentra-setup.sh` now simply copies `$BUNDLE_DIR/RELEASE_NOTES.md` to
  `/opt/cycentra/RELEASE_NOTES.md` — a single `cp` replacing the entire heredoc block.
- `git-push.sh` no longer runs the Python heredoc regeneration step — just stamps
  `_SCRIPT_VERSION` and commits.
- **Going forward**: update `RELEASE_NOTES.md` before running `bash git-push.sh`. CI will
  package the file into the bundle; the Settings tab on every server receives the latest
  history after the next `--update` run.

---

## v1.0.67 — 2026-04-06

### Bug Fixes

**cycentra-setup.sh — CySIEM credential extraction no longer aborts setup**
- The `grep` pipeline extracting admin and wazuh-wui passwords from `wazuh-install-files.tar`
  returned exit code 1 when the passwords file was absent or Wazuh 4.14 changed its format.
  With `set -euo pipefail` active this killed the script immediately after a successful CySIEM
  install, printing the ERR trap message for Step 4 "CySIEM INSTALLATION".
- Fixed: added `|| true` to both password-extraction greps so a no-match is non-fatal.
- Fixed: added a fallback grep against the tar file itself for the `Password: <value>` pattern
  printed by the Wazuh 4.x installer in its stdout summary.
- Note: Step 4.2 (CySIEM API Password Detection) auto-detects the wazuh-wui password from the
  dashboard config independently — these variables are purely for the final summary display.

---

## v1.0.66 — 2026-04-06

### Enhancements

**git-push.sh — release notes now auto-embedded into setup.sh on every push**
- The RELEASE_NOTES.md heredoc inside `cycentra-setup.sh` (written to `/opt/cycentra/RELEASE_NOTES.md`
  on every server deployment) was never being auto-regenerated by `git-push.sh` despite the comment
  claiming it was. The embedded copy was stuck at v1.0.61.
- `git-push.sh` now runs a Python one-liner before `git add` that replaces the heredoc content with
  the full current `RELEASE_NOTES.md`, keeping the Settings tab release history always up to date
  on every push without any manual step.

---

## v1.0.65 — 2026-04-06

### Bug Fixes

**cycentra-setup.sh — CySIEM → Redis bridge moved after CySIEM installation**
- The bridge step (deploying `cysiem_to_redis.py` and starting `cysiem-to-redis.service`) was
  running inside the INFRA block before CySIEM was installed. On a fresh server,
  `/var/ossec/logs/alerts/` did not exist yet, causing the service to fail silently at start.
- Moved to run after Step 4 (CySIEM install + API password detection) so the service starts
  successfully on first deployment.
- Bridge now runs in all modes (full/infra/update), ensuring re-deploys always refresh the watcher.

**cycentra-setup.sh — fatal error trap added**
- Added `trap '...' ERR` with `_LAST_STEP` tracking. Any unexpected non-zero exit now prints
  the step name, failed command, exit code, and line number before aborting — eliminating
  silent mid-script stops.

---

## v1.0.64 — 2026-04-06

### Bug Fixes

**cycentra-setup.sh — cysiem_to_redis.py deployment fixed on fresh servers**
- `/opt/cycentra/` directory did not exist on brand-new servers, causing the `cat >` write
  to fail with "No such file or directory". Fixed: `mkdir -p /opt/cycentra` added before
  the watcher script is written.

**cysiemstack — wazuh_to_redis.py renamed and relocated**
- `backend/cysiemstack/wazuh_to_redis.py` renamed to
  `backend/cysiemstack/correlation_engine/cysiem_to_redis.py` — co-located with the
  correlation engine that consumes its output.
- All references in `cycentra-setup.sh`, `filebeat.yml.example`, and the systemd unit
  updated to `cysiem_to_redis` / `cysiem-to-redis.service`.

---

## v1.0.63 — 2026-04-06

### Security

**Backend — OAuth and OIDC secrets now fully protected in env editor**
- `GOOGLE_CLIENT_SECRET`, `MICROSOFT_CLIENT_SECRET`, `CYIRIS_OIDC_SECRET`,
  `CYSOAR_OIDC_SECRET`, `IRIS_SECRET`, `IRIS_DB_PASS`, `JWT_SECRET`, `ADMIN_API_KEY`,
  `NODE_RED_CREDENTIAL_SECRET`, and `SMTP_PASS` were absent from `_SECRET_KEYS`.
- These values appeared as plain text in the Env Config tab and could be overwritten
  via the PUT endpoint.
- All secrets are now masked as `•••••••• (protected)` in the UI and blocked from writes.

---

## v1.0.62 — 2026-04-06

### Enhancements

**cycentra-setup.sh — Version pre-check skips redundant updates**
- In `--update` mode, the script now compares `_SCRIPT_VERSION` (embedded by `git-push.sh`
  at each release) against `/opt/cycentra/version` (written after every successful install).
- If versions match the script prints "Already at the latest version" and exits 0 immediately
  — no bundle download, no service restarts, no disruption.
- Run `FORCE_UPDATE=1 sudo -E bash cycentra-setup.sh --update` to bypass the check and
  re-apply the current version regardless.

**cycentra-setup.sh — Secrets and tokens no longer appear in terminal output**
- `_mask_url()` helper replaces Cloudsmith auth tokens in any printed URL with `[TOKEN]`.
- Applied to both the bundle download URL and the pip index URL so no credentials appear
  in terminal scrollback, logs, or CI capture.

**Backend — `/api/system/latest-version` endpoint**
- `GET /api/system/latest-version?csToken=…` fetches only the first 4 KB of the published
  `cycentra-setup.sh` from Cloudsmith, reads the embedded `_SCRIPT_VERSION`, and returns
  `{current, latest, up_to_date}` without downloading the full release bundle.

**Backend — Secrets redacted from live update log**
- `_redact_line()` applied to every line before it is appended to `_update_log`.
- Masks `key=value` / `key: value` patterns for password/secret/token/key fields, and
  replaces Cloudsmith auth tokens in URLs with `[TOKEN]` and `[REDACTED]` respectively.

**UI — Version comparison before triggering update**
- "Run Update" now performs a version check first:
  - If already on the latest version: shows "✓ Already running latest (vX.X.X)" and
    surfaces a "Force Reinstall" button for intentional re-application.
  - If an update is available: shows a yellow "↑ vX.X.X AVAILABLE" badge and proceeds.
  - If the version check fails (network/token error): shows a warning but allows the
    update to proceed anyway (non-fatal).
- The current-version card displays an inline `✓ UP TO DATE` or `↑ vX.X.X AVAILABLE` badge
  once a check has been performed.
- The CS_TOKEN input is of type `password` — not visible in the browser or screenshot.

---

## v1.0.61 — 2026-04-06

### Bug Fixes

**cycentra-setup.sh — UI-triggered update no longer fails with exit code 1**
- `clear` was called unconditionally at script start. When executed as a Flask subprocess
  there is no TTY, so `TERM=unknown` causes `clear` to output
  `'unknown': I need something more specific.` then exit 1 (caught by `set -euo pipefail`),
  aborting the entire update before the banner even printed.
  Fixed to `[[ -t 1 ]] && clear` — only clears the screen when stdout is a real terminal.

**cycentra-setup.sh — POSTGRES_PASSWORD no longer re-generated on every --update run**
- `cysiemstack.env` was never written with a standalone `POSTGRES_PASSWORD=` line; the
  credential existed only embedded inside `DATABASE_URL`. The update-mode grep found nothing
  and silently generated a fresh password on every run.
- Fix 1: Update mode now falls back to extracting the password from `DATABASE_URL` when the
  standalone key is absent (covers all existing installs prior to v1.0.61).
- Fix 2: `cysiemstack.env` template now includes a `POSTGRES_PASSWORD=` standalone line so
  future updates can read it directly without parsing the connection URL.

---

## v1.0.60 — 2026-04-08

### Bug Fixes

**cycentra-setup.sh — RELEASE_NOTES.md now embedded directly in the script**
- All prior fallback strategies (bundle tarball, script dir, Cloudsmith raw URL, GitHub raw URL)
  failed because RELEASE_NOTES.md is not published as a separate Cloudsmith artifact and the
  Git repository is private.
- Release notes content is now embedded as a heredoc block inside `cycentra-setup.sh` itself.
  Since the script is always freshly downloaded from Cloudsmith, the content is always present.
- `git-push.sh` updated to regenerate this heredoc from the live `RELEASE_NOTES.md` before each
  push, keeping the embedded copy in sync with every tagged release.

---

## v1.0.55 — 2026-04-07

### Bug Fixes

**cycentra-setup.sh — --update no longer aborts on missing POSTGRES_PASSWORD**
- The `--update` mode previously hard-exited if `POSTGRES_PASSWORD` was absent in
  `/opt/cycentra/cysiemstack.env`. Now it warns and auto-generates a fallback password
  so updates complete even on environments where the cysiemstack stack was not fully initialised.

**cycentra-setup.sh — version file now written on every run**
- After the bundle manifest is parsed, `BUNDLE_VERSION` is written to `/opt/cycentra/version`
  (create if absent, overwrite if present). System Settings version display now always reflects
  the latest deployed version.
- `RELEASE_NOTES.md` is also copied to `/opt/cycentra/` so the System Settings page
  can read release history on the live server.

**Backend — corrected env file paths for module targets**
- `cyiris`  → `/opt/cycentra/modules/cyiris/.env`
- `cysoar`  → `/opt/cycentra/modules/cysoar/.env`
- `cymisp`  → `/opt/cycentra/modules/cymisp/.env`
- `cysiem`  → `/opt/cycentra/.env` (shared global env)
- `cysiemstack` and `global` remain unchanged.

**Backend — RELEASE_NOTES.md multi-path resolution**
- The `/api/system/version` endpoint now tries `/opt/cycentra/RELEASE_NOTES.md`,
  then the dev repo path relative to `routes.py`, then `cwd` — so release notes
  display correctly in both production and local development.

**Frontend — asset status preserved across page refreshes and rescans**
- Status changes (`in-review`, `resolved`, etc.) are now persisted to `localStorage`
  under `cycentra_asset_statuses` (keyed by hostname).
- On page refresh or after a new cy-asm scan completes, saved statuses are re-applied
  before re-rendering the asset list — statuses no longer revert to "open".

**WorldMapWidget — significantly improved map + animations**
- Continent outlines replaced with detailed multi-point paths: all major landmasses
  including Scandinavia, Indian subcontinent, SE Asia, Japan, Madagascar, New Zealand.
- Animated scan-line sweep across the ocean, animated dot pulse rings (staggered per location),
  drop-shadow glow filter on dots, radial ocean gradient with subtle breathing animation.
- Risk colour escalation for co-located assets (worst risk shown per location).
- Asset count badge on co-located dots; legend shows total primary assets mapped.

---

## v1.0.54 — 2026-04-07

### New Features

**System Settings page (navConfig, App.jsx, SystemSettingsPage.jsx)**
- New "System Settings" entry in the PLATFORM section of the sidebar (gear icon, `#00e5a0` accent).
- **Updates & Version tab**: displays running version (read from `/opt/cycentra/version`), last 5
  release notes blocks from `RELEASE_NOTES.md`, CS_TOKEN password input, "Run Update" button that
  spawns `sudo -E bash cycentra-setup.sh --update` server-side in a daemon thread.
- Live update log console: polls `GET /api/system/update/log` every 1.5 s, auto-scrolls, colour-codes
  `[UPDATE]` lines (green) and `[UPDATE ERROR]` (red). Stops polling when backend reports `running: false`.
- **Environment Config tab**: sidebar with 6 targets (global, cysiemstack, cyiris, cysoar, cymisp, cysiem).
  Reads env file via `GET /api/system/env/<target>`; secrets masked as `•••••••• (protected)`, non-editable.
  Dirty-change tracker counts unsaved keys; `PUT /api/system/env/<target>` writes changes with
  shell-injection prevention on both keys and values.

**Asset geo-location world map (WorldMapWidget.jsx, AssetsPage.jsx)**
- Equirectangular SVG world map (800 × 380 viewBox) with simplified continent outlines and latitude/longitude
  grid lines — zero npm dependencies.
- Primary asset IPs resolved to `{lat, lon, country, city, flag}` via `POST /api/system/geoip` (backend
  proxies to `ipwho.is`, skips RFC-1918 private ranges, in-process cache avoids repeat lookups).
- Risk-coloured pulsing dots on map; co-located IPs aggregated into a count badge.
- Hover tooltip shows hostname, IP, city, country flag; "Refresh" button re-fetches geo data.
- Map inserted above the asset table in `AssetsPage.jsx`.

**Backend endpoints (blueprints/system/routes.py)**
- `GET  /api/system/version` — version string + last 5 `## v` blocks from RELEASE_NOTES.md.
- `POST /api/system/update`  — validates CS_TOKEN format, spawns update script, streams stdout.
- `GET  /api/system/update/log` — `{running, log}` payload for frontend polling.
- `GET  /api/system/env/<target>` — read env file; masked secrets.
- `PUT  /api/system/env/<target>` — write env file; injection-safe validation.
- `POST /api/system/geoip` — batch IP → geo resolver with cache.

**Nav sidebar renames (navConfig.jsx)**
- Dashboard → Threat Overview
- Assets → Asset Inventory
- Vulnerabilities → Findings
- CySIEM Feed → Alert Feed
- Incidents → Active Incidents
- Risk Scores → Entity Risk
- UEBA → Behaviour Analytics
- New Scan → Run Scan
- Modules → Platform Modules

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
