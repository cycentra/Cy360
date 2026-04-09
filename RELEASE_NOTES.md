# CyCentra 360 — Release Notes

---
## v1.0.101 — 2026-04-10

### Fix — System Update: GH_TOKEN Now Read from `.env` at Call-Time + Revert to Direct Download URL

**Root cause:** `_get_server_gh_token()` relied solely on `os.environ.get("GH_TOKEN")`.
This is set once when the Flask process starts — if `/opt/cycentra/.env` contained `GH_TOKEN`
but the process was started without it already loaded (e.g., `source .env` not run before
`systemctl start cycentra-portal`), the function returned an empty string, which caused
every `curl` call to fail with **404** on the private GitHub repo (GitHub treats unauthenticated
requests to private assets as 404, not 401).

**Fixes — `backend/blueprints/system/routes.py`:**

- **`_get_server_gh_token()` rewritten to read `/opt/cycentra/.env` directly at call-time.**
  Parses the file line-by-line looking for `GH_TOKEN=...`, strips surrounding quotes, and returns
  the value. Falls back to `os.environ` for dev/container environments without the file.
  This means the token is always picked up even if `.env` was edited or the token was added
  after the Flask service started — no service restart required.

- **`_run_setup_in_background()` reverted to the confirmed-working direct URL approach.**
  The GitHub API 2-step resolution added in v1.0.100 was unnecessary once the token is
  correctly loaded. The function now matches the working manual command exactly:
  ```
  curl -fsSL -H "Authorization: Bearer $GH_TOKEN" \
    https://github.com/cycentra/cycentra360/releases/latest/download/cycentra-setup.sh \
    -L -o /opt/cycentra/cycentra-setup.sh
  sudo -E bash /opt/cycentra/cycentra-setup.sh --update
  ```
  - Token is read **inside the background thread** (not before it starts) so it always reflects
    the most current value in `.env`.
  - Clear error message logged when `GH_TOKEN` is absent:
    `[UPDATE ERROR] GH_TOKEN not found — add GH_TOKEN=ghp_... to /opt/cycentra/.env`

---
## v1.0.100 — 2026-04-09

### Fix — System Update: Private-Repo Asset Download 404

**Root cause:** `curl -fsSL -H "Authorization: Bearer $TOKEN" https://github.com/.../releases/latest/download/FILE`
works for public repos but fails with 404 on private repos. When GitHub redirects the browser URL
to a CDN, curl drops the `Authorization` header on cross-domain redirects (standard security behaviour).
The CDN receives an unauthenticated request and returns 404.

**Fix — `backend/blueprints/system/routes.py` — `_run_setup_in_background()`:**
- **Step 1:** Call `https://api.github.com/repos/cycentra/cycentra360/releases/latest` (with
  `Authorization: Bearer` + `Accept: application/vnd.github+json`) to resolve the latest published
  release and find the `cycentra-setup.sh` asset entry. Provides actionable error messages for:
  - HTTP 401 → GH_TOKEN invalid/expired
  - HTTP 404 → no published release found (CI hasn't run yet for this tag)
  - Asset missing → lists available assets so the operator can diagnose
- **Step 2:** Download via `asset["url"]` (`api.github.com/repos/.../releases/assets/{id}`)
  with `Accept: application/octet-stream`. The GitHub API handles authentication before any CDN
  redirect — the token never reaches a third-party domain.
- Removed the old `github.com/releases/latest/download/` direct URL approach entirely.

---

## v1.0.99 — 2026-04-09

### Feature — CyIRIS (DFIR IRIS) Integration: Incident Escalation, Auto-Close & Ticket Lifecycle Sync

**Overview:**
Full end-to-end integration between the CySIEM Correlation Engine and DFIR IRIS (CyIRIS).
Incidents with a low false-positive confidence score are automatically escalated to DFIR IRIS
as tickets. Incidents with a high FP confidence score (configurable threshold, default 90%) are
auto-closed without raising a ticket. When an analyst closes a ticket in DFIR IRIS, the
corresponding incident is automatically closed in cycentra360. The dashboard shows ticket
status and a direct deep-link into CyIRIS.

---

**`backend/cysiemstack/correlation_engine/iris_connector.py` — New file:**
- `create_iris_case()` — POSTs a fully enriched case to DFIR IRIS `/api/v2/cases`; includes
  incident ID, severity, MITRE ATT&CK IDs, affected hosts/users, MISP IOC hits, and AI narrative
  from the LLM enricher; stores returned `case_id`, `case_url`, `case_status` on the Incident
- `get_iris_case_status()` — GETs `/api/v2/cases/{id}` and returns `"open"` or `"closed"`
- `sync_closed_cases()` — batch poller; fetches all open IRIS-linked incidents and closes any
  whose IRIS case is now closed; called every 5 minutes by `_iris_sync_scheduler`
- `auto_close_fp()` — closes an incident as false positive if `confidence_score >= iris_fp_threshold`;
  writes `false_positive_reason` with score and threshold for audit
- `_load_iris_config()` — reads `ai_settings.json` for mode (`disabled` / `cloud` / `local`);
  cloud mode reads `CLOUD_IRIS_URL` / `CLOUD_IRIS_API_KEY` from server env

**`backend/cysiemstack/correlation_engine/ingestor.py`:**
- Pipeline step 7 (after LLM enrichment): compute FP confidence score from rule confidence values;
  low-rule-confidence incidents score higher (more likely FP); no-rule incidents in low/medium
  severity get 70% FP score
- Calls `auto_close_fp()` first — if score ≥ threshold, incident is closed, no ticket raised
- If not auto-closed and incident is new or has new correlation rules, calls `create_iris_case()`
- WebSocket live event extended with `iris_case_id` and `iris_auto_closed` fields

**`backend/cysiemstack/correlation_engine/main.py`:**
- `_iris_sync_scheduler()` — polls `sync_closed_cases()` every 5 minutes; broadcasts
  `iris_cases_synced` WebSocket event when cases are closed
- `_incident_to_dict()` extended with `iris_case_id`, `iris_case_status`, `iris_case_url`,
  `confidence_score` fields — exposed via `GET /incidents` and `GET /incidents/{id}`

**`backend/cysiemstack/correlation_engine/models.py`:**
- `Incident` model: added `iris_case_id` (Integer), `iris_case_status` (Text),
  `iris_case_url` (Text), `confidence_score` (Numeric 5,1)

**`backend/cysiemstack/correlation_engine/config.py`:**
- Added `iris_mode`, `iris_url`, `iris_api_key`, `iris_enabled`, `iris_customer_id`,
  `iris_fp_threshold` (default 90.0) to Settings

**`backend/cysiemstack/correlation_engine/requirements.txt`:**
- Added `httpx==0.27.2` (was used by `misp_enricher.py` but missing from requirements)

**`backend/cysiemstack/.env.example`:**
- Added `IRIS_MODE`, `IRIS_ENABLED`, `IRIS_URL`, `IRIS_API_KEY`, `IRIS_CUSTOMER_ID`,
  `IRIS_FP_THRESHOLD` with inline documentation

**`backend/blueprints/system/routes.py`:**
- `_sync_iris_to_siem_env()` — mirrors `_sync_misp_to_siem_env()`; writes resolved CyIRIS
  config (mode-aware: cloud reads from env, local uses user-entered values) into
  `cysiemstack.env` on every portal Save action
- `POST /api/ai/settings` — `iris` added to allowed top-level keys; `iris.apiKey` masked
  in GET response; api key guard prevents overwriting with masked placeholder on re-save
- `POST /api/system/iris/test` — test endpoint; calls IRIS `/api/ping` then `/api/versions`
  to confirm auth and return version string; OPTIONS preflight handled

**`backend/core/helpers.py`:**
- `get_iris_config()` — mirrors `get_misp_config()`; single source of truth for CyIRIS
  connection parameters; returns `url`, `apiKey`, `customerId`, `fpThreshold`, `mode`

---

**`portal/src/pages/settings/SystemSettingsPage.jsx` — `CyIrisTab` (new) + `IntegrationsTab` (new):**
- `CyIrisTab` follows identical design pattern to `MispTab`:
  - Three-mode card selector: **No CyIRIS** / **Cloud CyIRIS** (cyiris.cycentra.com) / **Local CyIRIS**
  - Cloud mode: informational card, no user input required
  - Local mode: URL field, API Key (password), Customer ID (numeric), Test Connection button
    with inline pass/fail feedback; helper text guides user to find API key and Customer ID in IRIS
  - **False Positive Auto-Close Threshold slider** (50–99%, default 90) — always visible
    regardless of mode; shows live percentage; explains auto-close vs escalation behaviour
  - Save persists to `ai_settings.json` via `POST /api/ai/settings`; triggers
    `_sync_iris_to_siem_env()` server-side
- `IntegrationsTab` wrapper renders MispTab + divider + CyIrisTab in a single scrollable view
- Tab render updated: `{tab === "integrations" && <IntegrationsTab />}`

**`portal/src/siem/SiemIncidentsPage.jsx`:**
- Incidents list **INTEL column**: new `🎫 IRIS` badge (blue = open ticket) / `✓ IRIS` badge
  (green = ticket closed by analyst); clicking badge opens IRIS case in new tab
- `IncidentDrawer` header: **FP Score** displayed next to Risk score (orange if ≥ 90%)
- `IncidentDrawer` body: new **🎫 CYIRIS TICKET** section between MISP hits and AI Narrative:
  - Shows case number, open/closed status badge, descriptive message
  - "↗ Open in CyIRIS" button deep-links to the exact case in IRIS UI
  - If no ticket: shows "No ticket raised" message for non-closed incidents

---

## v1.0.98 — 2026-04-09

### Feature — Updates & Version Tab: Server-Side GH_TOKEN + Run Upgrade Button

**Overview:**
The PAT / GH_TOKEN input field has been removed from the Updates & Version UI.
The token is now read exclusively from the server's `/opt/cycentra/.env` file, eliminating
the need for customers to paste credentials into the portal. A new **Run Upgrade** button
sits next to Run Update and triggers a full re-installation rather than an incremental patch.

**`portal/src/pages/settings/SystemSettingsPage.jsx` — `UpdatesTab`:**
- Removed `ghToken` state and `localStorage` persistence; no token input field displayed
- Added `upgrading` state tracking (mirrors existing `updating`)
- Added `handleUpgrade()` — calls `POST /api/system/upgrade`; polls live log
- `handleUpdate()` — version check via `GET /api/system/latest-version` (no query params);
  then calls `POST /api/system/update` with empty JSON body
- Two side-by-side action cards:
  - **RUN UPDATE** (green) — incremental patch via `cycentra-setup.sh --update`
  - **RUN UPGRADE** (orange) — full re-installation via `cycentra-setup.sh` (no flags)
- Footer note: "GitHub credentials are configured server-side in `/opt/cycentra/.env` — no token entry required."
- Live log header shows `UPGRADE` or `UPDATE` label dynamically

**`backend/blueprints/system/routes.py`:**
- New `_get_server_gh_token()` helper — reads `GH_TOKEN` from `os.environ`; returns `None`
  if unset; callers return HTTP 400 with a descriptive message guiding the operator to `.env`
- New `_run_setup_in_background(flags: list[str], label: str)` — downloads the latest
  `cycentra-setup.sh` from GitHub Releases using Bearer auth, then executes
  `sudo -E bash /opt/cycentra/cycentra-setup.sh [flags]` in a background thread while
  streaming output lines into the shared `_update_log` buffer
- `POST /api/system/update` rewritten: reads token from server env; no request body
  fields consumed; calls `_run_setup_in_background(["--update"], "UPDATE")`
- **New** `POST /api/system/upgrade` endpoint: calls `_run_setup_in_background([], "UPGRADE")`
  — runs the full setup script without `--update`, performing a complete re-installation
- `GET /api/system/latest-version` updated: token now sourced from `_get_server_gh_token()`
  instead of `request.args.get("ghToken")`

**`cycentra-setup.sh`:**
- Added `GH_TOKEN=${GH_TOKEN:-}` to the generated `/opt/cycentra/.env` template so the
  token is persisted at install time and automatically loaded by the systemd service via
  `EnvironmentFile=/opt/cycentra/.env`

---
## v1.0.97 — 2026-04-09

### Feature — MISP 3-Mode Selector: Disabled / Cloud CyMISP / Local CyMISP (single source of truth)

**Overview:**
Customers can now choose how MISP threat intelligence is delivered across all modules.
The choice is made once in System Settings → Integrations and applies uniformly to
CySIEM Correlation Engine, ASM Deep Scans, CySOAR, and CyIRIS.

**`portal/src/pages/settings/SystemSettingsPage.jsx`:**
- `MispTab` replaced the simple enable/disable checkbox with a **3-button mode selector**:
  - **Disabled** — all MISP IOC lookups bypassed everywhere; no credentials required
  - **Cloud CyMISP** — connects to `misp.cycentra.com` using pre-provisioned credentials
    embedded in the server `.env`; no URL or key input required from the customer
  - **Local CyMISP** — customer's own MISP instance; URL + API Key fields + Test Connection
    button remain as before
- Backward-compatible: existing configs with `enabled: true` are migrated to `mode: "local"` automatically on load
- Save button confirmation updated to: "✓ Saved — all modules updated"

**`backend/core/helpers.py`:**
- New `get_misp_config() → dict | None` function — **single source of truth** for all modules
  that need to talk to MISP.  Reads `misp.mode` from `ai_settings.json` and resolves:
  - `"cloud"` → URL from `CLOUD_MISP_URL` env, key from `CLOUD_MISP_API_KEY` env
  - `"local"` → URL + key from `ai_settings.json`
  - `"disabled"` → returns `None` (callers should skip all MISP operations)

**`backend/blueprints/system/routes.py`:**
- `_sync_misp_to_siem_env()` updated: now writes `MISP_MODE`, resolves effective URL/key
  for all three modes (cloud credentials from env, local from ai_settings.json, disabled
  clears all), then writes to `cysiemstack.env`
- New `GET /api/system/misp-config` endpoint: returns resolved MISP mode + URL (no API key)
  for integration by CySOAR / CyIRIS / external modules

**`backend/cy_asm/cycentra_scan.py`:**
- `_get_misp_config()` now delegates to `core.helpers.get_misp_config()` instead of reading
  `ai_settings.json` directly — honours all three modes including Cloud CyMISP

**`backend/cysiemstack/correlation_engine/config.py`:**
- Added `misp_mode: str = "disabled"` pydantic field — loaded from `cysiemstack.env` for
  informational use; effective connection parameters (url + key) are always resolved
  by `_sync_misp_to_siem_env()` before the correlation engine reads them

**`cycentra-setup.sh`:**
- `CLOUD_MISP_URL=https://misp.cycentra.com` and `CLOUD_MISP_API_KEY=` added to the
  generated `/opt/cycentra/.env` template — the API key is populated from the
  `CLOUD_MISP_API_KEY` environment variable at install time (vendor-provisioned per tenant)

---
## v1.0.96 — 2026-04-09

### Feature — UI Enhancement Batch: Navigation Restructure, AI Config Tab, Env Masking, Configured Indicators, Vulnerability Remediation Steps

**`portal/src/sidebar/navConfig.jsx`:**
- Section renamed "MONITOR" → "THREAT INTELLIGENCE"
- "Threat Overview" tab renamed → "External Threat Overview"
- New **CORRELATION ENGINE** sidebar section added: Active Incidents (🔥), Entity Risk (⚡), Behaviour Analytics (👤)
- "AI Settings" removed from PLATFORM nav — replaced by AI Config tab in System Settings

**`portal/src/pages/ai/AISettingsPage.jsx`:**
- **Module URL Overrides section removed** — no longer exposed in UI
- Added `embedded={true}` prop to hide page header when rendered inside System Settings
- Added `useEffect` to fetch `GET /api/ai/settings` on mount; masked keys (`••••••••`) indicate previously configured state
- "✓ AI provider previously configured" green banner shown when API key is present
- `_BASE_DOMAIN` import removed

**`portal/src/pages/settings/SystemSettingsPage.jsx`:**
- New **AI Config** tab added (renders AISettingsPage in embedded mode)
- `aiConfig` and `onSaveAIConfig` props accepted from App.jsx
- **GH Token now persisted** to `localStorage("cycentra_gh_token")` — no re-entry needed across sessions
- **Sensitive env var masking**: `EnvVarRow` auto-detects keys matching `PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL` and renders as password input with show/hide toggle; label shown in amber
- MISP "✓ MISP previously configured and active" banner shown in Integrations tab when url + apiKey are set

**`portal/src/pages/vulnerabilities/VulnerabilityPage.jsx`:**
- Recommendations replaced with structured **"🛠 Steps to Remediate"** card per finding
- Multi-step recommendations parsed (numbered list or semicolon-separated) and shown as individual steps
- Inline commands/paths highlighted in monospace code style
- CVE IDs extracted from vulnerability name and linked to NVD (`nvd.nist.gov`)
- Port and CVE metadata shown per finding row

**`portal/src/pages/assets/WorldMapWidget.jsx`:**
- Map header now shows **total asset count + location count**: `N assets · M locations mapped` (was just "M locations mapped")

**`portal/src/App.jsx`:**
- `ai-settings` tab redirected to `system-settings` (AI Config is now a tab there)
- `aiConfig` and `onSaveAIConfig` props passed through to `SystemSettingsPage`

---
## v1.0.95 — 2026-04-14

### Fix — Removed duplicate "CySIEM Engine" from Environment Config dropdown

**`portal/src/pages/settings/SystemSettingsPage.jsx`:**
- Removed duplicate `{ id: "cysiem", label: "CySIEM Engine" }` entry from `ENV_TARGETS` array
- Removed corresponding `"cysiem"` entry from `_ENV_FILE_MAP` — was pointing to same path as another target, causing duplicate dropdown option

---
## v1.0.94 — 2026-04-13

### Fix — MISP UI configuration now syncs to cysiemstack.env automatically

**`backend/blueprints/ai/routes.py`:**
- `POST /api/ai/settings`: after saving `ai_settings.json`, calls `_sync_misp_to_siem_env()` which writes `MISP_URL`, `MISP_KEY`, `MISP_ENABLED` into `cysiemstack.env`
- Fixes issue where MISP settings configured from UI were not reaching the correlation engine

---
## v1.0.93 — 2026-04-11

### Fix — Update button immediately exits ("already at latest") due to version comparison bug

**`backend/blueprints/system/routes.py`:**
- `GET /api/system/latest-version`: version pre-check was comparing installed package version against `_SCRIPT_VERSION` constant (always matching) instead of resolving live version from GitHub Releases (`CYCENTRA_VERSION`). Fixed to compare against the resolved release tag.

---
## v1.0.92 — 2026-04-10

### Fix — Black screen on AI Settings page (orphaned MISP JSX reference)

**`portal/src/pages/ai/AISettingsPage.jsx`:**
- Removed orphaned MISP JSX block that referenced `misp` state which was no longer initialised after MISP was moved to System Settings in v1.0.90
- Fixes `TypeError: Cannot read properties of undefined` causing a blank white/black screen when navigating to AI Settings

---
## v1.0.91 — 2026-04-09

### Fix — Run Update migrated from Cloudsmith to GitHub, release notes now in bundle

**`portal/src/pages/settings/SystemSettingsPage.jsx`:**
- Token field renamed "Cloudsmith Token (CS_TOKEN)" → "GitHub Personal Access Token (GH_TOKEN)", placeholder `ghp_xxxx`
- Validation error updated: "Enter your GitHub Token (GH_TOKEN) first"
- `csToken` state/body key/query param renamed to `ghToken` throughout

**`backend/blueprints/system/routes.py`:**
- `POST /api/system/update`: reads `ghToken`, passes `GH_TOKEN` env var to setup script (was `CS_TOKEN`)
- `GET /api/system/latest-version`: replaced Cloudsmith partial-download with GitHub Releases API (`GET /repos/cycentra/cycentra360/releases/latest`) — fast, no bundle download, handles 401 explicitly
- Log redaction updated: Cloudsmith URL pattern replaced with GitHub PAT pattern (`ghp_`/`github_pat_`)

**`.github/workflows/deploy.yml`:**
- `cp RELEASE_NOTES.md cycentra-release/` added to bundle build — fixes release notes not appearing in System Settings after server update

---
## v1.0.90 — 2026-04-09

### Fix + Feature — MISP moved to System Settings, test connection, AI enrichment DB columns

**`portal/src/pages/settings/SystemSettingsPage.jsx`:**
- New **Integrations** tab added between "Updates & Version" and "Environment Config"
- Full MISP Threat Intelligence card moved here: enable toggle, MISP Server URL, API Key, **Test Connection** button, status indicator, Save
- Test Connection calls `POST /api/system/misp/test` and shows live result (✓ MISP version or ✗ error reason)

**`portal/src/pages/ai/AISettingsPage.jsx`:**
- MISP card and `misp` state removed — configuration is now exclusively in System Settings → Integrations
- No functional change to AI provider, prompts, or CyMind Episodic Memory sections

**`backend/blueprints/system/routes.py`:**
- New `POST /api/system/misp/test` endpoint — tests MISP connectivity via `GET /servers/getPyMISPVersion.json`; handles 403 (bad key), SSL errors, timeouts, and connection failures with specific messages

**`backend/cysiemstack/postgres/migrations/002_ai_enrichment.sql`:**
- New migration: `ALTER TABLE incidents ADD COLUMN IF NOT EXISTS llm_summary`, `llm_remediation`, `llm_generated_at`, `misp_enrichment`
- Fixes existing installations where the incidents table was created before these columns were added to `init.sql`

**`cycentra-setup.sh`:**
- DB migration step now also applies any `*.sql` files found inside the installed Python package (`site-packages/cysiemstack/postgres/migrations/`), covering upgrades where the bundle didn't ship a `db/migrations/` directory
- All migration files are idempotent — safe to re-run

---## v1.0.82 — 2026-04-09

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
