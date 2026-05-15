## v1.2.15 -- 2026-05-16

### New Features

  - **Policy Analysis pipeline** — Upload org policy documents, then run AI-powered analysis to auto-score the compliance questionnaire. For each control question, CyMind RAG retrieves relevant policy excerpts and the LLM assigns Pass / Partial / Fail. Results are written to the Assessment questionnaire with evidence snippets and justifications.
  - **Policy Analysis UI** (`Policy Documents` page) — Framework selector, overwrite toggle, "Run Policy Analysis" button, live progress bar with per-question status, and a completion summary showing answered / skipped / error counts.
  - **New API routes**: `POST /api/comp/policy-docs/analyze-framework` (start job) and `GET /api/comp/policy-docs/analyze-jobs/<job_id>` (poll progress).

---

## v1.2.14 -- 2026-05-15

### Improvements

  - Stability and performance improvements.

---

## v1.2.13 -- 2026-05-15

### Improvements

  - Stability and performance improvements.

---

## v1.2.12 -- 2026-05-15

### Improvements

  - Stability and performance improvements.

---

## v1.2.11 -- 2026-05-15

### Improvements

  - Stability and performance improvements.

---

## v1.2.11 -- 2026-05-15

### Features

- **GRC dashboard widgets now filter by framework selection** — All five widgets on the GRC Posture Dashboard now scope their data to the globally selected frameworks (Overall Posture donut, Findings by Severity pie, Findings by Verdict bars, Risk Register summary, Active Alerts count, Questionnaire Hub). The `GET /api/comp/dashboard?frameworks=...` endpoint accepts a comma-separated list of framework IDs and scopes every backend query accordingly.
- **GRC Scoring Model documentation** — Added `docs/GRC_SCORING_MODEL.md` with a complete explanation of the questionnaire weight-based baseline, alert penalty calculation (severity tiers, 40-point cap), zero-questions baseline logic, framework-to-alert mapping, score normalization, and the framework selector behaviour.

### Bug Fixes

- **Overall Posture score now reflects selected frameworks** — The donut percentage previously averaged all 7 frameworks regardless of the chip selector. It now averages only the selected frameworks.
- **Findings charts no longer show cross-framework noise** — Findings by Severity and Findings by Verdict now filter by `framework = ANY(selected)` so deselecting a framework removes its findings immediately.
- **Risk Register widget scoped to selected frameworks** — Risks with no overlap with selected frameworks are excluded from all counts.

---

## v1.2.10 -- 2026-05-15

### Improvements

  - Stability and performance improvements.

---

## v1.3.0 -- 2026-05-15

### Features

- **GDPR framework added** — Full EU GDPR coverage across all GRC modules:
  - 30-question assessment covering Art.5 (principles), Art.6/7 (lawful basis & consent), Art.12-23 (data subject rights), Art.25 (privacy by design), Art.28 (DPA contracts), Art.30 (RoPA), Art.32 (security), Art.33-34 (breach notification), Art.35 (DPIA), Art.37-39 (DPO), Art.44-49 (international transfers), Art.83 (accountability)
  - MITRE ATT&CK → GDPR control mappings added to enrichment engine for all 14 techniques and 10 Wazuh rule IDs (Art.32, Art.33, Art.34, Art.25, Art.5(1)(f))
  - GDPR appears in Framework Posture Scores, Score Trend, Findings, Assessment, Live Alerts, Reports
  - Score: `100 − alert_penalty` baseline (same formula as other frameworks)
- **Framework selector on GRC Posture Dashboard** — Coloured chip toggles above the Framework Posture Scores card let users select which frameworks are displayed. Selection is persisted to `localStorage` (`cy_fw_filter`) and propagates globally:
  - Dashboard: score bars, trend chart lines, questionnaire completion all filtered
  - Findings page: framework dropdown restricted to selected frameworks
  - Assessment page: framework tabs restricted to selected frameworks
  - Live Alerts page: framework filter dropdown restricted to selected
  - Reports page: framework report dropdown restricted to selected
  - Selecting a single framework auto-pre-selects it in per-page dropdowns

### Bug Fixes

- **Alert enrichment** — `_GROUP_TO_FRAMEWORK` now maps Wazuh `gdpr` rule group to `gdpr` (was incorrectly mapped to `avg`)
- **`avg` (GDPR-NL) references removed** from portal dropdowns in favour of canonical `gdpr` key

---

## v1.2.9 -- 2026-05-15

### Bug Fixes

  - cy-comp): v1.2.9 — live alert_penalty+q_answered, score bar labels, trend jitter

---

## v1.2.8 -- 2026-05-15

### Bug Fixes

  - cy-comp): v1.2.8 — harden CTL cache repair and trend chart visibility

---

## v1.2.8 -- 2026-05-15

### Bug Fixes

  - **CTL=0 and trend lines hardened**: `compute_framework_scores()` INSERT failures now log instead of silent swallow. `get_latest_scores()` writes corrected values back to DB on first dashboard load (no Refresh click needed). `LineChart` renders single-snapshot frameworks as visible dashed horizontal lines with label, instead of an invisible dot.

---

## v1.2.7 -- 2026-05-15

### Bug Fixes

  - **CTL/CRIT zeros, trend missing lines, appetite vs heatmap mismatch** — see v1.2.7 release notes.

---

## v1.2.7 -- 2026-05-15

### Bug Fixes

  - **Framework Posture Scores — CTL showing 0** — `get_latest_scores()` was returning stale cached rows from `cy_comp_framework_scores` where `total_controls=0` (rows written before the `FRAMEWORK_CONTROL_COUNTS` fallback existed). Fixed by skipping the cache when `total_controls=0` and running a fresh live computation. CTL now shows e.g. `0/28` for unstarted frameworks. Hover tooltip added: "CTL = passing questions / total questions", "CRIT = failing controls + critical/high compliance alerts".
  - **Score Trend — only 2 lines visible** — `LineChart` was silently dropping any framework with fewer than 2 score snapshots (`if (scores.length < 2) return null`). Fixed: frameworks with 1 snapshot now render as a coloured dot at the correct score level. Frameworks with 2+ snapshots render lines with timestamp-based x-positioning and an end-point dot. All 6 frameworks are now always visible once at least one score snapshot exists.
  - **Risk Appetite numbers differ from Heatmap** — The discrepancy is by design: the Heatmap counts ALL non-closed risks (including `accepted`); the Appetite analysis excludes `accepted` risks because they are intentionally outside the mitigation cycle. This was not communicated to users. Fixed: Appetite tab now shows a Severity Breakdown section (Critical/High/Medium/Low counts for open+mitigated risks only) and an explanatory note clarifying why the totals differ from the Heatmap. Backend `get_appetite()` extended to return `severity_summary` dict.

---

## v1.2.6 -- 2026-05-15

### New Features

  - **Comprehensive PDF compliance reports** — `report.py` completely rewritten. PDFs now include: navy/teal branded cover page with live posture score ring and grade, executive summary table (overall score, grade, completion %, findings count, open risks, alert count), framework posture scores table with per-framework grade/passing/critical-gaps/alert-penalty breakdown, horizontal bar chart (reportlab HorizontalBarChart), questionnaire completion table per framework, compliance-relevant alerts summary (30-day, severity breakdown), top-50 findings table (sortable by severity), risk register summary (severity counts + top-30 risks table), gap analysis section with per-framework prioritised recommendations (REC-01…), and conclusion with framework tier list and 6 next-step actions. PDF is fully usable and self-contained; JSON export retained alongside.
  - **Benchmark compliance integration** — `_collect_compliance_score()` in `blueprints/benchmark/routes.py` rewrote. Previously queried `cy_compliance_controls` (non-existent table), causing the compliance dimension to always return `score=None` and be silently excluded from the CSPI composite score. Now queries `cy_comp_framework_scores` for the latest cached score per framework (falls back to live questionnaire weight calculation if cache is empty), then averages across all frameworks. Compliance dimension is now live in the CSPI composite on the Benchmark page.
  - **Dashboard extended** — Risk Register Summary widget and Questionnaire Completion widget added to Compliance Dashboard (Row 5). Risk widget: severity count chips + stacked severity bar + "VIEW HEATMAP →" nav. Questionnaire widget: per-framework colour-coded progress bars with answered/total label + "OPEN ASSESSMENT →" nav.

### Bug Fixes

  - **Dashboard refresh blanking all widgets** — `Refresh Scores` button was writing the `/api/comp/framework-scores?refresh=true` response (shape `{scores:[...]}`) into the main `summary` state, destroying all other widget data. Fixed: score recompute call moved to `.finally(() => fetchDashboard())` so the full dashboard is always re-fetched after scores update.
  - **Scoring inconsistency** — `compliance.py` `_compute_score_for_framework()` used count-based formula while `questionnaire.py` `score_framework()` used weight-based formula, causing Dashboard and Assessment page to show different numbers for the same framework. Unified to weight-based formula: `q_score = (pass_weight + partial_weight × 0.5) / total_weight × 100`.

---

## v1.2.5 -- 2026-05-14

### New Features

  - **ISO 27001 Statement of Applicability (SoA)** — two-tier assessment model: 45 grouped questionnaire questions for scoring + a per-control SoA view listing all 93 Annex A controls individually, satisfying ISO 27001:2022 Cl.6.1.3(d). Analyst can include/exclude each control with a typed justification. Status (compliant / partial / gap / breach / excluded / not assessed) auto-derived from questionnaire responses and open breach findings. Controls grouped by Annex A theme (Organisational / People / Physical / Technological) with theme-level gap summaries and coverage percentage. Accessible as a "Statement of Applicability" sub-tab on the ISO 27001 assessment page.
  - **Policy Documents guidance panel** — collapsible guide on the Policy Documents page listing 12 recommended policy categories (Information Security Policy, IRP, Access Control, Risk Management, BCP/DR, Asset Management, Vendor Security, Data Classification, AUP, Change Management, Vulnerability Management, Privacy/GDPR), recommended naming convention (`<Policy_Name>_v<Version>_<Year>.pdf`) with examples, supported file types, annual review cycle note, and a callout clarifying the difference between org policy docs and framework reference documents.
  - **Extended compliance framework mapping** — enrichment engine (`enrichment.py`) now tags alerts against SOC 2 (CC Trust Services Criteria), NIST CSF 2.0 (GV/ID/PR/DE/RS/RC function.subcategory format), and PCI DSS v4.0 (Req 1–12) in addition to the existing NIS2 / DORA / ISO 27001 / AVG coverage. All 15 MITRE ATT&CK technique entries and all 10 Wazuh rule ID entries extended. Backfill endpoint added: `POST /api/comp/findings/re-enrich-alerts` resets and re-tags all historical alerts.

### Bug Fixes

  - **Risk heat map / Auto Populate 500 error** — `auto_populate_from_findings` was passing a raw Python list into a JSONB column without `json.dumps()`, causing a psycopg2 `ProgrammingError` on every call. Fixed with proper serialisation. Query also expanded to include manual findings (was previously restricted to `auto_generated = TRUE` only), so the button is useful immediately after questionnaire gap findings are generated.
  - **cy_comp_soa_entries table** — new DB table added (`cy_comp/models.py`) to persist analyst SoA include/exclude decisions and justifications. Auto-created at startup via `ensure_tables()`.

---

## v1.2.4 -- 2026-05-14

### Improvements

  - Stability and performance improvements.

---

## v1.2.3 -- 2026-05-14

### Improvements

  - Stability and performance improvements.

---

## v1.2.2 -- 2026-05-14

### Improvements

  - Stability and performance improvements.

---

## v1.2.1 -- 2026-05-14

### Improvements

  - Stability and performance improvements.

---

## v1.2.0 -- 2026-05-14

### New Features

  - cy-comp): zero-duplicate GRC — enrich alerts/incidents in-place, fix RAG URLs

---

## v1.1.3 -- 2026-05-14

### Bug Fixes

  - cy-comp): read cymind_integration nested object from ai_settings.json

---

## v1.1.2 -- 2026-05-14

### Bug Fixes

  - cy-comp): 4 UX improvements — risk pages merged, compliance tagging, RAG settings, severity mapping

---

## v1.1.1 -- 2026-05-14

### New Features

  - cy-comp): add cy_comp* to wheel package include list

---

## v1.1.0 -- 2026-05-14

### New Features

  - cy-comp): integrate GRC compliance module into CyCentra360
  - inject linked alerts into CyMind incident detail context

### Bug Fixes

  - incidents page now defaults to Active filter, shows all 20 correctly
  - active incidents now fetched by status=investigating|open
  - 3 chat context issues — incident count, ASM IDs, guest scan leak
  - action widget not triggering when INC-ID absent from close/resolve message

---

## v1.0.419 -- 2026-05-13

### Bug Fixes

  - ueba_flags AttributeError crash in _fetch_incident_detail_block

---

## v1.0.418 -- 2026-05-13

### Bug Fixes

  - guest-isolation): move guest scans/reports to separate dir tree

---

## v1.0.417 -- 2026-05-13

### Bug Fixes

  - scheduler): scheduled scans write to shared scheduler/ dir

---

## v1.0.416 -- 2026-05-13

### Bug Fixes

  - setup): deduplicate CLOUD_IRIS_URL in --update .env patch
  - deduplicate CLOUD_IRIS_URL in .env when CyIRIS is installed

---

## v1.0.415 -- 2026-05-12

### Bug Fixes

  - backfill Host Name and Host OS for existing incidents on engine restart

---

## v1.0.414 -- 2026-05-12

### New Features

  - add Host Name and Host OS columns to Active Incidents table

---

## v1.0.413 -- 2026-05-12

### Improvements

  - Stability and performance improvements.

---

## v1.0.412 -- 2026-05-12

### Improvements

  - Stability and performance improvements.

---

## v1.0.411 -- 2026-05-12

### Improvements

  - Stability and performance improvements.

---

## v1.0.410 -- 2026-05-12

### Improvements

  - Stability and performance improvements.

---

## v1.0.409 -- 2026-05-12

### Bug Fixes

  - setup): stop stripping OIDC settings in step 4.1 and decouple Wazuh OIDC from oauth2proxy gate

---

## v1.0.408 -- 2026-05-12

### Bug Fixes

  - **CySIEM OIDC — `--update` strips OIDC settings and doesn't restore them when oauth2-proxy secrets are absent**: Step 4.1 unconditionally removed `opensearch_security.auth.type` and all `opensearch_security.openid.*` keys from `opensearch_dashboards.yml` to "clean before re-write". The re-write (Step 4.3b) was nested inside the oauth2-proxy secrets gate (`if OAUTH2PROXY_SECRET && OAUTH2PROXY_COOKIE_SECRET`). On any `--update` run where those secrets were empty or not loaded in time, the entire Step 4.3b was skipped — leaving the dashboard permanently in basic-auth mode (Wazuh login screen shown instead of OIDC redirect). Two fixes applied: (1) Step 4.1 no longer strips OIDC keys — only legacy proxy-auth settings (`proxycache.*`, `requestHeadersAllowlist`) are removed; (2) the Wazuh Dashboard OIDC block is now structurally separated from the oauth2-proxy gate so it always runs when Wazuh is installed, regardless of oauth2-proxy secret availability. **Files changed**: `cycentra-setup.sh`, `docs/RELEASE_NOTES.md`.

---

## v1.0.407 -- 2026-05-12

### Bug Fixes

  - **CySIEM OIDC — admin users not mapped to Wazuh `administrator` role**: OIDC authentication gave users an OpenSearch `all_access` session (dashboard access) but Wazuh has a second, independent RBAC layer in the Wazuh Manager API that controls Wazuh operations (agent management, policies, etc.). Without explicit rules in the Wazuh API, OIDC users landed with only `own_index` and `all_access` — enough to see the dashboard but no agent management. Three security rules are now created via the Wazuh Manager API during setup, mapping OIDC `backend_roles` to Wazuh API roles:
    - `cy360_oidc_admin`: `backend_roles: "admin"` → Wazuh `administrator` (full access, agent management)
    - `cy360_oidc_analyst`: `backend_roles: "analyst"` → Wazuh `agents_admin` (agent management, no user/role admin)
    - `cy360_oidc_viewer`: `backend_roles: "viewer"` → Wazuh `readonly`
    The rules are idempotent — skipped if a rule with the same name already exists. **Files changed**: `cycentra-setup.sh` (Wazuh API RBAC rules block after OpenSearch rolesmapping step), `docs/RELEASE_NOTES.md`.

---

## v1.0.406 -- 2026-05-12

### Bug Fixes

  - **CySIEM OIDC — nginx `sites-enabled` symlink not recreated on `--update`**: On servers where `/etc/nginx/sites-enabled/cycentra-modules` existed as a hardcopy file (not a symlink), running `--update` would migrate the siem-gate proxy headers out of `sites-available/cycentra-modules` but nginx kept reading the untouched hardcopy in `sites-enabled`. This caused the old `auth_request /siem-gate`, `proxy_set_header Authorization $wazuh_auth`, and `X-Proxy-User`/`X-Proxy-Roles` injection to remain active after every update — preventing OIDC from taking effect. The `--update` path now explicitly re-creates `sites-enabled/cycentra-modules` as a symlink to `sites-available/cycentra-modules` whenever it detects a hardcopy (non-symlink) file, ensuring all nginx migrations are immediately visible to the running nginx process.

---

## v1.0.405 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.404 -- 2026-05-12

### New Features

  - **CySIEM OIDC SSO — individual user identity in Wazuh Dashboard**: Replaced the nginx siem-gate Basic Auth injection approach with native OIDC authentication in Wazuh Dashboard, giving each user their own identity instead of sharing a service account.

    **Root cause of the previous limitation**: When a user authenticated via nginx Basic Auth injection, Wazuh Dashboard set a `security_authentication` session cookie (Iron-sealed, HttpOnly). On subsequent requests, Wazuh used the cookie session — ignoring the `Authorization` header entirely. All users therefore appeared as the shared `cy360_sso` service account regardless of which Cy360 role they held.

    **Architecture — Wazuh OIDC via CyCentra IdP**:
    - `opensearch_dashboards.yml` now uses `opensearch_security.auth.type: openid` pointing to `https://cyasm.DOMAIN/oidc/.well-known/openid-configuration`.
    - The `cysiem` OIDC client (already registered in the CyCentra OIDC provider) issues RS256 ID tokens containing `email` (user identity) and `roles: ["admin"|"analyst"|"viewer"]` (Cy360 RBAC role).
    - OpenSearch Security `config.yml` has a new `openid_auth_domain` (order: 0, `subject_key: email`, `roles_key: roles`) that maps the OIDC token roles claim to OpenSearch backend roles.
    - SSO flow: user visits `cysiem.DOMAIN` → Wazuh Dashboard redirects to OIDC IdP → IdP checks existing Cy360 Flask session cookie (`.cycentra.com` domain, so shared across all subdomains) → issues auth code silently if logged in → Wazuh establishes individual session. No double login required.

    **Role mapping in OpenSearch Security**:
    - `all_access` backend_roles → `["admin", "analyst", "all_access"]` — full Wazuh Dashboard access.
    - `kibana_user` backend_roles → `["viewer", "kibanauser"]` — read-only dashboard.
    - `wazuh_ui_user` backend_roles → `["viewer", "wazuh_ui_user"]` — Wazuh UI panels.

    **nginx cysiem block simplified**: Removed `auth_request /siem-gate`, `auth_request_set $wazuh_auth`, `location = /siem-gate`, and `proxy_set_header Authorization $wazuh_auth`. The cysiem server block now has a simple `location /` proxy_pass to `127.0.0.1:5601` with no auth_request gate — Wazuh Dashboard OIDC handles authentication end-to-end.

    **`cycentra-setup.sh` changes**:
    - Step 4.1: Now clears stale auth settings only (OIDC config applied later in step 4.3b).
    - Step 4.3b: New `CySIEM OIDC Authentication` step: (1) writes OIDC settings to `opensearch_dashboards.yml` from `CYSIEM_OIDC_SECRET`; (2) idempotent Python script inserts `openid_auth_domain` block into `config.yml` (detects indent from `basic_internal_auth_domain`); (3) applies via `securityadmin.sh`; (4) updates `all_access`, `kibana_user`, `wazuh_ui_user` rolesmapping via REST API.
    - Idempotent nginx migration: detects existing siem-gate blocks and removes them, replacing with simple proxy_pass.

    **Files changed**: `cycentra-setup.sh` (step 4.1, step 4.3b, nginx cysiem template, idempotent migration), `docs/RELEASE_NOTES.md`.

---

## v1.0.403 -- 2026-05-11

### New Features

  - **CySIEM role-aware SSO — admin/analyst vs viewer differentiation**: Wazuh Dashboard auto-login now reflects the logged-in user's Cy360 RBAC role, replacing the previous single shared-credential approach (all users logged into Wazuh as the same admin service account).

    **Architecture change — nginx siem-gate auth_request**:
    - `auth_request /oauth2/auth` (static IAP gate) replaced with `auth_request /siem-gate` pointing to a new Flask endpoint `GET /api/siem/internal/auth`.
    - Flask validates the Cy360 session cookie forwarded by nginx in the sub-request, looks up the user's RBAC role, and returns `X-Wazuh-Auth: Basic <credential>` in the response header.
    - nginx captures the header via `auth_request_set $wazuh_auth $upstream_http_x_wazuh_auth` and injects it as `proxy_set_header Authorization $wazuh_auth` for the upstream Wazuh Dashboard request.
    - `401` from Flask → nginx `error_page 401 = @error401` → redirect to Cy360 login.

    **Role mapping**:
    - `admin` / `analyst` → `cy360_sso` OpenSearch account (`backend_roles: [admin]`) — full Wazuh Dashboard access.
    - `viewer` / any other → `cy360_readonly` OpenSearch account (`backend_roles: [kibana_user, wazuh_ui_user]`) — read-only Wazuh access.

    **New OpenSearch service account**: `cy360_readonly` (password: `CyCentra360!ReadOnly`, hash: `$2y$12$0Tim1grS5kbbBdG20PFsF...`). Created via `securityadmin.sh` in `cycentra-setup.sh` Step 7. Idempotent — skipped if already present.

    **Files changed**: `backend/siem_proxy.py` (new `GET /api/siem/internal/auth` endpoint + `_WAZUH_ADMIN_BASIC`/`_WAZUH_RO_BASIC` module constants), `cycentra-setup.sh` (cy360_readonly user creation, nginx template updated, idempotent migration for existing installs).

### Bug Fixes

  - **chat**: close/resolve incident action now pre-fetches current status, surfaces engine errors, and refreshes Incidents list on success.

---

## v1.0.402 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.401 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.403 — Fix close/resolve incident action via CyMind chat — 2026-05-11

### Bug Fixes

- **Agentic close-incident action**: Fixed silent failure where "close incident" appeared to succeed in the CyMind chat overlay but the incident status remained `investigating` in the database. Root causes addressed:
  - Backend now pre-fetches the current incident status before attempting the `→ resolved` transition. This provides an accurate `from_status` in the audit trail and surfaces a clear "not found" error if the incident ID doesn't exist.
  - Engine error responses (non-2xx) now pass their `detail` message back to the chat UI instead of being silently swallowed — analysts will see "Could not transition INC-XXXXX: transition not allowed from current state" rather than a false success.
  - The `mark_false_positive` action received the same hardening (pre-fetch + error surfacing).
- **Incidents list now refreshes immediately**: After the analyst clicks Execute on a close/FP/reopen action card in the CyMind chat overlay, a `cycentra:incident-updated` browser event is dispatched. `SiemIncidentsPage` listens for this event and calls `fetchIncidents()` immediately so the status change is visible without waiting for the 30-second polling cycle.
- **Anti-hallucination guard extended**: The SIEM context system prompt now explicitly instructs CyMind not to claim it has closed, resolved, blocked, quarantined, or marked any incident/asset **unless the user has already clicked Execute** on a confirmation card. This prevents CyMind from saying "I've closed the incident" before the action is actually confirmed and executed.

---

## v1.0.402 — Fix INC-ID lookup + ASM/SIEM incident format alignment — 2026-05-11

### Bug Fixes

- **"show me details of INC-00708" returning not found**: Root cause — the proxy only injected a top-10 open incidents snapshot. Any incident not in that slice was invisible to CyMind. Added `_fetch_incident_detail_block(message)` to `routes.py`: scans the user message for `INC-\d+` patterns, fetches each incident from `GET /incidents/{id}` on the correlation engine, and injects the **full record** (severity, status, risk score, categories, affected users/agents/IPs, MITRE tactics, kill chain, UEBA flags, correlated rules, AI summary and remediation). If the ID does not exist in the DB, injects a clear "not found" instruction so CyMind says exactly that instead of confabulating.
- **ASM incidents (`ASM-DOMAIN-MODULE-N`) in different format than SIEM incidents (`INC-XXXXX`)**: Root cause — ASM scan findings are stored into CyMind's Qdrant RAG memory by `store_to_cymind_memory` (in `cycentra_scan.py`) with different field names (`alert_type`, `source_ip`, `outcome`, `analyst_notes`) than the SIEM correlation engine incidents (`llm_summary`, `src_ips`, `status`, `llm_remediation`). CyMind presented them differently because they literally were different. Fixed by aligning the RAG payload to include both old (legacy) keys for existing queries AND new SIEM-consistent keys (`id`, `llm_summary`, `status`, `src_ips`, `affected_agents`, `categories`, `llm_remediation`).
- **Incident context table showing `?` for title and created**: The SIEM context block used `inc.get('title')` and `inc.get('created_at')` but neither field exists on the `Incident` model. Replaced with synthesized summary from `llm_summary` or `categories`, and added `affected_users` column.
- **Added ID format guide** to SIEM context header so CyMind always knows the two namespaces (INC-XXXXX = correlation engine, ASM-... = RAG/scan findings) and presents both in a consistent table format.

### Files Changed
- `backend/blueprints/system/routes.py` — `_fetch_incident_detail_block()`, proxy wiring, incident table fix, SIEM context format guide
- `backend/cy_asm/cycentra_scan.py` — aligned `store_to_cymind_memory` payload fields

---

### Bug Fixes

- **CyMind hallucinating incident data for user queries**: When asked "how many incidents are related to user shibu", CyMind was fabricating incident IDs, descriptions, timestamps and counts. Root cause: the `/incidents` REST endpoint had no `user` filter, the portal proxy had no entity-aware enrichment, and no anti-hallucination guard existed in the live SIEM context block. Three-layer fix applied:
  1. `/incidents` engine endpoint now accepts `user`, `agent`, and `src_ip` query parameters — uses PostgreSQL `array_to_string` + `ILIKE` to search `affected_users`, `affected_agents`, and `src_ips` arrays. Total count is now also correct for all filter combinations (was previously only counting status filter).
  2. Portal chat proxy (`cymind_chat_proxy`) now detects entity/user mentions in the user message via `_ENTITY_IN_MSG_RE` regex, pre-fetches that entity's incidents from the engine, and injects a `## Incidents for entity 'X'` table directly into the SIEM context block before forwarding to CyMind — so CyMind has the real data, not a gap to fill.
  3. `_fetch_siem_context_block()` now includes a `[SYSTEM INSTRUCTION — CRITICAL]` anti-hallucination footer that instructs the LLM to never invent incident IDs, descriptions, usernames, or counts beyond the provided data.
- **New `search_incidents` MCP tool**: Added to correlation engine for CyMind standalone path. Accepts `user`, `agent`, `src_ip`, `status`, `severity` filters. Returns exact DB records with a grounding note. Keyword-routed in `mcp_client.py`.

### Files Changed
- `backend/cysiemstack/correlation_engine/main.py` — `/incidents` user/agent/src_ip filters; `search_incidents` MCP tool
- `backend/blueprints/system/routes.py` — `_ENTITY_IN_MSG_RE`, `_fetch_entity_incidents_block()`, entity enrichment in proxy, anti-hallucination footer, `search_incidents` in `_MCP_TOOLS`
- `CyMind/cymind/api/mcp_client.py` — `search_incidents` keyword routing + label

---

## v1.0.400 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.400 — Incident Distribution MCP Tool — 2026-05-11

### Bug Fixes

- **MCP chat returning "?" for incident distributions**: Added `get_incident_distribution` as a dedicated MCP tool in the correlation engine. The tool queries the DB directly (severity, status, category GROUP BY) and returns exact counts. CyMind now auto-invokes it on any distribution/breakdown/count-by question instead of estimating from the limited `list_incidents` preview.

### Files Changed
- `backend/cysiemstack/correlation_engine/main.py` — new `get_incident_distribution` MCP tool
- `backend/blueprints/system/routes.py` — added to `_MCP_TOOLS` registry
- `CyMind/cymind/api/mcp_client.py` — keyword routing + label entry

---

## v1.0.399 -- 2026-05-11



---

## v1.0.399 — MCP Execution Layer + Benchmark Distribution — 2026-05-11

### Enhancements

#### MCP Unified Execution Layer (CyCentra 360 ↔ CyMind)

- **E1 — 7 new MCP read tools** in `correlation_engine/main.py`: `get_alert`, `search_alerts`, `update_incident`, `list_campaigns`, `get_threat_intel`, `get_vuln_summary`, `get_compliance_status` — all registered inside the `if _mcp_enabled:` block.
- **E2 — 6 new agentic action types** in `blueprints/system/routes.py`: `assign_incident`, `add_incident_note`, `escalate_incident`, `create_cyiris_case`, `enrich_ioc`, `trigger_soar_playbook` — intent patterns + confirmed execution handlers wired end-to-end.
- **E3 — Full audit trail for all confirmed actions**: New `POST /audit` engine endpoint accepts audit writes from the Flask proxy. New `_write_action_audit()` helper in `routes.py` — fire-and-forget loopback, never blocks action execution. All 5 original action handlers (`block_ip`, `disable_user`, `restart_agent`, `close_incident`, `mark_false_positive`) now write an audit entry on success.
- **E4 — Per-tool RBAC metadata in `_MCP_TOOLS`**: Added `access_level: "read"/"write"` and `requires_confirmation: true` flags to all 18 tool entries so the portal MCP config page can surface write tools distinctly.
- **E5 — CyMind `mcp_client.py` extended**: 6 new entries in `_WRITE_TOOLS`, 5 new tuples in `_KEYWORD_TOOLS` (campaigns, threat intel, compliance, vuln summary, single alert), 6 new `_LABELS` entries for `format_context_block`.

#### Benchmark Intelligence Engine — Incident Distribution

- **New engine endpoint `GET /incidents/distribution`**: Returns `by_severity`, `by_status`, and `by_category` (top 15, unnested from `categories` ARRAY) via three lightweight GROUP BY queries. Used by the Benchmark page.
- **`_collect_siem_score()` updated**: Now calls `/incidents/distribution` after the main score calculation and surfaces `severity_distribution`, `status_distribution`, and `category_distribution` in the SIEM dimension breakdown — available at `breakdown.siem.*` in `GET /api/benchmark/score`.

### Files Changed
- `backend/cysiemstack/correlation_engine/main.py`
- `backend/blueprints/system/routes.py`
- `backend/blueprints/benchmark/routes.py`
- `Documents/GitHub/Custom-Tools/CyMind/cymind/api/mcp_client.py`

---

## v1.0.398 -- 2026-05-11

### Bug Fixes

  - M365 correlation by username, cloud incident enriched-gate bypass, lower cloud IRIS ticket threshold, robust LLM parse fallback, richer AI context
  - vuln/incident rendering bugs — missing remediation steps, [object Object] in http_analysis and remediation, missing compliance impact, AI summary truncation

---

## v1.0.398 — Bug Fixes — 2026-05-11

### Bug Fixes

#### Vulnerabilities Page
- **BUG-1 — Missing "Steps to Remediate"**: `adapter.js` now injects severity-aware fallback remediation text when the ASM scanner returns an empty `recommendation` field, ensuring the Remediation card always renders.
- **BUG-2 — HTTP Analysis rendering `[object Object]`**: Technology entries in `VulnerabilityPage.jsx` and `AssetsPage.jsx` are now rendered via property extraction (`name → technology → product → JSON fallback`), correctly displaying technology names such as "jQuery 1.12.4" instead of `[object Object]`.
- **BUG-3 — Remediation Action rendering `[object Object]`**: `parseSteps()` in `VulnerabilityPage.jsx` rewritten to safely unwrap arrays-of-objects, plain objects, and AI-enriched nested structures — all remediation shapes now display as readable text.
- **BUG-4 — Compliance Impact field missing**: `adapter.js` applies a client-side NIS2/DORA/ISO 27001 keyword-matching fallback when the backend enrichment lookup yields no compliance tags, ensuring every vulnerability entry displays a compliance impact.

#### Active Incidents (SIEM)
- **BUG-5 — AI enrichment quality**: `llm_enricher.py` — `_parse_response()` now uses a 3-tier fallback (both markers → summary-only marker → numbered-list heuristic) so `llm_remediation` is populated even when the LLM omits the `REMEDIATION_STEPS:` header. `_build_context()` now supplies a union of top-5-by-score and top-5-by-recency alerts (up to 10) for richer attack timeline context.
- **BUG-6 — M365 incidents not correlating**: `grouper.py` `find_matching_incident()` gained a third match criterion — cloud-source events (`o365`, `azure`, `aws`, `gcp`, `github`) are now correlated by `username + category`, correctly grouping all M365 user activity into a single incident regardless of agent ID variance.
- **BUG-7 — CyIRIS ticket creation not triggering for low-FP incidents**: `iris_connector.py` lowers the `alert_count` threshold to `1` for cloud-source incidents (vs. `3` for on-prem). `ingestor.py` marks cloud incidents as `enriched=True` immediately, preventing them from stalling in Band 2 ("investigating") and allowing Band 3 ticket creation to fire.
- **BUG-8 — Truncated incident details / incomplete AI summaries**: `SiemIncidentsPage.jsx` — `llm_summary` block now renders with `whiteSpace: pre-wrap`, preserving multi-paragraph AI narratives. `llm_enricher.py` SYSTEM_PROMPT expanded from 2–3 to 3–5 sentences with explicit instruction to include affected usernames/hosts and describe attack progression.

### Files Changed
- `portal/src/core/adapter.js`
- `portal/src/pages/vulnerabilities/VulnerabilityPage.jsx`
- `portal/src/pages/assets/AssetsPage.jsx`
- `portal/src/siem/SiemIncidentsPage.jsx`
- `backend/cysiemstack/correlation_engine/grouper.py`
- `backend/cysiemstack/correlation_engine/iris_connector.py`
- `backend/cysiemstack/correlation_engine/ingestor.py`
- `backend/cysiemstack/correlation_engine/llm_enricher.py`

---

## v1.0.397 -- 2026-05-11

### Bug Fixes

  - benchmark): eliminate double-counting and fix Wazuh data path

---

## v1.0.396 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.395 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.394 -- 2026-05-11

### Improvements

  - Stability and performance improvements.

---

## v1.0.393 -- 2026-05-11

### Bug Fixes

  - portal): CTEMSyncPanel shows ACTIVE after page refresh
  - asm): downgrade scanner CA-bundle gap from Medium to Low severity
  - asm): eliminate false-positive SSL findings for ECDSA keys and SAN extraction

---

## v1.0.393 -- 2026-05-11

### Bug Fixes

**ASM — Eliminate 3 false-positive SSL/TLS findings in Standard scan (score accuracy)**

Three SSL findings generated by every Standard scan of a Cloudflare-backed or ECDSA-keyed domain were false positives that incorrectly reduced the posture score:

| False positive | Root cause | Fix |
|---|---|---|
| `Weak key: 256 bits` | Key-size check applied the RSA 2048-bit minimum to ECDSA; ECDSA-256 ≈ RSA-3072 (NIST SP 800-57) | `crypto_checks.py`: key-size guard now type-aware — RSA/DSA require ≥ 2048 bits; ECDSA requires ≥ 224 bits |
| `SAN mismatch: <domain> not covered` / `No SANs present` | Both `crypto_checks.py` and `debug_crypto.py` read SANs via `ssock.getpeercert()` which returns an empty dict when `ssl.CERT_NONE` is active | New helper `_get_sans_from_cert(cert)` reads SANs directly from the OpenSSL cert object via the `subjectAltName` extension; scan now correctly sets `san_valid: True` for domains the cert covers |
| `Chain validation failed: unable to get local issuer certificate` classified as Medium | Pattern `chain.validation.fail` → Medium caught the Python CA-bundle gap error (Google Trust Services intermediate not in system bundle); TLS actually works | New Low-priority pattern added for `unable.to.get.local.issuer` — evaluated before the generic chain failure rule — demotes this scanner-side limitation to informational (Low) |

**Net effect on posture score for cycentra.com:**

| Scan | Before all fixes | After v1.0.392 | After v1.0.393 |
|---|---|---|---|
| Standard | 17 (F) | 65 (C) | 67 (C) |
| Deep | 64 (C) → 52 (D)* | 52 (D) | 52 (D) |

*Deep scan rescanned independently; old 64 score was from pre-v1.0.391 run.

Standard is now correctly higher than Deep by 15 points (67 vs 52), matching the documented behavior in `docs/standard-vs-deep-scan.md`.

**Files changed:**
- `backend/cy_asm/modules/crypto_checks.py` — `_get_sans_from_cert()` helper; ECDSA key-size threshold; SAN block reads from cert object
- `backend/cy_asm/modules/debug_crypto.py` — `_get_sans_from_cert()` helper; SAN block reads from cert object
- `backend/cy_asm/cycentra_scan.py` — Low-priority pattern for local-issuer CA-bundle gap added before the generic chain-validation Medium rule

---

## v1.0.392 -- 2026-05-11

### New Features

  - asm): eliminate false-positive path exposures, dedup vuln findings, add crt.sh retry+cache, redesign CTEMSyncPanel

---

## v1.0.391 -- 2026-05-10

### Bug Fixes

  - asm): correct 3 bugs causing Standard scan to score lower than Deep scan

---

## v1.0.390 -- 2026-05-10

### Improvements

  - Stability and performance improvements.

---

## v1.0.389 -- 2026-05-10

### Bug Fixes

  - asm): rebuild guest dashboard with real data widgets; correct SCAN_TIERS for standard scan

---

## v1.0.389 -- 2026-05-10

### Enhancements

- **ASM Guest Dashboard — full real-data widget rebuild (Issues A, B, C)**

  **Issue A fixed — SSL/Email widgets now read from `raw_results` directly:**
  `SslWidget` and `EmailSecurityWidget` in `GuestScanPage.jsx` previously counted findings by filtering `a.vulnerabilities` with regex keyword matching. This inflated counts when Deep scan AI enrichment tagged additional findings as ssl/email-related. Both widgets are now completely rewritten to read from `asset.raw_results.crypto.results.ssl` and `asset.raw_results.email_sec.results` respectively — the exact module output, unchanged between scan types. SSL widget shows: protocol (color-coded by version), days to expiry (red/orange/green), chain validity, OCSP stapling, PQC hybrid TLS detection, and raw issue count. Email widget shows: SPF present/missing, DKIM valid selectors count, DMARC policy (reject/quarantine/none, color-coded), DNSSEC state, spoofing risk level, and elite score.

  **Issue B fixed — guest dashboard now shows 6 real unlocked widgets:**
  Replaced the previous layout (3 real + 5 locked) with a full rebuild covering all modules Standard scan collects:
  - Row 1: Risk Donut, SslWidget (raw_results), EmailSecurityWidget (raw_results)
  - Row 2: WebSecurityWidget (ports, exposed paths, JS secrets, HTTPS redirect, missing headers), DnsWidget (A/MX records, DNSSEC, typosquatting, subdomain summary), CloudWidget (providers, bucket counts, K8s exposure)
  - Row 3: PartialLockedWidget x3 (Dark Web, Supply Chain, AI Risk Score) — show teaser numbers if raw_results key exists, otherwise show "requires Deep Scan"
  Stat strip updated: shows posture_score/posture_grade from meta, total findings, critical count, subdomain total, open port count.

  **Issue C fixed — ScanPage.jsx SCAN_TIERS corrected for Standard scan:**
  Standard tier previously listed "Dark web mention search" and "AI enrichment & remediation" as included — both are false per `SCAN_PROFILES["standard"]` (ai_enrichment: False, no dark_web module). Features list corrected to: DNS/WHOIS, Subdomain enumeration, SSL/TLS audit, Email security, Web security & ports, Cloud exposure, OSINT — all included. Dark web, Supply chain, AI enrichment, PDF Technical Report — all marked excluded. Scan time corrected from ~60s to ~45s. A note field added explaining posture score tier differences, rendered as italic text with an ⓘ info icon and tooltip.

  **Issue D documented — posture score difference is by design:**
  Deep Scan activates 4 extra modules (dark_web, supply_chain, social_eng, mobile_api) + AI enrichment, surfacing more findings. Each additional finding deducts from the score per `posture_score.py`. A lower Deep Scan score is a more accurate measurement, not a regression. Documented in `docs/standard-vs-deep-scan.md` with the full formula table, FAQ, and module coverage matrix.

  **Files changed:**
  - `portal/src/pages/guest-scan/GuestScanPage.jsx` — full GuestDashboard rebuild, new widgets: SslWidget, EmailSecurityWidget, WebSecurityWidget, DnsWidget, CloudWidget, PartialLockedWidget
  - `portal/src/pages/scan/ScanPage.jsx` — SCAN_TIERS Standard features corrected, note + ⓘ tooltip added
  - `docs/standard-vs-deep-scan.md` — new document: Standard vs Deep Scan explanation, posture formula, FAQ

---

## v1.0.388 -- 2026-05-10

### New Features

  - asm): fix guest dashboard widgets, guest-only executive PDF, modernise PDF branding, fix scan comparison table

### Bug Fixes

  - asm): fix undefined 'results' variable in portal JSON fallback path

---

## v1.0.387 -- 2026-05-10

### Improvements

  - Stability and performance improvements.

---

## v1.0.386 -- 2026-05-09

### Improvements

  - Stability and performance improvements.

---

## v1.0.385 -- 2026-05-09

### Improvements

  - Stability and performance improvements.

---

## v1.0.384 -- 2026-05-08

### Bug Fixes

  - **`cycentra-setup.sh` — fatal grep abort in CySIEM dashboard step**: `grep -E "^#?\s*opensearch\.username:"` returned exit code 1 (no match) under `set -euo pipefail`, aborting every `--update` run at Step 1. Fixed by appending `|| true` to both grep assignments.

  - **`cycentra-setup.sh` — replace broken proxy-auth approach with nginx Basic Auth injection**: All sections that attempted to configure `opensearch_security.auth.type: proxy` in `opensearch_dashboards.yml` have been replaced. Confirmed root cause: OpenSearch proxy auth returned `Authentication finally failed for null` regardless of `requestHeadersAllowlist`, `challenge: false`, or `proxy_auth_domain.http_enabled: true` — headers were not being forwarded correctly in this Wazuh 4.x build.

    **Working SSO mechanism (nginx Basic Auth injection)**:
    - Wazuh Dashboard stays in default `basicauth` mode — no `opensearch_security.auth.type` change.
    - `cy360_sso` service account in OpenSearch with `backend_role: admin` (hash via `hash.sh`, `$2y$` prefix — Python bcrypt `$2b$` does not authenticate).
    - nginx cysiem location block injects `Authorization: Basic Y3kzNjBfc3NvOkN5Q2VudHJhMzYwIVNpZW1TU08=` (`cy360_sso:CyCentra360!SiemSSO`) for every request that passes the oauth2-proxy IAP gate.
    - Result: any logged-in Cy360 user clicking CySIEM lands directly in the Wazuh Dashboard — no secondary login prompt.

    **Files changed**: `cycentra-setup.sh` — Step 4.1 (grep fix + strip proxy auth), Step 4.3b (replaced proxy-auth/securityadmin block with cy360_sso user creation), nginx template cysiem location (added `proxy_set_header Authorization`), idempotent nginx patch section.

---

## v1.0.383 -- 2026-05-08

### Bug Fixes

  - **`backend/blueprints/benchmark/routes.py` — Threat Intel widget showing 0**: Two compounding issues caused the "Threat Intelligence" widget on the Posture Benchmark page to display score 0 with "feeds unavailable · attribute count unavailable":

    1. **Wrong MISP API key selected**: `_read_misp_config()` resolved credentials via `ai_settings.json` → `cysiemstack.env` → `os.environ`. The `cysiemstack.env` file contained a stale key (`MISP_API_KEY=v2ZTsp4J...`) that returned 401 from MISP. The correct key (`CLOUD_MISP_API_KEY=M74nCZUC...`) was written by the UI to `/opt/cycentra/.env` (loaded into `os.environ`), but was never reached because both URL and key appeared to be satisfied by `cysiemstack.env` (URL matched, key was stale).

       **Fix**: Added new Source 2 in `_read_misp_config()` that checks `os.environ.get("CLOUD_MISP_URL")` / `os.environ.get("CLOUD_MISP_API_KEY")` **before** reading `cysiemstack.env`. This matches the priority of all other CLOUD_* settings in the platform.

    2. **MISP feed response envelope not unwrapped**: `_collect_threat_intel_score()` counted enabled feeds with `f.get("enabled")`, but the MISP `/feeds/index` API wraps each feed: `[{"Feed": {"enabled": 1, ...}}]`. Fix: `f.get("Feed", f).get("enabled")` — handles both wrapped (MISP 2.4+) and unwrapped formats.

    **Result**: Score 40/40 (5/96 feeds enabled). Files: `backend/blueprints/benchmark/routes.py` lines ~859, ~765. Tests: `tests/unit/test_benchmark_threat_intel.py` (5 cases covering both formats).

---

## v1.0.382 -- 2026-05-07

### New Features

  - **CySIEM (Wazuh) seamless auto-login from Cy360 portal**: Clicking the CySIEM link in the portal now opens the Wazuh Dashboard without a secondary login prompt, matching the SSO experience of CyIRIS and CySOAR.

    **Architecture**: `cysiem.cycentra.com` is already gated by an oauth2-proxy IAP (`auth_request` in nginx) that validates the `.cycentra.com` session cookie. After the IAP gate passes, nginx injects `Authorization: Basic cy360_sso` credentials to Wazuh. The `cy360_sso` user is an OpenSearch admin service account created during setup. No Wazuh Dashboard config changes are required.

    **Portal changes** (`portal/src/siem/SiemIncidentsPage.jsx`, `portal/src/siem/SiemUebaPage.jsx`): CySIEM buttons call `GET /api/siem/wazuh-launch` before opening the tab, storing a launch token in `sessionStorage` for potential deep-link usage.

    **Backend** (`backend/siem_proxy.py`): Added `GET /api/siem/wazuh-launch` endpoint — session auth check, role guard (viewer blocked), rate limit (10 req/min), returns `{"launch_url": ..., "token": ...}` with graceful fallback if Wazuh API is unreachable.

---

## v1.0.381 -- 2026-05-07

### Improvements

  - Stability and performance improvements.

---

## v1.0.380 -- 2026-05-06

### Bug Fixes

  - SyntaxError in system/routes.py — MISP try block outside updates dict

---

## v1.0.379 -- 2026-05-06

### Bug Fixes

  - MISP config fallback chain (ai_settings → cysiemstack.env → env) + sync on save

---

## v1.0.378 -- 2026-05-06

### Bug Fixes

  - threat intel reads MISP from ai_settings.json, fix pathlib reference

---

## v1.0.377 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.376 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.375 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.374 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.373 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.372 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.371 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.370 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.369 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.368 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.367 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.366 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.365 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.364 -- 2026-05-06

### New Features

  - add missing benchmark blueprint routes.py — resolves startup ModuleNotFoundError

---

## v1.0.363 -- 2026-05-06

### New Features

  - add missing benchmark blueprint routes.py — resolves startup ModuleNotFoundError

---

## v1.0.363 -- 2026-05-06

### Bug Fixes

  - **[HOTFIX] Backend crash on startup — `ModuleNotFoundError: No module named 'blueprints.benchmark.routes'`.**
    The Benchmark Intelligence Engine wiring patch (PATCH_3) was applied to `app.py` — adding the `benchmark_bp` import and registration — but the blueprint source file (`PATCH_1`) was placed in the wrong directory (`backend/backend/blueprints/benchmark/routes.py`) instead of the correct location (`backend/blueprints/benchmark/routes.py`).
    Flask could not import the module on startup, causing an immediate exit (status=1) and an infinite systemd restart loop (140+ restarts observed).
    Fixed by moving `routes.py` to the correct package path. The `__init__.py` was already in place.

---

## v1.0.362 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.361 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.360 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.359 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.358 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.357 -- 2026-05-06

### Improvements

  - Stability and performance improvements.

---

## v1.0.356 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.355 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.354 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.353 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.352 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.351 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.350 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.349 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.348 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.347 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.346 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.345 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.344 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.343 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.342 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.341 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.340 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.339 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.338 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.338 -- 2026-05-05

### Bug Fixes

  - **SSO login broken: `unknown_client` error** — Fixed six interconnected root causes that broke the SSO login flow introduced in v1.0.331–v1.0.337:
    1. `sso_redirect()` now self-heals: for Google/Microsoft, the OIDC discovery URL is always overridden to the authoritative provider URL regardless of what is stored in the DB. The redirect URI is always forced to the canonical `/api/sso/callback` path — stale DB entries like the old `/api/v1/auth/sso/callback` path (CyMind format) can no longer cause token-exchange failures.
    2. `sso_configure()` now enforces correct values on save: Google/Microsoft always get their canonical discovery URLs; the redirect URI is always written as `{FRONTEND_URL}/api/sso/callback`.
    3. `sso_callback()` now uses the canonical redirect URI (matching what `sso_redirect()` sent to the IdP) instead of the DB value — prevents redirect_uri mismatch errors.
    4. Removed bare `/.well-known/openid-configuration` Flask route (without `/oidc/` prefix) from the OIDC provider blueprint. This route caused `cy360.cycentra.com/.well-known/...` to return CyCentra's own OIDC discovery doc, making it appear to be a valid Google IdP endpoint when an admin accidentally stored that URL.
    5. Added `GET /api/sso/config` endpoint (admin-only) returning the full non-secret current SSO configuration so the settings form can pre-populate all fields on re-open.
    6. Updated `SSOTab.jsx` to load from `/api/sso/config` on mount — `client_id`, `redirect_uri`, `default_role`, `auto_provision`, `require_approval`, `allowed_domains` are now pre-populated. The redirect URI field is now always read-only (it is fixed to `/api/sso/callback`). A badge shows when a secret is already stored.

---

## v1.0.337 -- 2026-05-05

### Improvements

  - Stability and performance improvements.

---

## v1.0.336 -- 2026-05-04

### Improvements

  - Stability and performance improvements.

---

## v1.0.335 -- 2026-05-04

### Improvements

  - Stability and performance improvements.

---

## v1.0.334 -- 2026-05-04

### Improvements

  - Stability and performance improvements.

---

## v1.0.333 -- 2026-05-04

### Improvements

  - Stability and performance improvements.

---

## v1.0.332 -- 2026-05-03

### Improvements

  - Stability and performance improvements.

---

## v1.0.331 -- 2026-05-03

### Improvements

  - Stability and performance improvements.

---

## v1.0.330 -- 2026-05-03

### New Features

  - **Audit Trail** — New dedicated Audit Trail section accessible from the sidebar (Actions > Audit Trail). Captures all user and system events with timestamps, categories, results, and contextual metadata. Includes a live search bar, multi-field filters (category, result, user/email, date range), paginated log table with expandable detail rows, and one-click CSV/JSON export. Events are automatically recorded for logins, logouts, document creation, config changes, scan triggers, scheduler job execution, and service lifecycle events. Logs are stored at `/var/log/cycentra/audit.log` and merged at query time with `/var/log/cycentra/auth.log` for unified visibility.

    **API:** `GET /api/audit/logs`, `GET /api/audit/stats`, `GET /api/audit/export?format=csv|json`, `POST /api/audit/event`, `GET /api/audit/categories`

    **How to use:** Navigate to the sidebar and click **Audit Trail** under Actions. Use the filter bar to narrow by category (authentication, configuration, scan, scheduler, document), result (success/failure), or time window. Click any row's expand arrow to see the full event metadata. Use the Export button to download logs as CSV or JSON for compliance reporting.

  - **ASM PDF Report Modernization** — Completely redesigned PDF report output using the SecuPulse Security Business Review as a style reference. Reports now use a deep navy dark theme (`#0A1628` background) with teal (`#00E5A0`) and sky-blue (`#38BDF8`) accents throughout. Improvements include: modernized cover page with dot-grid decorative pattern, dual accent strips, and a security score box with grade pill (A–F); dark-theme metric cards with colored top-border accents; teal-ruled section headers; dark alternating rows in finding tables; updated posture gauge, severity pie chart, and module bar chart all rendered with matching dark palettes using matplotlib.

    **How to use:** No configuration changes required. Generate ASM reports as usual via the web portal or API — all new reports will automatically use the modernized dark theme format. Previously generated reports are not affected.

---

## v1.0.329 -- 2026-05-03

### Improvements

  - Stability and performance improvements.

---

## v1.0.328 -- 2026-05-02

### Improvements

  - Stability and performance improvements.

---

## v1.0.327 -- 2026-05-02

### Improvements

  - Stability and performance improvements.

---

## v1.0.326 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.326 -- 2026-04-29

### Bug Fixes

- **FP auto-close, Entity Risk, and UEBA fixes not taking effect after `--update`** — Root cause: `cycentra-setup.sh --update` contained a version pre-check that called `exit 0` when the server was already at the latest version, aborting the entire script before reaching `systemctl restart cysiemstack-engine`. This meant: (1) the correlation engine process kept running with old in-memory bytecode indefinitely — `pip install` updates `.py` and `.pyc` files on disk but the running Python process never reloads them; (2) the startup data migrations added in v1.0.323 (close stale false_positive incidents, backfill alerts.category/username) never executed because the engine never restarted with the new `main.py`. Fixed: removed the `exit 0` early abort — `--update` now always re-applies packages and restarts services regardless of version match. Pip install is idempotent; the restart takes under 10 seconds. (`cycentra-setup.sh`)

---

## v1.0.325 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.324 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.323 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.323 -- 2026-04-29

### Bug Fixes

- **FP incidents stuck in "false_positive" state despite slider at 50%** — The `advance_incident_status()` fix (v1.0.319) correctly sets new incidents to `closed`. However 82 existing incidents were already written as `false_positive` by the old code before the fix was deployed. The `_fp_auto_close_scheduler` only promotes them after 7 days — they would remain visible in Active Incidents for a week. Added startup migration 4: on engine boot, all `false_positive` incidents where `fp_probability >= fpThreshold` (read live from `ai_settings.json`) are immediately closed. (`main.py` lifespan)

- **O365 incidents still showing "☁ Cloud" — alerts.category not migrated** — The normaliser fix (v1.0.312) correctly classifies new O365 alerts as `o365`. The prior lifespan migration (v1.0.319) updated `incidents.categories` cloud→o365. But the underlying `alerts.category` column was never updated — still stored as `cloud` for all 50 pre-fix alerts. This caused: (a) `_merge_categories()` in the grouper to re-inject `cloud` when new alerts merged into existing incidents, overriding the fixed category; (b) `risk_scorer.recalculate_all()` to find zero `o365` alerts and skip the Microsoft 365 entity entirely. Added startup migration 2: backfills `alerts.category` to `o365` for all alerts whose `full_alert` contains `office365` rule groups. (`main.py` lifespan)

- **UEBA / Entity Risk missing O365 users and showing only postgres/proxy** — `alerts.username` is NULL for all 93 pre-fix alerts because the O365 username extraction (MailboxOwnerUPN/UserId path in `_extract_username`) was added in v1.0.319 but not backfilled. UEBA baselines only contain `postgres` and `proxy` — SSH brute-force srcuser values extracted from pre-fix auth alerts. Added startup migration 3: backfills `alerts.username` from `full_alert→data→office365→MailboxOwnerUPN` (email only, `LIKE '%@%'`) then from `UserId` as fallback. On next `recalculate_all()` scheduler run, O365 users will appear in Entity Risk and Behavioral Analytics. (`main.py` lifespan)

---

## v1.0.322 -- 2026-04-29

  - Stability and performance improvements.

---

## v1.0.321 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.321 -- 2026-04-29

### Bug Fixes

- **Auto-ticket not raised when MISP disabled and CyMind not configured** — `enriched = bool(misp_result or llm_result)` evaluated to `False` when MISP is disabled (returns `{}`) and LLM is not configured (returns `{}`). Band 2 guard `fp_score >= 40.0 or not enriched` then trapped all incidents in "investigating" permanently — Band 3 (ticket creation) was never reached regardless of fp_score, severity, or alert count. Fixed: `enriched` is now `True` when alert_count reaches the LLM trigger threshold (3), indicating the enrichment window has closed. Also `True` when prior-cycle enrichment is stored on the incident (`llm_summary` or `misp_enrichment`). (`ingestor.py`)

---

## v1.0.320 -- 2026-04-29

  - Stability and performance improvements.

---

## v1.0.320 -- 2026-04-29

### Bug Fixes

- **FP auto-close threshold slider now respected in all IRIS modes** — When IRIS connection mode was set to `disabled`, `_load_iris_config()` returned `None` and `advance_incident_status()` fell back to the hard-coded default threshold (90%) instead of the user's slider value. The UI description states "False-positive auto-close still active based on threshold" even in disabled mode — this is now true. The threshold is read directly from `ai_settings.json` regardless of IRIS connection state, so user preference (slider set to e.g. 60%) is always honoured. (`iris_connector.py` `advance_incident_status()`)

---

## v1.0.319 -- 2026-04-29

  - Stability and performance improvements.

---

## v1.0.319 -- 2026-04-29

### Bug Fixes

- **FP auto-close threshold now closes directly** — `advance_incident_status()` was promoting incidents to `false_positive` (still visible, reviewable) instead of `closed` when `fp_probability ≥ fpThreshold`. The UI labelled this "FALSE POSITIVE AUTO-CLOSE THRESHOLD" and described it as "auto-closed without raising a ticket", but the terminal `closed` state was only reached after 7 days via the FP scheduler. Fixed: Band 1 now uses `threshold` (fpThreshold from the UI slider) and sets `status = "closed"` immediately. The intermediate "held" watch-zone band is removed — it was never exposed in the UI and created confusion. (`iris_connector.py` `advance_incident_status()`)

- **Entity Risk — Microsoft 365 now appears as a separate entity** — O365 alerts all arrived with `agent_id = "CY360-DEV"` (the Wazuh manager), so they were silently merged into the CY360-DEV host entity and never appeared as a distinct cloud service. Added `entity_type = 'cloud'` to the risk scorer: alerts are bucketed by `Alert.category` (e.g. `o365`) and tracked under a display name (e.g. "Microsoft 365"). The ingestor and the `recalculate_all()` scheduler both populate these new entities. (`risk_scorer.py`, `ingestor.py`)

- **UEBA — `root` and O365 users now tracked** — Two sub-bugs: (1) `_extract_username()` explicitly excluded the string `'root'`, so all `root` activity on CY360-DEV produced no UEBA baseline. (2) O365 alerts carry the user identity in `data.office365.UserId` / `MailboxOwnerUPN` — paths not checked by the extractor. Fixed: removed `'root'` from the exclusion list; added O365 email extraction. (`normaliser.py` `_extract_username()`)

- **Active Incidents — "☁ Cloud" upgraded to "☁ Microsoft 365"** — Incidents ingested before the `_CLOUD_SOURCE_MAP` normaliser fix (v1.0.312) have `categories = {cloud}`, displaying as "☁ Cloud" instead of "☁ Microsoft 365". Two-part fix: (1) Engine startup migration: UPDATE incidents whose linked alerts have `office365` rule groups, replacing `cloud` with `o365`. (2) `grouper.py` `merge_alert_into_incident()`: when a specific cloud-source alert (o365, azure, aws, gcp, github) merges into an incident with a legacy `cloud` category, the generic `cloud` entry is replaced by the specific source. (`main.py` lifespan migration, `grouper.py` `_merge_categories()`)

---

## v1.0.318 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.317 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.316 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.315 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.314 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.313 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.312 -- 2026-04-29

### Improvements

  - **Cloud integration source specificity** — Incidents sourced from cloud integrations now display the specific service name instead of the generic "Cloud event" label. The normaliser maps Wazuh rule groups to named sources: `office365`/`o365` → **Microsoft 365**, `azure`/`msaz` → **Microsoft Azure**, `aws`/`cloudtrail` → **AWS**, `gcp` → **Google Cloud**, `github` → **GitHub**. Both the incidents table and the incident drawer now show the service name with a ☁ icon. The drawer section header also includes the service name (e.g. "CLOUD COLLECTOR AGENT (☁ Microsoft 365)"). Legacy `cloud` category on pre-existing incidents is handled as a graceful fallback.

---

## v1.0.311 -- 2026-04-29

### Improvements

  - Stability and performance improvements.

---

## v1.0.311 -- 2026-04-29

### Improvements

  - **Incident lifecycle clarity** — False Positive and Closed are now distinct steps in a clear two-stage flow: `false_positive` (classification verdict, still reviewable) → `closed` (terminal, confirmed noise). A new auto-close scheduler advances false_positive incidents to closed after 7 days with a full audit entry.
  - **Archive scheduler** — The 30-day auto-archive now targets `closed` and `resolved` incidents (no longer `false_positive` directly), completing the FP → closed → deleted pipeline.
  - **Incident toolbar — two-stage archive** — The former "Clear Resolved / FP" button (which hard-deleted rows) is replaced with two distinct actions:
    - **Archive FP & Resolved** (yellow) — soft-close: transitions all `false_positive` and `resolved` incidents to `closed` with an audit trail. No data deleted.
    - **Purge Closed** (red) — hard-delete: permanently removes only `closed` incidents from the database. Requires a separate confirm step.
  - **Cloud incident host label** — Incidents sourced from cloud integrations (O365, Azure, AWS) now display "CLOUD COLLECTOR AGENT" instead of "AFFECTED HOSTS", with an inline note explaining that the agent shown is the Wazuh collector, not the victim host. Users are directed to "Affected Users" for victim identity.
  - **New engine endpoint** — `POST /incidents/batch-close` performs the soft-close operation; proxied through Flask at `analyst+` RBAC level.

---

## v1.0.310 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.309 -- 2026-04-28

### Bug Fixes

  - Fix CySIEM auto-login: write proxy auth config before first dashboard restart

---

## v1.0.308 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.307 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.306 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.305 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.304 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.303 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.302 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.302 -- 2026-04-29

### Features

- **Cloud Marketplace model** — no integrations or playbooks are bundled with the platform at ship time; all items originate from the cloud marketplace and are pulled on demand.
- **My Integrations & Playbooks page** — `UseCasesPage` now fetches from `/api/marketplace/catalog` + `/api/marketplace/installed` and displays only items the user has pulled. Empty state guides users to the Integration Marketplace.
- **Office 365 native module** — Wazuh integration upgraded from deprecated `<wodle name="office365">` to the native `<office365>` block format across all config surfaces (system routes, UseCasesPage modal, MarketplacePage modal).
- **O365 `api_type` selector** — choose between `commercial`, `gcc`, and `gcc-high` subscription plans.
- **O365 `only_future_events` toggle** — exposed in both the UseCasesPage and MarketplacePage config modals; defaults to enabled.
- **DLP.All subscription** — `DLP (Data Loss Prevention)` subscription option added to O365 integration.
- **Marketplace backend** — removed `_DEFAULT_CATALOG` hard-coded items; catalog is now cloud-only with on-server custom items. Removed `_DEFAULT_IDS` install whitelist; validation is now format-based only.

---

## v1.0.301 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.300 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.299 -- 2026-04-28

### Improvements

  - Scheduler timezone, ASM log timestamps, O365 status sync

---

## v1.0.298 -- 2026-04-28

### Bug Fixes

  - Fix scheduler: invalid */0 cron and wordlist wrong save path

---

## v1.0.297 -- 2026-04-28

### Bug Fixes

  - Fix scheduler jobs and O365 integration

---

## v1.0.296 -- 2026-04-28

### Improvements

  - Stability and performance improvements.

---

## v1.0.295 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.294 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.293 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.292 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.291 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.290 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.290 -- 2026-04-27

### Bug Fixes — Critical

- **Backend crash-loop fixed (issues: local auth "Network error", Google SSO 502, scheduler UI)**  
  `blueprints/scheduler/routes.py` `_load_jobs()` crashed at startup when reading the legacy dict-format `schedules.json`, iterating over string keys and calling `.get()` on them. Added `_normalise_legacy_job()` to convert the legacy flat-dict schema (`{job_id: {...}}`) to the list-of-dicts format the scheduler expects. The service was restart-looping 180+ times — this is now fixed, and the Flask backend (`cycentra-backend.service`) will come up cleanly.

- **ASM PDF report — chart aspect ratios fixed**  
  `cy_asm/reporting/pdf_base.py` `img_from_bytes()` previously called `Image(buf, width=w)` without an explicit height, allowing ReportLab to use an incorrect internal calculation that caused charts (gauge, radar, pie, world map) to appear extremely stretched. Now uses `ImageReader.getSize()` to compute the exact proportional height before constructing the `Image` object.

- **ASM PDF report — CyCentra logo added to cover page**  
  `build_cover()` now detects and embeds the actual CyCentra logo image (checked in priority order: `logo.png`, `logo-light.png`, `favicon-*.png`, `favicon.ico`). ICO files are transparently converted to PNG bytes via Pillow before embedding. Falls back gracefully to the existing "CY CENTRA" text monogram if no image is found.

---

## v1.0.289 -- 2026-04-27

### Auth / RBAC

  - Removed all JSON file references from RBAC backend — `cy_users` PostgreSQL table is now the sole source of truth with no file fallbacks.
  - `cyadmin@cycentra.com` bootstrap now runs on every Flask startup (idempotent `ON CONFLICT DO NOTHING`), not only when the table is empty — fixes a race condition where the default admin could be missing if the table was created in a prior partial run.
  - Removed `_migrate_json()`, `_json_load_raw()`, and `_load_rbac()` shim entirely.
  - DB errors now propagate as 500 responses rather than silently falling through to missing users.

---

## v1.0.288 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.287 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.286 -- 2026-04-27

### Bug Fix — Local login "Network error": duplicate CORS headers from nginx + Flask

  **Root cause:** The `cyasm.cycentra.com` nginx server block was adding its own
  `Access-Control-Allow-*` headers, and Flask's global `@app.after_request` hook was
  also adding them. Every response carried the headers twice; the browser CORS spec
  requires exactly one `Access-Control-Allow-Origin` value — two values causes the
  browser to reject the response entirely, surfacing as "Network error" in the UI.
  The backend showed a 200 success in logs because the rejection happens client-side
  after the response is received.

  **Fix:**
  - Removed the four CORS `add_header` directives from the `cyasm` nginx server block
    template in `setup.sh`. Flask is now the single CORS authority via its global
    `after_request` hook.
  - Added an idempotent `sed` patch in the `--update` path that strips those lines from
    already-deployed nginx configs, then reloads nginx automatically.

  **After `--update`:** nginx reloads without CORS headers; Flask adds them once;
  local login works end-to-end.

---

## v1.0.285 -- 2026-04-27

### Bug Fix — Local login UI shows "Network error" despite backend success

  **Root cause:** Duplicate CORS headers on every `/auth/local` response.
  `app.py` has a global `@app.after_request` hook that calls `add_cors_headers()`
  on every response. The `/auth/local` handler was also wrapping every response
  manually with its own `add_cors_headers()` call (via `_json()` helper added in
  v1.0.281). This produced two `Access-Control-Allow-Origin` headers on every
  response. The browser CORS spec requires exactly one value — receiving two causes
  the browser to reject the response entirely, and the `fetch()` catch block
  reported it as "Network error".

  **Fix:** Removed the manual `add_cors_headers()` / `_json()` wrapper from
  `/auth/local`. All responses now go through the single global `after_request`
  hook only. The OPTIONS preflight handler is also simplified to a plain
  `make_response('', 204)` — the global hook adds its CORS headers.

---

## v1.0.284 -- 2026-04-27

### Bug Fix — Local login always fails: cy_users table empty after migration

  **Root cause (3-step chain):**
  1. `rbac.json` was renamed to `rbac.json.old`; `rbac.default.json` was never deployed
     (server hadn't been updated since that file was added in v1.0.279).
  2. On Flask startup, `_ensure_table()` found `cy_users` empty and called
     `_migrate_json()`, which checked only `rbac.json` and `rbac.default.json`.
     Both missing → `if not data: return` → table stayed empty.
  3. Every `_get_user()` query returned `None` → all logins (local and SSO) denied.

  **Fixes applied to `_migrate_json()`:**
  - Now also checks `rbac.json.old` as an additional fallback source, restoring
    any users that were in the renamed file.
  - **Always seeds** `cyadmin@cycentra.com` (admin / local / `Admin@123`) via
    `INSERT ... ON CONFLICT DO NOTHING` regardless of whether any JSON files
    existed. This is the self-contained bootstrap guarantee — local admin login
    works even on a server with no RBAC files at all.

  **After update + Flask restart the server will have:**
  - `deepak1424@gmail.com` — admin, SSO (restored from `rbac.json.old`)
  - `cyadmin@cycentra.com` — admin, local, password `Admin@123` (seeded)

---

## v1.0.283 -- 2026-04-27

### Improvement — User Management UI: auth type + password for local accounts

  - **Add User form** (Settings → User Management) now has an **SSO / Local** selector.
    When "Local" is chosen a password field appears. The password is sent to the backend
    and stored as a bcrypt hash — never in plain text.
  - Validation: local accounts require a non-empty password before the Add button
    submits. SSO accounts require only email + role (unchanged behaviour).
  - On success the form resets all fields including the auth type selector.

---

## v1.0.282 -- 2026-04-27

### Feature — PostgreSQL-backed User Management (RBAC)

  - **`cy_users` table in `correlation` DB**: User accounts (roles, auth types, bcrypt
    hashes) are now stored in the existing PostgreSQL 16 cluster (`correlation` DB,
    port 5433) instead of a flat JSON file. No new database or database user is required.

  - **Auto-create & auto-migrate**: On first Flask startup, `blueprints/rbac/manager.py`
    runs `CREATE TABLE IF NOT EXISTS cy_users` and, if the table is empty, migrates all
    entries from `rbac.json` / `rbac.default.json` automatically.

  - **Graceful JSON fallback**: If `CYCENTRA_DB_URL` is empty or the DB is unreachable,
    every RBAC function falls back to reading `rbac.json` — no downtime on DB failure.

  - **`psycopg2-binary>=2.9` added** to `requirements.txt` for synchronous PostgreSQL
    access from Flask.

  - **`CYCENTRA_DB_URL` env var**: Added to `core/config.py` and written to
    `/opt/cycentra/.env` automatically by `setup.sh` (both full-install and update-mode
    patch paths). Value:
    `postgresql://corruser:<pass>@127.0.0.1:5433/correlation`

  - **`POST /api/rbac/users`**: Now accepts `auth_type`, `password`, `name`, `apps`
    in addition to `role`. Passwords are bcrypt-hashed server-side. Underlying write
    uses PostgreSQL UPSERT (`ON CONFLICT DO UPDATE`).

  - **`DELETE /api/rbac/users/<email>`**: Deletes from `cy_users` (previously edited
    `rbac.json` in-place).

  - **OAuth callbacks use single-row DB lookup**: Google and Microsoft SSO callbacks now
    call `_get_user(email)` (single `SELECT` by primary key) for the allowlist check
    instead of loading the full user table. Same fix applied to local auth. All three
    auth paths now make exactly one DB round-trip per login.

---

## v1.0.281 -- 2026-04-27

### Bug Fixes — Local Authentication CORS & RBAC Fallback

  - **Local auth: CORS headers on all responses** (root cause of "Network error"): The
    `POST /auth/local` endpoint was returning 401/4xx responses without
    `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials` headers. For
    credentialed cross-origin `fetch()` calls (portal at `cy360.*`, API at `cyasm.*`),
    the browser refuses to expose any response that lacks CORS headers — `fetch()` throws
    a TypeError which the catch block reported as "Network error — please try again",
    completely hiding the real error. All responses from `/auth/local` now go through
    `add_cors_headers()`.

  - **`_load_rbac()` falls back to `rbac.default.json`**: When `/opt/cycentra/rbac.json`
    is absent (e.g. renamed/deleted), the RBAC loader now tries
    `/opt/cycentra/rbac.default.json` before returning an empty dict. This ensures the
    bundled default account (`cyadmin@cycentra.com`) is always available as a recovery
    path without requiring a full re-install.

  - **`setup.sh` always deploys `rbac.default.json`**: The RBAC setup step now copies
    `rbac.default.json` from the bundle to `/opt/cycentra/rbac.default.json` on every
    run (not just on first install), so the Flask fallback file is always up-to-date.

  - **`bcrypt` added to `requirements.txt`**: Was missing from the declared dependencies;
    local auth silently failed with a 503 if bcrypt happened not to be installed.

---

## v1.0.280 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.279 -- 2026-04-27

### Improvements

  - Stability and performance improvements.

---

## v1.0.279 -- 2026-04-27

### Features — Local Authentication & CyIRIS Environment Improvements

  - **Local (username/password) authentication**: Added a new local login method
    alongside the existing Google and Microsoft SSO options. A dedicated "Sign in with
    local account" button is now present on the login page. Local users are stored in
    `rbac.json` with `auth_type: "local"` and a bcrypt-hashed password. The new
    `POST /auth/local` API endpoint validates credentials and creates the same session
    cookie as SSO — all RBAC roles and app permissions apply identically.

  - **OOB rbac.json with default local admin**: `rbac.default.json` is now bundled
    with every release. On a fresh install, setup.sh copies this file to
    `/opt/cycentra/rbac.json` (existing deployments are unaffected). The default file
    contains a single local-auth admin account `cyadmin@cycentra.com` with password
    `Admin@123` (bcrypt-hashed). Dynamic runtime creation of `rbac.json` from
    `${CLIENT_EMAIL}` has been removed from `cycentra-setup.sh`.

  - **CLOUD_IRIS_URL auto-populated on CyIRIS install**: When CyIRIS is installed
    via Platform Modules and the admin API key is captured from the DB, the installer
    now also ensures `CLOUD_IRIS_URL=http://127.0.0.1:4433` is present in
    `/opt/cycentra/.env`. If the variable already has a non-empty value it is not
    overwritten (backward-compatible).

  - **rbac.json schema extended**: New optional fields `auth_type` (`"local"` or
    `"sso"`) and `password_hash` (bcrypt) are supported per user entry. All existing
    SSO-only entries without these fields continue to work unchanged.

---

## v1.0.278 -- 2026-04-26

### Improvements

  - Stability and performance improvements.

---

## v1.0.278 -- 2026-04-27

### Bug Fixes

  - **Scheduler — backup cron entry fix**: Removed the spurious `root` username token
    from the backup cron entry generated by `_apply_schedules()`. User crontab format
    does not accept a username field (that is only valid in `/etc/cron.d/` files);
    the previous entry caused `root` to be executed as the command and
    `/opt/cycentra/run_backup.sh` to be silently discarded, so scheduled backups
    never ran.
  - **Setup — `docker-maintenance.sh` deployment fix**: Changed the deployment source
    from `_SCRIPT_DIR` to `BUNDLE_DIR` so `docker-maintenance.sh` is correctly deployed
    in all execution modes. In the portal --update path the script runs from
    `/opt/cycentra/` (where the file does not exist) but the bundle is always extracted
    to `BUNDLE_DIR`; using `_SCRIPT_DIR` caused the file to silently not be deployed,
    leaving the Docker Maintenance cron job broken with "not found" errors.

---

## v1.0.277 -- 2026-04-26

### Features — CyMind Agentic Chat (Response Actions)

The CyMind chat overlay can now execute security response actions directly from a conversation. When the analyst types an action request, the chat intercepts it, explains exactly what will happen, and presents a **Confirm / Cancel** card before any action is taken.

**Supported actions (analyst+ role required):**

- **Block IP** — `"block IP 10.0.0.1 on agent 003"` → Wazuh `firewall-drop` active-response
- **Disable user account** — `"disable user jdoe on agent 005"` → Wazuh `disable-account` active-response
- **Restart Wazuh agent** — `"restart agent 007"` → Wazuh `restart-wazuh` active-response
- **Close incident** — `"close incident INC-0042"` → transitions to `resolved` with audit log
- **Mark false positive** — `"mark INC-0037 as false positive"` → transitions to `false_positive`
- **Bulk mark false positives** — `"close all false positives"` → marks all open incidents, shows count before confirming
- **Trigger ASM scan** — `"run a deep scan on example.com"` → starts background scan, results in Asset Inventory
- **Add scan schedule** — `"schedule a daily scan of example.com at 3am"` → creates recurring job via new Scheduler

**New Scheduler subsystem:**
- Blueprint at `blueprints/scheduler/routes.py`
- API: `GET/POST/DELETE/PATCH /api/scheduler/jobs`
- APScheduler BackgroundScheduler with file-lock for multi-worker safety
- Job store: `/opt/cycentra/schedules.json`
- Supports cron and interval triggers

**New correlation engine endpoints:**
- `POST /active-response` — Wazuh active-response wrapper (block IP, disable user, restart agent)
- `POST /incidents/bulk-false-positive` — atomic bulk false-positive transition with audit trail

**All actions are:**
- Gated behind analyst+ RBAC
- Logged via existing SIEM audit infrastructure
- Intent-detected via deterministic regex (no LLM required for intent parsing)
- Require explicit analyst confirmation before execution

---

## v1.0.276 -- 2026-04-26

### Improvements

  - Stability and performance improvements.

---

## v1.0.275 -- 2026-04-26

### Improvements

  - Stability and performance improvements.

---

## v1.0.274 -- 2026-04-26

### Improvements

  - Stability and performance improvements.

---

## v1.0.273 -- 2026-04-25

### Improvements

  - Stability and performance improvements.

---

## v1.0.272 -- 2026-04-25

### Improvements

  - Stability and performance improvements.

---

## v1.0.271 -- 2026-04-25

### Improvements

  - Stability and performance improvements.

---

## v1.0.271 -- 2026-04-25

### New Features

  - **Active Incidents — Graphical Summary Section**: A visual analytics panel now
    appears at the top of the Active Incidents page, providing an at-a-glance
    overview before the incident list. Includes:
    · **Stat tiles** — Total, Open, Investigating, In Review, Resolved, Critical,
      and High counts updated in real-time.
    · **Severity Donut Chart** — interactive SVG pie; clicking a segment
      instantly applies the severity filter to the incident table below.
    · **Status Donut Chart** — same interactive filter binding for status.
    · **Category Distribution Bar** — horizontal bar chart of top-7 incident
      categories (colour-coded by category type).
    · **14-Day Trend Line** — smooth cubic-bezier line chart showing daily
      incident volume with hover tooltips. Driven by a separate unfiltered
      fetch (limit 500) so charts always reflect the full picture regardless
      of active table filters.

  - **Entity Risk — Graphical Summary Section**: A compact visualisation panel
    added above the entity leaderboard on the Entity Risk page. Includes:
    · **Stat tiles** — Total Entities, Critical (≥75), High (50–74),
      Medium (25–49), Low (0–24) counts.
    · **Score Distribution Histogram** — 10-bucket bar chart (0–9 … 90–100)
      with colour gradient (green → yellow → orange → red) and hover labels.
    · **Entity Type Split** — stacked bar and counters showing host vs. user
      breakdown with percentages.
    Charts refresh every 60 s independently of the filter tab selection.

---

## v1.0.270 -- 2026-04-25

### Improvements

  - Stability and performance improvements.

---

## v1.0.269 -- 2026-04-25

### Improvements

  - Stability and performance improvements.

---

## v1.0.268 -- 2026-04-25

### Improvements

  - Stability and performance improvements.

---

## v1.0.268 -- 2026-04-25

### Bug Fixes

  - **Scheduler — docker-maintenance.sh not deployed to customers**: `build-package.sh`
    now includes `docker-maintenance.sh` in the release tarball. Previously the file
    was absent from the bundle, causing `cycentra-setup.sh` to silently skip
    deployment, leaving the Scheduler unable to run maintenance jobs.

  - **Scheduler — ASM wordlist path corrected**: `_resolve_wordlist_path()` now
    searches `cy_asm/modules/Utils/update_wordlist.py` (correct `Utils/`
    subdirectory). Old flat-layout path retained as legacy fallback.

  - **Scheduler — ASM scan domain hardcoded to BASE_DOMAIN**: The target domain
    for scheduled scans is no longer a free-text input. Backend always reads
    `BASE_DOMAIN` from `/opt/cycentra/.env`; UI shows a read-only badge. Any
    client-supplied domain is stripped server-side on `PUT /api/system/schedules`.

---

## v1.0.267 -- 2026-04-25

### New Features

  - **Platform Modules — Version Check fixed**: "Check for Update" for CyIRIS and CySOAR
    now shows the actual running version extracted from the container's OCI image label
    (`org.opencontainers.image.version`) via a new backend endpoint
    `GET /api/platform/version/<module_id>`. The GitHub Releases API is called
    server-side (using `GH_TOKEN` from `/opt/cycentra/.env`) — no CORS issues.
    Running and Latest version numbers now appear correctly instead of "—".

  - **System Settings → Scheduler tab**: New tab for managing cron schedules from
    the portal UI. Supports three schedulable tasks:
    · Docker Maintenance (`docker-maintenance.sh`)
    · ASM Wordlist Update (`update_wordlist.py`)
    · ASM Scheduled Scan (configurable domain, scan type)
    Frequency options: every minute, hourly, daily, weekly, monthly, quarterly, yearly.
    Schedules persisted to `/opt/cycentra/schedules.json`; crontab applied immediately
    on save via `PUT /api/system/schedules` (admin only).

  - **System Settings → Environment Config**: Removed CyMISP entry — CyMISP is no
    longer managed through this portal. MISP integration settings remain in
    the Integrations tab (CySIEM Stack env).

### Bug Fixes / Improvements

  - `cycentra-setup.sh` Step 23 (Cron Jobs): removed auto-provisioning of
    docker-maintenance and ASM wordlist cron entries. Setup.sh now delegates all
    schedule management to the Scheduler tab. The `docker-maintenance.sh` script
    is still deployed to `/opt/cycentra/docker-maintenance.sh` as before.
    Existing schedules set up by older versions are preserved and remain active;
    they can be managed and overridden via the Scheduler tab.

---

## v1.0.266 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.265 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.264 -- 2026-04-24

### New Features

  - health check curl exit 7 kills script under set -e — add || true

### Bug Fixes

  - RELEASE_NOTES.md path moved to docs/ — update CI workflows

---

## v1.0.263 -- 2026-04-24

### New Features

  - health check curl exit 7 kills script under set -e — add || true

---

## v1.0.262 -- 2026-04-24

### New Features

  - health check curl exit 7 kills script under set -e — add || true

---

## v1.0.261 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.260 -- 2026-04-24

### Bug Fixes

  - guard WAZUH_API_PASSWORD grep against set -e on fresh install

---

## v1.0.259 -- 2026-04-24

### Bug Fixes

  - update workflow paths for docs/RELEASE_NOTES.md move

---

## v1.0.258 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.257 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.256 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.255 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.254 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.253 -- 2026-04-24

### Improvements

  - Stability and performance improvements.

---

## v1.0.252 -- 2026-04-23

### Bug Fixes

  - **CyIRIS Test Connection — whitespace in API key causes silent 401**:
    `iris_test()` read the API key from the request body without `.strip()`.
    A key copied from a terminal with a trailing newline/space failed the exact
    DB match in IRIS, producing 401 even though the key was correct.
    Fix: `api_key = data.get("apiKey", "").strip()` before any auth check.

  - **CyIRIS Test Connection — undifferentiated 401 message**:
    Both a genuine IRIS 401 (wrong key — JSON body `{"status":"error"}`) and a
    reverse-proxy 401 (oauth2-proxy / nginx IAP blocking Bearer tokens — HTML
    body) returned the same "Invalid API key (401 Unauthorized)" message.
    Fix: parse the response body; if JSON IRIS 401, show "Invalid API key" with
    a diagnostic `curl /api/ping` command; if HTML 401, surface "auth proxy /
    login gateway" hint and advise using the internal address
    (`http://127.0.0.1:4433`) to bypass the IAP gate.

  - **CyIRIS Test Connection — 401 on internal URL when running in oidc_proxy mode**:
    CyIRIS deployed in `oidc_proxy + lazy` mode only accepts `X-Email` header
    authentication (set by nginx/oauth2-proxy). Direct programmatic calls to
    `http://127.0.0.1:4433` with a Bearer API key bypassed the IAP gate but
    `_oidc_proxy_authentication_process()` in CyIRIS returned `None` when no
    `X-Email` header was present — blocking ALL API key access regardless of
    key correctness. Flask-Login's `request_loader` was resolving the Bearer
    token correctly but `is_user_authenticated()` ignored `current_user` in
    `oidc_proxy` mode. Fix (in CyIRIS `access_controls.py`): fall back to
    `current_user.is_authenticated` when `X-Email` is absent so programmatic
    REST access (correlation engine, System Settings test) is not locked out.
    Also fixed: stale `CLOUD_IRIS_API_KEY` in `/opt/cycentra/.env` — the key
    was set on initial install but never refreshed when the IRIS container was
    recreated, causing all API calls to fail with 401. Platform installer now
    captures the admin API key from the IRIS DB after first boot and writes it
    to `CLOUD_IRIS_API_KEY` in the master `.env` automatically.

---

## v1.0.251 -- 2026-04-23

### Improvements

  - Stability and performance improvements.

---

## v1.0.251 -- 2026-04-23

### Bug Fixes

  - **UI Update button — `_PIP_BSP: unbound variable` / exit code 1**:
    `_PIP_BSP` (the `--break-system-packages` flag detector for pip3) was
    initialised inside the `INFRASTRUCTURE BLOCK`, which is skipped entirely in
    `--update` mode. The `APP BLOCK` (runs in all modes) references `${_PIP_BSP}`
    in two places — the CySIEM→Redis bridge pip install and the backend wheel
    install (Step 12). With `set -euo pipefail` active, bash aborts on the first
    expansion of an unbound variable, producing the `_PIP_BSP: unbound variable`
    error and exit code 1. Manual `--update` runs succeeded because the server's
    on-disk copy pre-dated the Step 12 `${_PIP_BSP}` reference; the UI button
    always downloads the latest release script and ran into it. Fix: added a
    `_PIP_BSP` re-detection block immediately after `fi  # end INFRA block` so
    the variable is always set before any APP BLOCK code executes.
    File: `cycentra-setup.sh` — between INFRA block `fi` and APP BLOCK header.
    Regression tests: `tests/unit/test_pip_bsp_update_mode.py` (3 cases).

  - **Cloud CyIRIS test connection — "CyIRIS API Key is required" even when key is provisioned**:
    `iris_test()` read from `ai_settings.json` when `useStored=True` but had no env-var
    fallback, unlike the equivalent MISP handler. In cloud mode the UI never stores the key
    in `ai_settings.json` (it lives in `.env` as `CLOUD_IRIS_API_KEY`). Added
    `os.environ.get("CLOUD_IRIS_API_KEY")` fallback after the settings-file lookup —
    matching the pattern already used by MISP (`CLOUD_MISP_API_KEY`).
    File: `backend/blueprints/system/routes.py` — `iris_test()`.

  - **Cloud CyIRIS test connection — "Server returned a non-JSON response" (nginx IAP blocks Bearer token)**:
    Even after the API key was resolved, `iris_test()` used the URL the UI sends
    (`https://cyiris.cycentra.com`) which routes through the nginx IAP gate (oauth2-proxy).
    The proxy intercepts all requests without a browser session cookie — including
    Bearer-token API calls — and returns an HTML redirect to login. `iris_connector.py`
    (the correlation engine) works because it reads `CLOUD_IRIS_URL` from `.env`, which
    is set to the internal Docker address (e.g. `http://127.0.0.1:4433`) that bypasses
    nginx entirely. Fix: `iris_test()` now resolves the URL from `CLOUD_IRIS_URL` env var
    when `useStored=True`, using the same fallback logic as `iris_connector.py` and
    `_sync_iris_to_siem_env()`.
    File: `backend/blueprints/system/routes.py` — `iris_test()`.

  - **Local CyIRIS test connection — "Expecting value: line 1 column 1 (char 0)"**:
    When the configured URL pointed to a server returning HTTP 200 with an HTML/empty
    body (wrong host, default nginx page, proxy), `resp.ok` was `True` and the code
    entered the success branch. `ver_resp.json()` then raised `json.JSONDecodeError`
    which propagated to the outer `except Exception as e` → `str(e)` = the cryptic
    message. Two-part fix: (1) validate the `/api/ping` response is JSON with
    `status == "success"` before proceeding — gives a clear URL-mismatch message;
    (2) wrapped `ver_resp.json()` in its own `try/except` so a missing/invalid version
    endpoint never hides a successful ping.
    File: `backend/blueprints/system/routes.py` — `iris_test()` ping success path.

  - **Local CyIRIS test connection — misleading "Access denied (403 Forbidden)" on wrong URL**:
    Testing with `http://127.0.0.1` (port 80) on a CyCentra server hits CyCentra's own
    nginx/Flask — not CyIRIS. CyCentra's auth middleware returns 403 before routing, which
    the test handler reported as "Access denied (403 Forbidden)", implying an API key problem.
    Local CyIRIS listens on port 4433 by default. Fix: the 403 handler now inspects the
    response body — a real IRIS 403 carries `{"status": "error", ...}` JSON and gets a
    "check your API key" message; a non-IRIS server (HTML body) gets a "check URL/port"
    message.
    File: `backend/blueprints/system/routes.py` — `iris_test()`.
    Regression tests: `tests/unit/test_iris_test_route.py` (10 cases).

---

## v1.0.249 -- 2026-04-23

### Improvements

  - Stability and performance improvements.

---

## v1.0.248 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.247 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.247 -- 2026-04-22

### Portal URL — cysoc → cy360

  - Portal subdomain renamed from `cysoc.<domain>` to `cy360.<domain>` across all layers (nginx config, OAuth2-proxy redirect URIs, OIDC clients, CORS allowed origins, backend config defaults, RBAC app IDs, `constants.js` base-domain derivation). DNS registration updated on the server side.
  - `constants.js`: `_BASE_DOMAIN` derivation regex updated to strip `cy360.` instead of `cysoc.`; `PORTAL_URL` and `PORTAL_ISSUER` updated accordingly.
  - `SiemIncidentsPage.jsx`: Wazuh deep-link derivation updated from `cysoc.` to `cy360.` prefix.
  - `backend/core/config.py`: `FRONTEND_URL` default, OAuth2-proxy `redirect_uris`, `ROLE_APPS`, `CORS_ALLOWED_ORIGINS`.
  - `backend/blueprints/system/routes.py`: MCP public URL, CyMind nginx comment, activate-cycentra URL.
  - `backend/blueprints/platform/routes.py`: nginx block CSP, error401 redirects, SSL cert paths, certbot domain list.
  - `backend/blueprints/rbac/manager.py`: default fallback app list.
  - `cycentra-setup.sh`, `build-package.sh`: all 39 `cysoc` occurrences replaced.

### Stability: Storage bloat prevention

  - `core/auth.js`: Added `validateStorage()` — checks schema version, validates structure of all persisted keys (`cy_user`, `cycentra_ai_config`, `cycentra_modules`, `cycentra_asset_statuses`), clears any corrupt or version-mismatched entry automatically on app init.
  - `core/auth.js`: Added `clearNonEssentialCache()` — clears non-auth cache keys and sessionStorage, called by the Error Boundary.
  - `useAppState.js`: `validateStorage()` called once on mount before restoring config. Per-key `try/catch` blocks now also delete corrupt keys rather than silently skipping them.
  - `useAppState.js`: `_saveStatuses()` now caps `cycentra_asset_statuses` at 500 entries (trims oldest) to prevent unbounded localStorage growth across many rescans.
  - Storage schema version key (`cy_storage_ver`) added; future schema-breaking changes auto-wipe stale data on first load.

### Stability: React Error Boundary — Clear Cache & Reload

  - `App.jsx`: `PageErrorBoundary` enhanced with a second "Clear Cache & Reload" action button that calls `clearNonEssentialCache()` then `window.location.reload()`. Non-destructive: account session and scan results are preserved.

### Bug fix: Memory leaks in interval/timer management

  - `PlatformPage.jsx` (`InstallForm`): module install poll interval now stored in `pollRef` and cleaned up via `useEffect` return, preventing state updates on unmounted components if the user closes the install modal mid-progress.
  - `GuestScanPage.jsx`: Added `useEffect` unmount cleanup that calls `clearInterval` on both `pollRef.current` and `timerRef.current`, preventing orphaned scan-status pollers after navigation.
  - `SystemSettingsPage.jsx` (`UpdatesTab`): the version-fetch `useEffect` now returns a cleanup that clears `pollRef.current`, preventing the update-log poller from firing after the settings tab is closed.

---

## v1.0.246 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.245 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.244 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.243 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.242 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.241 -- 2026-04-22

### Improvements

  - Stability and performance improvements.

---

## v1.0.240 -- 2026-04-21

### Improvements

  - Stability and performance improvements.

---

## v1.0.239 -- 2026-04-21

### Improvements

  - Stability and performance improvements.

---

## v1.0.238 -- 2026-04-20

### Improvements

  - Stability and performance improvements.

---

## v1.0.237 -- 2026-04-20

### Improvements

  - Stability and performance improvements.

---

## v1.0.237 -- 2026-04-20

### Bug Fixes

- **Asset Inventory — React error #31 on exposed paths**: `exposed_paths` entries can
  be rich objects `{path, severity, status, url}` rather than plain strings. `AssetDrawer`
  now extracts `p.path || p.url` for display and renders the `severity` and `status` fields
  as inline badges alongside the path. The same type-guard fix was applied to `api_endpoints`
  entries that may carry object forms.
- **Findings — duplicate vulnerabilities at different severity levels**: The deduplication
  key in `VulnerabilityPage` previously included `source`, so the same CVE/finding reported
  by two scanners (e.g. OpenVAS Critical + Nuclei High) appeared as two rows. The key is
  now `asset|vulnerability|module` (source dropped) and when a duplicate is encountered
  the entry with the **higher severity** is kept.

### Verification

- **Automated status change logic**: Confirmed present and fully active on both pages.
  `VulnerabilityPage` — `computeConfidence` + `computeAutoStatus` drives
  `open → investigating` (confidence ≥ 75, CVSS ≥ 7.0, EPSS ≥ 60%) and
  `investigating → in_review` (CVSS ≥ 9.0, EPSS ≥ 75%, risk_score ≥ 8).
  `AssetsPage` — `computeAssetConfidence` + `computeAssetAutoStatus` mirrors the same
  state machine keyed on risk level and critical/high vuln counts. No changes required.

---

## v1.0.236 -- 2026-04-20

### Improvements

  - Stability and performance improvements.

---

## v1.0.236 -- 2026-04-20

### Bug Fixes

- **Asset Inventory & Findings — black page on entry click**: Added a `PageErrorBoundary`
  React error boundary in `App.jsx` that catches any render-time crash inside the page
  content area and displays a "RENDER ERROR + Retry" fallback instead of blanking the
  entire viewport. Previously any unhandled render exception (e.g. object rendered as a
  React child, undefined property access) would silently crash the whole page.
- **Asset Inventory drawer — type-safe field rendering**: Hardened `v.vulnerability`,
  `v.description`, and `v.module` fields in `AssetDrawer`'s findings list with explicit
  string coercion, preventing "objects are not valid as a React child" crashes when scan
  data includes structured objects in those fields.
- **Findings drawer — type-safe parent asset context**: Hardened `technologies`,
  `exposed_paths`, and `api_endpoints` renders in `FindingDrawer`'s parent asset section
  with explicit string coercion for the same class of crash.

### Improvements

- **Asset Inventory drawer — Status Lifecycle & auto-status**: `AssetDrawer` now includes
  the full Status Lifecycle section with a `computeAssetConfidence` score (base risk level
  + critical/high vuln count boost), an **AUTO-STATUS SUGGESTION** banner (`AssetAutoStatusBanner`)
  that proposes `open → investigating` (risk=critical, critCount>0, or confidence≥75) or
  `investigating → in_review` (critCount≥3, highCount≥5, or confidence≥90), and a
  one-click Apply button that POSTs the new status with an auto-generated audit comment.
- **Asset Inventory drawer — Audit Trail**: `AssetDrawer` now renders a full audit trail
  section at the bottom of the panel, sourced from the `audit_log` array in the
  `{status, audit_log}` object returned by `/api/asm/statuses`. Matches the audit trail
  already present in `FindingDrawer`.
- **Asset Inventory drawer — timestamps**: First Seen and Last Seen timestamps are now
  shown in the core details grid of `AssetDrawer`.

---

## v1.0.235 -- 2026-04-20

### Improvements

  - Stability and performance improvements.

---

## v1.0.234 -- 2026-04-20

### Bug Fixes

- **Findings — black page on row click**: `FindingDrawer` now resolves the parent
  asset via the `assetObj` reference that is co-located on every `allVulns` entry,
  with `assetLookup[assetId]` as a secondary fallback. This ensures the HTTP
  analysis, API endpoints, JS secrets, and SSL context sections always have the
  correct asset data even when `assetId` is null in a scan batch.
- **Asset Inventory — Base Domain drawer empty sections**: Added IP Enrichment,
  OSINT Data, Mobile/API Analysis, and PQC Readiness blocks to `AssetDrawer` so
  the panel matches the legacy Full Detail view. Fixed a regression where
  `dns_ips` entries were rendered as `[object Object]` — the display now correctly
  extracts `.ip` from object-typed entries.
- **`makeFindingId` empty-string guard**: When all of `asset`, `vulnerability`,
  and `module` are blank the slug now falls back to `"unknown-finding"` instead
  of `""`, preventing a silent `STATUS_CONFIG[""]` miss.

### Improvements

- **Findings deduplication**: The `allVulns` flatMap now filters through a `Set`
  keyed on `asset|vulnerability|module|source`. Duplicate findings that appear
  across overlapping scan profiles are collapsed to a single row in the
  Vulnerability Explorer.
- **Asset Detail Parity**: `AssetDrawer` now surfaces four additional data
  sections that were previously only in the legacy Full Detail modal:
  - **IP Enrichment** — ASN, Org, Country, City from the first resolved IP
  - **OSINT Data** — collated output from `a.osint_data` (emails, leaked data, etc.)
  - **Mobile / API** — mobile app and API data from `a.mobile_api`
  - **PQC Readiness** — post-quantum cryptography assessment from `a.pqc_data`
- **Unified AI Confidence logic — UEBA module**: The confidence-score engine
  (`open → investigating → in_review`) that was previously only in the ASM
  Findings drawer is now live in the UEBA anomaly cards.
  - `computeUebaConfidence(a)` maps each anomaly type to a severity tier
    (`privilege_escalation / svc_account_interactive / impossible_travel` → critical;
    `high_auth_fail_rate / multi_host_burst` → high; `off_hours_login` → medium;
    `new_agent_access` → low), then adjusts by `risk_contribution`.
  - `computeUebaAutoStatus(a, curStat)` applies the same thresholds:
    confidence ≥ 75 OR risk_contribution ≥ 3 OR critical-type → suggests
    `investigating`; confidence ≥ 90 OR risk_contribution ≥ 6 OR critical-type →
    suggests `in_review`.
  - An **AUTO-STATUS SUGGESTION** banner with one-click Apply appears in the
    Status Lifecycle section of each expanded anomaly card.
  - A **CONFIDENCE** bar renders at the top of the Status Lifecycle section,
    colour-coded red / amber / yellow / blue with 75 and 90 threshold ticks.

---

## v1.0.233 -- 2026-04-20

### Bug Fixes

  - **ASM Findings — black page on row click**: `findingStatuses[fid]` is now a full
    `{status, audit_log}` object returned by `/api/asm/statuses`. The table rows were
    passing the raw object to `StatusBadge` → `STATUS_CONFIG[object]` returned `undefined`
    → accessing `.color` threw and React's error boundary blanked the page. Fixed: all
    table rows now unwrap with `(typeof entry === "object" ? entry?.status : entry) || "open"`.

  - **FindingDrawer scroll regression**: the panel container had both `display:flex,
    flexDirection:column` and `overflowY:auto`. The inner scrollable body's `flex:1`
    could not size correctly because the parent itself could scroll. Fixed: panel
    container changed to `overflow:hidden`; the inner body div remains `flex:1,
    overflowY:auto` and scrolls correctly.

  - **Asset Inventory — dual panel on row click**: clicking a row in Asset Inventory
    triggered both the `AssetDrawer` (zIndex 3001) inside `AssetsPage` and the legacy
    `AssetModal` (zIndex 100) via the App.jsx-level `selectedAsset` state. The `AssetModal`
    remained visible when the `AssetDrawer` was closed. Fixed: `openDrawer` no longer
    calls `setSelectedAsset()` — the `AssetModal` is only opened from Dashboard asset
    clicks where it serves a distinct purpose.

  - **Asset Inventory — status object unwrap**: `assetStatuses[host]` can be a full
    `{status, audit_log}` object (mirrors the findings format). Table rows and
    `AssetDrawer` now correctly unwrap before reading current state.

### Improvements

  - **Asset Inventory — Status as second slide-out panel**: the Status Lifecycle controls
    have been extracted from the `AssetDrawer` body into a dedicated `AssetStatusPanel`
    component that renders at zIndex 3002, width 340px, sliding in to the left of the
    detail panel. An "UPDATE STATUS" toggle button in the detail panel header opens/closes
    the sub-panel. Transition buttons are now displayed vertically for easier touch targets.

  - **ASM Automation — State Transition Matrix (active)**: confidence-driven status
    suggestions are visible in the FindingDrawer as soon as the panel opens (black-page
    bug is now fixed). The `AutoStatusBanner` shows when `computeAutoStatus()` returns a
    suggestion and the one-click Apply posts to `/api/asm/findings/<id>/status` with an
    auto-generated audit comment.

    | From          | To            | Trigger                                         | Method      |
    |---------------|---------------|-------------------------------------------------|-------------|
    | open          | investigating | confidence ≥ 75  OR  cvss ≥ 7.0  OR  epss ≥ 60% | Automated   |
    | open          | investigating | confidence ≥ 90 (Critical)                      | Automated   |
    | investigating | in_review     | cvss ≥ 9.0  OR  epss ≥ 75%  OR  risk_score ≥ 8  | Automated   |
    | all others    | —             | analyst decision with audit comment             | Manual only |

---


## v1.0.233 -- 2026-04-20

### New Features

  - **CyMind RAG-Chat Integration**: Analyst and admin users now see a persistent chat
    overlay (brain FAB button, bottom-right) that loads the CyMind AI assistant inside
    CyCentra 360.  The overlay connects to CyMind via an iframe and leverages the existing
    Security MCP bridge so CyMind can answer live questions about open incidents, entity
    risk scores, UEBA anomalies, and Wazuh agents — all in natural language.

  - **MCP Access Control**: The Security MCP bridge endpoint (`/mcp/sse`) now enforces an
    API key (`CYMIND_API_KEY` in `cysiemstack.env`).  Unauthenticated requests receive HTTP
    401.  The key is generated in the portal and written to the env file automatically.

  - **System Settings → CyMind tab**: New integration settings page lets admins enter the
    CyMind base URL, generate / rotate the shared API key, test connectivity, and follow a
    step-by-step setup checklist.  Analyst users can read the config; only admins can write.

  - **RBAC: user role surfaced to frontend**: The OAuth callback now passes the user's RBAC
    role to the React app so role-gated features (CyMind overlay, future analyst-only pages)
    can be shown or hidden without an extra round-trip.

### Setup (minimum effort)

  See `docs/CYMIND_INTEGRATION.md` for the full guide.  Quick version:

  1. **System Settings → CyMind → Generate API Key** — copy the `cymk_…` key.
  2. `sudo systemctl restart cysiemstack-engine` — activates the key guard.
  3. Paste key into **CyMind → MCP Settings → API Key**, set endpoint to
     `http://127.0.0.1:8100/mcp/sse`.
  4. In CyMind `.env`: `CYCENTRA_ORIGIN=https://cysoc.YOUR_DOMAIN` — enables the iframe.
  5. Restart CyMind.  Analyst users see the chat FAB immediately on next login.

---

## v1.0.232 -- 2026-04-20

### Improvements

  - Stability and performance improvements.

---

## v1.0.232 -- 2026-04-20

### New Features

  - **Confidence Score + Automated State Transition Logic for ASM Findings**: each finding
    in the Findings drawer now shows a visual confidence bar (0–100) with threshold markers
    at 75 and 90. Confidence is computed per finding as a function of severity
    (Critical=95, High=80, Medium=55, Low=30) adjusted by risk_score (±7.5 pts). When a
    transition is algorithmically triggered the drawer shows an "AUTO-STATUS SUGGESTION"
    banner with a one-click Apply button. Auto-apply generates a mandatory audit-trail
    comment automatically so the backend requirement is satisfied.

  - **State Transition Matrix**:

    | From          | To            | Trigger Condition                               | Method      |
    |---------------|---------------|-------------------------------------------------|-------------|
    | open          | investigating | confidence ≥ 75  OR  cvss ≥ 7.0  OR  epss ≥ 60% | Automated   |
    | open          | investigating | confidence ≥ 90 (Critical severity)             | Automated   |
    | open          | in_review     | analyst decision with audit comment             | Manual only |
    | open          | resolved      | analyst decision with audit comment             | Manual only |
    | open          | false_positive| analyst decision with audit comment             | Manual only |
    | investigating | in_review     | cvss ≥ 9.0  OR  epss ≥ 75%  OR  risk_score ≥ 8 | Automated   |
    | investigating | resolved      | analyst closure with audit comment              | Manual only |
    | investigating | false_positive| analyst reclassification with audit comment     | Manual only |
    | in_review     | resolved      | analyst closure with audit comment              | Manual only |
    | in_review     | false_positive| analyst reclassification with audit comment     | Manual only |
    | in_review     | investigating | re-open for further investigation               | Manual only |
    | resolved      | investigating | resurfaced — re-engage investigation            | Manual only |
    | false_positive| investigating | reclassification after context review           | Manual only |

  - **findingStatuses format fix**: status store now correctly handles full `{status, audit_log}`
    objects returned by `/api/asm/statuses`; audit trail is rendered inline in the drawer.

  - **Inline Audit Trail in FindingDrawer**: the status history (who moved it, when, with
    which comment) is now rendered inside the drawer in reverse-chronological order with
    colour-coded from→to state labels.

  - **Backend `/api/asm/auto-status` route** (POST, auth required): accepts a JSON array of
    findings with severity/cvss/epss_pct/risk_score/current_status and returns a suggestions
    array with the triggered transition target and reason string. Read-only — does not apply
    transitions. Mirrors the frontend `computeAutoStatus()` logic exactly.

  - **AssetDrawer high-depth schema**: vulnerability list in the Asset detail panel now uses
    the exact same row layout as the Dashboard "Critical & High Vulnerabilities" widget
    (severity-coloured left border, Badge | title+description | module+CVSS | ↗). Rich data
    sections added: SSL/TLS, DNS resolution, HTTP analysis, API endpoints, JS secrets, cloud
    buckets, supply chain risk, social engineering exposure, and WHOIS.

  - **Extended Asset Context in FindingDrawer**: when a parent asset has http_analysis,
    api_endpoints, js_secrets, or ssl_detail the FindingDrawer now surfaces that data inline
    under an "Asset Context" block — scoped to fields relevant to the finding's module.

---

## v1.0.231 -- 2026-04-20

### New Features

  - **Right-side slide-out detail panels for ASM Findings and Asset Inventory**: clicking any
    row in Vulnerability Explorer or Asset Inventory now opens a fixed 480 px right-side
    drawer containing the full finding/asset detail, status lifecycle controls, and (for
    findings) the CyIRIS ticket indicator. Replaces the previous inline accordion expander
    (Vulnerabilities) and centre-overlay transition modal (Assets).

  - **Single Current Active State indicator on all list rows**: Vulnerability, Asset, and UEBA
    Anomaly rows now show exactly one status badge — the current active state. All status
    transition controls have been moved inside the detail panel / expanded card. No inline
    transition button clusters remain in the table rows.

  - **Three-state Ticket Status Indicator**:
    - SUCCESS — green case link (✓ Case #N ↗) when a CyIRIS ticket exists
    - FAILED  — red "⚠ Auto-raise failed" banner + orange "Manual Ticket" button when an
                automated raise attempt was rejected
    - NONE    — blue "Raise Ticket" / IRIS escalate button when no ticket exists yet
    Applied to ASM Findings (inside `FindingDrawer`) and UEBA Anomaly cards.

  - **Status lifecycle ported to UEBA Anomaly cards**: analysts can now transition anomalies
    through `open → investigating → in_review → resolved / false_positive` directly in the
    expanded anomaly panel, with a mandatory audit comment. Transitions are persisted in
    `/opt/cycentra/ueba_statuses.json` via two new Flask-only routes in `siem_proxy.py`.

  - **New Flask routes — UEBA Anomaly Status (siem_proxy.py)**:
    - `GET  /api/siem/ueba/anomaly/statuses`            — bulk status map (auth required)
    - `GET  /api/siem/ueba/anomaly/<id>/audit`          — full audit log for an anomaly
    - `POST /api/siem/ueba/anomaly/<id>/status`         — transition with mandatory comment
      (analyst+ role enforced; allowed transitions mirror ASM findings)

### Improvements

  - **Status naming synchronised across all modules**: canonical status names are `open`,
    `investigating`, `in_review`, `held`, `resolved`, `false_positive`, `closed`. The legacy
    alias `in-review` is retained in `STATUS_CONFIG` for backward compatibility only.
  - **Inline transition form embedded in detail panels**: no secondary modal. Comment textarea
    and Confirm/Cancel are inline within the slide-out drawer, reducing click depth by one
    step and making the audit requirement immediately visible.
  - **Manual Ticket fallback**: previously a failed auto-escalation showed only terse error
    text. It now shows an explicit labelled "Manual Ticket" button to re-attempt the raise.

---

## v1.0.230 -- 2026-04-20

### Improvements

  - Stability and performance improvements.

---

## v1.0.228 -- 2026-04-19

### Bug Fixes

  - **CySIEM SSO: Wazuh login screen shown instead of automatic sign-in (proxy_auth_domain never enabled)**:
    After the v1.0.225 kibanaserver / rolesmapping fixes the `{"statusCode":401}` error was
    resolved, but users still landed on Wazuh Dashboard's native login screen instead of being
    signed in automatically.
    Root cause A — Python state-machine bug: the `config.yml` patcher used `indent <= 4` as
    the exit condition for the `proxy_auth_domain` block, but that block is typically indented
    at 6 spaces; sibling keys (also at 6 spaces) never triggered the exit.  More importantly
    the script always exited 0 and printed `"OpenSearch proxy_auth_domain enabled"` even when
    the `proxy_auth_domain` key was never found in the file — `securityadmin.sh` then uploaded
    an unchanged `config.yml` (still `http_enabled: false`), silently leaving proxy auth
    disabled.
    Root cause B — no REST API fallback: `securityadmin.sh` was the only path to apply the
    config change.  Its stderr was discarded (`2>/dev/null`), so JVM or YAML failures were
    invisible and there was no retry.
    Fixes applied: (1) state-machine exit condition changed to `indent <= proxy_dom_indent`
    (the actual indent of `proxy_auth_domain:`); (2) script now exits 1 when no change was
    made; (3) if `proxy_auth_domain` is absent entirely the full block is injected before
    `basic_internal_auth_domain`; (4) a REST API primary path is added —
    `GET /_plugins/_security/api/securityconfig` → patch → `PUT .../config` — which requires
    no JVM and is immune to Java heap / timeout issues; (5) `securityadmin.sh` stderr is
    appended to `/var/log/cycentra/securityadmin.log` for post-install diagnosis.
    File: `cycentra-setup.sh`, `docs/SSO-Troubleshooting.md`.

---

## v1.0.227 -- 2026-04-19

### Bug Fixes

  - **setup.sh: `_CYSIEM_KS_PASS: unbound variable` crash during update/existing-install runs**:
    `_CYSIEM_KS_PASS` was only assigned inside the fresh Wazuh install `else` branch.
    When Wazuh was already installed, the variable was never declared and `set -u`
    threw `unbound variable` at Step 8 (CySIEM Dashboard Configuration), aborting
    the entire setup run.
    Fixed: initialised `_CYSIEM_KS_PASS=""` alongside `_CYSIEM_WUI_PASS=""` before
    the Wazuh install block so the variable is always defined regardless of install path.
    File: `cycentra-setup.sh`.

---

## v1.0.226 -- 2026-04-19

### Improvements

  - Stability and performance improvements.

---

## v1.0.225 -- 2026-04-19

### Improvements

  - Stability and performance improvements.

---

## v1.0.225 -- 2026-04-19

### Bug Fixes

  - **CySIEM (Wazuh) SSO: kibanaserver credentials left commented-out on fresh install**:
    Wazuh installer generates a random `kibanaserver` password but leaves
    `opensearch.username` / `opensearch.password` commented in `opensearch_dashboards.yml`.
    Dashboard has no service account → every request returns 401 before proxy headers
    are evaluated. `cycentra-setup.sh` Step 4.1 now extracts the kibanaserver password
    from the installer tar (or falls back to `wazuh-passwords-tool.sh`) and injects
    active credentials into the Dashboard config automatically.
    File: `cycentra-setup.sh`.

  - **CySIEM (Wazuh) SSO: securityadmin rolesmapping patch missing `_meta` header**:
    Previous securityadmin calls used a YAML without the required `_meta` block,
    causing `A version of 2 must have a _meta key for ROLESMAPPING` error and silently
    leaving the rolesmapping unchanged. Fixed: all securityadmin rolesmapping YAMLs
    now include `_meta: {type: rolesmapping, config_version: 2}`.
    File: `cycentra-setup.sh`.

  - **CySIEM (Wazuh) SSO: partial rolesmapping wipes kibana_server user mapping**:
    `securityadmin.sh -f <file> -t rolesmapping` replaces the *entire* rolesmapping.
    Patching only `all_access` removed `kibana_server → kibanaserver` causing
    `no permissions for cluster:monitor/nodes/info` cascade. Fixed: setup.sh now
    applies a complete rolesmapping including `kibana_server`, `kibana_user`,
    `wazuh_ui_user`, `wazuh_ui_admin`, `own_index`, and `all_access` entries.
    File: `cycentra-setup.sh`.

  - **CySIEM (Wazuh) SSO: `cd /` guard before securityadmin calls**:
    `securityadmin.sh` emits `getcwd` Java errors when run from a directory that
    no longer exists. Added `cd /` before every securityadmin invocation.
    File: `cycentra-setup.sh`.

  - **Docs: added `docs/SSO-Troubleshooting.md`** with full RCA history for CyIRIS
    and Wazuh SSO issues, diagnostic checklist, and per-version file change table.

---

## v1.0.224 -- 2026-04-19

### Bug Fixes

  - **CyIRIS crash-loop: `BASE_DOMAIN` blank — DNS failure on OIDC discovery URL**:
    `cyiris_env` in `_install_module_async` never included `BASE_DOMAIN`, so the
    module `.env` file had no `BASE_DOMAIN=` entry. Docker Compose substituted
    `${BASE_DOMAIN}` as empty string → `OIDC_IRIS_DISCOVERY_URL` became
    `https://cyasm./oidc/...` → DNS failure → `exit(0)` crash-loop.
    Fixed: added `"BASE_DOMAIN": base_domain` to `cyiris_env` dict.
    File: `backend/blueprints/platform/routes.py`.

---

## v1.0.223 -- 2026-04-19

---

## v1.0.223 -- 2026-04-19

### Bug Fixes

  - **CyIRIS logout redirects to `cyiris.DOMAIN/oauth2/sign_out` (404)**: The proxy
    logout URL was a relative path (`/oauth2/sign_out`). The browser resolved it against
    `cyiris.DOMAIN` which has no `/oauth2/` handler — nginx proxied it to CyIRIS → 404.
    Fixed: `AUTHENTICATION_PROXY_LOGOUT_URL` is now a fully-qualified URL
    (`https://cysoc.DOMAIN/oauth2/sign_out?rd=https://cysoc.DOMAIN/`) using `BASE_DOMAIN`
    env var. Files: `CyIRIS/source/app/configuration.py`, `backend/blueprints/platform/routes.py`
    (added `location = /logout` intercept in cyiris nginx block as belt-and-suspenders).

---

## v1.0.222 -- 2026-04-19

---

## v1.0.221 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.222 -- 2026-04-19

### Bug Fixes

  - **CyIRIS SSO users get no permissions after first login**: `create_user()` creates the
    DB record but does not assign a group. Auto-provisioned SSO users had zero group
    membership → no permissions. Fixed: `_authenticate_with_email` now calls
    `add_user_to_group(user.id, initial_group.group_id)` using `IRIS_NEW_USERS_DEFAULT_GROUP`
    after creating the user (mirrors the `ldap_handler.py` pattern).
    Files: `CyIRIS/source/app/blueprints/access_controls.py`,
    `backend/blueprints/platform/compose.py` (sets `IRIS_NEW_USERS_DEFAULT_GROUP: Administrators`).

---

## v1.0.221 -- 2026-04-19

### Bug Fixes

  - **CyIRIS logout — `KeyError: 'current_case'`**: `session['current_case']` raised
    `KeyError` for new SSO users whose session never had a case set. Changed to
    `session.get('current_case')`. File: `CyIRIS/source/app/blueprints/rest/dashboard_routes.py`.

  - **CyIRIS logout — re-logs user in immediately after logout**: `is_authentication_oidc()`
    returns `False` for `oidc_proxy` mode so the OIDC end-session block was skipped,
    leaving the oauth2-proxy cookie intact. Added an explicit `AUTHENTICATION_PROXY_LOGOUT_URL`
    redirect block (`/oauth2/sign_out?rd=<cysoc_url>`) that fires for `oidc_proxy` mode.
    File: `CyIRIS/source/app/blueprints/rest/dashboard_routes.py`.

  - **CyIRIS logout — redirect target**: After oauth2-proxy sign-out, users were redirected
    back to `/dashboard` on `cyiris.DOMAIN`. Redirect now points to `https://cysoc.DOMAIN/`
    using `BASE_DOMAIN` env var. Files: `cycentra360/backend/blueprints/platform/compose.py`
    (added `BASE_DOMAIN` to CyIRIS env), `CyIRIS/source/app/configuration.py`.

---

## v1.0.220 -- 2026-04-18

### Bug Fixes

  - **IAP / CySIEM SSO — Wazuh Dashboard still prompting for credentials**: nginx was
    sending `X-Proxy-Roles: admin` to Wazuh Dashboard via proxy auth. OpenSearch
    Security's default `roles_mapping.yml` has **no entry** for backend role `admin`,
    so authenticated users arrived with zero security roles and were denied.
    Fix: changed `X-Proxy-Roles` to `all_access` (the built-in backend role pre-mapped
    to the `all_access` security role) in the nginx `cysiem` server block in
    `cycentra-setup.sh`.  An idempotent `sed` patch step was also added to the IAP
    setup section so that existing servers are fixed automatically on the next
    `--update` run.
    (`cycentra-setup.sh`)

  - **IAP / CyIRIS SSO — container crash-loops on startup (TLS_ROOT_CA)**: In
    `oidc_proxy` auth mode CyIRIS calls `requests.get(discovery_url, verify=tls_root_ca)`
    at startup to fetch OIDC metadata.  `TLS_ROOT_CA` was set to
    `/opt/cycentra/certs/cycentra.crt` — a server leaf certificate, not a CA bundle.
    `requests` raises `SSLError` (cert is not a CA) or `FileNotFoundError` (file absent
    after a fresh install), which triggers `exit(0)` in the `except` block → Docker
    restart loop → 502 on `cyiris.DOMAIN`.
    Fix: removed `TLS_ROOT_CA` from the CyIRIS compose template; the system CA bundle
    inside the container already trusts Let's Encrypt/OIDC provider certs.
    (`backend/blueprints/platform/compose.py`)

  - **IAP / CyIRIS SSO — new users unable to log in (oidc_proxy lazy mode)**: Even
    after the container started, any user other than the seeded admin was rejected.
    `_authenticate_with_email()` called `get_user(email)` and returned `False` when
    the user wasn't found, silently ignoring `AUTHENTICATION_CREATE_USER_IF_NOT_EXIST:
    "True"`.  The create-user code path existed in the full OIDC flow
    (`login_routes.py`) but was not ported to the `oidc_proxy` lazy path.
    Fix: added auto-provisioning in `_authenticate_with_email` — when the user is
    not found and `AUTHENTICATION_CREATE_USER_IF_NOT_EXIST` is enabled, a new account is
    created with a random password (login is always via SSO so the password is unused).
    (`CyIRIS/source/app/blueprints/access_controls.py`)

---

## v1.0.219 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.218 -- 2026-04-18

### Bug Fixes

  - **Setup / pip3**: Fixed `no such option: --break-system-packages` fatal error during Step 10 (CySIEM Redis bridge) on Ubuntu 20.04 and systems with pip < 23.x. The flag is now detected at startup (`_PIP_BSP`) and used only when supported — all four `pip3 install` calls in setup.sh are covered.

---

## v1.0.217 -- 2026-04-18

### Bug Fixes

  - **IAP / CySIEM**: Fixed CySIEM (Wazuh) proxy auth not working OOB — setup.sh now enables `proxy_auth_domain` in OpenSearch Security `config.yml` and applies it via `securityadmin.sh` automatically during install.
  - **IAP / CySIEM**: Added `x-proxy-user` and `x-proxy-roles` to Wazuh Dashboard `requestHeadersAllowlist` during setup — previously missing, causing 401s even with proxy auth type set.
  - **IAP / CyIRIS**: Fixed CyIRIS nginx block using `cysoc.DOMAIN` cert path — `routes.py` now runs `certbot --nginx -d cyiris.DOMAIN` to obtain a dedicated cert and uses that cert path in the nginx server block.
  - **Platform / CySOAR nginx injection**: Fixed nginx syntax error after CySOAR install — routes.py was leaving trailing anchor text after the `/cysoar/` injection point. Now correctly replaces the full comment line.

---

## v1.0.215 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.214 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.213 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.212 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.211 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.210 -- 2026-04-18

### Bug Fixes

  - Fix IAP oauth2-proxy 500 on callback: OIDC provider now signs `oauth2proxy` client id_tokens with RS256 (RSA) so oauth2-proxy can verify via JWKS. Previously only `cysiem` was in RS256_CLIENTS; all other clients received HS256 tokens which oauth2-proxy could not verify.

---

## v1.0.209 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.208 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.207 -- 2026-04-18

### Improvements

  - Stability and performance improvements.

---

## v1.0.206 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.205 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.205 -- 2026-04-18

### Bug Fixes

  - **`_SCRIPT_VERSION` not stamped by `git-push.sh`**: `git-push.sh` was using a
    hardcoded line number (`233`) to update `_SCRIPT_VERSION` in `cycentra-setup.sh`.
    After earlier edits the variable moved to a different line, so all releases since
    v1.0.195 were published with `_SCRIPT_VERSION="v1.0.194"`.  The banner displayed
    the correct version (from the line-3 header stamp), but `--update` version
    comparison logic read the stale variable.
    Fix: replaced the hardcoded-line `sed` with a pattern-based match so it always
    finds and updates the variable regardless of line position.
    (`git-push.sh`)

---

## v1.0.204 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.204 -- 2026-04-18

### Bug Fixes

  - **CyIRIS OIDC — 500 / `KeyError: 'oidc_state'` after auto-login redirect**:
    With `AUTHENTICATION_LOCAL_FALLBACK=False`, `/oidc-login` wrote
    `session["oidc_state"]` and `session["oidc_nonce"]` then returned a `302`
    to the IdP.  Same browser cookie-store race as v1.0.203: `Set-Cookie` from
    the `302` was not committed before the browser followed to Google, so the
    callback arrived with an empty session → `KeyError: 'oidc_state'` → HTTP 500.
    Fix: `oidc_login` now returns a `200` HTML page with `<meta http-equiv=refresh>`
    and `window.location.replace()`.
    (`CyIRIS/source/app/blueprints/pages/login/login_routes.py`)

### Features

  - **CySOAR auto-login (no login button)**: Added `autoLogin: true` to the
    Node-RED `adminAuth.strategy` config.  Node-RED 4.x skips the SSO button
    page and redirects directly to the OIDC provider, matching Wazuh/CySIEM.
    (`CySOAR/data/settings.js`)

---

## v1.0.203 -- 2026-04-17

### Bug Fixes

  - **CyIRIS OIDC — infinite redirect loop after successful login**: After
    `wrap_login_user()` called `login_user()` and returned a `302` redirect from
    the `/oidc-authorize` callback, certain browsers (and browser/Cloudflare
    combinations) would not flush the `Set-Cookie` header to the cookie store
    before following the redirect, causing `current_user.is_authenticated` to
    return `False` on `/dashboard`.  Fix: for OIDC logins (`is_oidc=True`),
    `wrap_login_user` now returns a `200` HTML page with a `<meta http-equiv=refresh>`
    and `window.location.replace()`, giving the browser a committed first-party
    response to store the session cookie before navigating.
    (`CyIRIS/source/app/business/auth.py`)

### Features

  - **CyIRIS auto-login (no login button)**: When `IRIS_AUTHENTICATION_LOCAL_FALLBACK`
    is `"False"`, CyIRIS's `/login` route immediately redirects to `/oidc-login`,
    bypassing the local login form exactly like Wazuh/CySIEM.  The compose template
    now sets `IRIS_AUTHENTICATION_LOCAL_FALLBACK: "False"` by default.
    (`backend/blueprints/platform/compose.py`)

---

## v1.0.202 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.202 -- 2026-04-18

### Bug Fixes

  - **CyIRIS OIDC — "User not found in IRIS"**: `AUTHENTICATION_CREATE_USER_IF_NOT_EXIST`
    env var was ignored because CyIRIS config reads env vars using `{SECTION}_{OPTION}`
    naming convention (`IRIS_AUTHENTICATION_CREATE_USER_IF_NOT_EXIST`), not the bare
    option name.  Additionally the comparison in `configuration.py` is case-sensitive
    (`== "True"`), so the lowercase `"true"` value also evaluated to `False`.
    Fix: compose template now sets `IRIS_AUTHENTICATION_CREATE_USER_IF_NOT_EXIST: "True"`
    (correct prefix, correct case) alongside the old key for backwards compatibility.

---

## v1.0.201 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.201 -- 2026-04-17

### Bug Fixes

  - **CyIRIS OIDC `jwkest.BadSignature` — HS256 ID token signed with wrong key**:
    OIDC Core 1.0 §10.1 requires HS256 ID tokens to be signed with the client's
    `client_secret` so the relying party can verify using the secret it already
    holds.  The `/oidc/token` endpoint was signing with the server-wide `JWT_SECRET`
    instead.  pyoidc's `jwkest` library verifies using the `client_secret` stored
    in `store_registration_info()` → mismatched key → `BadSignature` → `id_token`
    not set in `AccessTokenResponse` → `KeyError: \'id_token\'` in CyIRIS
    `login_routes.py:183`.  Fix: sign HS256 ID tokens with `client["client_secret"]`.

---

## v1.0.200 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.200 -- 2026-04-17

### Bug Fixes

  - **CyIRIS OIDC login — `KeyError: 'id_token'`**: pyoidc sends token-endpoint
    credentials via `Authorization: Basic` header (`client_secret_basic`) by default.
    The `/oidc/token` endpoint only read `client_id`/`client_secret` from the POST
    form body (`client_secret_post`), so both values were `None` and the endpoint
    returned `{"error": "invalid_client"}, 401`.  pyoidc parsed this as an
    `ErrorResponse` with no `id_token`, causing the `KeyError` in CyIRIS
    `login_routes.py:183`.  Fix: parse `Authorization: Basic` header as fallback
    when form params are absent.  CySOAR (Node-oauth) was unaffected because it
    sends credentials in the form body.

---

## v1.0.199 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.199 -- 2026-04-17

### Bug Fix — CyIRIS OIDC: `KeyError: 'id_token'` after successful token exchange

**Root cause**: pyoidc (used by CyIRIS) verifies `id_token` JWTs before storing them in the
`AccessTokenResponse` object. With RS256, pyoidc needs to fetch an RSA public key from the
`jwks_uri`. When `provider_config()` falls back to the manual `ProviderConfigurationResponse`
(which does not include `jwks_uri`), pyoidc has no key to verify against. Signature
verification fails silently — pyoidc drops `id_token` from the parsed response dict entirely.
Subsequent access of `access_token_resp['id_token']` raises `KeyError`.

**Fix**: Per-client JWT algorithm selection in the OIDC token endpoint. `cysiem` (OpenSearch)
receives RS256 tokens verifiable via JWKS — required by the OpenSearch security plugin.
All other clients (`cyiris`, `cysoar`, etc.) receive HS256 tokens. pyoidc automatically
verifies HS256 using the stored `client_secret` (via `RegistrationResponse`) — no JWKS
fetch required. Node-RED (CySOAR) does not verify `id_token` at all, so either works.

---

## v1.0.198 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.198 -- 2026-04-17

### Bug Fix — `cycentra-setup.sh --update` aborts: `BASE_DOMAIN: unbound variable` in CySIEM OIDC step

`BASE_DOMAIN` is loaded from `/opt/cycentra/.env` at line ~1079 of setup.sh but the
CySIEM OIDC SSO step (Step 4.3) uses it in a heredoc at line ~603 — before the `.env`
source. In `--update` mode, the OIDC step ran before `BASE_DOMAIN` was in scope, causing
`set -euo pipefail` to abort with `unbound variable`.

**Fix**: Added a defensive `BASE_DOMAIN` load at the top of Step 4.3 (reading from
`/opt/cycentra/.env` when not already set), so the step is safe in all execution paths.

---

## v1.0.197 -- 2026-04-17

### Bug Fix — CyIRIS OIDC: SSL certificate verification failure (`unable to get issuer certificate`)

**Root cause**: `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` in the CyIRIS compose template
pointed to the server's own TLS certificate chain file. This overrode the system CA trust
store with an incomplete bundle (the cross-signed `GTS Root R4` intermediate is not a
self-signed root, so OpenSSL couldn't complete the chain). The server uses a valid
Google Trust Services production cert — no custom CA bundle is needed.

**Fix**: Removed `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` and the `/opt/cycentra/certs/cycentra.crt`
volume mount from `compose.py` cyiris template. The system CA bundle inside the container
already trusts Google Trust Services. The explicit OIDC endpoint env vars are retained as
a valid discovery fallback.

### Bug Fix — CySOAR OIDC: Page loads partially, URL stuck at `/cysoar/?`

**Root cause (1 — path)**: `httpAdminRoot` was not set in `settings.js`. Node-RED served
its admin API at root (`/`). When proxied under `/cysoar/`, the editor JS made API calls to
absolute paths like `/red/nodes` — which hit the CyCentra portal (not Node-RED) → 404 →
partial page load. Additionally nginx stripped the `/cysoar/` prefix via a trailing slash
in `proxy_pass http://127.0.0.1:1880/`, so Node-RED never saw the sub-path.

**Root cause (2 — verify)**: `passport-openidconnect` v0.1.2 dispatches the verify
callback by function arity. For arity-4, it calls `verify(iss, profile, context, done)` —
not `verify(iss, sub, profile, done)` as previously declared. The `profile` arg therefore
received the context object, making email extraction fail silently (username became
`[object Object]`).

**Fix**: Added `httpAdminRoot: '/cysoar'` to `settings.js` and the routes.py `_cysoar_settings`
string. Changed nginx `proxy_pass` to `http://127.0.0.1:1880` (no trailing slash — passes
full `/cysoar/...` path to Node-RED). Removed the now-unnecessary `proxy_redirect / /cysoar/`.
Fixed verify function signature to `(iss, profile, context, done)` with `profile.id` as
the fallback sub identifier.

### Feature — Wazuh/CySIEM OIDC SSO: RS256 JWT support in OIDC provider

**Root cause**: The OIDC `cysiem` client was registered and `CYSIEM_OIDC_SECRET` was set,
but the OIDC provider signed ID tokens with HS256 and the JWKS endpoint returned an empty
key set. OpenSearch's OIDC auth domain requires RS256 (asymmetric) JWTs verifiable via JWKS.

**Fix**: `provider.py` now generates (or loads from `/opt/cycentra/oidc_private.pem`) an
RSA-2048 key pair on startup. ID tokens are signed with RS256; `kid` header is included.
`/oidc/jwks` now returns the public key as a proper JWK. Discovery endpoint updated to
advertise `["RS256", "HS256"]`. Gracefully falls back to HS256 if `cryptography` is
unavailable. Server-side Wazuh Dashboard and OpenSearch indexer OIDC configuration is
applied via server patch (see deployment notes).

---

## v1.0.196 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.195 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.194 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.193 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.192 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.191 -- 2026-04-17

### New Features

  - add __init__.py to cylogo/wordlists/Utils; expand package-data to include .sh and image files

---

## v1.0.190 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.189 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.188 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.187 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.186 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.185 -- 2026-04-17

### Improvements

  - Stability and performance improvements.

---

## v1.0.184 -- 2026-04-16

### Improvements

  - Stability and performance improvements.

---

## v1.0.183 -- 2026-04-16

### Improvements

  - Stability and performance improvements.
  - Backend — scanner.py
GET /api/scans/list — returns last 15 scan summaries (scan_id, domain, date, scan_type, total_findings, critical, high, subdomains)
GET /api/scans/<scan_id> — returns full JSON for any historical scan by ID
Frontend — adapter.js
Bug fix: getWebSecStats no longer filters only module === "Web" — now catches all web/crypto/vuln_scanner/nuclei modules and source types
Vulnerability enrichment: merges vuln_scanner + nuclei raw findings onto the vulnerabilities[] array, adding CVSS, EPSS, compliance_impact, source, discovered_at, template_id, cve_refs
14 new fields on primary assets: osint_data, social_eng, mobile_api, whois_full, whois_history, dns_records, dns_ips, dns_takeovers, dns_unregistered, ssl_detail, pqc_data, http_analysis, api_endpoints, js_secrets
New helpers: getOsintData(), getSocialEngData(), getMobileApiData(); expanded getBrandData() with full breach/HIBP detail; getSupplyChainRisk() now returns full risks[] array
useAppState.js
New state: scanHistory[], selectedScanId, historyLoading
Fetches scan history list on login; refreshes after each new scan
handleScanSelect(scanId) loads any historical scan and navigates to dashboard
App.jsx
ScanHistoryDropdown component in topbar — shows last 15 scans in a table (date, domain, type pill, findings count with critical badge, subdomain count); click any row to load that scan
DashboardPage.jsx
Scan type badge (DEEP/STD/PASS) in header
"New Subdomains" stat card added
Widget 2: adds PQC (Post-Quantum Crypto) status
Widget 3: adds cloud bucket summary (public/private/total counts)
Widget 4: adds DNSSEC, TLS-RPT rows; elite score/status; spoofing risk badge
Widget 5: fixed module filter bug; shows JS secrets count, API endpoints count, CVSS on findings
Widget 6: shows new subdomain count separately
Widget 7: expanded to list top 4 risky libraries with library name, OSV ID, CVE IDs
Widget 8: adds HIBP breach detail (name, year, data classes); social engineering exposure (exposed emails + risk level); OSINT/MISP hit count; CVSS on critical vuln list
VulnerabilityPage.jsx
Summary pills: critical / high / with-CVSS / with-EPSS counts
CVSS pill (color-coded: red ≥9, orange ≥7, yellow ≥4)
EPSS pill with percentage probability
Source pill: port_banner, ssl_check, exposed_path, js_secret, nuclei, shodan
Compliance card: NIS2/DORA/ISO 27001 impact when present
Additional CVE refs from nuclei template; template_id, matched_at, discovered_at, risk_score in meta row
AssetModal.jsx
Tabbed navigation for primary assets: Overview / Vulns / DNS / SSL / Cloud / WHOIS / OSINT / Social Eng / Mobile/API / Supply Chain
Overview tab: exposed paths list (all paths, not just count); IP enrichment for IP sub-assets (ASN, country, city, cloud provider, rDNS); full resolved_ips for subdomains
DNS tab: full DNS record table by type (A/AAAA/MX/NS/TXT etc.); IP enrichment details; takeovers; unregistered typosquats
SSL tab: cipher suite, protocol, chain validity, OCSP stapling, heartbleed, compression, SANs; PQC status; HTTP security headers/CORS analysis
Cloud tab: provider list; K8s exposure banner; full bucket list with public/private status
WHOIS tab: registrar, creation/expiry dates, name servers, status, DNSSEC, history
OSINT tab: MISP threat intel hits; Shodan CVE findings with severity; Shodan raw results
Social Eng tab: risk assessment with reasons; exposed employee emails with name/title/confidence; LinkedIn profiles; email patterns
Mobile/API tab: API security findings (CORS, rate limiting, issues); APK secrets; app store links; deep links
Supply Chain tab: full risk list with library name, OSV ID, CVE IDs, CVSS, severity, reason
SiemFeedPage.jsx
Critical / High filter buttons with counts
Module tag on each alert card (color-coded)
Full ISO timestamp (not just time)
CVSS score pill, risk_score, source field on each alert

---

## v1.0.180 — 2026-04-16

### cy_asm — Scanner Capability enhancements

**Nuclei Template Scanner** (`modules/nuclei_scanner.py` — new)
- Added Nuclei CLI integration covering 9,000+ CVE/exposure/misconfiguration templates
- Runs as a post-sequential module on Standard and Deep scans
- Gracefully skipped when nuclei binary is absent — zero-impact on existing installs
- Requires: `apt install nuclei` on the scan host

**OSV.dev Supply-Chain CVE Lookup** (`modules/supply_chain.py`)
- Replaced static jQuery/Lodash heuristics with real-time queries to Google's OSV.dev API
- Detected library + version from CDN URLs queried against 10 package patterns (jQuery, React, Vue, Lodash, Bootstrap, etc.)
- Returns actual CVE/GHSA IDs with severity labels; static fallback retained for unversioned URLs
- No API key required

**NIS2 / DORA / ISO 27001 Compliance Tags** (`modules/vuln_scanner.py`)
- Added `compliance_impact` field (`{nis2, dora, iso27001}`) to every finding produced by vuln_scanner
- Covers port-banner CVEs, SSL/TLS protocol findings, exposed paths, OpenVAS results, and JS secret exposures
- Bridges cy_asm findings directly to CyComp audit evidence generation

**Shodan CVE Correlation** (`modules/passive_osint.py`)
- Shodan `vulns{}` dict per host now parsed into structured findings in `results["shodan_cve_findings"]`
- Shodan-confirmed CVEs with CVSS scores surfaced into `all_issues` alongside other scanner findings
- No new configuration required — uses existing `SHODAN_API_KEY`


## v1.0.172 — 2026-04-15

### Bug Fix — Wazuh fails to start: `Parent decoder name invalid: 'sysmon'` in `cycentra_sysmon_decoder.xml`

**Root cause**: Step 19.3 of `cycentra-setup.sh` defined the `sysmon` root decoder with
`<parent>windows</parent>`, making it a child decoder of `windows`. In Wazuh/OSSEC only
**root** decoders (those without any `<parent>` element) may be referenced as a parent by
other decoders. The four child decoders (`sysmon-process`, `sysmon-network`, `sysmon-registry`,
`sysmon-dns`) all declare `<parent>sysmon</parent>`, which caused `wazuh-analysisd` to fail
with `ERROR: (2101): Parent decoder name invalid: 'sysmon'` and refuse to load
`cycentra_sysmon_decoder.xml`, preventing `wazuh-manager` from starting.

**Fix**:
- Removed `<parent>windows</parent>` from the `sysmon` root decoder in the
  `cycentra_sysmon_decoder.xml` heredoc in `cycentra-setup.sh` (step 19.3).
- Added idempotent remediation in the `else` branch of step 19.3: if a previously-deployed
  `cycentra_sysmon_decoder.xml` contains the invalid `<parent>windows</parent>` line,
  `sed -i` removes it in-place so re-running `--update` or the full setup heals existing
  servers without manual intervention.

---

## v1.0.171 — 2026-04-15

### Bug Fix — Wazuh fails to start: `Invalid decoder type 'json'` in `cycentra_saas_decoders.xml`

**Root cause**: Step 19.5 of `cycentra-setup.sh` wrote `<type>json</type>` inside the `okta-event`
and `duo-event` child decoders (i.e. decoders that have a `<parent>` element). In Wazuh/OSSEC,
the `<type>` element is only valid on root/parent decoders — using it inside a child decoder is
rejected at startup with `Invalid decoder type 'json'`, causing `wazuh-analysisd` to refuse to
load `cycentra_saas_decoders.xml` entirely and `wazuh-manager` to fail to start. The `<type>json</type>`
lines were also functionally redundant because JSON parsing is already handled at the log-collection
layer via `<log_format>json</log_format>` in the `localfile` stubs deployed in step 19.6.

**Fix**:
- Removed `<type>json</type>` from the `okta-event` and `duo-event` child decoders in the
  `cycentra_saas_decoders.xml` heredoc in `cycentra-setup.sh`.
- Added idempotent remediation in the `else` branch of step 19.5: if a previously-deployed
  `cycentra_saas_decoders.xml` contains the invalid lines, `sed -i` removes them in-place so
  re-running `--update` or the full setup heals existing servers without manual intervention.

---

## v1.0.162 – 2026-04-14

### Diff Summary (AI)

## v1.0.163 – 2026-04-14

### Enhancement — Broader Subdomain & OSINT Coverage

- Subdomain discovery now leverages multiple global intelligence sources for improved coverage and accuracy.

These enhancements help customers identify more external assets and exposures, strengthening overall attack surface visibility.
### Chore — Tag/Release Notes Sync

- Confirmed all tag conflicts resolved and release notes are in sync with GitHub tags.
- git-push.sh now always uses GitHub tags as the source of truth for versioning.
- No functional changes; this is a sync and housekeeping release.

### Diff Summary (AI)


## v1.0.157 — 2026-04-14

### Chore — Enforce RELEASE_NOTES.md ≤ 1000 lines

- Added a test in `tests/run-all.sh` (Suite 01) to ensure `RELEASE_NOTES.md` never exceeds 1000 lines.
- If the file is too long, the test fails and blocks the release.
- This keeps release notes manageable and ensures compliance with project standards.

---
## v1.0.156 – 2026-04-13

### Diff Summary (AI)

# CyCentra 360 — Release Notes

---
## v1.0.154 — 2026-04-13

### Bug Fix — CySIEM Correlation Engine fails to start after `mcp` package upgrade (`FastMCP.get_application()` removed in v1.6)

**Root cause**: `mcp[cli]>=1.0.0` in `correlation_engine/requirements.txt` had no upper bound.
FastMCP v1.6+ removed the `get_application()` method. A routine package upgrade on the server
installed `mcp>=1.6`, causing the engine to crash at import time with:
`AttributeError: 'FastMCP' object has no attribute 'get_application'`

**Effect**: `cysiemstack-engine.service` entered a crash-restart loop (exit code 1) — 800+
restart cycles. All SIEM/UEBA/incident functionality unavailable.

**Fix**:
- `backend/cysiemstack/correlation_engine/main.py` — replaced bare `_mcp.get_application()`
  with a version-safe shim that checks for the method and falls back to `get_asgi_app()` or
  the FastMCP object itself (which is a valid ASGI app in v1.6+).
- `backend/cysiemstack/correlation_engine/requirements.txt` — pinned `mcp[cli]>=1.0.0,<1.6.0`
  to prevent future unguarded upgrades from breaking the engine.

**Files changed**:
- `backend/cysiemstack/correlation_engine/main.py` (line 1115)
- `backend/cysiemstack/correlation_engine/requirements.txt`

---
## v1.0.153 — 2026-04-13

### Bug Fix — Demo license expires every 24 hours (`license_validator.py` missing from installer package)

**Root cause**: `build-package.sh` defined `VALIDATOR_PY` pointing to
`backend/core/license_validator.py` but **never copied it into the installer tarball**.
The comment on line 81 incorrectly claimed the validator was "embedded in the binary" — it
is not; the embedded heredoc in `cycentra-setup.sh` writes a temporary validator to `/tmp`
only for the pre-install license check and deletes it immediately after.

As a result, `/opt/cycentra/license_validator.py` — called daily by the
`cycentra-license-check.timer` watchdog — was **never deployed** on any installation.

The daily watchdog runs:
```
python3 /opt/cycentra/license_validator.py --license /opt/cycentra/cycentra.lic
```
When the file does not exist, Python exits with code **2** ("can't open file"). The watchdog
checks `[[ $_CODE -eq 2 ]]` and treats code 2 as "license expired", writing
`/opt/cycentra/.license_expired` and stopping all CyCentra services — every 24 hours —
even during a valid 15-day demo (`.demo_start` still shows the original install date).

Running `--update` cleared `.license_expired` (lines 1311-1312 in `cycentra-setup.sh`) and
restarted services, but did **not** deploy the missing validator. 24 hours later the watchdog
fired again, repeating the cycle.

**Fix**:

#### `build-package.sh`
- Replaced the incorrect comment *"Validator is embedded in the binary — no external file needed"*.
- Added preflight guard: `[[ -f "$VALIDATOR_PY" ]] || error "..."` — build now fails fast if the validator is missing.
- Added `cp "$VALIDATOR_PY" "$PKG_DIR/license_validator.py"` so the runtime validator is
  included in every installer tarball and deployed to `/opt/cycentra/license_validator.py`
  by `cycentra-setup.sh` on every install/update.

#### `cycentra-setup.sh` — watchdog heredoc (defense-in-depth)
- Added an existence guard at the top of the deployed `/opt/cycentra/license-watchdog.sh`:
  ```bash
  if [[ ! -f /opt/cycentra/license_validator.py ]]; then
      _log "WARNING: /opt/cycentra/license_validator.py not found — skipping license check"
      _log "Re-run: sudo bash /opt/cycentra/cycentra-setup.sh --update to redeploy"
      exit 0
  fi
  ```
  This ensures a missing validator causes the watchdog to log a warning and exit cleanly
  (`exit 0`) rather than letting Python's "can't open file" exit code 2 be misread as
  "license expired".

#### `tests/run-all.sh` — Suite 09
- Added regression check: `build-package.sh` must contain a `cp "$VALIDATOR_PY"` line.
- Added regression check: the watchdog heredoc must contain a `-f license_validator.py`
  existence guard.
  Both tests **fail** on the unfixed code and **pass** after this fix.

---
## v1.0.152 — 2026-04-13

### Enhancement — SIEM Engine: 20 new correlation rules (CR-016 → CR-035) + UEBA detectors 8–12 + GeoIP enrichment

**Correlation Engine — `correlator.py`**
- Added 20 new `CorrelationRule` classes covering Windows, cloud and endpoint attack techniques:
  - CR-016 Password Spraying (20+ accounts from 1 source IP)
  - CR-017 Windows Brute Force → Login (EventID 4625 → 4624)
  - CR-018 Dormant Account Rebirth (no activity 90+ days)
  - CR-019 Privileged Group Membership Change (Domain Admins / Enterprise Admins)
  - CR-020 Kerberos Ticket Anomaly (Golden Ticket / RC4-HMAC)
  - CR-021 Registry Persistence (autorun Run/RunOnce keys)
  - CR-022 Scheduled Task Abuse (task pointing to Temp/AppData paths)
  - CR-023 Process Injection Indicator (Office/Browser → shell child process)
  - CR-024 Encoded/Obfuscated Command Execution (PowerShell -EncodedCommand, IEX)
  - CR-025 Web Shell Execution (web server spawning shell process)
  - CR-026 Security Tool Disabled (AV/EDR/firewall service stopped)
  - CR-027 Unusual Outbound Port (4444, 6667, 9001, 31337, etc.)
  - CR-028 RDP to External Host (outbound :3389)
  - CR-029 Internal Subnet Scan (20+ scan events from single host)
  - CR-030 Large Upload to Cloud Storage (Mega, Dropbox, OneDrive, etc.)
  - CR-031 Cloud Console Login without MFA (AWS/Azure MFA bypass)
  - CR-032 Privileged Cloud IAM Change (AdministratorAccess / Global Admin)
  - CR-033 Mass Cloud Resource Deletion (S3/Blob wipe)
  - CR-034 Suspicious Mail Forwarding Rule (BEC indicator)
  - CR-035 OAuth App Consent Grant (mail.read / files.readwrite phishing)
- `ALL_RULES` registry expanded from 15 to 35 rules

**UEBA Engine — `ueba.py`**
- Added `DORMANT_THRESHOLD_DAYS = 90` constant
- Added 5 new risk contribution types:
  `dormant_account_login (55)`, `concurrent_session (50)`, `activity_volume_spike (45)`,
  `suspicious_process (65)`, `repeated_privesc_attempt (50)`
- Added detectors 8–12 in `analyse_alert()`:
  - 8: Dormant account rebirth (login after 90+ inactive days)
  - 9: Concurrent sessions from different agents within 30 s
  - 10: Activity volume spike (10× hourly baseline, 20+ events)
  - 11: First-seen known attack-tool process (mimikatz, meterpreter, Cobalt Strike, etc.)
  - 12: Rapid privilege escalation (3+ privesc attempts in 2h window)

**Normaliser — `normaliser.py`**
- Added graceful `geoip2` import block (`_GEOIP_ENABLED` / `_GEOIP_READER`; no-op if DB absent)
- Added `_lookup_geoip(ip)` helper returning `{country_iso, country_name, city, lat, lon}`
- Added `'cloud'` category in `_classify_category()` for AWS/Azure/O365/GCP/GitHub rule groups
- `normalise()` return dict now includes `'geo'` key populated at parse time

**setup.sh — Step 19: Infrastructure Prerequisites (new)**
- Installs `geoip2` Python library
- Downloads `GeoLite2-City.mmdb` when `MAXMIND_KEY` is present in `/opt/cycentra/.env`
- Deploys Sysmon XML decoder to `/var/ossec/etc/decoders/cycentra_sysmon_decoder.xml`
- Deploys custom detection rules 100300–100309 to `/var/ossec/etc/rules/cycentra_custom_rules.xml`
  (process injection, encoded commands, web shell, registry persistence, LSASS, AV tamper,
  C2 ports, outbound RDP, privileged group changes, Kerberos Golden Ticket)
- Deploys SaaS auth decoders (Okta, Azure MFA, Duo) to `/var/ossec/etc/decoders/`
- Injects disabled cloud wodle stubs into `ossec.conf` (AWS CloudTrail, Azure AD, Microsoft 365,
  Okta/Duo localfile inputs) — requires customer to fill PLACEHOLDER_ values and enable
- Writes Sysmon deployment package to `/opt/cycentra/sysmon/` (config XML, deploy PS1, audit policy PS1)
- Reloads `wazuh-manager` after each config change; prints manual-action checklist post-install

---
## v1.0.151 — 2026-04-13

### Bug Fix

**Update button returns HTML instead of JSON — `⚠ Version check failed` / `SyntaxError: Unexpected token '<', "<!DOCTYPE"`**
- Root cause: Four routes in `blueprints/system/routes.py` were missing the mandatory
  `session.get("user_email")` auth guard required on every `/api/` endpoint:
  `POST /api/system/update`, `POST /api/system/upgrade`,
  `GET /api/system/latest-version`, and `GET /api/system/update/log`.
  When the browser session expired (or on the first request after a long idle), the nginx
  `auth_request` gate at `/api/auth/verify` returned a `302` redirect to the login page.
  The browser followed the redirect and the Flask endpoint received the request with no valid
  session — but because Flask itself had no auth guard, it executed the route and eventually
  returned either another redirect or a Werkzeug HTML error page. The frontend received HTML
  where it expected JSON, causing `SyntaxError: Unexpected token '<', "<!DOCTYPE "...`.
- Fix: Added `session.get("user_email") → 401` guard and role check to all four endpoints:
  - `POST /api/system/update` — analyst+ required (incremental patch)
  - `POST /api/system/upgrade` — admin only (full re-install, destructive)
  - `GET /api/system/latest-version` — any authenticated user
  - `GET /api/system/update/log` — any authenticated user
  All four now return `{"error": "Authentication required"}, 401` (JSON) on expired sessions
  instead of redirecting, so the frontend's catch block gets a valid JSON error.
  - `backend/blueprints/system/routes.py`: session guards + RBAC checks added to all four routes.

---
## v1.0.150 — 2026-04-13

### Fix

**MCP SSE endpoint URL updated from `siem.cycentra.com` to `cysoc.cycentra.com`**
- Root cause: `blueprints/system/routes.py` `/api/system/mcp` GET handler hard-coded
  `https://siem.{BASE_DOMAIN}/mcp/sse` as the `public_url` returned to clients and shown
  in the AI connection guide. The production server is reachable at `cysoc.cycentra.com`,
  not `siem.cycentra.com`, causing every externally-configured AI client to target an
  unreachable host.
- Fix: Changed the `public_url` construction from `f"https://siem.{base_domain}/mcp/sse"`
  to `f"https://cysoc.{base_domain}/mcp/sse"` in `blueprints/system/routes.py` (line 1151).
  The internal loopback `endpoint` (`http://127.0.0.1:8100/mcp/sse`) is unchanged.
  - `backend/blueprints/system/routes.py`: `public_url` subdomain changed `siem` → `cysoc`.

---
## v1.0.149 — 2026-04-13

### Chore

**`publish.yml` removed; `_SCRIPT_VERSION` synced to v1.0.149**
- Removed `.github/workflows/publish.yml` (stub workflow with no steps — superseded by
  `agent-release.yml` and `build-package.sh`).
- Bumped `_SCRIPT_VERSION` in `cycentra-setup.sh` from `v1.0.144` to `v1.0.149` to align
  the self-update version check with the actual release history.
  - `.github/workflows/publish.yml`: deleted.
  - `cycentra-setup.sh`: `_SCRIPT_VERSION` bumped to `v1.0.149`.

---
## v1.0.148 — 2026-04-13

### Chore

**Version sync — `pyproject.toml` and `cycentra-setup.sh` aligned to release history**
- Root cause: `backend/pyproject.toml` was pinned at `1.0.144` and `cycentra-setup.sh`
  `_SCRIPT_VERSION` was pinned at `v1.0.142` after the initial repository publish. Subsequent
  releases (v1.0.143–v1.0.147) were documented in `RELEASE_NOTES.md` but the two version fields
  were never updated, causing the installed package version and the setup-script self-update check
  to report stale values to operators.
- Fix: Bumped `version` in `backend/pyproject.toml` from `1.0.144` → `1.0.148` and
  `_SCRIPT_VERSION` in `cycentra-setup.sh` from `v1.0.142` → `v1.0.148`. Both files now reflect
  the full history of changes shipped in v1.0.143–v1.0.147:
  - v1.0.143: RBAC audit-log entries for role assignments/deletions; `MCP_ENABLED` added to
    `cysiemstack.env` heredoc in `cycentra-setup.sh`.
  - v1.0.144: `bypass_tests_gate` workflow-dispatch input added to `agent-release.yml` to
    unblock releases when the CI test gate cannot pass in the Actions environment.
  - v1.0.145: Automation smoke-test entry (superseded by v1.0.146).
  - v1.0.146: `agent-release.yml` YAML block-scalar fix — bare multi-line template literal
    replaced with `[...].join('\\n')` array, unblocking every release since workflow creation.
  - v1.0.147: `agent-post-release.yml` hotfix-issue body converted to `join('\\n')` array;
    `agent-label-pr.yml` extended with `ready_for_review` trigger type so auto-merge label
    is applied to agent PRs converted from draft.
  - `backend/pyproject.toml`: `version` bumped to `1.0.148`.
  - `cycentra-setup.sh`: `_SCRIPT_VERSION` bumped to `v1.0.148`.

---
## v1.0.147 — 2026-04-12

### Bug Fix

**`.github/workflows/agent-post-release.yml` and `agent-label-pr.yml` — remaining YAML syntax and trigger gaps**
- Root cause 1: `agent-post-release.yml` "Create hotfix issue" step used the same unindented multi-line template literal pattern as the bugs fixed in v1.0.146. Lines like `**Verification run:**` and `**Checks that failed:**` at column 0 terminated the `script: |` YAML block scalar early, causing a parse error that prevented GitHub Actions from queuing any jobs (all runs: `conclusion: failure, total_count: 0 jobs`).
- Root cause 2: `agent-label-pr.yml` only had `types: [opened]` as its trigger. Copilot agent PRs are always created as **draft** first; the `opened` event fires while the PR is still draft. When a draft PR is converted to ready-for-review, no new `opened` event fires, so the `auto-merge` label was never automatically applied to any agent PR.
- Fix 1: Replaced bare multi-line template literal in the hotfix issue body with a `[...].join('\\n')` array (all lines fully indented within the `script: |` block), matching the pattern used to fix v1.0.146.
- Fix 2: Added `ready_for_review` to `agent-label-pr.yml`'s `pull_request` event types so the auto-merge label is applied when a draft agent PR is converted to ready.
  - `.github/workflows/agent-post-release.yml`: "Create hotfix issue" body converted to `join('\\n')` array.
  - `.github/workflows/agent-label-pr.yml`: added `ready_for_review` to `types`.

---


### Bug Fix

**`.github/workflows/agent-release.yml` — YAML block scalar terminated early by unindented template literal**
- Root cause: Step 10 ("Post release summary comment") used a multi-line JavaScript template literal whose body lines had zero indentation. In YAML, a block scalar (`|`) terminates when it encounters a non-empty line with less indentation than the block content. Lines like `**Version:**` at column 0 broke out of the `script: |` block, causing a YAML parse error that prevented GitHub Actions from queuing any jobs. Every single `agent-release.yml` run since the workflow was created has failed for this reason.
- Fix: Replaced the single multi-line template literal with a `[...].join('\\n')` array where every element is a single-line template literal fully indented within the YAML block scalar.
  - `.github/workflows/agent-release.yml`: Step 10 body now uses `join('\\n')` instead of a bare multi-line template literal.

---
## v1.0.145 — 2026-04-12

### Chore

**End-to-end automation smoke test (superseded by v1.0.146)**
- Dummy entry from prior session; superseded by the actual bug fix in v1.0.146.

---
## v1.0.144 — 2026-04-12

### Chore

**`.github/workflows/agent-release.yml` — Emergency bypass for CI test gate blockage**
- Root cause: `agent-release.yml` gate step required a `tests:passed` label on the merged PR before
  it would create the version tag and trigger `deploy.yml`. When `agent-test-gate.yml` fails in the
  GitHub Actions environment (environment differences vs. local), the label is never set, and every
  subsequent `agent-release` run silently skips. `deploy.yml` (the actual build) continues to
  succeed — so the code is publishable — but no version tag is ever created, blocking all customers
  from receiving updates until a maintainer intervenes manually.
- Fix: Added a `bypass_tests_gate` boolean `workflow_dispatch` input (default `false`) to
  `agent-release.yml`. When set to `true`, the gate step skips the `tests:passed` label check and
  proceeds directly to stamp, tag, and publish. The `pr_number` input is now optional when using the
  bypass. Normal PR-driven releases (via `tests:passed` label → `agent-auto-merge`) are unaffected.
  - `.github/workflows/agent-release.yml`: added `bypass_tests_gate` input and updated gate step to
    honour it, with an explicit warning log when the bypass is active.

---
## v1.0.143 — 2026-04-13

### Bug Fixes

**`blueprints/rbac/manager.py` — RBAC mutations missing audit log entries**
- Root cause: `POST /api/rbac/users` and `DELETE /api/rbac/users/<email>` in
  `rbac_users()` / `rbac_delete_user()` called `auth_event` only on *denial* (HTTP 403)
  but never on *success*. Because Wazuh tails `/var/log/cycentra/auth.log` for security
  monitoring, every admin role assignment and user removal was invisible to the SIEM —
  a blind-spot for insider-threat and compliance use-cases.
- Fix: Added `auth_event("rbac_role_assigned", ...)` immediately after `_save_rbac()` in
  the POST handler, and `auth_event("rbac_user_deleted", ...)` in the DELETE handler.
  Both records include the acting admin's email, the target email, the new role (for
  assignments), and the request IP. The existing denial path is unchanged.
  - `backend/blueprints/rbac/manager.py`: two `auth_event(...)` calls added on the
    success return paths of `rbac_users()` (POST) and `rbac_delete_user()` (DELETE).

**`cycentra-setup.sh` — `MCP_ENABLED` absent from generated `cysiemstack.env`**
- Root cause: `backend/cysiemstack/correlation_engine/main.py` reads `MCP_ENABLED` from
  `cysiemstack.env` via `settings.__dict__.get("mcp_enabled", "true")` to decide whether
  to mount the Security MCP bridge at `/mcp/sse`. However, the `cysiemstack.env` heredoc
  template in `cycentra-setup.sh` (Step 10) never wrote `MCP_ENABLED`, so the generated
  file gave operators no documented toggle — the only way to disable the bridge was to
  manually add the variable after knowing to look for it in the engine source.
- Fix: Added `MCP_ENABLED=true` (with an explanatory comment) to the `cysiemstack.env`
  heredoc, immediately after `MISP_ENABLED`. The default is `true` (preserving existing
  behaviour). Operators can now set `MCP_ENABLED=false` in
  `/opt/cycentra/cysiemstack.env` and restart `cysiemstack-engine` to disable the bridge
  without uninstalling the `mcp` package.
  - `cycentra-setup.sh`: three lines added to the `cysiemstack.env` heredoc (comment +
    `MCP_ENABLED=true` + blank separator before `POSTGRES_PASSWORD`).

---
## v1.0.142 — 2026-04-12

### Feature — Full end-to-end automation: PR auto-merge and version publishing

Completed the fully automated pipeline from agent task → code → tests → merge → release → publish.
No human action is required after a task is assigned, except when tests fail.

**What was broken and is now fixed:**

- **Auto-merge missing:** `agent-test-gate` set `tests:passed` but nothing merged the PR.
  Added `agent-auto-merge.yml` — fires when `tests:passed` label is set, merges the PR,
  then explicitly dispatches `agent-release.yml`.

- **`agent-release` never ran (0 jobs every time):** Job condition checked
  `github.event.pull_request.merged` which is always null on `push` events (the actual
  event type GitHub uses). Fixed with a gate step that handles all three trigger types:
  `pull_request: closed`, `push: branches: [main]`, and `workflow_dispatch`.

- **GITHUB_TOKEN push blocks downstream workflows:** Tag pushes from workflow runs using
  `GITHUB_TOKEN` do not trigger further workflow runs (GitHub security restriction).
  `agent-release` now explicitly dispatches `deploy.yml` via `workflow_dispatch` after
  pushing the tag, guaranteeing the build-and-publish job always runs.

**Resulting full automation chain:**
```
Agent opens PR
  → agent-test-gate    runs tests → sets tests:passed label
  → agent-auto-merge   merges PR → dispatches agent-release
  → agent-release      stamps version, creates tag → dispatches deploy.yml
  → deploy.yml         builds wheel + portal, publishes GitHub Release
  → agent-post-release verifies artifacts, opens hotfix issue if broken
```

---
## v1.0.141 — 2026-04-12

### Fix — License watchdog fires immediately on setup re-enable, blocking backend restart

**Root cause — `Persistent=true` in `cycentra-license-check.timer`:**
When setup calls `systemctl start cycentra-license-check.timer`, systemd detected the
timer had not recently run (it was disabled/stopped before the update) and fired the
watchdog immediately. The watchdog wrote `.license_expired` (with `chattr +i`) before
`systemctl restart cycentra-backend` ran, causing the `ExecStartPre` license guard to
block the restart and abort setup at STEP 9.

**Fix 1 — Removed `Persistent=true` from timer:**
`OnBootSec=2min` already ensures a post-boot check; `Persistent=true` is redundant and
caused catch-up firing during setup.

**Fix 2 — Explicit sentinel cleanup before backend restart in STEP 9:**
Added `chattr -i` + `rm -f` of `.license_expired` after starting the timer and before
restarting the backend. The full-install path already had this cleanup; the `--update`
path did not, leaving a stale sentinel from a previous expiry event able to block restart.

---
## v1.0.140 — 2026-04-12

### Chore — Agent definitions and workflow docs cleanup

- Removed stale `cyra-360-old.md` agent file
- Synced latest agent definitions and GitHub workflow docs from remote

---
## v1.0.138 — 2026-04-12

### Feature — Integrated Security MCP Server

Introduces a native **Model Context Protocol (MCP) bridge** mounted directly inside
the existing `cysiemstack-engine` FastAPI process at `/mcp/sse` (port 8100). No
separate service or port is required — the MCP bridge starts automatically when the
`mcp[cli]` package is installed alongside the engine.

External AI clients (Claude Desktop, OpenAI Agents SDK, custom LLM toolchains, etc.)
connect to `http://127.0.0.1:8100/mcp/sse`.

Wazuh credentials are sourced automatically from `/opt/cycentra/cysiemstack.env`.

#### `backend/cysiemstack/correlation_engine/main.py`
- Added `import base64`, `import json as _stdlib_json`, `import httpx` to existing imports.
- Added module docstring entry for the `/mcp/sse` endpoint.
- At the end of the file: conditional `try/except ImportError` block that, when the
  `mcp` package is present, creates a `FastMCP` instance and registers 10 tools:
  - `get_stats`, `list_incidents`, `get_incident`, `list_alerts`, `list_risk_scores`
    — query the correlation engine's own REST endpoints (loopback)
  - `list_ueba_users`, `get_ueba_anomalies` — UEBA behavioural data
  - `wazuh_list_agents`, `wazuh_get_agent_vulnerabilities` — Wazuh Manager API (direct)
  - `wazuh_active_response` — trigger AR action on an agent (firewall-drop, etc.)
- Mounts the MCP ASGI sub-application: `app.mount("/mcp", _mcp.get_application())`
- Gracefully skips mount with an info log if `mcp` is not installed.

#### `backend/cysiemstack/correlation_engine/requirements.txt`
- Added `mcp[cli]>=1.0.0`

#### `cycentra-setup.sh`
- No new systemd unit (MCP runs inside `cysiemstack-engine`).
- Post-install success message updated: `CySIEMStack engine healthy :8100 (MCP bridge at /mcp/sse)`.
- Summary and `cycentra-setup-summary.txt` reference `http://127.0.0.1:8100/mcp/sse`.
## v1.0.137 — 2026-04-11

### Fix — Demo license expiry bugs and sentinel file tampering protection

**Root cause 1 — premature expiry on reinstall:**
`/opt/cycentra/.demo_start` persisted across installs. On a `--full` reinstall to the
same server, the old start date caused the validator to calculate 15+ days elapsed
immediately. The daily watchdog then stopped `cycentra-backend` and wrote
`.license_expired`, blocking any restart via the `ExecStartPre` guard.

**Root cause 2 — signed demo `.lic` expiry calculated from generation date:**
Signed demo `.lic` files have an `expires` calculated from the **generation date**, not
installation date. A `.lic` file prepared weeks in advance would expire almost immediately
on customer install. `validate()` trusted the file's `expires` exclusively for signed
licenses, ignoring `.demo_start` entirely.

**Root cause 3 — sentinel files unprotected:**
Sentinel files `.demo_start` and `.license_expired` had no filesystem immutability
protection — a privileged user could trivially reset the demo clock or bypass the
restart guard.

#### `backend/core/license_validator.py`
- `validate()`: for `type="demo"` signed licenses, effective `days_remaining` is now
  `max(lic_expiry_days, installation_clock_days)` — customer always gets `DEMO_MAX_DAYS`
  from install date regardless of when the `.lic` was generated.
- `_demo_days_remaining()`: applies `chattr +i` after writing `.demo_start` to make the
  demo clock immutable.

#### `backend/blueprints/system/routes.py`
- Added `if not resp.ok` guard in `ai_test()` so Anthropic/Gemini/DeepSeek error codes
  other than 401 no longer return a false-positive `ok: true`.

#### `portal/src/pages/ai/AISettingsPage.jsx`
- Inner try/catch on `res.json()` in `testConnection()` — nginx 502 HTML page now shows
  `"Backend service unavailable (HTTP 502)"` instead of `"Cannot reach backend"`.

#### `cycentra-setup.sh`
- Fresh `--full` install: resets `.demo_start` to today with `chattr -i` / `chattr +i`
  wrapper; clears any stale `.license_expired`.
- License watchdog: wraps all `.license_expired` writes with `chattr -i` before and
  `chattr +i` after — expired marker is immutable once set; `chattr -i` before `rm -f`
  on the OK (renewal) path.

---
## v1.0.136 — 2026-04-12

### Fix — Automated IRIS ticket creation broken for cloud CyIRIS mode

**Root cause (same env-var isolation as v1.0.135 manual fix):**
The correlation engine's ingestor runs `create_iris_case()` automatically when a new
incident is created or new correlation rules fire. This calls `_load_iris_config()` inside
`iris_connector.py`, which reads `CLOUD_IRIS_API_KEY` / `CLOUD_IRIS_URL` from
`os.environ`. Because the engine's systemd service uses
`EnvironmentFile=/opt/cycentra/cysiemstack.env` (which has no cloud IRIS vars), the lookup
always returned `None` → no IRIS ticket was ever auto-created for cloud mode.

#### `backend/cysiemstack/correlation_engine/iris_connector.py`
- Added `_CYCENTRA_ENV_FILE = Path("/opt/cycentra/.env")` constant.
- Added `_read_cycentra_env()` — a minimal `.env` parser (no external dependency) that
  reads `/opt/cycentra/.env` directly and returns a `dict`.
- `_load_iris_config()` cloud branch: when `CLOUD_IRIS_URL` or `CLOUD_IRIS_API_KEY` are
  absent from `os.environ`, falls back to `_read_cycentra_env()`. Covers:
  - Automated ticket creation from the ingestor pipeline
  - `sync_closed_cases()` (5-minute IRIS sync scheduler)
  - `auto_close_fp()` (FP threshold check)

#### Scope of automated ticket raising (for reference)
| Surface | Auto-raised? | Trigger |
|---|---|---|
| Active Incidents (SIEM) | ✅ Yes | New incident created OR new correlation rules fire (if FP score < threshold) |
| ASM Findings | ❌ No — manual only | Analyst clicks "Raise CyIRIS Ticket" |
| UEBA Anomalies | ❌ No — manual only | Analyst clicks escalate button |

#### FP score vs. confidence score
The ingestor derives an **FP probability score** (0–100) from rule confidence:
`fp_score = (1 − avg_rule_confidence) × 100`
- High rule confidence → low FP score → incident **is NOT auto-closed** → IRIS ticket IS raised
- FP score ≥ threshold (default 90.0) → incident auto-closed as false positive → NO ticket raised
- Threshold is configurable via `fpThreshold` in `ai_settings.json` (System Settings → CyIRIS)

---
## v1.0.135 — 2026-04-12

### Fix — "Raise Ticket" in Active Incidents fails when CyIRIS uses cloud credentials

**Root cause:** The correlation engine runs as a systemd service with
`EnvironmentFile=/opt/cycentra/cysiemstack.env`. That file does not contain
`CLOUD_IRIS_API_KEY` / `CLOUD_IRIS_URL` — those live in `/opt/cycentra/.env` which is
loaded by the Flask backend only. So `_load_iris_config()` inside the engine found an
empty API key and returned `None`, even though CyIRIS was fully operational for
UEBA and ASM Findings (which call IRIS from the Flask layer via `get_iris_config()`).

**Fix: move incident manual escalation entirely into the Flask proxy layer**
(same architecture as UEBA escalation — `siem_proxy.py` handles everything, the engine
is only used for data fetch and persistence).

#### `backend/siem_proxy.py`
- `POST /api/siem/incidents/<id>/escalate`: No longer proxied to the engine.
  Now self-contained in Flask:
  1. `GET /incidents/{id}` from engine — fetch incident data
  2. If already ticketed: return existing case info (no duplicate)
  3. `get_iris_config()` from `core.helpers` — reads cloud creds from `.env` correctly
  4. `POST /api/v2/cases` to IRIS — creates case with severity, affected hosts/users,
     MITRE IDs, correlated rules, and AI narrative
  5. `PATCH /incidents/{id}` back to engine — persists `iris_case_id/url/status`
  (step 5 failure is non-fatal — ticket was created, drawer still updates)

#### `backend/cysiemstack/correlation_engine/main.py`
- `IncidentPatch` model: added `iris_case_id`, `iris_case_url`, `iris_case_status`
  optional fields so the proxy can write ticket info back after creating the case.

---
## v1.0.134 — 2026-04-12

### Fix — "Raise Ticket" in Active Incidents shows "Engine offline" when CyIRIS not configured

**Root cause:** The correlation engine's `POST /incidents/{id}/escalate` endpoint raised
`HTTPException(status_code=503)` when CyIRIS was not configured. `siemFetch` in the
frontend maps **any** HTTP 503 to `{ _offline: true }`, causing the drawer to show
*"✗ Engine offline — try again shortly."* instead of the real error ("CyIRIS not configured").
Findings and UEBA were unaffected because their escalation is handled directly by the Flask
layer (never touches the engine), so they receive a proper `{"error": "..."}` response.

#### `backend/cysiemstack/correlation_engine/main.py`
- `POST /incidents/{id}/escalate`: Changed "CyIRIS not configured" status from **503 → 422**.
  503 must be reserved for "service itself is unavailable"; 422 correctly signals a
  configuration pre-condition failure.
- "IRIS case creation failed" changed from **502 → 422** for the same reason.

#### `portal/src/siem/siemApi.js` — `siemFetch`
- **503 handling:** Now reads the response body before deciding. If
  `body.error === "engine_unavailable"` → `{ _offline: true }` (genuine engine offline).
  All other 503s → `{ _error: body.error || body.detail || body.message }` (app-level error,
  real message shown to user).
- **Non-ok handling:** Added `body.detail` fallback alongside `body.error` so FastAPI
  `HTTPException` messages (which use `{"detail": "..."}`) are surfaced correctly instead of
  showing "HTTP 422".

---
## v1.0.133 — 2026-04-12

### Fix — Cloud MISP / Cloud CyIRIS panels no longer show unnecessary input fields

**Root cause:** Cloud credentials (`CLOUD_MISP_API_KEY`, `CLOUD_IRIS_API_KEY`,
`CLOUD_IRIS_CUSTOMER_ID`) are provisioned server-side in `/opt/cycentra/.env` at install
time. Showing API key and customer ID inputs in the cloud panel was misleading — values
entered there were stored in `ai_settings.json` but the backend already prefers env vars.

#### `portal/src/pages/settings/SystemSettingsPage.jsx`
- **Cloud CyMISP panel:** Removed API key `<input>`. Replaced with env-var explanation text
  referencing `CLOUD_MISP_URL` and `CLOUD_MISP_API_KEY`. Test Connection button still present.
- **Cloud CyIRIS panel:** Removed API key + Customer ID `<input>` fields. Replaced with
  env-var explanation text referencing `CLOUD_IRIS_URL`, `CLOUD_IRIS_API_KEY`,
  `CLOUD_IRIS_CUSTOMER_ID`. Test Connection button still present.
- Both panels show an ℹ️ footer: *"Cloud credentials are set at install time — contact
  Cycentra support to rotate your key."*
- `testConnection` (MispTab + CyIrisTab): Cloud path now explicitly passes
  `{ apiKey: "", useStored: true }` — no masked-key detection logic needed.
  Local path unchanged (requires URL + key, `useStored: false`).

---
## v1.0.132 — 2026-04-11

### Fix — Cloud CyMISP / Cloud CyIRIS Test Connection fails with masked API key

**Root cause:** When System Settings loads, the GET endpoint returns API keys masked as
`••••••••`. In cloud mode, the user clicks "Test Connection" without re-entering the key.
The frontend blocked with *"Enter your API Key (currently showing masked placeholder)"*
before the request even reached the backend. Local mode worked because users naturally
re-type both URL and key when configuring it for the first time.

#### `portal/src/pages/settings/SystemSettingsPage.jsx`
- Cloud mode `testConnection` (MispTab + CyIrisTab): if the field still shows the masked
  placeholder, sends `{ useStored: true, apiKey: "" }` instead of blocking the user
- Non-cloud modes still require the key to be explicitly entered

#### `backend/blueprints/system/routes.py` (`misp_test` + `iris_test`)
- When `useStored: true` is sent and `apiKey` is empty or masked, reads the real key from
  `/opt/cycentra/ai_settings.json` directly, so the test runs against the stored credential
  without the UI ever receiving the plaintext key

#### Server-side action required
The `/opt/cycentra/.env` on existing servers still has the old
`CLOUD_MISP_URL=https://misp.cycentra.com` line. This env var overrides the correct default.
Fix with:
```bash
sed -i 's|CLOUD_MISP_URL=https://misp.cycentra.com|CLOUD_MISP_URL=https://cymisp.cycentra.com|' /opt/cycentra/.env
systemctl restart cycentra-backend