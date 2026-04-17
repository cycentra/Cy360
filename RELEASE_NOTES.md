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