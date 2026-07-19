# Host Security Profile Enhancement Plan

**Status as of 2026-07-16:** Phases 0-6 ALL IMPLEMENTED (code complete, not yet deployed/tested
against a live agent or a live Postgres — see §9 for exact deploy + verification steps). Every
Host Security Profile tab (Inventory, SCA, Vulnerabilities, FIM, Malware, MITRE, Compliance) now
has a real EDR/ITAM-native data path with graceful fallback to the legacy Wazuh path.
**Re-verified 2026-07-18** (still code-only, not yet live-tested) — see §14 for a scope
clarification on what "Compliance" means in two different parts of this codebase.

**Owner:** g-cyra-360
**Trigger:** Host Intelligence → Hosts & Posture → host detail panel renders Inventory / SCA /
Vulnerabilities / FIM / Malware / MITRE / Compliance tabs empty.

If this session drops, re-read this doc top to bottom before touching code — it has the
root-cause diagnosis, the full phase plan, and a "what was built" section per phase so work
doesn't get re-derived or duplicated.

---

## 1. Root cause (confirmed by codebase audit, 2026-07-16)

The Host Security Profile UI (`portal/src/pages/hosts/HostDetailPanel.jsx`, tabs at line 36) and
its backing `host_posture_cache` table + `/api/siem/hosts/<id>/*` routes in `backend/siem_proxy.py`
are **Wazuh-shaped**: populated by live Wazuh Manager API calls or by `alerts` rows that only
Wazuh's ingest pipeline ever wrote. This project has moved away from using Wazuh as a sensor
(see `docs/SIEM_PROXY_AUDIT.md`, updated 2026-07-16). Once Wazuh creds/pipeline are gone, those
tabs go empty or 503.

Meanwhile, before this work started:
- **CyEDR's agent** (`agent/cyedr_agent.py`) never collected self-host inventory, had no File
  Integrity Monitoring, no CVE/vulnerability matching, no SCA/CIS checks.
- **ITAM** (`backend/blueprints/itam/`) already had a real, working inventory + NVD/KEV CVE-match
  pipeline (`network_assets`, `software_inventory` tables), populated only via *agentless*
  SSH/WinRM deep scans of *other* hosts — never the agent's own host.
- **ITAM ↔ EDR linkage was broken**: `network_assets` had no `hardware_uuid` column; the only link
  was IP address, which breaks on DHCP re-lease/roaming.
- **MITRE tagging already existed** server-side (`confidence_matrix.py`'s `HEURISTIC_TABLE`,
  `normalizer.py` — every `edr_detections` row already gets `mitre_id`/`mitre_tactic` at ingest
  time), but nothing rolled it up per-host or surfaced it in the Host Security Profile.

**Architecture decision (locked in, held for all 7 phases):** Do not build a second inventory/CVE
pipeline. CyEDR self-reports into ITAM's existing `network_assets`/`software_inventory` tables
(gets NVD/KEV CVE matching for free), linked via `hardware_uuid`. New EDR-only concerns (FIM, SCA)
get new tables owned by the EDR blueprint. The `/api/siem/hosts/<id>/*` URL surface in
`siem_proxy.py` stays as-is (no frontend rewrite) — only its backend implementation is rewired to
try EDR/ITAM data first, Wazuh as an optional fallback.

Full route-by-route audit backing this: `docs/SIEM_PROXY_AUDIT.md` (recommends retiring
`/hosts/<id>/inventory` and `/hosts/<id>/vulnerabilities` in favor of ITAM, flags `/hosts/<id>/sca`
as needing a genuine rebuild).

---

## 2. Phase plan

| Phase | Scope | Status |
|---|---|---|
| 0 | Foundation: `network_assets.hardware_uuid` column + hardware_uuid-based crossref/backfill | **DONE** |
| 1 | Asset Inventory: agent self-collects hardware/OS/software/services/processes/users/groups/net-if/ports/certs → new ingest route → writes into ITAM tables | **DONE** |
| 2 | FIM: `watchdog`-based platform watchers (inotify/fanotify Linux, FSEvents macOS, ReadDirectoryChangesW Windows) + nightly baseline hash; new `edr_fim_baseline`/`edr_fim_events` tables | **DONE** |
| 3 | SCA/CIS: policy-as-code checks bundled per-OS, agent executes locally; new `edr_sca_results` table; real compliance score derived from SCA pass rate | **DONE** |
| 4 | Vulnerabilities: Host Vuln tab reads ITAM's already-CVE-matched `software_inventory` (join via `network_assets`) instead of the dead Wazuh path | **DONE** |
| 5 | MITRE + Malware rollup: per-host rollup off `edr_detections` (MITRE tagging already existed via `confidence_matrix.py` — this phase was "surface it per-host", not "build it from scratch") | **DONE** |
| 6 | Rewire host detail routes: `_sync_host_detail`, `/sca`, `/vulnerabilities`, `/alerts` in `siem_proxy.py` blend EDR+ITAM as primary, Wazuh as optional fallback only; EDR-only hosts no longer 404 | **DONE** |

**2026-07-16: user requested all pending phases in one session** — Phases 2-6 were built on top of
the already-shipped Phase 0-1 foundation from the prior turn in this same session. Not yet deployed
or tested against a live agent/DB (see §9). See §10 for what's deliberately still open.

---

## 3. Phase 0 — Foundation (hardware_uuid linkage) — DONE

**What was built:**
- `backend/blueprints/itam/routes.py` — `network_assets.hardware_uuid TEXT` column added to the
  `init_itam_tables()` ALTER TABLE loop, plus 6 more Phase-1 columns (`processes`, `drivers`,
  `local_groups`, `network_interfaces`, `certificates`, `cloud_metadata`, all JSONB). Partial
  unique index `idx_network_assets_hwuuid ON network_assets(hardware_uuid) WHERE hardware_uuid IS
  NOT NULL`.
- `_crossref_agents_conn()` — hardware_uuid-first `edr_agent_id` re-link step *before* the existing
  IP-address match (stable identity survives roaming/DHCP re-lease). The pre-existing
  "auto-populate new edr_agents into network_assets" INSERT now also carries `hardware_uuid` with
  `ON CONFLICT (ip_address) DO UPDATE SET hardware_uuid = COALESCE(...)` — since that INSERT runs
  every crossref cycle, this *is* the backfill mechanism (no separate backfill function needed).
- `_resolve_or_create_network_asset(conn, agent_id, hardware_uuid, hostname)` — synchronous
  match-or-create used by the Phase 1 ingest route, since a brand-new agent can't wait for the next
  periodic crossref cycle.

---

## 4. Phase 1 — Asset Inventory — DONE

**Agent side (`agent/cyedr_agent.py`):** ~15 module-level collector functions inserted after
`_collect_arp_neighbors()`: `_local_run()`, `_collect_macs()`, `_collect_bios_info()`,
`_collect_hardware_info()`, `_collect_os_info()`, `_collect_installed_software()`,
`_collect_running_services()`, `_collect_running_processes()`, `_collect_installed_drivers()`,
`_collect_local_users()`, `_collect_local_groups()`, `_collect_network_interfaces()`,
`_collect_listening_ports()`, `_collect_certificates()`, `_collect_cloud_metadata()`. Every
collector is try/except-wrapped, returns partial/empty data rather than raising.
`InventoryReporter(threading.Thread)` — 30s startup delay, then every 6h, POSTs to
`/api/edr/inventory`. Output shape mirrors `NetworkProbePoller._ssh_deep_scan()`'s result dict.

**Backend ingest (`backend/blueprints/edr/routes.py`):** `POST /api/edr/inventory` +
`@require_agent_token`. Resolves/creates the `network_assets` row via
`_resolve_or_create_network_asset()`, then calls ITAM's `_ingest_deep_scan_result(asset_id, ip,
result)` — the single reuse point that gets NVD/KEV CVE-matching for free.

**`_ingest_deep_scan_result()` extension (`backend/blueprints/itam/routes.py`):** also persists
`processes`/`drivers`/`local_groups`/`network_interfaces`/`certificates`/`cloud_metadata` via
`COALESCE(%s::jsonb, <column>)` with a `None` param when absent, so a legacy agentless re-scan
never wipes previously self-reported data.

**Host detail route (`backend/siem_proxy.py`):** `_edr_itam_inventory(agent_id, pkg_limit)`,
called first inside `siem_host_inventory()`. Looks up `network_assets WHERE edr_agent_id = %s OR
siem_agent_id = %s`, joins `edr_agents`, pulls packages from `software_inventory`. Returns `None`
if nothing exists yet → falls through unchanged to the Wazuh path.

---

## 5. Phase 2 — File Integrity Monitoring — DONE

**Agent side (`agent/cyedr_agent.py`):** `_DEFAULT_FIM_PATHS` (per-OS list of security-critical
paths: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/root/.ssh`,
`/etc/cron.d` on Linux; `/etc/sudoers`, `/Library/LaunchDaemons`, `/Library/LaunchAgents` on macOS;
`drivers\etc\hosts`, `System32\config`, `System32\Tasks` on Windows). `_fim_hash_file()`
(SHA-256, 64MB cap), `_fim_file_meta()` (size/owner/permissions/hash via `os.stat`).

`FimMonitor(threading.Thread)` — lazily imports `watchdog` (new dependency, added to
`agent-packages/build-edr-packages.sh`'s requirements + PyInstaller `hiddenimports`); if absent,
logs a warning and the thread exits cleanly rather than crashing the agent. Uses
`watchdog.observers.Observer` — **this is the literal inotify (Linux) / FSEvents (macOS) /
ReadDirectoryChangesW (Windows) primitives the spec calls for**, via a well-tested cross-platform
wrapper instead of three hand-rolled ctypes bindings. Watches each default path (recursive for
directories, parent-dir-with-filename-filter for single files). Events are queued and flushed
every 15s as a batch POST to `/api/edr/fim/events`; a full baseline snapshot (capped 2000
files/root) is sent to `/api/edr/fim/baseline` once ~45s after startup and then every 24h.

**Design choice — diffing happens server-side, not in the agent:** the agent reports only current
on-disk facts (path, hash, size, owner, permissions, event_type); it holds no local baseline state.
`edr_fim_baseline` (new table, one row per `(agent_id, path)`, upserted) is the server's rolling
"last known good"; the ingest route diffs against it.

**Backend (`backend/blueprints/edr/routes.py`):**
- `POST /api/edr/fim/events` — for each event, looks up the prior hash in `edr_fim_baseline`,
  derives severity from (changed-hash vs. create vs. delete) × (path-is-critical flag, via
  `_FIM_CRITICAL_RE` matching passwd/shadow/sudoers/sshd_config/LaunchDaemons/etc.), writes to
  `edr_fim_events`, then rolls `edr_fim_baseline` forward (or deletes the baseline row on delete).
- `POST /api/edr/fim/baseline` — pure upsert into `edr_fim_baseline`, no `edr_fim_events` write (a
  baseline refresh is not itself a change event).

**DB schema (`backend/blueprints/edr/response_orchestrator.py: ensure_tables()`):**
`edr_fim_baseline` (`id, agent_id, path, sha256, size, owner, permissions, modified_at,
last_baselined`, unique on `(agent_id, path)`), `edr_fim_events` (`id, agent_id, event_type, path,
old_path, old_sha256, new_sha256, size, owner, permissions, username, severity, detected_at`).

**FIM tab wiring (`backend/siem_proxy.py`):** `_edr_native_alerts()` (shared with malware, see §7)
queries `edr_fim_events` when `category == "fim"`, formatted into the exact column shape
`_sync_host_alerts()`'s legacy `alerts`-table query already produces, so both paths feed the same
row-mapping code. Returns `None` (not empty) if zero rows, so the caller falls back to the legacy
`alerts` table instead of showing a false "no events".

**Known limitation:** FIM events carry the file `owner` (from `os.stat`) but not the *process* that
made the change — `watchdog` doesn't expose the triggering PID. Full process attribution would
need Linux `fanotify`/`auditd` (already has some coverage via CyEDR's existing `AuditdReader`) or
Windows ETW File Provider; out of scope for this pass.

---

## 6. Phase 3 — Security Configuration Assessment (SCA/CIS) — DONE

**Design choice — policy-as-code as embedded Python data, not parsed YAML files:** each check is
`{id, title, rationale, remediation, severity, check}` where `check` is a callable returning
`True`/`False`/`None` (not applicable). Same declarative shape the spec describes; avoids bundling
a YAML parser into a hardened security-agent PyInstaller binary. Swappable for real YAML policy
packs later without changing the ingest contract (`POST /api/edr/sca/results`' body shape doesn't
care how the agent produced the check list).

**Checks built (`agent/cyedr_agent.py`):**
- **Linux** (`_SCA_CHECKS_LINUX`, 10 checks): firewall active (ufw/firewalld), SSH
  `PermitRootLogin no` / `PasswordAuthentication no` (via `sshd -T`, resolves effective config
  including includes/defaults — more accurate than grepping the raw file), password max age ≤90
  days, kernel ASLR enabled, IPv4 forwarding disabled, SELinux/AppArmor enforcing, auditd running,
  cron restricted to `/etc/cron.allow`, `/etc/passwd` not world-writable.
- **macOS** (`_SCA_CHECKS_DARWIN`, 5 checks): Gatekeeper, application firewall, FileVault, System
  Integrity Protection, Remote Login (SSH) disabled unless required.
- **Windows** (`_SCA_CHECKS_WINDOWS`, 8 checks, via PowerShell): Firewall all profiles, Defender
  real-time protection, BitLocker on system drive, LSA Protection (RunAsPPL registry DWORD),
  PowerShell Script Block Logging, SMBv1 disabled, Credential Guard running, RDP Network Level
  Authentication required.

`_run_sca_checks()` executes the platform's list, catching exceptions per-check (one bad check
can't take down the scan). `ScaScanner(threading.Thread)` — 60s startup delay, then every 6h,
POSTs `{policy_id, policy_name, checks: [...]}` to `/api/edr/sca/results`. One synthetic "policy"
per OS: `CY-CIS-LINUX` / `CY-CIS-MACOS` / `CY-CIS-WINDOWS`.

**Backend (`backend/blueprints/edr/routes.py`):** `POST /api/edr/sca/results` — upserts into
`edr_sca_results` keyed `(agent_id, policy_id, check_id)`; a re-scan overwrites in place (the table
always reflects the latest run, not a growing history).

**DB schema:** `edr_sca_results` (`id, agent_id, policy_id, policy_name, check_id, title,
description, rationale, remediation, result, severity, scanned_at`).

**SCA tab wiring (`backend/siem_proxy.py`):** `_edr_sca(edr_agent_id, result_filter, page,
per_page, offset)` — new helper, tried first inside `siem_host_sca()`. Normalises the frontend's
`result=` filter (`"not applicable"` with a literal space, matching Wazuh's own convention) against
this table's `not_applicable` (underscore) in both directions. Builds the same `{policies, checks,
total, source}` shape `SCATab` already expects. Returns `None` if zero rows → falls back to
`_sca_from_alerts_db()`.

**Bonus fix while touching this route:** `siem_host_sca()` previously returned a hard `503 {"error":
"Wazuh API credentials not configured"}` when `WAZUH_API_PASS` was unset, *before* ever reaching
the `_sca_from_alerts_db()` fallback that already existed for exactly this situation — that
fallback was dead code, unreachable. Now: EDR-native → `_sca_from_alerts_db()` → only then (if
somehow still nothing) the old 503 path, though in practice `_sca_from_alerts_db()` always returns
a (possibly empty) 200 response, so the 503 branch should no longer be reachable in normal
operation.

---

## 7. Phase 4 — Vulnerabilities — DONE

No new pipeline — this phase is pure wiring. ITAM's `software_inventory.cves` (JSONB array of
`{cve_id, severity, score, description}` per package, populated by `enrich_asset_cves()` against
NVD, with a local NVD mirror + CISA KEV cross-reference already in `blueprints/itam/nvd_mirror.py`)
already had everything needed — it just wasn't reachable from the Host Security Profile.

**`backend/siem_proxy.py`:** `_edr_itam_vulnerabilities(agent_id, page, per_page, severity)` — new
helper, tried first inside `siem_host_vulnerabilities()`. Resolves the linked `network_assets` row,
then `SELECT ... FROM software_inventory si, jsonb_array_elements(si.cves) elem WHERE
si.asset_id = %s` to flatten the per-package CVE arrays into individual vulnerability rows, sorted
by CVSS score descending. Severity filter is normalised case-insensitively (frontend sends
`Critical`/`High`/etc., this table stores lowercase). Returns `None` if no CVE data exists yet →
falls back to the legacy Wazuh-vulnerability-detector `alerts` path.

**Not built (explicitly out of scope per the plan's §1 architecture decision, item deferred to a
future phase if wanted):** Nmap/RustScan/Nuclei network vulnerability scanning, weak
TLS/SMB/RDP/SSH config detection as a *separate* vuln category (the SSH/SMB/RDP checks that did
get built in Phase 3 live in SCA, not here — CIS-style pass/fail, not CVE-style).

---

## 8. Phase 5 — MITRE ATT&CK + Malware rollup — DONE

**Important correction from the original plan draft:** MITRE tagging was **not** missing — it
already existed. `confidence_matrix.py`'s `HEURISTIC_TABLE` maps every heuristic trigger to a
`(technique_id, tactic)` pair (e.g. `T1055` → Defense Evasion, `T1003.001` → Credential Access),
and `normalizer.py`'s `normalise_telemetry()` already sets `mitre_id`/`mitre_tactic` on every alert
before `_store_detection()` writes it into `edr_detections`. What was actually missing was a
**per-host rollup** surfacing that data in the Host Security Profile — `edr_detections` was never
queried by any host-detail route.

**Malware:** `_sync_host_alerts()`'s new EDR-native branch (`_edr_native_alerts()`, shared code
path with FIM — see §5) queries `edr_detections WHERE event_category = 'malware'` when
`category == "malware"`. This already covers the existing YARA/RUN_SCAN pipeline (rule_id
100210/100211, already tagged `event_category='malware'` by `normaliser.py`'s `MALWARE_RULE_IDS`
per prior work) — no new detection logic needed, just the query.

**MITRE rollup (`backend/siem_proxy.py`):** `_edr_native_host_overlay()` (new, see §9 for full
detail — it's the shared overlay function for Phase 5+6) queries `edr_detections GROUP BY mitre_id,
mitre_tactic` for the last 30 days, and `_sync_host_detail()` merges those counts into the
alerts-table-derived `mitre_breakdown` (summed by `(mitre_id, tactic)` key, not simply replaced —
a host with both Wazuh-era and EDR-era detections shows a true combined picture) and unions
`mitre_techniques`.

---

## 9. Phase 6 — Host detail route rewire (EDR-native fallback) — DONE

**The bigger issue found during this phase:** `_sync_host_detail()` (backs the Overview, MITRE, and
Compliance tabs, and is the single fetch `MitreTab`/`ComplianceTab` read from) started with
`SELECT * FROM host_posture_cache WHERE agent_id = %s` and returned `None` → **404 for the entire
host detail panel** if that row didn't exist. `host_posture_cache` is populated only by
`_refresh_host_cache_sync()`, which is Wazuh+`alerts`-table-only (confirmed: zero references to
`edr_agents`/`network_assets` in that function). An EDR-only host that has never triggered a
Wazuh-style refresh cycle would 404 the whole panel, not just show empty tabs.

**Fix, `backend/siem_proxy.py`:**
- `_resolve_edr_agent_id(cur, agent_id)` (new, shared helper used by every Phase 2-6 route) —
  resolves the URL's `agent_id` to the corresponding `edr_agents.agent_id`, whether the URL id is
  already an EDR agent's own UUID or a Wazuh/SIEM-style id linked via `network_assets` (Phase 0
  crossref). Returns `None` if this host has no EDR agent at all.
- `_edr_native_host_overlay(cur, edr_agent_id)` (new) — builds `{mitre_breakdown,
  mitre_techniques, sca, vuln_counts, fim_events, malware_detections, compliance_score}` purely
  from `edr_detections`/`edr_fim_events`/`edr_sca_results`/ITAM `software_inventory`.
- `_sync_host_detail()`: if `host_posture_cache` has no row **but** an EDR agent is resolvable,
  builds a minimal `host` dict from `edr_agents` (hostname, IP, os_type, status, last_seen) instead
  of returning `None`/404. The overlay then fills in real SCA/vuln/FIM/malware/MITRE data on top of
  that minimal shell. If `host_posture_cache` *does* have a row, the overlay's values take priority
  over the (possibly stale/absent) Wazuh-derived ones only where the overlay actually has data
  (`overlay["sca"]`, `overlay["vuln_counts"]` etc. are `None` when empty, so a host with real Wazuh
  SCA data but no EDR SCA data yet keeps showing the Wazuh numbers rather than getting zeroed out).
  EDR-native SCA failures (`edr_sca_results WHERE result='failed'`) similarly take priority over
  the legacy alerts-table SCA-failure query when present.
- Response gained a `"source": "edr_native" | "wazuh"` field for debugging which path served a
  given host.

---

## 10. Reference: exact current API contracts (frontend expectations)

From `portal/src/pages/hosts/HostDetailPanel.jsx` (audited 2026-07-16, do not re-derive — these
shapes were deliberately held stable across all 7 phases per the §1 architecture decision):

- **Inventory tab** (`InventoryTab`, `785-925`): `GET /api/siem/hosts/<agentId>/inventory` (`:792`).
  `{agent:{...}, os:{...}, hardware:{...}, packages:[...], packages_total}`.
- **SCA tab** (`SCATab`, `411-551`): `GET /api/siem/hosts/<agentId>/sca?result=&page=&per_page=`
  (`:426`). `{policies:[...], checks:[...], total, source}`. `result` filter values: `all`,
  `failed`, `passed`, `"not applicable"` (literal space).
- **Vulnerabilities tab** (`VulnerabilitiesTab`, `555-670`):
  `GET /api/siem/hosts/<agentId>/vulnerabilities?page=&per_page=&severity=` (`:569`).
  `{vulnerabilities:[...], total, note?}`. `severity` values: `Critical`/`High`/`Medium`/`Low`
  (capitalized) or omitted for all.
- **FIM / Malware tabs** (both use `AlertsTab`, `674-781`, with `category="fim"`/`"malware"`):
  `GET /api/siem/hosts/<agentId>/alerts?category=&page=&per_page=` (`:687`).
  `{alerts:[...], total}`.
- **MITRE tab** (`MitreTab`, `929-1017`): reads `detail.mitre.breakdown` from the top-level
  `GET /api/siem/hosts/<agentId>` fetch (no separate call).
- **Compliance tab** (`ComplianceTab`, `1021-1141`): reads `detail.sca`/`detail.compliance` from
  the same top-level fetch.

**Do not change these response shapes without updating `HostDetailPanel.jsx` in the same change.**

---

## 11. Relevant tables (for reference, don't recreate)

Pre-existing, reused:
- `network_assets` (`blueprints/itam/routes.py`) — now has `hardware_uuid` (Phase 0),
  `processes`/`drivers`/`local_groups`/`network_interfaces`/`certificates`/`cloud_metadata`
  (Phase 1), plus pre-existing `hardware_info`/`services`/`local_users`/`listening_ports`/
  `software_count`/`vuln_count`/`highest_cve_severity`.
- `software_inventory` (`blueprints/itam/software_inventory.py:32-45`) — keyed by `asset_id`, has
  `cve_count`/`highest_severity`/`cves` JSONB, NVD-enriched. Used by Phase 4.
- `edr_agents` (`blueprints/edr/response_orchestrator.py:62-77`) — has `hardware_uuid`.
- `edr_detections` (`blueprints/edr/response_orchestrator.py:79-105`) — `mitre_id`/`mitre_tactic`
  already populated at ingest time (not a Phase 5 addition — that was the discovery of Phase 5).
  Used by Phases 5/6.
- `host_posture_cache` (`siem_proxy.py`) — Wazuh+alerts-shaped; Phase 6 added a fallback path for
  when this has no row for an EDR-only host, but the table itself is untouched.

New this work (Phases 0-3):
- `network_assets.hardware_uuid` + 6 Phase-1 JSONB columns (Phase 0/1, see above).
- `edr_fim_baseline` — `id, agent_id, path, sha256, size, owner, permissions, modified_at,
  last_baselined`, unique `(agent_id, path)`. (Phase 2)
- `edr_fim_events` — `id, agent_id, event_type, path, old_path, old_sha256, new_sha256, size,
  owner, permissions, username, severity, detected_at`. (Phase 2)
- `edr_sca_results` — `id, agent_id, policy_id, policy_name, check_id, title, description,
  rationale, remediation, result, severity, scanned_at`, unique `(agent_id, policy_id, check_id)`.
  (Phase 3)

**Known pre-existing bug, NOT fixed (out of scope, discovered while reading around Phase 4):**
`blueprints/itam/routes.py: _push_deep_scan_cves_to_siem()` queries a `software_cves` table
(`JOIN software_cves sv ON sv.software_id = si.id`) that is never created anywhere —
`ensure_software_tables()` only creates `software_inventory`, whose CVEs live in the `cves` JSONB
column, not a separate table. This function will raise at runtime and is presumably swallowed by
whatever wraps its caller. Did not fix — unrelated to the Host Security Profile tabs (this function
pushes CVE findings into the Active Incidents pipeline, a different feature), and fixing
someone else's silent-failure pipeline wasn't in scope for "make these 7 tabs work."

---

## 12. Deploy + verify (all phases — do this before considering the feature done)

1. **Backend deploy:** `systemctl restart cycentra-backend.service`. All new tables/columns
   (`edr_fim_baseline`, `edr_fim_events`, `edr_sca_results`, `network_assets`'s new columns) are
   created automatically on startup via `ensure_tables()`/`init_itam_tables()`
   (`CREATE TABLE IF NOT EXISTS`/`ADD COLUMN IF NOT EXISTS`, safe to re-run).
2. **Agent rebuild required:** `agent-packages/build-edr-packages.sh` now pulls in `watchdog>=4.0`
   (new dependency for FIM) — existing enrolled agents keep running the OLD binary (no
   InventoryReporter/FimMonitor/ScaScanner) until reinstalled or self-updated. Check whether
   `AGENT_VERSION` in `cyedr_agent.py` needs bumping so `_self_update()` picks up the new build.
3. **Per-thread log lines to watch for** on a test host running the new agent:
   - `"Inventory reported in Xs: N packages, N processes, N services"` (~30s after start)
   - `"FimMonitor watching N path(s)"` (immediately) then `"FIM: reported N event(s)"` (on change)
     or `"FIM: baseline sent (N files)"` (~45s after start, then every 24h)
   - `"SCA scan reported: N/M checks passed"` (~60s after start, then every 6h)
   - If watchdog isn't bundled correctly for a given OS/arch: `"FIM disabled: watchdog not
     installed in this agent build"` — check the PyInstaller build logs for that arch.
4. **Postgres spot-checks:**
   - `SELECT hostname, hardware_uuid, jsonb_array_length(services) AS n_services, last_deep_scan
     FROM network_assets WHERE edr_agent_id IS NOT NULL ORDER BY last_deep_scan DESC LIMIT 5;`
   - `SELECT event_type, path, severity, detected_at FROM edr_fim_events ORDER BY detected_at DESC
     LIMIT 10;`
   - `SELECT policy_id, result, COUNT(*) FROM edr_sca_results GROUP BY 1,2 ORDER BY 1,2;`
   - `SELECT mitre_id, mitre_tactic, COUNT(*) FROM edr_detections WHERE mitre_id IS NOT NULL GROUP
     BY 1,2 ORDER BY 3 DESC LIMIT 10;`
5. **UI walkthrough:** Host Intelligence → Hosts & Posture → a host running the new agent → click
   through all 7 tabs. Inventory/SCA/Vulnerabilities/FIM/Malware should show real data once the
   agent has completed its first cycle of each (30s/45s/60s after start respectively, then FIM
   updates live on file changes). MITRE and Compliance depend on `_sync_host_detail`, which needs
   at least one `edr_detections`/`edr_sca_results` row to have anything to roll up.
6. **If a tab is still empty:** hit the underlying route directly (`GET
   /api/siem/hosts/<agent_id>/inventory` etc., browser devtools or curl with a session cookie).
   Check the JSON's shape/`source` field — `"source": "edr_native"` means the new path served it
   (empty just means the agent hasn't reported that data type yet); Wazuh-shaped output (or a
   404/503) means `_resolve_edr_agent_id()` didn't find a match — check `network_assets.edr_agent_id`
   / `.siem_agent_id` and `edr_agents.agent_id` for the host in question to see which ID space the
   URL's `agent_id` actually falls into.
7. **Nothing in this pass required `npm run build`** — every response shape was deliberately kept
   identical to what `HostDetailPanel.jsx` already expected (§1 architecture decision).

---

## 13. What's genuinely still open (not built this session, by design)

- **Detection Repository as data-driven rule files** (`Rules/MITRE/Windows/Linux/Containers/Cloud/…`
  from the original spec) — this project already has an equivalent for network/log detection
  (Sigma engine, `cysiemstack/detection/sigma_engine.py`, ~3,739 rules) and for host-behavior
  detection (`confidence_matrix.py`'s `HEURISTIC_TABLE`, extended in Phase 3 conceptually via the
  SCA check list). A literal YAML rule-file repo for EDR heuristics specifically wasn't built —
  `HEURISTIC_TABLE` is still Python dicts, matching the SCA-checks precedent set in Phase 3.
- **Network vulnerability scanning** (Nmap/RustScan/Nuclei/Masscan, scheduled separately per the
  spec) — out of scope; Phase 4 covers *inventory-based* vulnerability detection only (the spec's
  own recommended approach: "No scanning required. Inventory-based detection is much faster.").
  ITAM's existing `NetworkProbePoller`/agentless scanner already does *some* of this for
  IoT/SNMP/SSH deep-scan of other hosts, just not general Nmap/Nuclei CVE scanning.
- **Correlation across the new signal types** (e.g. "FIM change on /etc/passwd + new user created +
  new listening port" → single "Credential Theft"-style composite incident, per the spec's §7) —
  the correlation engine (`cysiemstack/correlation_engine/`) has 55 built-in rules + custom-rule
  support already, but none were written against `edr_fim_events`/`edr_sca_results` specifically in
  this pass. The data now exists for such rules to be written against; the rules themselves aren't.
- **TI enrichment of FIM/SCA findings** — `EnrichmentPanel`'s existing per-item AI+CyTIM enrichment
  (`POST /hosts/<id>/enrich`) already works generically against any item shape passed to it, so FIM
  and SCA items get the same enrichment UI as everything else — this wasn't a gap, just confirming
  no extra work was needed here.
- **Live verification** — nothing in Phases 0-6 has been exercised against a real Postgres DB or a
  real enrolled agent; all verification so far is `python3 -m py_compile`/AST-level. See §12.

---

## 14. Independent re-verification (2026-07-18) + GRC/Compliance scope clarification

Re-audited "does CyEDR capture Inventory/FIM/SCA/Vuln/MITRE/Compliance" directly against the
code (not this doc) in response to a product question. All Phase 0-6 claims above still hold as
of this date — confirmed via `grep`/read of `agent/cyedr_agent.py`, `blueprints/edr/routes.py`,
`blueprints/edr/confidence_matrix.py`, `blueprints/edr/normalizer.py`, `blueprints/itam/routes.py`,
and `cy_comp/services/auto_findings.py`. One scope distinction from that audit is worth pinning
down explicitly, because "Compliance" is used for two different things in this codebase:

**1. The Host Security Profile "Compliance" tab (per-host) is not a real compliance-framework
score — it's the SCA pass/fail score relabeled.** `backend/siem_proxy.py:1015`:
`overlay["compliance_score"] = overlay["sca"]["score"]`. There is no ISO27001/NIS2/DORA/SOC2/
NIST-CSF/PCI-DSS mapping anywhere in this code path. This was true by design per §8/§9 above
(SCA is CIS-style pass/fail, and the per-host tab was always meant to surface that) — noting it
here only because "Compliance" as a tab label invites the wrong assumption.

**2. The org-level GRC/Compliance module (`cy_comp/`) is separate and does do real framework
mapping — and EDR alerts reach it, but only incidentally.** `cy_comp/services/auto_findings.py`
runs `SELECT ... FROM alerts GROUP BY fw, mitre_id, rule_desc, category, compliance_controls` —
this is source-agnostic; it doesn't filter by origin engine. EDR-sourced alerts (rule_id range
100300-100399, tagged with `mitre_id`/`mitre_tactic` by `normalizer.py` at ingest, per §8 above)
land in the same shared `alerts` table as Wazuh/Sigma/correlation-engine alerts, so they get
picked up by this query and mapped to compliance controls exactly like any other alert with a
MITRE ID. **There is no EDR-specific route into `cy_comp`** — no code in `cy_comp/` references
`edr_detections`, `edr_agents`, `edr_sca_results`, or `edr_fim_events` directly. If a future
requirement needs FIM/SCA findings themselves (not just EDR *detections*) to drive compliance
findings — e.g. "CIS benchmark failure on host X → NIST CSF control gap" — that mapping doesn't
exist yet and would be new work in `auto_findings.py`, not something already covered by the
`alerts`-table query above (SCA/FIM rows don't write to `alerts`, only to their own tables).

**3. Vulnerability data for EDR-covered hosts is genuinely ITAM's, not CyEDR's own** — reconfirms
§7: CyEDR has no CVE scanner of its own: it self-reports installed software, and ITAM's existing
NVD/KEV-backed `enrich_asset_cves()` does the matching. Framed as a capability-ownership question
rather than a data-flow one: "vulnerability management" as a product capability belongs to ITAM;
CyEDR is one of its inventory sources (agentless SSH/WinRM scans of *other* hosts being the other).
