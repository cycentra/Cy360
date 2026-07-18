# siem_proxy.py Route Audit — Phase 5 Input (CyDataLake Migration)

> **Update, v1.0.229 (2026-07-16):** the product decision flagged below for `/agent-groups/*` and
> `/endpoint-policies/*` has been made — retire, not rebuild. Both route blocks (13 agent-groups
> routes + the full endpoint-policies block, helpers included) and their Host Intelligence UI tabs
> ("Agent Groups", "Response Playbooks") were deleted in full, since Wazuh is no longer used as a
> sensor. The rows below describing them are kept as historical record of the routes that existed,
> not as a live keep/retire recommendation.
>
> **Update, v1.0.238 (2026-07-18):** sequencing step 1 done — `GET /wazuh-launch` and
> `GET /internal/auth` retired, not just the routes: the "Launch Wazuh"/"View in Wazuh" buttons on
> the Active Incidents detail panel (`SiemIncidentsPage.jsx`) and UEBA anomaly cards
> (`SiemUebaPage.jsx`) were live and unconditionally rendered (the audit below undersold this —
> it wasn't a dead deep-link), so the UI was removed alongside the backend, along with the
> now-unused `GET /ueba/integrations` route and its `WAZUH_URL` config var (nothing else read
> either). Also discovered and fixed in the same pass, unrelated to this audit: the optional
> per-endpoint "install CySIEM agent alongside CyEDR" co-install feature was retired end-to-end
> (`--with-cysiem`/`-WithCySIEM` flags removed from `cyedr-install.sh`/`.ps1`, `cysiem-msi`/
> `cysiem-script` installer routes removed) after finding the Linux/macOS half of it had been
> silently 500ing since v1.0.215 (dangling import of a template deleted with the Sensor Deployment
> tab) and the Windows half was about to break too (its `.msi` source came from the same dead
> `packages.wazuh.com` download step this cleanup removed from `cycentra-setup.sh`).
>
> **Step 2 turned out to be mostly already done** by prior, undocumented work: both
> `/hosts/<id>/inventory` and `/hosts/<id>/vulnerabilities` already had an EDR/ITAM-first path
> (`_edr_itam_inventory()` / `_edr_itam_vulnerabilities()`) that only falls back to Wazuh when a
> host has no CyEDR-reported ITAM data yet. The vulnerabilities fallback was already
> Wazuh-API-free (reads historical `alerts` rows ingested via `cysiem_to_redis`, not a live call)
> — the Group B classification below is stale for that route. The inventory fallback *did* still
> make a live Wazuh Manager API call (`/syscollector/*`); per product decision this was removed
> — hosts without a CyEDR agent now get an empty inventory shape instead of Wazuh syscollector
> data, confirming CyEDR/ITAM as the only supported inventory source going forward.
>
> Next up: step 6 (`/hosts/<id>/sca` — no existing ITAM overlap, genuine rebuild) and step 5
> (`/hosts`, `/hosts/refresh`, `/hosts/<id>` enroll/remove — highest blast radius, doing last).

**Status: analysis only, no code changed.** This is the Phase 5 "route-by-route inventory" task
from `docs/CYDATALAKE_MIGRATION_PLAN.md` §9, produced by grepping `siem_proxy.py` for every
`@siem_bp.route` and tracing which handlers actually call the Wazuh Manager API
(`WAZUH_API_URL`/`_wazuh_auth_token()`) versus which are pure Postgres/correlation-engine logic
with no Wazuh dependency at all.

**Why no code changed in this pass:** `siem_proxy.py` is ~3900 lines serving live production
traffic — agent enroll/remove, endpoint isolation policies, host inventory. Rewriting any of this
without a live Wazuh Manager to test against (none was available in this session, same constraint
as the Phase 3 connectors) risks silently breaking real fleet management, which is explicitly the
highest-blast-radius risk called out in the migration doc. An audit is safe and reversible; a blind
rewrite of live RBAC/enroll/remove endpoints is neither. This document is the input a future PR
should use, not a substitute for one.

## Group A — Zero Wazuh Manager API dependency (KEEP forever, not Phase 5 scope at all)

These operate entirely on the correlation-engine Postgres tables (`alerts`, `incidents`, UEBA,
threat-hunting) or proxy the internal FastAPI correlation engine (`/engine/*`). They have nothing
to do with Wazuh as a vendor and should never be touched as part of "removing Wazuh dependency" —
they'd need to stay identical even if Wazuh were fully retired tomorrow.

`/health`, `/stats`, `/incidents` (all methods/sub-routes), `/fp-patterns` (all), `/risk-scores`,
`/ueba/users`, `/ueba/<username>`, `/ueba/integrations`, `/ueba/anomaly/statuses`,
`/ueba/anomaly/<id>/audit`, `/ueba/anomaly/<id>/status`, `/soar/status`,
`/incidents/<id>/approve-soar`, `/incidents/<id>/similar`, `/alerts`, `/alerts/ingest`, `/config`,
`/engine/status`, `/engine/restart`, `/threat-hunting/rules`, `/threat-hunting/findings`,
`/threat-hunting/run`, `/threat-hunting/summary`, `/threat-hunting/analyze`, `/posture/internal`,
`/hosts/<id>/tier`, `/hosts/<id>/enrich`, `/hosts/<id>/item-statuses` (GET/POST) — these three are
Postgres-only annotations keyed on `agent_id`; they don't care whether that agent_id came from
Wazuh, CyEDR, or a future CyCollector-only host, so they're already vendor-agnostic today.

## Group B — Confirmed Wazuh Manager API dependency (real Phase 5 targets)

Verified by grep: every handler below calls `_wazuh_auth_token()` and/or references
`WAZUH_API_URL` directly.

| Route(s) | What it does | Recommendation |
|---|---|---|
| `GET /wazuh-launch` | SSO deep-link into the Wazuh dashboard (`/security/user/authenticate`) | **Retire candidate.** Cy360 already has native incident/alert views; keep only if a specific customer still wants raw Wazuh dashboard access post-migration. |
| `GET /internal/auth` | Internal Wazuh SSO auth helper feeding the above | Same fate as `/wazuh-launch` — retire together. |
| `GET /hosts`, `POST /hosts/refresh`, `GET/DELETE /hosts/<id>` | Agent list/enroll/remove via Wazuh Manager API | **Rebuild, and use this as the opportunity to unify.** Cy360 now has three agent tables (`edr_agents`, `collector_agents`, plus whatever `WazuhConnector` surfaces) — this is the natural place to build one cross-source "hosts" view instead of a Wazuh-only one. Don't rebuild this 1:1; redesign it as source-agnostic. |
| `GET /hosts/<id>/inventory` | Wazuh syscollector (installed software, open ports, etc.) | **Retire in favor of ITAM.** `blueprints/itam/routes.py`'s deep-scan (`hardware_info`/`services`/`software_inventory` columns) already covers this ground for both agent-based and agentless assets. |
| `GET /hosts/<id>/vulnerabilities` | Wazuh vulnerability detector | **Retire in favor of ITAM.** `assets_list()`'s `vuln_count`/`highest_cve_severity` already overlaps — confirm feature parity, then drop the Wazuh-specific path. |
| `GET /hosts/<id>/sca` | Wazuh SCA (CIS benchmark checks) | **Genuine rebuild needed — no existing overlap.** If this capability must survive, the cleanest fit is folding it into a `WazuhConnector`-style per-tenant pull rather than a single global `WAZUH_API_URL`, since Phase 3 already established "one Wazuh cluster is one configured connector," not a singleton. Note the existing alerts-DB SCA fallback (`_sca_from_alerts_db`) already gives partial vendor-independence for stale/re-enrolled agents — study that path first. |
| `GET/POST/DELETE /agent-groups`, `GET/PUT /agent-groups/<name>/config`, `GET/POST/DELETE /agent-groups/<name>/agents`, `GET /agent-groups/available-agents` | Wazuh agent groups + `ossec.conf` push | **Rebuild or retire — needs a product decision.** Every one of these 8 routes calls `_wazuh_auth_token()`. If "agent groups" as a concept is Wazuh-specific plumbing rather than something customers directly value, consider retiring it in favor of whatever grouping CyEDR/CyCollector end up with natively, rather than rebuilding Wazuh group semantics against a different backend. |
| `POST /endpoint-policies/sync` (`ep_sync`) | Reads policies from Postgres, writes `<active-response>` blocks to `ossec.conf`, restarts `wazuh-manager` | **Retire the Wazuh-writing mechanics specifically.** This heavily overlaps with CyEDR's `APPLY_POLICY` (`agent/cyedr_agent.py` `ResponseExecutor._apply_policy()`), which already does device/app/network/exclusions/isolation control without touching Wazuh at all. The rest of `/endpoint-policies/*` (`ep_list`/`ep_create`/`ep_get`/`ep_update`/`ep_delete`/`ep_actions`/`ep_apply`/`ep_executions`) is generic Postgres-backed runbook CRUD — **keep those, they're not Wazuh-specific**, only `ep_sync`'s write-to-ossec.conf step is. |

## Group C — Needs live-instance verification before classifying (not confidently traced)

`GET /hosts/<id>/alerts` sits between two heavily-Wazuh-dependent routes in the file
(`/hosts/<id>/sca` and `/hosts/<id>/tier`) but its exact body wasn't traced line-by-line in this
pass — before Phase 5 work starts, confirm whether it queries the Postgres `alerts` table directly
(likely, given the naming convention of its neighbors `/tier`/`/enrich`/`/item-statuses`) or proxies
Wazuh. Same caveat for the four `_wazuh_auth_token()` call sites inside the hosts section (lines
1932-2900 in the version audited here) not individually re-verified per-route beyond the SCA route.

## Recommended sequencing for whoever picks up Phase 5

1. Retire `/wazuh-launch` + `/internal/auth` first — lowest risk, no live-agent impact, purely a
   dashboard deep-link.
2. Retire `/hosts/<id>/inventory` and `/hosts/<id>/vulnerabilities` in favor of ITAM's existing
   equivalents — confirm feature parity with a side-by-side comparison on a real host before
   cutting over, not a code-only migration.
3. Decide (product call, not engineering) whether `/agent-groups/*` survives at all before spending
   effort rebuilding it.
4. `/endpoint-policies/sync` — separate the generic runbook CRUD (keep) from the Wazuh-writing step
   (retire/replace with CyEDR's `APPLY_POLICY` path).
5. `/hosts`, `/hosts/refresh`, `/hosts/<id>` (enroll/remove) — do this **last**. It's the highest
   blast radius (real endpoint enroll/remove/isolate) and benefits most from the other four steps
   already having simplified what "a host" even means across Wazuh/EDR/Collector sources.
6. `/hosts/<id>/sca` — only rebuild if a product decision confirms SCA/CIS-benchmark checking is
   still a required capability; this is the one item with no existing overlap to lean on.
