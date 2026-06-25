# Cy360 Weekly Architecture Review

**Last reviewed:** 2026-06-25
**Current version:** v1.0.91
**Commits this week:** 40 (v1.0.58 → v1.0.91, 2026-06-17 → 2026-06-24)

## Summary

Heavy release activity (40 commits) this week. Major structural additions include a new `integrations_bp` blueprint with matching frontend page, four new `cysiemstack/correlation_engine` modules (evidence_collector, gap_analyser, hypothesis_engine, ti_enricher), seven active-response scripts in CYSIEM-Config, and a test suite (`tests/unit/`) with seven new test files. A `tests/` directory now exists and is not yet documented in CLAUDE.md. The `integrations_bp` is fully registered in `app.py` but undocumented in CLAUDE.md.

---

## CLAUDE.md Drift

Items present in code but **not described** in CLAUDE.md:

| Area | What exists in code | CLAUDE.md status |
|---|---|---|
| Blueprint | `blueprints/cases/` — `cases_bp` (routes.py, service.py, checklist_templates.py) | **Missing entirely** |
| Blueprint | `blueprints/integrations/` — `integrations_bp` (routes.py, health.py) | **Missing entirely** (new this week) |
| Sub-package | `backend/cysiemstack/` — correlation_engine (24 modules) + threat_hunter | **Missing entirely** |
| Core file | `core/license_validator.py` | Not listed; only config.py, helpers.py, kv_secrets.py mentioned |
| Blueprint support files | `blueprints/platform/compose.py`, `docker_utils.py`, `state.py` | Only `routes.py` mentioned |
| SIEM blueprint layout | `blueprints/siem/` has only `__init__.py`; proxy is `siem_proxy.py` at backend root. `app.py` header comment incorrectly references `blueprints/siem/proxy.py` | Comment is stale |
| Frontend pages | `pages/ai/`, `pages/assets/`, `pages/cases/`, `pages/hosts/`, `pages/guest-scan/`, `pages/history/`, `pages/integrations/`, `pages/platform-extensions/`, `pages/usecases/`, `pages/vulnerabilities/`, `HostIntelligencePage.jsx` | All absent from page directory list |
| Frontend SIEM component | `portal/src/siem/ThreatHuntingPage.jsx` | In `src/siem/`, not `src/pages/` — not documented |
| ASM modules | 15 actual modules (cloud_infra, crypto_checks, dark_web, debug_crypto, dns_recon, email_security, mobile_api, nuclei_scanner, passive_osint, social_eng, subdomain_enum, supply_chain, vuln_scanner, web_analysis, whois_history) | CLAUDE.md says "(dns, ssl, ports, etc.)" — no ssl or ports module exists |
| Test suite | `tests/unit/` — 17 test files, `tests/TEST_RUN_HISTORY.md`, `tests/TEST_RUN_REPORT.md` | `tests/` not mentioned anywhere in CLAUDE.md |
| Docs | 22 docs files not in CLAUDE.md reference table | Docs table significantly stale |

---

## New Since Last Review

*(Scoped to 2026-06-18 → 2026-06-25)*

**Backend:**
- `backend/blueprints/integrations/__init__.py`, `health.py`, `routes.py` — new `integrations_bp`; registered in `app.py`
- `backend/cysiemstack/correlation_engine/evidence_collector.py`
- `backend/cysiemstack/correlation_engine/gap_analyser.py`
- `backend/cysiemstack/correlation_engine/hypothesis_engine.py`
- `backend/cysiemstack/correlation_engine/ti_enricher.py`

**Frontend:**
- `portal/src/pages/hosts/EndpointPoliciesTab.jsx`
- `portal/src/pages/integrations/index.jsx`
- `portal/src/siem/ThreatHuntingPage.jsx`
- `portal/src/components/LicenseBanner.jsx`

**CYSIEM-Config:**
- `CYSIEM-Config/active-response/block-usb.sh`, `block-wifi.sh`, `collect-forensics.sh`, `isolate-host.sh`, `quarantine-file.sh`, `restrict-network.sh`, `scan-endpoint.sh`
- `CYSIEM-Config/agent_config/cy360_resource_check.ps1`, `cy360_resource_check.sh`
- `CYSIEM-Config/lists/sync_misp_cache.py`
- `CYSIEM-Config/sysmon/cycentra_sysmon_config.xml`

**Docs:**
- `docs/BENCHMARK_COHORT_OPT_IN.md`
- `docs/ENDPOINT_POLICY_ENGINE.md`
- `docs/INVESTIGATION_ENGINE_PLAN.md`
- `docs/KERNEL_TELEMETRY_QA.md`
- `docs/TEST_INVENTORY.md`
- `docs/THREAT_HUNTING.md`
- `docs/WAZUH_INTEGRATION_AUDIT.md`

**Tests (new this week):**
- `tests/unit/test_agent_installer.py`
- `tests/unit/test_correlation_rules.py`
- `tests/unit/test_integration_health.py`
- `tests/unit/test_investigation_engine.py`
- `tests/unit/test_resource_monitor.py`
- `tests/unit/test_ueba_detectors.py`
- `tests/unit/test_wazuh_kernel_virustotal.py`
- `tests/TEST_RUN_HISTORY.md`, `tests/TEST_RUN_REPORT.md`

---

## Registered Blueprints (authoritative from app.py)

| Blueprint variable | Source file | Responsibility |
|---|---|---|
| `auth_bp` | `blueprints/auth/oauth.py` | Google + Microsoft OAuth, auth verify, auth logs |
| `oidc_bp` | `blueprints/oidc/provider.py` | OIDC IdP (discovery, authorize, token, userinfo, introspect) |
| `rbac_bp` | `blueprints/rbac/manager.py` | RBAC load/save, role resolution, /api/users |
| `platform_bp` | `blueprints/platform/routes.py` | Module install/uninstall/status/logs |
| `asm_bp` | `blueprints/asm/scanner.py` | ASM scan trigger/status/results |
| `siem_bp` | `siem_proxy.py` (backend root) | CySIEM correlation engine proxy (13 endpoints) |
| `system_bp` | `blueprints/system/routes.py` | /health, /api/ai/test, /api/config, O365 wodle |
| `backup_bp` | `blueprints/backup/routes.py` | Backup create/restore/schedule |
| `scheduler_bp` | `blueprints/scheduler/routes.py` | APScheduler job management |
| `marketplace_bp` | `blueprints/marketplace/routes.py` | Marketplace catalog + install |
| `audit_bp` | `blueprints/audit/routes.py` | Audit trail for monitoring & compliance |
| `sso_bp` | `blueprints/sso/routes.py` | SSO configuration |
| `benchmark_bp` | `blueprints/benchmark/routes.py` | Security benchmark scoring |
| `comp_bp` | `blueprints/comp/routes.py` | GRC compliance engine routes |
| `cases_bp` | `blueprints/cases/routes.py` | CyCases native case management (undocumented in CLAUDE.md) |
| `integrations_bp` | `blueprints/integrations/routes.py` | Third-party integration health + configuration (undocumented in CLAUDE.md) |

---

## Frontend Pages (authoritative from portal/src/pages/)

| Page file(s) | Directory |
|---|---|
| `HostIntelligencePage.jsx` | `pages/` (root) |
| `AISettingsPage.jsx` | `pages/ai/` |
| `AssetsPage.jsx`, `AssetModal.jsx`, `ImportModal.jsx`, `WorldMapWidget.jsx` | `pages/assets/` |
| `AuditTrailPage.jsx` | `pages/audit/` |
| `BenchmarkPage.jsx` | `pages/benchmark/` |
| `CaseDetailPage.jsx`, `CasesListPage.jsx` | `pages/cases/` |
| `ComplianceAssessmentPage.jsx`, `ComplianceDashboardPage.jsx`, `ComplianceFindingsPage.jsx`, `ComplianceLiveAlertsPage.jsx`, `ComplianceReportsPage.jsx`, `PolicyDocumentsPage.jsx`, `RiskRegisterPage.jsx` | `pages/compliance/` |
| `DashboardPage.jsx` | `pages/dashboard/` |
| `GuestScanPage.jsx` | `pages/guest-scan/` |
| `ScanHistoryPage.jsx` | `pages/history/` |
| `AgentGroupsTab.jsx`, `EndpointPoliciesTab.jsx` *(new)*, `HostDetailPanel.jsx`, `HostsPage.jsx` | `pages/hosts/` |
| `index.jsx` *(new)* | `pages/integrations/` |
| `LoginPage.jsx` | `pages/login/` |
| `MarketplacePage.jsx` | `pages/marketplace/` |
| `index.jsx` | `pages/platform-extensions/` |
| `PlatformPage.jsx` | `pages/platform/` |
| `ScanPage.jsx` | `pages/scan/` |
| `SSOTab.jsx`, `SystemSettingsPage.jsx` | `pages/settings/` |
| `UseCasesPage.jsx` | `pages/usecases/` |
| `VulnerabilityPage.jsx` | `pages/vulnerabilities/` |

**Note:** `ThreatHuntingPage.jsx` lives in `portal/src/siem/`, not `pages/`.

---

## ASM Modules (authoritative from cy_asm/modules/)

`cloud_infra`, `crypto_checks`, `dark_web`, `debug_crypto`, `dns_recon`, `email_security`, `mobile_api`, `nuclei_scanner`, `passive_osint`, `social_eng`, `subdomain_enum`, `supply_chain`, `vuln_scanner`, `web_analysis`, `whois_history`

Support: `Utils/update_wordlist.py`, `wordlists/`

---

## cysiemstack Sub-Package (authoritative from backend/cysiemstack/)

Not documented in CLAUDE.md.

**`correlation_engine/`** (24 modules):
`ai_router`, `audit_reporter`, `campaign_correlator`, `config`, `correlator`, `cysiem_to_redis`, `cysoar_connector`, `evidence_collector` *(new)*, `feedback_store`, `fp_pattern_store`, `gap_analyser` *(new)*, `grouper`, `hypothesis_engine` *(new)*, `ingestor`, `llm_enricher`, `main`, `misp_enricher`, `models`, `normaliser`, `risk_scorer`, `ti_enricher` *(new)*, `ueba`, `ueba_ml`

**`threat_hunter/`**: `hunter.py`

**`host_service.py`** (top-level)

---

## Action Items

1. **CLAUDE.md — Add `blueprints/cases/` and `blueprints/integrations/` to Repository Layout and blueprint list.** Both are production-registered; both are absent from CLAUDE.md.

2. **CLAUDE.md — Document `backend/cysiemstack/`.** A substantial sub-service (24-module correlation engine + threat hunter) with zero CLAUDE.md coverage.

3. **CLAUDE.md — Add `tests/` to the repository layout.** A test suite now exists (`tests/unit/` — 17 test files). No mention exists in CLAUDE.md.

4. **CLAUDE.md — Add `core/license_validator.py` to the core/ list.** Currently only `config.py`, `helpers.py`, `kv_secrets.py` are mentioned.

5. **CLAUDE.md — Correct ASM modules description.** Replace "(dns, ssl, ports, etc.)" with actual module names; there is no `ssl` or `ports` module.

6. **CLAUDE.md — Update Frontend Pages section.** At least 11 page directories are unlisted.

7. **CLAUDE.md — Expand the Docs Reference table.** 32 docs files exist; only 9 are referenced.

8. **`app.py` header comment — Update blueprint list.** The docstring omits `scheduler_bp`, `marketplace_bp`, `sso_bp`, `benchmark_bp`, `comp_bp`, `cases_bp`, and `integrations_bp` from its blueprint–responsibility table.
