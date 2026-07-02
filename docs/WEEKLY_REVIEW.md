# Cy360 Weekly Architecture Review

**Last reviewed:** 2026-07-02
**Current version:** v1.0.151
**Commits this week:** 50 (v1.0.120 → v1.0.151; 14 substantive non-release commits)

## Summary

This week's work was dominated by CyEDR agent stability hardening: hardware UUID deduplication (preventing duplicate agent registration on reinstall), macOS brew/pip compatibility fixes, and enrollment token auth. Two new major blueprints — `edr_bp` and `itam_bp` — were added since the last review and are now registered in `app.py` but absent from CLAUDE.md. A CyScan YARA false-positive was fixed, and the release bundler was updated (with an auto-deploy step later reverted).

---

## CLAUDE.md Drift

Items present in code but **not described** in CLAUDE.md:

| Area | What exists in code | CLAUDE.md status |
|---|---|---|
| Blueprint | `blueprints/edr/` — `edr_bp` (routes.py + confidence_matrix, normalizer, policy_engine, response_orchestrator) | **Missing entirely** (added since last review) |
| Blueprint | `blueprints/itam/` — `itam_bp` (routes.py + 8 discovery/scanner modules) | **Missing entirely** (added since last review) |
| Blueprint | `blueprints/cases/` — `cases_bp` (routes.py, service.py, checklist_templates.py) | **Missing entirely** |
| Blueprint | `blueprints/integrations/` — `integrations_bp` (routes.py, health.py) | **Missing entirely** |
| Sub-package | `backend/cysiemstack/` — correlation_engine (24 modules) + threat_hunter + edr_bridge + host_service | **Missing entirely** |
| Core file | `core/license_validator.py` | Not listed; CLAUDE.md only mentions config.py, helpers.py, kv_secrets.py |
| GRC service | `cy_comp/services/itam_bridge.py` | Not listed in the cy_comp/services list |
| Blueprint support files | `blueprints/platform/compose.py`, `docker_utils.py`, `state.py` | Only routes.py mentioned |
| Frontend pages | `pages/edr/`, `pages/itam/`, `pages/cases/`, `pages/ai/`, `pages/assets/`, `pages/hosts/`, `pages/guest-scan/`, `pages/history/`, `pages/integrations/`, `pages/platform-extensions/`, `pages/usecases/`, `pages/vulnerabilities/`, `HostIntelligencePage.jsx` | All absent from CLAUDE.md page directory list |
| ASM modules | 15 modules present: cloud_infra, crypto_checks, dark_web, debug_crypto, dns_recon, email_security, mobile_api, nuclei_scanner, passive_osint, social_eng, subdomain_enum, supply_chain, vuln_scanner, web_analysis, whois_history | CLAUDE.md says "(dns, ssl, ports, etc.)" — no `ssl` or `ports` module exists |
| Docs | 41 docs files on disk; CLAUDE.md reference table covers 9 | Table significantly stale |

---

## New Since Last Review

*(Scoped to 2026-06-25 → 2026-07-02)*

**Backend blueprints (new):**
- `blueprints/edr/` — `edr_bp`; includes `confidence_matrix.py`, `normalizer.py`, `policy_engine.py`, `response_orchestrator.py`, `routes.py`
- `blueprints/itam/` — `itam_bp`; includes `agentless_scanner.py`, `cloud_discovery.py`, `dns_shadow_ai.py`, `exploit_intel.py`, `iot_classifier.py`, `mdns_discovery.py`, `network_discovery.py`, `nvd_mirror.py`, `snmp_scanner.py`, `software_inventory.py`, `routes.py`

**Backend services (new):**
- `cy_comp/services/itam_bridge.py` — ITAM↔compliance bridge
- `cysiemstack/edr_bridge.py` — CyEDR↔SIEM stack bridge

**Frontend pages (new):**
- `pages/edr/` — `EdrAgentInstallerPage.jsx`, `EdrCyScanRulesPage.jsx`, `EdrDetectionsPage.jsx`, `EdrEndpointDetailPage.jsx`, `EdrPoliciesPage.jsx`, `EdrResponsePage.jsx`, `EdrYaraRulesPage.jsx`, `index.jsx`
- `pages/itam/` — `AssetDetailPage.jsx`, `IotRegistryPage.jsx`, `ShadowAiPage.jsx`, `index.jsx`

**Bug fixes (substantive non-release commits):**
- `fix(cyedr)`: stable hardware UUID deduplication — prevents duplicate agent on reinstall
- `fix(cyedr)`: auto-merge duplicate agents by hardware_uuid at startup
- `fix(edr)`: save enrollment_token to config and use for agent auth
- `fix(edr)`: retire previous enrollments on re-enroll by same hostname
- `fix(edr)`: official OS SVGs in fleet; skip re-enrollment on reinstall
- `fix(edr)`: install Python deps with `--break-system-packages` for macOS; detect support before using
- `fix(edr)`: run brew as SUDO_USER (Homebrew refuses to run as root)
- `fix(edr)`: pip install to root home so LaunchDaemon can import deps; guarantee pip deps in root Python path
- `fix(itam)`: clear stale `edr_agent_id`/`siem_agent_id` refs before crossref
- `fix(cyscan)`: spurious critical detection when YARA finds 0 matches
- `fix(deploy)`: include CyEDR agent files in release bundle + auto-deploy to server
- `revert(deploy)`: remove hardcoded server auto-deploy step

---

## Registered Blueprints (authoritative from app.py)

| Blueprint variable | Source file | Responsibility |
|---|---|---|
| `auth_bp` | `blueprints/auth/oauth.py` | Google + Microsoft OAuth, auth verify, auth logs |
| `oidc_bp` | `blueprints/oidc/provider.py` | OIDC IdP (discovery, authorize, token, userinfo, introspect) |
| `rbac_bp` | `blueprints/rbac/manager.py` | RBAC load/save, role resolution, /api/users |
| `platform_bp` | `blueprints/platform/routes.py` | Module install/uninstall/status/logs |
| `asm_bp` | `blueprints/asm/scanner.py` | ASM scan trigger/status/results |
| `siem_bp` | `siem_proxy.py` (backend root) | CySIEM proxy endpoints |
| `system_bp` | `blueprints/system/routes.py` | /health, /api/ai/test, /api/config, O365 wodle |
| `backup_bp` | `blueprints/backup/routes.py` | Backup create/restore/schedule |
| `scheduler_bp` | `blueprints/scheduler/routes.py` | APScheduler job management |
| `marketplace_bp` | `blueprints/marketplace/routes.py` | Marketplace catalog + install |
| `audit_bp` | `blueprints/audit/routes.py` | Audit trail for monitoring & compliance |
| `sso_bp` | `blueprints/sso/routes.py` | SSO configuration |
| `benchmark_bp` | `blueprints/benchmark/routes.py` | Security benchmark scoring |
| `comp_bp` | `blueprints/comp/routes.py` | GRC compliance engine routes |
| `cases_bp` | `blueprints/cases/routes.py` | Case management (CyCases) |
| `integrations_bp` | `blueprints/integrations/routes.py` | Third-party integration health + config |
| `edr_bp` | `blueprints/edr/routes.py` | Endpoint detection + response (CyEDR) — not in CLAUDE.md |
| `itam_bp` | `blueprints/itam/routes.py` | IT asset management + discovery — not in CLAUDE.md |

---

## Frontend Pages (authoritative from portal/src/pages/)

| Directory | Files |
|---|---|
| `pages/` (root) | `HostIntelligencePage.jsx` |
| `pages/ai/` | `AISettingsPage.jsx` |
| `pages/assets/` | `AssetsPage.jsx`, `AssetModal.jsx`, `ImportModal.jsx`, `WorldMapWidget.jsx` |
| `pages/audit/` | `AuditTrailPage.jsx` |
| `pages/benchmark/` | `BenchmarkPage.jsx` |
| `pages/cases/` | `CaseDetailPage.jsx`, `CasesListPage.jsx` |
| `pages/compliance/` | `ComplianceAssessmentPage.jsx`, `ComplianceDashboardPage.jsx`, `ComplianceFindingsPage.jsx`, `ComplianceLiveAlertsPage.jsx`, `ComplianceReportsPage.jsx`, `PolicyDocumentsPage.jsx`, `RiskRegisterPage.jsx` |
| `pages/dashboard/` | `DashboardPage.jsx` |
| `pages/edr/` | `EdrAgentInstallerPage.jsx`, `EdrCyScanRulesPage.jsx`, `EdrDetectionsPage.jsx`, `EdrEndpointDetailPage.jsx`, `EdrPoliciesPage.jsx`, `EdrResponsePage.jsx`, `EdrYaraRulesPage.jsx`, `index.jsx` |
| `pages/guest-scan/` | `GuestScanPage.jsx` |
| `pages/history/` | `ScanHistoryPage.jsx` |
| `pages/hosts/` | `AgentGroupsTab.jsx`, `EndpointPoliciesTab.jsx`, `HostDetailPanel.jsx`, `HostsPage.jsx`, `SensorDeploymentTab.jsx` |
| `pages/integrations/` | `index.jsx` |
| `pages/itam/` | `AssetDetailPage.jsx`, `IotRegistryPage.jsx`, `ShadowAiPage.jsx`, `index.jsx` |
| `pages/login/` | `LoginPage.jsx` |
| `pages/marketplace/` | `MarketplacePage.jsx` |
| `pages/platform-extensions/` | `index.jsx` |
| `pages/platform/` | `PlatformPage.jsx` |
| `pages/scan/` | `ScanPage.jsx` |
| `pages/settings/` | `SSOTab.jsx`, `SystemSettingsPage.jsx` |
| `pages/usecases/` | `UseCasesPage.jsx` |
| `pages/vulnerabilities/` | `VulnerabilityPage.jsx` |

---

## ASM Modules (authoritative from cy_asm/modules/)

`cloud_infra`, `crypto_checks`, `dark_web`, `debug_crypto`, `dns_recon`, `email_security`, `mobile_api`, `nuclei_scanner`, `passive_osint`, `social_eng`, `subdomain_enum`, `supply_chain`, `vuln_scanner`, `web_analysis`, `whois_history`

Support: `Utils/update_wordlist.py`, `wordlists/`

---

## cysiemstack Sub-Package (authoritative from backend/cysiemstack/)

Not documented in CLAUDE.md.

**`correlation_engine/`** (24 modules): `ai_router`, `audit_reporter`, `campaign_correlator`, `config`, `correlator`, `cysiem_to_redis`, `cysoar_connector`, `evidence_collector`, `feedback_store`, `fp_pattern_store`, `gap_analyser`, `grouper`, `hypothesis_engine`, `ingestor`, `llm_enricher`, `main`, `misp_enricher`, `models`, `normaliser`, `risk_scorer`, `ti_enricher`, `ueba`, `ueba_ml`

**`threat_hunter/`**: `hunter.py`

**Top-level**: `edr_bridge.py` *(new this week)*, `host_service.py`

---

## Action Items

1. **CLAUDE.md — Add `blueprints/edr/` and `blueprints/itam/`** to Repository Layout and the blueprint table. Both are production-registered with substantial support modules; both are completely absent from CLAUDE.md.

2. **CLAUDE.md — Document `backend/cysiemstack/`** as a sub-package. A 24-module correlation engine + threat hunter + EDR bridge has zero CLAUDE.md coverage.

3. **CLAUDE.md — Add `blueprints/cases/` and `blueprints/integrations/`** to the blueprint list (carried over from last review — still absent).

4. **CLAUDE.md — Add `core/license_validator.py`** to the core/ file list.

5. **CLAUDE.md — Add `cy_comp/services/itam_bridge.py`** to the cy_comp/services service list.

6. **CLAUDE.md — Correct ASM modules description.** Replace "(dns, ssl, ports, etc.)" with the actual 15 module names; `ssl` and `ports` do not exist.

7. **CLAUDE.md — Update Frontend section.** Add `pages/edr/`, `pages/itam/`, and the other undocumented page directories.

8. **CLAUDE.md — Expand Docs Reference table.** 41 docs files exist; only 9 are referenced.
