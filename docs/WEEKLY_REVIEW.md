# Cy360 Weekly Architecture Review

**Last reviewed:** 2026-07-09
**Current version:** v1.0.189
**Commits this week:** 50 (v1.0.152 → v1.0.189; 8 substantive non-release commits since 2026-07-02)

## Summary

This week's changes were concentrated in the ASM pipeline: all external threat-intelligence and dark-web lookups were centralised through the CyTIM recon gateway, and AI enrichment was simplified to CyMind-only (Gemini and Ollama fallbacks removed). The SOC dashboard received a significant UI rework — SIEM widgets removed, External Attack Posture page redesigned, and all eight ASM widgets converted to donut charts. A new `RiskPredictionPage.jsx` and its backing `cy_comp/services/prediction.py` service landed for ML-based compliance risk forecasting. No new blueprints or sub-packages were registered this week; structural drift carried over from last review remains.

---

## CLAUDE.md Drift

Items present in code but **not described** in CLAUDE.md:

| Area | What exists in code | CLAUDE.md status |
|---|---|---|
| Blueprint | `blueprints/edr/` — `edr_bp` (routes.py + confidence_matrix, normalizer, policy_engine, response_orchestrator) | **Missing entirely** |
| Blueprint | `blueprints/itam/` — `itam_bp` (routes.py + 10 discovery/scanner modules) | **Missing entirely** |
| Blueprint | `blueprints/cases/` — `cases_bp` (routes.py, service.py, checklist_templates.py) | **Missing entirely** |
| Blueprint | `blueprints/integrations/` — `integrations_bp` (routes.py, health.py) | **Missing entirely** |
| Sub-package | `backend/cysiemstack/` — correlation_engine (22 modules) + threat_hunter + edr_bridge + host_service | **Missing entirely** |
| Core file | `core/license_validator.py` | Not listed; CLAUDE.md lists only config.py, helpers.py, kv_secrets.py |
| GRC services | `cy_comp/services/control_validator.py`, `itam_bridge.py`, `prediction.py` | Not listed in the cy_comp/services inventory |
| Blueprint support files | `blueprints/platform/compose.py`, `docker_utils.py`, `state.py` | Only routes.py mentioned |
| Frontend pages | `pages/edr/`, `pages/itam/`, `pages/cases/`, `pages/ai/`, `pages/assets/`, `pages/hosts/`, `pages/guest-scan/`, `pages/history/`, `pages/integrations/`, `pages/platform-extensions/`, `pages/usecases/`, `pages/vulnerabilities/`, `pages/compliance/RiskPredictionPage.jsx`, `HostIntelligencePage.jsx` | All absent from CLAUDE.md |
| ASM modules | 15 modules on disk: cloud_infra, crypto_checks, dark_web, dns_recon, email_security, mobile_api, nuclei_scanner, passive_osint, social_eng, subdomain_enum, supply_chain, vuln_scanner, web_analysis, whois_history, debug_crypto | CLAUDE.md placeholder "(dns, ssl, ports, etc.)" — `ssl` and `ports` modules do not exist |
| Docs | 44 files in docs/ (including archive/); CLAUDE.md reference table covers 9 | Table significantly stale |

---

## New Since Last Review

*(Scoped to 2026-07-02 → 2026-07-09)*

**Backend — new service:**
- `cy_comp/services/prediction.py` — ML-backed compliance risk prediction service

**Frontend — new page:**
- `portal/src/pages/compliance/RiskPredictionPage.jsx` — UI for risk prediction

**ASM — architectural changes (no new files, behavioural change):**
- All external TI lookups (VirusTotal, Shodan, Censys, dark web, etc.) now routed through the CyTIM centralised recon endpoint (`feat: Route all ASM external APIs through CyTIM recon endpoint`)
- AI enrichment simplified: CyMind-only; Gemini and Ollama fallback paths removed from `cy_asm/cycentra_scan.py`

**Dashboard — UI rework (no new files):**
- SIEM widgets removed from main dashboard
- External Attack Posture page layout redesigned
- All 8 ASM widgets converted to donut charts

**Docs — new this week:**
- `docs/CYTIM_CENTRALIZATION_2026-07-05.md` — architecture decision record for CyTIM centralisation
- `docs/CYTIM_RECON_ARCHITECTURE_2026-07-05_17-12.md` — detailed CyTIM recon architecture
- `docs/ASM_STATUS_REPORT_2026-07-05_17-12.md` — ASM status snapshot
- `docs/CYCOMP_ENHANCEMENTS_20260708.md` — GRC/compliance enhancement notes

---

## Registered Blueprints (authoritative from app.py)

| Blueprint | Source file | Responsibility |
|---|---|---|
| `auth_bp` | `blueprints/auth/oauth.py` | Google + Microsoft OAuth, auth verify, auth logs |
| `oidc_bp` | `blueprints/oidc/provider.py` | OIDC IdP (discovery, authorize, token, userinfo, introspect) |
| `rbac_bp` | `blueprints/rbac/manager.py` | RBAC load/save, role resolution, /api/users |
| `platform_bp` | `blueprints/platform/routes.py` | Module install/uninstall/status/logs |
| `asm_bp` | `blueprints/asm/scanner.py` | ASM scan trigger/status/results |
| `siem_bp` | `siem_proxy.py` (backend root) | CySIEM proxy (13 endpoints) |
| `system_bp` | `blueprints/system/routes.py` | /health, /api/ai/test, /api/config, O365 wodle |
| `backup_bp` | `blueprints/backup/routes.py` | Backup create/restore/schedule |
| `scheduler_bp` | `blueprints/scheduler/routes.py` | APScheduler job management |
| `marketplace_bp` | `blueprints/marketplace/routes.py` | Marketplace catalog + install |
| `audit_bp` | `blueprints/audit/routes.py` | Audit trail |
| `sso_bp` | `blueprints/sso/routes.py` | SSO configuration |
| `benchmark_bp` | `blueprints/benchmark/routes.py` | Security benchmark scoring |
| `comp_bp` | `blueprints/comp/routes.py` | GRC compliance engine |
| `cases_bp` | `blueprints/cases/routes.py` | Case management (CyCases) — **not in CLAUDE.md** |
| `integrations_bp` | `blueprints/integrations/routes.py` | Third-party integration health + config — **not in CLAUDE.md** |
| `edr_bp` | `blueprints/edr/routes.py` | Endpoint detection + response (CyEDR) — **not in CLAUDE.md** |
| `itam_bp` | `blueprints/itam/routes.py` | IT asset management + discovery — **not in CLAUDE.md** |

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
| `pages/compliance/` | `ComplianceAssessmentPage.jsx`, `ComplianceDashboardPage.jsx`, `ComplianceFindingsPage.jsx`, `ComplianceLiveAlertsPage.jsx`, `ComplianceReportsPage.jsx`, `PolicyDocumentsPage.jsx`, `RiskPredictionPage.jsx` *(new)*, `RiskRegisterPage.jsx` |
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

Not documented in CLAUDE.md at all.

**`correlation_engine/`** (22 modules): `ai_router`, `audit_reporter`, `campaign_correlator`, `config`, `correlator`, `cysiem_to_redis`, `cysoar_connector`, `cytim_enricher`, `evidence_collector`, `feedback_store`, `fp_pattern_store`, `gap_analyser`, `grouper`, `hypothesis_engine`, `ingestor`, `llm_enricher`, `main`, `models`, `normaliser`, `risk_scorer`, `ueba`, `ueba_ml`

**`threat_hunter/`**: `hunter.py` + 14 YAML hunt rules (HT-001 through HT-014)

**Top-level**: `edr_bridge.py`, `host_service.py`

**Migrations**: `postgres/migrations/` — 5 SQL migration files (001–005)

---

## GRC Services (authoritative from cy_comp/services/)

`ai_analysis`, `auto_findings`, `compliance`, `control_validator` *(not in CLAUDE.md)*, `enrichment`, `itam_bridge` *(not in CLAUDE.md)*, `policy_analysis`, `policy_rag`, `prediction` *(new this week; not in CLAUDE.md)*, `questionnaire`, `report`, `risk`, `siem_bridge`, `soa`

---

## Action Items

1. **CLAUDE.md — Add `blueprints/edr/` and `blueprints/itam/`** to the layout and blueprint table. Both are production-registered with substantial support modules.

2. **CLAUDE.md — Document `backend/cysiemstack/`** as a sub-package alongside `cy_comp` and `cy_asm`. A 22-module correlation engine + threat hunter + EDR bridge has zero CLAUDE.md coverage.

3. **CLAUDE.md — Add `blueprints/cases/` and `blueprints/integrations/`** to the blueprint list.

4. **CLAUDE.md — Add `core/license_validator.py`** to the core/ file list.

5. **CLAUDE.md — Update `cy_comp/services/` list** to include `control_validator.py`, `itam_bridge.py`, and `prediction.py`.

6. **CLAUDE.md — Correct ASM modules description.** Replace the placeholder "(dns, ssl, ports, etc.)" with the actual 15 module names; `ssl` and `ports` modules do not exist.

7. **CLAUDE.md — Expand Frontend section.** Add all undocumented page directories (edr, itam, cases, ai, assets, hosts, guest-scan, history, integrations, platform-extensions, usecases, vulnerabilities).

8. **CLAUDE.md — Expand Docs Reference table.** 44 docs files on disk; only 9 are listed.

9. **ASM — CyMind-only enrichment** is now the sole AI path. If CyMind is unavailable the enrichment step silently fails with no fallback. Consider documenting degraded-mode behaviour in `docs/CYMIND_INTEGRATION.md`.
