# Cy360 Weekly Architecture Review

**Last reviewed:** 2026-07-16
**Current version:** v1.0.225
**Commits this week:** 50 (v1.0.200 → v1.0.225; 1 substantive non-release commit since 2026-07-09)

## Summary

This week's most significant structural change was the addition of three new blueprints (`collector_bp`, `connectors_bp`, `detection_rules_bp`) all now registered in `app.py`, corresponding to Phase 7 of the CyDataLake migration plan. The `cysiemstack` sub-package gained major additions: a full vendor-connector layer (10 sources), a Sigma detection engine, and Kafka/ClickHouse data-pipeline infrastructure. A new top-level `agent/` directory appeared containing the CyCollector and CyEDR agent scripts, and a formal `tests/` directory was created with 13 unit tests and 27 manual test modules. The single substantive non-release commit was a shadow-AI telemetry fix (`fix(shadow-ai): resolve telemetry 401 and bare-envelope format bugs`).

---

## CLAUDE.md Drift

Items present in code but **not described** in CLAUDE.md:

| Area | What exists in code | CLAUDE.md status |
|---|---|---|
| Blueprint | `blueprints/collector/` — `collector_bp` (routes.py) | **Missing entirely** |
| Blueprint | `blueprints/connectors/` — `connectors_bp` (routes.py) | **Missing entirely** |
| Blueprint | `blueprints/detection_rules/` — `detection_rules_bp` (routes.py) | **Missing entirely** |
| Blueprint | `blueprints/edr/` — `edr_bp` + confidence_matrix, normalizer, policy_engine, response_orchestrator | **Missing entirely** |
| Blueprint | `blueprints/itam/` — `itam_bp` + 10 discovery/scanner support modules | **Missing entirely** |
| Blueprint | `blueprints/cases/` — `cases_bp` + service.py, checklist_templates.py | **Missing entirely** |
| Blueprint | `blueprints/integrations/` — `integrations_bp` + health.py | **Missing entirely** |
| Sub-package | `backend/cysiemstack/` — connectors (10 vendors), correlation_engine (24 modules), detection (Sigma), threat_hunter, data-pipeline infra | **Missing entirely** |
| Top-level | `agent/` — `cycollector_agent.py`, `cyedr_agent.py` | **Missing entirely** |
| Top-level | `tests/` — 13 unit tests, 27 manual test modules | **Missing entirely** |
| Core file | `core/license_validator.py` | Not listed; CLAUDE.md lists only config.py, helpers.py, kv_secrets.py |
| GRC services | `cy_comp/services/control_validator.py`, `itam_bridge.py`, `prediction.py` | Not listed in the cy_comp/services inventory |
| Blueprint support | `blueprints/platform/compose.py`, `docker_utils.py`, `state.py` | Only routes.py mentioned |
| Frontend pages | `pages/edr/`, `pages/itam/`, `pages/cases/`, `pages/ai/`, `pages/assets/`, `pages/hosts/`, `pages/guest-scan/`, `pages/history/`, `pages/integrations/`, `pages/connectors/`, `pages/platform-extensions/`, `pages/usecases/`, `pages/vulnerabilities/`, `HostIntelligencePage.jsx`, `settings/DetectionRulesPage.jsx` | All absent from CLAUDE.md |
| ASM modules | 15 modules on disk: cloud_infra, crypto_checks, dark_web, dns_recon, email_security, mobile_api, nuclei_scanner, passive_osint, social_eng, subdomain_enum, supply_chain, vuln_scanner, web_analysis, whois_history, debug_crypto | CLAUDE.md placeholder "(dns, ssl, ports, etc.)" — `ssl` and `ports` modules do not exist |
| Docs | 47+ files in docs/ (plus archive/); CLAUDE.md reference table covers 9 | Table significantly stale |

---

## New Since Last Review

*(Scoped to 2026-07-09 → 2026-07-16; compared against previous review's documented state)*

**New Blueprints (3 newly registered in app.py):**
- `blueprints/collector/routes.py` → `collector_bp` — log/data collector API
- `blueprints/connectors/routes.py` → `connectors_bp` — vendor SIEM connector management
- `blueprints/detection_rules/routes.py` → `detection_rules_bp` — detection rule CRUD

**New cysiemstack components:**
- `cysiemstack/connectors/` — 10-vendor connector sub-package: `aws_connector`, `azure_connector`, `gcp_connector`, `office365_connector`, `paloalto_connector`, `qradar_connector`, `sentinelone_connector`, `splunk_connector`, `wazuh_connector`, `base`, `registry`
- `cysiemstack/detection/` — Sigma detection engine: `sigma_engine`, `import_sigma_rules`, `rule_corpus_refresh`, `validate_sigma_rules`
- `cysiemstack/clickhouse_store.py`, `collector_bridge.py`, `connector_bridge.py`, `dedup.py`, `ingest_worker.py`, `kafka_bridge.py` — data-pipeline infrastructure
- `cysiemstack/correlation_engine/custom_rules_engine.py`, `correlation_engine/rule_cache.py` — two new correlation engine modules (total now 24)

**New top-level directories:**
- `agent/cycollector_agent.py`, `agent/cyedr_agent.py` — on-endpoint agent scripts

**New test infrastructure:**
- `tests/unit/` — 13 unit test files
- `tests/modules/` — 27 manual test modules (M01–M27)
- `tests/MANUAL_TEST_GUIDE.md`, `tests/TEST_RUN_HISTORY.md`, `tests/TEST_RUN_REPORT.md`

**New frontend pages:**
- `pages/connectors/index.jsx` — Connector management UI
- `pages/settings/DetectionRulesPage.jsx` — Detection rules management UI

**Bug fix:**
- `fix(shadow-ai): resolve telemetry 401 and bare-envelope format bugs` — fixes ITAM Shadow AI telemetry endpoint auth and response envelope parsing

---

## Registered Blueprints (authoritative from app.py)

| Blueprint | Source file | Responsibility |
|---|---|---|
| `auth_bp` | `blueprints/auth/oauth.py` | Google + Microsoft OAuth, auth verify, auth logs |
| `oidc_bp` | `blueprints/oidc/provider.py` | OIDC IdP (discovery, authorize, token, userinfo, introspect) |
| `rbac_bp` | `blueprints/rbac/manager.py` | RBAC load/save, role resolution, /api/users |
| `platform_bp` | `blueprints/platform/routes.py` | Module install/uninstall/status/logs |
| `asm_bp` | `blueprints/asm/scanner.py` | ASM scan trigger/status/results |
| `siem_bp` | `siem_proxy.py` (backend root) | CySIEM proxy |
| `system_bp` | `blueprints/system/routes.py` | /health, /api/ai/test, /api/config, O365 wodle |
| `backup_bp` | `blueprints/backup/routes.py` | Backup create/restore/schedule |
| `scheduler_bp` | `blueprints/scheduler/routes.py` | APScheduler job management |
| `marketplace_bp` | `blueprints/marketplace/routes.py` | Marketplace catalog + install |
| `audit_bp` | `blueprints/audit/routes.py` | Audit trail |
| `sso_bp` | `blueprints/sso/routes.py` | SSO configuration |
| `benchmark_bp` | `blueprints/benchmark/routes.py` | Security benchmark scoring |
| `comp_bp` | `blueprints/comp/routes.py` | GRC compliance engine |
| `cases_bp` | `blueprints/cases/routes.py` | Case management (CyCases) |
| `integrations_bp` | `blueprints/integrations/routes.py` | Third-party integration health + config |
| `edr_bp` | `blueprints/edr/routes.py` | Endpoint detection + response (CyEDR) |
| `itam_bp` | `blueprints/itam/routes.py` | IT asset management + discovery |
| `collector_bp` | `blueprints/collector/routes.py` | Log/data collector API — **new this week** |
| `connectors_bp` | `blueprints/connectors/routes.py` | Vendor SIEM connector management — **new this week** |
| `detection_rules_bp` | `blueprints/detection_rules/routes.py` | Detection rule CRUD — **new this week** |

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
| `pages/compliance/` | `ComplianceAssessmentPage.jsx`, `ComplianceDashboardPage.jsx`, `ComplianceFindingsPage.jsx`, `ComplianceLiveAlertsPage.jsx`, `ComplianceReportsPage.jsx`, `PolicyDocumentsPage.jsx`, `RiskPredictionPage.jsx`, `RiskRegisterPage.jsx` |
| `pages/connectors/` | `index.jsx` — **new this week** |
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
| `pages/settings/` | `SSOTab.jsx`, `SystemSettingsPage.jsx`, `DetectionRulesPage.jsx` *(new this week)* |
| `pages/usecases/` | `UseCasesPage.jsx` |
| `pages/vulnerabilities/` | `VulnerabilityPage.jsx` |

---

## ASM Modules (authoritative from cy_asm/modules/)

`cloud_infra`, `crypto_checks`, `dark_web`, `debug_crypto`, `dns_recon`, `email_security`, `mobile_api`, `nuclei_scanner`, `passive_osint`, `social_eng`, `subdomain_enum`, `supply_chain`, `vuln_scanner`, `web_analysis`, `whois_history`

Support: `Utils/update_wordlist.py`, `wordlists/`

---

## cysiemstack Sub-Package (authoritative from backend/cysiemstack/)

Not documented in CLAUDE.md at all.

**`connectors/`** (NEW this week): `aws_connector`, `azure_connector`, `gcp_connector`, `office365_connector`, `paloalto_connector`, `qradar_connector`, `sentinelone_connector`, `splunk_connector`, `wazuh_connector`, `base`, `registry`

**`correlation_engine/`** (24 modules): `ai_router`, `audit_reporter`, `campaign_correlator`, `config`, `correlator`, `custom_rules_engine` *(new)*, `cysiem_to_redis`, `cysoar_connector`, `cytim_enricher`, `evidence_collector`, `feedback_store`, `fp_pattern_store`, `gap_analyser`, `grouper`, `hypothesis_engine`, `ingestor`, `llm_enricher`, `main`, `models`, `normaliser`, `risk_scorer`, `rule_cache` *(new)*, `ueba`, `ueba_ml`

**`detection/`** (NEW this week): `sigma_engine`, `import_sigma_rules`, `rule_corpus_refresh`, `validate_sigma_rules`

**`threat_hunter/`**: `hunter.py`

**Top-level**: `clickhouse_store.py` *(new)*, `collector_bridge.py` *(new)*, `connector_bridge.py` *(new)*, `dedup.py` *(new)*, `edr_bridge.py`, `host_service.py`, `ingest_worker.py` *(new)*, `kafka_bridge.py` *(new)*

---

## GRC Services (authoritative from cy_comp/services/)

`ai_analysis`, `auto_findings`, `compliance`, `control_validator`, `enrichment`, `itam_bridge`, `policy_analysis`, `policy_rag`, `prediction`, `questionnaire`, `report`, `risk`, `siem_bridge`, `soa`

(`control_validator`, `itam_bridge`, `prediction` are not listed in CLAUDE.md.)

---

## Action Items

1. **CLAUDE.md — Add `blueprints/collector/`, `blueprints/connectors/`, `blueprints/detection_rules/`** to the repository layout and blueprint table. All three are production-registered as of this week.

2. **CLAUDE.md — Add `backend/cysiemstack/`** as a documented sub-package alongside `cy_comp` and `cy_asm`. The connectors and detection sub-packages are particularly undocumented.

3. **CLAUDE.md — Add `agent/` top-level directory** (`cycollector_agent.py`, `cyedr_agent.py`).

4. **CLAUDE.md — Add `tests/` directory reference** (unit tests, manual test modules).

5. **CLAUDE.md — Add `blueprints/edr/`, `blueprints/itam/`, `blueprints/cases/`, `blueprints/integrations/`** to the layout table — carried over from prior reviews.

6. **CLAUDE.md — Add `core/license_validator.py`** to the core/ listing.

7. **CLAUDE.md — Update `cy_comp/services/` list** to include `control_validator.py`, `itam_bridge.py`, `prediction.py`.

8. **CLAUDE.md — Correct ASM modules description.** Replace "(dns, ssl, ports, etc.)" with actual 15 module names; `ssl` and `ports` modules do not exist.

9. **CLAUDE.md — Expand Frontend section** to cover the 15+ undocumented page directories.

10. **CLAUDE.md — Expand Docs Reference table** — 47+ files on disk, only 9 listed.

11. **Shadow-AI degraded mode** — CyMind-only AI enrichment path (no fallback) means silent failure if CyMind is unavailable. Consider documenting in `docs/CYMIND_INTEGRATION.md`.
