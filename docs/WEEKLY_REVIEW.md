# Cy360 Weekly Architecture Review

**Last reviewed:** 2026-06-18
**Current version:** v1.0.57 (git HEAD `2560f90`; RELEASE_NOTES.md also contains pre-release notes for v1.0.58)
**Commits this week:** 30 (v1.0.28 → v1.0.57, 2026-06-10 → 2026-06-17)

## Summary

This week saw heavy release activity (30 commits) focused on SIEM stability — critical fixes for a zero-incident production outage caused by an FP-threshold miscalibration and a race condition in incident ID assignment. Structural additions include new threat hunter rules (HT-007 through HT-012), the `AgentGroupsTab` frontend component, multi-platform cy360-agent distribution packages, and automation tooling for agent command updates.

---

## CLAUDE.md Drift

Items present in code but **not described** in CLAUDE.md:

| Area | What exists in code | CLAUDE.md status |
|---|---|---|
| Blueprint | `blueprints/cases/` — `cases_bp` (routes.py, service.py, checklist_templates.py) — fully registered in app.py as a case management module | **Missing entirely** |
| Sub-package | `backend/cysiemstack/` — FastAPI correlation engine (20+ files) + threat_hunter with 12 YAML hunt rules | **Missing entirely** |
| Core file | `core/license_validator.py` | Not listed; only config.py, helpers.py, kv_secrets.py mentioned |
| Blueprint support files | `blueprints/platform/compose.py`, `docker_utils.py`, `state.py` | Only `routes.py` mentioned |
| SIEM blueprint layout | `blueprints/siem/` contains only `__init__.py`; actual proxy is `siem_proxy.py` at backend root. App.py header comment incorrectly labels it as `blueprints/siem/proxy.py` | Comment is stale |
| Frontend pages | `pages/ai/`, `pages/assets/`, `pages/cases/`, `pages/hosts/`, `pages/guest-scan/`, `pages/history/`, `pages/platform-extensions/`, `pages/usecases/`, `pages/vulnerabilities/`, `HostIntelligencePage.jsx` | All missing from page directory list |
| ASM modules | 15 actual modules: cloud_infra, crypto_checks, dark_web, debug_crypto, dns_recon, email_security, mobile_api, nuclei_scanner, passive_osint, social_eng, subdomain_enum, supply_chain, vuln_scanner, web_analysis, whois_history | CLAUDE.md says "(dns, ssl, ports, etc.)" — no ssl or ports module exists |
| Agent packages | `agent-packages/` — cy360-agent v1.0.33 for amd64 deb, x86_64/aarch64 rpm, arm64/intel64 pkg, msi | Not documented |
| Docs | 15 docs files not in CLAUDE.md reference table (see docs list below) | Docs table is significantly stale |

---

## New Since Last Review

*(No prior WEEKLY_REVIEW.md — scoped to last 8 days, 2026-06-10 → 2026-06-18)*

**Code:**
- `backend/cysiemstack/threat_hunter/rules/HT-007-wmi-persistence.yml`
- `backend/cysiemstack/threat_hunter/rules/HT-008-lolbas-pattern.yml`
- `backend/cysiemstack/threat_hunter/rules/HT-009-slow-cloud-exfil.yml`
- `backend/cysiemstack/threat_hunter/rules/HT-010-mfa-fatigue-campaign.yml`
- `backend/cysiemstack/threat_hunter/rules/HT-011-pass-the-hash-lateral.yml`
- `backend/cysiemstack/threat_hunter/rules/HT-012-cryptominer-detection.yml`
- `portal/src/pages/hosts/AgentGroupsTab.jsx`
- `scripts/update_agent_commands.py`

**Infra / tooling:**
- `.github/workflows/update-agent-commands.yml` — CI workflow for agent command sync
- `.claude/commands/` — 12 CyRA agent command files added
- `agent-packages/` — cy360-agent v1.0.33 multi-platform distribution packages (deb, rpm, msi, pkg)

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
| `cases_bp` | `blueprints/cases/routes.py` | CyCases native case management (**undocumented in CLAUDE.md**) |

---

## Frontend Pages (authoritative from portal/src/pages/)

| Page file | Path |
|---|---|
| HostIntelligencePage.jsx | `pages/` (root) |
| AISettingsPage.jsx | `pages/ai/` |
| AssetsPage.jsx, AssetModal.jsx, ImportModal.jsx, WorldMapWidget.jsx | `pages/assets/` |
| AuditTrailPage.jsx | `pages/audit/` |
| BenchmarkPage.jsx | `pages/benchmark/` |
| CaseDetailPage.jsx, CasesListPage.jsx | `pages/cases/` |
| ComplianceAssessmentPage.jsx, ComplianceDashboardPage.jsx, ComplianceFindingsPage.jsx, ComplianceLiveAlertsPage.jsx, ComplianceReportsPage.jsx, PolicyDocumentsPage.jsx, RiskRegisterPage.jsx | `pages/compliance/` |
| DashboardPage.jsx | `pages/dashboard/` |
| GuestScanPage.jsx | `pages/guest-scan/` |
| ScanHistoryPage.jsx | `pages/history/` |
| AgentGroupsTab.jsx, HostDetailPanel.jsx, HostsPage.jsx | `pages/hosts/` |
| LoginPage.jsx | `pages/login/` |
| MarketplacePage.jsx | `pages/marketplace/` |
| index.jsx | `pages/platform-extensions/` |
| PlatformPage.jsx | `pages/platform/` |
| ScanPage.jsx | `pages/scan/` |
| SSOTab.jsx, SystemSettingsPage.jsx | `pages/settings/` |
| UseCasesPage.jsx | `pages/usecases/` |
| VulnerabilityPage.jsx | `pages/vulnerabilities/` |

---

## ASM Modules (authoritative from cy_asm/modules/)

`cloud_infra`, `crypto_checks`, `dark_web`, `debug_crypto`, `dns_recon`, `email_security`, `mobile_api`, `nuclei_scanner`, `passive_osint`, `social_eng`, `subdomain_enum`, `supply_chain`, `vuln_scanner`, `web_analysis`, `whois_history`

Support: `Utils/update_wordlist.py`, `wordlists/`

---

## cysiemstack Sub-Package (undocumented — authoritative from backend/cysiemstack/)

**`correlation_engine/`** (FastAPI service):
`ai_router`, `audit_reporter`, `campaign_correlator`, `config`, `correlator`, `cysiem_to_redis`, `cysoar_connector`, `feedback_store`, `fp_pattern_store`, `grouper`, `ingestor`, `llm_enricher`, `main`, `misp_enricher`, `models`, `normaliser`, `risk_scorer`, `ueba`, `ueba_ml`

**`threat_hunter/`**: `hunter.py` + 12 YAML hunt rules (HT-001 through HT-012)

**`host_service.py`** (top-level)

---

## Docs in docs/ (authoritative)

Documented in CLAUDE.md: `GRC_ENGINE_FLOW.md`, `CYMIND_INTEGRATION.md`, `INFISICAL-SETUP.md`, `SCAN_DATA_FLOW.md`, `GRC_SCORING_MODEL.md`, `SSO-Configuration.md`, `SCHEDULER.md`, `RELEASE_NOTES.md`, `MARKETPLACE.md`

**Not in CLAUDE.md docs table:**
`AGENTS_MARKETPLACE.md`, `AGENT_TROUBLESHOOTING.md`, `ASM_ENHANCEMENTS.md`, `AUTO_TICKET_LOGIC.md`, `BEHAVIOURAL_ANALYTICS.md`, `Benchmark Score Calculations.md`, `COMPLIANCE_GAP_ANALYSIS.md`, `GRC_CROSS_FRAMEWORK_CORRELATION.md`, `MITRE_ATTACK_COVERAGE.md`, `Reports.md`, `SIEM_SEVERITY_TUNING.md`, `SSO-Troubleshooting.md`, `infisical-secrets-template.csv`, `install-warnings-explained.md`, `standard-vs-deep-scan.md`

---

## Action Items

1. **CLAUDE.md — Add `blueprints/cases/` to Repository Layout and blueprint list.** `cases_bp` is fully registered and production-active; CLAUDE.md is the primary onboarding reference and it is completely absent.

2. **CLAUDE.md — Document `backend/cysiemstack/`.** This is a substantial FastAPI sub-service (correlation engine + threat hunter) with no mention anywhere in CLAUDE.md. Add it to the repo layout, describe its role, and note it is separate from the Flask app.

3. **CLAUDE.md — Add `core/license_validator.py` to the core/ list.** Currently only `config.py`, `helpers.py`, `kv_secrets.py` are mentioned.

4. **CLAUDE.md — Correct ASM modules description.** Replace "(dns, ssl, ports, etc.)" with the actual module names; there is no `ssl` or `ports` module.

5. **CLAUDE.md — Update Frontend Pages section.** At least 10 page directories are unlisted (assets, cases, hosts, guest-scan, history, platform-extensions, usecases, vulnerabilities, ai, HostIntelligencePage).

6. **CLAUDE.md — Expand the Docs Reference table.** 15 additional doc files exist and are not referenced.

7. **`app.py` header comment — Update blueprint list.** The docstring at the top of app.py omits `scheduler_bp`, `marketplace_bp`, `sso_bp`, `benchmark_bp`, `comp_bp`, and `cases_bp` from its blueprint–responsibility table.
