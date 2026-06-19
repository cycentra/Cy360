# Wazuh Integration Audit — CyCentra 360

**Audit Date:** 2026-06-19
**Requested by:** Product Owner
**Scope:** Wazuh coupling depth, SIEM source portability, Settings > Security Compliance > SIEM Sources UI

---

## Executive Summary

Wazuh is **deeply hardcoded** throughout the CyCentra 360 backend stack. There is no abstraction layer or adapter pattern. The Settings > Security Compliance > SIEM Sources UI (which offers Wazuh / Splunk / Elastic / Sentinel / QRadar / Correlation Engine) is **scaffold-only** — the `siem_type` field is stored in the DB but never read by any runtime process. Switching the setting has zero effect on platform behaviour. If Wazuh were replaced by another SIEM, alert ingestion, all 55 correlation rules, all 7 UEBA detectors, host posture, compliance mappings, and active response would all fail.

---

## 1. Hardcoded Wazuh References — File Inventory

| File | Ref Count | Nature of Coupling |
|------|-----------|--------------------|
| `backend/cysiemstack/correlation_engine/normaliser.py` | 9 | Complete structural dependency — field schema, rule IDs, agent model |
| `backend/cysiemstack/correlation_engine/correlator.py` | 63 | `wazuh_id` as primary alert identifier; all 55 rules filter on Wazuh rule ID sets |
| `backend/cysiemstack/correlation_engine/ueba.py` | 21 | `wazuh_id` is the alert reference key for all 7 UEBA anomaly types |
| `backend/cysiemstack/correlation_engine/main.py` | 32 | Active-response API calls Wazuh REST directly; `wazuh_id` in all UEBA joins |
| `backend/cysiemstack/correlation_engine/models.py` | 2 | `Alert.wazuh_id` column (unique constraint); `HostPostureCache.wazuh_status` |
| `backend/cysiemstack/correlation_engine/config.py` | 3 | `wazuh_api_url`, `wazuh_api_user`, `wazuh_api_password` as typed settings |
| `backend/cysiemstack/correlation_engine/grouper.py` | 1 | `wazuh_id` written to DB at alert creation |
| `backend/siem_proxy.py` | 46 | `WAZUH_API_URL/USER/PASS` env vars; Wazuh SSO; `_wazuh_auth_token()`; Wazuh REST calls for agents/SCA/vulnerabilities |
| `backend/blueprints/benchmark/routes.py` | ~15 | Benchmark scoring entirely driven by Wazuh SCA and vulnerability APIs |
| `backend/blueprints/system/routes.py` | ~30 | `systemctl restart wazuh-manager` for O365/GCP/GitHub integrations; agent installer embeds Wazuh binary paths |
| `backend/cy_comp/services/enrichment.py` | ~15 | `WAZUH_RULE_TO_CONTROLS` — compliance mapping table keyed by Wazuh rule IDs |
| `backend/cy_comp/services/siem_bridge.py` | indirect | Calls `WAZUH_RULE_TO_CONTROLS` for compliance enrichment pass |
| `backend/cysiemstack/host_service.py` | ~15 | `_wazuh_token()`, `_wazuh_get()`, `_fetch_wazuh_agents()` — host posture from Wazuh /agents API |
| `backend/core/config.py` | 4 | `WAZUH_URL` exported; OIDC SSO comments reference Wazuh Dashboard |
| `CYSIEM-Config/conf/ossec.conf` | Many | Wazuh Manager config (all `/var/ossec/` paths, service name, Filebeat certs) |
| `CYSIEM-Config/integrations/custom-llm.py` | Direct | `send_to_wazuh()` injects LLM enrichment back into Wazuh via internal socket |

**Total estimated hardcoded references: ~246 across 15+ files.**

---

## 2. The Settings > SIEM Sources UI — Cosmetic Scaffold

### What it shows

- **Location:** Settings > Security Compliance > SIEM Sources tab (`compTab === "comp-siem"`)
- **File:** `portal/src/pages/settings/SystemSettingsPage.jsx` lines 2302–2391
- **Dropdown options:** `wazuh | splunk | elastic | sentinel | qradar | correlation_engine`
- **Default on form load:** `wazuh`, port 55000

### What it actually does

- **API:** `POST /api/comp/settings/siem-connections` → `backend/blueprints/comp/routes.py` line 1166
- **DB table:** `cy_comp_siem_connections` → `backend/cy_comp/models.py` lines 136–149
- **Runtime effect:** **None.** The saved `siem_type` is never read by any data pipeline.
  - `cy_comp/services/siem_bridge.py` (compliance enrichment) ignores this table entirely and queries the Wazuh-backed `alerts` / `incidents` tables directly.
  - `password_enc` and `api_key_enc` columns exist in the schema but the API does not accept or write these values.
  - `last_sync` timestamp column is never updated by any scheduled job.
- **UI hint:** The empty-state message reads *"No SIEM sources configured. The built-in Correlation Engine adapter runs automatically."*

### Verdict

The SIEM Sources UI is **roadmap scaffolding** — the intent to support multiple SIEMs is architecturally declared but not yet implemented.

---

## 3. What Breaks if Wazuh Is Replaced

| Capability | What Breaks | Why |
|------------|-------------|-----|
| **Alert ingestion** | 100% failure | `normaliser.py` expects Wazuh JSON schema (`rule.id`, `rule.level`, `agent.id`, `agent.name`, `data.srcip`). All non-Wazuh events are dropped. |
| **Correlation rules (all 55)** | 100% failure | Rules filter on hardcoded Wazuh rule ID sets (e.g., SSH: `{5710, 5715, 5716}`, FIM: `{550, 554}`). No Wazuh = zero rule matches = zero incidents ever fire. |
| **UEBA (all 7 detectors)** | 100% failure | All detectors reference `wazuh_id` as primary alert key and filter on Wazuh-specific rule ID ranges. |
| **Host Posture / Agents tab** | Total blackout | `host_service.py` and `siem_proxy.py` call Wazuh REST API at `:55000` for `/agents`, `/sca`, `/vulnerability`. |
| **Benchmark scoring** | Total blackout | `benchmark/routes.py` SCA and vulnerability subscores call Wazuh REST API directly. |
| **Active response** | Immediate failure | `POST /active-response` calls Wazuh REST API directly. |
| **Compliance auto-findings** | Zero results | `WAZUH_RULE_TO_CONTROLS` in `enrichment.py` keyed on Wazuh rule IDs — no Splunk/Sentinel event would match any key. |
| **Cloud integrations (O365/GCP/GitHub)** | Partial failure | Setup routes call `systemctl restart wazuh-manager` — without Wazuh, log collection never starts. |

---

## 4. Migration Path — Making the Platform SIEM-Agnostic

**Estimated effort: 8–12 engineer-days of core refactoring + full test cycle.**

### Layer 1 — Normalisation Adapter (Blocking — must be done first)

Create a `normaliser/` package replacing the monolithic `normaliser.py`:

```
cysiemstack/normaliser/
  base.py        # NormalisedAlert dataclass with canonical fields
  wazuh.py       # Current normaliser logic moved here
  splunk.py      # Maps Splunk JSON → NormalisedAlert
  sentinel.py    # Maps OCSF/CEF → NormalisedAlert
  factory.py     # Reads siem_type from cy_comp_siem_connections, returns right adapter
```

Replace `Alert.wazuh_id` → `Alert.source_alert_id` (source-agnostic). Add `Alert.siem_source` column.

### Layer 2 — Decouple Rule IDs from Wazuh Numbering (Blocking)

Replace hardcoded Wazuh rule ID sets in all 55 correlator rules with normalised category tags:
- `rule_id in {5710, 5715}` → `category == 'authentication_failure'`
- `rule_id in {550, 554}` → `category == 'fim'`

The normaliser already produces these category tags via `_classify_category()` — the correlator must be updated to use them instead of raw `rule_id` sets.

### Layer 3 — Abstract the Agent / Host Registry

Replace direct Wazuh REST calls in `host_service.py`, `siem_proxy.py`, and `benchmark/routes.py` with an `AgentProvider` interface that has a Wazuh implementation and stubs for other SIEMs.

### Layer 4 — Compliance Mapping via MITRE (not Wazuh Rule IDs)

Retire `WAZUH_RULE_TO_CONTROLS` in `enrichment.py` and rely exclusively on `MITRE_TO_CONTROLS` (which already exists). This works because:
- MITRE ATT&CK technique IDs are SIEM-agnostic
- The normaliser already maps Wazuh rules → MITRE IDs
- Splunk/Sentinel events also carry MITRE tags natively

### Layer 5 — Pluggable Active Response

`POST /active-response` must call the SIEM-specific response API (Wazuh REST, Splunk adaptive response, or Sentinel playbooks) based on the configured source.

### Layer 6 — System Management Routes

`systemctl restart wazuh-manager` calls in `system/routes.py` must be conditional on Wazuh being the active SIEM source.

---

## 5. Current SIEM Connections Table Schema

```sql
CREATE TABLE cy_comp_siem_connections (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    siem_type    TEXT NOT NULL,      -- 'wazuh'|'splunk'|'elastic'|'sentinel'|'qradar'|'correlation_engine'
    host         TEXT,
    port         INTEGER DEFAULT 55000,
    username     TEXT,
    password_enc TEXT,               -- encrypted; NOT YET WRITTEN by API
    api_key_enc  TEXT,               -- encrypted; NOT YET WRITTEN by API
    extra_config JSONB DEFAULT '{}',
    is_active    BOOLEAN DEFAULT TRUE,
    last_sync    TIMESTAMPTZ,        -- NEVER updated by any scheduler
    created_at   TIMESTAMPTZ
);
```

**Gap:** The API (`POST /api/comp/settings/siem-connections`) does not accept or write `password_enc` / `api_key_enc`. Even if a user configures a connection, credentials cannot be stored through the UI.

---

## 6. Recommendation

| Priority | Action |
|----------|--------|
| **Immediate** | Add inline note to SIEM Sources UI clarifying it is read-only metadata at this time (prevent user confusion) |
| **Short-term** | Implement Layers 1–2 above to unlock non-Wazuh ingestion |
| **Medium-term** | Implement Layers 3–4 to restore host posture and compliance mapping for other SIEMs |
| **Long-term** | Implement Layers 5–6 for full operational parity |

Until Layer 1 is implemented, the platform is **Wazuh-only** regardless of what is configured in the SIEM Sources setting.
