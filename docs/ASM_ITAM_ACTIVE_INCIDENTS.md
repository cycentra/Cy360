# CyCentra 360 — ASM & ITAM Anomalies in Active Incidents
## Design, Architecture & Implementation Record

**Status:** IMPLEMENTED  
**Date:** 2026-07-02  
**Prepared by:** g-cyra-360  
**Trigger:** Gap identified — ASM findings and ITAM anomalies had no path into the SIEM correlation engine; analysts had no unified triage view across all signal sources.

---

## 1. Problem Statement

CyCentra 360 has three detection surfaces outside the SIEM correlation engine:

| Surface | What it detects | Pre-fix visibility |
|---|---|---|
| **ASM** (Attack Surface Management) | External vulnerabilities, exposed services, misconfigured DNS/TLS/email | Own findings store only — never reached Active Incidents |
| **ITAM deep scan** | High/critical CVEs on internal assets | Stored in `software_inventory` / `software_cves` — never reached Active Incidents |
| **ITAM IoT registry** | High-risk IoT devices (default creds, Telnet, no TLS) | Stored in `iot_devices` — never reached Active Incidents |
| **ITAM shadow AI** | Unauthorised AI tools running on endpoints | Stored in `shadow_ai_findings` — never reached Active Incidents |

**Consequence:** Analysts had to switch between four separate views (External Attack Posture, Asset Coverage, IoT Registry, Shadow AI Monitor) to find anomalies that should be triaged together. None of these anomalies received MISP enrichment, threat-intel (VT/AbuseIPDB/GreyNoise) correlation, LLM narrative, UEBA analysis, FP scoring, or automatic CyCase creation.

**Additionally:** Case Management was embedded inside the INTERNAL EXPOSURE nav section, giving it no visual distinction from SIEM-specific items.

---

## 2. What Changed

### 2a. Navigation

Case Management moved from the INTERNAL EXPOSURE section into its own **CASE MANAGEMENT** section at the bottom of the sidebar, above PLATFORM CONFIGURATION. File: `portal/src/sidebar/navConfig.jsx`.

### 2b. ASM → Active Incidents

Two hooks added to `blueprints/asm/scanner.py`:

**Hook 1 — Scan completion (automatic)**  
`GET /api/scans/latest` now calls `_push_scan_to_siem_once()` on first read after a scan finishes. The function:
1. Extracts all `vulnerabilities` from the portal JSON (`assets[*].vulnerabilities`)
2. Filters to severity = high or critical
3. Calls `edr_bridge.push_asm_scan_findings()` which bulk-pushes them to Redis
4. Writes a companion `<scan_file>.siem_pushed` marker file to prevent replay on subsequent GET calls

**Hook 2 — Analyst escalation (manual)**  
`POST /api/asm/findings/<id>/status` now calls `_push_finding_escalation_to_siem()` when the target status is `in_review`. The function reads the matching finding from the latest scan JSON (for context), then calls `edr_bridge.push_asm_finding()` with severity floor of `high`.

### 2c. ITAM → Active Incidents

Three hooks added to `blueprints/itam/routes.py`:

**Hook 1 — Deep scan CVEs**  
`_ingest_deep_scan_result()` calls `_push_deep_scan_cves_to_siem()` after CVE enrichment completes. This queries `software_inventory JOIN software_cves` for the top-20 high/critical CVEs on the scanned asset and pushes each unique CVE as a separate alert.

**Hook 2 — Shadow AI detection**  
`ingest_shadow_ai()` (called by EDR telemetry and DNS monitor) now uses `RETURNING id` on its INSERT. When a **new** finding is inserted (not a duplicate), it calls `_push_shadow_ai_to_siem()`. Existing duplicate detections are not re-pushed.

**Hook 3 — High-risk IoT device**  
The IoT device upsert loop now uses `RETURNING (xmax = 0) AS is_new_row`. When a device is **first discovered** (not updated) with `risk_score >= 75`, it calls `_push_iot_risk_to_siem()`. Repeated scans of the same high-risk device do not generate duplicate incidents.

---

## 3. Architecture — Full Pipeline

Every alert pushed by these hooks flows through the same pipeline as EDR detections and Wazuh alerts:

```
ASM scan complete  ──►  _push_scan_to_siem_once()       ──►┐
ASM finding escalated►  _push_finding_escalation_to_siem()  │
ITAM high/crit CVE  ──► _push_deep_scan_cves_to_siem()      │
ITAM shadow AI new  ──► _push_shadow_ai_to_siem()           │
ITAM IoT risk ≥75   ──► _push_iot_risk_to_siem()            │
                                                             ▼
                              edr_bridge.push_asm_finding()
                              edr_bridge.push_itam_anomaly()
                                           │
                                           ▼
                              _wrap_as_wazuh()
                        (synthetic Wazuh-format JSON envelope)
                                           │
                                           ▼
                              Redis  cysiemstack:alerts:raw
                                           │
                                           ▼
                          ingestor.py  (correlation engine)
                                           │
                              normalise() → _classify_category()
                                           │
                              group_alert() → Incident created or merged
                                           │
                          ┌────────────────┴────────────────┐
                          │                                 │
                 MISP IOC enrichment            TI enrichment
                 (known bad IPs/hashes)     (VT + AbuseIPDB + GreyNoise)
                          │                                 │
                          └────────────────┬────────────────┘
                                           │
                              Correlation rules (55 rules)
                                           │
                              UEBA analysis (user + host)
                                           │
                              FP probability scoring (0–100)
                                           │
                            ┌──────────────┴──────────────┐
                            │              │              │
                        FP ≥ threshold  FP 40-threshold  FP < 40
                        auto-close      investigating    in_review
                                                              │
                                                    severity high/critical
                                                    alert_count ≥ 3
                                                              │
                                                    CyCase auto-opened
                                                    case_type inferred
                                                              │
                                              LLM narrative generated
                                              (if high/critical, ≥3 alerts)
                                                              │
                                              SOAR trigger (if configured)
```

### Critical vs. high findings — forced case opening

For **critical ASM findings** and **critical ITAM CVEs**, `_try_open_case()` is called directly from the bridge (same pattern as EDR high-confidence detections with `_edr_score ≥ 80`). This bypasses the `alert_count ≥ 3` threshold so a single critical finding opens a case without waiting for corroboration.

---

## 4. Rule ID Allocation

These are **synthetic rule IDs** — they exist only as integer labels in the cysiemstack correlation engine's `alerts` table. They are **never loaded into Wazuh**. No XML entry is needed. `cycentra-setup.sh` does not need to be updated.

The `normaliser.py` `_classify_category()` function recognises them by range and assigns the correct category.

| Rule ID | Source | Severity | Level | Category |
|---|---|---|---|---|
| 200100 | ASM critical finding | critical | 15 | asm |
| 200101 | ASM high finding | high | 12 | asm |
| 200102 | ASM medium finding | medium | 7 | asm |
| 200103 | ASM finding escalated by analyst | high | 10 | asm |
| 200200 | ITAM critical CVE (CVSS critical) | critical | 15 | vulnerability |
| 200201 | ITAM high CVE | high | 12 | vulnerability |
| 200202 | ITAM high-risk IoT device (risk ≥ 75) | high | 10 | asm |
| 200203 | ITAM shadow AI / rogue service | high | 9 | system |

### Why 200100+ and not 100400+

`cy_cust_rules.xml` already occupies:
- 100400–100402 → Lateral Movement rules (Pass-the-Hash, DCOM, Remote Service)
- 100500–100502 → Persistence rules (Startup Folder, Cron, LaunchAgent)
- 100100–101042 → full Wazuh/kernel rule range

The 200xxx range is unoccupied by any Wazuh rule definition and provides a clean namespace for all future synthetic sources.

### Existing synthetic ID ranges (for reference)

| Range | Owned by |
|---|---|
| 100210–100211 | YARA scan results (`_ingest_yara_scan_result`) |
| 100300–100399 | CyEDR behavioral detections (`confidence_matrix.py`) |
| 200100–200199 | ASM findings (this release) |
| 200200–200299 | ITAM anomalies (this release) |

---

## 5. Category Classification

`cysiemstack/correlation_engine/normaliser.py` `_classify_category()` updated:

```
rule_id in ASM_RULE_IDS (200100–200109)   → 'asm'
rule_id in ITAM_VULN_RULE_IDS (200200–200201) → 'vulnerability'
rule_id in ITAM_IOT_RULE_IDS (200202)     → 'asm'
rule_id in ITAM_AI_RULE_IDS (200203)      → 'system'
group 'asm' in alert groups               → 'asm'
group 'vulnerability' in alert groups     → 'vulnerability'
```

---

## 6. Case Type Inference

`_infer_case_type()` updated in **both** `blueprints/cases/service.py` and `cysiemstack/correlation_engine/ingestor.py` (they are separate copies — both must stay in sync):

| Category / tactic | Case type |
|---|---|
| contains `vulnerability` | `vulnerability` |
| contains `asm` | `asm_finding` |
| contains `shadow_ai` | `shadow_ai` |
| contains `itam` | `itam_anomaly` |
| contains `ransomware` | `ransomware` |
| contains `phishing` | `phishing` |
| contains `brute` | `brute_force` |
| contains `exfil` | `data_exfil` |
| contains `lateral` | `lateral_movement` |
| (default) | `generic` |

---

## 7. Deduplication Guards

| Source | Guard mechanism |
|---|---|
| ASM scan findings | `.siem_pushed` companion file per scan JSON — pushes once, never replays |
| ASM analyst escalation | Only fires on `in_review` status transition — analyst must explicitly escalate |
| ITAM shadow AI | `INSERT ... RETURNING id` — only pushes on new finding, not on duplicate ON CONFLICT DO NOTHING |
| ITAM IoT device | `RETURNING (xmax = 0) AS is_new_row` — only pushes on first discovery, not on rescan updates |
| ITAM deep scan CVEs | Per-CVE deduplication via `pushed_cves` set within the same scan invocation |

---

## 8. Files Changed

| File | Change |
|---|---|
| `portal/src/sidebar/navConfig.jsx` | Case Management moved to standalone CASE MANAGEMENT section at bottom of nav |
| `cysiemstack/edr_bridge.py` | Added `push_asm_finding()`, `push_asm_scan_findings()`, `push_itam_anomaly()`, `_build_asm_alert()`, and supporting constants |
| `cysiemstack/correlation_engine/normaliser.py` | Added `ASM_RULE_IDS`, `ITAM_VULN_RULE_IDS`, `ITAM_IOT_RULE_IDS`, `ITAM_AI_RULE_IDS`; updated `_classify_category()` |
| `cysiemstack/correlation_engine/ingestor.py` | Updated `_infer_case_type()` for asm/vulnerability/shadow_ai/itam case types |
| `blueprints/asm/scanner.py` | Added `_push_scan_to_siem_once()`, `_push_finding_escalation_to_siem()`; hooked into `GET /api/scans/latest` and `POST /api/asm/findings/<id>/status` |
| `blueprints/itam/routes.py` | Added `_push_deep_scan_cves_to_siem()`, `_push_shadow_ai_to_siem()`, `_push_iot_risk_to_siem()`; hooked into `_ingest_deep_scan_result()`, `ingest_shadow_ai()`, and IoT upsert loop |
| `blueprints/cases/service.py` | Updated `_infer_case_type()` for asm/vulnerability/shadow_ai/itam |

---

## 9. What Each Source Sees in Active Incidents

### ASM findings
- **Title:** `[ASM] <vulnerability name>` (e.g., `[ASM] Email spoofing risk: DMARC missing`)
- **Category:** `asm`
- **Agent:** the scanned domain (e.g., `example.com`)
- **Severity:** maps from ASM severity (critical/high/medium)
- **Case type when opened:** `asm_finding`

### ITAM CVE findings
- **Title:** `CVE-XXXX-XXXX (CRITICAL, CVSS 9.8) in openssl 1.1.1 on 192.168.1.50`
- **Category:** `vulnerability`
- **Agent:** asset hostname or IP
- **Severity:** critical or high per CVSS severity field
- **Case type when opened:** `vulnerability`

### ITAM high-risk IoT
- **Title:** `High-risk IoT device discovered: Hikvision [camera] at 192.168.1.200 — risk score 82/100, ports: 80,554,8080`
- **Category:** `asm`
- **Agent:** device IP
- **Severity:** high (rule level 10 → score 7.1)
- **Case type when opened:** `asm_finding`

### ITAM shadow AI
- **Title:** `Unauthorised AI tool detected on workstation-12: ollama (severity=high)`
- **Category:** `system`
- **Agent:** hostname where detected
- **Severity:** high (rule level 9 → score 7.0)
- **Case type when opened:** `shadow_ai`

---

## 10. Deployment

No schema migrations required. No `cycentra-setup.sh` changes needed.

```bash
# Backend (Flask + correlation engine)
systemctl restart cycentra-backend.service
systemctl restart cysiemstack-correlation   # if running as separate unit

# Frontend
cd /opt/cycentra/portal && npm run build
```

The first time `GET /api/scans/latest` is called after deployment, existing completed scans will push their high/critical findings to SIEM (once, guarded by the `.siem_pushed` marker file).

---

## 11. Known Limitations

| Limitation | Notes |
|---|---|
| ASM medium findings not pushed by default | `push_asm_scan_findings()` uses `min_severity="high"`. Change the call argument to `"medium"` to include medium findings — not recommended due to volume. |
| ITAM CVE push limited to top-20 per scan | Prevents Redis flooding on assets with hundreds of CVEs. The most critical (highest CVSS) are pushed first. |
| LLM narrative requires ≥3 alerts | A single one-off critical finding opens a case but may not have an LLM summary until the incident receives 2+ more correlated alerts. Critical findings get the forced-case path. |
| No retroactive push for ITAM IoT | Existing high-risk IoT devices already in the `iot_devices` table before this release will not be pushed. Only newly-discovered (first-time insert) devices trigger the hook. Run a rescan to emit alerts for existing high-risk devices. |
