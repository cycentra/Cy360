# M22 — Threat Intelligence Enrichment
**File:** `backend/cysiemstack/correlation_engine/ti_enricher.py`, `config.py`
**Run Date:** 2026-06-29

---

## Module Scope

Multi-source threat intelligence enrichment for SIEM incidents. Enriches IOCs (IPs, domains, SHA256 hashes) using MISP, VirusTotal v3, AbuseIPDB, and GreyNoise. Results stored in `incident.ti_reputation`.

**TI Sources:**
- **MISP** — Internal threat intel platform (confidence: +35 for hits)
- **VirusTotal v3** — `malicious ≥10%` → +25 pts; `combined ≥5%` → +10 pts suspicious
- **AbuseIPDB** — `score ≥50` → +20 pts
- **GreyNoise** — `malicious` → +20 pts; `benign` → -10 pts

**Key Resolution Chain (VT API key, never hand-edit env):**
1. Settings UI → `ai_settings.json` `threat_intel.vtApiKey`
2. `_sync_ti_to_siem_env()` auto-syncs to `cysiemstack.env`
3. Vault fallback via `ENGINE_KV_MAP["VIRUSTOTAL_API_KEY"]` → `"VIRUSTOTAL-API-KEY"`

---

## AI-Executable Tests (110 tests — 110/110 PASS in isolation)

### A1 — Config: API Key Fields

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `vt_api_key` field in Settings | ✅ PASS | |
| A1.02 | Default is empty string (no hardcode) | ✅ PASS | |
| A1.03 | `VIRUSTOTAL_API_KEY` env-var bridge | ✅ PASS | `_bridge_ti_keys()` validator |
| A1.04 | Bridge only fills when UI field empty | ✅ PASS | |
| A1.05 | `abuseipdb_api_key` present | ✅ PASS | |
| A1.06 | `greynoise_api_key` present | ✅ PASS | |

### A2 — VT Verdict Logic

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | Empty API key → {} (skipped) | ✅ PASS | |
| A2.02 | ≥10% malicious engines → 'malicious' | ✅ PASS | |
| A2.03 | 9% malicious, 0% suspicious → NOT malicious | ✅ PASS | |
| A2.04 | 3%+3% combined ≥5% → 'suspicious' | ✅ PASS | |
| A2.05 | 0%+0% → 'benign' | ✅ PASS | |
| A2.06 | `community_score` preserved | ✅ PASS | |
| A2.07 | `malicious` count in result | ✅ PASS | |
| A2.08 | `source='virustotal'` in result | ✅ PASS | |
| A2.09 | Total engine count in result | ✅ PASS | |

### A3 — HTTP Edge Cases

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | HTTP 404 → verdict='unknown' | ✅ PASS | IOC not yet analysed |
| A3.02 | HTTP 403 → {} | ✅ PASS | Invalid/quota key |
| A3.03 | HTTP 429 → {} | ✅ PASS | Rate limit graceful |
| A3.04 | Network exception → {} | ✅ PASS | Never raises |
| A3.05 | Unknown IOC type → {} | ✅ PASS | |
| A3.06 | Empty key → no HTTP client instantiated | ✅ PASS | |

### A4 — IOC URL Routing

| # | Test | Result | Detail |
|---|------|--------|--------|
| A4.01-A4.03 | ip-src/ip-dst/ip → `/api/v3/ip_addresses/{ioc}` | ✅ PASS | |
| A4.04 | domain → `/api/v3/domains/{ioc}` | ✅ PASS | |
| A4.05 | sha256 → `/api/v3/files/{ioc}` | ✅ PASS | |
| A4.06 | VT v3 base URL (not v2) | ✅ PASS | |

### A5 — Confidence Scoring

| # | Test | Result | Detail |
|---|------|--------|--------|
| A5.01 | VT malicious → +25 pts | ✅ PASS | |
| A5.02 | VT suspicious → +10 pts | ✅ PASS | |
| A5.03 | VT benign → +0 pts | ✅ PASS | |
| A5.04 | MISP(35) + VT malicious(25) = 60 → 'malicious' | ✅ PASS | |

### A6 — Key Resolution Chain

| # | Test | Result | Detail |
|---|------|--------|--------|
| A6.01 | `ENGINE_KV_MAP` has `VIRUSTOTAL_API_KEY` | ✅ PASS | |
| A6.02 | Vault name is `VIRUSTOTAL-API-KEY` | ✅ PASS | |
| A6.03 | ASM_KV_MAP also covers VT key | ✅ PASS | One vault entry, two consumers |
| A6.04 | `_sync_ti_to_siem_env()` exists | ✅ PASS | |
| A6.05-A6.10 | Sync path, masking, test endpoint | ✅ PASS | All 10 B7 tests pass |

---

## Manual Test Suite

### M-TI-01: MISP Integration
**Steps:**
1. Install CyMISP from Marketplace
2. Navigate to Settings → Threat Intelligence → MISP
3. Configure MISP URL and API key
4. Test connection — verify "Connected" status
5. Trigger a SIEM incident with a known malicious IP from MISP
6. Verify incident enriched with MISP hit details

### M-TI-02: VirusTotal Integration
**Steps:**
1. Navigate to Settings → AI & Integrations → Threat Intelligence
2. Enter VT API key in Threat Intel tab → Save
3. Verify key stored in `ai_settings.json` as `threat_intel.vtApiKey`
4. Trigger SIEM incident with a known malicious IP hash
5. Navigate to `Settings → TI → Test → VirusTotal`
6. Verify test returns correct verdict

### M-TI-03: AbuseIPDB Integration
**Steps:**
1. Configure AbuseIPDB API key in Threat Intelligence settings
2. Generate incident with high-abuse IP
3. Verify enrichment shows `abuseipdb_score ≥50` in incident detail

### M-TI-04: Enrichment in Incident Detail
**Steps:**
1. Open a SIEM incident with IOCs
2. Navigate to Threat Intelligence tab in incident detail
3. Verify: verdict, sources_used, ioc_hits, confidence, checked_at timestamp
4. Verify verdict color-coding: red=malicious, orange=suspicious, green=benign

### M-TI-05: Rate Limit Handling
**Steps:**
1. Set VT API key with low quota
2. Generate 100 incidents rapidly
3. Verify `429` responses handled gracefully (no crashes)
4. Verify `sources_used` for affected incidents does not include 'virustotal'
