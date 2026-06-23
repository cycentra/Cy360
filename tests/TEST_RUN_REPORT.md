# g-cyra-test — Latest Test Run Report

> This file is **overwritten** on every g-cyra-test trigger.
> For history of all runs see `tests/TEST_RUN_HISTORY.md`.
> For the full list of test items see `docs/TEST_INVENTORY.md`.

**Run Date:** 2026-06-23 09:45 UTC
**Trigger:** Manual — /g-cyra-test: Wazuh agent kernel package + VirusTotal feed validation (rev 2 — key resolution chain added)
**Branch / PR:** main (local) / working tree
**Commit:** working tree (new test file added)
**Files Changed:** 1 total (new test file only — no backend/frontend/infra changes)
**Suites Selected:** 13 (new — Wazuh Kernel Package & VirusTotal Feed Tests)
**Overall Result:** PASSED ✅

---

## Suite 01 — Smoke & Validation (BLOCKING)

SKIPPED — not selected (no backend/frontend/infra files changed)

**Suite 01 result: SKIPPED**

---

## Suite 02 — Unit Tests (BLOCKING)

SKIPPED — not selected

**Suite 02 result: SKIPPED**

---

## Suite 03 — API Contract Tests (BLOCKING)

SKIPPED — not selected

**Suite 03 result: SKIPPED**

---

## Suite 04 — OWASP Security (BLOCKING on A01/A03/A07)

SKIPPED — not selected

**Suite 04 result: SKIPPED**

---

## Suite 05 — Load & Performance (WARNING ONLY)

SKIPPED — not selected

**Suite 05 result: SKIPPED**

---

## Suite 06 — Correlation Accuracy (BLOCKING)

SKIPPED — not selected

**Suite 06 result: SKIPPED**

---

## Suite 07 — ASM Module Tests (BLOCKING)

SKIPPED — not selected

**Suite 07 result: SKIPPED**

---

## Suite 08 — Frontend Build (BLOCKING)

SKIPPED — not selected

**Suite 08 result: SKIPPED**

---

## Suite 09 — Infrastructure (BLOCKING)

SKIPPED — not selected

**Suite 09 result: SKIPPED**

---

## Suite 10 — End-to-End Integration (BLOCKING)

SKIPPED — not selected

**Suite 10 result: SKIPPED**

---

## Suite 11 — Resource Monitor E2E (BLOCKING)

SKIPPED — not selected

**Suite 11 result: SKIPPED**

---

## Suite 12 — AI Investigation Engine (BLOCKING)

SKIPPED — not selected (previously PASSED 132/132; see run 2026-06-22)

**Suite 12 result: SKIPPED**

---

## Suite 13 — Wazuh Agent Kernel Package & VirusTotal Feed (NEW — BLOCKING)

**Files under test:**
- `CYSIEM-Config/agent_config/agent.conf`
- `CYSIEM-Config/conf/ossec.conf`
- `backend/cysiemstack/correlation_engine/ti_enricher.py`
- `backend/cysiemstack/correlation_engine/config.py`

**Test file:** `tests/unit/test_wazuh_kernel_virustotal.py`

### Part A — Wazuh Agent Kernel Package Telemetry

#### A1 — macOS Apple Unified Logging System (ULS / apple-oslog)
- [x] 13-A1.01 Darwin agent_config block present in agent.conf
- [x] 13-A1.02 ULS localfile present (log_format=apple-oslog)
- [x] 13-A1.03 location value is 'apple-oslog'
- [x] 13-A1.04 log_format value is 'apple-oslog'
- [x] 13-A1.05 query targets com.apple.Authentication subsystem
- [x] 13-A1.06 query targets com.apple.securityd subsystem
- [x] 13-A1.07 query filters for 'error' type events
- [x] 13-A1.08 query filters for 'fault' type events
- [x] 13-A1.09 NOT using deprecated log_format=macos (Wazuh 4.4+ compat)
- [x] 13-A1.10 Darwin resource-check command uses /Library/Ossec path
- [x] 13-A1.11 Darwin resource-check alias=cy360-resource-check
- [x] 13-A1.12 Darwin resource-check frequency=300s
- [x] 13-A1.13 Darwin resource-check log_format=full_command
- [x] 13-A1.14 Darwin resource-check command starts with 'bash '
- [x] 13-A1.15 ULS query is non-trivial compound predicate (>20 chars)
- [x] 13-A1.16 ULS query uses 'subsystem' predicate keyword

**A1 result: 16/16 PASSED ✅**

#### A2 — Linux auditd / journald
- [x] 13-A2.01 Linux agent_config block present
- [x] 13-A2.02 journald localfile present (log_format=journald)
- [x] 13-A2.03 journald location value is 'journald'
- [x] 13-A2.04 PRIORITY filter set to 0,1,2,3,4 (emergency→warning only)
- [x] 13-A2.05 Linux resource-check command uses /var/ossec path
- [x] 13-A2.06 Linux resource-check alias=cy360-resource-check
- [x] 13-A2.07 Linux resource-check frequency=300s
- [x] 13-A2.08 Linux resource-check log_format=full_command
- [x] 13-A2.09 Linux resource-check command starts with 'bash '

**A2 result: 9/9 PASSED ✅**

#### A3 — Windows Sysmon / eventchannel
- [x] 13-A3.01 Windows agent_config block present
- [x] 13-A3.02 Security eventchannel localfile present
- [x] 13-A3.03 eventchannel location value is 'Security'
- [x] 13-A3.04 EventID suppression <query> block present
- [x] 13-A3.05 EventID 5156 (MPSSVC Allow connection) in suppression list
- [x] 13-A3.06 EventID 4658 (handle to object closed) in suppression list
- [x] 13-A3.07 Windows resource-check invokes PowerShell
- [x] 13-A3.08 Windows resource-check alias=cy360-resource-check
- [x] 13-A3.09 Windows resource-check log_format=full_command

**A3 result: 9/9 PASSED ✅**

#### A4 — Manager-side syscollector (kernel package inventory)
- [x] 13-A4.01 syscollector wodle present in ossec.conf
- [x] 13-A4.02 syscollector disabled=no
- [x] 13-A4.03 packages=yes (installed software inventory)
- [x] 13-A4.04 os=yes (OS version telemetry)
- [x] 13-A4.05 network=yes (network interface inventory)
- [x] 13-A4.06 processes=yes (running process list)
- [x] 13-A4.07 users=yes and groups=yes
- [x] 13-A4.08 hardware=yes
- [x] 13-A4.09 scan_on_start=yes

**A4 result: 9/9 PASSED ✅**

#### A5 — Vulnerability detection
- [x] 13-A5.01 vulnerability-detection block present
- [x] 13-A5.02 enabled=yes
- [x] 13-A5.03 index-status=yes
- [x] 13-A5.04 feed-update-interval set (60m)

**A5 result: 4/4 PASSED ✅**

#### A6 — FIM / syscheck
- [x] 13-A6.01 disabled=no
- [x] 13-A6.02 scan_on_start=yes
- [x] 13-A6.03 alert_new_files=yes
- [x] 13-A6.04 /usr/bin or /usr/sbin in monitored directories
- [x] 13-A6.05 /etc in monitored directories

**A6 result: 5/5 PASSED ✅**

#### A7 — Rootcheck (trojan/rootkit detection)
- [x] 13-A7.01 disabled=no
- [x] 13-A7.02 check_trojans=yes
- [x] 13-A7.03 check_sys=yes
- [x] 13-A7.04 check_pids=yes
- [x] 13-A7.05 check_files=yes

**A7 result: 5/5 PASSED ✅**

#### A8 — Active-response (isolation pipeline for kernel telemetry rules)
- [x] 13-A8.01 isolate-host command block present in ossec.conf
- [x] 13-A8.02 isolate-host executable=isolate-host.sh
- [x] 13-A8.03 AR block for rules_id=101000,101001 (local, 600s timeout)
- [x] 13-A8.04 AR block for rules_id=101002,101003 (all agents, 3600s timeout)
- [x] 13-A8.05 Local AR timeout=600s confirmed

**A8 result: 5/5 PASSED ✅**

---

### Part B — VirusTotal v3 Feed Integration

#### B1 — Config: vt_api_key field and env-var bridge
- [x] 13-B1.01 vt_api_key field present in config.py Settings class
- [x] 13-B1.02 vt_api_key default is empty string (no hardcoded value)
- [x] 13-B1.03 VIRUSTOTAL_API_KEY env-var bridge implemented
- [x] 13-B1.04 Bridge only fills field when UI has not set a value
- [x] 13-B1.05 abuseipdb_api_key present (corroborating TI source)
- [x] 13-B1.06 greynoise_api_key present (benign-scanner deduction)

**B1 result: 6/6 PASSED ✅**

#### B2 — Verdict logic (mocked HTTP)
- [x] 13-B2.01 Empty API key → {} (lookup skipped)
- [x] 13-B2.02 ≥10% malicious engines → verdict='malicious'
- [x] 13-B2.03 9% malicious + 0% suspicious → NOT 'malicious'
- [x] 13-B2.04 3%+3% combined ≥5% threshold → verdict='suspicious'
- [x] 13-B2.05 0%+0% → verdict='benign'
- [x] 13-B2.06 community_score (VT reputation) preserved in result
- [x] 13-B2.07 malicious and suspicious counts in result dict
- [x] 13-B2.08 source='virustotal' in result
- [x] 13-B2.09 total engine count in result

**B2 result: 9/9 PASSED ✅**

#### B3 — HTTP edge cases
- [x] 13-B3.01 HTTP 404 → verdict='unknown' (IOC not yet analysed by VT)
- [x] 13-B3.02 HTTP 403 → {} (API key invalid/quota exhausted)
- [x] 13-B3.03 HTTP 429 → {} (rate limit — graceful skip, no exception)
- [x] 13-B3.04 Network exception → {} never raises
- [x] 13-B3.05 Unknown IOC type → {} (no URL constructed)
- [x] 13-B3.06 Empty API key → httpx.AsyncClient never instantiated

**B3 result: 6/6 PASSED ✅**

#### B4 — IOC type URL routing
- [x] 13-B4.01 ip-src → /api/v3/ip_addresses/{ioc}
- [x] 13-B4.02 ip-dst → /api/v3/ip_addresses/{ioc}
- [x] 13-B4.03 ip → /api/v3/ip_addresses/{ioc}
- [x] 13-B4.04 domain → /api/v3/domains/{ioc}
- [x] 13-B4.05 sha256 → /api/v3/files/{ioc}
- [x] 13-B4.06 virustotal.com/api/v3 base URL used (v3 API, not v2)

**B4 result: 6/6 PASSED ✅**

#### B5 — Confidence scoring integration
- [x] 13-B5.01 VT malicious → +25 confidence points
- [x] 13-B5.02 VT suspicious → +10 confidence points
- [x] 13-B5.03 VT benign → +0 confidence points (no inflation)
- [x] 13-B5.04 MISP(35) + VT malicious(25) = 60 → verdict='malicious'
- [x] 13-B5.05 VT malicious alone > 0 (feeds positive value without MISP)

**B5 result: 5/5 PASSED ✅**

#### B6 — enrich_incident_ti() top-level integration (unchanged)
- [x] 13-B6.01 No keys configured → httpx never called
- [x] 13-B6.02 vt_api_key set → 'virustotal' in sources_used
- [x] 13-B6.03 vt_api_key empty → 'virustotal' NOT in sources_used
- [x] 13-B6.04 Result always has 'verdict' field
- [x] 13-B6.05 Result always has 'checked_at' ISO timestamp
- [x] 13-B6.06 Result written back to incident.ti_reputation

**B6 result: 6/6 PASSED ✅**

#### B7 — VT Key Resolution Chain (NEW — Settings UI → vault, never hand-edit env)
- [x] 13-B7.01 ENGINE_KV_MAP contains VIRUSTOTAL_API_KEY → vault secret name
- [x] 13-B7.02 Vault secret name is 'VIRUSTOTAL-API-KEY' (dash-separated convention)
- [x] 13-B7.03 ASM_KV_MAP also covers VIRUSTOTAL-API-KEY (one vault entry, two consumers)
- [x] 13-B7.04 _sync_ti_to_siem_env() function exists in system/routes.py
- [x] 13-B7.05 Sync reads 'vtApiKey' camelCase field from ai_settings.json threat_intel block
- [x] 13-B7.06 Sync writes VT_API_KEY= into cysiemstack.env (UI → engine bridge)
- [x] 13-B7.07 POST /api/ai/settings calls _sync_ti_to_siem_env() after every save
- [x] 13-B7.08 GET /api/ai/settings masks vtApiKey with ●●●●●●●● (key never returned)
- [x] 13-B7.09 VT key names in routes-level secret filter list (log-leak prevention)
- [x] 13-B7.10 POST /api/system/ti/test exists and handles source='virustotal'

**B7 result: 10/10 PASSED ✅**

---

## Summary Table

| Suite | Name | Ran | Result | Items | Passed | Failed |
|-------|------|-----|--------|-------|--------|--------|
| 01 | Smoke & Validation | NO | SKIPPED | 15 | — | — |
| 02 | Unit Tests | NO | SKIPPED | 584 | — | — |
| 03 | API Contract | NO | SKIPPED | 9 | — | — |
| 04 | OWASP Security | NO | SKIPPED | 18 | — | — |
| 05 | Performance | NO | SKIPPED | 5 | — | — |
| 06 | Correlation Accuracy | NO | SKIPPED | 17 | — | — |
| 07 | ASM Modules | NO | SKIPPED | 8 | — | — |
| 08 | Frontend Build | NO | SKIPPED | 10 | — | — |
| 09 | Infrastructure | NO | SKIPPED | 9 | — | — |
| 10 | E2E Integration | NO | SKIPPED | 10 | — | — |
| 11 | Resource Monitor E2E | NO | SKIPPED | 58 | — | — |
| 12 | AI Investigation Engine | NO | SKIPPED | 132 | — | — |
| **13** | **Wazuh Kernel + VirusTotal** | **YES** | **✅** | **110** | **110** | **0** |
| **TOTAL (this run)** | | | **✅** | **110** | **110** | **0** |

## Blocking Failures

- [NONE] — All 100 tests passed.

---

## Suite 13 — Analysis Notes & Operational Findings

### A. Kernel Package Monitoring — FULLY OPERATIONAL (configuration-level)

**macOS Apple ULS — CORRECT but FDA is a manual prerequisite:**
- Configuration uses `apple-oslog` (not deprecated `macos`) — correct for Wazuh 4.4+
- Subsystem filter covers `com.apple.Authentication` (sudo, PAM, Kerberos) and `com.apple.securityd` (keychain, SecAuthorize, security policy)
- Event-type filter for `error` and `fault` captures kernel-boundary security violations without flooding with informational events
- **⚠ Manual action required on each macOS endpoint:** Full Disk Access must be explicitly granted to `/Library/Ossec/bin/wazuh-agentd` in System Settings → Privacy & Security → Full Disk Access. Without FDA, macOS 14+ silently blocks ULS streaming to third-party readers. This cannot be automated and must be verified on-device.

**Linux journald — CORRECT:**
- Priority 0–4 filter correctly limits to Emergency, Alert, Critical, Error, Warning — captures all kernel security events while excluding noisy Notice/Info/Debug levels

**Windows Security eventchannel — CORRECT:**
- EventID suppression list (5156, 5157, 5447, 4658) is well-targeted — these are MPSSVC filtering-platform and handle-lifecycle events that generate 100k+ events/day on active hosts with no security detection value

**Manager syscollector — ALL 9 INVENTORY MODULES ENABLED:**
- `packages: yes` means Wazuh will enumerate all installed packages (including kernel extensions, kexts, System Extensions on macOS) every hour
- This data flows directly into `vulnerability-detection` for CVE correlation against the NVD/OVAL feeds

### B. VirusTotal Feed — IMPLEMENTED BUT INACTIVE (API key not configured)

**Verdict:** The VirusTotal v3 integration in `ti_enricher.py` is correctly implemented and will add real detection value once an API key is configured.

**Quantified TI value when activated:**
| Scenario | VT contribution | Combined score | Outcome |
|----------|----------------|----------------|---------|
| Malicious IP + MISP hit | +25 pts | 60 → 'malicious' | SOAR dispatch eligible at ≥90% confidence |
| Suspicious IP, no MISP | +10 pts | 10 → 'benign'* | Flags for analyst review |
| Malicious file hash | +25 pts | 25 → 'benign'* | Adds to IOC hit list |
| Malicious IP + AbuseIPDB≥50 + GN malicious | +25+20+20 | 65 → 'malicious' | Auto-closes at high confidence |

*Note: 'benign' verdict at 10–25 score does not mean the IOC is clean — it means the TI confidence is below the 30-point 'suspicious' threshold. The IOC hit still appears in `ioc_hits` for analyst review.

**Key resolution order (never write directly to cysiemstack.env):**

The VT API key follows a three-tier resolution chain — the correlation engine config.py `_bridge_ti_keys()` model validator reads in this priority order:

1. **Settings → Threat Intel tab (UI):**
   - Navigate to `Settings → AI & Integrations → Threat Intelligence`
   - Enter the VirusTotal API key in the VT field and Save
   - The portal `POST /api/ai/settings` writes it to `/opt/cycentra/ai_settings.json` as `threat_intel.vtApiKey`
   - `_sync_ti_to_siem_env()` in `system/routes.py` then auto-syncs it into `cysiemstack.env` as `VT_API_KEY=…`
   - The correlation engine picks it up on next restart/reload

2. **Cloud Vault (Infisical / Azure Key Vault):**
   - Secret name: `VIRUSTOTAL-API-KEY` (mapped in `ENGINE_KV_MAP` in `core/kv_secrets.py`)
   - Loaded at engine startup via `load_kv_secrets(ENGINE_KV_MAP)` before `Settings()` is instantiated
   - `_bridge_ti_keys()` then reads `os.environ["VIRUSTOTAL_API_KEY"]` as fallback when the UI field is empty

3. **env var only as last resort** — `VIRUSTOTAL_API_KEY` in process environment (vault-injected). Never set this manually in `cysiemstack.env`; use the UI or vault instead.

**Verify active key (on server):**
```bash
grep "virustotal" /opt/cycentra/logs/correlation.log | tail -5
# Expected: ti_enrichment_complete ... sources_used=['misp','virustotal',...]
```

**Rate limiting:** The integration caps at 5 IPs + 3 domains + 3 hashes per incident (11 max lookups). A free VT API key (4 requests/min public, ~500/day) supports ~45 incidents/day before hitting limits. Upgrade to VT Enterprise for production volumes.
