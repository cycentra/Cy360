# ASM Module — Full Status Report
**Generated:** 2026-07-05 17:12  
**Scope:** API architecture, dashboard coverage, PDF report coverage, AI enrichment, all changes made

---

## 1. External API Inventory — Full Picture (15 APIs)

### 1.1 Routed through CyTIM (9 APIs)

CyTIM is an on-prem threat intelligence broker. When ASM modules call these sources, they do so via `POST /api/cytim/bulk-enrich` (profile `"asm"`) or `POST /api/cytim/darkweb-enrich`. CyTIM holds its own keys — ASM has no keys for these.

| # | API | CyTIM Endpoint | What CyTIM calls it for |
|---|-----|---------------|------------------------|
| 1 | **Shodan** | `bulk-enrich` (`asm` profile) | Port/service fingerprinting, CVE matching on discovered IPs |
| 2 | **VirusTotal** | `bulk-enrich` (`asm` profile) | IOC reputation: `/api/v3/domains/{d}`, `/api/v3/ip_addresses/{ip}` — maliciousness score |
| 3 | **AlienVault OTX** | `bulk-enrich` (`asm` profile) | Threat attributes: pulse data, tags, malware families |
| 4 | **MISP** | `bulk-enrich` (`asm` profile) | On-prem threat intelligence attribute lookup |
| 5 | **GreyNoise** | `bulk-enrich` (`asm` profile) | IP classification (scanner vs. targeted attacker) |
| 6 | **AbuseIPDB** | `bulk-enrich` (`asm` profile) | IP abuse confidence score |
| 7 | **CiscoTalos** | `bulk-enrich` (`asm` profile) | IP/domain reputation |
| 8 | **HIBP** | `darkweb-enrich` | Data breach records for the scanned domain |
| 9 | **Ahmia** | `darkweb-enrich` | Tor search index mentions |

> **HIBP + Ahmia fix (this session):** These two were previously listed as direct ASM connections — `HIBP_API_KEY` was declared in `config.py:72` and `kv_secrets.py` even though `dark_web.py` already delegated entirely to CyTIM. The orphaned key declarations have been removed. CyTIM is now unambiguously the single source.

---

### 1.2 Direct ASM Calls — Two Categories

#### 1.2a Correct: Unique capabilities, no CyTIM equivalent (6 APIs)

These are called directly from ASM modules and **should stay direct** — CyTIM has no equivalent endpoint for these capabilities.

| # | API | File | Endpoint called | Why it stays direct |
|---|-----|------|----------------|-------------------|
| 1 | **SecurityTrails** | `subdomain_enum.py` | `/v1/domain/{d}/subdomains` | Subdomain enumeration/discovery — CyTIM has no subdomain recon capability |
| 2 | **crt.sh** | `subdomain_enum.py` | `crt.sh/?q=%.{d}&output=json` | Certificate transparency logs — free, no key, no CyTIM equivalent |
| 3 | **Hunter.io** | `social_eng.py` | `/v2/domain-search` | Corporate email discovery — CyTIM has no email discovery capability |
| 4 | **IPInfo** | `cloud_infra.py`, `passive_osint.py` | `/json/{ip}` | GeoIP + ASN lookup — CyTIM has no GeoIP capability |
| 5 | **NVD + EPSS** | `vuln_scanner.py` | `nvd.nist.gov/rest/json/cves`, `api.first.org/data/v1/epss` | CVE detail + exploitation probability — free, keyless, no CyTIM equivalent |
| 6 | **ViewDNS** | `whois_history.py` | `/api/whoishistory/` | WHOIS history records — CyTIM has no WHOIS history capability |

#### 1.2b Direct calls using the SAME vendor as CyTIM (2 APIs — intentional, different endpoints)

This is the nuance. **VirusTotal and AlienVault OTX are called both directly from ASM and via CyTIM** — but they hit completely different API endpoints for completely different purposes.

| API | Where | Endpoint | Purpose |
|-----|-------|----------|---------|
| **VirusTotal** | `subdomain_enum.py:37` (direct, uses `VIRUSTOTAL_API_KEY`) | `/api/v3/domains/{domain}/subdomains` | **Subdomain discovery** — returns a list of known subdomains for the target domain |
| **VirusTotal** | CyTIM `sources/virustotal.py` (uses CyTIM's own key) | `/api/v3/domains/{d}`, `/api/v3/ip_addresses/{ip}` | **IOC reputation** — maliciousness score, engine detections |
| **AlienVault OTX** | `subdomain_enum.py:50` (direct, **no key** — public endpoint) | `/api/v1/indicators/domain/{d}/passive_dns` | **Passive DNS / subdomain discovery** — historical DNS resolutions |
| **AlienVault OTX** | CyTIM `sources/` (uses CyTIM key/config) | Threat pulse endpoints | **Threat intelligence** — pulse data, malware tags |

**Implication:** `VIRUSTOTAL_API_KEY` must be provisioned for ASM even though CyTIM also has a VT key. They are separate keys serving separate purposes. OTX subdomain calls require no key (public endpoint).

**Should these be consolidated into CyTIM?** No — CyTIM's `bulk-enrich` is an IOC enrichment endpoint, not a subdomain discovery endpoint. Adding subdomain discovery would change CyTIM's scope and purpose. The direct calls are correct architecture.

---

### 1.3 API Key Inventory in `config.py`

Current state of `backend/cy_asm/config.py` (lines 65–73):

```python
IPINFO_API_KEY          = os.environ.get("IPINFO_API_KEY", "")
SECURITYTRAILS_API_KEY  = os.environ.get("SECURITYTRAILS_API_KEY", "")
VIRUSTOTAL_API_KEY      = os.environ.get("VIRUSTOTAL_API_KEY", "")   # subdomain discovery only
NVD_API_KEY             = os.environ.get("NVD_API_KEY", "")
SHODAN_API_KEY          = os.environ.get("SHODAN_API_KEY", "")       # CyTIM-first; this is the fallback
GOOGLE_GEMINI_KEY       = os.environ.get("GOOGLE_GEMINI_KEY", "")    # AI enrichment cascade
HUNTER_API_KEY          = os.environ.get("HUNTER_API_KEY", "")
GVM_PASSWORD            = os.environ.get("GVM_PASSWORD", "")
GVM_USER                = os.environ.get("GVM_USER", "")
```

`HIBP_API_KEY` — **removed** (was at line 72 before this session).

**Shodan note:** `SHODAN_API_KEY` is still declared in ASM config because `passive_osint.py` has a direct-call fallback for when CyTIM is not configured. This is correct — CyTIM-first with graceful degradation.

---

## 2. Scan Profiles

| Profile | Duration | Modules Active | AI Enrichment |
|---------|----------|---------------|---------------|
| `passive` | ~20s | DNS, Email Security, WHOIS, OSINT (MISP+Shodan via CyTIM), Dark Web (CyTIM) | No |
| `standard` | ~45s | + Subdomains, Web Analysis, SSL/Crypto, Cloud Infrastructure | No |
| `deep` | ~90s | Everything above + Supply Chain, Social Engineering, Mobile/API, Nuclei, Vuln Scanner | Yes — mandatory |

Deep is always a strict superset of standard. AI enrichment cascade: **CyMind → Google Gemini → Ollama** (first available wins).

---

## 3. AI Enrichment — Context Payload

`enrich_findings_with_ai()` in `cycentra_scan.py:689` builds the context sent to the AI model. Current state after this session:

| Context key | Source path | Scan profiles | Added this session? |
|-------------|------------|---------------|-------------------|
| `dns` | `dns.results.records` | Standard + Deep | No |
| `email` | `email_sec.results` | Standard + Deep | No |
| `web` | `web.results.{http_analysis, fingerprints, ssl}` | Standard + Deep | No |
| `cloud` | `cloud.results` | Standard + Deep | No |
| `supply_chain` | `supply_chain.results` (trimmed to 10 items for standard) | Standard + Deep | No |
| `crypto` | `crypto.results` | Standard + Deep | No |
| `dark_web` | `dark_web.results` | Standard + Deep | No |
| `osint` | `osint.results` (MISP attributes + Shodan CVE findings) | Standard + Deep | **Yes** |
| `whois` | `whois.results` | Standard + Deep | **Yes** |
| `social_eng` | `social_eng.results` | Deep only | No |
| `mobile_api` | `mobile_api.results` | Deep only | No |

**What changed:** OSINT (MISP + Shodan CVE data) and WHOIS (registrar, expiry) were being collected by the scan engine but were never passed to the AI for analysis. Now they are included for both standard and deep prompts.

---

## 4. External Attack Posture Dashboard

File: `portal/src/pages/dashboard/DashboardPage.jsx`  
All 8 gaps identified in the audit have been addressed.

### Widget 3 — Infrastructure & Cloud
| Addition | Data source (via adapter.js) | Condition |
|----------|------------------------------|-----------|
| DNS Takeover risk banner (red, lists dangling CNAMEs) | `primaryAsset.dns_takeovers` → `raw_results.dns.results.takeovers` | Shows if `dnsTakeovers.length > 0` |
| WHOIS domain expiry countdown | `primaryAsset.whois_full.expiration_date` → `raw_results.whois.results.whois` | Color: red=expired, orange=<30d, yellow=<90d |
| IP Geo / ASN table (up to 4 IPs) | `primaryAsset.dns_ips` → `raw_results.dns.results.ips` | Shows if IPs present |

Widget badge shows `"N TAKEOVER RISK"` in red when takeovers detected.

### Widget 5 — Web Security
| Addition | Data source | Condition |
|----------|------------|-----------|
| HTTP security headers checklist | `primaryAsset.http_analysis.http_headers` → `raw_results.web.results.http_analysis` | Always shown; ✓/✗ per header |
| EPSS exploitation probability badge | `v.epss` on each vulnerability (enriched by adapter) | Shows if `v.epss != null` |

### Widget 6 — Attack Surface Inventory
| Addition | Data source | Notes |
|----------|------------|-------|
| Unregistered Typosquats count | `primaryAsset.dns_unregistered` → `raw_results.dns.results.typos.unregistered` | Yellow color |
| DNS Takeover Risks count | `dnsTakeovers.length` | Red if > 0 |

### Widget 8 — Brand & External Exposure
| Addition | Data source | Notes |
|----------|------------|-------|
| Stat row: Shodan Exposed Services | `osint.shodan.length` | Orange if > 0 |
| Stat row: Mobile App Links | `mobileApi.app_links.android + ios` | Shows count |
| Shodan services detail block | `shodanServices` (top 4) | ip:port + product |
| Mobile/App exposure block | `mobileApi.api_findings`, `mobileApi.deeplinks` | Shows top 2 findings + deep link count |

### Bottom Critical/High Vulnerability Table
| Addition | Notes |
|----------|-------|
| EPSS badge alongside CVSS | Purple, format: `EPSS {x.x}%`. Shows on every vuln row where `v.epss` is present |

---

## 5. Technical PDF Report

File: `backend/cy_asm/reporting/technical_report.py`

### 5.1 New Sections Added

#### `_whois_section()` (new)
- Registrar, registrant org, creation/updated/expiry dates, DNSSEC status, name servers — in a table
- Expiry alert: **CRITICAL** (red heading) if <30 days, **Warning** if <30–90 days
- WHOIS history records (up to 5 past ownership changes)
- Graceful: shows "WHOIS data not available" if no data

#### `_social_eng_section()` (new)
- Social engineering risk level summary
- Exposed corporate email table: email, name, position, confidence% (up to 30 addresses)
- Context note explaining phishing/credential-stuffing risk
- LinkedIn presence breakdown
- Phishing domain list (up to 10)
- Data source: Hunter.io via `social_eng.results`

#### `_mobile_api_section()` (new)
- Android and iOS app store links discovered
- Deep links / Universal links table with risk note (auth bypass risk)
- API endpoint table: HTTP method, endpoint path, status code, description (up to 20 endpoints)
- Data source: `mobile_api.results`

#### `_dns_section()` (enhanced, was already present)
- **Added:** Unregistered typosquats list (up to 20) with brand-hijacking risk note
- **Added:** DNS takeover table (subdomain, provider, dangling CNAME) with attacker-registration risk explanation
- Existing: DNS records table, registered typosquats list — unchanged

### 5.2 Section Sequence (full)

```
1.  Scan Metadata & Summary Statistics
2.  All Findings (sorted by severity)
3.  Module Breakdown
4.  Subdomain Enumeration
5.  DNS Records & Typosquatting          ← enhanced with takeovers + unregistered typosquats
6.  SSL/TLS Certificate Analysis
7.  Email Security (SPF/DKIM/DMARC)
8.  Cloud Infrastructure
9.  Web Security
10. Supply Chain Risk
11. Dark Web & Breach Intelligence
12. Passive OSINT & Threat Intelligence
13. WHOIS & Domain Registration          ← NEW
14. Social Engineering & Email Exposure  ← NEW
15. Mobile Application & API Exposure    ← NEW
```

---

## 6. Data Flow Summary

```
Scan Engine (cycentra_scan.py)
  └── Calls modules (dns, ssl, web, cloud, osint, dark_web, social_eng, mobile_api, ...)
        ├── OSINT module → CyTIM bulk-enrich → Shodan, VT (IOC), OTX (threat), MISP, GreyNoise ...
        ├── Dark Web module → CyTIM darkweb-enrich → HIBP, Ahmia
        ├── Subdomain module → SecurityTrails (direct), crt.sh (direct),
        │                       VT /subdomains (direct — discovery, not IOC),
        │                       OTX /passive_dns (direct — discovery, no key)
        ├── Social Eng module → Hunter.io (direct)
        ├── Cloud/OSINT → IPInfo (direct)
        └── Vuln Scanner → NVD + EPSS (direct, free)
  └── Stores portal JSON (assets[].raw_results)
  └── Deep scan → enrich_findings_with_ai()
        └── Context: dns, email, web, cloud, supply_chain, crypto, dark_web,
                     osint (NEW), whois (NEW), social_eng (deep only), mobile_api (deep only)
        └── AI cascade: CyMind → Gemini → Ollama

Portal JSON → adapter.js → DashboardPage.jsx (8 widgets)
           → technical_report.py (15 sections)
           → executive_report.py (unchanged)
```

---

## 7. Files Modified in This Session

| File | Change |
|------|--------|
| `backend/cy_asm/config.py` | Removed `HIBP_API_KEY` (orphaned declaration) |
| `backend/core/kv_secrets.py` | Removed `"HIBP_API_KEY": "HIBP-API-KEY"` from `ASM_KV_MAP` |
| `portal/src/pages/dashboard/DashboardPage.jsx` | Added `getMobileApiData` import; 8 new computed vars; Widget 3/5/6/8 additions; bottom vuln table EPSS |
| `backend/cy_asm/reporting/technical_report.py` | New `_whois_section()`, `_social_eng_section()`, `_mobile_api_section()`; enhanced `_dns_section()`; all wired into `generate_technical_report()` |
| `backend/cy_asm/cycentra_scan.py` | Added `osint` and `whois` to AI enrichment context payload |
| `.claude/commands/g-cyra-asm.md` | Updated with API consolidation decisions, dashboard coverage, PDF coverage, AI enrichment status |

---

## 8. Open Items / Not Changed

| Item | Status | Notes |
|------|--------|-------|
| `executive_report.py` | Unchanged — complete | No gaps identified |
| `adapter.js` | Unchanged — all data paths were already correct | We only started calling functions that existed |
| `passive_osint.py` Shodan fallback | Unchanged — correct architecture | CyTIM-first with direct fallback when CyTIM not configured |
| VT/OTX subdomain calls in `subdomain_enum.py` | Unchanged — intentional direct calls | Different VT endpoint (`/subdomains`) from CyTIM's IOC enrichment (`/domains/{d}`); `VIRUSTOTAL_API_KEY` in ASM config is legitimately needed |
| All module `run_*_check()` functions | Unchanged — no scan logic modified | Only reporting, dashboard, and AI context changed |
