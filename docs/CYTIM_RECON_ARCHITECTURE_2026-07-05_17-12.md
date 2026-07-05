# CyTIM Recon Consolidation — Architecture & Status
**Date:** 2026-07-05 17:12  
**Scope:** Full migration of all ASM external API calls to CyTIM as single source of truth

---

## 1. What Changed and Why

Before this change, ASM made direct outbound calls to 15 external APIs using keys spread across `cy_asm/config.py` and `core/kv_secrets.py`. This created:
- Duplicate key provisioning (VT key in both ASM and CyTIM)
- No caching — every scan hit the APIs fresh
- No central rate-limit control
- API failures silently degraded individual modules with no visibility

After this change, **CyTIM is the sole gateway for all external API calls from ASM**. ASM modules call CyTIM over the internal network; CyTIM manages all API keys, caching, rate limiting, and fallback logic.

---

## 2. Final API Architecture

### 2.1 CyTIM — All External Calls (complete list)

#### Threat Intelligence — `POST /api/cytim/bulk-enrich` (profile `asm`)
| Source | Purpose | Key location |
|--------|---------|-------------|
| Shodan | Port/service CVE matching | `cytim.env: SHODAN_API_KEY` |
| VirusTotal | IOC reputation (maliciousness score) | `cytim.env: VT_API_KEY` |
| AlienVault OTX | Threat attributes, pulse data | `cytim.env: ALIENVAULT_API_KEY` |
| MISP | On-prem threat intelligence attributes | `cytim.env: MISP_URL + MISP_API_KEY` |
| GreyNoise | IP noise classification | `cytim.env: GREYNOISE_API_KEY` |
| AbuseIPDB | IP abuse confidence score | `cytim.env: ABUSEIPDB_API_KEY` |
| CiscoTalos | IP/domain reputation | `cytim.env: TALOS_CLIENT_ID/SECRET` |

#### Dark Web — `POST /api/cytim/darkweb-enrich`
| Source | Purpose | Key location |
|--------|---------|-------------|
| HIBP | Data breach records | `cytim.env: HIBP_API_KEY` |
| Ahmia | Tor search index mentions | No key (public endpoint) |

#### Recon — `POST /api/cytim/recon` ← **NEW**
| Source | Module | Purpose | Key location |
|--------|--------|---------|-------------|
| VirusTotal | `subdomains` | `/api/v3/domains/{d}/subdomains` — subdomain discovery | `cytim.env: VT_API_KEY` (reused) |
| AlienVault OTX | `subdomains` | `/api/v1/indicators/domain/{d}/passive_dns` — passive DNS | No key (public endpoint) |
| SecurityTrails | `subdomains` | `/v1/domain/{d}/subdomains` — historical subdomains | `cytim.env: SECURITYTRAILS_API_KEY` |
| Hunter.io | `emails` | `/v2/domain-search` — exposed corporate emails | `cytim.env: HUNTER_API_KEY` |
| IPInfo | `geoip` | `/json/{ip}` — GeoIP + ASN lookup | `cytim.env: IPINFO_API_KEY` |
| ViewDNS | `whois_history` | `/reversewhois/?q={d}` — WHOIS history records | No key (public scrape) |
| NVD | `cve` | `/rest/json/cves/2.0` — CVE keyword search | `cytim.env: NVD_API_KEY` (optional) |
| EPSS (FIRST.org) | `cve` | `/data/v1/epss` — exploitation probability | No key (free) |

### 2.2 ASM Direct Calls — Irreducible (3 credentials only)

| Credential | File | Reason stays direct |
|-----------|------|-------------------|
| `SHODAN_API_KEY` | `cy_asm/config.py` | CyTIM-first fallback in `passive_osint.py` — activates only if CyTIM unreachable |
| `GOOGLE_GEMINI_KEY` | `cy_asm/config.py` | AI text generation for deep scan enrichment (CyMind → Gemini → Ollama cascade) |
| `GVM_PASSWORD` / `GVM_USER` | `cy_asm/config.py` | OpenVAS/Greenbone local scanner socket connection — not an external API |

---

## 3. New CyTIM Endpoint — `POST /api/cytim/recon`

### 3.1 Request Schema
```json
{
  "domain": "example.com",
  "modules": ["subdomains", "emails", "geoip", "whois_history", "cve"],

  "ips": ["1.2.3.4", "5.6.7.8"],       // optional — for geoip module; auto-resolved if absent
  "cve_keywords": ["apache 2.4", "nginx"],  // optional — for cve module NVD search
  "cve_ids": ["CVE-2024-1234"]          // optional — for cve module EPSS lookup
}
```

### 3.2 Response Schema
```json
{
  "domain": "example.com",
  "cached": false,
  "results": {
    "subdomains": ["mail.example.com", "api.example.com"],
    "emails": [
      {"email": "john@example.com", "first_name": "John", "last_name": "Doe",
       "position": "CEO", "confidence": 87, "source": "hunter.io"}
    ],
    "geoip": {
      "1.2.3.4": {"country": "US", "city": "San Francisco",
                  "org": "Cloudflare Inc", "asn": "AS13335", "hostname": "..."}
    },
    "whois_history": ["domain1.com", "domain2.com"],
    "cve": {
      "findings": [{"cve_id": "CVE-2024-1234", "cvss": 9.1,
                    "severity": "Critical", "description": "..."}],
      "epss": {"CVE-2024-1234": 0.023}
    }
  }
}
```

### 3.3 Module Behaviour When Key Is Missing
| Module | Behaviour |
|--------|-----------|
| `subdomains` | VT + SecurityTrails skipped; OTX (public) still runs |
| `emails` | Returns `[]` immediately |
| `geoip` | Returns `{}` immediately |
| `whois_history` | Runs (no key needed) |
| `cve` | NVD runs without `apiKey` header (lower rate limit); EPSS runs (free) |

---

## 4. New Files Created in CyTIM

```
CyTIM/cytim/
  recon/
    __init__.py           — package marker
    base.py               — ReconSource ABC: name, run(domain, **kwargs), health_check()
    registry.py           — _RECON_SOURCES dict; register_recon(), run_recon_module()
    subdomains.py         — SubdomainsSource: VT + OTX + SecurityTrails (concurrent threads)
    emails.py             — EmailsSource: Hunter.io /v2/domain-search
    geoip.py              — GeoIPSource: ipinfo.io per-IP (max 10, 5s timeout)
    whois_history.py      — WhoisHistorySource: ViewDNS HTML scrape
    cve.py                — CVESource: NVD keyword search + EPSS batch lookup
  api/
    recon.py              — recon_bp blueprint: POST /api/cytim/recon
```

### Modified in CyTIM
| File | Change |
|------|--------|
| `cytim/config.py` | Added `SECURITYTRAILS_API_KEY`, `HUNTER_API_KEY`, `IPINFO_API_KEY`, `NVD_API_KEY` |
| `cytim/app.py` | Registered `recon_bp`; registered all 5 ReconSource instances |

---

## 5. ASM Modules Changed

### 5.1 New helper — `core/helpers.py`
Added `cytim_recon(domain, modules, **kwargs) → dict`. Follows the same pattern as `cytim_bulk_enrich` and `cytim_darkweb_enrich` — POST to CyTIM, returns `{}` on any failure, never raises.

### 5.2 Per-module changes

| Module | What was removed | What replaced it |
|--------|-----------------|-----------------|
| `subdomain_enum.py` | `get_subdomains_virustotal()`, `get_subdomains_alienvault()`, `get_subdomains_securitytrails()` | `get_subdomains_cytim_recon()` — single CyTIM `subdomains` call |
| `social_eng.py` | `find_emails_hunter()` | `find_emails_cytim()` — CyTIM `emails` call |
| `dns_recon.py` | Per-IP loop calling `ipinfo.io` directly | Batch CyTIM `geoip` call with all IPs at once |
| `vuln_scanner.py` | `_fetch_nvd_cves()`, `_fetch_epss()` | `_fetch_cve_via_cytim()` — single CyTIM `cve` call with all banner keywords |
| `whois_history.py` | `get_domain_history()` ViewDNS direct scrape | CyTIM `whois_history` call inside same function |

### 5.3 Config and secrets cleanup

| File | Removed | Kept |
|------|---------|------|
| `cy_asm/config.py` | `IPINFO_API_KEY`, `SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY`, `NVD_API_KEY`, `HUNTER_API_KEY` | `SHODAN_API_KEY`, `GOOGLE_GEMINI_KEY`, `GVM_PASSWORD`, `GVM_USER` |
| `core/kv_secrets.py` ASM_KV_MAP | Same 5 keys | Same 4 remaining |

---

## 6. Fallback Behaviour

Every ASM module wraps the CyTIM recon call in `try/except` and falls back gracefully:
- `subdomain_enum.py` → empty list from `cytim_recon` → subdomain sources from crt.sh, MISP, brute-force, crawl still run
- `social_eng.py` → empty email list → LinkedIn dork still runs; risk score calculated on partial data
- `dns_recon.py` → IP entries created without geo enrichment; reverse DNS still present
- `vuln_scanner.py` → NVD/EPSS findings empty; SSL vuln checks, exposed paths, JS secrets still run
- `whois_history.py` → `history=[]`; local `python-whois` data (registrar, expiry) still returned

**CyTIM being down degrades enrichment quality but never breaks a scan.**

---

## 7. Provisioning — What Ops Needs to Do

Keys that were in Cy360's `.env` / Azure Key Vault and must move to CyTIM's `cytim.env`:

```bash
# Move from Cy360 .env → CyTIM cytim.env
SECURITYTRAILS_API_KEY=<value>
HUNTER_API_KEY=<value>
IPINFO_API_KEY=<value>
NVD_API_KEY=<value>          # optional; NVD works without it at lower rate limit

# VT_API_KEY already in CyTIM — no action needed (reused for recon module)
# ALIENVAULT_API_KEY already in CyTIM — OTX passive DNS uses public endpoint anyway

# Remove from Cy360 .env / Azure KV ASM secrets:
# VIRUSTOTAL_API_KEY, SECURITYTRAILS_API_KEY, HUNTER_API_KEY, IPINFO_API_KEY, NVD_API_KEY
```

---

## 8. Pros and Cons

### Pros
| Benefit | Detail |
|---------|--------|
| **Single key management point** | All external API keys provisioned in one place (`cytim.env`) |
| **Caching** | CyTIM DB-backed cache — repeated scans of same domain reuse results without hitting APIs |
| **Rate limit control** | CyTIM's `RATE_LIMIT_RPM` controls all outbound API quota centrally |
| **Audit trail** | All external API calls logged in CyTIM — visibility across ASM and SIEM consumers |
| **SIEM reuse** | GeoIP, WHOIS history, email discovery now available to SIEM enrichment via the same endpoint |
| **ASM simplicity** | ASM modules become thin consumers — no API key logic, no HTTP session management per module |
| **No duplicate VT key** | Single `VT_API_KEY` in CyTIM serves both IOC enrichment and subdomain discovery |

### Cons / Trade-offs
| Risk | Mitigation |
|------|-----------|
| **CyTIM availability dependency** | Every module falls back gracefully to empty results — scans complete, enrichment degrades |
| **Added network hop** | CyTIM is on the same internal network; adds ~10-50ms per call, negligible vs. scan duration |
| **CyTIM scope expansion** | CyTIM grows from "TI broker" to "external intelligence gateway" — purposeful but increases its responsibility |
| **crt.sh stays direct** | crt.sh is free, has no key, already has a 6h on-disk cache in ASM — routing through CyTIM adds a hop for no key-management benefit |
| **NVD without key** | NVD free tier allows keyless access at lower rate limits (~5 req/30s). With `NVD_API_KEY` this rises to 50 req/30s. |

---

## 9. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     ASM Scan Engine                         │
│                                                             │
│  subdomain_enum.py ──────────────────────────────────────┐  │
│  social_eng.py ─────────────────────────────────────────┐│  │
│  dns_recon.py ──────────────────────────────────────────┤│  │
│  vuln_scanner.py ───────────────────────────────────────┤│  │
│  whois_history.py ──────────────────────────────────────┤│  │
│  passive_osint.py ──────────────────────────────────────┤│  │
│  dark_web.py ───────────────────────────────────────────┤│  │
│                                                          ││  │
│  crt.sh (direct, cached 6h) ←── no key, free            ││  │
│  GVM/OpenVAS (direct socket)  ←── local scanner         ││  │
│  Google Gemini (direct) ←── AI generation                ││  │
└──────────────────────────────────────────────────────────┘│  │
                                                            ▼▼  │
                               ┌────────────────────────────────┐
                               │            CyTIM               │
                               │                                │
                               │  POST /api/cytim/bulk-enrich   │──→ Shodan, VT (IOC),
                               │    profile: "asm"              │    OTX (IOC), MISP,
                               │                                │    GreyNoise, AbuseIPDB,
                               │  POST /api/cytim/darkweb-enrich│──→ HIBP, Ahmia
                               │                                │
                               │  POST /api/cytim/recon  [NEW] ─┤──→ VT /subdomains
                               │    modules: subdomains         │    OTX /passive_dns
                               │             emails             │    SecurityTrails
                               │             geoip              │    Hunter.io
                               │             whois_history      │    IPInfo
                               │             cve                │    ViewDNS
                               │                                │    NVD + EPSS
                               └────────────────────────────────┘
```

---

## 10. Related Documents

| Document | Content |
|----------|---------|
| [CYTIM_CENTRALIZATION_2026-07-05.md](CYTIM_CENTRALIZATION_2026-07-05.md) | Earlier HIBP/Ahmia consolidation |
| [ASM_STATUS_REPORT_2026-07-05_17-12.md](ASM_STATUS_REPORT_2026-07-05_17-12.md) | Full ASM status before this change |
| `CyTIM/cytim/recon/` | New recon source implementations |
| `Cy360/backend/core/helpers.py` | `cytim_recon()` gateway function |
