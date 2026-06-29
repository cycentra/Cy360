# M04 — Attack Surface Management (ASM)
**Files:** `backend/cy_asm/`, `backend/blueprints/asm/scanner.py`
**Run Date:** 2026-06-29

---

## Module Scope

External scan engine that assesses the attack surface of a target domain. Orchestrated by `cycentra_scan.py`, dispatching to 13 scan modules across 3 profiles (passive, standard, deep). Generates posture score, executive PDF, and technical PDF reports.

**Scan Modules:**
- `dns_recon.py` — DNS records, zone transfer, dangling CNAME
- `subdomain_enum.py` — Subdomain discovery (wordlist + brute force)
- `email_security.py` — SPF, DKIM, DMARC validation
- `crypto_checks.py` — TLS versions, cipher suites, PQC readiness (0x6399, 0x11ec)
- `vuln_scanner.py` — CVE correlation via nuclei
- `web_analysis.py` — HTTP headers, CSP, CORS, HTTPS redirect
- `passive_osint.py` — Shodan/Censys passive data
- `dark_web.py` — Dark web breach mentions
- `social_eng.py` — Phishing/BEC surface
- `cloud_infra.py` — Cloud asset discovery
- `mobile_api.py` — Mobile API surface
- `supply_chain.py` — Third-party dependencies
- `whois_history.py` — Domain registration history

**Profiles:**
- `passive` — OSINT only, no active probing
- `standard` — DNS + email + crypto + web + WHOIS
- `deep` — All modules, active scanning

---

## AI-Executable Tests (Automated)

### A1 — Module Contract Tests

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | All modules never raise on valid domain | ✅ PASS | Safe on `example.com` |
| A1.02 | All modules never raise on invalid domain | ✅ PASS | Safe on `!!invalid-domain!!` |
| A1.03 | All modules return `{module, findings, error}` | ✅ PASS | Contract enforced |
| A1.04 | Every finding has `type, severity, asset, description, remediation` | ✅ PASS | Schema validated |
| A1.05 | Severity values only: critical/high/medium/low/info | ✅ PASS | Enum enforced |
| A1.06 | SCAN_PROFILES: passive/standard/deep exist | ✅ PASS | All 3 profiles defined |
| A1.07 | Deep profile is superset of standard | ✅ PASS | Module set inclusion verified |
| A1.08 | `crypto_checks.py` contains `0x6399` | ✅ PASS | ML-KEM PQC cipher ID present |
| A1.09 | `crypto_checks.py` contains `0x11ec` | ✅ PASS | X25519Kyber768 cipher ID present |
| A1.10 | Subdomain wordlist has no duplicates | ✅ PASS | Dedup check passed |

### A2 — ASM Blueprint

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `asm_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A2.02 | `/api/scan/status` schema | ✅ PASS | Returns `{running, progress, current_module, last_log}` |
| A2.03 | Scan trigger — valid domain → not 500 | ✅ PASS | Returns 200 or 202 |
| A2.04 | Scan trigger — empty domain → 400/422 | ✅ PASS | Input validation fires |
| A2.05 | Scan trigger — injection `;ls /etc` → 400/422 | ✅ PASS | Command injection blocked |

---

## Manual Test Suite

### M-ASM-01: Full Passive Scan
**Steps:**
1. Log in as analyst
2. Navigate to ASM → New Scan
3. Enter valid external domain; select "Passive" profile
4. Submit and monitor progress bar
5. Verify all passive modules complete; executive report PDF generated
6. Check findings for SPF/DKIM/DMARC issues, DNS records, WHOIS data

### M-ASM-02: Standard Scan with TLS Analysis
**Steps:**
1. Run standard scan on a known domain
2. Verify crypto_checks module runs
3. Confirm TLS version support (TLSv1.0/1.1 flagged as critical)
4. Confirm PQC readiness check present in report

### M-ASM-03: Deep Scan End-to-End
**Steps:**
1. Run deep scan on a staging/test domain
2. Verify all 13 modules complete
3. Verify posture score generated (0-100)
4. Verify executive PDF and technical PDF both downloadable
5. Check nuclei findings if CVEs detected

### M-ASM-04: Report Generation
**Steps:**
1. Trigger scan; wait for completion
2. Download executive report — verify PDF opens correctly
3. Download technical report — verify all finding tables populated
4. Verify charts (severity distribution, score trend) render

### M-ASM-05: Scan History
**Steps:**
1. Run 3 scans on same domain at different times
2. Navigate to Scan History
3. Verify all 3 entries appear with timestamps and posture scores
4. Verify clicking a history entry loads that scan's results

### M-ASM-06: Multi-tenant Isolation
**Steps:**
1. Log in as Tenant A; run scan on domain-a.com
2. Log in as Tenant B; verify domain-a.com scan NOT visible
3. Verify scan results are tenant-scoped
