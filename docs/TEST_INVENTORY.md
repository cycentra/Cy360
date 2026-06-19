# CyCentra 360 — Test Inventory

> **Purpose:** Master reference of every test item the g-cyra-test agent can run.
> This document is static. For live pass/fail results see `tests/TEST_RUN_REPORT.md`
> and the full history in `tests/TEST_RUN_HISTORY.md`.

---

## Summary

| Suite | Name | Type | Items | Blocking |
|-------|------|------|-------|----------|
| 01 | Smoke & Validation | Static analysis | 8 | YES |
| 02 | Unit Tests | pytest (576) + structural | 600+ | YES |
| 03 | API Contract | HTTP assertions | 9 | YES |
| 04 | OWASP Security | Security scan | 9 | YES (A01/A03/A07) |
| 05 | Load & Performance | Concurrency | 5 | WARNING only |
| 06 | Correlation Accuracy | Rule logic | 12 | YES |
| 07 | ASM Module Tests | Module contract | 7 | YES |
| 08 | Frontend Build | Build pipeline | 10 | YES |
| 09 | Infrastructure | Shell/CI/release | 8 | YES |
| 10 | End-to-End Integration | Auth lifecycle | 9 | YES |

**Total tracked test items: 677+** (576 pytest + 101 suite checks)

---

## Suite 01 — Smoke & Validation

File: `tests/01-smoke-validation.sh` | Always runs on every trigger.

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 1.01 | Python AST syntax | `python -m py_compile` exits 0 on all modified `.py` files |
| 1.02 | Blueprint imports — auth_bp | `from blueprints.auth.oauth import auth_bp` succeeds |
| 1.03 | Blueprint imports — oidc_bp | `from blueprints.oidc.provider import oidc_bp` succeeds |
| 1.04 | Blueprint imports — rbac_bp | `from blueprints.rbac.manager import rbac_bp` succeeds |
| 1.05 | Blueprint imports — platform_bp | `from blueprints.platform.routes import platform_bp` succeeds |
| 1.06 | Blueprint imports — asm_bp | `from blueprints.asm.scanner import asm_bp` succeeds |
| 1.07 | Blueprint imports — system_bp | `from blueprints.system.routes import system_bp` succeeds |
| 1.08 | Blueprint imports — siem_bp | `from siem_proxy import siem_bp` succeeds |
| 1.09 | No circular import guard | `from app import` absent from `siem_proxy.py` |
| 1.10 | Flask /health endpoint | Returns `{"status":"ok","version":"*","service":"cycentra360-backend"}` |
| 1.11 | Frontend build | `npm run build` exits 0, no circular import warnings |
| 1.12 | App.jsx size guard | `portal/src/App.jsx` ≤ 120 lines |
| 1.13 | app.py size guard | `backend/app.py` ≤ 70 lines |
| 1.14 | Installer safety flag | `cycentra-setup.sh` contains `set -euo pipefail` |
| 1.15 | Installer bare-clear guard | No bare `clear` — must be `[[ -t 1 ]] && clear` |

---

## Suite 02 — Unit Tests

File: `tests/02-unit-tests.sh` | Runs on any Python change.

### 02-A: Correlation Rules — `tests/unit/test_correlation_rules.py` (438 tests)

#### Registry Integrity (8 tests)
| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 2.01 | Rule count | `len(ALL_RULES) >= 55` |
| 2.02 | All IDs start with CR- | No rule_id without `CR-` prefix |
| 2.03 | Unique IDs | No duplicates in ALL_RULES |
| 2.04 | Sequential IDs | IDs are CR-001 through CR-055 with no gaps |
| 2.05 | Valid severity values | All severities in {low, medium, high, critical} |
| 2.06 | Non-empty tactics | No rule has empty tactics list |
| 2.07 | Name and description present | Every rule has non-empty name and description |
| 2.08 | Positive window | Every rule has window > 0 seconds |

#### Safety — every rule, parametrized (3 × 55 = 165 tests)
| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 2.09 | Empty list → None | `rule.match([])` is `None` for all 55 rules |
| 2.10 | Null-field alert → no raise | `rule.match([null_alert])` returns None or dict, never raises |
| 2.11 | Return type contract | When not None, result has `key_alert_ids`, `detail`, `confidence` |

#### Individual Rule Logic (4–6 tests per rule × 55 rules = ~265 tests)

| Rule | Tests Included |
|------|---------------|
| CR-001 SSH Brute Force | Threshold=5 fires; 4→None; no-success→None; rule_5711 counts; confidence scales; exact 5 fires at 0.25 |
| CR-002 Login→PrivEsc | Same agent, privesc after login→fires; different agent→None; privesc before login→None; no username→None; only login→None |
| CR-003 Full Compromise Chain | All 3 components same host→fires; missing impact→None; different hosts→None; malware=impact; fires with 3 key_alert_ids |
| CR-004 Web→FIM | FIM after web attack→fires; FIM before web→None; no exploit keyword→None; traversal triggers |
| CR-005 Lateral Movement | 3+ hosts same src_ip→fires; 2 hosts→None; no src_ip→None; 5 hosts=confidence 1.0 |
| CR-006 Host Takeover | rootkit(510-535)+FIM→fires; rid 509→None; only rootkit→None |
| CR-007 Account Creation→Login | create+login same username in order→fires; reversed→None; different usernames→None; no username→None |
| CR-008 Scan→Exploit | scan+exploit keyword→fires; only scan→None; exploit without scan→None |
| CR-009 Data Exfiltration | FIM then net→fires; net before FIM→None; only FIM→None |
| CR-010 Service Account | 2+ svc_ logins→fires; 1→None; regular user→None |
| CR-011 Event Log Cleared | rule_id 18101→fires; 60101→fires; confidence==0.95; unrelated→None |
| CR-012 DNS Tunnelling | 20+ dns same host→fires; 19→None; spread 20 hosts→None |
| CR-013 Credential Dumping | lsass+login→fires; mimikatz triggers; dump without login→None |
| CR-014 Ransomware | 30 FIM+net→fires; .encrypted ext+net→fires; FIM only→None; confidence==0.85 |
| CR-015 C2 Beacon | 6 regular-interval outbound→fires; <5→None; high-variance→None |
| CR-016 Password Spraying | 20 unique usernames same src→fires; 19→None; no src_ip→None |
| CR-017 Windows Brute Force | 5×60122+60106→fires; 4→None; no success→None |
| CR-018 Dormant Account | first login+ext IP→fires; off-hours+no prior→fires; business hours+no prior fail→None |
| CR-019 Domain Admin | rule_id 60148→fires; keyword→fires; unrelated→None |
| CR-020 Golden Ticket | kerb rule_id→fires; kerberoast keyword→fires; RC4 encryption→fires |
| CR-021 Registry Persistence | FIM on Run key→fires; RunOnce→fires; Run keyword in desc→fires; non-registry FIM→None |
| CR-022 Scheduled Task | 60280+suspicious path→fires; AppData path→fires; system32 path→None |
| CR-023 Process Injection | chrome+cmd→fires; winword+powershell→fires; notepad→None |
| CR-024 Encoded Command | -EncodedCommand→fires; iex invoke→fires; FromBase64String→fires; Get-ChildItem→None |
| CR-025 Web Shell | w3wp+cmd→fires; apache+bash→fires; web shell keyword→fires; normal GET→None |
| CR-026 Security Tool Disabled | windefend+service stopped→fires; crowdstrike+disabled→fires; real-time protection disabled→fires; print spooler→None; "Windows Defender service stopped" (no 'windefend')→None |
| CR-027 Unusual Outbound Port | :4444→fires; :6667→fires; :443→None |
| CR-028 RDP to Internet | outbound :3389→fires; rdp egress→fires; rdp login accepted→None |
| CR-029 Internal Subnet Scan | 20 scan same host→fires; ping sweep×20→fires; 19→None |
| CR-030 Large Cloud Upload | 3× mega.nz same host→fires; dropbox×3→fires; 2→None |
| CR-031 Cloud Login No MFA | mfaUsed: No→fires; without MFA→fires; mfaUsed: Yes→None |
| CR-032 Cloud IAM Privilege | AdministratorAccess→fires; Global Admin→fires; AttachUserPolicy AmazonS3ReadOnly→FIRES (any AttachUserPolicy triggers); ListObjects→None |
| CR-033 Mass Cloud Deletion | 5× DeleteBucket→fires; 4→None; Azure delete×5→fires |
| CR-034 Mail Forwarding | ForwardTo→fires; mail forward rule→fires; normal email→None |
| CR-035 OAuth Consent | Mail.Read→fires; Files.ReadWrite→fires; token issued→None |
| CR-036 WMI Execution | wmic →fires; wmiprvse→fires; invoke-wmimethod in raw_log→fires; normal→None |
| CR-037 Pass The Hash | pass-the-hash→fires; ntlmrelayx→fires; lsass+NTLM logon→fires; plain logon→None |
| CR-038 MFA Push Bombing | 10 prompts same user→fires; 9→None; different users→None |
| CR-039 Session Cookie Theft | cookie theft→fires; pass-the-cookie→fires; 3 IPs same user→fires; 2 IPs→None |
| CR-040 Cryptomining | xmrig→fires; stratum+tcp→fires; 3× mining port→fires; normal→None |
| CR-041 Shadow Copy Deletion | vssadmin delete shadows→fires; wmic shadowcopy delete→fires; bcdedit recoveryenabled→fires; confidence==0.97; VSS backup start→None |
| CR-042 LOLBAS Download | certutil -urlcache→fires; bitsadmin /transfer→fires; mshta http→fires; certutil -verify→None |
| CR-043 DGA | dga keyword→fires; high entropy domain→fires; google.com→None |
| CR-044 Automated Collection | find / -name→fires; 30 FIM same host→fires; 29 FIM→None |
| CR-045 Archive Collected Data | 7z +/etc/→fires; tar+/home/→fires; 7z /opt/app→None |
| CR-046 Phishing Attachment | macro enabled→fires; VBA macro→fires; winword spawned→fires; Word saved→None |
| CR-047 Startup Folder | FIM on Windows\Startup→fires; /etc/init.d→fires; documents/→None |
| CR-048 Cron Persistence | /etc/crontab→fires; crontab -e in raw_log→fires; .timer unit→fires; new cron keyword→fires; cron daemon started→None |
| CR-049 Access Token Manipulation | JuicyPotato→fires; SweetPotato→fires; SeImpersonatePrivilege→fires; runas→None |
| CR-050 Remote Service Creation | psexec \\→fires; sc \\ in raw_log→fires; sc create (any)→FIRES; sc create local→FIRES; service running normally→None |
| CR-051 DLL Hijacking | dll hijack→fires; dll side-load→fires; DLL loaded kernel32→None |
| CR-052 HTTPS Long-Poll C2 | Cobalt Strike→fires; Havoc C2→fires; Metasploit→fires; api.github.com→None |
| CR-053 Credentials in Files | grep -r password→fires; cat /etc/shadow→fires; reg query SAM→fires; grep import→None |
| CR-054 SMB Enumeration | net view→fires; SharpHound→fires; crackmapexec smb→fires; net user→FIRES (net use substring); smtp connection→None |
| CR-055 DCSync | dcsync→fires; mimikatz lsadump::dcsync→fires; secretsdump DC→fires; confidence==0.95; AD replication success→None |

### 02-B: UEBA Detectors — `tests/unit/test_ueba_detectors.py` (89 tests)

| # | Detector | Test Items |
|---|----------|-----------|
| RISK-01 | RISK_CONTRIBUTIONS completeness | All 17 types present; scores 1-100; impossible_travel≥50; svc_account≥50 |
| RISK-02 | AUTH_SUCCESS_IDS / AUTH_FAIL_IDS / PRIVESC_IDS | Non-empty; min sizes enforced |
| D-01 | off_hours_login | 3am fires with established baseline; midnight fires; 10am→None; <5 baseline hours→None; auth fail→None; 3am already typical→None |
| D-02 | high_auth_fail_rate | High fail rate (9/10) fires; <5 failures→None; success event→None; 0% baseline uses 15% floor |
| D-03 | new_agent_access | Unknown host fires; known host→None; empty typical_agents→None; auth fail→None |
| D-04 | multi_host_burst | 4 hosts in 10min fires; 3 hosts→None; hosts >10min old→None |
| D-05 | svc_account_interactive | svc_ prefix fires; daemon_ fires; _admin suffix fires; regular user→None; serviceaccount_ fires |
| D-06 | privilege_escalation | Service account+privesc→fires; off-hours+privesc→fires; preceded by fail+privesc→fires; regular user+biz hours+no fail→None; non-privesc rule→None |
| D-07 | impossible_travel | Different agents within 2min fires; >2min→None; same agent→None; auth fail→None |
| D-08 | dormant_account_login | 91-day gap fires; 30-day→None; never active (avg=0)→None; threshold=90 days |
| D-09 | concurrent_session | Different agents within 30s fires; >30s→None; same agent→None |
| D-10 | activity_volume_spike | 21 events with baseline=24/day (21× hourly)→fires; high baseline (2400/day)→None; baseline=0→None; FIM category also triggers |
| D-11 | suspicious_process | mimikatz+malware→fires; meterpreter→fires; cobalt→fires; rubeus→fires; svchost.exe→None; non-malware category→None; no process→None |
| D-12 | repeated_privesc_attempt | 3 recent privesc+auth fail→fires; 2→None; success event→None |
| D-13 | mfa_fatigue | 8 prompts same user→fires; Duo push→fires; 7→None; different users→None |
| D-14 | data_staging | 7z+10 recent FIM→fires; tar+FIM→fires; archive only no FIM→None; FIM only→None; archive in raw_log fires |
| D-15 | wmi_execution | wmic →fires; wmiprvse→fires; invoke-wmimethod in raw_log→fires; normal→None |
| D-16 | token_theft | cookie theft keyword→fires; pass-the-cookie→fires; 5 IPs same user→fires; 4 IPs→None (VPN threshold); other user IPs→None |
| D-17 | crypto_miner | xmrig→fires; stratum+tcp→fires; nicehash in raw_log→fires; normal→None |
| HOST-01 | host multi_host_burst | 4 peer agents in 10min→fires; 3→None |
| HOST-02 | host impossible_travel | IP change within 2min→fires; same IP→None; no src_ip→None |
| HOST-03 | host c2_beaconing | 5 regular-interval outbound (CV<0.25)→fires; high variance→None; <5→None |
| ROUTE-01 | No-username path | username=None → returns [] (not error) |
| ROUTE-02 | entity_type='host' routing | _analyse_host_alert called (not user path) |

### 02-C: Agent Installer — `tests/unit/test_agent_installer.py` (49 tests)

| # | Category | Test Items |
|---|----------|-----------|
| INS-01 | Shell safety | `set -euo pipefail` present; no bare `clear`; 3 format placeholders present |
| INS-02 | Template rendering | Renders without error; no unresolved Python placeholders after format; server_url/manager/version resolved |
| INS-03 | Special chars | URL with port number renders correctly |
| INS-04 | _register_agent() | Function exists; output captured before RC check; 'Duplicate agent' detected; upgrade path uses ok() not err(); no `${CTRL_BIN} restart` inside function body; port 1515 mentioned in error; err() called for non-duplicate failures |
| INS-05 | macOS FDA notice | 'Full Disk Access' present; wazuh-agentd listed; wazuh-logcollector listed; wazuh-control restart instruction present; both in Darwin section; 'will not start' warning present |
| INS-06 | Audit key branding | cy360_agent_tamper present; wazuh_tamper absent; cy360_exec present; cy360_privesc present |
| INS-07 | Linux restart | cy360-agent tried first; cy360-agent before wazuh-agent in restart chain |
| INS-08 | Darwin single restart | Restart follows MACEOF heredoc; exactly 1 CTRL_BIN restart in Darwin section |
| INS-09 | PowerShell template | All 3 placeholders; renders; server_url resolved; $ErrorActionPreference="Stop"; Tls12; agent-auth.exe; CyCentra branding |
| INS-10 | _read_installed_version() | Returns '1.0.0' fallback; reads from file; strips leading v; no-v version passes through |
| INS-11 | Route presence | /api/system/agent-installer defined; session user_email check; 401 without auth; text/x-shellscript MIME; text/plain for PS1; Content-Disposition attachment; nosniff header; format param lowercased; OPTIONS handler present |

### 02-D: Other Unit Tests

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 2.600 | RBAC get_user_role — known admin | Returns `"admin"` |
| 2.601 | RBAC get_user_role — known viewer | Returns `"viewer"` |
| 2.602 | RBAC get_user_role — unknown user | Returns `"viewer"` (default) |
| 2.603 | ASM module return contract | Each module returns `{module, findings, error}` |
| 2.604 | ASM finding schema | Every finding has `type`, `severity`, `asset`, `description`, `remediation` |
| 2.605 | ASM severity values | Only: critical / high / medium / low / info |
| 2.606 | Auth guard — unauthenticated | All `/api/` routes return 401 or 302 without session |

---

## Suite 03 — API Contract Tests

File: `tests/03-api-contract.sh`

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 3.01 | Unauth → 401/302 on all /api/ | Every `/api/` route returns 401 or 302 without session cookie |
| 3.02 | Analyst-only → 403 for viewer | Write routes with `analyst` minimum return 403 for viewer session |
| 3.03 | Admin-only → 403 for analyst | Admin-only routes return 403 for analyst session |
| 3.04 | OPTIONS preflight → 204 | All POST/PUT/DELETE routes support OPTIONS with 204 + CORS headers |
| 3.05 | Content-Type on 200 | All 200 responses have `Content-Type: application/json` |
| 3.06 | /health never 500 | `/health` returns 200 always |
| 3.07 | /api/scan/status schema | Returns `{running, progress, current_module, last_log}` when authenticated |
| 3.08 | RBAC POST validation | `/api/rbac/users` POST with invalid role or missing email → 400 |
| 3.09 | Escalate auth | `POST /api/siem/incidents/<id>/escalate` → 401 unauth; 403 viewer |

---

## Suite 04 — OWASP Security

File: `tests/04-owasp-security.sh` | A01/A03/A07 failures are blocking; others are warnings.

| # | OWASP Category | Test Item | Pass Criteria |
|---|----------------|-----------|--------------|
| 4.01 | A01 — Broken Access Control | Unauthenticated access | All `/api/` → 401/302 without session |
| 4.02 | A01 — Broken Access Control | Viewer write routes | Viewer → 403 on all write endpoints |
| 4.03 | A01 — Broken Access Control | Role header bypass | `X-Role: admin` header must not bypass RBAC |
| 4.04 | A02 — Cryptographic Failures | Session cookie flags | `SESSION_COOKIE_HTTPONLY=True`; SAMESITE in (Lax/Strict/None) |
| 4.05 | A02 — Cryptographic Failures | SECRET_KEY strength | `SECRET_KEY` not empty; not a known-weak default |
| 4.06 | A03 — Injection | SQL injection | `'; DROP TABLE incidents; --` in email → not 500 |
| 4.07 | A03 — Injection | Command injection | `;ls /etc` in scan domain → 400/422 |
| 4.08 | A03 — Injection | XSS | `<script>alert(1)</script>` in text fields → `<script>` not in response |
| 4.09 | A05 — Security Misconfiguration | Debug mode | `app.debug=False` |
| 4.10 | A05 — Security Misconfiguration | Stack traces | No `Traceback` or `File "` in 4xx/5xx responses |
| 4.11 | A07 — Auth Failures | Empty email session | `session["user_email"] = ""` → 401 |
| 4.12 | A07 — Auth Failures | None email session | `session["user_email"] = None` → 401 |
| 4.13 | A09 — Logging | Auth log configured | `AUTH_LOG_FILE` defined; `auth_event()` callable |
| 4.14 | A09 — Logging | Auth log schema | `auth_event()` writes JSON with `timestamp`, `email`, `result` |
| 4.15 | A10 — SSRF | Loopback SSRF | `http://127.0.0.1` as baseUrl → does not return internal data |
| 4.16 | A10 — SSRF | Metadata SSRF | `http://169.254.169.254` → blocked |
| 4.17 | A10 — SSRF | File SSRF | `file:///etc/passwd` → blocked |
| 4.18 | Static scan | Hardcoded secrets | No `sk-[A-Za-z0-9]{20,}` or `AIza[0-9A-Za-z_-]{35}` in source |

---

## Suite 05 — Load & Performance

File: `tests/05-load-performance.sh` | WARNING ONLY — never blocks merge.

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 5.01 | /health — 50 concurrent | 100% success; p99 < 1000ms |
| 5.02 | /api/scan/status — 100 concurrent | ≥95% success; p99 < 1000ms |
| 5.03 | /api/auth/verify — 200 concurrent | Measure p99; compare to 100ms baseline |
| 5.04 | Memory stability | 200 sequential requests → RSS growth < 50MB |
| 5.05 | Post-burst recovery | 100-request burst then 10 sequential → avg < 500ms |

---

## Suite 06 — Correlation Accuracy

File: `tests/06-correlation-accuracy.sh` + `tests/unit/test_correlation_rules.py`

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 6.01 | ALL_RULES count | Exactly 55 entries |
| 6.02 | All IDs unique | No duplicates |
| 6.03 | All IDs sequential | CR-001 through CR-055, no gaps |
| 6.04 | All IDs start with CR- | No exceptions |
| 6.05 | Empty list safety | `match([])` → None for all 55 rules |
| 6.06 | Null-field safety | `match([null_alert])` → None or valid dict, never raises |
| 6.07 | Result contract | `key_alert_ids`, `detail`, `confidence` in every non-None result |
| 6.08 | Confidence range | 0.0 ≤ confidence ≤ 1.0 for all rules |
| 6.09 | CR-001 threshold | 5 failures + success fires; 4 failures → None |
| 6.10 | CR-011 confidence | EventLogCleared confidence == 0.95 |
| 6.11 | CR-041 confidence | ShadowCopyDeletion confidence == 0.97 |
| 6.12 | CR-055 confidence | DCSyncAttack confidence == 0.95 |
| 6.13 | FP auto-close formula | `(1 - 0.05) * 100 = 95.0 ≥ 90.0` → auto-close to 'closed' |
| 6.14 | FP keep-open formula | `(1 - 0.95) * 100 = 5.0 < 90.0` → keep open |

---

## Suite 07 — ASM Module Tests

File: `tests/07-asm-modules.sh`

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 7.01 | Module never raises (valid domain) | Every `run_*_check()` exits cleanly on valid domain |
| 7.02 | Module never raises (invalid domain) | Every `run_*_check()` exits cleanly on `!!invalid-domain!!` |
| 7.03 | Return dict contract | Every module returns `{module, findings, error}` |
| 7.04 | Finding schema | Every finding has `type`, `severity`, `asset`, `description`, `remediation` |
| 7.05 | Severity enum | Severity only: `critical`, `high`, `medium`, `low`, `info` |
| 7.06 | Scan profiles | `SCAN_PROFILES` has passive, standard, deep; deep is superset of standard |
| 7.07 | PQC cipher IDs | `crypto_checks.py` contains `0x6399` and `0x11ec` |
| 7.08 | Wordlist dedup | Subdomain wordlist has no duplicate entries |

---

## Suite 08 — Frontend Build

File: `tests/08-frontend-tests.sh`

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 8.01 | npm ci | Exits 0 |
| 8.02 | npm run build | Exits 0 |
| 8.03 | dist/index.html exists | File present after build |
| 8.04 | No build errors | No `<script>` errors or `ERROR:` lines in build output |
| 8.05 | No circular imports | No circular import warnings in build output |
| 8.06 | App.jsx size guard | `portal/src/App.jsx` ≤ 120 lines |
| 8.07 | constants.js exports | `BASE_API_URL` (or `API_BASE`) and `CYSCAN_URL` exported |
| 8.08 | adapter.js exports | `adaptCyCentraJSON` exported |
| 8.09 | aiProviders.js exports | `AI_PROVIDERS` and `DEFAULT_PROMPTS` exported |
| 8.10 | Vitest (if configured) | `npm run test -- --run` passes |

---

## Suite 09 — Infrastructure

File: `tests/09-infra-tests.sh`

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 9.01 | shellcheck | `shellcheck --severity=error cycentra-setup.sh` → 0 errors |
| 9.02 | set -euo pipefail | Present in `cycentra-setup.sh` |
| 9.03 | No bare clear | No bare `clear` command (must be `[[ -t 1 ]] && clear`) |
| 9.04 | No unguarded grep | All grep calls followed by `\|\| true` or inside `if` |
| 9.05 | DATABASE_URL fallback | `POSTGRES_PASSWORD` fallback present in setup/deploy scripts |
| 9.06 | deploy.yml concurrency | `concurrency:` block with `cancel-in-progress: true` |
| 9.07 | deploy.yml runtime versions | Python `3.12`, Node `20` |
| 9.08 | deploy.yml bundle | `dist/*.whl` copied into bundle directory before tar |
| 9.09 | RELEASE_NOTES.md | Has ≥1 `## v` entry with `### Bug Fixes` or `### Enhancements` |

---

## Suite 10 — End-to-End Integration

File: `tests/10-e2e-integration.sh`

| # | Test Item | Pass Criteria |
|---|-----------|--------------|
| 10.01 | Unauthenticated → 401 | All protected routes return 401 without session |
| 10.02 | Viewer read access | `GET /api/scan/status` → 200 for viewer |
| 10.03 | Viewer write blocked | `POST /api/rbac/users` → 403 for viewer |
| 10.04 | Analyst scan trigger | `POST /api/scan/trigger` → not 401/403 for analyst |
| 10.05 | Admin RBAC CRUD | Create → read → update → delete → verify deletion |
| 10.06 | Role change reflection | Changing session email reflected on next request |
| 10.07 | Logout flow | After logout, protected routes → 401 |
| 10.08 | Scan trigger validation | Valid domain → not 500; empty/invalid domain → 400/422 |
| 10.09 | Platform status schema | Returns dict with keys `cymisp`, `cysoar` |
| 10.10 | API response consistency | All 200 → JSON; all 4xx → JSON with `error` key; `/health` has `status`, `version`, `service` |

---

## Known Behavior Notes (Not Bugs)

These behaviors are surprising but correct — tests encode them explicitly to prevent future "fixes" that would break them.

| Rule/Detector | Surprising Behavior |
|--------------|---------------------|
| CR-032 | Fires on ANY `attachuserpolicy` event, not only admin-level policies |
| CR-050 | `sc create` (even local) triggers — keyword is not `sc \\` only |
| CR-054 | `net user` fires because `net use` is a substring of it |
| CR-026 | `"Windows Defender service stopped"` does NOT fire — needs `"windefend"` literal |
| UEBA D-16 | token_theft IP threshold is 5 (not 3) — raised to avoid VPN false positives |
| UEBA D-10 | spike_ratio = `recent_count / max(baseline/24, 1)` — needs low baseline to trigger with small N |
| UEBA D-06 | privilege_escalation only fires with corroborating context (service acct OR off-hours OR prior fail) |
| Agent installer | Darwin section has exactly 1 `${CTRL_BIN} restart` — double-restart was v1.0.61 bug |

---

*Last updated: 2026-06-19 | Test count: 677+ (576 pytest + 101 suite checks)*
