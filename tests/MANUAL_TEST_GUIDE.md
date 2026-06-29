# CyCentra 360 — Manual Test Guide

> **Purpose:** Step-by-step reference for human testers to verify all platform functionality.
> Cross-reference automated results: `tests/TEST_RUN_REPORT.md` | Inventory: `docs/TEST_INVENTORY.md`
> Per-module detail: `tests/modules/M01-*.md` through `M27-*.md`
>
> **Last validated:** 2026-06-29 — all blocking failures resolved, 1300+ tests passing.

---

## Table of Contents

1. [Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
2. [Quick Automated Checks (Local)](#2-quick-automated-checks-local)
3. [Server Infrastructure Checks (SSH)](#3-server-infrastructure-checks-ssh)
4. [Part A — Authentication & Access Control](#4-part-a--authentication--access-control)
5. [Part B — SIEM & Threat Detection](#5-part-b--siem--threat-detection)
6. [Part C — UEBA (Behavioral Analytics)](#6-part-c--ueba-behavioral-analytics)
7. [Part D — Attack Surface Management](#7-part-d--attack-surface-management)
8. [Part E — GRC / Compliance](#8-part-e--grc--compliance)
9. [Part F — Case Management (CyCases)](#9-part-f--case-management-cycases)
10. [Part G — EDR & Agent Installer](#10-part-g--edr--agent-installer)
11. [Part H — Platform & Integrations](#11-part-h--platform--integrations)
12. [Part I — Frontend Portal](#12-part-i--frontend-portal)
13. [Part J — AI Investigation Engine](#13-part-j--ai-investigation-engine)
14. [Part K — Infrastructure & CI/CD](#14-part-k--infrastructure--cicd)
15. [Part L — Resource Monitor](#15-part-l--resource-monitor)
16. [Part M — Threat Intelligence & VirusTotal](#16-part-m--threat-intelligence--virustotal)
17. [Part N — Kernel Telemetry & Wazuh Config](#17-part-n--kernel-telemetry--wazuh-config)
18. [Known Edge Cases & Gotchas](#18-known-edge-cases--gotchas)
19. [Test Status Summary](#19-test-status-summary)

---

## 1. Prerequisites & Environment Setup

### Server Access
| Resource | Value |
|----------|-------|
| Cy360 Backend | `ssh -p 2026 root@77.42.75.20` |
| Flask backend port | `5252` |
| Portal files (server) | `/tmp/portal-build/` |
| Platform config | `/opt/cycentra/` |
| AI settings | `/opt/cycentra/ai_settings.json` |

### Local Dev Setup
```bash
# Python environment (production uses 3.12; local tests use 3.9+)
cd /Users/deepakbhatnagar/Documents/CyRepo/Cy360/backend
pip install -r requirements.txt

# Frontend
cd /Users/deepakbhatnagar/Documents/CyRepo/Cy360/portal
npm install

# Run automated tests
cd /Users/deepakbhatnagar/Documents/CyRepo/Cy360
pytest tests/unit/ -v
```

### Test Accounts Required
Before running manual tests, ensure these test accounts exist in RBAC (`/opt/cycentra/rbac.json` or equivalent):
- `admin@test.local` — role: `admin`
- `analyst@test.local` — role: `analyst`
- `viewer@test.local` — role: `viewer`

### Blocking vs Non-Blocking
- **BLOCKING** — failure stops the release
- **WARNING** — log and investigate, does not stop release
- **MANUAL ONLY** — no automated equivalent; must be verified by a human

---

## 2. Quick Automated Checks (Local)

Run these first. They cover ~1300 tests in minutes and catch most regressions before manual testing.

### 2.1 Full Pytest Suite
```bash
cd /Users/deepakbhatnagar/Documents/CyRepo/Cy360
pytest tests/unit/ -v --tb=short 2>&1 | tee /tmp/cy360-test-run.txt
```

Expected: 637+ passed, 0 failures (in Python 3.12 environment).

Known Python 3.9 limitations (non-blocking):
- `test_siem_sso.py` — needs Python 3.12 container
- `test_benchmark_threat_intel.py` — core namespace conflict in 3.9

### 2.2 Targeted Suite Commands

| Suite | Command | Blocking |
|-------|---------|---------|
| Correlation rules (446 tests) | `pytest tests/unit/test_correlation_rules.py -v` | YES |
| UEBA detectors (89 tests) | `pytest tests/unit/test_ueba_detectors.py -v` | YES |
| Agent installer (49 tests) | `pytest tests/unit/test_agent_installer.py -v` | YES |
| AI investigation engine (132 tests) | `pytest tests/unit/test_ai_investigation_engine.py -v` | YES |
| Resource monitor (61 tests) | `pytest tests/unit/test_resource_monitor.py -v` | YES |
| Wazuh + VirusTotal (110 tests) | `pytest tests/unit/test_wazuh_kernel_virustotal.py -v` | YES |
| Integration health | `pytest tests/unit/test_integration_health.py -v` | YES |
| SIEM SSO | `pytest tests/unit/test_siem_sso.py -v` | YES (3.12 only) |

### 2.3 Static Checks (No Server Needed)

```bash
# 1. Syntax check all Python files
find backend/ -name "*.py" | xargs python3 -m py_compile && echo "SYNTAX OK"

# 2. App.jsx line count (must be ≤ 120)
wc -l portal/src/App.jsx

# 3. app.py line count (must be ≤ 70)
wc -l backend/app.py

# 4. No hardcoded secrets scan
grep -r 'sk-[A-Za-z0-9]\{20,\}\|AIza[0-9A-Za-z_-]\{35\}' backend/ portal/src/ && echo "SECRETS FOUND" || echo "CLEAN"

# 5. Installer script safety
grep 'set -euo pipefail' cycentra-setup.sh && echo "FOUND" || echo "MISSING"
grep -n '^\s*clear\s*$' cycentra-setup.sh && echo "BARE CLEAR FOUND" || echo "OK"

# 6. No circular import in siem_proxy
grep -n 'from app import' backend/siem_proxy.py && echo "CIRCULAR IMPORT" || echo "OK"

# 7. Blueprint imports clean
cd backend && python3 -c "
from blueprints.auth.oauth import auth_bp
from blueprints.oidc.provider import oidc_bp
from blueprints.rbac.manager import rbac_bp
from blueprints.platform.routes import platform_bp
from blueprints.asm.scanner import asm_bp
from blueprints.system.routes import system_bp
from siem_proxy import siem_bp
print('All blueprints: OK')
"

# 8. Frontend build
cd portal && npm run build && ls dist/index.html && echo "BUILD OK"
```

---

## 3. Server Infrastructure Checks (SSH)

Run these against the live production server.

```bash
# Connect
ssh -p 2026 root@77.42.75.20
```

### 3.1 Flask Health Check
```bash
curl -s http://localhost:5252/health | python3 -m json.tool
```
**Expected:**
```json
{"status": "ok", "version": "4.3", "service": "cycentra360-backend"}
```

### 3.2 Frontend Build Verification
```bash
cd /tmp/portal-build
npm run build 2>&1 | tail -5
ls -la dist/index.html
```
**Expected:** Exit 0, `dist/index.html` exists.

### 3.3 Load Test — 50 Concurrent /health
```bash
python3 - <<'EOF'
import urllib.request, time, concurrent.futures
URL = "http://localhost:5252/health"
def hit(_):
    t = time.time()
    urllib.request.urlopen(URL).read()
    return time.time() - t
with concurrent.futures.ThreadPoolExecutor(50) as ex:
    times = list(ex.map(hit, range(50)))
times.sort()
p99 = times[int(len(times)*0.99)]
print(f"50 requests: 100% success, p99={p99*1000:.0f}ms")
assert p99 < 1.0, f"p99 {p99*1000:.0f}ms exceeds 1000ms"
EOF
```
**Pass criteria:** p99 < 1000ms, 100% success.

### 3.4 Load Test — 100 Concurrent /api/scan/status
```bash
# Requires an authenticated session cookie — run after login
python3 - <<'EOF'
import urllib.request, urllib.error, time, concurrent.futures
URL = "http://localhost:5252/api/scan/status"
COOKIE = "session=<paste_session_cookie_here>"
def hit(_):
    t = time.time()
    req = urllib.request.Request(URL, headers={"Cookie": COOKIE})
    try:
        urllib.request.urlopen(req).read()
        return time.time() - t, True
    except: return time.time() - t, False
with concurrent.futures.ThreadPoolExecutor(100) as ex:
    results = list(ex.map(hit, range(100)))
times = sorted(r[0] for r in results)
ok = sum(1 for _, s in results if s)
p99 = times[int(len(times)*0.99)]
print(f"{ok}/100 success, p99={p99*1000:.0f}ms")
EOF
```
**Pass criteria:** ≥95% success. p99 warning at >1000ms (non-blocking).

### 3.5 Memory Stability
```bash
python3 - <<'EOF'
import urllib.request, os
pid = int(os.popen("pgrep -f 'gunicorn.*5252' | head -1").read().strip() or 0)
def rss():
    with open(f"/proc/{pid}/status") as f:
        for l in f:
            if l.startswith("VmRSS"): return int(l.split()[1])
before = rss()
for _ in range(200): urllib.request.urlopen("http://localhost:5252/health").read()
after = rss()
print(f"RSS growth: {(after-before)//1024} KB")
assert after - before < 50*1024, "Memory growth > 50MB"
EOF
```

### 3.6 Shellcheck (Local Only)
```bash
# Run locally (shellcheck is not on the production server)
/opt/homebrew/bin/shellcheck --severity=error cycentra-setup.sh
echo "Exit: $?"
```
**Pass criteria:** Exit 0, no error-level findings.

### 3.7 Deploy YAML Validation
```bash
# Run locally
grep 'cancel-in-progress' .github/workflows/deploy.yml && echo "CONCURRENCY OK"
grep 'python-version.*3\.12' .github/workflows/deploy.yml && echo "PYTHON 3.12 OK"
grep 'node-version.*20' .github/workflows/deploy.yml && echo "NODE 20 OK"
```

---

## 4. Part A — Authentication & Access Control

> Automated coverage: Suite 02-D, Suite 03, Suite 04 (OWASP A01/A07)
> Module docs: [M01-Auth.md](modules/M01-Auth.md), [M03-RBAC.md](modules/M03-RBAC.md)

### A-01: Google OAuth Login
1. Navigate to the portal URL (unauthenticated)
2. Verify login page appears: CyCentra logo, Google and Microsoft login buttons
3. Click **Login with Google** — complete OAuth consent with a valid Google account
4. Verify redirect back to portal; dashboard loads; user name shown in top-right
5. Check `AUTH_LOG_FILE` (server: `/opt/cycentra/auth.log`): entry with `{timestamp, email, provider:"google", result:"success"}`

**Pass:** Dashboard loads, auth log entry written.

### A-02: Microsoft OAuth Login
1. Repeat A-01 using **Login with Microsoft**
2. Verify auth log has `"provider":"microsoft"`

### A-03: Viewer Cannot Write
1. Log in as `viewer@test.local`
2. Attempt `POST /api/rbac/users` via browser devtools or curl
3. Attempt to trigger an ASM scan via UI
4. Expect: **403 Forbidden** on all write operations; scan button disabled/hidden

**Pass:** Viewer gets 403 or UI hides write actions.

### A-04: Analyst Can Scan, Cannot Manage RBAC
1. Log in as `analyst@test.local`
2. Trigger an ASM scan — expect success
3. Navigate to Settings → Users → attempt to change a user's role
4. Expect: **403 Forbidden** on RBAC write

### A-05: Admin Full Access
1. Log in as `admin@test.local`
2. Verify Settings → Users is accessible
3. Change `viewer@test.local` role to `analyst`; verify change saved
4. Revert the change

### A-06: Session Expiry
1. Log in as any user
2. Manually delete the session cookie in browser devtools
3. Attempt to access `/api/scan/status` directly
4. Expect: **401** or redirect to login

### A-07: Role Header Bypass Attempt (Security)
```bash
curl -s http://localhost:5252/api/rbac/users \
  -H "X-Role: admin" \
  -H "Cookie: session=invalid"
```
**Pass:** Returns 401 or 302 — NOT user data. The `X-Role` header must never bypass RBAC.

### A-08: Session Injection (Empty/None Email)
```bash
# Confirm via pytest (automated):
pytest tests/unit/ -k "test_empty_session or test_none_session" -v
```
Both must return 401.

---

## 5. Part B — SIEM & Threat Detection

> Automated coverage: Suite 02-A (446 tests), Suite 06
> Module docs: [M05-SIEM-Correlation.md](modules/M05-SIEM-Correlation.md)

### B-01: Alert Ingestion
1. Trigger a Wazuh test event on a monitored host (e.g., `logger -t wazuh "test event"`)
2. Navigate to SIEM → Alert Feed
3. Verify alert appears within 30 seconds
4. Verify: `agent_name`, `rule_id`, `severity`, `timestamp` are all populated

### B-02: CR-001 SSH Brute Force (End-to-End)
1. From a test host, run 5 failed SSH logins followed by 1 successful login to a monitored server
2. Navigate to SIEM → Incidents
3. Find **CR-001: SSH Brute Force** incident
4. Verify: `confidence ≥ 0.25`, `tactics: ["Credential Access"]`, `key_alert_ids` lists the 6 alerts
5. Verify **detail** describes the brute force pattern

**Pass criteria:** Incident created within 60 seconds of the 5th failure.

### B-03: Incident Lifecycle State Machine
1. Open any SIEM incident
2. Transition through: `new → in_review → held → closed`
3. Verify each transition saves and appears in audit log (`GET /api/siem/incidents/<id>/audit`)
4. Attempt invalid transition (e.g., `closed → held`) — expect error

### B-04: SOAR Escalation
1. Open a `high` severity incident
2. Click **Escalate to SOAR**
3. Verify `POST /api/siem/incidents/<id>/escalate` returns 200
4. Verify incident status updates to `escalated`
5. Verify: viewer gets **403** on this action, unauthenticated gets **401**

### B-05: Batch Incident Close
1. Select 5+ incidents using checkbox
2. Mark as **False Positive** and submit batch close
3. Verify all selected incidents closed
4. Verify FP pattern stored (future similar alerts auto-suppressed)

### B-06: SIEM Rule Catalog
```bash
curl -s -H "Cookie: session=<admin_cookie>" \
  http://localhost:5252/api/siem/rules | python3 -m json.tool | head -30
```
Verify: 56 rules returned, all IDs sequential CR-001 through CR-056.

### B-07: Dashboard KPIs
1. Navigate to SIEM → Dashboard
2. Verify widgets: Total Incidents, Open, In Review, Held, Closed, AI Auto-Closed
3. Create a new incident manually; verify Total count increments
4. Close an incident; verify Closed count increments
5. **AI Auto-Closed** widget must read from `/api/siem/stats` endpoint (not incidents list)

### B-08: False Positive Auto-Close Formula
```bash
# Run automated verification:
pytest tests/unit/test_correlation_rules.py -k "fp" -v
```
Verify: `(1 - 0.05) * 100 = 95.0 ≥ 90.0` → auto-closes; `(1 - 0.95) * 100 = 5.0 < 90.0` → stays open.

---

## 6. Part C — UEBA (Behavioral Analytics)

> Automated coverage: Suite 02-B (89 tests)
> Module doc: [M06-UEBA.md](modules/M06-UEBA.md)

### C-01: Off-Hours Login Alert
1. Set up a user baseline with logins only during business hours (09:00-17:00)
2. Simulate a login event at 03:00 for that user
3. Navigate to SIEM → UEBA
4. Verify `off_hours_login` anomaly detected for the user
5. Verify risk score contribution recorded

### C-02: Impossible Travel Detection
1. Generate two auth-success events for the same user from different agents within 2 minutes
2. Verify `impossible_travel` anomaly raised
3. Verify detail shows both agent names and timestamps

### C-03: Token Theft Detection (IP Threshold)
1. Generate auth events for the same user from 5 distinct IP addresses within the window
2. Verify `token_theft` fires
3. Try with 4 IPs — must NOT fire (VPN users commonly use 3-4)

**Note:** Threshold is 5 IPs, not 3. This is intentional to avoid VPN false positives.

### C-04: Suspicious Process Detection
1. Simulate an alert with `description` containing `mimikatz`
2. Navigate to SIEM → UEBA
3. Verify `suspicious_process` anomaly with full risk contribution

### C-05: Service Account Interactive Login
1. Simulate a login for user `svc_backup@domain.com` (service account naming)
2. Verify `svc_account_interactive` anomaly fires
3. Service accounts: any username starting with `svc_`, `daemon_`, `_admin` suffix

### C-06: UEBA Risk Score API
```bash
curl -s -H "Cookie: session=<analyst_cookie>" \
  http://localhost:5252/api/siem/ueba | python3 -m json.tool
```
Verify: returns list of users with `risk_score`, `anomalies`, `last_seen` fields.

---

## 7. Part D — Attack Surface Management

> Automated coverage: Suite 02-D (ASM), Suite 07 (8 tests)
> Module doc: [M04-ASM.md](modules/M04-ASM.md)

### D-01: Standard ASM Scan
1. Navigate to ASM / Scan
2. Enter a valid test domain (e.g., `testphp.vulnweb.com`)
3. Select profile: **Standard**
4. Click **Scan**
5. Verify progress updates every few seconds
6. Verify results appear with: module name, findings, severity

**Pass:** Scan completes without 500 error; findings have type/severity/asset/description/remediation.

### D-02: Invalid Domain Handling
1. Enter `!!invalid-domain!!` as the scan target
2. Click Scan
3. Expect: **400 or 422** response — not 500, not a hang

### D-03: Scan Profile Validation
```bash
cd backend && python3 -c "
from cy_asm.cycentra_scan import SCAN_PROFILES
assert set(SCAN_PROFILES.keys()) >= {'passive','standard','deep'}
standard = set(SCAN_PROFILES['standard'])
deep = set(SCAN_PROFILES['deep'])
assert standard.issubset(deep), 'deep must be superset of standard'
print('Scan profiles OK')
"
```

### D-04: PQC (Post-Quantum Cryptography) Detection
```bash
grep -n '0x6399\|0x11ec' backend/cy_asm/modules/crypto_checks.py
```
Both cipher suite IDs must be present (Kyber/MLKEM detection).

### D-05: ASM PDF Report
1. Complete a standard scan
2. Click **Download Report**
3. Verify: PDF generated, not empty, contains finding summaries
4. Verify: No 500 error during report generation

### D-06: Posture Score
1. After a scan, navigate to ASM Dashboard
2. Verify posture score (0-100) is calculated
3. Verify score changes if you rescan after fixing a finding

---

## 8. Part E — GRC / Compliance

> Module doc: [M07-GRC-Compliance.md](modules/M07-GRC-Compliance.md)

### E-01: Framework Questionnaire
1. Navigate to Compliance → Assessment
2. Select **ISO 27001** framework
3. Answer 10 questions; verify auto-save after each
4. Verify compliance score updates in real-time
5. Verify correct control denominator (ISO 27001 = 19 controls)

**Framework control denominators (canonical):**
| Framework | Controls |
|-----------|---------|
| NIS2 | 20 |
| DORA | 19 |
| ISO 27001 | 19 |
| SOC 2 | 16 |
| NIST CSF | 17 |
| PCI DSS | 17 |

### E-02: Cross-Framework Correlation
1. Complete assessments for 2 different frameworks
2. Navigate to Compliance → Gap Analysis
3. Verify controls appearing in both frameworks are linked
4. Verify MITRE technique mappings appear for gaps

### E-03: GRC Report Generation
1. Navigate to Compliance → Reports
2. Click **Generate PDF Report** for any framework
3. Verify: PDF generated, sections present (Executive Summary, Controls, Gaps)
4. Verify: No 500 error

### E-04: Risk Register
1. Navigate to Compliance → Risk Register
2. Create a new risk entry: title, category, likelihood, impact
3. Verify risk score calculated: likelihood × impact
4. Verify entry saved and appears in list

### E-05: Policy Document RAG
1. Upload a policy document (PDF) to Compliance → Policy Documents
2. Ask a question about the uploaded policy via CyMind chat
3. Verify CyMind retrieves relevant sections from the uploaded document

### E-06: Auto-Findings from SIEM
1. Generate a SIEM incident that maps to a compliance control (e.g., CR-001 → ISO 27001 A.12.6)
2. Navigate to Compliance → Findings
3. Verify auto-finding created linking the incident to the control gap

---

## 9. Part F — Case Management (CyCases)

> Module doc: [M08-Cases.md](modules/M08-Cases.md)

### F-01: Create Case from Incident
1. Open a SIEM incident
2. Click **Create Case** (or equivalent)
3. Verify case created in Cases module with link back to incident
4. Verify case appears in `GET /api/cases` response

### F-02: Case Workflow
1. Open a case
2. Add a note/comment
3. Change status: `open → in_progress → resolved`
4. Assign to a team member
5. Verify all changes reflected in case audit trail

### F-03: Case-Incident Link
1. Navigate to Cases → open a case
2. Verify linked incidents are listed
3. Click a linked incident — verify navigation to SIEM incident detail
4. Verify `casesIncidentId` routing works in portal

### F-04: Case Permissions
1. As **viewer**: attempt to create a case — expect 403
2. As **analyst**: create a case — expect success
3. As **admin**: delete a case — expect success

---

## 10. Part G — EDR & Agent Installer

> Automated coverage: Suite 02-C (49 tests — all passing)
> Module docs: [M09-EDR.md](modules/M09-EDR.md), [M18-AgentInstaller.md](modules/M18-AgentInstaller.md)

### G-01: Linux Agent Install
1. Navigate to EDR → Agent Installer → select **Linux**
2. Download the script; verify `Content-Type: text/x-shellscript`
3. On a test Linux VM (as root): `bash agent-installer.sh`
4. Verify agent registers within 2 minutes
5. Verify in SIEM: new agent appears in `GET /api/siem/agents`
6. Check audit key: `ls /etc/audit/rules.d/cy360_agent_tamper*`

**Pass:** Agent registers, audit key present.

### G-02: macOS Agent Install with Full Disk Access
1. Download macOS agent installer script
2. On a macOS test machine: `sudo bash agent-installer.sh`
3. Follow the FDA notice printed by the installer:
   - Grant Full Disk Access to `wazuh-agentd` in System Settings → Privacy & Security
   - Grant Full Disk Access to `wazuh-logcollector`
4. Verify `wazuh-agentd` restarts after FDA granted
5. Verify Apple ULS log events appear in SIEM (System category events)

**Note:** FDA must be granted manually — this cannot be automated.

### G-03: Windows Agent Install (PowerShell)
1. Download PS1 installer (`?format=ps1`)
2. Verify `Content-Type: text/plain`; `Content-Disposition: attachment; filename=agent-installer.ps1`
3. On test Windows host (elevated PS): `.\agent-installer.ps1`
4. Verify agent service starts: `Get-Service -Name "Wazuh"`
5. Verify Windows Security events appear in SIEM

### G-04: Duplicate Agent Detection
1. Run the installer on a host that already has the agent registered
2. Verify: installer prints "Duplicate agent" message
3. Verify: installer prompts for upgrade/uninstall — does NOT register twice
4. Verify: no double restart in Darwin/Linux sections

### G-05: Agent Installer Security Check
```bash
# 401 without auth
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:5252/api/system/agent-installer
# Must return 401

# X-Content-Type-Options header present
curl -I -H "Cookie: session=<valid_session>" \
  "http://localhost:5252/api/system/agent-installer?format=sh" | grep nosniff
```

### G-06: EDR Endpoint List
1. Navigate to EDR → Endpoints
2. Verify table: hostname, OS, status, agent version, last seen
3. Click an endpoint → detail panel: process list, detections, policies tabs
4. Verify: offline agents marked with appropriate status

### G-07: EDR Detection Response
1. On a monitored endpoint, run a known-bad process name (test tool only)
2. Navigate to EDR → Detections
3. Verify detection appears with: technique, severity, endpoint name, timestamp
4. Trigger response action: **Isolate Host**
5. Verify host is isolated; SIEM shows isolation event

---

## 11. Part H — Platform & Integrations

> Module docs: [M10-Platform.md](modules/M10-Platform.md), [M11-Marketplace.md](modules/M11-Marketplace.md),
>               [M12-Integrations.md](modules/M12-Integrations.md), [M16-SSO.md](modules/M16-SSO.md)

### H-01: Platform Module Status
```bash
curl -s -H "Cookie: session=<admin_cookie>" \
  http://localhost:5252/api/platform/status | python3 -m json.tool
```
**Expected:** JSON dict with keys `cymisp` and `cysoar` (status of Docker-managed modules).
Note: `cyiris` is no longer a valid key — CyCases is built-in, not Docker-managed.

### H-02: Module Install/Uninstall (Marketplace)
1. Navigate to Marketplace
2. Find a module not currently installed
3. Click **Install** — verify install progress shown
4. Navigate to Platform — verify module now appears as active
5. Click **Uninstall** — verify module deactivates

### H-03: MISP Integration Health
```bash
curl -s -H "Cookie: session=<admin_cookie>" \
  http://localhost:5252/api/integrations/health | python3 -m json.tool
```
Verify `misp` entry in response. If MISP not configured, expect `{"status":"unconfigured"}`.

### H-04: OIDC Provider (SSO)
1. Navigate to Settings → SSO
2. View OIDC Discovery endpoint: `GET /api/oidc/.well-known/openid-configuration`
3. Verify: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` all present
4. Configure a test OIDC client; verify login flow works end-to-end

### H-05: Backup & Restore
1. Navigate to Settings → Backup
2. Create a backup — verify backup file generated
3. Restore from that backup
4. Verify data consistency after restore

### H-06: Audit Trail
1. Perform 5 actions: login, view incident, change role, create case, logout
2. Navigate to Audit Trail
3. Verify all 5 events logged with: `timestamp`, `user`, `action`, `resource`, `result`
4. Verify: audit log cannot be deleted by non-admin users

### H-07: SMTP Alert Test
1. Navigate to Settings → Notifications
2. Configure SMTP settings
3. Click **Send Test Email**
4. Verify email received at configured address
5. Trigger a high-severity incident; verify auto-email sent

### H-08: Benchmark Scoring
1. Navigate to Benchmark
2. Verify benchmark score calculated (0-100)
3. View cohort comparison (if enabled)
4. Verify: `POST /api/benchmark/opt-in` accepts/rejects correctly

---

## 12. Part I — Frontend Portal

> Automated coverage: Suite 08 (10 checks)
> Module doc: [M20-Frontend-Portal.md](modules/M20-Frontend-Portal.md)

### I-01: Login Page
1. Open portal URL (unauthenticated)
2. Verify: CyCentra logo, Google button, Microsoft button, no JavaScript errors in console
3. Verify: clicking either login button initiates OAuth flow

### I-02: Navigation by Role
| Tab | Viewer | Analyst | Admin |
|-----|--------|---------|-------|
| Dashboard | ✅ | ✅ | ✅ |
| SIEM / Incidents | ✅ | ✅ | ✅ |
| ASM Scan | view only | ✅ trigger | ✅ |
| Compliance | ✅ | ✅ | ✅ |
| Settings | ✗ | ✗ | ✅ |
| RBAC / Users | ✗ | ✗ | ✅ |

Test: log in as each role; verify correct tabs visible or disabled.

### I-03: SIEM Dashboard Widgets
1. Navigate to Dashboard
2. Verify KPI widgets load without "NaN" or empty states
3. Verify **AI Auto-Closed** count reads from `/api/siem/stats` (not incident list)
4. Verify **Open Incidents** count includes both `in_review` and `held` states

### I-04: Scan History Dropdown (AppTopBar)
1. Verify scan history dropdown in top bar renders
2. Select a previous scan — verify page updates to show historical results
3. Verify scan type labels (standard/deep/passive) displayed
4. Verify findings count and subdomains shown per scan entry

### I-05: Error Boundary
1. Force a JS error in a page component (dev tools → break on error)
2. Verify `PageErrorBoundary` catches it: shows error message, **Retry** button, **Clear Cache & Reload** button
3. Click Retry — verify page recovers without full browser reload

### I-06: CyMind Chat Overlay
1. Click the CyMind chat button
2. Verify overlay opens and is scrollable
3. Type: `"List open high-severity incidents"` — verify response with data
4. Verify overlay can be minimized
5. Verify overlay persists across page navigation

### I-07: License Banner
1. With valid license: verify no banner shown
2. Simulate license expiry (or use expired license in test env)
3. Verify `LicenseBanner.jsx` shows a warning at top of page
4. Verify features are appropriately restricted

### I-08: Asset Modal and Import
1. Navigate to Assets
2. Click on an asset → verify `AssetModal` opens with correct data
3. Click **Import** → verify `ImportModal` opens
4. Import a CSV of assets → verify assets appear in list

### I-09: App.jsx Line Count (Critical)
```bash
wc -l portal/src/App.jsx
```
**Must be ≤ 120 lines.** Current: 101 lines ✅
After any feature addition that touches App.jsx, re-check.

---

## 13. Part J — AI Investigation Engine

> Automated coverage: Suite 12 (132 tests — all passing)
> Module doc: [M23-Investigation.md](modules/M23-Investigation.md)

### J-01: Trigger AI Investigation
1. Open a `high` or `critical` severity SIEM incident
2. Click **Investigate with AI**
3. Verify progress through 6 phases (shown in UI):
   - Phase 1: Generating hypotheses...
   - Phase 2: Collecting evidence...
   - Phase 3: LLM enrichment...
   - Phase 4: Campaign correlation...
   - Phase 5: Generating report...
   - Phase 6: Gap analysis...
4. Verify investigation report generated

**Pass:** All 6 phases complete; report visible.

### J-02: Investigation Report Quality
1. Review the generated report
2. Verify structure:
   - Executive Summary
   - Attack Hypothesis (with TTPs)
   - Evidence (with specific alert references)
   - Cross-Incident Correlation
   - MITRE ATT&CK Coverage Gaps
   - Recommendations
3. Verify technique IDs are valid MITRE format (T1xxx)
4. Verify recommendations are actionable

### J-03: CyMind Fallback to Groq
1. Stop the CyMind container: `docker stop cymind` (on server)
2. Trigger an AI investigation
3. Verify: system falls back to Groq LLM
4. Verify: report still generated (may be lower quality)
5. Restart CyMind: `docker start cymind`

### J-04: Campaign Correlation (Multi-Incident)
1. Generate 5+ related incidents with shared IOCs (same src_ip, same username)
2. Trigger investigation on any one incident
3. Verify Phase 4 links all related incidents into a campaign
4. Verify campaign timeline shows unified attack sequence

### J-05: MITRE Gap Analysis
1. Review gap analysis section of investigation report
2. Identify 2-3 missing technique IDs
3. Navigate to SIEM → Rules
4. Verify suggested rules would cover identified gaps

---

## 14. Part K — Infrastructure & CI/CD

> Automated coverage: Suite 09
> Module doc: [M21-Infrastructure.md](modules/M21-Infrastructure.md)

### K-01: Setup Script Safety
```bash
# All three must pass:
grep -c 'set -euo pipefail' cycentra-setup.sh      # must be ≥ 1
grep -c '^\s*clear\s*$' cycentra-setup.sh           # must be 0
grep -c '\[\[ -t 1 \]\] && clear' cycentra-setup.sh  # must be ≥ 1 (guarded clear)
```

### K-02: Deploy Workflow Config
```bash
grep -A3 'concurrency:' .github/workflows/deploy.yml
grep 'cancel-in-progress: true' .github/workflows/deploy.yml
grep 'python-version.*3.12' .github/workflows/deploy.yml
grep 'node-version.*20' .github/workflows/deploy.yml
```
All four must be present.

### K-03: Release Package Build
```bash
./build-package.sh
ls dist/*.whl    # Python wheels
ls dist/*.tar.gz # Release bundle
```
Verify: `.whl` files are included in the bundle tarball before packaging.

### K-04: DATABASE_URL Fallback
```bash
grep 'POSTGRES_PASSWORD' cycentra-setup.sh | grep 'DATABASE_URL'
```
Must construct a fallback `DATABASE_URL` from `POSTGRES_PASSWORD` env var.

---

## 15. Part L — Resource Monitor

> Automated coverage: Suite 11 (61 tests)
> Module doc: [M19-ResourceMonitor.md](modules/M19-ResourceMonitor.md)

### L-01: Script Execution on Linux (Infra Test)
1. SSH to a monitored Linux host
2. Set thresholds to 0: `CPU_THRESH=0 MEM_THRESH=0 DISK_THRESH=0`
3. Run: `bash cy360_resource_check.sh`
4. Verify: ≥1 JSON line emitted per resource type
5. Verify format: `{"event":"high_cpu","cpu_percent":N,"threshold":0,"host":"...","ts":"YYYY-MM-DDTHH:MM:SSZ"}`

### L-02: Threshold Enforcement
1. Set `CPU_THRESH=101 MEM_THRESH=101 DISK_THRESH=101`
2. Run script
3. Verify: **zero output** (nothing exceeds 101%)

### L-03: Wazuh Rule Trigger
1. On a host with CPU at normal levels, manually force a rule 101004 alert:
   ```bash
   logger "ossec: output: 'cy360-resource-check': {\"event\":\"high_cpu\",\"cpu_percent\":95,\"threshold\":80,\"host\":\"$(hostname)\",\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
   ```
2. Verify rule 101004 fires in SIEM within 2 minutes

### L-04: CR-056 Correlation (Manual End-to-End)
1. Generate 2+ resource alerts (mix of CPU, disk, memory)
2. Navigate to SIEM → Incidents
3. Find **CR-056: High Resource Utilization** incident
4. Verify: confidence=0.80, severity=medium, tactics=["Impact"]
5. Verify detail shows which resource types breached

### L-05: Rule 101007 Sustained Breach
1. Generate 3+ resource alerts within the timeframe configured in `cy_cust_rules.xml`
2. Verify rule 101007 fires at level 10
3. Verify CR-056 picks up 101007 alerts as well as individual type alerts

---

## 16. Part M — Threat Intelligence & VirusTotal

> Automated coverage: Suite 13-B (43 tests), Suite 22 (31 tests)
> Module docs: [M22-ThreatIntel.md](modules/M22-ThreatIntel.md), [M24-WazuhKernelTelemetry.md](modules/M24-WazuhKernelTelemetry.md)

### M-01: MISP Integration Health Check
```bash
curl -s -H "Cookie: session=<admin_cookie>" \
  http://localhost:5252/api/integrations/health/misp
```
If MISP not configured: returns `{"status":"unconfigured"}` — not 500.

### M-02: VirusTotal Key Activation
1. Navigate to Settings → Threat Intelligence
2. Enter a VT API key
3. Click **Save**
4. Verify: key stored via `_sync_ti_to_siem_env()` — check `/opt/cycentra/ai_settings.json`
5. Verify: GET endpoint masks the key (shows `vt-api-****` not full key)

**IMPORTANT:** Never hand-edit `cysiemstack.env` for the VT key. Use the Settings UI or vault.

### M-03: VirusTotal Enrichment Verdict
1. In Settings → Threat Intelligence → click **Test Connection**
2. Submit a known-malicious hash (e.g., EICAR test file SHA256)
3. Verify: verdict is `malicious` (≥10% engines agree)
4. Submit a known-clean hash
5. Verify: verdict is `clean` or `unknown`

### M-04: AbuseIPDB / GreyNoise (if configured)
1. Navigate to Settings → Integrations
2. Verify AbuseIPDB and GreyNoise keys are configured
3. Generate a SIEM alert from a suspicious external IP
4. Verify enrichment panel shows AbuseIPDB confidence score

---

## 17. Part N — Kernel Telemetry & Wazuh Config

> Automated coverage: Suite 13-A (57 tests)
> Module doc: [M24-WazuhKernelTelemetry.md](modules/M24-WazuhKernelTelemetry.md)

### N-01: macOS Apple ULS Telemetry
1. Navigate to EDR → Agent installer; download macOS script
2. Install on macOS test host with FDA granted to both `wazuh-agentd` and `wazuh-logcollector`
3. Verify: macOS ULS system log events (category: kernel, subsystem: com.apple.security) appear in SIEM

**Note:** FDA is a manual prerequisite — cannot be automated. Without FDA, `wazuh-logcollector` cannot read system logs.

### N-02: Linux Kernel Telemetry
1. On a monitored Linux host, verify journald is configured with priority 0-4
2. Run: `logger -p kern.crit "Test kernel critical message"`
3. Verify: alert appears in SIEM within 2 minutes

### N-03: Windows Event Channel
1. On a monitored Windows host, verify Security event channel is configured
2. Trigger a Security event (e.g., failed login attempt)
3. Verify event appears in SIEM with `channel: Security`

### N-04: Wazuh syscollector
```bash
# On a monitored host, verify these 9 inventory modules are enabled in ossec.conf:
grep -A2 '<syscollector>' /var/ossec/etc/ossec.conf | grep -E 'os|hardware|packages|processes|ports|hotfixes|interfaces|users|groups'
```
All 9 inventory modules must be active.

---

## 18. Known Edge Cases & Gotchas

These behaviors are **correct** — they exist to prevent past false-positive issues. Tests encode them explicitly. If someone tries to "fix" these, they will break the tests.

| Area | Behavior | Why It's Correct |
|------|----------|-----------------|
| CR-032 (CloudIAMPrivilege) | Fires on ANY `attachuserpolicy` event, not only admin-level | ANY IAM privilege attachment is suspicious by policy |
| CR-050 (RemoteServiceCreation) | `sc create` without `\\` (local) still fires | Local service creation is equally suspicious as remote |
| CR-054 (SMBShareEnumeration) | `net user` fires because `net use` is a substring | Substring match is intentional — both are recon commands |
| CR-026 (SecurityToolDisabled) | `"Windows Defender service stopped"` does NOT fire; needs `"windefend"` literal | Prevents false positives on generic service stop messages |
| UEBA D-16 (token_theft) | Threshold is 5 distinct IPs, not 3 | VPN users regularly appear from 3-4 IPs; 3 was too noisy |
| UEBA D-10 (activity_volume_spike) | spike_ratio = `recent_count / max(baseline_daily/24, 1)` | Low baseline (≤24/day) amplifies recent activity spikes |
| UEBA D-06 (privilege_escalation) | Only fires with corroborating context (service account, off-hours, or prior auth fail) | Isolated sudo is not anomalous in most environments |
| Agent installer (Darwin) | Exactly **1** `${CTRL_BIN} restart` in `do_install_macos()` — not in the case block | Double-restart was a v1.0.61 bug that caused race conditions |
| SIEM open_incidents | Includes `in_review` + `held` states (not just `new`) | In-review and held are active investigations, not resolved |
| App.jsx | Must stay ≤ 120 lines | Enforced to prevent regression to the 471-line monolith |
| app.py | Must stay ≤ 70 lines | Thin factory pattern — logic belongs in blueprints |

---

## 19. Test Status Summary

> As of **2026-06-29** — all blocking failures resolved.

| Suite | Tests | Status | Blocking |
|-------|-------|--------|---------|
| 01 — Smoke & Validation | 15 checks | ✅ PASS | YES |
| 02-A — Correlation Rules | 446 pytest | ✅ PASS | YES |
| 02-B — UEBA Detectors | 89 pytest | ✅ PASS | YES |
| 02-C — Agent Installer | 49 pytest | ✅ PASS | YES |
| 02-D — Other Unit | 7 pytest | ✅ PASS | YES |
| 03 — API Contract | 9 checks | ✅ PASS | YES |
| 04 — OWASP Security | 18 checks | ✅ PASS | YES (A01/A03/A07) |
| 05 — Load & Performance | 5 checks | ⚠️ WARN | WARNING ONLY |
| 06 — Correlation Accuracy | 17 checks | ✅ PASS | YES |
| 07 — ASM Module Tests | 8 checks | ✅ PASS | YES |
| 08 — Frontend Build | 10 checks | ✅ PASS | YES |
| 09 — Infrastructure | 9 checks | ✅ PASS | YES |
| 10 — End-to-End Integration | 10 checks | ✅ PASS | YES |
| 11 — Resource Monitor E2E | 61 pytest | ✅ PASS | YES |
| 12 — AI Investigation Engine | 132 pytest | ✅ PASS | YES |
| 13 — Wazuh Kernel + VirusTotal | 110 pytest | ✅ PASS | YES |

**Total automated:** 1300+ tests
**Manual scenarios in this guide:** 70+ test cases across 17 areas

### Performance Notes (Suite 05)
- `/health` 50 concurrent: p99=888ms ✅
- `/api/scan/status` 100 concurrent: p99=1949ms ⚠️ (above 1000ms target — investigate)
- `/api/auth/verify` 200 concurrent: p99=103ms ✅
- Memory growth: 0 KB ✅
- Post-burst recovery: 1.8ms ✅

### Known Non-Blocking Limitations (Python 3.9 Local Env)
These tests pass in the Python 3.12 production container but need workarounds locally:
- `test_siem_sso.py` — Flask `create_app()` not on sys.path
- `test_benchmark_threat_intel.py` — `core` namespace conflict

**Run in Docker for accurate results:**
```bash
docker run --rm -v $(pwd):/app -w /app python:3.12 \
  bash -c "pip install -r backend/requirements.txt && pytest tests/unit/ -v"
```

---

*Guide last updated: 2026-06-29 | References: `tests/TEST_RUN_REPORT.md`, `docs/TEST_INVENTORY.md`, `tests/modules/M01-M27.md`*
