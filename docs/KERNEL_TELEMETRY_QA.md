# CyCentra 360 — Kernel Telemetry & Active Response QA Playbook

**Version:** v1.0.60  
**Scope:** Linux Auditd, macOS Apple ULS, Windows Sysmon, MISP Threat Intel Pipeline, Host Isolation Active Response  
**Last updated:** 2026-06-19

---

## Rule ID Reference

| Rule ID | Description | Trigger | AR Action |
|---------|-------------|---------|-----------|
| 101000 | XDR anti-tamper: Wazuh agent binary/config accessed | auditd key `cy360_wazuh_tamper` | Local isolation, 600s |
| 101001 | Fileless malware / process injection syscall | auditd keys `cy360_privesc` + `cy360_exec` (memfd_create, process_vm_writev, ptrace) | Local isolation, 600s |
| 101002 | MISP threat intel: outbound connection to blacklisted IP | `dstip` matches `misp_global_blacklist` CDB | Global isolation (all agents), 3600s |
| 101003 | MISP threat intel: process hash in global blacklist | `data.win.eventdata.hashes` matches CDB | Global isolation (all agents), 3600s |

> **Naming note:** Rules 100501/100502/100503 referenced in earlier planning docs are FIM persistence rules (cron, LaunchAgent, startup). The kernel telemetry + isolation rules are 101000–101003.

> **FIM persistence rules also active (fixed in v1.0.60):**  
> 100500 = Startup folder write (T1547.001), 100501 = Cron modified (T1053.003), 100502 = LaunchAgent/systemd unit added (T1543.001)

---

## SECTION 1 — Sensor Verification Checklist

### 1A. Linux Auditd

Run on each enrolled Linux agent:

```bash
# 1. Service running
systemctl is-active auditd
# Expected: active

# 2. CyCentra baseline rules loaded into kernel
auditctl -l | grep -E 'cy360_exec|cy360_privesc|cy360_wazuh_tamper'
# Expected: multiple rules for all three keys

# 3. Rules file on disk
cat /etc/audit/rules.d/cy360-baseline.rules
# Expected: -a always,exit rules covering execve, setuid, ptrace, memfd_create,
#            process_vm_writev, process_vm_readv, and -w /var/ossec/ watch rules

# 4. Wazuh auditd localfile block in ossec.conf
grep -A3 'audit.log' /var/ossec/etc/ossec.conf
# Expected: <log_format>audit</log_format> and <location>/var/log/audit/audit.log</location>

# 5. Auditd writing events to log
tail -5 /var/log/audit/audit.log
# Expected: recent SYSCALL, PATH, EXECVE records

# 6. Wazuh agent is reading the audit log (file handle open)
lsof -p "$(pgrep wazuh-logcollector)" 2>/dev/null | grep audit.log
# Expected: wazuh-logcollector has /var/log/audit/audit.log open for reading
```

### 1B. macOS Apple Unified Logging System (ULS)

Run on enrolled macOS endpoint as root:

```bash
# 1. Agent running
/Library/Ossec/bin/wazuh-control status
# Expected: wazuh-agentd running

# 2. ULS localfile block in ossec.conf
grep -A8 'macos' /Library/Ossec/etc/ossec.conf
# Expected: <log_format>macos</log_format> with CDATA query predicate targeting
#            sudo, sshd, SecurityAgent, com.apple.securityd

# 3. Full Disk Access granted (manual step — cannot be automated)
#    System Settings → Privacy & Security → Full Disk Access
#    Verify: /Library/Ossec/bin/wazuh-agentd is toggled ON
#    Without FDA, ULS streaming is silently blocked.

# 4. ULS stream producing events (sanity check)
log stream --predicate 'process == "sudo" OR process == "sshd"' \
  --level debug --style compact 2>&1 | head -5
# Expected: log output within a few seconds (any user activity triggers this)

# 5. Wazuh agent log shows activity
tail -20 /Library/Ossec/logs/ossec.log | grep -i 'macos\|localfile\|error' | head -10
```

### 1C. Windows Sysmon

Run on enrolled Windows endpoint as Administrator:

```powershell
# 1. Sysmon service running
Get-Service Sysmon64 | Select-Object Status, DisplayName
# Expected: Running

# 2. Sysmon config loaded with correct schema version and hash algorithms
C:\CyCentra\Sysmon\sysmon64.exe -c 2>&1 | Select-String "schemaversion|HashAlgorithms"
# Expected: schemaversion="4.90", HashAlgorithms: SHA256,IMPHASH

# 3. Sysmon eventchannel registered in Wazuh ossec.conf
Select-String "Sysmon/Operational" "C:\Program Files (x86)\ossec-agent\ossec.conf"
# Expected: <location>Microsoft-Windows-Sysmon/Operational</location>

# 4. Sysmon events visible in Windows Event Log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
  Select-Object TimeCreated, Id, Message
# Expected: recent events (EventID 1=ProcessCreate, 3=NetworkConnect, 11=FileCreate, etc.)

# 5. Wazuh agent reading Sysmon channel
Get-Content "C:\Program Files (x86)\ossec-agent\logs\ossec.log" -Tail 20 |
  Where-Object { $_ -match "Sysmon|eventchannel" }
# Expected: no errors about Sysmon channel
```

---

## SECTION 2 — Benign Test Scenarios

All tests are fully reversible. No actual attack payloads used.

### 2A. Rule 101000 — Anti-Tamper Trigger (Linux, Auditd)

Writes a benign file into the Wazuh-monitored directory. Auditd captures the write with key `cy360_wazuh_tamper`, which Wazuh rule 101000 matches and may trigger local isolation (auto-clears after 600s).

```bash
# On enrolled Linux agent:

# 1. Create a benign test file in monitored path
echo "# cy360 test $(date)" >> /var/ossec/etc/test-tamper.tmp

# 2. Verify auditd captured the event
sleep 2
ausearch -k cy360_wazuh_tamper --start today | tail -10
# Expected: SYSCALL record with key=cy360_wazuh_tamper

# 3. Confirm Wazuh forwarded the event (check on manager):
#    grep '101000\|cy360_wazuh_tamper' /var/ossec/logs/alerts/alerts.json | tail -5

# 4. Clean up test file
rm -f /var/ossec/etc/test-tamper.tmp

# ISOLATION NOTE: If rule 101000 fires and the active response isolates this host,
# isolation auto-expires after 600 seconds. For immediate rollback:
# iptables -D INPUT -j CY360_ISOLATION 2>/dev/null
# iptables -D OUTPUT -j CY360_ISOLATION 2>/dev/null
# iptables -F CY360_ISOLATION 2>/dev/null
# iptables -X CY360_ISOLATION 2>/dev/null
# rm -f /var/ossec/var/run/cy360-isolation.lock
```

### 2B. Rule 101001 — Fileless Malware / Process Injection (Linux, Syscall)

Uses strace (a legitimate diagnostic tool) to trigger the ptrace syscall, which the `cy360_privesc` auditd key monitors. This simulates the syscall pattern used by process injection without any malicious activity.

```bash
# On enrolled Linux agent:

# 1. Trigger ptrace syscall via strace
strace -e trace=ptrace ls /tmp 2>/dev/null | head -3

# 2. Verify auditd captured the ptrace event
sleep 2
ausearch -k cy360_privesc --start today | grep ptrace | tail -5
# Expected: SYSCALL record with syscall=ptrace, key=cy360_privesc

# To trigger memfd_create (for fileless execution detection):
python3 -c "
import ctypes
libc = ctypes.CDLL('libc.so.6', use_errno=True)
fd = libc.memfd_create(b'cy360-test', 0)
if fd >= 0:
    import os; os.close(fd)
    print('memfd_create triggered — check auditd')
"
sleep 2
ausearch -k cy360_exec --start today | grep memfd | tail -5
# Expected: SYSCALL record for memfd_create
```

### 2C. Rule 101002 — MISP Blacklist IP Match (Manager)

Adds a test IOC IP to the blacklist CDB, verifies compilation, and then removes it.

```bash
# On Wazuh manager:

# 1. Check current blacklist state
wc -l /var/ossec/etc/lists/misp_global_blacklist
cat /var/ossec/etc/lists/misp_global_blacklist | head -5

# 2. Add RFC 5737 documentation IP as test IOC (safe — never routed)
echo "192.0.2.1:test-ioc-$(date +%s)" >> /var/ossec/etc/lists/misp_global_blacklist

# 3. Compile CDB
/var/ossec/bin/wazuh-dbcheck -c /var/ossec/etc/lists/misp_global_blacklist
echo "CDB compile exit: $?"
# Expected: exit 0

# 4. Verify CDB binary exists
ls -la /var/ossec/etc/lists/misp_global_blacklist.cdb 2>/dev/null
# Expected: .cdb file present and newer than list file

# 5. Remove test IOC
sed -i '/test-ioc/d' /var/ossec/etc/lists/misp_global_blacklist
/var/ossec/bin/wazuh-dbcheck -c /var/ossec/etc/lists/misp_global_blacklist
echo "Cleanup complete"
```

### 2D. MISP Sync Pipeline (Direct Execution)

Runs the sync script directly to validate secret resolution, MISP API connectivity, CDB write, and compilation.

```bash
# On manager — run sync manually
/var/ossec/framework/python/bin/python3 /var/ossec/etc/lists/sync_misp_cache.py
echo "Exit: $?"

# Check log output
tail -30 /var/ossec/logs/misp_sync.log
# Expected:
#   [INFO] MISP fetch complete: N indicators  (or stub/fallback message)
#   [INFO] CDB written: /var/ossec/etc/lists/misp_global_blacklist
#   [INFO] wazuh-dbcheck: OK

# Verify cron schedule
cat /etc/cron.d/cycentra-misp-sync
# Expected: 0 * * * * root /var/ossec/framework/python/bin/python3 /var/ossec/etc/lists/sync_misp_cache.py
```

---

## SECTION 3 — Alert & Log Verification

### 3A. Live Alert Monitor (Manager)

```bash
# Real-time filter for kernel telemetry rule IDs:
tail -f /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line.strip())
        rid = str(a.get('rule',{}).get('id',''))
        if rid in ('101000','101001','101002','101003'):
            ts  = a.get('timestamp','')
            ag  = a.get('agent',{}).get('name','?')
            desc = a.get('rule',{}).get('description','')
            mitre = ','.join(a.get('rule',{}).get('mitre',{}).get('id',[]))
            print(f'{ts} | RULE {rid} | agent={ag} | {desc} | MITRE={mitre}')
    except: pass
"

# Historical search:
python3 - << 'EOF'
import json
rules = {'101000','101001','101002','101003'}
try:
    with open('/var/ossec/logs/alerts/alerts.json') as f:
        for line in f:
            try:
                a = json.loads(line.strip())
                rid = str(a.get('rule',{}).get('id',''))
                if rid in rules:
                    print(a['timestamp'], 'RULE', rid,
                          a['agent']['name'], a['rule']['description'])
            except: pass
except FileNotFoundError:
    print('alerts.json not found')
EOF
```

### 3B. Wazuh Dashboard Query

1. Navigate to **CySIEM → Threat Hunting → Events**
2. KQL filter: `rule.id: 101000 OR rule.id: 101001 OR rule.id: 101002 OR rule.id: 101003`
3. Time range: Last 24h
4. Expected columns: `agent.name`, `rule.description`, `rule.mitre.id`, `rule.level`, `timestamp`

### 3C. Active Response Execution Log (Agent)

```bash
# On agent that received an isolation command:
cat /var/ossec/logs/active-responses.log | grep isolate-host | tail -20
# Expected entries:
#   isolate-host: command=add manager=<IP>
#   isolate-host: iptables isolation APPLIED
#   isolate-host: lock written to /var/ossec/var/run/cy360-isolation.lock

# Check current isolation state:
ls -la /var/ossec/var/run/cy360-isolation.lock 2>/dev/null && \
  echo "ISOLATED since $(date -d @$(cat /var/ossec/var/run/cy360-isolation.lock) 2>/dev/null || date -r $(cat /var/ossec/var/run/cy360-isolation.lock) 2>/dev/null)"
# If lock exists: host is currently isolated
```

### 3D. MISP Sync Log (Manager)

```bash
tail -50 /var/ossec/logs/misp_sync.log

# Green indicators:
#   [INFO] MISP fetch complete: N indicators
#   [INFO] CDB written: /var/ossec/etc/lists/misp_global_blacklist
#   [INFO] wazuh-dbcheck: OK

# Yellow indicators (secrets not configured yet):
#   [WARN] MISP URL or API key not configured — using stub list
#   [WARN] Infisical fetch failed: ... — will use env fallback

# Red indicators:
#   [ERROR] MISP fetch failed: connection refused / 403
#   [ERROR] wazuh-dbcheck failed: ... (check /var/ossec/logs/ossec.log)
```

---

## SECTION 4 — Active Response Validation

### 4A. Deployment Verification (Manager)

```bash
# 1. Script file present and executable
ls -la /var/ossec/active-response/bin/isolate-host.sh
# Expected: -rwxr-x--- 1 root wazuh  (mode 750)

# 2. Command block in ossec.conf
grep -A4 'isolate-host' /var/ossec/etc/ossec.conf | head -15
# Expected: <name>isolate-host</name>, <executable>isolate-host.sh</executable>,
#            <timeout_allowed>yes</timeout_allowed>

# 3. Both AR blocks present
grep -E 'rules_id>101000,101001|rules_id>101002,101003' /var/ossec/etc/ossec.conf
# Expected: two matches — local/600s block and global/3600s block

# 4. Wazuh loaded the AR config without error
grep 'isolate-host\|active-response' /var/ossec/logs/ossec.log | grep -v remoted | tail -5
```

### 4B. Manual Isolation Test (Controlled — Non-Production Agent Only)

```bash
# On a test Linux agent — manually inject the Wazuh AR JSON payload:

# 1. Apply isolation
echo '{"command":"add","parameters":{"alert":{"manager":{"name":"77.42.75.20"}}}}' \
  | bash /var/ossec/active-response/bin/isolate-host.sh

# 2. Verify iptables chain created
iptables -L CY360_ISOLATION -n --line-numbers
# Expected: ACCEPT rules for lo, manager:1514 (TCP+UDP both dirs), ESTABLISHED; DROP at end

# 3. Verify Wazuh manager connection still alive (port 1514 whitelisted)
ss -tnp | grep 1514
# Expected: ESTABLISHED connection to 77.42.75.20:1514

# 4. Verify lock file written
cat /var/ossec/var/run/cy360-isolation.lock
# Expected: Unix epoch timestamp of isolation start

# 5. Remove isolation
echo '{"command":"delete","parameters":{"alert":{"manager":{"name":"77.42.75.20"}}}}' \
  | bash /var/ossec/active-response/bin/isolate-host.sh

# 6. Verify chain removed
iptables -L CY360_ISOLATION -n 2>&1
# Expected: "No chain/target/match by that name"

# 7. Verify lock file removed
ls /var/ossec/var/run/cy360-isolation.lock 2>&1
# Expected: "No such file or directory"
```

### 4C. Emergency Manual Rollback

If isolation fires unintentionally and needs immediate removal:

```bash
# iptables engine:
iptables -D INPUT  -j CY360_ISOLATION 2>/dev/null
iptables -D OUTPUT -j CY360_ISOLATION 2>/dev/null
iptables -F CY360_ISOLATION 2>/dev/null
iptables -X CY360_ISOLATION 2>/dev/null
rm -f /var/ossec/var/run/cy360-isolation.lock

# nftables engine (if iptables not present):
nft delete table inet cy360_isolation 2>/dev/null
rm -f /var/ossec/var/run/cy360-isolation.lock

echo "Isolation removed — $(date)"
```

---

## SECTION 5 — Top 3 Failure Points & Triage

### Failure 1: Wazuh Rules Not Loading (cy_cust_rules.xml Error)

**Symptom:** `CRITICAL: Error loading the rules: 'etc/rules/cy_cust_rules.xml'` in ossec.log. Rules 101000–101003 never fire.

**Root cause (v1.0.60 context):** In Wazuh 4.x, FIM events decoded as `syscheck_integrity_changed` do not support `<field name="...">` for path matching. Must use `<match>` instead. Fixed in v1.0.60 — rules 100500–100502 now use `<match>`.

**Triage:**
```bash
grep 'ERROR\|CRITICAL\|cy_cust_rules' /var/ossec/logs/ossec.log | tail -10

# Validate XML manually:
python3 -c "
import xml.etree.ElementTree as ET
with open('/var/ossec/etc/rules/cy_cust_rules.xml') as f:
    content = f.read()
try:
    ET.fromstring('<_root>' + content + '</_root>')
    print('XML valid')
except ET.ParseError as e:
    print('XML ERROR:', e)
"

# Redeploy and restart:
# scp -P 2026 CYSIEM-Config/rules/cy_cust_rules.xml root@server:/var/ossec/etc/rules/
# ssh -p 2026 root@server "/var/ossec/bin/wazuh-control restart"
```

### Failure 2: MISP Sync Fails — Secrets Not Resolved

**Symptom:** misp_sync.log shows `[WARN] MISP URL or API key not configured` or `[ERROR] MISP fetch failed: HTTP 403`. Blacklist stays at 0 entries.

**Root cause:** 3-tier secret resolution chain failed — `.env` lacks `CLOUD_MISP_URL`/`CLOUD_MISP_API_KEY`, no env vars set, and HIMDS Arc auth to Infisical is failing or unconfigured.

**Triage:**
```bash
# 1. Check .env:
grep -E 'CLOUD_MISP_URL|CLOUD_MISP_API_KEY|INFISICAL_URL' /opt/cycentra/.env

# 2. Test HIMDS availability (Arc OIDC auth):
curl -si http://localhost:40342/metadata/identity/oauth2/token 2>/dev/null | head -5
# 401 + WWW-Authenticate header = HIMDS running; read keyfile path from realm= value

# 3. Run sync with debug output:
/var/ossec/framework/python/bin/python3 -u /var/ossec/etc/lists/sync_misp_cache.py 2>&1

# 4. Emergency override — inject secrets directly:
echo "CLOUD_MISP_URL=https://your-misp.example.com" >> /opt/cycentra/.env
echo "CLOUD_MISP_API_KEY=your-api-key"              >> /opt/cycentra/.env
/var/ossec/framework/python/bin/python3 /var/ossec/etc/lists/sync_misp_cache.py
```

### Failure 3: Active Response Fires But Host Not Isolated

**Symptom:** Alert fires for rule 101000/101001, Wazuh sends AR command, but `active-responses.log` has no isolate-host entry or shows `ERROR: neither iptables nor nft found`.

**Causes (in priority order):**
1. `isolate-host.sh` missing from `/var/ossec/active-response/bin/` or wrong permissions
2. iptables/nft not installed on the agent
3. `<disabled>yes</disabled>` in ossec.conf AR block (should be `no`)
4. Timeout already expired (600s local, 3600s global) — lock file absent because isolation expired

**Triage:**
```bash
# Manager side:
grep 'isolate-host\|active.response' /var/ossec/logs/ossec.log | tail -10
grep 'active-response' /var/ossec/logs/active-responses.log | tail -10

# Agent side:
ls -la /var/ossec/active-response/bin/isolate-host.sh
which iptables nft 2>&1
cat /var/ossec/logs/active-responses.log | grep isolate | tail -20

# Fix missing iptables (Debian/Ubuntu):
apt-get install -y iptables

# Fix permissions if script present but wrong mode:
chown root:wazuh /var/ossec/active-response/bin/isolate-host.sh
chmod 750 /var/ossec/active-response/bin/isolate-host.sh
```

---

## SECTION 6 — Automated Test Results

**Last run:** 2026-06-19T14:12:10Z — Server: `77.42.75.20` — CyCentra 360 v1.0.60 — Wazuh 4.14.5

| ID | Test | Expected | Result | Notes |
|----|------|----------|--------|-------|
| T01 | Wazuh manager active | `active` | **PASS** | |
| T02 | cy_cust_rules.xml valid XML | 38 rules parsed | **PASS** | 38 rules total, 2 groups |
| T03 | Rule 101000 present | match | **PASS** | XDR anti-tamper |
| T04 | Rule 101001 present | match | **PASS** | Fileless malware |
| T05 | Rule 101002 present | match | **PASS** | MISP IP match |
| T06 | Rule 101003 present | match | **PASS** | MISP hash match |
| T07 | isolate-host.sh deployed (750 root:wazuh) | present + perms | **PASS** | `/var/ossec/active-response/bin/` |
| T08 | ossec.conf: isolate-host command block | present | **PASS** | |
| T09 | ossec.conf: misp_global_blacklist CDB | present | **PASS** | |
| T10 | ossec.conf: AR block rules_id 101000,101001 | present | **PASS** | local, 600s |
| T11 | ossec.conf: AR block rules_id 101002,101003 | present | **PASS** | all agents, 3600s |
| T12 | MISP blacklist stub present | file exists | **PASS** | 0 lines (empty — awaiting IOC feed) |
| T13 | sync_misp_cache.py deployed | file exists | **PASS** | `/var/ossec/etc/lists/` |
| T14 | MISP hourly cron installed | cron entry | **PASS** | `/etc/cron.d/cycentra-misp-sync` |
| T15 | CDB compile round-trip | exit 0 | **PASS** | via `wazuh-control reload` (wazuh-dbcheck absent on this build) |
| T16 | MISP sync connectivity | reaches MISP | **PASS** | 0 indicators (empty MISP or key lacks attribute read) |
| T17 | No CRITICAL errors in ossec.log | 0 CRITICAL | **PASS** | |
| T18 | Isolation APPLY | chain created | **PASS** | CY360_ISOLATION chain created |
| T19 | Isolation lock file | file present | **PASS** | epoch timestamp written |
| T20 | iptables rules structure | ≥8 rules | **PASS** | 9 rules: lo × 2, 1514 TCP/UDP × 4, ESTABLISHED × 2, DROP |
| T21 | Isolation REMOVE | chain removed | **PASS** | |
| T22 | Lock file removed | file absent | **PASS** | |

**Overall: 22/22 PASS**

### Notes on specific results

**T15 — wazuh-dbcheck absent:** `wazuh-dbcheck` binary is not present in Wazuh 4.14.5 on this build. The fallback `wazuh-control reload` is used to trigger CDB compilation at analysisd restart. This is expected behaviour — the script handles this correctly.

**T16 — 0 MISP indicators:** The MISP endpoint at `https://cymisp.cycentra.com` was reachable (SSL + Cloudflare WAF bypassed). Two issues fixed during this QA run:
1. SSL certificate: Wazuh's bundled OpenSSL lacked the Google WE1 intermediate cert. Fixed by loading `certifi` CA bundle.
2. Cloudflare 1010 block: Default Python-urllib User-Agent was blocked. Fixed by setting `User-Agent: CyCentra360-MISP-Sync/1.0`.
3. 0 indicators returned: Either the MISP instance has no published IOCs in the last 30 days, or the API key lacks `read` permission on Attributes. The script correctly preserves the existing list when MISP returns empty. **Action required:** verify MISP API key permissions and seed the instance with IOCs.

### Known excluded sensors (require enrolled endpoints — not testable on manager)

| Sensor | Status | How to verify |
|--------|--------|---------------|
| Linux auditd on agents | **Not tested** | Run Section 1A on each enrolled Linux agent |
| macOS Apple ULS | **Not tested** | Run Section 1B on enrolled macOS endpoint; FDA grant is manual |
| Windows Sysmon | **Not tested** | Run Section 1C on enrolled Windows endpoint |
| Rule 101000 real alert | **Not tested** | Run Section 2A on enrolled Linux agent |
| Rule 101001 real alert | **Not tested** | Run Section 2B on enrolled Linux agent |
