# M24 — Wazuh Kernel Telemetry & Agent Config
**Files:** `CYSIEM-Config/agent_config/agent.conf`, `CYSIEM-Config/conf/ossec.conf`
**Run Date:** 2026-06-29

---

## Module Scope

Wazuh agent configuration for kernel-level telemetry collection. Platform-specific blocks for macOS (Apple ULS), Linux (journald), and Windows (Security eventchannel). Manager-side syscollector for package/OS/process inventory.

**Configuration Blocks:**
- macOS: `apple-oslog` localfile with ULS subsystem queries
- Linux: `journald` localfile with priority 0-4 filter
- Windows: Security eventchannel with EventID suppression list
- Resource monitor: per-platform command wodle (`cy360-resource-check`)
- Syscollector: packages, OS, network, processes, users, groups, hardware
- Vulnerability detection: feed-update-interval=60m
- FIM/syscheck: /etc, /usr/bin, /usr/sbin monitored
- Rootcheck: trojans, sys, pids, files
- Active response: isolate-host.sh (rules 101000-101003)

---

## AI-Executable Tests (63 tests — ALL PASS)

### A1 — macOS Apple ULS Configuration (16/16)

| # | Test | Result |
|---|------|--------|
| A1.01-A1.16 | Darwin config block, apple-oslog format, ULS subsystem queries, frequency, alias, resource-check | ✅ ALL PASS |

### A2 — Linux auditd/journald (9/9)

| # | Test | Result |
|---|------|--------|
| A2.01-A2.09 | Linux block, journald format, PRIORITY 0-4, resource-check command and alias | ✅ ALL PASS |

### A3 — Windows Sysmon/eventchannel (9/9)

| # | Test | Result |
|---|------|--------|
| A3.01-A3.09 | Windows block, Security channel, EventID suppression (5156/4658), PS resource-check | ✅ ALL PASS |

### A4 — Manager Syscollector (9/9)

| # | Test | Result |
|---|------|--------|
| A4.01-A4.09 | All 9 inventory modules enabled: packages, OS, network, processes, users, groups, hardware, scan_on_start | ✅ ALL PASS |

### A5 — Vulnerability Detection (4/4)

| # | Test | Result |
|---|------|--------|
| A5.01-A5.04 | Block present, enabled=yes, index-status=yes, feed interval | ✅ ALL PASS |

### A6 — FIM Syscheck (5/5)

| # | Test | Result |
|---|------|--------|
| A6.01-A6.05 | disabled=no, scan_on_start, alert_new_files, /usr/bin and /etc monitored | ✅ ALL PASS |

### A7 — Rootcheck (5/5)

| # | Test | Result |
|---|------|--------|
| A7.01-A7.05 | disabled=no, check_trojans, check_sys, check_pids, check_files | ✅ ALL PASS |

### A8 — Active Response (5/5)

| # | Test | Result |
|---|------|--------|
| A8.01-A8.05 | isolate-host.sh command, AR for 101000-101001 (local/600s), AR for 101002-101003 (all/3600s) | ✅ ALL PASS |

---

## Manual Test Suite

### M-WAZ-01: macOS FDA Prerequisite
**Steps:**
1. Install Wazuh agent on macOS 14+
2. Open System Settings → Privacy & Security → Full Disk Access
3. Add `/Library/Ossec/bin/wazuh-agentd`
4. Restart agent
5. Verify Apple ULS events appear in SIEM

### M-WAZ-02: Linux journald Priority Filter
**Steps:**
1. Verify journald priority filter set to 0,1,2,3,4
2. Generate a kernel error (priority 3): `logger -p kern.err "test"`
3. Verify event appears in SIEM within 30 seconds
4. Verify informational events (priority 6) do NOT appear

### M-WAZ-03: Windows Sysmon EventID Suppression
**Steps:**
1. Verify EventID 5156 not appearing in SIEM (MPSSVC allow — high volume)
2. Verify EventID 4658 not appearing (handle close — high volume)
3. Verify Security events like 4625 (failed login), 4648 (runas) DO appear

### M-WAZ-04: Syscollector Inventory
**Steps:**
1. Run `wazuh-control start` on manager
2. Wait for inventory scan (scan_on_start=yes)
3. Navigate to CySIEM → Host Intelligence
4. Verify packages, OS, processes visible for enrolled endpoints

### M-WAZ-05: Active Response — Host Isolation
**Steps:**
1. Simulate rule 101000 trigger on test endpoint
2. Verify `isolate-host.sh` executes on endpoint
3. Verify network connectivity lost (except management subnet)
4. Wait 600 seconds — verify auto-restoration
