# CyCentra 360 — Endpoint Policy Engine

**Location in Portal:** Host Intelligence → Endpoint Policies tab  
**Backend routes:** `/api/siem/endpoint-policies/*`  
**Introduced:** v1.0.31+

---

## Overview

The Endpoint Policy Engine lets security analysts and administrators define **named response policies** — each containing one or more remediation actions — and apply them to endpoints either manually from the portal or automatically when specific Wazuh detection rules fire.

Policies bridge the gap between detection and response. Instead of configuring Wazuh `<active-response>` XML blocks by hand, you create a policy in the UI, pick your actions, define where and when they run, and let the engine handle the rest.

---

## How It Works — Architecture

```
DETECTION                     POLICY ENGINE                     ENDPOINT
──────────                    ──────────────                    ─────────
Wazuh rule fires
    │
    │  Auto-trigger            ┌──────────────────────┐
    └──(ossec.conf AR block)──▶│  Wazuh Manager       │──▶ AR script on agent
                               │  (via Sync button)   │
                               └──────────────────────┘

Portal "Apply Now"
    │
    │  Manual trigger           ┌──────────────────────┐
    └──(Flask → Wazuh API)────▶│ PUT /active-response │──▶ AR script on agent
                               └──────────────────────┘

Results logged to:  endpoint_policy_executions table (PostgreSQL)
Viewed in portal:   Policy → Execution History tab
```

**Two trigger paths — same scripts on the endpoint:**

| Path | How it fires | Wazuh config |
|---|---|---|
| **Manual** | Analyst clicks "Apply Now" in the portal | Flask calls Wazuh REST API in real-time |
| **Auto** | Wazuh rule fires on the agent | Managed `<active-response>` block written to `ossec.conf` via "Sync to Wazuh" |

---

## Policy Concepts

### Actions
A policy contains one or more **actions** — each action maps to an executable script (or Wazuh built-in command) that runs on the target endpoint. Actions can be combined: e.g., a ransomware response policy might run `Isolate Host` + `Collect Forensics` simultaneously.

### Scope
Scope controls **which endpoints** a policy applies to when triggered:

| Scope | Meaning | When to use |
|---|---|---|
| **Specific Agents** | Analyst picks agents at apply time | Ad-hoc incident response |
| **All Active Endpoints** | Every active Wazuh agent | Organisation-wide lockdowns |
| **Agent Group** | All agents in a named Wazuh group | Team/department/OS-specific controls |
| **Agent ID List** | Fixed list of agent IDs (JSON array) | Permanent policy on known critical servers |

### Trigger Mode
| Mode | Behaviour |
|---|---|
| **Manual only** | Policy runs only when an analyst clicks "Apply Now" |
| **Auto-trigger** | In addition to manual, runs automatically when any of the listed rule IDs fire on an agent. Requires "Sync to Wazuh" after saving. |

---

## Available Actions

### 1. Isolate Host
**Severity:** Critical &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Auto-reverts:** 1 hour (configurable)

**What it does:** Drops all inbound and outbound network traffic on the endpoint using `iptables` (Linux) or `nftables` (fallback). A single exception is carved out: Wazuh manager communication on port 1514 (TCP + UDP) is always preserved so the agent remains visible and controllable from the portal.

**When to use:**
- Confirmed ransomware execution
- Active C2 beacon with lateral movement indicators
- Process injection or credential dump detected
- Any situation where the risk of the host remaining networked outweighs the operational disruption

**Platform support:** Linux (iptables/nftables) · macOS (pfctl — via policy API) · Windows (Windows Firewall — via Wazuh API)

**What happens on apply:**
1. A named chain `CY360_ISOLATION` is created in iptables
2. Loopback and Wazuh port 1514 rules are inserted first
3. A DROP-all rule is appended
4. The chain is hooked into both INPUT and OUTPUT
5. A lock file `/var/ossec/var/run/cy360-isolation.lock` records the isolation time

**Reverting (delete command):** Removes the `CY360_ISOLATION` chain from INPUT/OUTPUT and deletes the lock file. Network connectivity is restored immediately.

**Script:** `isolate-host.sh` | **ossec.conf command:** `isolate-host`

---

### 2. Restrict Network
**Severity:** High &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Auto-reverts:** 1 hour

**What it does:** A more surgical alternative to full isolation. Blocks all internet-bound traffic while preserving internal LAN connectivity (RFC1918 address ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Keeps internal DNS, SMB, and remediation tooling reachable.

**When to use:**
- C2 beacon detected but you need to maintain internal access for investigation
- Cryptominer detected — cut the outbound mining pool connection while keeping the host accessible
- Threat is still being investigated and full isolation would disrupt critical business services
- Incident containment when the host is a server that must remain reachable internally

**Platform support:** Linux (iptables/nftables)

**What it preserves:**
- Loopback
- All RFC1918 LAN traffic (both directions)
- Wazuh manager port 1514
- LAN DNS (ports 53 TCP+UDP)
- Established sessions at time of application (existing SSH connections survive)

**Script:** `restrict-network.sh` | **ossec.conf command:** `restrict-network`

---

### 3. Block USB Storage
**Severity:** Medium &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Timeout:** Permanent (timeout=0)

**What it does:** Prevents USB mass storage devices from mounting by blacklisting the `usb-storage` kernel module on Linux. The block persists across reboots because it writes a `modprobe.d` configuration file. On macOS, the `IOUSBMassStorageClass` kext is blocked via `kextutil`.

**When to use:**
- Data exfiltration prevention on sensitive endpoints
- After a USB-connected malware delivery incident (e.g., T1091 rule 100910/100911 fires)
- Compliance policy: prevent removable media on servers or kiosk machines
- Proactive lockdown during an active incident to prevent a secondary exfiltration vector

**Platform support:** Linux (modprobe.d) · macOS (kextutil — requires partial SIP disable or MDM)

**Permanent block behaviour on Linux:**
1. Writes `/etc/modprobe.d/cy360-block-usb.conf` with `blacklist usb-storage` and `install usb-storage /bin/true`
2. Runs `update-initramfs -u` so the block survives reboot
3. Unloads `usb-storage` if currently loaded: `modprobe -r usb-storage`

**Reverting (delete command):** Removes the modprobe.d config, re-runs initramfs update, and loads `usb-storage` back. Effective immediately without reboot.

**Script:** `block-usb.sh` | **ossec.conf command:** `block-usb`

---

### 4. Block WiFi
**Severity:** Medium &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Auto-reverts:** 1 hour

**What it does:** Disables the wireless networking adapter. On Linux, uses `nmcli radio wifi off` (NetworkManager) with `rfkill block wifi` as a fallback. On macOS, uses `networksetup -setairportpower <interface> off` with automatic Airport interface detection.

**When to use:**
- Prevent a compromised laptop from connecting to untrusted WiFi networks while a wired investigation is underway
- Policy enforcement: prohibit wireless on servers or lab machines where only wired is allowed
- During an incident on a remote worker machine — cuts potential home/guest network C2 channel while leaving wired corporate VPN intact
- Force endpoint onto audited wired-only network segment

**Platform support:** Linux (nmcli + rfkill) · macOS (networksetup)

> **Note:** Windows WiFi control requires a separate MDM-pushed policy (e.g., via Intune). This action targets Linux and macOS agents only.

**Reverting (delete command):** Runs `nmcli radio wifi on` / `rfkill unblock wifi` (Linux) or `networksetup -setairportpower on` (macOS). Interface is re-enabled immediately.

**Script:** `block-wifi.sh` | **ossec.conf command:** `block-wifi`

---

### 5. Quarantine File
**Severity:** High &nbsp;|&nbsp; **Reversible:** No (manual restoration required) &nbsp;|&nbsp; **Timeout:** Permanent

**What it does:** Removes a suspicious file from its original location and moves it to `/var/ossec/quarantine/` where it can no longer execute. The owning process is killed first using `fuser -k` to release file handles. A `.meta` sidecar file is written alongside the quarantined file recording the original path, timestamp, triggering rule, and hostname.

**When to use:**
- MISP hash blacklist match on a file present on the endpoint (rule 101003)
- Malware confirmed by ClamAV scan — remove it immediately
- Analyst has confirmed a file is malicious and wants it preserved for forensic analysis rather than deleted

**Platform support:** Linux · macOS

**What happens on apply:**
1. Validates the file path exists and is not in a protected system path (`/var/ossec/`, `/usr/bin/`, etc.)
2. Kills any process with an open handle on the file: `fuser -k <path>`
3. Moves the file: `mv -- <source> /var/ossec/quarantine/<basename>.<UTC-timestamp>`
4. Sets quarantined file permissions to `000` (no read/write/execute)
5. Writes `<filename>.meta` with source path, timestamp, and trigger rule

**Reverting:** Files are NOT automatically restored. An analyst must manually review the quarantine directory and restore files via the command line. This is intentional — quarantine is a one-way action that requires explicit human review.

**Script:** `quarantine-file.sh` | **ossec.conf command:** `quarantine-file`

---

### 6. Scan Endpoint
**Severity:** Low &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Timeout:** 10 minutes

**What it does:** Runs a malware scan on the endpoint. If ClamAV is installed, runs `clamscan --recursive --infected` on volatile paths. If ClamAV is not installed, falls back to a heuristic scan: finds setuid/setgid binaries in volatile locations, executable files dropped in `/tmp` and `/var/tmp`, and files modified in the last 24 hours.

**Scan targets (both modes):** `/tmp` · `/var/tmp` · `/dev/shm` · `/home` · `/root`

**When to use:**
- Post-incident: verify no malware dropper was left after a compromise
- Routine sweep on an endpoint after a suspicious alert
- Pre-investigation sweep before collecting forensics
- Portal-triggered manual scan from an analyst who sees anomalous behaviour

**Platform support:** Linux · macOS

**Scan results location:** `/var/ossec/logs/cy360-scan-reports/scan-<TIMESTAMP>.log`  
Also emitted as a Wazuh alert event if infected files are found, which surfaces in the Alert Feed.

**Script:** `scan-endpoint.sh` | **ossec.conf command:** `scan-endpoint`

---

### 7. Collect Forensics
**Severity:** Low &nbsp;|&nbsp; **Reversible:** Yes (read-only) &nbsp;|&nbsp; **Timeout:** 5 minutes

**What it does:** Non-destructively captures volatile artifacts from the endpoint into a compressed archive. This action does not modify any files on the endpoint — it only reads. The archive is written to `/var/ossec/logs/cy360-forensics/` on the agent.

**Artifacts collected:**

| Artifact | Source | Contents |
|---|---|---|
| Process list | `ps auxf` / `pstree -p` | All running processes with CPU/mem, parent-child tree |
| Network state | `ss -tulnp`, `ss -anp` | Listening sockets, all connections, routing table, ARP |
| Open files | `lsof /tmp /var/tmp /dev/shm` | Files open in volatile locations |
| Cron/scheduled tasks | `/etc/crontab`, `/etc/cron.d/*`, `systemctl list-timers` | All scheduled tasks |
| Persistence | Enabled systemd units, `/etc/rc.local`, `~/.bashrc`, SSH `authorized_keys` | All autostart mechanisms |
| Kernel modules | `lsmod` | Loaded modules — detect rootkit drivers |
| Recent file changes | `find / -mmin -1440` | Files modified in last 24 hours |
| Users & sessions | `who`, `last -n 30`, `/etc/shadow` lock status | Active logins, recent history |
| System info | `uname -a`, `/etc/os-release`, `uptime`, `free`, `df` | Host metadata |

**Output:** `/var/ossec/logs/cy360-forensics/<hostname>-<YYYYMMDDTHHMMSSZ>.tar.gz`  
Archives auto-rotate: only the 20 most recent are retained.

**When to use:**
- First action on any suspected compromise before remediation changes the evidence
- Before applying Isolate Host — capture the network connections while they exist
- After a suspicious alert that needs investigation before escalation
- Preserving evidence before a system is rebuilt

> **Best practice:** Run Collect Forensics *before* Isolate Host on critical systems. Isolation will terminate active network connections which would otherwise appear in the forensic capture.

**Script:** `collect-forensics.sh` | **ossec.conf command:** `collect-forensics`

---

### 8. Disable Account
**Severity:** High &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Auto-reverts:** 1 hour

**What it does:** Locks the user account that triggered the detection alert. Uses Wazuh's built-in `disable-account` active-response, which runs `passwd -l <user>` (Linux) to lock the password entry. The account cannot log in until manually unlocked or the timeout expires.

**When to use:**
- MFA push bombing detected (rule 100801) — lock the account being spammed
- Credential theft indicator (rules 100100–100104) — immediately revoke the compromised account's access
- Insider threat detected — rapid account suspension pending investigation
- Brute-force success against a service account

**Platform support:** Linux · macOS

> **Windows note:** Wazuh's built-in `disable-account` does not lock Active Directory accounts. For AD environments, pair this with a custom SOAR playbook or use the Firewall Drop IP action to cut the source IP while an AD admin suspends the account.

**What gets locked:** The specific user (`$(user)`) extracted from the triggering alert. The alert must contain a `user` field for this action to identify the correct account.

**Reverting:** After the timeout expires, the account is automatically re-enabled. For immediate re-enable: `passwd -u <username>` on the endpoint.

**ossec.conf command:** `disable-account` (Wazuh built-in)

---

### 9. Firewall Drop IP
**Severity:** Medium &nbsp;|&nbsp; **Reversible:** Yes &nbsp;|&nbsp; **Auto-reverts:** 1 hour

**What it does:** Adds the source IP address from the triggering alert to iptables DROP rules. Uses Wazuh's built-in `firewall-drop` active-response. Blocks all traffic from `$(srcip)` at the firewall level.

**When to use:**
- C2 IP confirmed in the alert (rules 100950, 100601) — drop the specific attacker IP rather than isolating the entire host
- Port scan source (rule 100901) — block the scanner immediately
- Brute-force source — targeted block without disrupting the endpoint
- MISP IP blacklist match (rule 101002) — known malicious IP, block it specifically

**Platform support:** Linux (iptables)

**Difference from Isolate Host:** Firewall Drop IP blocks a *specific source IP* while leaving the endpoint fully functional for all other traffic. Isolate Host drops *all* traffic. Use Firewall Drop IP when you know the attacker's IP; use Isolate Host when the compromise is severe enough to warrant complete network removal.

**ossec.conf command:** `firewall-drop` (Wazuh built-in)

---

## Creating a Policy — Step by Step

### Step 1: Navigate to Endpoint Policies
From the sidebar: **Host Intelligence** → click the **🔒 Endpoint Policies** tab.

### Step 2: Open the Create Dialog
Click **+ New** in the top-left of the policy list panel.

### Step 3: Name and Describe the Policy
- **Policy Name** *(required)* — a clear, descriptive name. Examples:
  - `Ransomware Containment`
  - `USB Block — BYOD Fleet`
  - `C2 Detection Response`
  - `MFA Abuse — Account Lock`
- **Description** *(optional)* — describe when the policy applies, who owns it, or link to an incident response runbook.

### Step 4: Select Actions
Choose one or more actions from the grid. Each action shows:
- **Severity badge** (critical / high / medium / low) — indicates the impact level on the endpoint
- **Reversible / Irreversible** label — irreversible actions (Quarantine File) require analyst confirmation that the file is malicious
- **Description** — what the action does in plain language

**Combining actions:** Actions in a single policy all execute on the same target agents. For an incident response scenario:
- Ransomware response: `Isolate Host` + `Collect Forensics` + `Scan Endpoint`
- C2 detection: `Restrict Network` + `Collect Forensics` + `Firewall Drop IP`
- Insider threat: `Block USB` + `Block WiFi` + `Collect Forensics`

### Step 5: Set Scope
Choose who the policy targets when applied:

| Option | What to enter | Example |
|---|---|---|
| Specific Agents | Nothing — select at apply time | For ad-hoc response to a specific incident |
| All Active Endpoints | Nothing else needed | Organisation-wide USB lockdown |
| Agent Group | Select from the group dropdown | `BYOD`, `SERVERS`, `WORKSTATIONS` |
| Agent ID List | JSON array: `["001","002","003"]` | Fixed set of critical servers |

### Step 6: Configure Trigger Mode
**Manual only (default):** The policy only runs when you click "Apply Now". No changes to ossec.conf.

**Auto-trigger:** Toggle on, then enter the Wazuh rule IDs (comma-separated) that should trigger this policy. After saving, you must click **Sync to Wazuh** to write the `<active-response>` blocks to `ossec.conf` and restart wazuh-manager.

See the [Rule ID Reference](#rule-id-reference) section below for recommended rule→action pairings.

### Step 7: Save
Click **Create Policy**. The policy appears in the list immediately and is enabled by default.

---

## Applying a Policy Manually

### Apply to policy-scoped agents
1. Select the policy from the left panel
2. Click **▶ Apply Now** in the detail header
3. If the policy scope is **All Endpoints**, **Agent Group**, or **Agent ID List**: confirm in the modal
4. The engine calls Wazuh's `PUT /active-response` for each agent × each action
5. Results appear as a summary: `3 succeeded, 0 failed`

### Apply to specific agents (Specific Agents scope)
1. Select the policy → click **▶ Apply Now**
2. The modal shows a live list of all active Wazuh agents
3. Click individual agents to select them (multiple selection supported)
4. Click **Apply Now** — actions run only on the selected agents

### Viewing results after apply
After applying, switch to the **Execution History** tab in the detail panel. Each execution row shows:
- **Agent** — hostname of the target
- **Action** — which action was run
- **Trigger** — Manual (▶) or Auto (⚡)
- **Status** — ✓ success or ✗ failed
- **Error** — if failed, the error message from the Wazuh API or AR script
- **By** — which analyst triggered it
- **Time** — time ago

---

## Auto-Trigger Setup

Auto-trigger makes a policy respond automatically to specific alert types without analyst involvement. Use this for high-confidence, well-tuned rules only — it executes on every matched alert.

### Setup process:

1. Create the policy (or edit an existing one)
2. Toggle **Auto-trigger** ON
3. Enter the rule IDs that should fire this policy (comma-separated)
4. Save the policy
5. In the detail panel, click **Sync to Wazuh**

**What Sync to Wazuh does:**
1. Reads all enabled auto-trigger policies from the database
2. Generates `<active-response>` XML blocks for each policy × action × rule set
3. Injects them into a managed section of `ossec.conf` (marked `<!-- CyCentra Policy Engine: BEGIN/END MANAGED -->`)
4. Writes the updated `ossec.conf` back to Wazuh via the Wazuh REST API
5. Restarts `wazuh-manager` to pick up the new configuration

> **Important:** Sync is required after every change to an auto-trigger policy. The portal shows the current database state; the actual Wazuh behaviour reflects the last sync.

### Checking sync status
After sync, the modal reports:
- `policies_synced: N` — how many auto-trigger policies were included
- `blocks_generated: N` — total `<active-response>` blocks written
- `wazuh_restarted: true/false` — whether wazuh-manager restart succeeded

If `wazuh_restarted: false`, SSH to the manager and run `systemctl restart wazuh-manager` manually.

---

## Enabling and Disabling Policies

A policy can be enabled or disabled without deleting it. The enable/disable toggle is the green/grey dot in the policy detail header.

- **Disabled policy** — appears greyed out in the list; manual "Apply Now" still works but auto-trigger blocks are not generated on the next Sync
- **Re-enabling** — toggle back ON and run Sync to Wazuh again to restore auto-trigger

Use this to temporarily suspend a policy during maintenance windows or after a false positive investigation.

---

## Rule ID Reference

Recommended rule → policy action pairings based on CyCentra detection rules:

### Credential Attacks
| Rule ID | Detection | Recommended Actions |
|---|---|---|
| 100100 | Credential dumping tool (Mimikatz etc.) | Isolate Host, Collect Forensics |
| 100101 | Brute-force threshold (20 failures/60s) | Disable Account, Firewall Drop IP |
| 100102 | Kerberoasting activity | Collect Forensics, Restrict Network |
| 100103 | Credential file search | Collect Forensics |
| 100104 | DCSync replication attack | Isolate Host, Collect Forensics, Firewall Drop IP |
| 100400 | Pass-the-Hash | Isolate Host, Collect Forensics |
| 100800 | Token theft / privilege escalation | Collect Forensics, Restrict Network |
| 100801 | MFA push bombing (10 pushes/30min) | Disable Account |

### Malware & Ransomware
| Rule ID | Detection | Recommended Actions |
|---|---|---|
| 100203 | Shadow copy deletion (ransomware precursor) | Isolate Host, Collect Forensics, Scan Endpoint |
| 100202 | AV/Defender disabled | Scan Endpoint, Collect Forensics |
| 100600 | Cryptominer detected | Restrict Network, Scan Endpoint, Firewall Drop IP |
| 101003 | MISP hash blacklist match (known malware) | Quarantine File, Scan Endpoint |

### C2 / Exfiltration
| Rule ID | Detection | Recommended Actions |
|---|---|---|
| 100601 | C2 beacon detected | Restrict Network, Collect Forensics, Firewall Drop IP |
| 100602 | DGA / high-entropy DNS | Restrict Network, Collect Forensics |
| 100950 | C2 beacon confirmed (AR trigger) | Firewall Drop IP |
| 100951 | DCSync AR trigger | Firewall Drop IP |
| 100952 | Pass-the-Hash AR trigger | Firewall Drop IP |
| 100953 | Cryptominer AR trigger | Firewall Drop IP |
| 101002 | MISP IP blacklist match | Isolate Host, Firewall Drop IP |

### Persistence & Execution
| Rule ID | Detection | Recommended Actions |
|---|---|---|
| 100300 | Obfuscated PowerShell | Collect Forensics, Scan Endpoint |
| 100301 | WMI event subscription persistence | Collect Forensics |
| 100302 | Office macro / VBA execution | Scan Endpoint, Collect Forensics |
| 100500 | Startup folder write | Collect Forensics, Scan Endpoint |
| 100501 | Crontab modified | Collect Forensics |

### Removable Media
| Rule ID | Detection | Recommended Actions |
|---|---|---|
| 100910 | USB storage device connected (Windows built-in) | Block USB |
| 100911 | Sysmon: USBSTOR driver loaded | Block USB |

### Anti-Tamper (XDR)
| Rule ID | Detection | Recommended Actions |
|---|---|---|
| 101000 | Wazuh agent binary modified (Linux auditd) | Isolate Host, Collect Forensics |
| 101001 | Process injection / ptrace into Wazuh (Linux) | Isolate Host, Collect Forensics |
| 101010 | Wazuh agent service stopped (Windows EventID 7036) | Isolate Host |
| 101011 | Sysmon: CreateRemoteThread injection | Isolate Host, Collect Forensics |
| 101012 | Sysmon: LSASS memory access | Collect Forensics, Disable Account |
| 101013 | Sysmon: Process hollowing (EventID 25) | Isolate Host, Collect Forensics |
| 101020 | Wazuh agent tampered (macOS FIM) | Isolate Host, Collect Forensics |

---

## Pre-Built Policy Recipes

These recipes are ready to create as-is. Adapt rule IDs and scope to your environment.

### Recipe 1: Ransomware Containment
```
Name:          Ransomware Containment
Actions:       Isolate Host, Collect Forensics, Scan Endpoint
Scope:         All Active Endpoints
Auto-trigger:  YES
Rule IDs:      100203, 101002, 101003
```
Fires when shadow copy deletion is detected or a known-malicious file/IP is matched. Full isolation + evidence capture + scan runs immediately.

### Recipe 2: C2 Soft Block
```
Name:          C2 Network Restriction
Actions:       Restrict Network, Collect Forensics, Firewall Drop IP
Scope:         All Active Endpoints
Auto-trigger:  YES
Rule IDs:      100601, 100602, 100950
```
Softer than full isolation — cuts internet while preserving LAN so internal IR tools remain accessible. Drops the specific C2 IP.

### Recipe 3: USB Lockdown — BYOD Fleet
```
Name:          USB Block — BYOD
Actions:       Block USB Storage
Scope:         Agent Group: BYOD
Auto-trigger:  YES
Rule IDs:      100910, 100911
```
Immediately blocks USB when a storage device is detected on any BYOD-group endpoint.

### Recipe 4: MFA Abuse Response
```
Name:          MFA Push Bombing
Actions:       Disable Account
Scope:         All Active Endpoints
Auto-trigger:  YES
Rule IDs:      100801
```
Locks the user account automatically when 10+ MFA pushes are detected in 30 minutes.

### Recipe 5: Pre-Incident Forensics
```
Name:          Forensic Collection
Actions:       Collect Forensics
Scope:         Specific Agents (pick at apply time)
Auto-trigger:  NO
```
Manual-only policy for collecting volatile evidence before any remediation. Apply first, then apply a containment policy.

### Recipe 6: Credential Theft Response
```
Name:          Credential Theft — Full Response
Actions:       Isolate Host, Collect Forensics, Disable Account
Scope:         Specific Agents (pick at apply time)
Auto-trigger:  YES
Rule IDs:      100100, 100104, 100400
```
Full credential theft response: isolate the compromised host, collect evidence, and lock the victim account simultaneously.

### Recipe 7: Endpoint Threat Hunt
```
Name:          Threat Hunt Sweep
Actions:       Scan Endpoint, Collect Forensics
Scope:         Agent Group: SERVERS
Auto-trigger:  NO
```
Manual threat hunting: run across the server fleet on demand to sweep for dormant threats.

---

## Platform Support Matrix

| Action | Linux | macOS | Windows |
|---|---|---|---|
| Isolate Host | ✓ iptables / nftables | ✓ pfctl | ✓ Windows Firewall (via Wazuh) |
| Restrict Network | ✓ iptables / nftables | — | — |
| Block USB Storage | ✓ modprobe.d | ✓ kextutil (partial — SIP) | — (use MDM) |
| Block WiFi | ✓ nmcli / rfkill | ✓ networksetup | — (use MDM) |
| Quarantine File | ✓ | ✓ | — |
| Scan Endpoint | ✓ ClamAV + heuristic | ✓ ClamAV + heuristic | — |
| Collect Forensics | ✓ | ✓ | — |
| Disable Account | ✓ passwd -l | ✓ passwd -l | — (use AD admin) |
| Firewall Drop IP | ✓ iptables | ✓ pfctl (Wazuh built-in) | ✓ (Wazuh built-in) |

> **Windows gap:** Most custom AR scripts run only on Linux/macOS. Windows endpoint containment uses Isolate Host (Windows Firewall via Wazuh built-in), Firewall Drop IP, and Disable Account. USB/WiFi blocking on Windows endpoints requires an MDM policy (Intune / Jamf) triggered separately.

---

## Execution History

Every policy execution — whether manual or auto-triggered — is logged to the `endpoint_policy_executions` table in PostgreSQL and visible in the **Execution History** tab of each policy.

**Columns:**

| Column | Description |
|---|---|
| Agent | Hostname of the target endpoint |
| Action | The specific action that ran (a policy with 3 actions creates 3 rows per agent) |
| Trigger | Manual (▶) or Auto-triggered by a rule (⚡) |
| Status | ✓ success / ✗ failed / ○ pending |
| Error | If failed: the Wazuh API response or script error (truncated to 200 chars) |
| By | Email (username part) of the analyst who triggered it, or "system" for auto |
| Time | Relative time since execution |

**Filtering:** Use the Limit parameter in the API (`?limit=200`) for deeper history. Default shows last 50 executions.

**Interpreting failures:**
- `Wazuh credentials not configured` — `WAZUH_API_PASSWORD` not set in `cysiemstack.env`
- `Wazuh unreachable` — wazuh-manager is down or the API port (55000) is blocked
- `404` from Wazuh API — the agent ID no longer exists or was removed
- `Script not found` — the AR script was not deployed to `/var/ossec/active-response/bin/`. Re-run `cycentra-setup.sh --update`

---

## API Reference

All routes require an active portal session. All POST/PUT/DELETE require `analyst` role or higher. DELETE requires `admin`.

### List policies
```
GET /api/siem/endpoint-policies
Response: { "policies": [...], "total": N }
```

### Create policy
```
POST /api/siem/endpoint-policies
Body: {
  "name":          "string (required)",
  "description":   "string",
  "actions":       ["isolate_host", "collect_forensics"],
  "scope_type":    "local" | "all" | "group" | "agents",
  "scope_value":   "group-name" | '["001","002"]' | null,
  "auto_trigger":  false | true,
  "trigger_rules": [100203, 101002]
}
Response: { "policy": {...} }  HTTP 201
```

### Update policy
```
PUT /api/siem/endpoint-policies/<id>
Body: any subset of the create body fields
Response: { "policy": {...} }
```

### Delete policy
```
DELETE /api/siem/endpoint-policies/<id>
Response: { "ok": true }
```

### Apply policy (manual trigger)
```
POST /api/siem/endpoint-policies/<id>/apply
Body: { "agent_ids": ["001","002"] }  -- optional; omit to use policy scope
Response: {
  "ok": true,
  "agents_targeted": N,
  "actions_attempted": N,
  "successes": N,
  "failures": N
}
```

### Execution history
```
GET /api/siem/endpoint-policies/<id>/executions?limit=50
Response: { "executions": [...], "total": N }
```

### Sync auto-trigger policies to ossec.conf
```
POST /api/siem/endpoint-policies/sync
Response: {
  "ok": true,
  "policies_synced": N,
  "blocks_generated": N,
  "wazuh_restarted": true | false
}
```

### List available actions
```
GET /api/siem/endpoint-policies/actions
Response: { "actions": [{ "key": "isolate_host", "label": "...", "severity": "...", ... }] }
```

---

## Troubleshooting

### Policy shows "0 agents targeted" on apply
- **Scope is "Specific Agents":** You must select agents in the Apply modal. This scope never auto-resolves.
- **Scope is "Agent Group":** Verify the group name in the policy matches exactly what appears in the Agent Groups tab.
- **Scope is "All":** Check Wazuh API connectivity — if `WAZUH_API_PASSWORD` is missing, the agent list query returns empty.

### Apply returns "Wazuh credentials not configured"
Add to `/opt/cycentra/cysiemstack.env`:
```
WAZUH_API_URL=https://127.0.0.1:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=<password>
```
Restart: `systemctl restart cycentra-backend`

### Auto-trigger does not fire
1. Check the policy is enabled (green dot)
2. Verify you clicked **Sync to Wazuh** after adding rule IDs
3. Confirm the Sync reported `wazuh_restarted: true`
4. Check `/var/ossec/etc/ossec.conf` for the managed block between the `CyCentra Policy Engine: BEGIN/END MANAGED` markers
5. Verify the rule ID actually fires: `tail -f /var/ossec/logs/alerts/alerts.json | grep '"id":"<rule_id>"'`

### AR script not found on endpoint
- Symptom: `executions` table shows `success` but action has no effect
- Cause: AR script not deployed to `/var/ossec/active-response/bin/` on the agent's manager
- Fix: run `sudo bash cycentra-setup.sh --update` on the Wazuh manager — this copies all 7 scripts to `active-response/bin/`

### Isolate Host cannot be reversed remotely
If you isolated a host and lost Wazuh connectivity (port 1514 was blocked by another tool or the host firewall was independently modified):
1. Physical/console access required
2. Run: `iptables -D INPUT -j CY360_ISOLATION && iptables -D OUTPUT -j CY360_ISOLATION && iptables -F CY360_ISOLATION && iptables -X CY360_ISOLATION`
3. Or: `rm /var/ossec/var/run/cy360-isolation.lock` then run the script with `{"command":"delete"}` via stdin

### Sync fails with "cannot read ossec.conf from Wazuh API"
The Wazuh API endpoint `GET /manager/files` requires the API user to have the `manager:read` permission. Verify the `wazuh-wui` API user has the correct role in Wazuh security settings.

---

## Security Considerations

- **Least privilege:** Apply irreversible actions (Quarantine File) only in confirmed-malicious scenarios. Use the forensics-first approach — Collect Forensics before Quarantine File to preserve evidence of the original location.
- **Scope control:** "All Active Endpoints" scope on a Disable Account policy can lock every user account organisation-wide if a broadly-matching rule fires. Prefer narrower scopes for destructive actions.
- **Auto-trigger tuning:** Only attach auto-trigger to rules with low false-positive rates. Start with manual-only, review execution history for 2 weeks, then enable auto-trigger once you're confident the rule is well-tuned.
- **Irreversibility warning:** Quarantine File has `reversible: false`. The file is moved, not deleted — it can be manually restored — but the portal will not restore it automatically. This is by design to force analyst review before any restored file re-enters the filesystem.
- **Audit trail:** All executions (including who triggered them and when) are logged permanently in `endpoint_policy_executions`. This table is not pruned automatically — retain it for compliance audit purposes.
