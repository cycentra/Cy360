# Network Probe — User & Admin Guide

> CyCentra 360 v1.0.167+ · Introduced as part of the ITAM cloud-LAN scan fix

---

## The Problem This Solves

CyCentra 360 is cloud-hosted. Customer networks use private RFC-1918 subnets (`192.168.x.x`, `10.x.x.x`, `172.16–31.x.x`) that are not routable from the internet. When an admin clicks **Run IoT Scan**, **Run Subnet Scan**, **SNMP Scan**, or **Deep Scan** from the portal, the request runs on the cloud server — and every single one fails silently against private addresses.

**Network Probe** fixes this by deploying a lightweight scanning agent *inside* the customer LAN. All scan traffic originates from that internal host and reports back to the cloud server over standard outbound HTTPS. No inbound firewall rules, no VPN, no port forwarding required.

---

## Architecture

```
                    CUSTOMER NETWORK                        CLOUD
                 ┌──────────────────────┐            ┌───────────────┐
                 │                      │            │               │
  IoT devices   │  ┌────────────────┐  │  HTTPS     │  CyCentra 360 │
  Printers      │  │  CyEDR Agent   │◀─┼────────────│  (Cy360)      │
  SNMP switches │  │  (Probe mode)  │  │  (outbound │               │
  Linux hosts   │  │                │  │   only)    │  itam_scan_    │
  Windows hosts │  │  nmap          │──┼────────────▶  jobs table   │
                 │  │  snmpwalk      │  │            │               │
                 │  │  SSH (paramiko)│  │  Results   │  network_     │
                 │  │  WinRM         │──┼────────────▶  assets table │
                 │  └────────────────┘  │            │               │
                 │     192.168.x.x/24   │            └───────────────┘
                 └──────────────────────┘

Flow: Portal button click → Cy360 creates job → Probe polls + claims job →
      Probe scans LAN locally → Probe POSTs result → Cy360 ingests into ITAM
```

**Key design constraints:**
- One probe per network segment (one /24 = one probe agent)
- Multiple probe agents = duplicate ITAM asset rows (avoid)
- All scans are non-destructive read-only operations
- The probe thread only starts when the `network_probe` policy is active — zero overhead otherwise

---

## What Scan Types Are Supported

| Scan Button | Where | Works via Probe | Fallback (no probe) |
|---|---|---|---|
| **Run IoT Scan** | ITAM → IoT Registry | Yes — nmap | Cloud nmap (fails for RFC-1918) |
| **Run Subnet Scan** | ITAM → Asset Coverage | Yes — nmap | Cloud nmap (fails for RFC-1918) |
| **SNMP Scan** | Asset detail page | Yes — snmpget/snmpwalk | Cloud SNMP (fails for RFC-1918) |
| **Deep Scan** | Asset detail page | Yes — SSH/WinRM | Cloud SSH (fails for RFC-1918) |

---

## Prerequisites

Before configuring a probe, ensure the following are in place:

### On the probe host
- CyEDR agent installed and enrolled (any active agent in the target LAN)
- `nmap` installed — required for Subnet/IoT scans
- `snmpget` / `snmpwalk` installed — required for SNMP scans (`apt install snmp` or `yum install net-snmp-utils`)
- SSH access to Linux/macOS hosts — requires credentials set in ITAM settings
- WinRM access to Windows hosts — requires credentials set in ITAM settings

The CyEDR installer (v1.0.167+) installs `nmap` and SNMP tools automatically. On older installs, run:

```bash
# Debian/Ubuntu
apt-get install -y nmap snmp

# RHEL/CentOS/Fedora
yum install -y nmap net-snmp-utils

# macOS
brew install nmap net-snmp
```

On Windows, the installer tries `winget install Insecure.Nmap` then chocolatey. Manual: https://nmap.org/download.html

### On Cy360 (for Deep Scan only)
SSH/WinRM credentials must be configured so the probe can retrieve them at scan time:
**Settings → Modules → Asset Management → SSH / WinRM Credentials**

---

## Step 1 — Configure SSH/WinRM Credentials (Admin)

> **Required for Deep Scan only.** IoT Scan and SNMP Scan do not need credentials.

Navigate to **Settings → Modules → Asset Management**.

| Field | Purpose | Example |
|---|---|---|
| **SSH Username** | Username for SSH login to Linux/macOS hosts | `ubuntu`, `root`, `svc-scan` |
| **SSH Password** | Password (stored encrypted in DB) | _(enter and save)_ |
| **SSH Key Path** | Absolute path to private key on the **probe agent host** | `/opt/cycentra/.ssh/scan_key` |
| **SSH Port** | Default 22; change if hosts use non-standard port | `22` |
| **WinRM Username** | Windows admin username | `Administrator`, `DOMAIN\scan` |
| **WinRM Password** | WinRM password | _(enter and save)_ |
| **WinRM Port** | Default 5985 (HTTP) or 5986 (HTTPS) | `5985` |
| **WinRM SSL** | Enable HTTPS transport for WinRM | `false` (default) |

**Important:**
- The portal shows `•STORED•` once a password is saved — this is intentional. Re-entering a new value replaces it; leaving the field blank keeps the existing stored value.
- Credentials are retrieved by the probe agent at scan time over the existing encrypted, token-authenticated channel. They are never stored in the scan job table.
- If SSH Key Path is set, it takes priority over password for SSH authentication. The key must exist at that path on the probe agent host, not on the Cy360 server.
- WinRM falls back to SSH credentials if separate WinRM credentials are not set.

---

## Step 2 — Install CyEDR on a LAN Host

Pick **one host per network segment** to act as the probe. Requirements:

- Always-on (server, NAS, management workstation — not a laptop)
- Has IP connectivity to the full target subnet
- Outbound HTTPS to the Cy360 server URL (port 443)
- Linux, macOS, or Windows

Install CyEDR using the standard installer from **Endpoint Defence → Agent Installer**:

```bash
# Linux/macOS
sudo bash -c "$(curl -fsSL https://your-cy360-url/api/edr/installer/unix)" -- \
  --platform https://your-cy360-url --token YOUR_DEPLOY_TOKEN
```

```powershell
# Windows (PowerShell as Administrator)
iex (irm https://your-cy360-url/api/edr/installer/win) `
  -Platform https://your-cy360-url -Token YOUR_DEPLOY_TOKEN
```

Confirm the agent appears in **Endpoint Defence → Fleet** with status **Active** before proceeding.

---

## Step 3 — Deploy the Network Probe Policy

This is the step that activates probe mode on the chosen agent.

Navigate to **Endpoint Defence → Policies → New Policy** (or edit an existing policy assigned to this agent).

1. Set **Policy Type** to **Network Probe**
2. Configure the policy fields (see full reference below)
3. Set **Enabled** to **On**
4. **Apply the policy** to the specific probe agent

Within 60 seconds the agent picks up the policy, starts the `NetworkProbePoller` thread, and sends a heartbeat with `probe_active: true`. The probe now appears in the **ITAM → IoT Registry** banner as active.

### Policy Field Reference

| Field | Default | Description |
|---|---|---|
| **Enabled** | Off | Master toggle. Off = probe thread stops immediately, no scan activity. |
| **Subnet (CIDR)** | _(blank = auto-detect)_ | The subnet this probe should scan, e.g. `192.168.1.0/24`. Leave blank to auto-detect from the agent's own IP (derives `/24` from its primary interface). |
| **Scan Interval (minutes)** | 60 | How often the probe auto-scans its subnet without waiting for a manual trigger. Set to `0` to disable scheduled scans entirely (on-demand only). |
| **Scan Types** | `subnet` | Which scan methods to include in auto-scans. `subnet` = nmap host discovery. `snmp` = SNMP polling (planned — grayed out in UI, enable manually via policy JSON). |
| **Ports** | `22,23,80,443,554,631,8080,8883,9100,161,502,47808` | Port list passed to nmap during subnet scans. Covers common IoT, web, SCADA, and management protocols. |
| **SNMP Community** | `public` | SNMPv2c community string for SNMP scan jobs. |
| **SNMP Port** | `161` | UDP port for SNMP queries. |
| **DNS Monitor** | Off | Reserved for future release — passive DNS change detection inside the LAN. |

### Recommended Settings by Use Case

**Office network (100–200 hosts, general asset discovery):**
```
Enabled: On
Subnet: 192.168.1.0/24
Scan Interval: 60
Scan Types: subnet
Ports: 22,80,443,8080,3389,5985
```

**Factory / OT network (IoT + SCADA devices):**
```
Enabled: On
Subnet: 10.0.10.0/24
Scan Interval: 120
Scan Types: subnet
Ports: 22,23,80,443,502,4840,47808,102,2404,20000,44818
```

**On-demand only (no scheduled scans, just respond to manual triggers):**
```
Enabled: On
Subnet: 172.16.0.0/24
Scan Interval: 0
```

---

## How Each Scan Works After Probe Is Active

### IoT Scan (ITAM → IoT Registry → Run IoT Scan)

1. Portal sends `POST /api/itam/iot/scan` with the configured subnet
2. Backend calls `_get_active_probe_for_subnet()` — finds probe whose subnet overlaps the target
3. Inserts a `subnet` job into `itam_scan_jobs` with status `queued`
4. Returns immediately with `{mode: "probe"}` — UI shows cyan "Scanning via Network Probe" message
5. Probe polls `/api/itam/probe/jobs` every 30 seconds, claims the job
6. Probe runs `nmap -sn -PS22,80,443 --open -p <ports> -oX - --host-timeout 5s <subnet>`
7. Probe POSTs raw nmap XML to `/api/itam/probe/jobs/<id>/result`
8. Server parses XML → upserts `network_assets` → classifies IoT devices → `iot_devices` table updated

**UI:** Reload IoT Registry after ~60 seconds to see new devices.

### Subnet Scan (ITAM → Asset Coverage → Run Subnet Scan)

Identical flow to IoT Scan — same job type (`subnet`), same nmap command, result populates `network_assets` with `discovery_source='nmap'`. Both the asset list and coverage gap analysis update.

### SNMP Scan (Asset Detail Page → SNMP Scan button)

1. Portal sends `POST /api/itam/assets/<id>/snmp-scan`
2. Backend checks if the asset's IP is covered by a probe
3. Inserts an `snmp` job with params `{asset_id, community, port}`
4. Probe claims job, runs `snmpget` for system OIDs (description, hostname, location, uptime)
5. POSTs result back; server writes `os_info`, `hostname`, and `notes` columns on the asset

**Requirements:** `snmpget` and `snmpwalk` must be installed on the probe host. The target device must have SNMP enabled and respond to the configured community string (`public` by default).

**What gets collected:**
- System description (device type / firmware version)
- System hostname
- System location
- Object ID (device classification)
- Uptime in seconds

### Deep Scan (Asset Detail Page → Deep Scan button)

Deep scan collects full OS-level inventory: installed packages with versions, running services, listening ports, and local users.

1. Portal sends `POST /api/itam/assets/<id>/deep-scan`
2. Backend detects RFC-1918 target IP + active probe covering that subnet
3. Inserts a `deep_scan` job with params `{asset_id, target_ip}` — credentials are **not** stored in the job
4. Asset status changes to `scanning` immediately in the DB
5. Probe claims the job; separately fetches credentials via `GET /api/itam/probe/creds` (Bearer token, HTTPS)
6. Probe attempts **SSH first** (via paramiko):
   - Connects to the target IP with the configured username/password or key
   - Runs package, service, port, and user enumeration commands
7. If SSH fails, probe attempts **WinRM** (via pywinrm):
   - Connects via HTTP or HTTPS to WinRM endpoint
   - Runs PowerShell equivalents of the same inventory commands
8. Probe POSTs the full result back; server writes all inventory fields to `network_assets`

**UI feedback:** "Deep scan dispatched to Network Probe (hostname) — results appear in 30–90 seconds."  
Reload the asset detail page after ~90 seconds.

**What gets collected:**
| Field | Source |
|---|---|
| Hostname | `hostname` command or `$env:COMPUTERNAME` |
| OS info | `/etc/os-release` or `Get-WmiObject Win32_OperatingSystem` |
| Hardware | CPU info, memory, disk |
| Packages | `dpkg -l` / `rpm -qa` / `Get-Package` (up to 500) |
| Services | Running systemd units / WinRM `Get-Service` |
| Listening ports | `ss -tlnup` / `Get-NetTCPConnection -State Listen` |
| Local users | `getent passwd` (UID ≥ 1000) / `Get-LocalUser` |

CVE enrichment runs automatically after package ingestion (requires NVD API key in settings).

---

## Checking Probe Status

### Via Portal (ITAM → IoT Registry)

A banner at the top of the IoT Registry page shows:
- **Cyan banner (Network Probe active):** Hostname of the probe agent + time of last scan. All scan buttons will route through the probe automatically.
- **Amber banner (No Network Probe configured):** Link to Policies page to set one up.

### Via API

```
GET /api/itam/probe/status
Authorization: session cookie (viewer role or above)
```

Returns all agents with `probe_policy_active = true`:
```json
{
  "probes": [
    {
      "agent_id": "ag-abc123",
      "hostname": "mgmt-server-01",
      "probe_subnet": "192.168.1.0/24",
      "probe_last_scan": "2026-07-02T10:30:00Z",
      "probe_policy_active": true,
      "last_seen": "2026-07-02T11:00:00Z"
    }
  ]
}
```

### Via Fleet page

In **Endpoint Defence → Fleet**, agents with an active probe policy display their probe subnet in the detail modal. The `probe_active` and `probe_subnet` fields are visible in the heartbeat payload.

---

## Performance Impact

The probe is designed for minimal impact on the host it runs on:

| Concern | How it's handled |
|---|---|
| Idle overhead | Zero — probe thread only starts when `network_probe` policy is active. Disabled agents use zero extra CPU/memory. |
| nmap scan load | nmap runs as an external subprocess. `--host-timeout 5s` caps time per host. A full /24 scan takes 30–120s total. |
| SSH/WinRM scan | Runs in its own daemon thread — does not block the poll loop or delay other jobs. Slow SSH targets do not queue up. |
| SNMP scan | 3 subprocess calls per device, each with 3-second timeout. Completes in under 10 seconds per device. |
| Memory | paramiko and pywinrm are lazy-imported inside the scan method — they are not loaded into memory until a deep scan job actually arrives. |
| Poll loop | Polls `/api/itam/probe/jobs` every 30 seconds. Each poll is a single HTTPS GET with a 15-second timeout. |
| Auto-scan interval | Defaults to 60 minutes. Set to 0 for on-demand-only if you want zero background activity. |

---

## Policy Deployment and Rollback

### Apply a Network Probe policy

1. **Endpoint Defence → Policies → Create Policy**
2. Type: **Network Probe**
3. Fill in fields (see reference above)
4. Click **Apply to Agent** — select the designated probe host
5. The agent picks up the policy within 60 seconds on its next command poll

The policy is persisted to `policy_state.json` on the agent host — it **survives agent restarts**. On restart, the agent auto-starts the `NetworkProbePoller` thread if the policy was active when it last ran.

### Disable probe (without deleting policy)

Edit the policy → set **Enabled** to **Off** → re-apply to the agent. The probe thread stops within 60 seconds. No further jobs are claimed or scans triggered.

### Move probe to a different agent

1. Disable the existing policy on the current agent (set Enabled = Off, apply)
2. Confirm `probe_policy_active` shows false in the Fleet page
3. Create or copy the policy; apply to the new agent

**Do not run two probe agents on the same /24.** Both will claim and execute the same scan jobs, creating duplicate `network_assets` rows.

### Upgrade requirement

If you are running agent binaries built before v1.0.167, those agents will silently ignore the `network_probe` policy type (no error, just no probe thread). You must rebuild and redeploy agent binaries using `build-edr-packages.sh` to include the probe capability and the bundled paramiko/pywinrm libraries.

---

## Troubleshooting

### Probe not appearing in IoT Registry banner

**Check 1:** Is the policy enabled? Go to Policies, find the network_probe policy, confirm Enabled = On and it's applied to the correct agent.

**Check 2:** Is the agent active? Fleet page shows last heartbeat. If last seen > 5 minutes ago, the agent may be offline.

**Check 3:** Did the policy apply? SSH to the probe host and check:
```bash
cat /opt/cycentra/cyedr/policy_state.json | python3 -m json.tool | grep -A5 network_probe
```
If `network_probe` is absent or `enabled` is false, the policy hasn't applied yet. Wait 60 seconds and check the agent log:
```bash
tail -f /opt/cycentra/cyedr/logs/cyedr.log | grep -i probe
```

---

### Scan button shows "No Network Probe configured" warning

The scan request fell through to the cloud server because no probe agent covers the target subnet. This means either:
- No probe policy is deployed (go to Step 3 above)
- The probe's configured subnet doesn't overlap with the target IP — check the `Subnet (CIDR)` field in the policy

---

### IoT/Subnet scan returns 0 devices

**Check 1: nmap installed?**
```bash
which nmap || echo "nmap not found"
```
Install: `apt install nmap` / `yum install nmap` / `brew install nmap`

**Check 2: Can nmap reach the subnet?**
```bash
nmap -sn 192.168.1.0/24
```
If this returns no hosts, there's a routing or firewall issue on the probe host itself.

**Check 3: Check probe agent log for nmap error**
```bash
grep -i "nmap\|probe" /opt/cycentra/cyedr/logs/cyedr.log | tail -20
```

---

### SNMP Scan returns "snmpget not found"

Install SNMP tools on the probe host:
```bash
# Debian/Ubuntu
apt-get install -y snmp

# RHEL/CentOS
yum install -y net-snmp-utils

# macOS
brew install net-snmp
```

---

### Deep Scan fails with "No SSH username configured"

SSH/WinRM credentials have not been saved in ITAM settings. Go to:
**Settings → Modules → Asset Management → SSH Credentials**

Enter username and password (or key path), click **Save**. The probe fetches credentials fresh from the server on each deep scan job — no agent restart needed.

---

### Deep Scan fails with SSH "Authentication failed" or "Connection refused"

- Confirm the SSH username and password/key are correct for the target host
- Confirm port 22 is open: `nmap -p 22 <target_ip>` from the probe host
- If using a key, confirm the private key exists at the configured path **on the probe host** (not the Cy360 server)
- For Windows targets: Deep Scan automatically falls back to WinRM if SSH fails. Confirm WinRM is enabled on the target: `winrm quickconfig`

---

### Deep Scan result shows packages = 0

This usually means the package manager command wasn't recognized. The probe tries `dpkg -l`, `rpm -qa`, and `brew list --versions` in order. For Alpine Linux, add `apk info -v` manually. For Windows, `Get-Package` requires the PackageManagement module — it should be present on modern Windows.

---

## Security Notes

- **Credentials at rest:** SSH/WinRM passwords are stored in the `itam_settings` PostgreSQL table (same DB as all other settings). Access requires admin role.
- **Credentials in transit:** The probe retrieves credentials via `GET /api/itam/probe/creds` over HTTPS, authenticated with the agent's enrollment Bearer token. Credentials are never stored in the `itam_scan_jobs` table.
- **Scan jobs:** Only the designated probe agent (matched by enrollment token) can claim and complete its jobs. Other agents cannot see or claim jobs that aren't theirs.
- **Scan scope:** nmap uses `-sn` (ping scan, no port scan unless ports are listed) and `--host-timeout 5s`. It does not attempt exploitation or service fingerprinting beyond the configured port list.
- **SSH host key policy:** The probe uses paramiko with `AutoAddPolicy` — it does not verify host keys. This is appropriate for trusted internal subnets but means the probe is susceptible to MITM within the LAN. For high-security environments, pre-populate known_hosts on the probe host and restrict the policy setting.
