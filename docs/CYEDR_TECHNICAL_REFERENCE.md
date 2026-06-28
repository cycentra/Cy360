# CyEDR — Complete Technical Reference

**Document version:** 1.0  
**Date:** 2026-06-28  
**Status:** Phase 1 implementation complete (Python bridge sensor + full platform)  
**Audience:** Engineers, Operators, Security Analysts, Technical Writers  
**Companion doc:** [CYEDR_ARCHITECTURE.md](CYEDR_ARCHITECTURE.md) — Architecture strategy, comparison charts, sensor roadmap

---

## Table of Contents

1. [What Was Built (Implementation Summary)](#1-what-was-built-implementation-summary)
2. [File Map — Every File That Matters](#2-file-map--every-file-that-matters)
3. [Installation Guide](#3-installation-guide)
   - 3.1 [Server-Side Prerequisites](#31-server-side-prerequisites)
   - 3.2 [Linux / macOS (Quick Install)](#32-linux--macos-quick-install)
   - 3.3 [Windows (Quick Install)](#33-windows-quick-install)
   - 3.4 [Enterprise Package Deployment](#34-enterprise-package-deployment)
   - 3.5 [Air-Gap / Offline Installation](#35-air-gap--offline-installation)
   - 3.6 [Deploying with CySIEM Together](#36-deploying-with-cysiem-together)
4. [Agent Configuration Reference (config.json)](#4-agent-configuration-reference-configjson)
5. [Telemetry Schema (TelemetryEnvelope)](#5-telemetry-schema-telemetryenvelope)
6. [Detection Engine Reference](#6-detection-engine-reference)
   - 6.1 [The 19 Heuristic Triggers](#61-the-19-heuristic-triggers)
   - 6.2 [Confidence Matrix Formula](#62-confidence-matrix-formula)
   - 6.3 [Asset Criticality Multipliers](#63-asset-criticality-multipliers)
   - 6.4 [Severity Bands](#64-severity-bands)
7. [SIEM Integration — How Logs Flow](#7-siem-integration--how-logs-flow)
   - 7.1 [Pipeline Stages](#71-pipeline-stages)
   - 7.2 [Redis Queue Format](#72-redis-queue-format)
   - 7.3 [Wazuh Rules Deployed](#73-wazuh-rules-deployed)
   - 7.4 [Dual Ownership: CyEDR vs Wazuh](#74-dual-ownership-cyedr-vs-wazuh)
8. [Response Actions Reference](#8-response-actions-reference)
9. [Policy Engine Reference](#9-policy-engine-reference)
10. [API Endpoint Reference](#10-api-endpoint-reference)
11. [Database Schema](#11-database-schema)
12. [Package Distribution](#12-package-distribution)
13. [Anti-Tamper & Hardening](#13-anti-tamper--hardening)
14. [Troubleshooting Guide](#14-troubleshooting-guide)
15. [Enhancement Guide (for future developers)](#15-enhancement-guide-for-future-developers)
16. [Quick Reference Cards](#16-quick-reference-cards)

---

## 1. What Was Built (Implementation Summary)

CyEDR Phase 1 is a complete, production-deployed Endpoint Detection & Response system. Every component below is live code.

### Platform Components (Backend + Frontend)

| Component | File | Purpose |
|-----------|------|---------|
| API Blueprint | `backend/blueprints/edr/routes.py` | All `/api/edr/*` routes — dual auth (session + Bearer token) |
| Detection Normaliser | `backend/blueprints/edr/normalizer.py` | Maps TelemetryEnvelope → SIEM alert dict |
| Confidence Matrix | `backend/blueprints/edr/confidence_matrix.py` | 19 triggers × weights × asset modifier → 0–100 score |
| Response Orchestrator | `backend/blueprints/edr/response_orchestrator.py` | Command queue, auto-respond rules |
| Policy Engine | `backend/blueprints/edr/policy_engine.py` | 7 policy types, deployment tokens, agent groups |
| SIEM Bridge | `backend/cysiemstack/edr_bridge.py` | Pushes normalized alert to Redis queue, auto-opens CyCases |
| Fleet Page | `portal/src/pages/edr/EdrFleetPage.jsx` | Agent health cards, fleet stats, quick actions |
| Detections Page | `portal/src/pages/edr/EdrDetectionsPage.jsx` | Behavioral event feed, MITRE tags, analyst status |
| Endpoint Detail | `portal/src/pages/edr/EdrEndpointDetailPage.jsx` | Forensic timeline, response commands, policies |
| Policies Page | `portal/src/pages/edr/EdrPoliciesPage.jsx` | Policy builder (7 types), assign to agents/groups |
| Installer Page | `portal/src/pages/edr/EdrAgentInstallerPage.jsx` | Deployment tokens, OS+arch selector, install commands |
| OS Logo Components | `portal/src/components/OsLogo.jsx` | Official OS logos + CyCentra brand SVG components |
| Brand Logo | `portal/public/cycentra-logo.svg` | CyCentra 360 official SVG (CY monogram + tagline) |

### Agent Components (Endpoint)

| Component | File | Purpose |
|-----------|------|---------|
| Python Bridge Daemon | `agent/cyedr_agent.py` | The endpoint agent — reads OS events, scores, sends telemetry, executes response |
| Linux Installer | `scripts/cyedr-install.sh` | Installs CyEDR on Linux and macOS with arch-specific binary |
| Windows Installer | `scripts/cyedr-install.ps1` | Installs CyEDR on Windows (Sysmon, YARA, service) |
| Package Builder | `agent-packages/build-edr-packages.sh` | PyInstaller cross-compile → DEB/RPM/MSI/PKG |
| Package Downloader | `agent-packages/download-packages.sh` | Downloads Wazuh packages + stages CyEDR packages |

### SIEM Configuration Changes

| File | Change Made |
|------|-------------|
| `CYSIEM-Config/agent_config/agent.conf` | Removed Sysmon localfile block (CyEDR owns Sysmon now) |
| `CYSIEM-Config/rules/cy_cust_rules.xml` | Added rules 101030 (CyEDR Linux tamper), 101031 (CyEDR Windows service stop); removed dead Sysmon rules 100911, 101001, 101011, 101012, 101013; updated rule 101003 field path |
| `scripts/integrate_sysmon.sh` | Removed deploy_sysmon.ps1 generation; updated rule 100303 for CyEDR telemetry field |
| `cycentra-setup.sh` | Updated AR block rules_id; migration guard for stale configs; /edr-packages/ NGINX block; updated post-install notes |

---

## 2. File Map — Every File That Matters

```
Cy360/
├── agent/
│   └── cyedr_agent.py              ← The endpoint agent (976 lines, Phase 1 bridge)
│
├── agent-packages/
│   ├── build-edr-packages.sh       ← PyInstaller build: 8 arch/OS packages
│   └── download-packages.sh        ← Downloads Wazuh + stages CyEDR packages
│
├── backend/
│   └── blueprints/
│       └── edr/
│           ├── routes.py            ← All /api/edr/* endpoints (~1,600 lines)
│           ├── normalizer.py        ← TelemetryEnvelope → SIEM alert
│           ├── confidence_matrix.py ← 19 heuristic triggers + scoring
│           ├── response_orchestrator.py ← Command queue + auto-respond
│           └── policy_engine.py     ← 7 policy types + deployment tokens
│   └── cysiemstack/
│       └── edr_bridge.py           ← Redis push + CyCases auto-open
│
├── CYSIEM-Config/
│   ├── agent_config/
│   │   └── agent.conf              ← Wazuh agent config (Sysmon block removed)
│   └── rules/
│       └── cy_cust_rules.xml       ← Custom Wazuh rules (101030/101031 added)
│
├── portal/public/
│   └── cycentra-logo.svg           ← Official CyCentra SVG brand asset
│
├── portal/src/
│   ├── components/
│   │   └── OsLogo.jsx              ← WindowsLogo/AppleLogo/LinuxLogo/CyCentraEDRBadge
│   └── pages/edr/
│       ├── EdrAgentInstallerPage.jsx ← Token mgmt, OS/arch selector, install commands
│       ├── EdrFleetPage.jsx          ← Agent fleet view
│       ├── EdrDetectionsPage.jsx     ← Detection feed
│       ├── EdrEndpointDetailPage.jsx ← Per-agent forensic detail
│       └── EdrPoliciesPage.jsx       ← Policy management
│
├── scripts/
│   ├── cyedr-install.sh            ← Linux/macOS installer (arch-aware, no venv)
│   ├── cyedr-install.ps1           ← Windows installer (arch-aware, no Python)
│   ├── agent-installer.sh          ← CySIEM Agent Manager — smart detect/install/upgrade/uninstall
│   └── integrate_sysmon.sh         ← Sysmon DC policy (points to CyEDR, not Wazuh)
│
└── cycentra-setup.sh               ← Main platform installer (NGINX blocks, AR rules)
```

### Runtime Paths on an Enrolled Endpoint

```
Linux / macOS:
  /opt/cycentra/edr/
  ├── cyedr-agent          ← PyInstaller standalone binary
  ├── config.json          ← Agent config (chmod 600)
  ├── logs/
  │   └── cyedr_agent.log
  ├── quarantine/          ← Quarantined files (chmod 700)
  ├── yara_rules/
  │   └── cycentra.yar    ← YARA rules bundle
  └── ioc_cache/
      └── ioc.json         ← Local IOC hash/IP/domain cache

Windows:
  C:\Program Files\CyCentra\edr\
  ├── cyedr-agent.exe      ← PyInstaller standalone binary
  ├── config.json
  ├── logs\
  ├── quarantine\
  └── yara_rules\
  C:\Program Files\CyCentra\sysmon\
  ├── Sysmon64.exe
  └── cycentra_sysmon_config.xml

Platform server:
  /var/lib/cycentra-agent-packages/        ← CySIEM Agent packages (cy360-agent-*.*)
  /var/lib/cycentra-agent-packages/edr/    ← CyEDR packages (cyedr-agent-*.*)
```

---

## 3. Installation Guide

### 3.1 Server-Side Prerequisites

Before deploying agents, ensure the platform is ready:

**1. Create a deployment token** (admin only):

```
CyCentra 360 Portal → EDR → Agent Installer → New Deployment Token
```

Or via API:
```bash
curl -X POST https://cy360.{domain}/api/edr/installer/token \
  -H "Cookie: session=<admin-session>" \
  -H "Content-Type: application/json" \
  -d '{"label":"Production Linux servers","os_type":"LINUX","max_uses":50,"expires_hours":72}'
# Response: {"token":"eyJ...","id":"...","label":"..."}
```

**2. Verify NGINX serves the installer scripts:**
```bash
curl -fsSL https://cy360.{domain}/api/edr/installer/unix | head -5
# Should return the cyedr-install.sh script
```

**3. Verify CyEDR packages are built** (for package-based installs):
```bash
ls /var/lib/cycentra-agent-packages/edr/
# Should show: cyedr-agent-linux-x86_64, cyedr-agent-linux-aarch64, *.deb, *.rpm, etc.
# If empty: sudo bash /opt/cycentra/agent-packages/build-edr-packages.sh
```

---

### 3.2 Linux / macOS (Quick Install)

The one-liner installs CyEDR on Linux and macOS. Automatically detects OS type and architecture.

**Minimum command:**
```bash
curl -fsSL https://cy360.{domain}/api/edr/installer/unix | \
  sudo bash -s -- \
    --token "eyJ..." \
    --platform "https://cy360.{domain}"
```

**Full options:**
```bash
curl -fsSL https://cy360.{domain}/api/edr/installer/unix | \
  sudo bash -s -- \
    --token "eyJ..." \
    --platform "https://cy360.{domain}" \
    --asset-type domain_controller \
    --with-cysiem \
    --silent
```

**Options:**

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--token` | `<deploy-token>` | (required) | Deployment token from portal |
| `--platform` | `https://...` | (required) | CyCentra 360 base URL |
| `--asset-type` | `workstation`, `server`, `database`, `domain_controller`, `api_gateway`, `jump_server` | `workstation` | Asset classification (affects confidence scoring) |
| `--with-cysiem` | (flag) | prompt | Also install CySIEM Agent on this endpoint |
| `--no-cysiem` | (flag) | prompt | Skip CySIEM without asking |
| `--silent` | (flag) | false | Non-interactive; implies `--no-cysiem` unless `--with-cysiem` set |

**What the installer does:**

1. Detects OS (`uname -s`) → `LINUX` or `MACOS`
2. Detects architecture (`uname -m`) → `x86_64`/`aarch64`
3. Installs system dependencies (auditd, YARA, curl, python3)
4. Downloads arch-specific pre-built agent binary from `GET /api/edr/installer/agent-bundle?os=LINUX&arch=x86_64` using the deployment token
5. Downloads YARA rules bundle from `GET /api/edr/installer/yara-rules`
6. Writes `config.json` with platform URL, token, asset type, hostname
7. **Linux only:** deploys auditd rules (`/etc/audit/rules.d/60-cyedr.rules`) with `cy360_edr_*` key namespace; installs `cyedr-agent.service` + `cyedr-watchdog.timer`
8. **macOS only:** installs LaunchDaemon at `/Library/LaunchDaemons/com.cycentra.edr.plist`
9. Enrolls with platform via `POST /api/edr/agents/self-enroll`, saves `agent_id` to `config.json`
10. Optionally installs CySIEM Agent via `GET /api/edr/installer/cysiem-script`
11. Hardens permissions (`chmod 600 config.json`, `chmod 700 quarantine/`)
12. Starts service

**Verify installation:**
```bash
# Linux
systemctl status cyedr-agent
journalctl -u cyedr-agent -n 30 --no-pager

# macOS
launchctl list com.cycentra.edr
tail -50 /opt/cycentra/edr/logs/cyedr_agent.log
```

---

### 3.3 Windows (Quick Install)

Run as Administrator in PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol = "Tls12"
iwr "https://cy360.{domain}/api/edr/installer/win" -UseBasicParsing | iex
cyedr-install.ps1 -Token "eyJ..." -Platform "https://cy360.{domain}"
```

**Full options:**
```powershell
.\cyedr-install.ps1 `
  -Token "eyJ..." `
  -Platform "https://cy360.{domain}" `
  -AssetType domain_controller `
  -WithCySIEM `
  -Silent
```

**Parameters:**

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `-Token` | `<deploy-token>` | (required) | Deployment token |
| `-Platform` | `https://...` | (required) | Platform base URL |
| `-AssetType` | `workstation`, `server`, `database`, `domain_controller`, `api_gateway`, `jump_server` | `workstation` | Asset type for scoring |
| `-WithCySIEM` | (switch) | prompt | Install Wazuh alongside CyEDR |
| `-NoCySIEM` | (switch) | prompt | Skip Wazuh |
| `-Silent` | (switch) | false | Non-interactive |

**What the installer does:**

1. Detects architecture (`$env:PROCESSOR_ARCHITECTURE` → `x64` or `arm64`)
2. Checks Windows admin rights
3. Creates `C:\Program Files\CyCentra\edr\` with restricted ACLs (SYSTEM + Administrators only)
4. Downloads arch-specific MSI from `/edr-packages/cyedr-agent-latest-{arch}.msi` (enterprise path)
   - Falls back to standalone exe from `/api/edr/installer/agent-bundle?os=WINDOWS&arch={arch}`
5. Downloads Sysmon64.exe + `cycentra_sysmon_config.xml` from platform, installs/updates Sysmon
6. Downloads YARA exe and rules bundle
7. Enables PowerShell Script Block Logging (HKLM ScriptBlockLogging)
8. Writes `config.json`
9. Applies anti-tamper ACLs (deny BUILTIN\Users write to EDR home)
10. Enrolls with platform via self-enroll API
11. Creates `CyEDRAgent` Windows service (NSSM if present, else `sc.exe`)
12. Optionally installs CySIEM (downloads Wazuh MSI from `/api/edr/installer/cysiem-msi`)
13. Starts service

**Verify installation:**
```powershell
Get-Service CyEDRAgent
Get-Service Sysmon64
Get-EventLog Application -Source CyEDRAgent -Newest 10
```

---

### 3.4 Enterprise Package Deployment

For organizations with MDM (JAMF, Intune, Ansible, SCCM):

**Linux DEB (Ubuntu/Debian):**
```bash
# amd64
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  "https://cy360.{domain}/api/edr/installer/agent-bundle?os=LINUX&arch=amd64" \
  -o cyedr-agent.deb
dpkg -i cyedr-agent.deb
systemctl enable --now cyedr-agent
# Then run enrollment separately:
/usr/local/bin/cyedr-agent --enroll \
  --token "$TOKEN" \
  --platform "https://cy360.{domain}" \
  --asset-type server
```

**Linux RPM (RHEL/CentOS):**
```bash
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  "https://cy360.{domain}/api/edr/installer/agent-bundle?os=LINUX&arch=x86_64" \
  -o cyedr-agent.rpm
rpm -ivh cyedr-agent.rpm
systemctl enable --now cyedr-agent
```

**macOS PKG (via MDM):**
```bash
# Push via JAMF/Intune as PKG
# PKG post-install script handles LaunchDaemon installation
# Enrollment token passed via MDM environment variable or profile
```

**Windows MSI (via SCCM/Intune):**
```powershell
msiexec /i cyedr-agent-x64.msi `
  DEPLOYMENT_TOKEN="eyJ..." `
  COLLECTOR_URL="https://cy360.{domain}/api/edr" `
  INSTALL_CYSIEM=0 `
  /qn /l*v cyedr-install.log
```

**Package naming convention:**
```
cyedr-agent-{VERSION}-amd64.deb         Linux DEB (Ubuntu/Debian, Intel)
cyedr-agent-{VERSION}-arm64.deb         Linux DEB (Ubuntu/Debian, ARM)
cyedr-agent-{VERSION}-x86_64.rpm        Linux RPM (RHEL/CentOS, Intel)
cyedr-agent-{VERSION}-aarch64.rpm       Linux RPM (RHEL/CentOS, ARM)
cyedr-agent-{VERSION}-intel64.pkg       macOS PKG (Intel Macs)
cyedr-agent-{VERSION}-arm64.pkg         macOS PKG (Apple Silicon M1/M2/M3)
cyedr-agent-{VERSION}-x64.msi           Windows MSI (x64)
cyedr-agent-{VERSION}-arm64.msi         Windows MSI (ARM64 — Surface/Qualcomm)
cyedr-agent-linux-x86_64               Standalone binary (quick-install path)
cyedr-agent-linux-aarch64              Standalone binary (quick-install path)
cyedr-agent-macos-intel64             Standalone binary (quick-install path)
cyedr-agent-macos-arm64               Standalone binary (quick-install path)
```

---

### 3.5 Air-Gap / Offline Installation

For environments without internet access from endpoints:

**1. Pre-stage the binary on the endpoint:**
```bash
# On an internet-connected staging host, download the bundle:
curl -fsSL -H "Authorization: Bearer $TOKEN" \
  "https://cy360.{domain}/api/edr/installer/agent-bundle?os=LINUX&arch=x86_64" \
  -o cyedr-agent-linux-x86_64

# Copy to endpoint via USB / internal file share / SSH
scp cyedr-agent-linux-x86_64 root@endpoint:/tmp/
```

**2. Run installer with fallback detection:**
```bash
# Place binary alongside the installer script OR at /tmp/cyedr-agent
# The installer scans for it in: $SCRIPT_DIR/cyedr-agent-linux-$ARCH, $SCRIPT_DIR/../agent/cyedr-agent, /tmp/cyedr-agent
bash cyedr-install.sh --token "..." --platform "https://cy360.internal" --silent
```

**3. For full air-gap (no platform reachable from endpoint at all):**
```bash
# 1. Pre-write config.json manually (see Section 4)
# 2. Copy binary to /opt/cycentra/edr/cyedr-agent and chmod 750
# 3. Create systemd service manually (see systemd unit in scripts/cyedr-install.sh)
# 4. Generate enrollment token manually on platform, write agent_id to config.json
```

---

### 3.6 Deploying with CySIEM Together

CyEDR and CySIEM (Wazuh) are designed to co-exist. CyEDR owns behavioral detection; CySIEM owns log collection and compliance.

**What CyEDR covers exclusively (do NOT duplicate in Wazuh):**
- Sysmon events (Windows) — CyEDR reads Microsoft-Windows-Sysmon/Operational
- auditd `cy360_edr_*` keyed events — CyEDR reads these; Wazuh would create duplicates

**What CySIEM covers exclusively:**
- Windows Security event log (4624/4625/4648/4688 etc.)
- Windows System log (service state changes)
- PowerShell logging (4103/4104/4106)
- journald / syslog (Linux system events)
- apple-oslog (macOS auth/TCC subsystems)
- auditd `cy360_wazuh_tamper` key (Wazuh self-protection)

**Install both with one command:**
```bash
# Linux
curl -fsSL https://cy360.{domain}/api/edr/installer/unix | \
  sudo bash -s -- --token "eyJ..." --platform "https://cy360.{domain}" --with-cysiem

# Windows
.\cyedr-install.ps1 -Token "eyJ..." -Platform "https://cy360.{domain}" -WithCySIEM
```

**Overlap check:** Run `grep -E 'cy360_edr_|cy360_wazuh_tamper' /etc/audit/rules.d/*.rules` to verify key separation. CyEDR uses `cy360_edr_*` prefix; Wazuh uses `cy360_wazuh_tamper`. Never conflict.

---

## 4. Agent Configuration Reference (config.json)

Located at: `/opt/cycentra/edr/config.json` (Linux/macOS) or `C:\Program Files\CyCentra\edr\config.json` (Windows)

```json
{
  "platform_url":       "https://cy360.example.com",
  "deploy_token":       "eyJ...",
  "agent_id":           "uuid-assigned-at-enrollment",
  "asset_type":         "workstation",
  "hostname":           "ENDPOINT01",
  "os_type":            "LINUX",
  "edr_home":           "/opt/cycentra/edr",
  "poll_interval":      60,
  "heartbeat_interval": 60,
  "telemetry_batch":    20,
  "yara_rules":         "/opt/cycentra/edr/yara_rules/cycentra.yar",
  "quarantine_dir":     "/opt/cycentra/edr/quarantine",
  "ioc_cache":          "/opt/cycentra/edr/ioc_cache/ioc.json",
  "log_file":           "/opt/cycentra/edr/logs/cyedr_agent.log",
  "sysmon_channel":     "Microsoft-Windows-Sysmon/Operational"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `platform_url` | string | CyCentra 360 base URL (no trailing slash) |
| `deploy_token` | string | Deployment token (used for initial self-enrollment only) |
| `agent_id` | string | UUID assigned at enrollment — written by installer after enrollment |
| `asset_type` | string | Criticality classification: workstation/server/database/domain_controller/api_gateway/jump_server |
| `os_type` | string | LINUX, MACOS, or WINDOWS |
| `edr_home` | string | Base directory for agent runtime files |
| `poll_interval` | int | Seconds between command polls (default 60) |
| `heartbeat_interval` | int | Seconds between heartbeat POSTs (default 60) |
| `telemetry_batch` | int | Maximum events per telemetry batch POST (default 20) |
| `yara_rules` | string | Path to main YARA rules file |
| `quarantine_dir` | string | Directory for quarantined files |
| `ioc_cache` | string | Path to local IOC cache JSON |
| `log_file` | string | Agent log file path |
| `sysmon_channel` | string | Windows only — ETW channel for Sysmon events |

**Reload without restart:** The agent re-reads `config.json` at startup only. To apply config changes, restart the service:
```bash
# Linux
systemctl restart cyedr-agent
# macOS
launchctl stop com.cycentra.edr && launchctl start com.cycentra.edr
# Windows
Restart-Service CyEDRAgent
```

---

## 5. Telemetry Schema (TelemetryEnvelope)

The agent sends batches of events to `POST /api/edr/telemetry`. Each event is a `TelemetryEnvelope`:

```json
{
  "timestamp_epoch_ns": 1751000000000000000,
  "endpoint_uuid":      "agent-id-uuid",
  "os_type":            "LINUX",
  "event_uuid":         "random-uuid-per-event",
  "event_category":     "PROCESS",
  "process": {
    "pid":               1234,
    "ppid":              5678,
    "executable_path":   "/usr/bin/python3",
    "command_line":      "python3 /tmp/exploit.py",
    "file_hash_sha256":  "abc123...",
    "is_signed":         false,
    "signer_identity":   "",
    "user_sid_or_uid":   "0"
  },
  "parent_process": {
    "pid":               5678,
    "ppid":              1,
    "executable_path":   "/usr/sbin/sshd",
    "command_line":      "sshd: root@pts/0",
    "file_hash_sha256":  "def456...",
    "is_signed":         true,
    "signer_identity":   "OpenSSH"
  },
  "event_payload":       "base64-encoded-event-specific-bytes",
  "raw_text":            "type=SYSCALL msg=audit(1751000000.000:12345): arch=c000003e ...",
  "score":               75,
  "triggers":            ["process_lineage_anomaly", "unsigned_temp_exec"],
  "ti_match":            false,
  "asset_type":          "server"
}
```

**Event categories:**

| `event_category` | Source | Typical Trigger |
|-----------------|--------|-----------------|
| `PROCESS` | auditd execve / Sysmon EventID 1 / macOS log | process_lineage_anomaly, living_off_land |
| `NETWORK` | auditd connect / Sysmon EventID 3 / macOS log | c2_beacon, network_ioc_match |
| `FILE` | auditd file watch / Sysmon EventID 11 | ransomware_canary, ransomware_extension |
| `REGISTRY` | Sysmon EventID 12/13 | registry_manipulation, persistence_mechanism |
| `DRIVER` | Sysmon EventID 6 | dll_sideloading |
| `THREAD_INJECT` | Sysmon EventID 8/10/25 | memory_injection, lsass_access |
| `AUTH` | auditd uid/gid change / macOS TCC | token_impersonation, credential_dump |
| `DNS` | Sysmon EventID 22 / macOS log | c2_beacon, dns_tunneling |
| `MALWARE` | YARA scan match | file_hash_ioc |

---

## 6. Detection Engine Reference

### 6.1 The 19 Heuristic Triggers

Each trigger has a **weight** added to the raw score when it fires. Multiple triggers accumulate additively.

| Trigger ID | Weight | MITRE | What fires it |
|-----------|--------|-------|---------------|
| `unsigned_temp_exec` | +15 | T1059 | Binary executed from /tmp, %TEMP%, AppData\Local\Temp without code signature |
| `process_lineage_anomaly` | +35 | T1059.003 | Unexpected parent-child: office/browser/DB spawning cmd/powershell/bash |
| `memory_injection` | +40 | T1055 | ptrace, process_vm_writev, memfd_create syscalls; Sysmon EventID 8 CreateRemoteThread |
| `lsass_access` | +45 | T1003.001 | Sysmon EventID 10 TargetImage=lsass.exe |
| `credential_dump` | +40 | T1003 | Mimikatz patterns, NTDS.dit access, SAM registry key read |
| `ransomware_canary` | +50 | T1486 | Write to canary file in monitored directory |
| `lateral_movement` | +35 | T1021 | Remote service execution patterns (PsExec, WMI remote, RDP drive map) |
| `c2_beacon` | +35 | T1071 | Periodic outbound pattern, jitter-based timing, known C2 ports |
| `defense_evasion` | +25 | T1562 | Security tool process terminated, ETW provider patched, audit log cleared |
| `persistence_mechanism` | +30 | T1053 | Registry Run key write, scheduled task create, new service installed, cron modification |
| `script_obfuscation` | +25 | T1027 | Base64-encoded PowerShell, XOR-obfuscated scripts, VBA macro execution |
| `living_off_land` | +20 | T1218 | certutil.exe, regsvr32.exe, mshta.exe, rundll32.exe, msiexec.exe used atypically |
| `first_time_execution` | +20 | T1059 | Binary hash never seen before from this user/system identity in baseline window |
| `network_ioc_match` | +35 | T1071 | Outbound connection to known-bad IP or domain in IOC cache |
| `file_hash_ioc` | +50 | T1204 | File SHA-256 matches known malware in IOC cache |
| `registry_manipulation` | +25 | T1112 | HKLM\SYSTEM, HKLM\SECURITY, HKCU\Run write from unexpected process |
| `ransomware_extension` | +45 | T1486 | File renamed with .locked, .encrypted, .crypted, or novel random 4-8 char extension |
| `dll_sideloading` | +30 | T1574.002 | DLL loaded from non-standard path by signed binary; Sysmon EventID 7 |
| `token_impersonation` | +35 | T1134 | SetThreadToken, ImpersonateLoggedOnUser, setuid/setresuid syscall patterns |

**TI match bonus:** +50 (added on top when `ti_match=True` — i.e., IOC cache confirmed a hit)

### 6.2 Confidence Matrix Formula

```
raw_score   = Σ(weight for each triggered heuristic) + (50 if ti_match else 0)
final_score = min(100, round(raw_score × asset_modifier, 1))
```

**Example calculations:**

| Scenario | Triggers | Raw | Asset (×) | Final | Severity |
|----------|----------|-----|----------|-------|---------|
| Mimikatz on workstation | lsass_access(45) + credential_dump(40) | 85 | ×1.0 | 85 | Critical |
| Mimikatz on domain controller | lsass_access(45) + credential_dump(40) | 85 | ×2.0 | 100 | Critical |
| New ransomware (no IOC) | canary(50) + extension(45) + unsigned_temp(15) | 110 → 100 | ×1.0 | 100 | Critical |
| Known malware binary | file_hash_ioc(50) + ti_match_bonus(50) | 100 | ×1.3 | 100 | Critical |
| Living-off-land on server | lolbas(20) + process_lineage(35) | 55 | ×1.4 | 77 | High |
| Suspicious script on workstation | script_obfuscation(25) + first_time(20) | 45 | ×1.0 | 45 | Medium |
| Minor registry write | registry_manipulation(25) | 25 | ×1.0 | 25 | Medium |

### 6.3 Asset Criticality Multipliers

| Asset Type | Multiplier | Rationale |
|-----------|-----------|-----------|
| `workstation` | ×1.0 | Standard user endpoint — baseline |
| `server` | ×1.3 | Broader blast radius, more data |
| `api_gateway` | ×1.6 | Central traffic node |
| `database` | ×1.7 | Regulated/sensitive data |
| `jump_server` | ×1.8 | Lateral movement pivot point |
| `domain_controller` | ×2.0 | Full domain compromise if breached |

### 6.4 Severity Bands

| Score | Severity | Wazuh Rule Level | Auto-Response |
|-------|----------|-----------------|---------------|
| 75–100 | critical | 14 | If ransomware triggers: ISOLATE + ROLLBACK + FORENSICS; if lateral movement ≥90: ISOLATE |
| 50–74 | high | 11 | If c2_beacon: COLLECT_FORENSICS |
| 25–49 | medium | 7 | None |
| 10–24 | low | 4 | None |
| 0–9 | (dropped) | — | Dropped before storage |

All detections with score ≥ 80 automatically open a CyCases case regardless of severity band.

---

## 7. SIEM Integration — How Logs Flow

### 7.1 Pipeline Stages

```
[Endpoint]
  cyedr_agent.py reads auditd/Sysmon/macOS logs
  → evaluates 19 heuristics
  → scores event (confidence matrix)
  → assembles TelemetryEnvelope
  → POST /api/edr/telemetry  (HTTPS, Bearer enrollment token)
         │
[CyCentra 360 Backend — blueprints/edr/routes.py]
         │
  normalizer.py: TelemetryEnvelope → SIEM alert dict
         │
  confidence_matrix.compute_score()
         │
  _store_detection() → PostgreSQL: edr_detections table
         │
  response_orchestrator.auto_respond() → edr_response_commands (if triggered)
         │
  edr_bridge.forward_to_siem()
         │
[Redis: cysiemstack:alerts:raw RPUSH]
         │
[CySIEM Correlation Engine — cysiemstack/correlation_engine/]
         │
  ingestor.py: reads Redis queue
         │
  normaliser.py: standardizes field names
         │
  grouper.py: groups correlated events
         │
  correlator.py: applies 55 correlation rules
         │
  ueba_engine.py: runs 17 behavioral detectors
         │
  risk_scorer.py: final risk score
         │
  misp_enricher.py: threat actor/campaign context
         │
  llm_enricher.py: AI narrative summary
         │
  PostgreSQL: alerts + incidents tables
         │
  [If score ≥ 80 → edr_bridge._try_open_case()]
         │
  cases_bp.service.open_case() → CyCases incident
```

### 7.2 Redis Queue Format

The SIEM bridge pushes a Wazuh-compatible JSON dict to `cysiemstack:alerts:raw`:

```json
{
  "timestamp":      "2026-06-28T12:34:56.789Z",
  "source":         "cyedr",
  "agent_id":       "uuid-of-edr-agent",
  "rule": {
    "id":           "100300",
    "level":        14,
    "description":  "CyEDR: lsass_access + credential_dump on ENDPOINT01"
  },
  "agent": {
    "name":         "ENDPOINT01",
    "ip":           "10.0.1.55",
    "os":           "WINDOWS"
  },
  "data": {
    "edr": {
      "score":          85,
      "severity":       "critical",
      "triggers":       ["lsass_access", "credential_dump"],
      "ti_match":       false,
      "asset_type":     "domain_controller",
      "detection_id":   "edr-detection-uuid",
      "process": {
        "executable_path":  "C:\\Windows\\Temp\\mimikatz.exe",
        "command_line":     "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "file_hash_sha256": "abc123...",
        "pid":              4444,
        "ppid":             3333,
        "user_sid_or_uid":  "S-1-5-21-..."
      }
    }
  },
  "mitre": {
    "id":     "T1003.001",
    "tactic": "Credential Access"
  },
  "wazuh_id":     null,
  "full_log":     "CyEDR telemetry: lsass_access credential_dump on ENDPOINT01"
}
```

The `source: "cyedr"` field allows the SIEM to distinguish EDR events from native Wazuh events in dashboards and queries.

### 7.3 Wazuh Rules Deployed

These rules in `CYSIEM-Config/rules/cy_cust_rules.xml` process events for CyEDR:

| Rule ID | Level | Trigger | Description |
|---------|-------|---------|-------------|
| `101000` | 14 | `audit.key = cy360_wazuh_tamper` | Wazuh agent files accessed/modified — Wazuh self-protection |
| `101010` | 13 | Windows EventID 7036 — Wazuh service stopped | Wazuh service stop (Windows) |
| `101020` | 14 | macOS FIM on `/Library/Ossec/` | Wazuh tamper on macOS |
| `101030` | 14 | `audit.key = cy360_edr_tamper` | **CyEDR anti-tamper:** CyEDR agent binary or config modified (Linux) |
| `101031` | 14 | Windows EventID 7036 — CyEDR service stopped | **CyEDR anti-tamper:** CyEDR agent service stopped (Windows) |

**Removed rules** (no longer in Wazuh — CyEDR owns these event sources):

| Rule ID | Reason Removed |
|---------|---------------|
| `100911` | Sysmon EventID 6 USBSTOR — CyEDR reads Sysmon, Wazuh never sees this event |
| `101001` | auditd ptrace/memfd_create — CyEDR detects process injection; Wazuh rule would duplicate |
| `101011` | Sysmon EventID 8 CreateRemoteThread — Wazuh never sees Sysmon events |
| `101012` | Sysmon EventID 10 LSASS access — dead |
| `101013` | Sysmon EventID 25 ProcessTampering — dead |

**ossec.conf active-response rules_id** (updated):
```
Old: 101000,101001,101010,101011
New: 101000,101010,101030,101031
```

### 7.4 Dual Ownership: CyEDR vs Wazuh

Understanding who owns what prevents duplicates and coverage gaps.

| Event Source | Owner | File Read By | Wazuh Rule? |
|-------------|-------|-------------|-------------|
| auditd `cy360_edr_*` keys (process/net/inject/privesc/creds/persist/tamper) | **CyEDR** | `cyedr_agent.py` (AuditdReader) | None — CyEDR scores these |
| auditd `cy360_wazuh_tamper` key | **Wazuh** | Wazuh native auditd reader | Rule 101000 |
| Microsoft-Windows-Sysmon/Operational | **CyEDR** | `cyedr_agent.py` (WindowsSysmonReader) | None — Wazuh no longer reads Sysmon |
| Windows Security event log | **Wazuh** | Wazuh agent (agent.conf localfile) | Native Wazuh rules |
| Windows System event log (7036/7045) | **Wazuh** | Wazuh agent | Rules 101010/101031 |
| PowerShell/Operational (4103/4104) | **Wazuh** | Wazuh agent | Native Wazuh rules |
| journald / syslog | **Wazuh** | Wazuh agent | Native Wazuh rules |
| macOS apple-oslog (auth/TCC/kext subsystems) | **Wazuh** | Wazuh agent | macOS rules |
| macOS apple-oslog (kernel/endpointsecurity/process) | **CyEDR** | `cyedr_agent.py` (MacOSLogReader) | None — CyEDR scores these |

---

## 8. Response Actions Reference

All actions are queued as `edr_response_commands` rows. The agent polls `GET /api/edr/response/<agent_id>/pending` every `poll_interval` seconds, acknowledges commands, executes them, and reports back via `POST .../commands/<cmd_id>/complete`.

### ISOLATE

Cuts all network connectivity except the CyEDR management channel.

| Platform | Implementation |
|----------|---------------|
| Linux | `iptables -F; iptables -P INPUT DROP; iptables -P OUTPUT DROP; iptables -A INPUT -i lo -j ACCEPT; iptables -A OUTPUT -o lo -j ACCEPT; iptables -A OUTPUT -d {PLATFORM_IP} -p tcp --dport 443 -j ACCEPT` |
| macOS | `pfctl` anchor rules: block all, pass out to platform IP/443, pass lo0 |
| Windows | `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound; netsh advfirewall firewall add rule name="CyEDR-mgmt" ...` |

> Isolation is logged to the agent log and to `edr_agents.isolation_state = 'isolated'` in the DB.

### UNISOLATE

Reverses isolation — restores default OS firewall state.

| Platform | Implementation |
|----------|---------------|
| Linux | `iptables -F; iptables -P INPUT ACCEPT; iptables -P OUTPUT ACCEPT` |
| macOS | `pfctl -d` (disables pf) |
| Windows | `netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound` + removes CyEDR rules |

### KILL_PROCESS

Terminates a process by PID or image name.

```json
// Command params
{"pid": 4444, "image_name": "mimikatz.exe"}
```

| Platform | Implementation |
|----------|---------------|
| Linux | `os.kill(pid, signal.SIGKILL)` or `pkill -f image_name` |
| macOS | Same as Linux |
| Windows | `taskkill /F /PID 4444 /T` (recursive — kills child processes) |

### BLOCK_HASH

Add a SHA-256 hash to the local deny list. Any running process matching the hash is killed; future execution is blocked by the agent before allowing the process to start.

```json
{"sha256": "abc123...", "reason": "Confirmed malware — Incident IC-0042"}
```

### QUARANTINE_FILE

Moves a file to the quarantine directory with restricted ACLs preventing execution.

```json
{"file_path": "/tmp/evil.py"}
```

Quarantine directory: `$EDR_HOME/quarantine/` — root:root 700 on Linux, SYSTEM-only ACL on Windows.

### ROLLBACK

Invoke OS-native snapshot restore.

```json
{"snapshot": "latest", "scope": "modified_files"}
```

| Platform | Implementation |
|----------|---------------|
| Windows | `vssadmin list shadows` → find most recent → `wmic shadowcopy call revert` |
| macOS | `tmutil localsnapshot` restore via `tmutil restore` |
| Linux | Btrfs: `btrfs subvolume snapshot` restore; ZFS: `zfs rollback`; ext4: file-level copy from `/var/lib/cycentra/journal/` |

### RUN_SCAN

Trigger on-demand YARA scan against the endpoint's file system.

```json
{"scan_type": "full", "path": "/", "yara_rules": "all"}
```

The agent runs `yara -r /opt/cycentra/edr/yara_rules/cycentra.yar /` and returns structured results:
```json
{
  "output": "...",
  "matches": [
    {"rule": "Mimikatz_strings", "path": "/tmp/mimi.exe", "tags": ["cred_dump"]}
  ],
  "source": "bundled"
}
```
Matches are ingested by `command_complete()` into `edr_detections` and the SIEM `alerts` table.

### COLLECT_FORENSICS

Collect forensic artifacts and upload to platform.

```json
{"scope": "memory,process,network", "reason": "Post-incident forensics — IC-0042"}
```

Collects:
- Running process list (`ps auxf` / `tasklist /V`)
- Open network connections (`ss -tunap` / `netstat -an`)
- Loaded kernel modules (Linux: `lsmod`; Windows: loaded DLLs per process)
- Recent file changes (`find /tmp /home -newer /proc/1/exe` / recent MFT entries)
- Memory dump of flagged process (if PID specified)
- Last 500 lines of system log

Uploaded as a `.tar.gz` / `.zip` to `POST /api/edr/agents/<id>/forensics`.

---

## 9. Policy Engine Reference

Seven policy types managed at `GET/POST /api/edr/policies`. All delivered to agents via `APPLY_POLICY` command.

### Policy Types Summary

| Type | Key Setting Areas |
|------|------------------|
| `threat_prevention` | real_time_protection, memory_protection, lsass_protection, ransomware_rollback, yara_scanning, ai_sensitivity (low/medium/high/aggressive) |
| `device_control` | usb_storage_mode (allow/readonly/block), wifi_mode, bluetooth, camera, microphone, clipboard, screen_capture |
| `app_control` | mode (off/audit/blacklist/whitelist), block_unsigned, allowed_apps[], blocked_apps[], trusted_publishers[] |
| `network_control` | default_inbound_policy, default_outbound_policy, malicious_dns_blocking, corporate_proxy |
| `exclusions` | excluded_paths[], excluded_processes[], excluded_extensions[], excluded_hashes[], excluded_ips[] |
| `update` | channel (stable/beta/lts), reboot_behavior (auto/prompt/defer), maintenance_window |
| `isolation_exceptions` | allowed_ips[], allowed_ports[], dns_resolution, dhcp_renewal |

### Assignment Model

```
Policy → assigned_to: agent | group

Groups:
  POST /api/edr/groups             Create group
  POST /api/edr/groups/<id>/members Add agents
  GET  /api/edr/agents/<id>/policies Returns effective policies (direct + via group)
```

Multiple policies of different types can apply simultaneously. If two policies of the same type apply (direct + group), the direct assignment takes precedence.

---

## 10. API Endpoint Reference

All routes under `/api/edr/`. Auth legend: 🔑 = session (viewer/analyst/admin), 🤖 = Bearer enrollment token, 🎟️ = Bearer deployment token, 🌐 = public (no auth).

### Fleet Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/agents/enroll` | 🔑 admin | Manually enroll agent (admin creates token) |
| `GET` | `/agents` | 🔑 viewer | List all agents with stats |
| `GET` | `/agents/<id>` | 🔑 viewer | Agent detail + recent detections + commands |
| `POST` | `/agents/<id>/heartbeat` | 🤖 | Agent heartbeat (updates last_seen) |
| `POST` | `/agents/self-enroll` | 🎟️ | Agent self-enrolls using deployment token |

### Telemetry & Detections

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/telemetry` | 🤖 | Ingest TelemetryEnvelope batch |
| `GET` | `/detections` | 🔑 viewer | List detections (filter: severity, status, agent_id) |
| `GET` | `/detections/<id>` | 🔑 viewer | Detection detail |
| `PATCH` | `/detections/<id>/status` | 🔑 analyst | Update status: open→investigating→resolved/false_positive |

### Response Actions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/response/<id>/isolate` | 🔑 analyst | Queue ISOLATE command |
| `POST` | `/response/<id>/unisolate` | 🔑 analyst | Queue UNISOLATE command |
| `POST` | `/response/<id>/kill-process` | 🔑 analyst | Queue KILL_PROCESS |
| `POST` | `/response/<id>/block-hash` | 🔑 analyst | Queue BLOCK_HASH |
| `POST` | `/response/<id>/collect-forensics` | 🔑 analyst | Queue COLLECT_FORENSICS |
| `POST` | `/response/<id>/quarantine-file` | 🔑 analyst | Queue QUARANTINE_FILE |
| `POST` | `/response/<id>/rollback` | 🔑 analyst | Queue ROLLBACK |
| `POST` | `/response/<id>/run-scan` | 🔑 analyst | Queue RUN_SCAN (YARA) |
| `GET` | `/response/<id>/pending` | 🤖 | Agent polls for pending commands |
| `POST` | `/response/<id>/commands/<cmd_id>/complete` | 🤖 | Agent reports command completion |

### Policies & Groups

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/policies` | 🔑 viewer | List all policies |
| `POST` | `/policies` | 🔑 admin | Create policy |
| `GET` | `/policies/<id>` | 🔑 viewer | Policy detail |
| `PUT` | `/policies/<id>` | 🔑 admin | Update policy |
| `DELETE` | `/policies/<id>` | 🔑 admin | Delete policy |
| `POST` | `/policies/<id>/assign` | 🔑 analyst | Assign policy to agents/groups |
| `GET` | `/agents/<id>/policies` | 🔑 viewer | Effective policies for agent |
| `GET` | `/policy-defaults` | 🔑 viewer | Default config per policy type |
| `GET` | `/groups` | 🔑 viewer | List groups |
| `POST` | `/groups` | 🔑 analyst | Create group |
| `POST` | `/groups/<id>/members` | 🔑 analyst | Add agents to group |

### Stats & Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/stats` | 🔑 viewer | Fleet-wide stats (agents, detections, auto-responses) |
| `GET` | `/triggers` | 🔑 viewer | Heuristic trigger catalog (weights, MITRE, descriptions) |

### Installer & Deployment

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/installer/token` | 🔑 admin | List deployment tokens |
| `POST` | `/installer/token` | 🔑 admin | Create deployment token |
| `POST` | `/installer/token/<id>/revoke` | 🔑 admin | Revoke token |
| `GET` | `/installer/commands?token=` | 🔑 admin | Arch-aware install commands (OS→arch→method→cmd) |
| `GET` | `/installer/agent-bundle?os=&arch=` | 🎟️ | Serve standalone binary for quick-install path |
| `GET` | `/installer/sysmon-config` | 🎟️ | Serve cycentra_sysmon_config.xml |
| `GET` | `/installer/sysmon-exe` | 🎟️ | Serve Sysmon64.exe |
| `GET` | `/installer/yara-rules` | 🎟️ | Serve cycentra.yar |
| `GET` | `/installer/yara-exe` | 🎟️ | Serve yara64.exe (Windows) |
| `GET` | `/installer/cysiem-script` | 🎟️ | Serve Wazuh shell installer |
| `GET` | `/installer/cysiem-msi` | 🎟️ | Serve Wazuh MSI (Windows) |
| `GET` | `/installer/unix` | 🌐 | Serve cyedr-install.sh |
| `GET` | `/installer/win` | 🌐 | Serve cyedr-install.ps1 |

### IOC Feed (agent-facing)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/ioc-feed` | 🤖 | Returns IOC cache (hashes, IPs, domains) for local agent cache |

---

## 11. Database Schema

Database: `correlation` on port 5433 (PostgreSQL). Connection string: `CYCENTRA_DB_URL` env var.

### edr_agents

```sql
CREATE TABLE edr_agents (
    agent_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname         TEXT NOT NULL,
    os_type          TEXT NOT NULL CHECK (os_type IN ('WINDOWS','LINUX','MACOS','UNKNOWN')),
    asset_type       TEXT DEFAULT 'workstation',
    agent_ip         TEXT,
    enrollment_token TEXT NOT NULL,    -- Bearer token for agent-facing API calls
    enrolled_by      TEXT DEFAULT 'self-enrollment',
    enrolled_at      TIMESTAMPTZ DEFAULT NOW(),
    last_seen        TIMESTAMPTZ,
    version          TEXT,
    status           TEXT DEFAULT 'active' CHECK (status IN ('active','inactive','decommissioned')),
    isolation_state  TEXT DEFAULT 'normal' CHECK (isolation_state IN ('normal','isolated','pending_isolation')),
    tags             JSONB DEFAULT '[]',
    metadata         JSONB DEFAULT '{}'
);
```

Key columns:
- `enrollment_token` — returned at enrollment, used by agent for all subsequent API calls. Strip from list API responses.
- `isolation_state` — updated by `command_complete()` when ISOLATE/UNISOLATE succeeds
- `last_seen` — updated by heartbeat; online = `last_seen > NOW()-5min`

### edr_detections

```sql
CREATE TABLE edr_detections (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         UUID NOT NULL REFERENCES edr_agents(agent_id),
    event_uuid       TEXT UNIQUE,           -- idempotency key from TelemetryEnvelope
    detected_at      TIMESTAMPTZ DEFAULT NOW(),
    severity         TEXT NOT NULL,          -- critical/high/medium/low
    score            NUMERIC NOT NULL,       -- 0–100 confidence score
    rule_id          TEXT,                   -- e.g. "100300"
    rule_desc        TEXT,                   -- human-readable detection summary
    mitre_id         TEXT,                   -- e.g. "T1003.001"
    mitre_tactic     TEXT,                   -- e.g. "Credential Access"
    event_category   TEXT,                   -- PROCESS/NETWORK/FILE/etc.
    process_name     TEXT,
    process_path     TEXT,
    command_line     TEXT,
    file_path        TEXT,
    src_ip           TEXT,
    dst_ip           TEXT,
    username         TEXT,
    triggers         JSONB DEFAULT '[]',     -- list of fired heuristic trigger IDs
    ti_match         BOOLEAN DEFAULT FALSE,
    status           TEXT DEFAULT 'open',    -- open/investigating/resolved/false_positive/in_review
    notes            TEXT,
    raw_envelope     JSONB                   -- full TelemetryEnvelope for forensics
);
```

### edr_response_commands

```sql
CREATE TABLE edr_response_commands (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         UUID NOT NULL REFERENCES edr_agents(agent_id),
    action           TEXT NOT NULL,          -- ISOLATE/UNISOLATE/KILL_PROCESS/etc.
    params           JSONB DEFAULT '{}',
    status           TEXT DEFAULT 'pending', -- pending/acknowledged/completed/failed
    issued_by        TEXT,
    issued_at        TIMESTAMPTZ DEFAULT NOW(),
    acknowledged_at  TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    result           JSONB DEFAULT '{}',
    auto_triggered   BOOLEAN DEFAULT FALSE,  -- true = fired by auto_respond()
    detection_id     UUID REFERENCES edr_detections(id),
    incident_id      TEXT                    -- SIEM incident reference
);
```

### edr_deployment_tokens

```sql
CREATE TABLE edr_deployment_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token        TEXT UNIQUE NOT NULL,
    label        TEXT,
    os_type      TEXT DEFAULT 'any',         -- WINDOWS/LINUX/MACOS/any
    created_by   TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    max_uses     INT DEFAULT 0,              -- 0 = unlimited
    used_count   INT DEFAULT 0,
    revoked      BOOLEAN DEFAULT FALSE
);
```

### edr_policies, edr_policy_assignments, edr_agent_groups

See `blueprints/edr/policy_engine.py:ensure_policy_tables()` for full CREATE TABLE statements. Key relationship:

```
edr_policies (id, name, policy_type, config JSONB, description, created_by)
edr_policy_assignments (id, policy_id→edr_policies, target_type agent|group, target_id)
edr_agent_groups (id, name, description)
edr_group_members (group_id→edr_agent_groups, agent_id→edr_agents)
```

---

## 12. Package Distribution

### Build Pipeline

```bash
# Build all CyEDR packages (requires Docker + QEMU multiarch)
sudo bash agent-packages/build-edr-packages.sh 1.0.58

# Outputs to: /var/lib/cycentra-agent-packages/edr/
ls /var/lib/cycentra-agent-packages/edr/
# cyedr-agent-linux-x86_64
# cyedr-agent-linux-aarch64
# cyedr-agent-1.0.58-amd64.deb
# cyedr-agent-1.0.58-arm64.deb
# cyedr-agent-1.0.58-x86_64.rpm
# cyedr-agent-1.0.58-aarch64.rpm
# [macOS/Windows: require native build hosts]

# Download/verify all packages (Wazuh + CyEDR):
sudo bash agent-packages/download-packages.sh
```

### Platform Serving

Packages are served via NGINX:

```nginx
location /edr-packages/ {
    alias /var/lib/cycentra-agent-packages/edr/;
    autoindex off;
    add_header Content-Disposition "attachment" always;
    add_header Cache-Control "no-store, must-revalidate" always;
}
```

The NGINX block is injected by `cycentra-setup.sh` at setup time.

Direct download URL (no auth — protected by Cloudflare/VPN at the HTTPS layer):
```
https://cy360.{domain}/edr-packages/cyedr-agent-linux-x86_64
```

Token-authenticated download (for installer scripts):
```
GET /api/edr/installer/agent-bundle?os=LINUX&arch=x86_64
Authorization: Bearer <deployment-token>
```

### macOS and Windows Build Notes

macOS PKG and Windows MSI require native build hosts and are not produced by Docker:

**macOS PKG:**
```bash
# On macOS host:
pip3 install pyinstaller
pyinstaller --onefile agent/cyedr_agent.py --name cyedr-agent
# Then package into PKG:
pkgbuild --root dist/ --identifier com.cycentra.edr \
  --version 1.0.58 --scripts pkg-scripts/ \
  cyedr-agent-1.0.58-intel64.pkg
```

**Windows MSI:**
Use WiX Toolset or Advanced Installer on a Windows build host:
```powershell
# On Windows:
pip install pyinstaller
pyinstaller --onefile agent\cyedr_agent.py --name cyedr-agent
# Build MSI with WiX — see agent-packages/windows/cyedr.wxs
```

---

## 13. Anti-Tamper & Hardening

### Linux Anti-Tamper

1. **auditd watch on EDR home:**
   Rule in `/etc/audit/rules.d/60-cyedr.rules`:
   ```
   -w /opt/cycentra/edr -p wa -k cy360_edr_tamper
   ```
   Any write or attribute change to the EDR home directory fires `cy360_edr_tamper`, which Wazuh rule 101030 picks up at level 14 (critical).

2. **Systemd watchdog timer:**
   `cyedr-watchdog.timer` runs every 5 minutes:
   ```bash
   systemctl is-active cyedr-agent || systemctl restart cyedr-agent
   ```

3. **Filesystem hardening:**
   ```bash
   chown -R root:root /opt/cycentra/edr
   chmod -R 750 /opt/cycentra/edr
   chmod 700 /opt/cycentra/edr/quarantine
   chmod 600 /opt/cycentra/edr/config.json
   ```

4. **systemd protections:**
   ```ini
   ProtectSystem=strict
   OOMScoreAdjust=-900
   MemoryMax=256M
   CPUQuota=25%
   ReadWritePaths=/opt/cycentra/edr /var/run /var/log/audit /tmp
   ```

### Windows Anti-Tamper

1. **Restrictive ACLs on EDR home:**
   Only SYSTEM and BUILTIN\Administrators have FullControl. BUILTIN\Users explicitly denied Write/Delete/Modify.

2. **Windows service failure recovery:**
   ```
   sc failure CyEDRAgent reset=86400 actions=restart/10000/restart/30000/restart/60000
   ```

3. **Wazuh rule 101031:** Fires at level 14 if the CyEDRAgent service stops (Windows System log EventID 7036).

4. **Future (Phase 2+):** Register as PsProtectedSignerAntimalware-Light (PPL) — prevents SYSTEM processes from killing the agent.

### macOS Anti-Tamper

1. **LaunchDaemon** with `KeepAlive=true` — launchd restarts the process if it exits.
2. **Wazuh rule 101020** watches `/Library/Ossec/` for CySIEM tamper.
3. **Future:** ESF-based self-protection and APFS snapshot of EDR binaries.

---

## 14. Troubleshooting Guide

### Agent Won't Start

**Linux:**
```bash
journalctl -u cyedr-agent -n 50 --no-pager
systemctl status cyedr-agent
# Common causes:
# - Binary not present: ls /opt/cycentra/edr/cyedr-agent
# - config.json missing agent_id: cat /opt/cycentra/edr/config.json | python3 -m json.tool
# - Platform unreachable: curl -I https://cy360.{domain}/api/edr/stats
```

**Windows:**
```powershell
Get-EventLog Application -Source CyEDRAgent -Newest 20 | Format-List
# Check binary:
Test-Path "C:\Program Files\CyCentra\edr\cyedr-agent.exe"
# Check config:
Get-Content "C:\Program Files\CyCentra\edr\config.json" | ConvertFrom-Json
```

### Agent Enrolled but Not Appearing in Fleet

1. Check heartbeat interval: `poll_interval` in config.json should be ≤ 60.
2. Check network: `curl -X POST https://cy360.{domain}/api/edr/agents/{agent_id}/heartbeat -H "Authorization: Bearer {enrollment_token}" -H "Content-Type: application/json" -d '{}'`
3. Check agent_id in config.json matches the DB: `psql -p 5433 -U postgres correlation -c "SELECT agent_id, hostname, last_seen FROM edr_agents WHERE hostname='ENDPOINT01';"`

### No Detections Firing

1. Verify auditd rules loaded (Linux): `auditctl -l | grep cy360_edr`
2. Verify Sysmon running (Windows): `Get-Service Sysmon64`
3. Check agent log for scoring output: `grep "score=" /opt/cycentra/edr/logs/cyedr_agent.log | tail -20`
4. Check minimum score threshold: Events scoring < 10 are dropped. Adjust `MIN_SCORE_THRESHOLD` in `confidence_matrix.py` if needed.
5. Test telemetry endpoint directly: `curl -X POST https://cy360.{domain}/api/edr/telemetry -H "Authorization: Bearer {enrollment_token}" -H "Content-Type: application/json" -d '{"events":[...]}'`

### SIEM Not Receiving EDR Events

1. Check Redis queue: `redis-cli llen cysiemstack:alerts:raw` — should be increasing
2. Check edr_bridge: `grep "forward_to_siem" /opt/cycentra/logs/flask.log | tail -20`
3. Verify the CySIEM correlation engine is running: `systemctl status cysiemstack-correlator`
4. Check for normalizer errors: `grep "normalise_telemetry" /opt/cycentra/logs/flask.log | grep ERROR`

### Isolation Command Not Working

1. Check agent log for iptables/netsh output: `grep "ISOLATE" /opt/cycentra/edr/logs/cyedr_agent.log`
2. Verify the platform IP is in the management exemption (agent stores `PLATFORM_IP` from `platform_url`)
3. On Linux: `iptables -L -n` shows active rules during isolation
4. On Windows: `netsh advfirewall show allprofiles`
5. Management channel test: after isolation, the agent should still be able to heartbeat. If heartbeats stop, the management exemption IP is wrong.

### Deployment Token Issues

- **"Invalid or expired deployment token"**: token may have hit `max_uses` or `expires_at`. Create a new one.
- **"os_type restriction"**: token was created with `os_type=LINUX` but being used on Windows.
- Self-enrollment: `POST /api/edr/agents/self-enroll` — response must include `agent_id`. If not, check `validate_deployment_token()` in `policy_engine.py`.

### Log Locations

| Component | Log Path |
|-----------|----------|
| CyEDR Agent (Linux) | `/opt/cycentra/edr/logs/cyedr_agent.log` |
| CyEDR Agent (Linux system) | `journalctl -u cyedr-agent` |
| CyEDR Agent (macOS) | `/opt/cycentra/edr/logs/cyedr_agent.log` |
| CyEDR Agent (Windows) | `C:\Program Files\CyCentra\edr\logs\cyedr_agent.log` |
| Flask backend | `/opt/cycentra/logs/flask.log` |
| SIEM Correlation | `/opt/cycentra/logs/cysiemstack/correlator.log` |
| NGINX | `/var/log/nginx/access.log` and `error.log` |

---

## 15. Enhancement Guide (for future developers)

This section captures design decisions and extension points for engineers working on CyEDR future versions.

### Adding a New Heuristic Trigger

1. Add entry to `HEURISTIC_TABLE` in `confidence_matrix.py`:
   ```python
   "new_trigger_name": {
       "weight":  30,
       "mitre":   ("T1XXX", "Tactic Name"),
       "desc":    "What this trigger detects",
       "regex":   r"pattern_to_match_against_raw_text",
   }
   ```
2. The `score_event()` function in `cyedr_agent.py` automatically picks up new entries — it iterates `PATTERN_MAP` which is built from `HEURISTIC_TABLE`.
3. Update `CYEDR_TECHNICAL_REFERENCE.md` Section 6.1 with the new trigger.
4. Add a test case in `tests/test_confidence_matrix.py`.

### Adding a New Response Action

1. Add the action string to `VALID_ACTIONS` set in `response_orchestrator.py`.
2. Add a handler to `ResponseExecutor` class in `cyedr_agent.py`:
   ```python
   def _handle_new_action(self, cmd: dict):
       params = cmd.get("params", {})
       # implement platform-specific logic
   ```
3. Add the action dispatch to `ResponseExecutor.execute()`.
4. Add a new route in `routes.py` following the existing pattern.
5. Add a button in `EdrEndpointDetailPage.jsx` or `EdrFleetPage.jsx`.

### Adding a New Policy Type

1. Add the type string to `POLICY_TYPES` set in `policy_engine.py`.
2. Add default config dict to `POLICY_DEFAULTS[new_type]`.
3. Handle `APPLY_POLICY` with the new type in `ResponseExecutor._handle_apply_policy()` in `cyedr_agent.py`.
4. Add UI for the new type in `EdrPoliciesPage.jsx`.

### Migrating from Python Bridge to Native Kernel Sensor

When Phase 2 (native kernel sensor) is ready, the migration path is:

1. The kernel sensor binary replaces `cyedr-agent` (same filename, same CLI args, same config.json format).
2. The sensor must POST `TelemetryEnvelope` JSON to `POST /api/edr/telemetry` — same API, no backend changes.
3. The `event_category` field must use the same values as the bridge (PROCESS, NETWORK, FILE, etc.).
4. The `triggers` list must use the same trigger ID strings as in `HEURISTIC_TABLE`.
5. If the kernel sensor handles scoring locally, it sets `score` and `triggers` on the envelope. The backend normalizer will still run `compute_score()` as a validation fallback.
6. No backend changes required. No DB schema changes required. No UI changes required.

### Extending SIEM Integration

The `edr_bridge.py` module is the integration point. To add new downstream systems:

1. **Elasticsearch/OpenSearch:** After `forward_to_siem()`, add `es_client.index(index="cyedr-detections", body=alert)`.
2. **Webhook/SOAR:** Add `requests.post(WEBHOOK_URL, json=alert)` with retry logic.
3. **Additional Redis queues:** RPUSH to additional queue keys for additional consumers.

The normalized `alert` dict format is stable — adding new fields is backward-compatible.

---

## 16. Quick Reference Cards

### Operator Quick Reference

```
DEPLOY AGENT:
  Linux:   curl -fsSL https://cy360.DOMAIN/api/edr/installer/unix | sudo bash -s -- --token TOKEN --platform URL
  Windows: iwr URL/api/edr/installer/win | iex; .\cyedr-install.ps1 -Token TOKEN -Platform URL

CHECK AGENT STATUS:
  Linux:   systemctl status cyedr-agent | journalctl -u cyedr-agent -n 50
  macOS:   launchctl list com.cycentra.edr | tail -50 /opt/cycentra/edr/logs/cyedr_agent.log
  Windows: Get-Service CyEDRAgent | Get-EventLog Application -Source CyEDRAgent -Newest 10

KEY DIRECTORIES:
  Agent home (Linux/macOS): /opt/cycentra/edr/
  Agent home (Windows):     C:\Program Files\CyCentra\edr\
  Packages (server):        /var/lib/cycentra-agent-packages/edr/
  Agent log:                $EDR_HOME/logs/cyedr_agent.log

KEY DATABASE:
  psql -p 5433 -U postgres correlation
  \dt edr_*   -- list all EDR tables
  SELECT hostname, last_seen, isolation_state FROM edr_agents ORDER BY last_seen DESC;
  SELECT severity, rule_desc, detected_at FROM edr_detections WHERE status='open' ORDER BY score DESC;
```

### Detection Score Quick Calc

```
Score = (Σ trigger weights) + (50 if IOC match) × asset_multiplier   →  capped at 100

Common single-trigger examples on workstation (×1.0):
  Memory injection alone:   40 → Medium
  LSASS access alone:       45 → Medium
  Ransomware canary alone:  50 → High
  Known malware hash + IOC: 100 → Critical

On domain controller (×2.0):
  Memory injection alone:   40 × 2.0 = 80 → Critical → auto CyCases case
  LSASS + cred dump:        85 × 2.0 = 100 → Critical → auto ISOLATE
```

### MITRE Coverage Summary

```
Tactic               Techniques   Coverage Method
───────────────────────────────────────────────────────────────
Execution            T1059,T1218  lolbas, script_obfuscation, process_lineage_anomaly
Persistence          T1053,T1574  persistence_mechanism, dll_sideloading
Privilege Escalation T1134        token_impersonation
Defense Evasion      T1055,T1562  memory_injection, defense_evasion
  + T1027,T1112,T1218             script_obfuscation, registry_manipulation, living_off_land
Credential Access    T1003,T1003.001  credential_dump, lsass_access
Lateral Movement     T1021        lateral_movement
C2                   T1071        c2_beacon, network_ioc_match, dns_tunneling (via DNS category)
Impact               T1486        ransomware_canary, ransomware_extension  [auto-isolate]
```

---

*Document maintained by CyCentra 360 Engineering.*  
*Last updated: 2026-06-28.*  
*For architecture decisions and comparison charts see CYEDR_ARCHITECTURE.md.*
