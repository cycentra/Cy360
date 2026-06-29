# ITAM Module — Commercial Gap Analysis

> CyCentra 360 v1.0.108 · Last updated 2026-06-30
>
> This document is an honest, engineering-level assessment of the ITAM module's current capabilities
> versus commercially mature products (Axonius, Armis, Claroty, Netskope, Qualys CSAM).
> It is intended for product planning, customer conversations, and sprint prioritisation.

---

## Executive Summary

| Domain | Current Maturity | Commercial Benchmark |
|---|---|---|
| Network Asset Inventory | **72%** — SNMP + mDNS + Cloud added | Axonius, Qualys CSAM |
| EDR/SIEM Coverage Gap | **85%** — production-ready | Built for this platform |
| IoT Device Registry | **30%** — mDNS passive discovery added | Armis, Claroty, Forescout |
| Shadow AI — Local Process | **70%** — effective for on-prem AI | Proprietary (rare in market) |
| Shadow AI — SaaS/Web | **40%** — DNS + network layer added | Netskope, Zscaler CASB |
| Agent-less Deep Inventory | **75%** — SNMP + credential profiles added | Qualys Cloud Agent, Tenable |
| Software Inventory | **70%** — local NVD mirror + EPSS + KEV | Qualys, Tenable, Rapid7 |
| CVE Correlation | **70%** — offline NVD + CISA KEV catalog | Full Tenable/Qualys scanners |
| Cloud Asset Discovery | **65%** — AWS EC2 + Azure VMs implemented | Axonius, Qualys TotalCloud |
| Compliance Auto-Feed | **55%** — 6 controls, bridge pattern solid | Vanta, Drata, Hyperproof |

---

## Section 1: Network Asset Inventory

### What's Implemented

| Feature | Status | Notes |
|---|---|---|
| ARP neighbor collection via CyEDR | ✅ Done | Every 60s heartbeat, all platforms |
| CMDB CSV import (manual, highest priority) | ✅ Done | ip,hostname,mac,type,vendor,notes,tags |
| nmap subnet scan (on-demand, admin) | ✅ Done | -sn -PS flags, XML parsed |
| Cross-reference to EDR agents by IP | ✅ Done | Auto-links edr_agents table |
| Cross-reference to SIEM agents by IP | ✅ Done | Auto-links host_posture_cache |
| Asset type classification | ✅ Done | 8 types: workstation/server/printer/camera/… |
| Coverage gap KPI dashboard | ✅ Done | Total / EDR% / SIEM% / Uncovered |
| Paginated asset table with search | ✅ Done | IP, hostname, vendor search |
| Asset manual edit (analyst+) | ✅ Done | type, notes, tags, hostname, vendor |
| Vulnerability count per asset | ✅ Done | From software_inventory after deep scan |

### What's Missing vs. Commercial Products

| Gap | Commercial Example | Effort to Build |
|---|---|---|
| ✅ **SNMP polling** — collect sysDescr, ifTable, arp table, device model from routers/switches without SSH | Qualys, SolarWinds | ✅ Done in v1.0.108 |
| **Agent-less WMI direct** without WinRM — for Windows hosts that don't have WinRM enabled (uses DCOM) | Qualys Cloud Agent | High — impacket WMI is complex |
| **Passive traffic analysis** — discover assets without scanning, just by watching network flows | Axonius, Armis | Very High — requires pcap tap or mirror port |
| ✅ **Cloud asset discovery** — AWS EC2 + Azure VMs via cloud APIs | Axonius, Qualys TotalCloud | ✅ Done in v1.0.108 (AWS + Azure) |
| **Container/Kubernetes inventory** — Docker containers, K8s pods, image layers | Prisma Cloud, Aqua | High — K8s API integration needed |
| **Asset ownership mapping** — business unit, department, owner email per asset | ServiceNow CMDB | Low-Medium — add owner fields + LDAP lookup |
| **Asset lifecycle management** — procurement date, end-of-life, retirement workflow | ServiceNow | Medium — new state machine + UI |
| **Duplicate detection logic** — merge assets seen from multiple sources with conflicting data | Axonius | Medium — matching heuristics |
| **Real-time asset change alerting** — alert when a new asset appears, or one disappears | Most CSAM tools | Low — add APScheduler job + alert rule |
| **Bi-directional CMDB sync** — push discovered assets back to ServiceNow/Jira | Axonius | High — ServiceNow API integration |
| **Network topology map** — visualise segments, VLANs, connected devices | Auvik, Nmap.online | High — graph rendering in React |

---

## Section 2: IoT Device Registry

### What's Implemented

| Feature | Status | Notes |
|---|---|---|
| OUI vendor lookup (MAC prefix → vendor/category) | ✅ Done | ~65 prefixes covering major brands |
| Port fingerprinting (RTSP/MQTT/Modbus/BACnet) | ✅ Done | 12 port → category mappings |
| Risk scoring (0–100 composite) | ✅ Done | Telnet/no-TLS/default-creds/industrial |
| Default credential probing | ✅ Done | Opt-in: ITAM_PROBE_CREDS=true |
| IoT-specific subnet scan | ✅ Done | POST /api/itam/iot/scan |
| Risk tier filter UI (LOW/MED/HIGH/CRIT) | ✅ Done | Risk factor detail panel on click |
| Category breakdown dashboard | ✅ Done | Count per device type |

### What's Missing vs. Commercial Products

| Gap | Commercial Example | Effort to Build | Priority |
|---|---|---|---|
| **Passive traffic fingerprinting** — identify devices from actual traffic patterns without scanning | Armis, Claroty, Forescout | Very High — requires pcap/Zeek/Arkime integration | Low for IT, High for OT |
| **OUI database at scale** — 65 prefixes vs. Armis' 2+ billion device fingerprints | Armis | High — import IEEE OUI CSV (50k+ entries) and build lookup DB | Medium |
| **CVE per device model/firmware** — look up CVEs against specific camera/printer/switch firmware | Claroty, Forescout | High — requires NVD CPE matching on device model strings | Medium |
| **Network segmentation analysis** — flag when IoT device talks to unexpected segments | Armis, Cisco Cyber Vision | Very High — needs traffic metadata per flow | Low |
| **Firmware extraction / analysis** — unpack and scan device firmware images | Finite State, Centrifuge | Very High — separate product category | Low |
| ✅ **mDNS/SSDP passive discovery** — discover devices from broadcast protocols passively | Forescout | ✅ Done in v1.0.108 — zeroconf listener, 19 service types | Medium |
| **802.1X integration** — trigger quarantine VLAN on risk-score threshold | Forescout | High — RADIUS integration needed | Low |
| **Industrial protocol anomaly detection** — detect unusual Modbus/DNP3 commands | Claroty, Nozomi | Very High — deep packet inspection at protocol level | Low |

> **Assessment**: The current IoT registry is suitable for **IT environments** to gain visibility into non-agent devices. For **OT/ICS environments** (manufacturing, utilities, healthcare), passive fingerprinting without active scanning is a hard requirement — active nmap on an OT network can crash PLCs and SCADA systems. CyCentra should clearly communicate this scope boundary to customers.

---

## Section 3: Shadow AI Detection

### What's Implemented (Post v1.0.107)

| Layer | Method | Coverage | Status |
|---|---|---|---|
| **L1 — Local process scan** | CyEDR psutil, 25 process names | On-prem AI tools (Ollama, LM Studio, etc.) | ✅ Done |
| **L2 — DNS journal monitoring** | systemd-resolved / mDNSResponder log parsing | Linux/macOS — SaaS AI domain DNS queries | ✅ Done |
| **L2 — Sysmon EventID 22** | Wazuh rule 101040, 65+ domains | Windows — DNS queries to AI SaaS | ✅ Done |
| **L2 — Sysmon EventID 3** | Wazuh rule 101041, 45+ domains | Windows — TCP connections to AI APIs | ✅ Done |
| **L3 — Local AI port detection** | Wazuh rule 101042 + agent telemetry | Ollama (11434), LM Studio (1234), WebUI (7860) | ✅ Done |
| **L4 — Network DNS monitor** | dnslib forwarding resolver on CyCentra server | ALL devices (no agent required) — optional | ✅ Done |
| **AI domain watchlist** | 70+ domains across 30+ providers | OpenAI, Anthropic, Gemini, Groq, DeepSeek, xAI, etc. | ✅ Done |
| **Approved tool whitelist** | ai_tool_whitelist table, admin-managed | Suppresses findings for sanctioned tools | ✅ Done |
| **Finding workflow** | open/approve/escalate/suppress | Full audit trail with resolved_by/resolved_at | ✅ Done |

### What's Missing vs. Commercial Products

| Gap | Commercial Example | Effort to Build | Priority |
|---|---|---|---|
| **SSL/TLS traffic inspection** — see the actual HTTP body sent to AI APIs (what data was transmitted) | Netskope, Zscaler | Very High — requires CA cert deployment across all endpoints, SSL interception proxy | High |
| **Browser extension monitoring** — detect ChatGPT used via browser without DNS capture | Netskope Agent, Securly | High — requires browser extension deployment | High |
| **Data exfiltration detection** — alert when >N KB is pasted into an AI chat (the real risk) | Netskope, Microsoft Purview | Very High — depends on SSL inspection | High |
| **API key usage detection** — detect employees using personal OpenAI keys from corp network via IP/ASN matching | Some CASB tools | Medium — correlate IP → ASN for AI cloud providers in network logs | Medium |
| **AI output ingestion detection** — detect AI-generated content being saved to corp systems | Proprietary | Very High — semantic analysis required | Low |
| **Scheduled/automated AI API calls** — detect cron jobs or scripts calling AI APIs | Limited | Medium — correlate DNS queries with process scheduling | Medium |
| **Process rename evasion** — detect ollama renamed as svchost.exe | None in market | Medium — hash-based process fingerprinting | Medium |
| **Mobile device coverage** — detect ChatGPT on iOS/Android on corporate Wi-Fi | Netskope Mobile | High — MDM integration required | Low |

> **Assessment**: The L1 (process scan) + L2 (DNS) combination is more complete than most SIEM vendors offer out of the box. The key missing piece is **what data is being sent**, not just **which tool**. For compliance purposes (GDPR, PCI, legal hold), detecting the tool is Step 1; knowing what data was shared requires SSL inspection which is a significant deployment undertaking. Customers should be advised that CyCentra catches the "installed/running AI tool" and "SaaS AI domain access" problem, but data-exfiltration via AI requires a CASB.

---

## Section 4: Agent-less Deep Inventory

### What's Implemented

| Feature | Status | Notes |
|---|---|---|
| SSH-based inventory (Linux/macOS) | ✅ Done | paramiko, key or password auth |
| WinRM/PowerShell inventory (Windows) | ✅ Done | pywinrm, NTLM auth |
| OS info (name, version, build) | ✅ Done | /etc/os-release + Win32_OperatingSystem |
| Hardware (CPU cores/model, RAM, disk) | ✅ Done | /proc/cpuinfo, free, df, Win32_Processor |
| Installed packages (deb/rpm/brew/winreg) | ✅ Done | dpkg-query, rpm -qa, brew list, registry |
| Running services | ✅ Done | systemctl, launchctl, Get-Service |
| Listening ports | ✅ Done | ss -tlnp |
| Local users | ✅ Done | /etc/passwd UID≥1000, Get-LocalUser |
| Per-asset detail page | ✅ Done | Hardware, OS, software table, services |
| Background async scan | ✅ Done | daemon thread, result stored in DB |
| Global SSH/WinRM credentials (env vars) | ✅ Done | ITAM_SSH_USERNAME, ITAM_WINRM_USERNAME |
| Per-scan credential override (API body) | ✅ Done | POST body overrides env defaults |

### What's Missing vs. Commercial Products

| Gap | Commercial Example | Effort to Build | Priority |
|---|---|---|---|
| **SSH key rotation / credential vault** — per-asset SSH key stored in Infisical/Azure KV, not global env var | Qualys, CyberArk integration | Medium — Infisical integration pattern exists | High |
| ✅ **Scheduled deep scan** — auto re-scan assets every N days | All CSAM tools | ✅ Done in v1.0.108 — ITAM_DEEP_SCAN_INTERVAL_DAYS | High |
| ✅ **SNMP agent-less** — router/switch/firewall inventory without SSH | Qualys, SolarWinds | ✅ Done in v1.0.108 — pysnmp-lextudio | Medium |
| **WMI over DCOM** (no WinRM) — for Windows hosts where WinRM is not enabled | Qualys Cloud Agent | High — impacket wmiquery | Medium |
| **AWS SSM Run Command** — inventory cloud EC2 instances without direct SSH | AWS Systems Manager integration | Medium — boto3 + SSM | Medium |
| ✅ **Scan progress/status visibility** — show scan_status badge per asset | Most tools | ✅ Done in v1.0.108 — scan_status field + UI badge | Low |
| ✅ **Per-subnet credential profiles** — save named credential sets per CIDR | Qualys, Tenable | ✅ Done in v1.0.108 — itam_credential_profiles table + API | Medium |
| **macOS agent-less via MDM** — leverage JAMF/Mosyle API for inventory without SSH | JAMF | High — JAMF API integration | Low |

---

## Section 5: Software Inventory & CVE Correlation

### What's Implemented

| Feature | Status | Notes |
|---|---|---|
| Software inventory storage (software_inventory table) | ✅ Done | Per asset: name, version, vendor, package_manager |
| Package ingestion from SSH/WinRM deep scan | ✅ Done | deb/rpm/brew/winreg, deduplication |
| OS noise filtering | ✅ Done | Skips locales, fonts, base-files, glibc, etc. |
| NVD API 2.0 CVE lookup | ✅ Done | httpx, CVSSv3.1 → v3.0 → v2 priority |
| CVE severity per package | ✅ Done | critical/high/medium/low/none |
| Rate limiting (free: 6s, with key: 0.6s) | ✅ Done | NVD_API_KEY env var |
| Vuln count per asset in coverage dashboard | ✅ Done | vuln_count + highest_cve_severity columns |
| Software inventory tab in asset detail | ✅ Done | Paginated, sortable by CVE count, severity filter |
| CVE enrichment trigger (analyst+) | ✅ Done | POST /api/itam/assets/<id>/enrich-cves |

### What's Missing vs. Commercial Products

| Gap | Commercial Example | Effort to Build | Priority |
|---|---|---|---|
| **Authenticated vulnerability scanning** — actually probe the host for exploitability, not just keyword match | Tenable, Qualys, Rapid7 | Very High — full vulnerability scanner is a separate product category | Low |
| **NVD CPE matching** — use Common Platform Enumeration for precise product version matching instead of keyword search | Tenable, Qualys | High — build local CPE dictionary, match package name → CPE | High |
| ✅ **Local NVD mirror** — download and cache NVD feeds locally, eliminates rate limits | Most enterprise scanners | ✅ Done in v1.0.108 — nvd_cves PG table, daily incremental + weekly full sync | High |
| ✅ **EPSS score** — probability-of-exploitation score (0-1) from FIRST.org per CVE | Tenable, Qualys | ✅ Done in v1.0.108 — api.first.org batch fetch, stored in software_inventory | High |
| ✅ **CISA KEV flag** — mark actively exploited CVEs from CISA Known Exploited Vulnerabilities | Tenable, Qualys, Rapid7 | ✅ Done in v1.0.108 — kev_catalog table, daily sync, KEV badge in asset detail | High |
| **Patch management integration** — know if a patch is available and auto-remediate | Qualys Patch Management | Very High — separate product category | Low |
| **SBOM generation** — Software Bill of Materials export (CycloneDX/SPDX) | Dependency-Track | Medium — generate from software_inventory table | Medium |
| **Container image scanning** — scan Docker images pulled on a host | Trivy, Snyk, Grype | High — Trivy can be called as a subprocess | Medium |
| **Differential scan** — only show new packages or CVEs since last scan | Most tools | Low — compare last_scanned timestamps | Low |

---

## Section 6: Compliance Auto-Feed

### What's Implemented

| Feature | Status | Notes |
|---|---|---|
| NIST CSF ID.AM-1 (asset inventory) | ✅ Done | Coverage % as evidence |
| ISO 27001 A.8.1 (asset inventory) | ✅ Done | |
| DORA Art.8 (ICT asset management) | ✅ Done | |
| NIS2 Art.21 (asset management) | ✅ Done | |
| EU AI Act Art.28 (AI system inventory) | ✅ Done | Shadow AI finding count as evidence |
| ISO 42001 (AI management) | ✅ Done | |
| Auto-finding when EDR coverage < 50% | ✅ Done | medium severity |
| 6-hour APScheduler job | ✅ Done | itam_compliance_sync |

### What's Missing vs. Commercial Products

| Gap | Commercial Example | Effort to Build | Priority |
|---|---|---|---|
| **Per-control evidence depth** — currently 6 controls; ISO 27001 alone has 93 | Vanta, Drata | Low per control — mapping work, not engineering | High |
| **Per-asset compliance** — is this specific server compliant with its applicable controls? | Qualys, Tenable | Medium — per-asset compliance view |Medium |
| **Audit-ready evidence export** — PDF with screenshots, timestamps, API signatures | Vanta, Drata | Medium — extend reportlab PDF generator | Medium |
| **Remediation workflow** — compliance gap → ticket → owner → SLA tracking | Hyperproof, Drata | High — workflow engine needed | Low |
| **Evidence attestation** — human review/sign-off on each evidence item | All GRC tools | Medium — attestation table + UI | Low |
| **Framework coverage tracking** — show which controls are auto-evidenced vs. manual | Vanta | Low — add field to questionnaire_responses | Low |

---

## Deployment Guidance by Use Case

### ✅ Ready for production use today

- **Coverage gap dashboard** — Any organization wanting to know their EDR/SIEM blind spots
- **CMDB import** — Organizations with existing asset spreadsheets
- **Shadow AI process detection** — Any org concerned about employees running local LLMs
- **Shadow AI DNS monitoring** — Catch SaaS AI tool usage on enrolled endpoints
- **Network DNS monitor** — Opt-in, requires secondary DNS config on DHCP server

### ⚠ Use with awareness of limitations

- **ARP-based discovery** — Only discovers devices that have communicated with an EDR-enrolled host. Isolated segments will not appear.
- **IoT risk scoring** — Works well for standard IT environments. Do NOT run active nmap/credential probing on OT/ICS networks without explicit authorization.
- **Agent-less SSH/WinRM** — Requires network access + credentials. Not recommended for production PCI-DSS hosts without change advisory board approval.
- **NVD CVE lookup** — Keyword-based, not CPE-matched. Expect false positives on common package names. Use the **EPSS score** and **KEV badge** (both live as of v1.0.108) to prioritise truly dangerous CVEs over theoretical ones.

### ❌ Do not position as replacement for

- **Armis/Claroty/Forescout** — for passive OT/ICS device discovery and anomaly detection
- **Netskope/Zscaler** — for SaaS Shadow AI data exfiltration (what data was sent)
- **Qualys/Tenable** — for full authenticated vulnerability scanning with CPE matching
- **Axonius** — for multi-source asset consolidation at enterprise scale (100k+ assets)
- **ServiceNow CMDB** — for full asset lifecycle management with ITSM workflow

---

## Prioritised Enhancement Roadmap

### Sprint 1 — ✅ Completed in v1.0.108

| Item | Status | Value Delivered |
|---|---|---|
| ✅ Local NVD mirror (nvd_cves PG table, daily/weekly sync) | Done | Eliminates NVD rate limits entirely |
| ✅ EPSS score per CVE from api.first.org (batch 100) | Done | Prioritise exploitable CVEs vs. theoretical |
| ✅ CISA KEV flag (kev_catalog, daily sync) | Done | Instantly identify actively exploited CVEs |
| ✅ Scheduled CVE refresh (nightly APScheduler) | Done | Keeps CVE data current without manual trigger |
| ✅ Per-subnet credential profiles (itam_credential_profiles) | Done | Named credential sets per CIDR subnet |
| ✅ SNMP polling (pysnmp-lextudio, sysDescr/ifTable) | Done | Inventories routers/switches/firewalls |
| ✅ mDNS passive discovery (zeroconf, 19 service types) | Done | Discovers printers/cameras/IoT passively |
| ✅ Cloud asset discovery (AWS EC2 + Azure VMs) | Done | Hybrid environment coverage |
| ✅ Scan status badge per asset (scan_status field + UI) | Done | Visibility into scan progress |

### Sprint 2 — Next priorities

| Item | Effort | Value |
|---|---|---|
| Real-time new asset alert (APScheduler + alert rule) | 1 day | Alert when unknown IP first appears |
| IEEE OUI full database import (50k+ entries) | 2 days | Massively improves IoT vendor identification |
| SBOM export (CycloneDX format) | 3 days | Regulatory / supply chain requirement |
| NVD CPE matching (precise version correlation) | 1 week | Reduces CVE false positives significantly |

### Sprint 3 — Complex, strategic

| Item | Effort | Value |
|---|---|---|
| Browser-based Shadow AI detection via corp proxy | 2 weeks | Catches ChatGPT-via-browser (80% of real SaaS AI usage) |
| Passive device discovery via Zeek/pcap | 4+ weeks | Required for OT/ICS environments |
| Bi-directional ServiceNow CMDB sync | 3 weeks | Enterprise integration requirement |
| WMI over DCOM (no WinRM) for Windows hosts | 2 weeks | Covers Windows without WinRM enabled |

---

## Appendix: New API Endpoints (v1.0.108)

| Endpoint | Method | RBAC | Purpose |
|---|---|---|---|
| `/api/itam/assets/<id>/snmp-scan` | POST | analyst+ | Trigger SNMP poll on network device |
| `/api/itam/assets/<id>/scan-status` | GET | viewer+ | Get current scan_status + scan_error |
| `/api/itam/assets/<id>/exploit-intel` | GET | viewer+ | EPSS scores + KEV status for asset's CVEs |
| `/api/itam/cloud-sync` | POST | admin | Trigger AWS EC2 + Azure VM sync |
| `/api/itam/cloud-sync/status` | GET | viewer+ | Cloud source counts and config status |
| `/api/itam/credential-profiles` | GET/POST | analyst+/admin | List or create per-subnet credential profiles |
| `/api/itam/credential-profiles/<id>` | PUT/DELETE | admin | Update or delete a credential profile |
| `/api/itam/nvd-mirror/status` | GET | viewer+ | NVD mirror stats: CVE count, last sync dates |
| `/api/itam/nvd-mirror/sync` | POST | analyst+ | Trigger incremental NVD sync (last 8 days) |
| `/api/itam/nvd-mirror/full-sync` | POST | admin | Trigger full NVD sync from start_year (hours) |
| `/api/itam/nvd-mirror/kev-sync` | POST | analyst+ | Sync CISA Known Exploited Vulnerabilities |

## Appendix: New API Endpoints (v1.0.107)

| Endpoint | Method | RBAC | Purpose |
|---|---|---|---|
| `/api/itam/assets/<id>/deep-scan` | POST | analyst+ | Trigger SSH/WinRM inventory for a specific asset |
| `/api/itam/assets/<id>/detail` | GET | viewer+ | Per-asset detail: hardware, OS, services, users, software summary |
| `/api/itam/assets/<id>/software` | GET | viewer+ | Paginated software inventory with CVE data |
| `/api/itam/assets/<id>/enrich-cves` | POST | analyst+ | Trigger NVD CVE lookup for asset's software |
| `/api/itam/shadow-ai/dns-watchlist` | GET | viewer+ | Return the full 70+ domain watchlist with categories |
| `/api/itam/shadow-ai/dns-ingest` | POST | bearer/session | Receive DNS-detected Shadow AI findings from network monitor or CyEDR |

## Appendix: New Environment Variables (v1.0.108)

```bash
# SNMP polling
ITAM_SNMP_COMMUNITY=public      # SNMPv2c community string
ITAM_SNMP_PORT=161              # SNMP UDP port

# mDNS passive discovery
ITAM_MDNS_ENABLED=false         # Set true to start zeroconf listener at startup

# Refresh intervals
ITAM_DEEP_SCAN_INTERVAL_DAYS=7  # Re-run deep scan every N days (APScheduler)
ITAM_CVE_REFRESH_INTERVAL_DAYS=1 # Re-enrich stale CVE data nightly

# AWS EC2 cloud discovery
AWS_REGIONS=us-east-1,eu-west-1 # Comma-separated AWS regions to scan
AWS_ACCESS_KEY_ID=              # IAM access key (ec2:DescribeInstances permission)
AWS_SECRET_ACCESS_KEY=
AWS_SESSION_TOKEN=              # Optional — for temporary credentials / STS

# Azure VM cloud discovery
AZURE_SUBSCRIPTION_ID=          # Azure subscription UUID
AZURE_CLIENT_ID=                # Service principal app ID
AZURE_CLIENT_SECRET=            # Service principal secret
AZURE_TENANT_ID=                # Azure AD tenant ID
```

## Appendix: New Environment Variables (v1.0.107)

```bash
# Agentless SSH inventory
ITAM_SSH_USERNAME=           # Linux/macOS scan username
ITAM_SSH_PASSWORD=           # Password (prefer key-based auth)
ITAM_SSH_KEY_PATH=           # /path/to/id_rsa for key-based auth
ITAM_SSH_PORT=22             # Default SSH port

# Agentless WinRM inventory (Windows targets)
ITAM_WINRM_USERNAME=         # Domain\User or localuser
ITAM_WINRM_PASSWORD=
ITAM_WINRM_PORT=5985         # 5985=HTTP, 5986=HTTPS
ITAM_WINRM_SSL=false

# NVD CVE enrichment
NVD_API_KEY=                 # Free key: nvd.nist.gov/developers/request-an-api-key
                              # Without key: 5 req/30s. With key: 50 req/30s.

# Network DNS monitor (Shadow AI — all devices, no agent needed)
ITAM_DNS_MONITOR_ENABLED=false   # Set true to enable
ITAM_DNS_MONITOR_PORT=5454        # Listen port (5454=non-privileged; 53=root/setcap)
ITAM_DNS_UPSTREAM=8.8.8.8         # Upstream DNS to forward all queries to
```
