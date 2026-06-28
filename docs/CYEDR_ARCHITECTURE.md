# CyEDR — Architecture, Capabilities & Roadmap

**Document version:** 2.0  
**Date:** 2026-06-28  
**Status:** Phase 1 (Python Bridge) COMPLETE and deployed · Native kernel sensor planned Phase 2+  
**Audience:** Engineering, Product, Security Architecture  
**Companion doc:** [CYEDR_TECHNICAL_REFERENCE.md](CYEDR_TECHNICAL_REFERENCE.md) — Installation, API, troubleshooting, DB schema

---

## Table of Contents

1. [What CyEDR Is](#1-what-cyedr-is)
2. [System Architecture](#2-system-architecture)
3. [Full Data Flow — End to End](#3-full-data-flow--end-to-end)
4. [Detection Engine](#4-detection-engine)
5. [Threat Intelligence Integration](#5-threat-intelligence-integration)
6. [TTP Coverage (MITRE ATT&CK)](#6-ttp-coverage-mitre-attck)
7. [Response & Containment](#7-response--containment)
8. [Policy Engine](#8-policy-engine)
9. [Agent Deployment & Fleet Management](#9-agent-deployment--fleet-management)
10. [The Missing Piece — The Sensor Explained](#10-the-missing-piece--the-sensor-explained)
11. [Capability Comparison: CyEDR vs SentinelOne vs CrowdStrike](#11-capability-comparison-cyedr-vs-sentinelone-vs-crowdstrike)
12. [Build vs Buy Analysis](#12-build-vs-buy-analysis)
13. [Sensor Development Roadmap](#13-sensor-development-roadmap)

---

## 1. What CyEDR Is

CyEDR is the Endpoint Detection and Response module of CyCentra 360. It is designed as a **native, integrated EDR** — not a connector to a third-party tool — meaning endpoint telemetry flows directly into the same correlation engine, case management system, compliance framework, and UI that the rest of the platform uses.

### Design Principles

**Single pipeline.** EDR events enter the existing `cysiemstack:alerts:raw` Redis queue and are processed by the same ingestor, correlator, UEBA engine, MISP enricher, and risk scorer that handles Wazuh SIEM alerts. No separate data store, no separate pipeline, no separate correlation rules engine.

**No duplicate scoring.** The EDR Confidence Matrix outputs a `rule_level` (1–15) and `base_score` that are compatible with the SIEM's existing scoring scale. The downstream `risk_scorer.py` processes EDR events identically to Wazuh events.

**Policy-as-commands.** All 7 policy types (threat prevention, device control, app control, network control, exclusions, update, isolation exceptions) are delivered to agents as `APPLY_POLICY` commands via the same command queue used for containment actions. No separate policy delivery channel.

**Automated case escalation.** Detections scoring ≥ 80/100 automatically open a CyCases case via `cases_bp.service.open_case()`, linking the endpoint detection directly to the SIEM incident it generated.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ENDPOINT (Agent Side)                               │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐ │
│  │  Windows Layer  │  │   Linux Layer   │  │       macOS Layer           │ │
│  │ ETW Kernel-     │  │ eBPF kprobes    │  │ ESF (Endpoint Security      │ │
│  │ Process/TI      │  │ execve/connect/ │  │ Framework) process/fork/    │ │
│  │ WFP (network)   │  │ clone tracepts  │  │ exec/auth events            │ │
│  │ MiniFilter (FS) │  │ per-CPU ring    │  │ TCC permission monitoring   │ │
│  └────────┬────────┘  └───────┬─────────┘  └────────────┬────────────────┘ │
│           └──────────────────┬┴────────────────────────┘                   │
│                              ▼                                              │
│          ┌───────────────────────────────────────────┐                     │
│          │         User-Space Agent Process           │                     │
│          │  - Process context cache (PID/hash/signer) │                    │
│          │  - Edge deduplication (5s rolling window)  │                    │
│          │  - 19 heuristic trigger evaluations        │                    │
│          │  - Local IOC cache check (file hashes,     │                    │
│          │    known-bad IPs/domains)                  │                    │
│          │  - L1 YARA scan on file events             │                    │
│          │  - TelemetryEnvelope assembly (Protobuf)   │                    │
│          │  - Anti-tamper watchdog                    │                    │
│          └─────────────────────┬─────────────────────┘                     │
│                                │ POST /api/edr/telemetry                   │
│                                │ Bearer: <enrollment_token>                │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │ HTTPS (mTLS in full deployment)
┌────────────────────────────────▼────────────────────────────────────────────┐
│                        CyCentra 360 Backend                                  │
│                                                                              │
│  blueprints/edr/routes.py          — /api/edr/* (dual auth: session + token) │
│  blueprints/edr/normalizer.py      — TelemetryEnvelope → SIEM alert dict     │
│  blueprints/edr/confidence_matrix.py — 19 triggers × weights × asset mod     │
│  blueprints/edr/response_orchestrator.py — command queue, auto-respond       │
│  blueprints/edr/policy_engine.py   — 7 policy types, deployment tokens       │
│  cysiemstack/edr_bridge.py         — push to Redis, auto-open CyCases        │
│                                                                              │
│                    ┌────────────────────────────────┐                        │
│                    │   Redis: cysiemstack:alerts:raw │                       │
│                    └───────────────┬────────────────┘                        │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                   CySIEM Correlation Engine                          │    │
│  │  ingestor → normaliser → grouper → correlator (55 rules)            │    │
│  │  → UEBA (17 detectors) → risk_scorer → MISP enricher → LLM enricher │   │
│  │  → PostgreSQL: alerts, incidents, entities, risk_scores              │    │
│  └──────────────────────────────┬──────────────────────────────────────┘    │
│                                 │ score ≥ 80?                               │
│                                 ▼                                            │
│                    cases_bp.service.open_case()                              │
│                    → CyCases incident linked to EDR detection                │
│                                                                              │
│  PostgreSQL (port 5433):                                                     │
│  edr_agents, edr_detections, edr_response_commands                           │
│  edr_policies, edr_policy_assignments, edr_agent_groups                      │
│  edr_deployment_tokens                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
                                 │
┌────────────────────────────────▼────────────────────────────────────────────┐
│                         CyCentra 360 Portal (React)                          │
│                                                                              │
│  edr-fleet         — Agent health, isolation state, quick actions            │
│  edr-detections    — Behavioral feed, MITRE tags, severity, analyst actions  │
│  edr-response      — Issue containment, command history                      │
│  edr-policies      — 7-type policy builder, assign to agents/groups          │
│  edr-installer     — Deployment tokens, OS-specific install commands         │
│  edr-endpoint-detail — Forensic timeline, applied policies, cmd history      │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Full Data Flow — End to End

### Phase 1: Event Collection (Agent Side)

The agent continuously monitors OS-level event sources. On Windows this means subscribing to ETW providers (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Threat-Intelligence`), hooking WFP callout drivers for network events, and running a MiniFilter for file system pre-operation callbacks. On Linux, eBPF programs attached to `sys_enter_execve`, `sys_enter_connect`, and `sys_enter_clone` tracepoints capture process and network events with minimal overhead. On macOS, the Endpoint Security Framework delivers process lifecycle events (fork, exec, exit) and authorization requests.

Raw events pass through the **Edge Deduplication Engine** first. A 5-second rolling window suppresses burst events — if a process loads 200 DLLs during startup, one aggregated payload is sent, not 200 individual events. This prevents bandwidth and backend saturation from legitimate high-volume activity like compilers or database engines.

### Phase 2: Local Evaluation (Agent Side)

Before any network transmission, the agent evaluates events against **19 heuristic triggers** (see Section 4). It also checks file hashes and network destinations against a **local IOC cache** — a compact dataset of known-bad indicators synchronized from the platform at regular intervals. If a local match is found, `ti_match=True` is set on the telemetry envelope. Events that pass no heuristics and have no TI match may be suppressed below the minimum score threshold.

### Phase 3: Telemetry Ingestion (Backend)

The agent sends a `TelemetryEnvelope` to `POST /api/edr/telemetry`. The endpoint authenticates via Bearer enrollment token (no user session required — agents run as system services). The `normalizer.py` module converts the envelope into the SIEM-compatible alert format:

- `confidence_matrix.compute_score()` is called with the trigger list, TI match flag, and asset type
- The score determines severity, rule_level (for Wazuh compatibility), and primary MITRE technique
- Process actor fields, network fields, and file paths are extracted and mapped to the canonical alert schema
- Events below `MIN_SCORE_THRESHOLD = 10.0` are dropped — pure noise filtering

### Phase 4: Detection Storage & Auto-Response

The normalized detection is written to `edr_detections`. `response_orchestrator.auto_respond()` then evaluates the detection against auto-response rules:

| Condition | Auto Actions Queued |
|---|---|
| `ransomware_canary` or `ransomware_extension` in triggers | ISOLATE + COLLECT_FORENSICS + ROLLBACK (all three, immediately) |
| `lateral_movement` trigger AND score ≥ 90 | ISOLATE |
| `c2_beacon` trigger AND severity = high or critical | COLLECT_FORENSICS |
| Any detection with score ≥ 80 | CyCases case auto-opened |

Commands are inserted into `edr_response_commands` with `auto_triggered=True`. The agent picks them up on its next poll cycle.

### Phase 5: SIEM Pipeline Injection

`edr_bridge.forward_to_siem()` wraps the alert in a Wazuh-compatible JSON envelope and pushes it to `cysiemstack:alerts:raw` via Redis RPUSH. The existing CySIEM correlation engine processes it identically to any Wazuh alert:

- The **correlator** applies all 55 correlation rules — EDR events can trigger rules for persistence patterns, lateral movement chains, and multi-stage attack sequences
- The **UEBA engine** runs all 17 behavioral detectors — EDR process and user context feeds anomaly baselines
- The **MISP enricher** looks up the alert's file hashes, IPs, and domains against the full MISP threat intelligence database, adding attribution, campaign context, and related indicators
- The **LLM enricher** generates a natural-language summary of the alert for analysts
- An **Incident** is created (or merged into an existing open incident) in PostgreSQL

### Phase 6: CyCases Escalation

If score ≥ 80, `edr_bridge._try_open_case()` polls the `alerts` table (with up to 5 × 2-second retries to allow the async ingestor to commit), finds the incident_id created from this detection's `wazuh_id`, and calls `cases_bp.service.open_case(conn, incident_id, opened_by="cyedr-auto", case_type="edr_detection")`. The case appears in the CyCases UI linked to the SIEM incident, with full evidence trail.

### Phase 7: Agent Command Execution

The agent polls `GET /api/edr/response/<agent_id>/pending` (typically every 30–60 seconds, or immediately after sending telemetry). Pending commands are returned and immediately marked `acknowledged`. The agent executes them locally:

- **ISOLATE:** Windows — WFP filters block all traffic except TCP to the management server; Linux — iptables/nftables rules; macOS — pf firewall rules
- **KILL_PROCESS:** OS-native process termination by PID or image name
- **BLOCK_HASH:** Add SHA-256 to local deny list, terminate any running instance
- **COLLECT_FORENSICS:** Dump memory of suspicious process, collect running process list, open network connections, recent file changes; upload to platform
- **ROLLBACK:** Invoke VSS (Windows), APFS snapshot (macOS), or Btrfs/ZFS snapshot (Linux) to restore files modified since a pre-attack baseline
- **QUARANTINE_FILE:** Move file to isolated quarantine directory with restricted ACL
- **APPLY_POLICY:** Apply JSON policy configuration blob to local agent settings

The agent reports completion via `POST /api/edr/response/<agent_id>/commands/<cmd_id>/complete`.

---

## 4. Detection Engine

### Confidence Matrix Formula

```
raw_score  = Σ(weight for each fired trigger) + (50 if ti_match else 0)
final_score = min(100, round(raw_score × asset_modifier, 1))
```

### Heuristic Triggers (19 total)

| Trigger | Weight | MITRE Technique | Description |
|---|---|---|---|
| `unsigned_temp_exec` | +15 | T1059 Execution | Unsigned binary executed from temp directory |
| `process_lineage_anomaly` | +35 | T1059.003 Execution | Suspicious parent-child (e.g., sqlservr.exe → powershell.exe) |
| `memory_injection` | +40 | T1055 Defense Evasion | Cross-process memory injection pattern |
| `lsass_access` | +45 | T1003.001 Credential Access | Unauthorized LSASS memory read |
| `credential_dump` | +40 | T1003 Credential Access | Credential dumping tool or technique |
| `ransomware_canary` | +50 | T1486 Impact | Ransomware canary file modified |
| `lateral_movement` | +35 | T1021 Lateral Movement | Remote execution service abuse |
| `c2_beacon` | +35 | T1071 Command & Control | Periodic outbound beacon pattern |
| `defense_evasion` | +25 | T1562 Defense Evasion | Security tool disabled or ETW patched |
| `persistence_mechanism` | +30 | T1053 Persistence | Registry run key / scheduled task / service installed |
| `script_obfuscation` | +25 | T1027 Defense Evasion | Heavily obfuscated script execution |
| `living_off_land` | +20 | T1218 Defense Evasion | LOLBin abuse (certutil, regsvr32, mshta, etc.) |
| `first_time_execution` | +20 | T1059 Execution | First execution of this tool by this identity |
| `network_ioc_match` | +35 | T1071 Command & Control | Connection to known-bad IP/domain |
| `file_hash_ioc` | +50 | T1204 Execution | File hash matches known malware IOC |
| `registry_manipulation` | +25 | T1112 Defense Evasion | Sensitive registry key modification |
| `ransomware_extension` | +45 | T1486 Impact | File renamed with ransomware extension pattern |
| `dll_sideloading` | +30 | T1574.002 Persistence | DLL side-loaded into legitimate signed process |
| `token_impersonation` | +35 | T1134 Privilege Escalation | Token theft or impersonation |

**TI match bonus:** +50 (added when local IOC cache or agent confirms a threat intelligence hit)

### Asset Criticality Multipliers

| Asset Type | Multiplier | Rationale |
|---|---|---|
| workstation | ×1.0 | Standard user endpoint — baseline risk |
| laptop | ×1.0 | Same as workstation |
| iot_device | ×1.2 | Limited visibility, often unpatched |
| server | ×1.4 | Broader blast radius, more data exposure |
| api_gateway | ×1.5 | Central traffic node — compromise is systemic |
| ci_cd_node | ×1.6 | Supply chain attack vector |
| database | ×1.7 | Contains regulated/sensitive data |
| jump_server | ×1.8 | Lateral movement pivot point |
| domain_controller | ×2.0 | Full domain compromise if breached |

### Severity Bands

| Score | Severity | Rule Level | Default SIEM Rule ID Range |
|---|---|---|---|
| 75–100 | Critical | 14 | 100300–100399 |
| 50–74 | High | 11 | 100300–100399 |
| 25–49 | Medium | 7 | 100300–100399 |
| 0–24 | Low | 4 | 100300–100399 |

A single memory injection event (`+40`) on a domain controller (`×2.0`) = **80 → Critical**, regardless of whether the injecting process is known or unknown. This is the mechanism by which unknown/zero-day threats still reach critical severity based purely on behavior.

---

## 5. Threat Intelligence Integration

### Layer 1 — Local IOC Cache (Agent Side)

The agent maintains a compact, periodically-synchronized cache of threat indicators:
- Known-bad file SHA-256 hashes → fires `file_hash_ioc` trigger (+50)
- Known-bad IP addresses and domains → fires `network_ioc_match` trigger (+35)
- When either fires, `ti_match=True` is set on the envelope → additional +50 bonus

A single known malware hash match therefore scores: 50 (file_hash_ioc) + 50 (ti_match bonus) = **100 × asset_modifier** — guaranteed critical regardless of asset type.

### Layer 2 — MISP Enrichment (Pipeline Side)

Once the alert enters the CySIEM pipeline, the existing MISP enricher runs against every alert. For EDR events this adds:
- **Threat actor attribution** — links the technique to known APT groups
- **Campaign context** — identifies if the IOC belongs to an active campaign
- **Related indicators** — surfaces adjacent hashes, IPs, domains from the same MISP event
- **Confidence tags** — MISP's own confidence scoring on the indicator
- **TLPREF** classification for sharing decisions

### Layer 3 — Behavioral Zero-Day Coverage

This is the most important layer for unknown threats. When no IOC matches exist (zero-day, novel malware, custom tooling), the heuristic engine still fires based on **what the code does**, not what it is. Example:

A brand-new ransomware variant, never seen before:
- Executes from `%TEMP%` → `unsigned_temp_exec` (+15)
- Its installer drops a DLL into a legitimate app → `dll_sideloading` (+30)
- It modifies canary files → `ransomware_canary` (+50)
- It renames files with a new extension → `ransomware_extension` (+45)
- **Total raw: 140 → capped at 100 → Critical**
- Auto-response fires: ISOLATE + COLLECT_FORENSICS + ROLLBACK — before any signature exists

### Layer 4 — UEBA Behavioral Baseline

The 17 UEBA detectors in the CySIEM engine run against EDR events the same as network events. Unusual process execution patterns, off-hours activity, privilege escalation, and first-seen entity behaviors are all caught here — cross-correlated with identity data, asset context, and network telemetry.

---

## 6. TTP Coverage (MITRE ATT&CK)

| Tactic | Techniques Covered | Coverage Method |
|---|---|---|
| **Initial Access** | T1078 (Valid Accounts) | AUTH category default mapping |
| **Execution** | T1059, T1059.003 (PowerShell/cmd), T1204 (User Execution), T1218 (Signed Binary Proxy) | Heuristic triggers + category |
| **Persistence** | T1053 (Scheduled Tasks/Jobs), T1574.002 (DLL Sideloading) | Heuristic triggers |
| **Privilege Escalation** | T1134 (Access Token Manipulation), T1574.002 | Heuristic triggers |
| **Defense Evasion** | T1055 (Injection), T1562 (Tool Disable), T1027 (Obfuscation), T1112 (Registry), T1218 (LOLBin) | Heuristic triggers |
| **Credential Access** | T1003 (OS Credential Dumping), T1003.001 (LSASS Memory) | Heuristic triggers |
| **Discovery** | T1082, T1083 (via first_time_execution) | Partial — heuristic inference |
| **Lateral Movement** | T1021 (Remote Services) | Heuristic trigger |
| **Command & Control** | T1071 (Application Layer Protocol), T1071.004 (DNS) | Heuristic + DNS category |
| **Impact** | T1486 (Data Encrypted for Impact / Ransomware) | Two independent heuristics |

**Every detection** that enters the SIEM carries `mitre_id` and `mitre_tactic`. The SIEM correlator uses these fields to detect multi-stage attack chains — for example, a sequence of `T1059.003` (PowerShell execution) → `T1003.001` (LSASS dump) → `T1021` (lateral movement) over a 30-minute window would fire a correlation rule and escalate severity.

---

## 7. Response & Containment

### Automated Response Matrix

| Detection Condition | Actions Fired | Timing |
|---|---|---|
| `ransomware_canary` OR `ransomware_extension` | ISOLATE + COLLECT_FORENSICS + ROLLBACK | Immediate — same request cycle |
| `lateral_movement` AND score ≥ 90 | ISOLATE | Immediate |
| `c2_beacon` AND severity high/critical | COLLECT_FORENSICS | Immediate |
| Any detection with score ≥ 80 | CyCases case opened | Within 10 seconds (retry loop) |

### Manual Response Actions

All available to analysts+ via the Response Console UI or direct API:

| Action | What It Does on the Endpoint |
|---|---|
| **ISOLATE** | Block all network traffic except EDR management channel (TCP to platform). Implemented via WFP (Windows), iptables/nftables (Linux), pf (macOS). |
| **UNISOLATE** | Restore normal network connectivity. |
| **KILL_PROCESS** | Terminate by PID or image name. Cleans up child processes. |
| **BLOCK_HASH** | Add SHA-256 to local deny list. Any running instance of that hash is killed; future execution is blocked. |
| **COLLECT_FORENSICS** | Collect: running process list, open network connections, loaded modules, memory dump of suspicious process, recent file system changes, event log extracts. Upload package to platform for analyst review. |
| **ROLLBACK** | Invoke OS-native snapshot restore: VSS on Windows, APFS local snapshot on macOS, Btrfs/ZFS snapshot on Linux. Restores files to pre-attack state. |
| **QUARANTINE_FILE** | Move file to isolated quarantine directory with ACLs preventing execution or access by non-system processes. |
| **RUN_SCAN** | Trigger on-demand YARA scan against the endpoint's file system, using rules synchronized from the platform. |

---

## 8. Policy Engine

Seven policy types managed centrally and delivered to agents as `APPLY_POLICY` commands:

### Threat Prevention
Controls the core protection engine: real-time protection, behavioral AI engine, memory protection (injection/hollowing/shellcode), exploit prevention (heap spray, ROP chains), LSASS protection, AMSI integration, auto-quarantine, ransomware rollback, YARA scanning, PUA detection, script control (off/audit/block), and AI sensitivity (low/medium/high/aggressive).

### Device Control
Granular peripheral control matching commercial EDR capabilities:
- **USB storage:** allow / read-only / block / prompt; encrypted-only enforcement; corporate-approved device ID list
- **Wireless:** WiFi (allow all / managed approved SSIDs / block all); personal hotspot blocking; Bluetooth (allow/managed/block); Bluetooth file transfer
- **Peripherals:** camera, microphone (allow/block); removable media, CD-ROM, network/local printers
- **Data exfiltration controls:** clipboard sharing (allow/monitor/block), screen capture (allow/monitor/block)

### App Control
Execution control with four modes:
- **Off** — no restrictions
- **Audit** — log all, block nothing
- **Blacklist** — block specified apps/hashes/publishers; allow everything else
- **Whitelist** — allow only approved apps; block everything else (strict enforcement)

Additional controls: block unsigned executables, block unknown publishers, trusted system publisher bypass, script engine blocking in whitelist mode. Allows app lists by name, path, hash, or publisher.

### Network Control
Host-based firewall managed from the platform: default inbound/outbound policy, custom firewall rules, connection logging (off/anomalies/all), malicious DNS blocking (sinkhole known C2 domains from TI), custom domain sinkhole list, bandwidth monitoring, corporate proxy enforcement.

### Exclusions
Scan exclusions by: file/directory paths, process names, file extensions, SHA-256 hashes, network IP addresses/ranges. Applied globally across all protection layers.

### Update Policy
Agent auto-update configuration: update channel (stable/beta/LTS), reboot behavior (auto/prompt/defer), maintenance window (start time, end time, days of week).

### Isolation Exceptions
Define what remains accessible during full network isolation: allowed IP addresses/ranges, allowed ports, DNS resolution toggle, DHCP renewal toggle. EDR management channel is always preserved regardless of these settings.

---

## 9. Agent Deployment & Fleet Management

### Deployment Token System

Admins create **deployment tokens** with configurable constraints:
- OS type binding (windows/linux/macos/any)
- Maximum use count (prevents token reuse beyond intended scale)
- Expiry window (1–168 hours)
- Human-readable label for tracking

Agents self-enroll via `POST /api/edr/agents/self-enroll` using only the token — no admin session, no manual intervention. The platform validates the token, registers the agent, and returns a persistent enrollment token for future API calls.

### Fleet Management

The Endpoint Fleet page provides:
- Live agent cards with online/offline status (5-minute heartbeat window), isolation state, OS, asset type, open detection count, pending command count
- Stats bar: total agents, online, isolated, open detections, critical open, detections (24h), auto-responses (24h)
- Filters by status (active/all) and text search by hostname, IP, or asset type
- Quick actions: Details (→ Endpoint Detail page), Isolate/Unisolate, Collect Forensics, Run Scan

### Endpoint Detail

Per-agent deep-dive page with:
- Full metadata: hostname, IP, OS version, asset type, domain, agent version, enrollment info
- Live isolation controls with confirm dialog
- Stats: total detections, critical/high/open counts, commands issued
- **Forensic Timeline:** chronological detection event list, expandable to show MITRE ID, confidence score bar, triggered heuristics (as chips), process name, username, src/dst IPs, file path
- **Response Commands tab:** full command history with status, auto-trigger badge, parameters, timestamps
- **Applied Policies tab:** all policies currently assigned to this endpoint (direct + via group)

---

## 10. The Missing Piece — The Sensor Explained

### What "The Sensor" Means

In EDR terminology, the **sensor** (also called the **agent binary** or **kernel agent**) is the compiled executable that runs on every endpoint. It is the piece of software that:

1. **Hooks into the operating system kernel** to observe raw events as they happen
2. **Evaluates those events locally** against heuristics before sending anything to the platform
3. **Executes containment actions** directly on the endpoint when commanded

Without the sensor, CyEDR has **no visibility into any endpoint**. The backend platform — the scoring engine, the SIEM pipeline, the response orchestrator, the policy engine, the UI — is 100% built and production-ready. But it is waiting for data. The sensor is the source of that data.

Think of it this way: CyEDR as built is a fully operational airport — control tower, runways, gates, baggage systems, staff, all working. The sensor is the aircraft. Without aircraft, the airport sits idle.

### What Building the Sensor Actually Involves

The sensor is a systems-programming project, fundamentally different from building a web application. It requires expertise in:

- **Kernel programming** — operating system internals, kernel APIs, driver development
- **Low-level C/C++ or Rust** — languages that operate close to hardware with minimal runtime overhead
- **OS-specific subsystems** — three completely different implementations for Windows, Linux, and macOS
- **Real-time safety constraints** — code running in kernel context cannot crash, leak memory, or block. A kernel panic caused by the sensor crashes the endpoint.
- **Anti-tamper engineering** — the sensor must protect itself from being killed by the malware it is detecting

### The Three Kernel Implementations Required

#### Windows Sensor

**ETW (Event Tracing for Windows):**
ETW is Windows' built-in high-speed event bus. The sensor subscribes to specific providers:
- `Microsoft-Windows-Kernel-Process` — every process create/terminate, thread create/inject
- `Microsoft-Windows-Kernel-Threat-Intelligence` — memory injection detection without a driver (this is how CrowdStrike avoids some kernel driver requirements)
- `Microsoft-Windows-Kernel-Registry` — registry key reads/writes
- `Microsoft-Windows-DNS-Client` — DNS queries for C2 detection

ETW is event-driven. The sensor registers a callback that fires synchronously when events occur. The engineering challenge is that this callback runs in a constrained context — it cannot block, allocate large memory, or call many Windows APIs. Writing the deduplication engine and heuristic evaluation to operate within these constraints is non-trivial.

**WFP (Windows Filtering Platform):**
WFP is Windows' network inspection framework. The sensor registers a callout driver at the network stack layer to inspect and optionally block outbound/inbound connections. This is what enforces network isolation — the isolation command causes the sensor to install WFP filters that block all traffic except connections to the platform's IP and port. WFP callouts run in kernel mode, requiring a signed kernel driver (Windows requires Extended Validation code signing for kernel drivers — a $500+/year certificate with strict validation).

**MiniFilter Driver:**
A MiniFilter is a file system filter driver. The sensor's MiniFilter intercepts file system operations (create, write, rename, delete) before they complete. This is how ransomware canary detection works — the MiniFilter monitors writes to a set of hidden canary files. Any process that writes to these files triggers the `ransomware_canary` heuristic. The MiniFilter must be registered with Windows Filter Manager and has strict ordering requirements relative to antivirus and backup drivers.

**Windows Driver Signing:**
Every kernel component (WFP callout, MiniFilter) must be signed with an EV code signing certificate. Since 2016, Microsoft requires all kernel drivers to also be submitted to the Windows Hardware Developer Center (WHCP) for cross-signing — meaning Microsoft itself must countersign the driver. This is a formal process with submission requirements, review time, and compatibility testing.

**Windows PPL (Protected Process Light):**
To prevent the sensor from being killed by malware that achieves admin privileges, the sensor service registers as `PsProtectedSignerAntimalware-Light`. This designation prevents even `SYSTEM`-level processes from calling `OpenProcess` with termination rights. Achieving PPL status requires that the service binary be signed with a certificate that Microsoft recognizes as an antimalware vendor — this requires a formal Microsoft enrollment in the Windows Defender AV partner program.

#### Linux Sensor

**eBPF (Extended Berkeley Packet Filter):**
eBPF allows small programs to be loaded into the Linux kernel and run at specific hook points (system call entry/exit, network events, etc.) without writing a kernel module. This is the modern, safe approach to kernel-level monitoring.

The sensor attaches eBPF programs to:
- `sys_enter_execve` / `sys_exit_execve` — every process execution
- `sys_enter_connect` — every outbound network connection attempt
- `sys_enter_clone` — every process/thread creation
- `security_file_open`, `security_inode_rename` — file access and rename events

eBPF programs are verified by the kernel's BPF verifier before loading — the verifier statically analyzes the program to prove it cannot crash the kernel, cannot loop infinitely, and accesses only safe memory regions. Writing eBPF programs that pass verification while implementing complex logic (process context lookup, heuristic evaluation) requires deep eBPF expertise.

**Per-CPU ring buffers:** Events from eBPF programs are sent to user space via `bpf_perf_event_output()` into per-CPU ring buffers. The user-space agent reads from these buffers in a polling loop. Proper sizing of ring buffers is critical — undersized buffers drop events under high load; oversized buffers waste memory.

**Kernel version compatibility:** eBPF features are heavily tied to kernel version. `bpf_ringbuf` (preferred) requires kernel 5.8+. `bpf_perf_event_output` works from kernel 4.4+. The sensor must either require a minimum kernel version or detect available features at runtime and adapt. Supporting distributions like RHEL 7 (kernel 3.10) requires falling back to older mechanisms.

#### macOS Sensor

**ESF (Endpoint Security Framework):**
ESF is Apple's officially supported API for security software, introduced in macOS 10.15 (Catalina). It delivers events for process lifecycle (fork, exec, exit), file system operations, network connections, and authorization events. Unlike the older KAuth and kext approach, ESF runs in user space — it does not require a kernel extension.

However, ESF requires:
- An Apple-issued **System Extension entitlement** — applied for through the Apple Developer Program with a specific use case justification. Apple reviews and can reject applications.
- **Full Disk Access** permission — the user (or MDM) must explicitly grant this to the sensor via System Preferences / System Settings
- Code signing with a Developer ID certificate and notarization — Apple must notarize the binary before macOS Gatekeeper allows it to run

**TCC (Transparency, Consent, and Control):**
macOS's privacy framework. The sensor must monitor TCC database changes to detect when malware modifies privacy permissions (granting itself camera/mic/screen recording access). TCC database access itself requires Full Disk Access.

**APFS Snapshots:**
The rollback capability on macOS uses `tmutil` or the `FSSnapshot` API to create and restore local APFS snapshots. In practice, APFS snapshot creation requires SIP (System Integrity Protection) to be considered — on endpoints with SIP enabled (default), only entitled processes can create/restore snapshots. The sensor's entitlements must include the appropriate snapshot entitlement.

### What It Takes to Build the Sensor

| Area | Effort | Skill Required |
|---|---|---|
| Windows ETW subscriber | 8–12 weeks | Windows internals, C/C++ |
| Windows WFP callout driver | 10–16 weeks | Windows kernel driver development |
| Windows MiniFilter driver | 8–12 weeks | Windows kernel driver development |
| Windows PPL registration | 4–6 weeks | Microsoft partner enrollment + legal |
| Windows EV driver signing | 4–8 weeks | EV cert + WHCP submission |
| Linux eBPF programs | 10–16 weeks | eBPF, kernel internals, C |
| Linux kernel version compatibility | 4–8 weeks | Linux kernel expertise |
| macOS ESF integration | 8–12 weeks | macOS systems programming, Swift/ObjC/C |
| macOS Apple entitlements | 4–8 weeks | Apple Developer Program, legal review |
| Anti-tamper (all platforms) | 8–12 weeks | OS security, watchdog design |
| Local YARA scanner | 4–6 weeks | YARA library integration, performance |
| Local IOC cache + sync | 3–4 weeks | Cryptographic hash comparison, delta sync |
| Edge deduplication engine | 3–4 weeks | Ring buffer design, heuristic state machine |
| Update mechanism + rollback | 4–6 weeks | Diff patching, rollback-safe update |
| Installer + enrollment flow | 3–4 weeks | Platform-specific packaging (MSI/DEB/RPM/PKG) |
| Cross-platform test suite | 12–16 weeks | QA automation, virtual machine fleet |
| **Total realistic estimate** | **18–24 months** | **5–8 senior engineers** |

The cost and timeline reflect why commercial EDR sensors represent years of proprietary investment. CrowdStrike's Falcon sensor, for example, has been in development since 2011. SentinelOne's agent since 2013.

### The Shortcut Options

Rather than building from scratch, there are three practical paths to give CyEDR a working sensor:

**Option A — Wazuh Agent Integration (Fastest, 2–4 weeks)**
Wazuh agents are already deployed on CyCentra 360 endpoints. The Wazuh agent on Windows uses `Sysmon` (a Microsoft tool) for process/network/file telemetry, already forwarded to the platform. CyEDR could be configured to translate Wazuh/Sysmon events into the `TelemetryEnvelope` format, effectively making Wazuh the sensor. This gives 60–70% of EDR telemetry coverage with zero new sensor development. The limitation: Wazuh/Sysmon cannot do network isolation, process kill, or rollback natively — response actions would remain advisory or require integration with OS management tools.

**Option B — osquery Integration (Fast, 4–8 weeks)**
osquery is an open-source endpoint agent (used by many enterprises) that exposes OS state as SQL tables. CyEDR could query osquery for process trees, network connections, file events, and loaded modules at regular intervals. Coverage is polling-based (not real-time event-driven) but is cross-platform and well-maintained. Same limitation as Option A on response capabilities.

**Option C — Commercial Sensor OEM (6–12 months, requires partnership)**
Some EDR vendors offer OEM licensing of their sensor component. The platform (management, correlation, UI) is replaced with CyCentra 360, while the sensor binary is licensed from a partner. This is expensive but gives immediate production-grade kernel coverage.

---

## 11. Capability Comparison: CyEDR vs SentinelOne vs CrowdStrike

### Management Plane (Backend + UI)

| Capability | CyEDR | SentinelOne | CrowdStrike |
|---|---|---|---|
| Fleet management UI | Complete | Complete | Complete |
| Behavioral detection feed | Complete | Complete | Complete |
| Manual response actions (8 types) | Complete | Complete | Complete |
| Auto-response rules | Complete (3 rules) | Complete (100s of rules) | Complete (100s of rules) |
| Policy management (7 types) | Complete | Complete | Complete |
| Device control (USB/WiFi/BT/camera/mic) | Complete | Complete | Complete |
| SIEM native integration | Native — same pipeline | Requires connector | Requires connector |
| Case management integration | Native CyCases | Requires SOAR | Requires SOAR |
| MITRE ATT&CK mapping | All detections | All detections | All detections |
| Deployment token system | Complete | Complete | Complete |
| Multi-tenant | Yes (CyCentra 360 tenancy) | Yes | Yes |
| MISP threat intel enrichment | Native | Requires integration | Requires integration |
| Forensic timeline UI | Complete | Complete | Complete |

### Detection Engine

| Capability | CyEDR | SentinelOne | CrowdStrike |
|---|---|---|---|
| Behavioral heuristics | 19 triggers | Hundreds of behaviors | Hundreds of behaviors |
| **On-device ML model** | **Not built** | Static + behavioral AI model runs on-device | Falcon ML runs on-device, no cloud roundtrip |
| **Kernel-level visibility** | **Requires sensor** | PPL-protected kernel agent | PPL-protected kernel driver, ring3/ring0 |
| Zero-day coverage | Behavioral heuristics (no ML) | Behavioral AI (ML) | Behavioral AI (ML) |
| Known malware (signatures) | IOC hash match | Yes | Yes |
| Fileless attack detection | Memory injection heuristic | Full process hollowing/injection coverage | Full coverage |
| Script detection | Script control policy flag | Full PowerShell/WScript/VBA analysis | Full coverage |
| Cloud TI graph | MISP (self-hosted) | Cloud TI updated from millions of sensors globally | Threat Graph — industry-scale, graph database |
| Identity threat detection | SIEM UEBA | Dedicated Singularity Identity module | Falcon Identity Threat Detection |
| Mobile EDR (iOS/Android) | Not planned | Yes (Singularity Mobile) | Yes |
| Cloud workload (K8s/containers) | Not planned | Yes (Singularity Cloud) | Yes (Cloud Security) |
| Firmware/UEFI detection | Not planned | Limited | Yes (Falcon Firmware) |

### Response Capabilities

| Capability | CyEDR | SentinelOne | CrowdStrike |
|---|---|---|---|
| Network isolation | Yes (ISOLATE command) | Yes | Yes |
| Process kill | Yes | Yes | Yes |
| File quarantine | Yes | Yes | Yes |
| Hash blocklist | Yes | Yes | Yes |
| Rollback (VSS/APFS/Btrfs) | Yes (command queued) | Yes (1-Click Remediation + Storyline) | Yes (Falcon Forensics) |
| Automated SOAR playbooks | Manual auto_respond rules | Full SOAR integration | Full SOAR integration |
| Remote shell | Not built | Yes | Yes (Real-Time Response) |
| Automated threat hunting | Not built | Yes (Storyline Active Response) | Yes (Overwatch) |

---

## 12. Build vs Buy Analysis

### CyEDR Advantages Over Commercial EDR

**If the sensor is built (or a shortcut taken), CyEDR has structural advantages no commercial EDR can match:**

1. **No SIEM integration cost.** SentinelOne → Splunk/QRadar/SIEM requires a connector, license, data ingestion fees, and latency. CyEDR events are in the SIEM pipeline in milliseconds at zero marginal cost.

2. **No SOAR integration cost.** CrowdStrike auto-isolation → case management requires Falcon Fusion or a SOAR platform (ServiceNow, Palo Alto XSOAR). CyEDR auto-opens CyCases natively.

3. **Compliance correlation is native.** A CyEDR detection that maps to T1003.001 (LSASS dump) automatically surfaces in the GRC compliance module as a finding against ISO 27001 control A.12.6, NIST CSF DE.CM, and NIS2 requirements — because the compliance enrichment runs on every alert in the same pipeline.

4. **Single vendor, single platform.** No API surface between EDR → SIEM → SOAR → Case Management → Compliance. The blast radius of a vendor API change is zero.

5. **On-premises.** SentinelOne and CrowdStrike require cloud connectivity for their management console and cloud AI. CyEDR runs entirely air-gapped — critical for government, defence, and regulated industries that cannot send endpoint telemetry to a US SaaS provider.

### What Commercial EDR Has That CyEDR Needs

1. **The sensor.** Everything else is secondary to this.

2. **Cloud-scale threat intelligence.** MISP is powerful for an on-prem stack but is not updated with the speed or breadth of a feed from 10 million+ endpoints globally.

3. **On-device ML.** CrowdStrike and SentinelOne run trained models locally that do not need a cloud roundtrip — this is critical for air-gap scenarios and detection latency.

---

## 13. Sensor Development Roadmap

If CyCentra 360 pursues building the sensor natively, the recommended phased approach:

### Phase 1 — Python Bridge Sensor (COMPLETE as of v1.0.5+)

The Python bridge (`agent/cyedr_agent.py`) is the implemented Phase 1 sensor. It reads OS-native event sources in user space:

- **Linux:** tails `/var/log/audit/audit.log`, filters `cy360_edr_*` keys (auditd rules deployed by installer)
- **macOS:** runs `log stream` subprocess, subscribes to `kernel`, `endpointsecurity`, and `process` subsystems
- **Windows:** subscribes to `Microsoft-Windows-Sysmon/Operational` event channel via `win32evtlog` (Sysmon deployed by installer)

This gives 60–75% of kernel-level EDR telemetry without requiring driver development. The bridge is a standalone PyInstaller binary — no Python installation required on endpoints.

**Delivered capabilities:** All 19 heuristic triggers, confidence matrix, asset multipliers, SIEM pipeline injection, 7 response actions (iptables/pf/WFP isolation, KILL_PROCESS, QUARANTINE_FILE, ROLLBACK, RUN_SCAN, COLLECT_FORENSICS, BLOCK_HASH), policy engine, deployment tokens, anti-tamper watchdog, IOC cache.

**Limitation vs native kernel sensor:** Event delivery is slightly delayed (log file polling vs real-time kernel callback). Process injection and hollowing detection is auditd/Sysmon-based rather than direct kernel memory inspection. Network isolation is OS firewall-based rather than WFP callout or eBPF network hook.

Deliverable: CyEDR detections firing from real endpoint data. FULLY SHIPPED.

### Phase 2 — Native Linux Sensor (Months 3–10)

Build the eBPF-based Linux sensor first. eBPF is the most accessible kernel programming environment — no driver signing required, no PPL, no Apple entitlements. Run on internal infrastructure. This validates the telemetry pipeline and heuristic trigger design against real kernel events.

Deliverable: Production Linux sensor. Deploy internally and to Linux-heavy customer segments.

### Phase 3 — macOS Sensor (Months 8–14)

ESF-based macOS sensor. Requires Apple entitlements (4–8 weeks to obtain). Build in parallel with Phase 2 where possible. Primarily targets macOS-heavy corporate environments.

Deliverable: macOS sensor with Full Disk Access deployment via MDM.

### Phase 4 — Windows Sensor (Months 12–24)

The most complex phase. ETW subscriber first (no driver signing required), then WFP callout and MiniFilter drivers (require EV cert + WHCP submission + PPL enrollment). Windows drives the majority of enterprise EDR demand.

Deliverable: Full Windows sensor with PPL anti-tamper protection.

### Phase 5 — On-Device ML (Months 18–30)

Train a behavioral classification model on the telemetry collected from Phases 1–4. Deploy as a lightweight ONNX model loaded by the agent, running inference locally. This closes the last major gap versus SentinelOne/CrowdStrike.

Deliverable: Zero-day detection without cloud roundtrip, matching commercial EDR AI capability.

---

*Document maintained by CyCentra 360 Engineering. For questions contact the platform team.*
