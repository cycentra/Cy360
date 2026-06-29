# ITAM Module — IT Asset Management Reference

> CyCentra 360 v1.0.60+ · Last updated 2026-06-29

---

## Overview

The ITAM module extends CyCentra 360 with full IT Asset Management capabilities, bridging network asset visibility with endpoint security (CyEDR), SIEM coverage, GRC compliance, and Shadow AI governance.

### What ITAM adds

| Capability | How it works |
|---|---|
| **Network asset inventory** | Three additive discovery sources feed a single `network_assets` table |
| **EDR coverage gap** | Cross-references `edr_agents` + `host_posture_cache` by IP — shows uncovered hosts |
| **IoT / OT device registry** | OUI vendor lookup + port fingerprinting classifies non-agent devices |
| **Shadow AI detection** | CyEDR process scan + Wazuh Sysmon DNS/network events catch unauthorized AI tools |
| **Compliance auto-feed** | `itam_bridge.py` writes evidence to `cy_comp_questionnaire_responses` every 6 hours |

---

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │           DISCOVERY SOURCES              │
                         │                                          │
                         │  ① CMDB CSV Import (manual, highest pri) │
                         │  ② ARP Neighbors (CyEDR heartbeat)       │
                         │  ③ nmap Subnet Scan (admin on-demand)    │
                         └──────────────┬──────────────────────────┘
                                        │ upsert_assets()
                                        ▼
                              ┌──────────────────┐
                              │  network_assets  │  (PostgreSQL)
                              │  (CYCENTRA DB)   │
                              └────────┬─────────┘
                    ┌─────────────────┼───────────────────┐
                    ▼                 ▼                    ▼
           ┌──────────────┐  ┌──────────────┐   ┌──────────────────┐
           │  iot_devices │  │ shadow_ai_   │   │  ai_tool_        │
           │  (risk       │  │ findings     │   │  whitelist       │
           │   scoring)   │  │ (open/esc.)  │   │  (approved list) │
           └──────────────┘  └──────────────┘   └──────────────────┘
                    │                 │
                    └────────┬────────┘
                             ▼
                   ┌──────────────────┐
                   │  itam_bridge.py  │ (6h APScheduler job)
                   │  Compliance feed │
                   └────────┬─────────┘
                            ▼
              cy_comp_questionnaire_responses
              cy_comp_findings (when coverage < 50%)
```

---

## Database Schema

### `network_assets`

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PK | |
| `ip_address` | VARCHAR(45) | UNIQUE — upsert key |
| `hostname` | TEXT | |
| `mac_address` | VARCHAR(20) | |
| `asset_type` | VARCHAR(50) | workstation/server/printer/camera/network_device/iot_device/unknown |
| `vendor` | TEXT | OUI lookup or CMDB supplied |
| `os_info` | TEXT | From SIEM/EDR if known |
| `edr_agent_id` | TEXT | FK to edr_agents (null if uncovered) |
| `siem_agent_id` | TEXT | FK to host_posture_cache (null if uncovered) |
| `is_managed` | BOOLEAN | True if edr or siem covered |
| `discovery_source` | VARCHAR(20) | arp / cmdb / nmap |
| `notes` | TEXT | Manual annotations |
| `tags` | TEXT | Comma-separated |
| `first_seen` | TIMESTAMPTZ | |
| `last_seen` | TIMESTAMPTZ | Updated on every upsert |

**Indexes:** `ip_address` (unique), `edr_agent_id`, `siem_agent_id`

**Discovery source priority (upsert logic):**
- `cmdb` → overwrites ALL fields unconditionally
- `arp` / `nmap` → only fills empty fields (never overwrites CMDB data)

### `iot_devices`

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PK | |
| `network_asset_id` | INTEGER | FK → network_assets |
| `ip_address` | VARCHAR(45) | UNIQUE |
| `mac_address` | VARCHAR(20) | |
| `vendor` | TEXT | From OUI table |
| `device_category` | VARCHAR(50) | camera/printer/hvac_bms/industrial/smart_device/network_device/embedded/unknown |
| `open_ports` | JSONB | `[{"port": 554, "service": "rtsp", "category": "camera"}]` |
| `risk_score` | INTEGER | 0–100 composite |
| `risk_factors` | JSONB | List of human-readable risk strings |
| `default_creds_risk` | BOOLEAN | True if ITAM_PROBE_CREDS=true and probe succeeded |
| `has_telnet` | BOOLEAN | Port 23 open |
| `no_tls_on_mgmt` | BOOLEAN | Port 80 open but not 443 |
| `mdns_service_type` | TEXT | From mDNS discovery |
| `notes` | TEXT | |
| `last_seen` | TIMESTAMPTZ | |

### `shadow_ai_findings`

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PK | |
| `agent_id` | TEXT | CyEDR agent that reported |
| `hostname` | TEXT | Endpoint hostname |
| `ai_tool` | TEXT | Normalized tool name (e.g. "ollama", "lm_studio") |
| `process_name` | TEXT | Exact process name observed |
| `detection_method` | VARCHAR(20) | process / dns / network |
| `severity` | VARCHAR(10) | critical/high/medium/low |
| `status` | VARCHAR(20) | open / approved / suppressed / escalated |
| `whitelisted` | BOOLEAN | True if tool was on approved list at detection time |
| `first_seen` | TIMESTAMPTZ | |
| `last_seen` | TIMESTAMPTZ | |
| `resolved_at` | TIMESTAMPTZ | Set when status → approved/suppressed |
| `resolved_by` | TEXT | User email who acted |

### `ai_tool_whitelist`

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PK | |
| `ai_tool` | TEXT | UNIQUE — normalized lowercase tool name |
| `vendor` | TEXT | e.g. GitHub, Microsoft |
| `rationale` | TEXT | Why approved |
| `approved_by` | TEXT | User email |
| `created_at` | TIMESTAMPTZ | |

---

## API Endpoints

### Asset Coverage (`/api/itam/`)

| Method | Path | RBAC | Description |
|---|---|---|---|
| GET | `/api/itam/coverage` | viewer+ | Coverage summary KPIs |
| GET | `/api/itam/assets` | viewer+ | Paginated asset list with filters |
| PUT | `/api/itam/assets/<id>` | analyst+ | Update asset type/notes/tags |
| DELETE | `/api/itam/assets/<id>` | admin | Remove asset |
| POST | `/api/itam/assets/import` | admin | Upload CMDB CSV |
| POST | `/api/itam/assets/scan` | admin | Trigger nmap subnet scan |

#### `GET /api/itam/coverage` — Response

```json
{
  "total_network_assets": 342,
  "edr_covered": 198,
  "siem_covered": 210,
  "both_covered": 185,
  "uncovered": 72,
  "coverage_pct": 79.0,
  "iot_devices": 24,
  "shadow_ai_open": 3,
  "sources": {"arp": 201, "cmdb": 85, "nmap": 56},
  "breakdown": {"workstation": 120, "server": 45, "printer": 12, ...}
}
```

#### `GET /api/itam/assets` — Query Parameters

| Param | Values | Description |
|---|---|---|
| `page` | int | Default 1 |
| `per_page` | int | Default 50, max 200 |
| `asset_type` | workstation/server/printer/... | Filter by type |
| `covered` | yes/no/edr/siem | Filter by coverage status |
| `q` | string | Search IP, hostname, vendor |

#### `POST /api/itam/assets/import` — CMDB CSV Format

Required column: `ip_address`
Optional columns: `hostname`, `mac_address`, `asset_type`, `vendor`, `notes`, `tags`

```csv
ip_address,hostname,mac_address,asset_type,vendor,notes
192.168.1.10,webserver-01,00:11:22:33:44:55,server,Dell,Production web tier
192.168.1.20,printer-lobby,AA:BB:CC:DD:EE:FF,printer,HP,
```

### IoT Registry (`/api/itam/iot/`)

| Method | Path | RBAC | Description |
|---|---|---|---|
| GET | `/api/itam/iot` | viewer+ | Paginated IoT devices |
| GET | `/api/itam/iot/risk-summary` | viewer+ | Risk counts + by-category |
| GET | `/api/itam/iot/<id>` | viewer+ | Device detail |
| PUT | `/api/itam/iot/<id>` | analyst+ | Update device notes/category |
| POST | `/api/itam/iot/scan` | analyst+ | Trigger IoT-specific subnet scan |

#### `GET /api/itam/iot` — Query Parameters

| Param | Description |
|---|---|
| `risk_min` | Minimum risk score (0, 25, 50, 75) |
| `category` | Filter by device_category |

#### `GET /api/itam/iot/risk-summary` — Response

```json
{
  "total": 24,
  "critical": 2,
  "high": 5,
  "medium": 9,
  "low": 8,
  "default_creds": 1,
  "by_category": {"camera": 8, "printer": 6, "hvac_bms": 4, "industrial": 2, "unknown": 4}
}
```

### Shadow AI (`/api/itam/shadow-ai/`)

| Method | Path | RBAC | Description |
|---|---|---|---|
| GET | `/api/itam/shadow-ai` | viewer+ | Paginated findings |
| GET | `/api/itam/shadow-ai/summary` | viewer+ | Counts + 7d/30d trend + by-tool |
| PUT | `/api/itam/shadow-ai/<id>/status` | analyst+ | Set status (open/approved/suppressed/escalated) |
| GET | `/api/itam/ai-whitelist` | viewer+ | List approved tools |
| POST | `/api/itam/ai-whitelist` | admin | Add approved tool |
| DELETE | `/api/itam/ai-whitelist/<id>` | admin | Remove approved tool |

#### `GET /api/itam/shadow-ai` — Query Parameters

| Param | Values | Description |
|---|---|---|
| `status` | open/approved/suppressed/escalated | Filter by status |
| `severity` | critical/high/medium/low | Filter by severity |
| `hostname` | string | Filter by endpoint hostname |
| `ai_tool` | string | Filter by tool name |

---

## Shadow AI Detection

### Layer 1 — CyEDR Process Scan

The CyEDR agent scans the running process list every heartbeat cycle for known Shadow AI process names:

```
ollama, lm_studio, lmstudio, jan, gpt4all, koboldcpp, kobold_cpp,
text-generation-webui, textgenwebui, llamafile, llama.cpp, llama-server,
llama-cpp, comfyui, stable-diffusion-webui, invokeai, whisper, localai,
localai-server, open-webui, msty, chatbox
```

When detected, a `TelemetryEnvelope` with `event_category="shadow_ai"` is sent to `/api/edr/telemetry`. The telemetry ingestion handler intercepts this category **before** normalisation, routing to `ingest_shadow_ai()` instead of the EDR detections + SIEM pipeline. Shadow AI events do NOT generate SIEM alerts — they are pure governance events.

### Layer 2 — Wazuh Sysmon DNS (Windows)

Wazuh rules 101040 and 101041 in `cy_cust_rules.xml`:
- Rule 101040 (level 6): Sysmon EventID 22 — DNS query to known AI API domains
- Rule 101041 (level 6): Sysmon EventID 3 — Network connection to AI API hosts

These fire when `cycentra_sysmon_config.xml` captures DNS and network events. The DNS capture covers all non-Microsoft domains via the `<DnsQuery>` filter.

### Layer 3 — Local AI Service Port Detection

Rule 101042 (level 7): Detects processes listening on local AI ports:
- Ollama: 11434
- LM Studio: 1234
- Stable Diffusion WebUI: 7860

### Whitelist Enforcement

Before creating a finding, `ingest_shadow_ai()` queries `ai_tool_whitelist` for the normalized tool name. Whitelisted tools do NOT generate findings — they are silently dropped. The CyEDR agent refreshes its local copy of the whitelist hourly from `/api/edr/installer/custom-yara` (same endpoint mechanism).

---

## IoT Classification Engine

### OUI Vendor Lookup

`iot_classifier.py` contains `OUI_TABLE` — a dictionary of 60+ MAC address OUI prefixes mapped to `(vendor, device_category)`. Categories include:

| Category | Examples |
|---|---|
| `camera` | Hikvision, Dahua, Axis Communications, Hanwha |
| `printer` | HP Enterprise, Canon, Epson, Brother |
| `network_device` | Cisco, Ubiquiti, Ruckus, Aruba |
| `smart_device` | Nest, Ring, Lutron, Ecobee |
| `hvac_bms` | Siemens BT, Honeywell, Johnson Controls |
| `industrial` | Rockwell, Schneider, GE Digital |
| `embedded` | Raspberry Pi Foundation |

### Port Fingerprinting

After OUI classification, open ports from nmap are compared against `PORT_SIGNATURES`:

| Port | Service | Category | Risk delta |
|---|---|---|---|
| 23 | Telnet | ANY | +20 |
| 554 | RTSP | camera | +15 |
| 631 | IPP | printer | 0 |
| 1883 | MQTT | smart_device | +10 |
| 502 | Modbus | industrial | +25 |
| 4840 | OPC-UA | industrial | +15 |
| 47808 | BACnet | hvac_bms | +20 |
| 80 | HTTP (no HTTPS) | ANY | +10 |

### Risk Score Calculation

Base score starts at 10 for any IoT candidate. Risk is added for:
- Port 23 open (Telnet): +20
- No TLS on management interface: +10
- High-risk industrial ports (Modbus/BACnet): +20–25
- Default credentials confirmed: +40
- Network-exposed camera (RTSP): +15
- Smart device with MQTT: +10

Maximum: 100. Risk tiers: LOW (0–24), MEDIUM (25–49), HIGH (50–74), CRITICAL (75+).

### Default Credential Probing

Only active when `ITAM_PROBE_CREDS=true` (default: false). When enabled, `probe_default_creds()` attempts known default credentials per vendor against port 80/8080/443. This is opt-in to avoid unintended network interaction.

---

## Discovery Sources

### Source 1: CMDB CSV Import

- Triggered via UI (Asset Coverage page → Import CMDB) or `POST /api/itam/assets/import`
- CSV must have `ip_address` column; all others are optional
- CMDB data has highest priority — it overwrites any previously discovered data for matching IPs
- After import, `_crossref_agents_conn()` runs in a background thread to link new assets to EDR/SIEM agents
- After import, IoT classification runs for any asset with a known MAC address

### Source 2: ARP Neighbors (CyEDR Heartbeat)

- The CyEDR agent collects ARP table entries on every heartbeat (every 60s)
- Platform: `arp -a` on Linux/macOS, `arp -a` on Windows (parsed cross-platform)
- Filtered: loopback (127.x, ::1), link-local (169.254.x, fe80::), broadcast, multicast
- Sent as `arp_neighbors: [{ip, mac}]` in the heartbeat payload
- Backend `agent_heartbeat()` handler calls `ingest_arp_neighbors()` in a daemon thread
- ARP data fills empty fields only — never overwrites CMDB-supplied data

### Source 3: nmap Subnet Scan (Admin On-Demand)

- Triggered via UI or `POST /api/itam/assets/scan`
- Requires `ITAM_SUBNET` env var (e.g. `192.168.1.0/24`)
- Command: `nmap -sn -PS22,80,443 --open -p <ITAM_IOT_PORTS> -oX -`
- Default ports scanned: `22,23,80,443,554,631,8080,8443,8883,9100,161,502,1883,4840,47808`
- Results parsed from nmap XML output — hostname, MAC, open ports, vendor
- Runs asynchronously in a daemon thread; page auto-refreshes on completion
- IoT classification + agent cross-reference run after scan completes

### Cross-Reference Logic

`_crossref_agents_conn()` runs after every import, scan, or ARP ingest:

```sql
-- Link network_assets to CyEDR agents by IP
UPDATE network_assets na
SET edr_agent_id = ea.agent_id, is_managed = true
FROM edr_agents ea
WHERE ea.ip_address = na.ip_address AND na.edr_agent_id IS NULL;

-- Link network_assets to SIEM agents by IP
UPDATE network_assets na
SET siem_agent_id = hp.agent_id, is_managed = true
FROM host_posture_cache hp
WHERE hp.ip_address = na.ip_address AND na.siem_agent_id IS NULL;

-- Auto-insert EDR-covered hosts not yet in network_assets
INSERT INTO network_assets (ip_address, hostname, edr_agent_id, is_managed, discovery_source)
SELECT ip_address, hostname, agent_id, true, 'edr'
FROM edr_agents ea
WHERE ea.ip_address IS NOT NULL AND ea.ip_address NOT IN (SELECT ip_address FROM network_assets)
ON CONFLICT (ip_address) DO NOTHING;
```

---

## Compliance Auto-Feed

`cy_comp/services/itam_bridge.py` runs every 6 hours via APScheduler.

### Controls Populated

| Control ID | Framework | What triggers it |
|---|---|---|
| `nist-id-01` | NIST CSF | Asset inventory coverage % |
| `iso-org-06` | ISO 27001 | Asset inventory coverage % |
| `dora-asset-01` | DORA | Asset inventory coverage % |
| `nis2-asset-01` | NIS2 | Asset inventory coverage % |
| `euai-ai-inv-01` | EU AI Act | Shadow AI findings + approved tools |
| `iso-ai-mgmt` | ISO 42001 | Shadow AI management posture |

### Evidence Format

Coverage-based controls write evidence like:
```
Asset inventory: 342 assets discovered (ARP: 201, CMDB: 85, nmap: 56). 
EDR coverage: 79% (271/342 assets). SIEM coverage: 61% (208/342 assets). 
IoT devices: 24 classified. Last sync: 2026-06-29 14:00 UTC
```

Shadow AI controls write:
```
Shadow AI governance: 3 open findings, 12 suppressed, 8 approved tools on whitelist.
Detection: CyEDR process scan + Wazuh Sysmon DNS/network telemetry.
```

### Auto-Finding Threshold

When EDR coverage drops below 50%, a `cy_comp_findings` record is written:
- Category: `asset_management`
- Severity: `medium`
- Title: `Asset Management — EDR coverage below threshold`

---

## Environment Variables

Declare in `/opt/cycentra/.env`:

| Variable | Default | Description |
|---|---|---|
| `ITAM_SUBNET` | *(empty)* | Subnet for nmap scan, e.g. `192.168.1.0/24` |
| `ITAM_IOT_PORTS` | `22,23,80,443,554,631,8080,8443,8883,9100,161,502,1883,4840,47808` | Ports scanned during IoT discovery |
| `ITAM_PROBE_CREDS` | `false` | Set `true` to enable default credential probing (use with caution) |

---

## Frontend Pages

### Asset Coverage (`/portal/#itam-coverage`)

- **KPI row**: Total Assets · EDR Covered (%) · SIEM Covered · Uncovered · IoT Devices · Shadow AI open
- **Coverage bar**: Color-coded (green ≥80%, amber ≥50%, red <50%)
- **Asset type breakdown**: grid of type → count with color coding
- **CMDB Import**: Admin button — opens file picker for CSV upload
- **Subnet Scan**: Admin button — triggers nmap scan, auto-refreshes after 15s
- **Tab filter**: All Assets | Uncovered (N) | EDR Covered (N)
- **Search**: IP, hostname, vendor substring match
- **Table**: IP · Hostname · Vendor · Type · EDR · SIEM · Source · Last Seen

### IoT Registry (`/portal/#itam-iot`)

- **KPI row**: Total IoT · Critical · High · Medium · Default Creds
- **Category breakdown**: pills showing count per device category with icons
- **Run IoT Scan**: Analyst+ button — triggers IoT-specific nmap scan
- **Risk filter**: All / ≥25 / ≥50 / ≥75 buttons
- **Table**: Icon · IP · Vendor · Category · Open Ports · Risk · Default Creds · Last Seen
- **Detail panel**: Click any row to expand risk factors for that device

### Shadow AI Monitor (`/portal/#itam-shadow-ai`)

- **KPI row**: Open Findings · Escalated · Approved · Suppressed · Unique Tools
- **Tool breakdown**: by-tool pills showing count per detected AI tool
- **Findings tab**: Findings list with status filter (open/escalated/approved/suppressed/all)
  - Inline actions: Approve / Escalate / Suppress / Reopen
  - Detection method icons: 🖥 Process / 🌐 DNS / 🔌 Network
- **Approved AI Tools tab**: Manage the enterprise AI whitelist
  - Add tool with name, vendor, rationale
  - Remove tools (admin only)
  - Note: whitelist updates propagate to all CyEDR agents within 1 hour

---

## File Map

| File | Purpose |
|---|---|
| `backend/blueprints/itam/__init__.py` | Python package init |
| `backend/blueprints/itam/routes.py` | All ITAM API routes + `init_itam_tables()` |
| `backend/blueprints/itam/network_discovery.py` | CMDB parse, ARP parse, nmap runner |
| `backend/blueprints/itam/iot_classifier.py` | OUI table, port signatures, risk scoring |
| `backend/cy_comp/services/itam_bridge.py` | Compliance auto-feed (6h APScheduler job) |
| `backend/core/config.py` | ITAM env vars: ITAM_SUBNET, ITAM_IOT_PORTS, ITAM_PROBE_CREDS |
| `backend/blueprints/scheduler/routes.py` | Registers `itam_compliance_sync` job |
| `backend/blueprints/edr/routes.py` | Heartbeat extended: ARP ingest + Shadow AI intercept |
| `agent/cyedr_agent.py` | ARP neighbor collection + Shadow AI process scan |
| `CYSIEM-Config/rules/cy_cust_rules.xml` | Rules 101040/101041/101042 (Shadow AI DNS/network) |
| `portal/src/pages/itam/index.jsx` | Asset Coverage Dashboard |
| `portal/src/pages/itam/IotRegistryPage.jsx` | IoT Device Registry |
| `portal/src/pages/itam/ShadowAiPage.jsx` | Shadow AI Monitor + Whitelist |
| `portal/src/sidebar/navConfig.jsx` | ASSET MANAGEMENT section (3 nav items) |
| `portal/src/components/AppRouter.jsx` | Routes for itam-coverage/iot/shadow-ai |

---

## Troubleshooting

### Assets not appearing after ARP import

1. Check CyEDR agent is running and connected: `GET /api/edr/fleet`
2. Check the heartbeat includes `arp_neighbors`: look for `"arp_neighbors"` in `backend/` logs
3. Check the EDR blueprint log for `[ITAM] ingest_arp_neighbors agent_id=...` — if missing, the heartbeat handler isn't calling it
4. Verify the `network_assets` table exists: `psql -p 5432 -d cycentra -c "\d network_assets"` (or port 5433 for correlation DB — ITAM uses the main `cycentra` DB)

**Note:** ITAM uses the main Flask DB (`CYCENTRA_DB_URL`), not the correlation engine DB on port 5433.

### nmap scan returns no results

1. Verify `ITAM_SUBNET` is set in `/opt/cycentra/.env`
2. Test nmap directly: `nmap -sn 192.168.1.0/24`
3. Check the Flask process has permission to run nmap (may need `setuid` or `sudo` exception)
4. Check scan logs in the Flask backend: look for `[ITAM] nmap scan starting` and `[ITAM] nmap scan complete`

### IoT devices not classified

1. IoT classification only runs after nmap (not ARP-only) — run a full scan
2. Check the MAC address is in the OUI_TABLE: `grep -i "MAC_PREFIX" blueprints/itam/iot_classifier.py`
3. If MAC is missing from OUI_TABLE, add it — the table is in `iot_classifier.py:OUI_TABLE`
4. Port-based classification works even without MAC — ensure the nmap scan includes the IoT ports list

### Shadow AI findings not appearing

1. Check CyEDR agent version includes Shadow AI process scan (`SHADOW_AI_PROCESSES` in `cyedr_agent.py`)
2. Confirm the target process name matches the `_SHADOW_AI_RE` pattern: `python3 -c "import re; print(re.search(r'(?i)(ollama)[\s\"\'\\\/]', 'ollama serve'))"` 
3. Check the telemetry endpoint is receiving `event_category=shadow_ai` events
4. Check if the tool is on the whitelist — whitelisted tools do not generate findings: `GET /api/itam/ai-whitelist`
5. For Wazuh DNS-based detection: verify Sysmon is deployed and capturing EventID 22 events

### Compliance sync not running

1. Check the scheduler is registered: `GET /api/scheduler/jobs` — look for `itam_compliance_sync`
2. Check that `network_assets` table exists (bridge skips gracefully if table is missing)
3. Check `backend/` logs for `[ITAM-BRIDGE]` log lines — the job logs start, count, and completion
4. Manually trigger: `POST /api/scheduler/run` with `{"job_id": "itam_compliance_sync"}`

### `app.py` line limit violated

`app.py` must stay ≤70 lines. The ITAM registration uses a single-line try/except pattern:
```python
try: init_itam_tables(CYCENTRA_DB_URL)
except Exception as _e: pass
```
Do not expand this to multi-line without checking the total line count.

---

## Enhancement Notes

### Adding new IoT device types

Edit `backend/blueprints/itam/iot_classifier.py`:

1. Add OUI entries to `OUI_TABLE`:
   ```python
   "xx:xx:xx": ("Vendor Name", "device_category"),
   ```
2. Add port signatures to `PORT_SIGNATURES` if the device uses a proprietary port:
   ```python
   9999: ("proprietary-mgmt", "device_category", 15),
   ```
3. Add to `CATEGORY_ICONS` in `IotRegistryPage.jsx` and `ShadowAiPage.jsx` if a new category.

### Adding new Shadow AI tools

Edit `agent/cyedr_agent.py` → `SHADOW_AI_PROCESSES` list. The regex is rebuilt automatically from the list. No backend changes needed — the regex is compiled at agent startup.

For Wazuh-based detection of new AI domains, add the domain to Rule 101040's `<match>` pattern in `CYSIEM-Config/rules/cy_cust_rules.xml`.

### Adding new compliance controls

Edit `cy_comp/services/itam_bridge.py`:
1. Add the control ID to `ASSET_INVENTORY_CONTROLS` or `AI_INVENTORY_CONTROLS`
2. Implement a corresponding question template in `cy_comp/data/` if needed
3. Run `seed_templates(force=True)` on next startup (automatic)

### Enabling nmap privileged scan (SYN scan)

The current scan uses `-sn -PS` (ping scan). For more accurate port detection, administrators can add a `sudoers` entry:
```
cycentra ALL=(root) NOPASSWD: /usr/bin/nmap
```
Then change `run_nmap_discovery()` to use `sudo nmap -sS` for SYN scan (requires root).

---

## Security Considerations

- **ITAM_PROBE_CREDS**: Default credential probing is disabled by default. Enable only in environments where you have explicit authorization to test device credentials. This feature connects to device management interfaces.
- **nmap scan authorization**: Ensure network scanning is authorized for the target subnet. Unapproved scanning may violate network policies.
- **Shadow AI whitelist management**: Only admins can add/remove tools. All whitelist changes are logged in the audit trail.
- **ITAM routes use the same dual-auth model** as the rest of CyCentra 360: session RBAC for UI users, Bearer enrollment token for agent-facing endpoints (`ingest_arp_neighbors`, `ingest_shadow_ai`).
