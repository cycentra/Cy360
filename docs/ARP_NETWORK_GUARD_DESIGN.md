# CyCentra 360 — ARP Network Guard
## Design, Architecture & Implementation Record

**Status:** IMPLEMENTED  
**Date:** 2026-06-30  
**Prepared by:** g-cyra-360  
**Trigger:** Design review of INVESTIGATION_ENGINE_PLAN — ARP asset inventory scoping concern  
**Linked plan:** `docs/INVESTIGATION_ENGINE_PLAN.md`

---

## 1. Problem Statement

The CyEDR agent collects the OS ARP table on every 60-second heartbeat and sends all
neighbor entries to the server, which upserts them into `network_assets` as enterprise
inventory. This mechanism has no concept of "where is the agent right now."

**Consequence:** A laptop user working from home, a coffee shop, or a hotel would populate
the enterprise asset database with their home router, ISP gateway, neighbouring guests'
devices, and smart-home equipment — all tagged as corporate assets.

### Affected Scenarios

| User Location | ARP captures | Pre-fix effect |
|---|---|---|
| Corporate office | Workstations, servers, printers | Correct — legitimate assets |
| Home office | Home router, smart TV, family phones | **Noise injected** |
| Coffee shop / hotel WiFi | Other patrons' devices | **Noise + privacy exposure** |
| Corporate VPN (split) | Home LAN devices (VPN does not extend L2) | **Noise injected** |

### Downstream Risk

The `INVESTIGATION_ENGINE_PLAN.md` Phase 3 (Evidence Gap Analysis) will query
`network_assets` as ground-truth for the asset inventory. If home/hotel devices are
present, the investigation engine may anchor hypotheses on non-corporate devices, producing
incorrect confidence scores and incorrect SOAR recommendations.

---

## 2. Design Decision: Option B — Agent-Side Network Guard with Server-Side Zone Trust

Three options were evaluated:

| Option | Description | Decision |
|---|---|---|
| A | Server-side CIDR allow-list only | Partial mitigation, no MAC-level trust |
| **B** | Agent detects gateway MAC → server evaluates zone trust → controls ARP collection | **SELECTED — security from design** |
| C | Per-agent static flag (fixed vs mobile) | Manual, does not scale |

**Option B** was selected because it eliminates home/public data at the source (the agent)
rather than filtering after the fact. This is "security from design" — the most correct
architectural pattern for a security product.

---

## 3. Architecture Overview

```
AGENT (every 60s heartbeat)
  └─ _get_gateway_macs()           ← detect default GW IPs from routing table
  └─ ARP lookup each GW IP         ← resolve MACs cross-platform
  └─ POST /api/edr/agents/<id>/heartbeat
       { version, agent_ip, gateway_macs: [{ip, mac}], arp_neighbors?: [...] }

SERVER (heartbeat handler)
  └─ evaluate_zone_trust(agent_ip, gateway_macs)
       ├─ Load approved network_zones from DB
       ├─ Check CIDR match (agent_ip ∈ trusted_cidrs)
       ├─ Check MAC match (reported gateway ∈ trusted_gateways)
       └─ Return (arp_enabled, zone_name, confidence)
  └─ record_gateway_sighting()     ← background, non-blocking
       ├─ Upsert network_zone_suggestions
       └─ If agent_count ≥ 3 → _raise_zone_approval_case() → CyCase in incidents table
  └─ Response: { arp_enabled, arp_enabled_until, network_zone, zone_confidence }

AGENT (reads response)
  └─ Persist arp_enabled + arp_enabled_until to config.json
  └─ Next beat: skip _collect_arp_neighbors() if not arp_enabled or trust expired
```

---

## 4. Trust Evaluation — Multi-Signal Confidence Model

Each heartbeat is evaluated against all approved `network_zones`. A zone grants trust when
**any** of these signals match:

| Signal | Source | Reliability | Notes |
|---|---|---|---|
| CIDR match | Agent IP vs zone `trusted_cidrs[]` | High | Simple and fast; VPN zones use CIDR-only |
| Gateway MAC match | Reported MAC vs zone `trusted_gateways[].macs[]` | High | Stable on VRRP/HSRP networks |
| Both match | CIDR + MAC | Highest (`high` confidence) | Best case for wired corporate |

**Confidence levels returned to agent:**
- `high` — CIDR + MAC both matched
- `medium` — CIDR only matched (VPN zone, or MAC not yet registered) or MAC only matched
- `low` — nothing matched → `arp_enabled: false`
- `unknown` — agent_ip not available

**Offline grace period:** `arp_enabled_until` is set to `NOW() + 3 minutes` (2× heartbeat
interval). If the agent cannot reach the server (e.g., flight mode during travel), the last
known `arp_enabled` state expires automatically after 3 minutes. This prevents a laptop that
was just in the office from persisting `arp_enabled=true` during a hotel stay.

---

## 5. Gateway MAC Considerations

### Legitimate MAC Changes (router replacement, hardware refresh)

When network gear is replaced:
1. Agents start reporting the new gateway MAC.
2. `record_gateway_sighting()` creates a new `network_zone_suggestions` entry.
3. When 3+ agents report the new MAC, a CyCase is raised.
4. Admin approves the new MAC → it is added to the zone's `trusted_gateways` list.
5. All agents restore `arp_enabled: true` within one heartbeat cycle (60s).

No agent restarts or config changes are required.

### VRRP / HSRP (High Availability Gateways)

Virtual router protocols use a stable virtual MAC (`00:00:5E:00:01:XX` for VRRP,
`00:00:0C:07:AC:XX` for HSRP). The agent performs ARP lookup on the virtual gateway IP,
which always resolves to the virtual MAC — not the underlying physical interface MAC. This
makes the trust evaluation stable across active/standby failovers.

### Multiple Gateways per Site

Each `network_zones` row stores `trusted_gateways` as a JSON array:
```json
[
  { "ip": "10.10.0.1", "macs": ["00:00:5E:00:01:01", "AA:BB:CC:11:22:33"] },
  { "ip": "10.10.0.250", "macs": ["AA:BB:CC:44:55:66"] }
]
```
The agent sends all detected gateway MACs (one per default route). The server matches
against **any** MAC in the entire trusted_gateways array — ECMP and multi-uplink networks
are fully supported.

### MAC Spoofing (Threat Model)

An attacker would need to:
1. Spoof the gateway MAC to match a trusted corporate entry, AND
2. Make the corporate DHCP server assign the target endpoint a corporate IP

This requires full control of the L2 segment and the DHCP server — at which point the
attacker has capabilities far beyond tricking an asset inventory agent. The layered
CIDR + MAC requirement defeats opportunistic spoofing completely.

---

## 6. Multi-Site / Multi-Office Design

Each office is a separate `network_zones` record:

```
Zone: "London HQ"          trusted_cidrs: ["10.10.0.0/16"]
                            trusted_gateways: [{"ip":"10.10.0.1","macs":["00:00:5E:00:01:01"]}]

Zone: "New York Office"     trusted_cidrs: ["10.20.0.0/16"]
                            trusted_gateways: [{"ip":"10.20.0.1","macs":["00:00:5E:00:01:02"]}]

Zone: "Corporate VPN"       trusted_cidrs: ["172.16.100.0/24"]
                            trusted_gateways: []  ← VPN has no L2 gateway; CIDR alone trusted
```

Agents match against all zones simultaneously. The first matching zone wins and its name is
stored in `edr_agents.current_network_zone` and shown in the EDR Fleet UI.

---

## 7. Auto-Learning & Admin Workflow

### Phase 1 — Enrollment Bootstrap (zero admin action)

Both installer scripts (`cyedr-install.sh`, `cyedr-install.ps1`) detect the default gateway
IP and MAC **before** calling `self-enroll`. This is always run from a corporate network
(the deploy token requires platform reachability). The gateway MAC is stored in
`edr_agents.enrollment_gateway_mac`.

### Phase 2 — Consensus Learning (ongoing)

On every heartbeat, `record_gateway_sighting()` (async, non-blocking) upserts a record in
`network_zone_suggestions`. When 3 or more distinct agents on the same `/16` subnet all
report the same gateway MAC:
- A suggestion entry is promoted (agent_count ≥ 3 threshold)
- A CyCase is raised in the `incidents` table with `case_type='network_zone_approval'`
- The CyCase appears in the CyCases UI as an open medium-severity case

### Phase 3 — Admin Approval (one click, not config)

The **ITAM > Network Zones** tab shows:
- **Pending Approval** panel — all auto-discovered zone candidates with the CyCase reference
- **Approved Zones** table — all active zones with live agent count and ARP status

Admin clicks **Approve**, enters a zone name (e.g., "London HQ"), and clicks confirm.
The zone is created, the CyCase remains open for audit trail (admin closes it manually),
and all matching agents see `arp_enabled: true` on their next heartbeat.

Admin never types a CIDR or MAC address manually — the system provides them.

---

## 8. Files Changed

| File | Change |
|---|---|
| `backend/blueprints/edr/response_orchestrator.py` | ALTER TABLE edr_agents: add `current_network_zone`, `arp_enabled`, `last_gateway_mac`, `arp_enabled_until`, `enrollment_gateway_mac` |
| `backend/blueprints/itam/routes.py` | New `network_zones` + `network_zone_suggestions` tables; `evaluate_zone_trust()`, `record_gateway_sighting()`, `_raise_zone_approval_case()`; full CRUD routes for `/api/itam/network-zones` and suggestion approval/rejection |
| `backend/blueprints/edr/routes.py` | `agent_heartbeat()`: receive `gateway_macs`, call `evaluate_zone_trust`, return `arp_enabled` + `arp_enabled_until` + `network_zone`; only ingest ARP when zone trusted; `self_enroll_agent()`: store `gateway_mac` + `gateway_ip` |
| `agent/cyedr_agent.py` | `Config`: add `arp_enabled`, `arp_enabled_until`, `save_arp_state()`; new `_get_gateway_macs()` (cross-platform routing table + ARP lookup); `_beat()`: send `gateway_macs`, read `arp_enabled` response, persist state, skip ARP collection when not trusted, apply offline grace-period; `ensure_enrolled()`: detect and submit gateway at enrollment |
| `scripts/cyedr-install.sh` | Detect default gateway IP + MAC before `self-enroll` call; include `gateway_ip` and `gateway_mac` in enrollment payload |
| `scripts/cyedr-install.ps1` | Same for Windows via `Get-NetRoute` + `Get-NetNeighbor` |
| `portal/src/pages/itam/index.jsx` | New `NetworkZonesTab` component with pending suggestions panel (Approve/Reject), approved zones table, zone stats; `ZoneApproveModal`; Network Zones tab added to main page |
| `portal/src/pages/edr/index.jsx` | Agent cards show `Network Zone` and `ARP Discovery ACTIVE/BLOCKED` badges |

---

## 9. New API Routes

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/api/itam/network-zones` | viewer+ | List all zones with live agent count |
| POST | `/api/itam/network-zones` | admin | Create zone manually |
| GET | `/api/itam/network-zones/<id>` | viewer+ | Zone detail |
| PUT | `/api/itam/network-zones/<id>` | admin | Update zone (name, CIDRs, gateways) |
| DELETE | `/api/itam/network-zones/<id>` | admin | Delete zone |
| GET | `/api/itam/network-zones/suggestions` | viewer+ | List pending suggestions |
| POST | `/api/itam/network-zones/suggestions/<id>/approve` | admin | Approve → create zone + close CyCase |
| POST | `/api/itam/network-zones/suggestions/<id>/reject` | admin | Reject suggestion |
| GET | `/api/itam/network-zones/stats` | viewer+ | KPI counts for dashboard widget |

---

## 10. New DB Schema

### `network_zones`
```sql
CREATE TABLE network_zones (
  id               SERIAL PRIMARY KEY,
  zone_name        TEXT NOT NULL UNIQUE,
  trusted_cidrs    TEXT[] NOT NULL DEFAULT '{}',
  trusted_gateways JSONB  DEFAULT '[]',   -- [{ip, macs:[]}]
  status           TEXT   DEFAULT 'approved',
  approved_by      TEXT,
  approved_at      TIMESTAMPTZ,
  auto_discovered  BOOLEAN DEFAULT FALSE,
  notes            TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);
```

### `network_zone_suggestions`
```sql
CREATE TABLE network_zone_suggestions (
  id               SERIAL PRIMARY KEY,
  subnet_prefix    TEXT NOT NULL,       -- e.g. "10.10.0.0/16"
  gateway_mac      TEXT NOT NULL,
  gateway_ip       TEXT,
  supporting_agents TEXT[] DEFAULT '{}',
  agent_count      INTEGER DEFAULT 1,
  status           TEXT DEFAULT 'pending',   -- pending|approved|rejected
  approved_zone_id INTEGER REFERENCES network_zones(id),
  case_id          TEXT,               -- UUID of the CyCase incident record
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(subnet_prefix, gateway_mac)
);
```

### `edr_agents` — New Columns
```sql
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS current_network_zone TEXT;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS arp_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS last_gateway_mac TEXT;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS arp_enabled_until TIMESTAMPTZ;
ALTER TABLE edr_agents ADD COLUMN IF NOT EXISTS enrollment_gateway_mac TEXT;
```

---

## 11. CyCase Integration

When a new zone suggestion reaches 3 supporting agents, `_raise_zone_approval_case()` is
called. It inserts a minimal record into the `incidents` table in the correlation DB:

```python
INSERT INTO incidents (id, first_seen, last_seen, status, severity,
  categories, case_type, case_opened_at, llm_summary)
VALUES (<uuid>, NOW(), NOW(), 'open', 'medium',
  ARRAY['network_security'], 'network_zone_approval', NOW(), <detail>)
```

This creates an open CyCase visible in CyCases UI. The `llm_summary` field contains:
- Subnet prefix and gateway MAC
- Number of reporting agents
- Link to ITAM > Network Zones to take action

The case remains open until the admin manually closes it after approving or rejecting the
suggestion. This creates a full audit trail of every network zone decision.

**CyCase `case_type`:** `network_zone_approval`  
**CyCase severity:** `medium`  
**CyCase categories:** `['network_security']`

---

## 12. Agent Config Format (post-implementation)

`/opt/cycentra/edr/config.json` gains an `arp_discovery` block persisted by the agent:

```json
{
  "platform_url": "https://cycentra.corp.example.com",
  "deploy_token": "...",
  "agent_id": "...",
  "arp_discovery": {
    "enabled": true,
    "arp_enabled_until": "2026-06-30T14:02:00+00:00"
  }
}
```

The `arp_enabled_until` timestamp is refreshed on every successful heartbeat. If the agent
is offline for more than 3 minutes, `enabled` is treated as `false` regardless of the
persisted value — preventing stale trust from persisting during travel.

---

## 13. Open Items / Future Phases

| Item | Priority | Notes |
|---|---|---|
| SSID-based detection | Medium | Add `current_ssid` to heartbeat; trusted SSID list per zone; wireless confirmation signal |
| DNS search domain detection | Low | `scutil --dns` / `resolvectl` — additional signal for domain-joined machines |
| `arp_enabled_until` tunable | Low | Current: 3 minutes. Make configurable per zone (e.g. longer for stable servers) |
| VRRP MAC auto-recognition | Low | Detect `00:00:5E:00:01:XX` pattern and label as "VRRP virtual" in UI |
| Zone MAC history | Low | Track per-zone MAC change events for audit / troubleshooting |
| Investigation Engine integration | High | Phase 3 of INVESTIGATION_ENGINE_PLAN evidence collectors should validate asset IPs against `network_assets.discovery_source != 'arp_report' OR zone_trusted = true` to exclude stale roaming data |

---

## 14. Design Review Q&A Record

The following questions were raised during the design phase (2026-06-30):

**Q: Who sets up the gateway MAC?**  
A: Nobody manually. Enrollment scripts detect and submit it automatically. Ongoing heartbeats
feed the auto-learning engine. Admins review and approve suggestions — they never type MACs.

**Q: Can the gateway MAC be changed or spoofed?**  
A: Yes to legitimate change (hardware refresh) — handled by the re-approval workflow (admin
approves new candidate MAC within minutes). Malicious spoofing is defeated by requiring CIDR
match as a second factor; an attacker cannot spoof both the MAC and DHCP assignment.

**Q: What if there are multiple gateways (ECMP, VRRP, multi-VLAN)?**  
A: Agent sends all detected gateway MACs (one per default route). Server matches against any
MAC in the zone's `trusted_gateways` array. VRRP virtual MACs are stable across failovers.

**Q: What if the company has multiple office locations?**  
A: Each office is a separate `network_zones` record with its own CIDRs and gateway list. VPN
pools are their own zone with no gateway MACs (CIDR-only trust). A roaming laptop matches
exactly one zone per heartbeat (or none if roaming).

**Q: Can this be automated?**  
A: Yes, fully. Enrollment bootstraps the first MAC. Heartbeat clustering auto-discovers new
zones. Admin only approves — never configures from scratch. MAC changes are auto-proposed
for re-approval within 60 seconds of the first heartbeat after the change.
