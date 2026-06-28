# Custom YARA Threat Hunting — Zero-Day Response

**Feature area:** Endpoint Defense > Custom Threat Hunting  
**Introduced:** v1.0.31+  
**Hunt rules added:** HT-013, HT-014

---

## 1. What This Feature Does

CyCentra 360 now supports **custom YARA rule-based threat hunting** across the entire endpoint fleet. When a zero-day exploit is disclosed, your security team can:

1. Write a YARA rule targeting the known indicators (file magic bytes, strings, PE structures, hashes)
2. Upload it in the portal — the platform validates syntax and stores it immediately
3. Either wait up to 60 minutes for all agents to auto-fetch it, **or** click "Fleet Scan Now" to scan every endpoint within seconds

This eliminates the classic gap where teams had to wait for an AV vendor update before they could detect a new threat.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  PORTAL — Endpoint Defense > Custom Threat Hunting                      │
│   • Upload YARA rule (CRUD modal)                                       │
│   • Fleet Scan Now button                                               │
│   • Match count per rule, last deployed timestamp                       │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │  POST /api/edr/yara-rules/custom
                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  FLASK BACKEND — blueprints/edr/routes.py                               │
│   • Validates YARA syntax (yara-python bindings)                        │
│   • Stores in edr_custom_yara_rules table (correlation DB, port 5433)  │
│   • Fleet scan: queues RUN_SCAN in edr_response_commands for all agents │
└────────┬──────────────────────────────────────┬───────────────────────-─┘
         │                                       │
         │ GET /api/edr/installer/custom-yara    │ RUN_SCAN command
         │ (hourly IOC sync)                     │ (immediate or scheduled)
         ▼                                       ▼
┌────────────────────────┐         ┌─────────────────────────────────────┐
│  CyEDR Agent           │         │  CyEDR Agent — ResponseExecutor     │
│  IOCRefresher thread   │         │   • Compiles cycentra.yar           │
│  • Writes custom.yar   │         │   • Compiles custom.yar             │
│  • Every 60 minutes    │         │   • Runs yara -r against scan_path  │
└────────────────────────┘         │   • Returns structured match list   │
                                   └───────────────────┬─────────────────┘
                                                       │
                           POST /api/edr/response/<id>/commands/<cid>/complete
                                                       │
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  BACKEND — _ingest_yara_scan_result()                                   │
│   • Parses structured match list                                        │
│   • Writes to edr_detections (EDR Detections page)                     │
│   • Writes to alerts table with category='malware', rule_desc='yara…'  │
│   • rule_id 100210 (bundled YARA) / 100211 (custom YARA)               │
└──────────────────────┬──────────────────────────────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
┌─────────────────┐     ┌────────────────────────────────────────────────┐
│  EDR Detections │     │  Threat Hunter (cysiemstack/threat_hunter/)    │
│  Page           │     │   HT-013 — Zero-Day YARA Signature Match       │
│  (immediate)    │     │     • Fires on min_count=1 YARA alert          │
│                 │     │     • 24h window, severity=critical             │
│                 │     │   HT-014 — Custom YARA Fleet Match             │
│                 │     │     • Fires when 2+ agents match same rule     │
│                 │     │     • 48h window, severity=critical             │
└─────────────────┘     │   Both run every 6h (APScheduler) or on-demand│
                        └────────────────────────────────────────────────┘
```

---

## 3. Autonomous Operation (How It Triggers Without Human Action)

### 3a. Custom Rule Auto-Deployment (every 60 minutes)

Every enrolled CyEDR agent runs an `IOCRefresher` thread that wakes every 3,600 seconds. On each tick it:

1. Fetches `GET /api/edr/ioc-feed` — refreshes the IOC hash/IP/domain cache
2. **Fetches `GET /api/edr/installer/custom-yara`** — downloads all active custom YARA rules merged into one text block
3. Writes the result to `{edr_home}/custom.yar` (default: `/opt/cycentra/edr/custom.yar`)

This means: upload a rule → within 60 minutes every agent in your fleet has it on disk, without any further action.

The `last_deployed` timestamp in `edr_custom_yara_rules` is updated each time the endpoint calls this API, giving you visibility into which agents have received the latest ruleset.

### 3b. Threat Hunt Sweep (every 6 hours)

The APScheduler job in `cysiemstack/main.py` calls `run_all_hunts()` every 6 hours. This evaluates:

| Rule | What it sweeps | Fires when |
|------|----------------|------------|
| **HT-013** | `alerts` table for `category='malware'` + `rule_desc LIKE '%yara%'` | 1 YARA match on any endpoint in the last 24h |
| **HT-014** | Same, but `rule_desc LIKE '%custom_yara%'` grouped by `src_ip` | 2+ agents match the same custom rule in 48h |

When either rule fires, the engine creates an `Incident` with:
- `id` = `HUNT-HT-013-{uuid}` or `HUNT-HT-014-{uuid}`
- `categories = ['hunt_finding']`
- `severity = 'critical'`
- Auto-generated `llm_summary` describing which rule fired and which endpoints are affected

These findings appear on:
- **Threat Hunting page** → Active Hunt Findings table
- **Active Incidents** (filter by `hunt_finding` category)
- **Security Compliance** → Findings & Alerts (MITRE→framework enrichment runs automatically)

### 3c. YARA Match Result Ingestion (immediate, per-scan)

When any `RUN_SCAN` command completes (whether from fleet scan or an individual response action), the agent sends the structured match list back to `POST /api/edr/response/<agent_id>/commands/<cmd_id>/complete`. The `_ingest_yara_scan_result()` function runs synchronously:

- For each YARA match: inserts a row in `edr_detections` (severity = critical, score = 95)
- For each YARA match: inserts a row in `alerts` (category = malware, rule_id = 100210/100211)
- `alerts` rows are immediately available to the threat hunter on its next scheduled run

This closes the feedback loop: even between the 6-hour hunt sweeps, matches appear in the EDR Detections page within seconds of the agent completing its scan.

---

## 4. On-Demand Triggers

There are three ways to trigger hunting without waiting for any schedule:

### 4a. Fleet Scan — Portal UI

**Endpoint Defense → Custom Threat Hunting → ⚡ Fleet Scan Now**

This opens a confirmation dialog where you set:
- **Scan Path** — default `/`. Use `/tmp` or `/var/tmp` for targeted hunting of dropped payloads.
- **Reason** — free text that appears in the audit log

Clicking "Scan All Agents Now" calls `POST /api/edr/fleet-scan` which:
1. Queries all agents with `status='active'`
2. Queues a `RUN_SCAN` command for each, with a shared `scan_id` UUID for traceability
3. Returns `{ scan_id, queued, agents[] }` immediately — commands are asynchronous

Agents pick up their `RUN_SCAN` command on the next poll cycle (default: every 60 seconds). Matches begin appearing in EDR Detections within 1–2 minutes for small fleets.

### 4b. Fleet Scan — API

```bash
curl -X POST https://your-platform/api/edr/fleet-scan \
  -H "Content-Type: application/json" \
  -b "session=..." \
  -d '{"scan_path": "/tmp", "reason": "CVE-2026-99999 zero-day response"}'
```

Response:
```json
{
  "scan_id": "a3f9c12b-...",
  "queued": 47,
  "agents": ["agent-id-1", "agent-id-2", "..."],
  "message": "RUN_SCAN queued for 47 active agents"
}
```

Requires: **analyst or admin** session role.

### 4c. Threat Hunt On-Demand — Threat Hunting Page

**Internal Exposure → Threat Hunting → Run Hunt Now**

This triggers `POST /api/siem/threat-hunting/run`, which evaluates ALL 14 hunt rules (HT-001 through HT-014) immediately rather than waiting for the 6-hour APScheduler cycle. New HT-013/HT-014 findings will appear if YARA match alerts already exist in the `alerts` table from prior scans.

---

## 5. API Reference

All routes are under `/api/edr/`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/yara-rules/custom` | viewer+ | List all custom YARA rules (metadata, no rule_text) |
| `POST` | `/yara-rules/custom` | admin | Upload a new rule (validates syntax) |
| `GET` | `/yara-rules/custom/<id>` | viewer+ | Full rule detail including rule_text |
| `PUT` | `/yara-rules/custom/<id>` | admin | Update name, threat_name, mitre_id, or rule_text |
| `DELETE` | `/yara-rules/custom/<id>` | admin | Permanently delete a rule |
| `POST` | `/yara-rules/custom/<id>/activate` | admin | Re-enable a disabled rule |
| `POST` | `/yara-rules/custom/<id>/deactivate` | admin | Disable without deleting |
| `GET` | `/installer/custom-yara` | Bearer agent token | Agents fetch merged active ruleset |
| `POST` | `/fleet-scan` | analyst+ | Queue RUN_SCAN on all active agents |

---

## 6. Database

### `edr_custom_yara_rules` (correlation DB, port 5433)

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | UUID |
| `name` | TEXT | Human-readable rule name |
| `threat_name` | TEXT | CVE, threat actor, or campaign name |
| `mitre_id` | TEXT | MITRE ATT&CK technique (e.g. T1203) |
| `rule_text` | TEXT | Full YARA rule source |
| `author` | TEXT | Email of analyst who uploaded |
| `active` | BOOLEAN | Controls inclusion in `/installer/custom-yara` feed |
| `created_at` | TIMESTAMPTZ | When uploaded |
| `updated_at` | TIMESTAMPTZ | Last modified |
| `last_deployed` | TIMESTAMPTZ | When an agent last fetched this rule |
| `match_count` | INTEGER | Cumulative YARA hits across all agents |

### Alert ingestion rule IDs

| rule_id | Source | Description |
|---------|--------|-------------|
| 100210 | CyEDR RUN_SCAN | YARA match from bundled `cycentra.yar` |
| 100211 | CyEDR RUN_SCAN | YARA match from analyst custom rule |

Both IDs are in `MALWARE_RULE_IDS` in `normaliser.py`, so they are classified as `category='malware'` by the correlation engine.

---

## 7. YARA Rule Authoring Guide

### Minimum structure

```yara
rule CVE_2026_12345_Payload {
  meta:
    description = "Detects CVE-2026-12345 dropped payload"
    author      = "SOC Team"
    date        = "2026-06-28"
    reference   = "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
  strings:
    $magic   = { 4D 5A 90 00 }           // PE magic bytes
    $str1    = "evil_c2_callback" nocase
    $str2    = { 68 74 74 70 3A 2F 2F }  // "http://"
  condition:
    $magic at 0 and any of ($str1, $str2)
}
```

### Best practices for zero-day rules

1. **Be specific.** Overly broad rules (e.g., `any string`) produce noise across thousands of endpoints.
2. **Use `at 0` for PE files.** `$magic at 0` ensures you're matching actual executables, not files that happen to contain the bytes.
3. **Combine signature + behavioral strings.** Malware authors change strings; magic bytes are harder to change.
4. **Set `min_count: 1` in hunt rules** (already done in HT-013) — for zero-days, a single hit is a critical event.
5. **Name the threat in `threat_name`** exactly as it appears in CVE databases or threat intel (e.g., "CVE-2026-12345", "Log4Shell", "MOVEit-2024"). This populates the threat column in the portal.

### Where to source YARA rules

- CISA publishes YARA rules alongside security advisories: `cisa.gov/known-exploited-vulnerabilities-catalog`
- Google's VirusTotal community shares rules via `github.com/Neo23x0/signature-base`
- Mandiant (Google): `github.com/mandiant/OpenIOCs`
- Florian Roth's `yarGen` can auto-generate rules from samples

---

## 8. End-to-End Zero-Day Response Playbook

**Scenario:** CVE-2026-99999 disclosed at 09:00. CISA publishes a YARA rule at 09:15.

```
09:15 — Analyst opens Portal → Endpoint Defense → Custom Threat Hunting
09:16 — Clicks "+ New YARA Rule"
         • Name: "CVE-2026-99999_Payload"
         • Threat Name: "CVE-2026-99999"
         • MITRE: T1203
         • Pastes CISA YARA rule text
         • Clicks "Save & Activate"
09:16 — Backend validates YARA syntax → stores in edr_custom_yara_rules
09:16 — Analyst clicks "⚡ Fleet Scan Now"
         • Scan Path: /
         • Reason: "CVE-2026-99999 emergency response"
         • Clicks "Scan All Agents Now"
09:17 — Fleet Scan API returns: "RUN_SCAN queued for 47 active agents"
09:17–09:22 — Agents pick up RUN_SCAN on next poll cycle, scan begins
09:22 — First match results arrive: 2 agents hit
         • EDR Detections → 2 critical detections visible immediately
         • alerts table → 2 rows with rule_id=100211 inserted
09:22 — Analyst can immediately isolate the two affected endpoints from
         Response Console without waiting for the 6h hunt cycle
10:00 — All 47 agents complete scans. 2 confirmed matches.
10:00 — Remaining 45 agents also receive updated custom.yar on next
         hourly IOC sync so future runs always include this rule.
Next hunt cycle (within 6h) — HT-013 fires for the 2 matching agents,
         creates HUNT-HT-013-xxx Incidents, routes to Cases if critical.
```

**Total time from disclosure to fleet-wide coverage: under 10 minutes.**

---

## 9. How It Relates to Existing Threat Hunting

| Capability | Existing (HT-001–HT-012) | New (HT-013, HT-014 + Custom YARA) |
|------------|--------------------------|--------------------------------------|
| Data source | `alerts` table (Wazuh events) | `alerts` table (YARA match alerts) |
| Detection type | Behavioral pattern over time | File artifact signature |
| Speed | Low-and-slow (days/weeks) | Immediate (hours/minutes) |
| Rule authoring | Edit YAML in `threat_hunter/rules/` | Portal UI upload |
| Zero-day response | No (requires prior alert patterns) | Yes (new rules deployed immediately) |
| Fleet coverage | All Wazuh-enrolled hosts | All CyEDR-enrolled endpoints |
| Auto-escalation | If confidence ≥ 0.88 + severity=critical | Same — both HT-013/HT-014 are critical |

The two systems are complementary. Existing hunt rules catch **who has been behaving suspiciously over time**. Custom YARA rules catch **which endpoints have specific zero-day artefacts right now**.

---

## 10. File Reference

| File | Role |
|------|------|
| `backend/blueprints/edr/routes.py` | Custom YARA CRUD, fleet-scan, `_ingest_yara_scan_result()`, `installer_custom_yara()` |
| `backend/blueprints/edr/response_orchestrator.py` | `ensure_tables()` — creates `edr_custom_yara_rules` on startup |
| `backend/cysiemstack/correlation_engine/normaliser.py` | `MALWARE_RULE_IDS` — includes 100210, 100211 so YARA alerts are classified as `malware` |
| `backend/cysiemstack/threat_hunter/rules/HT-013-zero-day-yara-signature-hunt.yml` | Hunt rule: single YARA hit on any endpoint → critical incident |
| `backend/cysiemstack/threat_hunter/rules/HT-014-custom-yara-fleet-match.yml` | Hunt rule: same custom rule fires on 2+ agents → campaign-level incident |
| `agent/cyedr_agent.py` | `IOCRefresher._refresh_custom_yara()` — hourly fetch of `custom.yar`; `_run_scan()` — compiles both YARA files |
| `portal/src/pages/edr/EdrYaraRulesPage.jsx` | Upload modal, fleet-scan modal, rule table, match counts |
| `portal/src/sidebar/navConfig.jsx` | "Custom Threat Hunting" nav item under ENDPOINT DEFENSE |
| `portal/src/App.jsx` | Routes `edr-yara-rules` tab to `EdrYaraRulesPage` |
