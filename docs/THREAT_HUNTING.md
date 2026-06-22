# Threat Hunting — How It Works, What It Shows, and How to Make It Better

**Feature area:** Internal Exposure > Threat Hunting  
**Engine introduced:** v1.0.66  
**Bug fixes applied:** v1.0.68 (column name correction — see Section 7)

---

## 1. What Is Threat Hunting in CyCentra 360?

The threat hunting engine is a **proactive, sweep-based** complement to the reactive correlator.

The correlator fires in near-real-time when an alert matches a specific pattern (e.g., 5 auth failures in 2 minutes). Threat hunting takes the opposite approach: it runs on a schedule and sweeps **historical** alert data looking for patterns that are too slow or spread-out to trigger a real-time rule — the classic "low and slow" attacker behaviour.

**The key distinction:**

| | Correlator | Threat Hunter |
|---|---|---|
| Trigger | Real-time, per-alert | Scheduled (every 6h) or on-demand |
| Window | Seconds to minutes | Hours to days |
| Pattern type | Threshold breach | Aggregation over time / entity |
| Designed for | High-velocity attacks | Low-and-slow attackers |
| Output | `Incident` (via correlation engine) | `Incident` with `categories = ['hunt_finding']` |

---

## 2. Engine Architecture

### File locations

```
backend/cysiemstack/threat_hunter/
  hunter.py          # Core: load_hunt_rules, _evaluate_rule, _create_hunt_incident, run_all_hunts
  rules/             # 12 YAML rule files (auto-loaded on every run)
    HT-001-low-slow-brute-force.yml
    HT-002-lateral-movement-chain.yml
    HT-003-fim-spike.yml
    HT-004-recurring-malware.yml
    HT-005-sca-hardening-regression.yml
    HT-006-privilege-escalation-chain.yml
    HT-007-wmi-persistence.yml
    HT-008-lolbas-pattern.yml
    HT-009-slow-cloud-exfil.yml
    HT-010-mfa-fatigue-campaign.yml
    HT-011-pass-the-hash-lateral.yml
    HT-012-cryptominer-detection.yml
```

### How a hunt run works (step by step)

```
1. APScheduler fires run_all_hunts() every 6 hours
   OR analyst clicks "Run Hunt Now" → POST /api/siem/threat-hunting/run

2. load_hunt_rules() reads all *.yml files from rules/

3. For each rule:
   a. _evaluate_rule() builds a SQL query against the 'alerts' table:
      - Filters by category and/or rule_desc_contains (from the YAML)
      - Looks back window_hours into history
      - Groups results by same_field (agent_id | username | src_ip)
      - Returns all entity groups with COUNT >= min_count

   b. For each matched entity:
      - Checks if an open hunt_finding already exists for this rule+entity
        (deduplication — prevents duplicate incidents for the same ongoing pattern)
      - If new: _create_hunt_incident() creates an Incident row

4. session.commit() persists all new incidents

5. Summary returned: {rules_run, matches_found, incidents_created, errors}
```

### YAML rule structure

```yaml
id: HT-001                      # Unique ID — used as deduplication key
name: Low-and-Slow Brute Force
description: Repeated auth failures that stay below single-rule thresholds
severity: high                  # critical | high | medium | low
confidence: 0.75                # 0–1; used to compute fp_probability = (1-confidence)*100
window_hours: 48                # How far back to look in the alerts table
mitre:
  - T1110
  - T1110.001
frameworks:
  - nis2
  - iso27001
conditions:
  - category: authentication_failure   # alerts.category value to filter on
    min_count: 20                       # Fire when >= 20 matching alerts found per entity
    same_field: agent_id                # agent_id | username | src_ip
    rule_desc_contains: authentication failed  # Optional substring match on alerts.rule_desc
```

Drop a new `.yml` file into `threat_hunter/rules/` — the engine picks it up automatically on the next run without any code change or restart.

---

## 3. What Does a Hunt Finding Look Like in the Database?

Hunt findings are stored as regular rows in the `incidents` table (correlation DB on port 5433).

Key fields that distinguish them:

| Field | Value |
|-------|-------|
| `id` | `HUNT-{rule_id}-{8-char-uuid}` e.g. `HUNT-HT-001-A3F9C12B` |
| `categories` | `['hunt_finding']` — this is the tag; there is no separate `incident_type` column |
| `status` | `'open'` on creation |
| `correlated_rules` | `[{"rule_id": "HT-001", "rule_name": "...", "confidence": 0.75, "event_count": 23}]` |
| `llm_summary` | Auto-generated text: which rule fired, how many events, for which entity, over which window |
| `mitre_ids` | From the rule YAML plus any MITRE IDs found in the matched alerts |
| `fp_probability` | `(1 - confidence) * 100` — e.g. 0.75 confidence → 25% FP probability |
| `affected_agents` | List of Wazuh agent IDs involved |
| `affected_users` | Populated when `same_field = username` |

---

## 4. What Does the Threat Hunting Page Show?

### KPI Row (5 cards)

| Card | What it counts |
|------|----------------|
| Total Rules | Number of YAML rules loaded (currently 12) |
| Active Findings | Open hunt_finding incidents (status not closed/FP) |
| Critical / High | Open findings with severity = critical or high |
| New (24h) | Open findings with first_seen in the last 24 hours |
| Rules Firing | Count of distinct rules that have at least one open finding |

All 5 cards are sourced from `GET /api/siem/threat-hunting/summary`.

### Hunt Rules table

All 12 loaded YAML rules, showing:
- Rule ID and name
- Severity badge
- MITRE technique tags
- Lookback window (e.g. "48h")
- Open findings count (live, from DB) — red if > 0, green if 0

### Active Hunt Findings table

All open hunt_finding incidents ordered by first_seen descending. Click any row to expand and see the AI-generated summary. "View in Incidents ↗" navigates to the main incidents list.

### CyMind AI Analysis panel

On-demand: sends all rule states + the 10 most recent open findings to CyMind, which returns a free-text narrative covering which rules produce the most noise, MITRE patterns, and recommended analyst actions.

### "Run Hunt Now" button

Triggers an immediate background hunt. The message "Threat hunt running in background" is the confirmation — the engine runs asynchronously and results appear after the 60-second auto-refresh.

---

## 5. Does Threat Hunting Create Active Incidents or Raise Cases?

### Incidents — YES, automatically

Every time a hunt rule matches, the engine **creates an Incident** in the `incidents` table with `status = 'open'`. These are visible in:
- Threat Hunting page → Active Hunt Findings table
- Internal Exposure dashboard → Threat Hunt Activity widget
- Active Incidents list (filter to see `hunt_finding` category)
- Compliance > Findings & Alerts (after MITRE→control enrichment runs)

### Cases (CyCases) — NO, not automatically

**Hunt findings do NOT automatically open a CyCases ticket.** The case management layer (`blueprints/cases/service.py`) requires an explicit call to `open_case(incident_id, opened_by)` — this only happens when an analyst manually opens a case from the UI or API.

**What this means in practice:**
- Hunt findings sit as open incidents waiting for analyst triage
- An analyst reviews the finding, confirms it's a true positive, then clicks "Open Case" in the Cases module
- At that point, `_infer_case_type()` runs — since "hunt_finding" doesn't match any keyword mapping (ransomware/phishing/brute/exfil/lateral), the case is classified as `"generic"` unless the analyst selects a type explicitly

**Recommended improvement:** Auto-open cases for critical/high hunt findings with confidence >= 0.80. See Section 6, Enhancement 1.

### Compliance enrichment — YES, automatic

Hunt findings flow through `cy_comp/services/siem_bridge.py → enrich_incidents_pass()` automatically. Because they are regular `incidents` table rows with `mitre_ids`, the MITRE→framework control mapping fires and the findings surface in **Security Compliance > Findings & Alerts** with framework tags (NIS2, ISO 27001, DORA, etc.). No extra work needed.

---

## 6. Making Threat Hunting More Powerful

### Enhancement 1 — Auto-escalate critical/high findings to Cases (Low effort, highest priority)

**Problem:** High-confidence critical findings just sit as incidents with no escalation path. Analysts may miss them in the incident queue.

**How to build:**
1. In `hunter.py → _create_hunt_incident()`, after `session.add(inc)` and `session.commit()`, add an auto-case step:
   ```python
   if severity in ("critical", "high") and confidence >= 0.80:
       _auto_open_case(incident_id, rule)
   ```
2. `_auto_open_case()` calls `blueprints.cases.service.open_case()` via psycopg2 (sync), setting `opened_by = "threat_hunter"` and inferring the case type from the YAML rule's `frameworks` + MITRE tags
3. Add a `case_type` field to hunt rule YAML (e.g. `case_type: lateral_movement`) so the inference is explicit

**Also needed:** Add `"hunt_finding"` to `_infer_case_type()` in `cases/service.py` so hunts produce a meaningful case type rather than "generic":
```python
if "hunt_finding" in combined: return "threat_hunt"
```

---

### Enhancement 2 — AI-Generated Hunt Hypotheses (Medium effort)

**What:** CyMind proposes new hunt hypotheses based on which MITRE techniques are being observed in alerts but are not yet covered by any existing hunt rule.

**How to build:**
1. Add `POST /api/siem/threat-hunting/hypothesize` in `siem_proxy.py`
2. Query: which MITRE technique IDs appear in `alerts` from the last 7 days that are NOT in any existing rule's `mitre:` list
3. Prompt CyMind: *"Given these uncovered MITRE techniques with observed alert activity: {list}, propose 3 new threat hunt hypotheses as YAML rules compatible with this schema: {schema}."*
4. Return proposed YAML text
5. Add "Generate Hypotheses" button to the AI Analysis panel; show proposed rules in a diff-style view with one-click "Create Rule" that saves the YAML to `threat_hunter/rules/` via a new admin API

---

### Enhancement 3 — Hunt Finding Triage Brief (Low effort, high analyst value)

**What:** When an analyst expands a hunt finding, CyMind generates a triage brief: likely attack path, 3 investigation steps, related incidents, and a recommended action.

**How to build:**
1. Add `POST /api/siem/threat-hunting/findings/{incident_id}/triage` in `siem_proxy.py`
2. Pull the full incident + the raw alerts that triggered it from the `alerts` table (filter by agent + time window + category from the rule)
3. Prompt CyMind with all details and request structured output: `{attack_path, investigation_steps[], recommended_action, confidence}`
4. Display in the expandable row detail inside `HuntFindingsTable` in `ThreatHuntingPage.jsx`

---

### Enhancement 4 — Autonomous Rule Tuning via FP Feedback (Medium effort)

**What:** Automatically detect rules producing too many false positives and suggest or apply threshold adjustments.

**How to build:**
1. `fp_probability` is already written to every hunt finding (`= (1-confidence)*100`). Add a weekly aggregation:
   ```sql
   SELECT correlated_rules->0->>'rule_id' AS rule_id,
          AVG(fp_probability) AS avg_fp,
          COUNT(*) FILTER (WHERE status = 'false_positive') AS fp_count,
          COUNT(*) AS total
   FROM incidents
   WHERE 'hunt_finding' = ANY(categories)
     AND first_seen > NOW() - INTERVAL '30 days'
   GROUP BY 1
   ```
2. For rules with `avg_fp > 60` or `fp_count/total > 0.4`, send to CyMind: *"Rule HT-XXX has a 65% false positive rate over 30 days. Here are its current settings: {yaml}. Suggest tighter thresholds."*
3. Surface suggestions as inline alerts on the rule row in the Hunt Rules table

---

### Enhancement 5 — Wazuh Native Intelligence Integration (Low effort)

**What:** Pull Wazuh's built-in threat intelligence data directly into the Threat Hunting page — SCA failures, rootcheck findings, and CVE exposure create natural hunting pivot points.

**How to build:**
1. Add `GET /api/siem/threat-hunting/wazuh-intel` in `siem_proxy.py` that calls:
   - `GET /mitre` — which MITRE techniques are active across all agents
   - `GET /sca/{agent_id}` — hardening gaps (per agent)
   - `GET /vulnerability/{agent_id}` — known unpatched CVEs
   - `GET /rootcheck/{agent_id}` — rootkit findings
2. Add a "Wazuh Intelligence" tab to `ThreatHuntingPage.jsx` with:
   - MITRE technique frequency chart (bar chart of which T-codes are most active)
   - SCA failures table (hardening gaps that expand the attack surface)
   - CVE exposure list (unpatched CVEs as hunting pivot points)

---

### Enhancement 6 — Continuous AI-Orchestrated Hunt Loop (High effort, high impact)

**What:** CyMind drives the entire hunting cycle — generate hypothesis → create rule → evaluate → classify findings → escalate TP / close FP — with analyst approval gates at each step.

**Architecture:**
```
Every 6h:
  CyMind → "What should we hunt next, given current alert landscape?"
  AI generates YAML hypothesis
  Engine runs hypothesis rule
  Results sent back to CyMind → "Are these findings genuine threats?"
  CyMind classifies each: true_positive | likely_fp | needs_more_data
  true_positive  → auto-open Case, notify SOC via SMTP
  likely_fp      → auto-close finding with AI explanation
  needs_more_data → create 'pending' finding, surface in UI for analyst
```

**How to build:**
1. Add `CymindOrchestrator` class to `hunter.py` (or a new `orchestrator.py`)
2. Add `POST /api/siem/threat-hunting/orchestrate` (admin-only)
3. Add APScheduler job alongside the existing 6h hunt job
4. Add "AI Orchestrator Active" toggle to the Threat Hunting page header
5. New "Orchestrator Log" panel in the UI showing each step of the last cycle

---

## 7. Bug Fixes Applied (v1.0.68)

All four bugs were in `backend/siem_proxy.py`. No frontend changes were needed.

### Bug 1 & 2 — `_sync_hunt_rules()` used wrong column names

**Root cause:** The `Incident` model has no `incident_type` column (the correct tag is the `categories` ARRAY) and no `metadata` column (rule IDs are in `correlated_rules` JSONB). Both columns were referenced in the SQL that counts findings per rule.

**Effect:** PostgreSQL threw `column "incident_type" does not exist` → Flask returned 500 → every call to the rules endpoint returned `_error` → the Hunt Rules table showed empty.

**Fix:** Changed the SQL to:
```sql
SELECT correlated_rules->0->>'rule_id' AS rule_id,
       COUNT(*) AS total,
       COUNT(*) FILTER (WHERE status NOT IN ('closed','false_positive')) AS open
FROM incidents
WHERE 'hunt_finding' = ANY(categories)
GROUP BY correlated_rules->0->>'rule_id'
```

### Bug 3 — `siem_threat_hunt_summary()` used wrong column in 4 queries

**Root cause:** All four COUNT queries in the summary route used `WHERE incident_type = 'hunt_finding'`.

**Effect:** Same PostgreSQL error → 500 → all 5 KPI cards showed 0.

**Fix:** Replaced all 4 with `WHERE 'hunt_finding' = ANY(categories)`.

### Bug 4 — `siem_threat_hunt_findings()` passed unsupported filter to correlation engine

**Root cause:** The route proxied to `GET /incidents?category=hunt_finding`, but the correlation engine's `/incidents` endpoint has no `category` query parameter — it was silently ignored, returning all incidents.

**Fix:** Replaced the proxy call with a direct psycopg2 query that correctly filters `WHERE 'hunt_finding' = ANY(categories)`, with support for optional `status` and pagination (`limit` / `offset`) parameters.

### Bug 5 — `siem_threat_hunt_analyze()` also used `incident_type`

**Root cause:** The AI analysis route had the same column error in its SQL to fetch the 10 most recent findings for the CyMind prompt.

**Fix:** Replaced with `WHERE 'hunt_finding' = ANY(categories)`.

---

## 8. Adding New Hunt Rules

Drop a `.yml` file in `backend/cysiemstack/threat_hunter/rules/`. The engine loads all `*.yml` files on every run — no restart required.

### Minimum viable rule

```yaml
id: HT-013                      # Unique — used as dedup key in incidents table
name: My New Hunt Rule
description: What low-and-slow pattern this detects
severity: high                  # critical | high | medium | low
confidence: 0.70                # 0–1; fp_probability = (1-confidence)*100
window_hours: 24
mitre:
  - T1059
frameworks:
  - nis2
  - iso27001
conditions:
  - category: malware           # Must match alerts.category values in your environment
    min_count: 3
    same_field: agent_id        # agent_id | username | src_ip
    rule_desc_contains: ""      # Optional: substring filter on alerts.rule_desc
```

### Current `alerts.category` values to filter on

Run this against the correlation DB to see what categories are in your environment:
```sql
SELECT category, COUNT(*) FROM alerts GROUP BY category ORDER BY 2 DESC LIMIT 20;
```

---

## 9. Quick Reference

| Component | File |
|-----------|------|
| Engine core | `backend/cysiemstack/threat_hunter/hunter.py` |
| YAML rules | `backend/cysiemstack/threat_hunter/rules/` |
| Proxy routes | `backend/siem_proxy.py` — `_sync_hunt_rules()`, `siem_threat_hunt_*` routes |
| Frontend page | `portal/src/siem/ThreatHuntingPage.jsx` |
| Dashboard widget | `portal/src/siem/InternalExposureDashboard.jsx` — Row 5, "Threat Hunt Activity" |
| Nav entry | `portal/src/sidebar/navConfig.jsx` — INTERNAL EXPOSURE section |
| API helpers | `portal/src/siem/siemApi.js` — `getThreatHuntRules`, `getThreatHuntFindings`, `getThreatHuntSummary`, `runThreatHunt`, `analyzeThreatHunt` |
| Case service | `backend/blueprints/cases/service.py` — `open_case()` (must be called manually) |
| Compliance enrichment | `backend/cy_comp/services/siem_bridge.py` — `enrich_incidents_pass()` (automatic) |
