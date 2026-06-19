# Threat Hunting — Architecture, UI, and AI Enhancement Roadmap

**Feature area:** Internal Exposure > Threat Hunting
**Status:** Operational (engine + UI live as of v1.0.66)

---

## 1. How the Engine Works Today

### Overview

The threat hunting engine is a **proactive, sweep-based** complement to the reactive correlator. While the correlator fires on real-time alert patterns, the hunter sweeps historical alert data looking for low-and-slow patterns that individually fall below the correlation threshold.

### Engine location

```
backend/cysiemstack/threat_hunter/
  __init__.py
  hunter.py        # Core engine: load_hunt_rules, _evaluate_rule, _create_hunt_incident, run_all_hunts
  rules/           # 12 YAML rule files
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

### Run schedule

Every 6 hours via APScheduler registered in `cysiemstack/correlation_engine/main.py`.
On-demand: `POST /api/siem/threat-hunting/run` (admin only).

### YAML rule structure

```yaml
id: HT-001
name: Low-and-Slow Brute Force
description: Repeated authentication failures that stay below single-rule thresholds
severity: high
confidence: 0.75
window_hours: 48
mitre:
  - T1110
  - T1110.001
frameworks:
  - nis2
  - iso27001
conditions:
  - category: authentication_failure
    min_count: 20
    same_field: agent_id
    rule_desc_contains: authentication failed
```

### What happens when a rule fires

1. `_evaluate_rule()` queries the `alerts` table with the rule's WHERE clause
2. Groups by `same_field` (agent_id, username, or src_ip)
3. For each entity exceeding `min_count`, calls `_create_hunt_incident()`
4. Creates an `Incident` with `categories = ["hunt_finding"]` and ID prefix `HUNT-{rule_id}-{uuid}`
5. Deduplicates — will not create a second open finding for the same rule+entity

### Output in the DB

Hunt findings are stored as regular incidents in the `incidents` table (correlation DB):
- `categories @> ARRAY['hunt_finding']` — identifies them as hunt output
- `status = 'open'` on creation
- `llm_summary` — auto-generated text describing the pattern
- `mitre_ids` — from the rule YAML plus any MITRE tags found in the alerts
- `fp_probability` — `(1 - confidence) * 100`

### Compliance enrichment (automatic)

Hunt findings flow through `cy_comp/services/siem_bridge.py` → `enrich_incidents_pass()` without any special handling because:
1. They are regular `incidents` table rows
2. `enrich_incidents_pass()` processes ALL incidents with `compliance_breach IS NULL` or `FALSE`
3. MITRE IDs in the finding map to compliance controls via `MITRE_TO_CONTROLS` in `enrichment.py`
4. Enriched findings surface automatically in **Security Compliance > Findings & Alerts**

---

## 2. UI — What Was Built (v1.0.66)

### Navigation

Internal Exposure section → **Threat Hunting** 🎯 (between Behavioral Analytics and Case Management)

### Page: ThreatHuntingPage.jsx

**KPI row (5 cards):**
| Card | Source |
|------|--------|
| Total Rules | `summary.rules_total` |
| Active Findings | `summary.findings_open` |
| Critical / High | `summary.findings_critical_high` |
| New (24h) | `summary.findings_last_24h` |
| Rules Firing | `summary.rules_with_open_findings` |

**Hunt Rules table:** All loaded YAML rules with severity badge, MITRE technique badges, window hours, and live open-findings count.

**CyMind AI Analysis panel:** On-demand AI analysis of current hunt state (see Section 3).

**Active Hunt Findings table:** All open `hunt_finding` incidents with rule name, entity, severity, MITRE IDs, first seen, status, and expandable llm_summary.

**Run Hunt Now button:** Triggers `POST /api/siem/threat-hunting/run` (admin only).

### Internal Attack Posture Dashboard widget

Row 5 on `InternalExposureDashboard.jsx` — "Threat Hunt Activity" panel showing:
- Active Findings, Critical/High, Rules Firing, New (24h) stat boxes
- Top 2 firing rules
- "View All" → navigates to Threat Hunting page

### API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/siem/threat-hunting/rules` | viewer | All rules with per-rule finding counts |
| GET | `/api/siem/threat-hunting/findings` | viewer | All hunt_finding incidents |
| GET | `/api/siem/threat-hunting/summary` | viewer | Aggregate stats for dashboard widget |
| POST | `/api/siem/threat-hunting/run` | admin | Trigger on-demand hunt (background) |
| POST | `/api/siem/threat-hunting/analyze` | viewer | AI analysis via CyMind |

---

## 3. AI Enhancement — Current + Roadmap

### Current AI capability (implemented in v1.0.66)

**`POST /api/siem/threat-hunting/analyze`** calls CyMind with a structured prompt:
- Enumerates all hunt rules with FIRING / quiet status and open finding counts
- Lists the 10 most recent open hunt findings: entity, severity, MITRE IDs, rule name, LLM summary
- CyMind returns a free-text narrative with recommended analyst actions

This is **reactive AI** — it summarises what the engine already found.

---

### Roadmap — Making Threat Hunting AI-Native

The following enhancements are ordered by implementation effort and impact.

---

#### AI Enhancement 1 — AI-Generated Hunt Hypotheses (Medium effort)

**What:** CyMind proposes new hunt hypotheses based on the current alert landscape, MITRE ATT&CK coverage gaps, and recent incidents.

**How to build:**
1. Add `POST /api/siem/threat-hunting/hypothesize` endpoint
2. Pull current MITRE technique coverage from `alerts` (what techniques are seen), current rule YAML set (what techniques are already hunted), and recent critical/high incidents
3. Compute the coverage delta — techniques seen in alerts but NOT covered by any existing hunt rule
4. Prompt CyMind: *"Given these uncovered MITRE techniques with observed activity, propose 3 new threat hunt hypotheses in YAML rule format compatible with our hunter.py schema."*
5. Return the proposed YAML rule texts
6. Add "Create Rule" button in UI that saves the YAML to `threat_hunter/rules/` via a new admin API

**UI:** Add "Generate Hypotheses" button to the AI Analysis panel. Display proposed rules in a diff-style view with one-click accept.

---

#### AI Enhancement 2 — Autonomous Hunt Rule Tuning (Medium effort)

**What:** AI analyses false-positive rates and rule firing frequency, then suggests threshold tuning for rules that fire too broadly or too narrowly.

**How to build:**
1. Track `fp_probability` over time for each rule (already written to incidents as `fp_probability` column)
2. Add a scheduled weekly job: for each rule with `avg(fp_probability) > 0.6` (high FP rate), generate a tuning suggestion via CyMind
3. Suggestion: adjust `min_count`, `window_hours`, or add `rule_desc_contains` filter to narrow the rule
4. Surface suggestions in the Threat Hunting UI as inline rule card alerts

---

#### AI Enhancement 3 — Hunt Finding Triage Assistant (Low effort, high value)

**What:** When an analyst clicks on a hunt finding, CyMind generates a triage brief: likely attack path, recommended investigation steps, related incidents, and suggested response action.

**How to build:**
1. Add `POST /api/siem/threat-hunting/findings/{incident_id}/triage` endpoint
2. Pull the full incident + its linked alerts from DB
3. Prompt CyMind with the incident details and ask for: attack path hypothesis, 3 investigation steps, related MITRE techniques, recommended action (isolate / monitor / close FP)
4. Return structured JSON: `{attack_path, investigation_steps[], recommended_action, confidence}`
5. Display in the expandable row detail in the findings table

---

#### AI Enhancement 4 — Wazuh Threat Intelligence Pull (Low effort, high value)

**What:** Pull Wazuh's built-in threat intelligence findings (MISP events, vulnerability intel, agent-level anomaly reports) directly into the Threat Hunting page — bridging Wazuh's native hunting capability with CyCentra's UI.

**How to build:**
1. Wazuh exposes these via its REST API:
   - `GET /mitre` — MITRE ATT&CK techniques seen across all agents
   - `GET /sca/{agent_id}` — SCA check results (hardening gaps)
   - `GET /vulnerability/{agent_id}` — known CVEs on each agent
   - `GET /rootcheck/{agent_id}` — rootkit detection findings
2. Add `GET /api/siem/threat-hunting/wazuh-intel` in `siem_proxy.py` that aggregates all four into a unified "Wazuh Threat Intel" payload
3. Add a "Wazuh Intelligence" tab to the Threat Hunting page showing:
   - MITRE technique frequency chart (which techniques are most active)
   - SCA failures by policy (hardening gaps that create hunting surface)
   - CVE exposure table (unpatched CVEs as hunting pivot points)
   - Rootcheck findings

---

#### AI Enhancement 5 — Continuous Hunt Loop with CyMind Orchestration (High effort)

**What:** CyMind drives the entire hunting cycle autonomously — generating hypotheses, creating rules, evaluating results, closing false positives, and escalating true positives — with analyst oversight at each step.

**Architecture:**
```
Scheduled trigger (every 6h)
  → CyMind: "What should we hunt next, given current alert landscape?"
  → AI generates hypothesis + YAML rule
  → Engine runs the rule
  → Findings returned to CyMind: "Are these findings genuine threats?"
  → CyMind classifies each: true_positive | likely_fp | needs_more_data
  → True positives: auto-escalate to Case Management + notify SOC
  → Likely FP: auto-close with explanation
  → Needs more data: create "pending" finding, request additional log sources
```

**How to build:**
1. Extend `hunter.py` with a `CymindOrchestrator` class
2. Add `POST /api/siem/threat-hunting/orchestrate` endpoint (admin-only)
3. Wire into APScheduler alongside the existing 6-hour hunt job
4. Add "AI Orchestrator Active" toggle in the Threat Hunting page header
5. Show orchestrator activity log in a new "Orchestrator Log" panel

---

## 4. Feeding Hunt Findings to Other Platform Areas

### Compliance > Findings & Alerts (automatic — no work needed)

Hunt findings with MITRE IDs are automatically enriched by `enrich_incidents_pass()` and appear in `comp-findings` with framework tags (NIS2, ISO 27001, etc.).

### Internal Attack Posture Dashboard (implemented)

The "Threat Hunt Activity" widget in Row 5 of `InternalExposureDashboard.jsx` shows aggregate hunt stats and links to the full page.

### Risk Management

To feed hunt findings into the Risk Register:
1. Add a `hunt_findings_to_risks()` function in `cy_comp/services/risk.py`
2. For each critical/high hunt finding with MITRE IDs, check if a matching risk exists; if not, auto-create a risk entry
3. Wire into the compliance scheduler alongside `enrich_incidents_pass()`

### Reports

Hunt findings are already included in `cy_comp/services/report.py` PDF generation if they carry `compliance_breach = TRUE`. No changes needed for standard compliance reports.

---

## 5. Adding New Hunt Rules

Rules are YAML files in `backend/cysiemstack/threat_hunter/rules/`. The engine loads all `*.yml` files at startup and on each scheduled run.

### Minimum viable rule

```yaml
id: HT-013                    # Unique — used as dedup key
name: My Hunt Rule
description: What pattern this hunts for
severity: high                # critical | high | medium | low
confidence: 0.70              # 0–1; used to compute fp_probability
window_hours: 24              # Lookback window for the query
mitre:
  - T1059
frameworks:
  - nis2
  - iso27001
conditions:
  - category: malware         # Must match a value that normaliser.py writes to alerts.category
    min_count: 3              # Fire when this many matching alerts found for the same entity
    same_field: agent_id      # agent_id | username | src_ip
    rule_desc_contains: ""    # Optional substring match on alerts.rule_desc
```

Drop the file in `threat_hunter/rules/` and it is picked up automatically on the next scheduled run or on-demand trigger.

---

## 6. Quick Reference

| Component | File |
|-----------|------|
| Engine core | `backend/cysiemstack/threat_hunter/hunter.py` |
| YAML rules directory | `backend/cysiemstack/threat_hunter/rules/` |
| Proxy routes | `backend/siem_proxy.py` lines 2326–2530 |
| Frontend page | `portal/src/siem/ThreatHuntingPage.jsx` |
| Dashboard widget | `portal/src/siem/InternalExposureDashboard.jsx` (Row 5, "Threat Hunt Activity") |
| Nav entry | `portal/src/sidebar/navConfig.jsx` (INTERNAL EXPOSURE section) |
| API helpers | `portal/src/siem/siemApi.js` (getThreatHuntRules, getThreatHuntFindings, getThreatHuntSummary, runThreatHunt, analyzeThreatHunt) |
| Compliance enrichment | `backend/cy_comp/services/siem_bridge.py` → `enrich_incidents_pass()` (automatic) |
