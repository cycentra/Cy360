# CyCentra 360 — AI Investigation Engine
## Architecture Assessment & Phased Implementation Plan

**Status:** APPROVED FOR IMPLEMENTATION — Phase 1 next  
**Prepared by:** g-cyra-360  
**Date:** 2026-06-21  
**Trigger:** OpenAI enhancement proposal — evidence-driven autonomous investigation engine

---

## 1. Executive Summary

The OpenAI proposal is architecturally sound and **highly feasible** because ~65% of the
infrastructure already exists in CyCentra 360. This is an enhancement initiative, not a
rewrite. All new stages plug into the existing `cysiemstack/correlation_engine/` pipeline.

The proposed architecture transforms CyCentra from "alert + AI summary" into a closed-loop
autonomous investigation engine — iteratively gathering evidence, scoring hypotheses, and
gating SOAR actions on deterministic confidence thresholds rather than raw LLM output.

**Patent potential: Moderate-High.** The combination of iterative hypothesis generation →
autonomous evidence gap collection → deterministic re-scoring → confidence-gated SOAR
execution is genuinely novel. Most vendors detect → summarize → surface. CyCentra's loop
closes autonomously.

**Phase order decision:** SIEM-agnostic adapter refactor moved to last (Phase 7) to avoid
disrupting working Wazuh integration. All investigation engine enhancements ship first.

**UI verification principle:** Every backend enhancement in every phase ships with a corresponding
UI panel, badge, or widget so it is immediately visually verifiable without reading logs or
querying the database.

---

## 2. Feasibility Gap Map — What Exists vs What is New

| Proposed Stage | File | Current State | Gap |
|---|---|---|---|
| Stage 1 — Alert Normalization | `normaliser.py` | Production-grade. Extracts IP, user, asset, process, MITRE, timestamp | **None** |
| Stage 2 — Context Enrichment (TI) | `misp_enricher.py` | MISP IOC lookup only | External TI: VirusTotal, AbuseIPDB, GreyNoise |
| Stage 2 — Context Enrichment (Asset) | `host_posture_cache`, `risk_scorer.py` | Asset tier, posture score, SCA, vulns | None — solid |
| Stage 2 — Context Enrichment (User) | `ueba.py`, `ueba_ml.py` | UEBA anomaly detection | None — solid |
| Stage 2 — Historical Context | `risk_scores` table | Historical incidents per entity | Pattern similarity scoring |
| Stage 3 — Hypothesis Generator | `llm_enricher.py` | One-shot: context → ANALYST_SUMMARY + REMEDIATION_STEPS. No structured hypotheses | Structured hypothesis prompt returning JSON with probability + evidence_needed |
| Stage 4 — Evidence Gap Analysis | — | Does not exist | New `gap_analyser.py` |
| Stage 5 — Autonomous Collection | `siem_proxy.py` Wazuh API calls | Wazuh API calls exist but not gap-driven | Evidence collector registry dispatched by gap analyser |
| Stage 6 — Re-evaluate Hypotheses | — | Does not exist | Second LLM pass after evidence collection |
| Stage 7 — Confidence Engine | `risk_scorer.py` | Deterministic multi-factor scoring exists | Add 2 new weight components: LLM reasoning + historical similarity |
| Stage 8 — Recommendation Engine | `llm_enricher.py` | Free-text remediation steps | Structured Containment / Eradication / Recovery JSON |
| Stage 9 — Analyst Approval / SOAR Gate | `cysoar_connector.py` | SOAR connector + analyst transitions exist | Confidence threshold gating for auto-SOAR dispatch |

---

## 3. Additional Enhancement Recommendations

### A. Incident Pattern Memory
After resolution, persist `{technique, process_chain, payload_indicators, response_effectiveness}`
to a new `incident_patterns` table. Future incidents of the same type inherit a prior
confidence signal. `_store_to_cymind_memory()` in `llm_enricher.py` already does this for
RAG — extend it for structured similarity matching.

### B. Kill-Chain Stage Tagging on Hypotheses
`risk_scorer.py` has `kill_chain_stage_name` in `compute_fp_score()` but it is never
populated from hypothesis output. Wire hypothesis technique → kill-chain stage → FP score
so Exfiltration/C2 hypotheses auto-tighten confidence bounds.

### C. Evidence Freshness Decay
A 96% confidence score from 48 hours ago should decay like risk scores (`_apply_decay()`
already exists in `risk_scorer.py`). Apply the same decay to `confidence_score` on incidents
to prevent stale high-confidence incidents from permanently occupying analyst queues.

### D. Collector Capability Registry
When a new SIEM is added (later, Phase 7), it must declare which evidence types it can supply.
The gap analyser only dispatches collection requests to collectors that the active SIEM supports.

### E. Patent Claim Path
The most defensible claim:
> *"A method wherein an autonomous security investigation engine generates a ranked hypothesis
> set from normalized alert data, determines a set of evidence deficiencies for each hypothesis,
> autonomously dispatches structured queries to registered evidence collectors, recalculates
> hypothesis confidence using a deterministic weighted scoring model incorporating the collected
> evidence, and conditionally executes SOAR containment actions when confidence exceeds a
> predefined threshold — without requiring analyst intervention at any intermediate stage."*

Provisional patent filing recommended before Phase 5 ships publicly.

---

## 4. What Does NOT Change (in any phase 1–6)

The following are explicitly excluded — tested, production-stable:

- `normaliser.py` — already best-in-class, no changes
- `grouper.py` correlation rules — untouched; phases plug around them
- `ueba.py`, `ueba_ml.py` — feeds confidence engine as-is
- `fp_pattern_store.py`, `feedback_store.py` — FP handling untouched
- `blueprints/` auth / RBAC / OIDC layer — no changes
- `cy_comp/services/siem_bridge.py` — compliance enrichment unaffected
- All Docker Compose, nginx, systemd configs — no infra changes until Phase 7
- All existing Wazuh env vars (`WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS`) — remain untouched until Phase 7

---

## 5. Phased Implementation Plan

> **Rule:** No phase begins without explicit approval.
> **UI Rule:** Every phase ships backend + UI together. No backend-only phases.
> Each enhancement must be visually verifiable from the portal without touching logs or DB.

---

### Phase 1 — External Threat Intelligence Enrichment Layer

**Goal:** Expand threat context beyond MISP to VirusTotal, AbuseIPDB, and GreyNoise.
Parallel async lookups — zero latency impact on alert ingestion.

**How to verify it's working:** Open any incident detail page → see a new "Threat Intelligence"
panel showing per-source reputation results, confidence scores, and source badges.

#### Backend Files

| File | Change |
|---|---|
| `backend/cysiemstack/correlation_engine/ti_enricher.py` | **New** — `enrich_iocs(ioc_list)` dispatches async to VirusTotal, AbuseIPDB, GreyNoise, MISP. Returns aggregated `{source, verdict, confidence, raw}` per IOC |
| `backend/cysiemstack/correlation_engine/misp_enricher.py` | Refactor: become one plugin in `ti_enricher.py` registry. External API unchanged |
| `backend/cysiemstack/correlation_engine/correlator.py` | Wire `ti_enricher.enrich_iocs()` after alert grouping, before LLM enricher |
| `backend/cysiemstack/correlation_engine/models.py` | Add `ti_reputation JSONB` column to `Incident` |
| `backend/blueprints/system/routes.py` | Add TI API key fields to `/api/ai/settings` GET+POST |
| `backend/core/config.py` | Add `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY` |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/pages/settings/SystemSettingsPage.jsx` | Add "Threat Intelligence" section in AI Config tab — fields for VT key, AbuseIPDB key, GreyNoise key, each with inline test button |
| `portal/src/siem/SiemIncidentsPage.jsx` | **TI Reputation panel** in incident detail: per-IOC rows showing source badges (VT/AbuseIPDB/GreyNoise/MISP), verdict chip (MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN), confidence percentage |
| `portal/src/siem/SiemIncidentsPage.jsx` | **TI summary badge** on incident list cards: small coloured chip showing worst IOC verdict (e.g. `⚠ MALICIOUS · VT`) |
| `portal/src/siem/SiemFeedPage.jsx` | TI reputation column in alert feed table |

#### UI Verification Checklist
- [ ] Settings → AI Config → "Threat Intelligence" section visible with 3 API key fields
- [ ] Each key field has "Test" button that shows green/red inline result
- [ ] Incident detail → "Threat Intelligence" tab appears when `ti_reputation` is populated
- [ ] Per-IOC rows show source, verdict, confidence
- [ ] Incidents list card shows TI badge when any IOC is MALICIOUS or SUSPICIOUS
- [ ] No TI badge appears when `ti_reputation` is empty/null (graceful absence)

**New env vars:** `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY` (all optional)
**RBAC:** GET TI data → viewer+; POST API keys → admin only
**Agents to notify:** @g-cyra-siem
**Archive after phase:** `CYSIEM-Config/lists/sync_misp_cache.py` (superseded by `ti_enricher.py`)

---

### Phase 2 — Hypothesis Engine

**Goal:** Replace one-shot LLM prompt with structured hypothesis generation. Existing
ANALYST_SUMMARY + REMEDIATION_STEPS output is preserved unchanged — hypotheses are additive.

**How to verify it's working:** Open any incident detail → new "Investigation Hypotheses" panel
shows ranked cards (H1, H2, H3) each with a probability bar, MITRE technique tag, and
expandable "Evidence Needed" list.

#### Backend Files

| File | Change |
|---|---|
| `backend/cysiemstack/correlation_engine/hypothesis_engine.py` | **New** — `generate_hypotheses(incident, context_bundle)`. Structured JSON prompt returning `[{id, label, technique, kill_chain_stage, evidence_needed: [], initial_probability, reasoning}]`. JSON schema validated before storing. Returns `[]` on any LLM failure |
| `backend/cysiemstack/correlation_engine/llm_enricher.py` | Extend `enrich_incident()`: after existing summary generation, call `hypothesis_engine.generate_hypotheses()`. Store to `incident.hypotheses`. Existing flow unchanged |
| `backend/cysiemstack/correlation_engine/risk_scorer.py` | Populate `kill_chain_stage_name` in `compute_fp_score()` from top hypothesis `kill_chain_stage` field |
| `backend/cysiemstack/correlation_engine/models.py` | Add `hypotheses JSONB`, `hypothesis_generated_at TIMESTAMPTZ` to `Incident` |
| `backend/siem_proxy.py` | Expose `hypotheses`, `hypothesis_generated_at` in `/api/siem/incidents/<id>` |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/siem/SiemIncidentsPage.jsx` | **"Investigation Hypotheses" panel** in incident detail: ranked hypothesis cards (H1, H2, H3...) showing label, technique tag, kill-chain stage chip, animated probability bar (0–100%), expandable "Evidence Needed" list, reasoning text |
| `portal/src/siem/SiemIncidentsPage.jsx` | **Top hypothesis chip** on incident list cards: shows H1 label + probability (e.g. `H1: Malware Execution · 72%`) |
| `portal/src/siem/SiemIncidentsPage.jsx` | "Generated At" timestamp below hypothesis panel — confirms freshness |

#### UI Verification Checklist
- [ ] Incident detail shows "Investigation Hypotheses" section (only when hypotheses exist)
- [ ] H1, H2, H3 cards appear in probability order (highest first)
- [ ] Probability bar fills proportionally (e.g. 72% = 72% fill)
- [ ] MITRE technique shown as clickable tag (links to ATT&CK)
- [ ] "Evidence Needed" expands per hypothesis with item list
- [ ] Incident list card shows H1 chip with probability
- [ ] When LLM fails: section is absent, no error shown to user
- [ ] `hypothesis_generated_at` timestamp is visible and recent

**RBAC:** GET hypotheses → viewer+; hypothesis generation → analyst+ (on-demand trigger)
**Archive after phase:** Nothing — additive only.

---

### Phase 3 — Evidence Gap Analysis & Autonomous Collection

**Goal:** For each hypothesis, determine what evidence is missing, autonomously collect it
from Wazuh, and store results. This is the most novel stage — the first time CyCentra
closes the investigation loop without analyst input.

**How to verify it's working:** Open any incident detail → new "Evidence Collection" tab shows
a timeline of collection events: what was dispatched, what came back, what is still missing.
Each hypothesis card (from Phase 2) now has a "Coverage" indicator showing % of required
evidence collected.

#### Backend Files

| File | Change |
|---|---|
| `backend/cysiemstack/correlation_engine/gap_analyser.py` | **New** — `analyse_gaps(hypotheses, available_evidence)`. Returns `{hypothesis_id, missing: [{evidence_type, collector, priority}]}` per hypothesis |
| `backend/cysiemstack/correlation_engine/evidence_collector.py` | **New** — `EvidenceCollector` Protocol + registry. Built-in collectors: `ProcessTreeCollector`, `FileHashCollector`, `DNSHistoryCollector`, `UserPrivilegeCollector`, `VulnerabilityCollector`. Each wraps existing Wazuh API calls already in `siem_proxy.py` |
| `backend/cysiemstack/correlation_engine/llm_enricher.py` | After hypothesis generation: `gap_analyser.analyse_gaps()` → `evidence_collector.collect_all()` async (fire-and-forget, 30s timeout). Results written to `incident.evidence_log`. Never blocks incident creation |
| `backend/cysiemstack/correlation_engine/models.py` | Add `evidence_log JSONB`, `evidence_collected_at TIMESTAMPTZ`, `evidence_coverage NUMERIC(4,2)` to `Incident` |
| `backend/siem_proxy.py` | Expose `evidence_log`, `evidence_coverage` in `/api/siem/incidents/<id>` |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/siem/SiemIncidentsPage.jsx` | **"Evidence Collection" tab** in incident detail: timeline list of collection events (`[timestamp] [collector] [status] [summary]`). Status chips: COLLECTED (green), MISSING (amber), FAILED (red), PENDING (grey) |
| `portal/src/siem/SiemIncidentsPage.jsx` | **Coverage bar** added to each hypothesis card from Phase 2: `Evidence Coverage: ██████░░ 67%` |
| `portal/src/siem/SiemIncidentsPage.jsx` | **Overall evidence coverage badge** on incident header: `Evidence: 5/8 collected` |
| `portal/src/siem/SiemIncidentsPage.jsx` | Expandable evidence item rows: clicking "COLLECTED" item shows the raw collected data (process tree JSON, DNS records, etc.) |

#### UI Verification Checklist
- [ ] Incident detail shows "Evidence Collection" tab
- [ ] Collection events appear in chronological order with timestamps
- [ ] Status chips use correct colours (COLLECTED=green, MISSING=amber, FAILED=red)
- [ ] Each hypothesis card shows evidence coverage bar
- [ ] Header shows total collected / total required count
- [ ] Clicking a COLLECTED row expands raw evidence data
- [ ] FAILED rows show error reason (e.g. "Wazuh process tree unavailable")
- [ ] Tab is absent (not empty) when no hypotheses generated (Phase 2 not run yet)

**RBAC:** GET evidence log → viewer+
**Key constraint:** All collection is async. The incident detail page loads immediately
regardless of whether collection is in progress or complete.

---

### Phase 4 — Confidence Engine Enhancement & Re-evaluation Loop

**Goal:** Upgrade the confidence model with 5 weighted components. Add a second LLM pass
after evidence collection to re-score hypotheses with the new evidence in context. Surface
a single definitive confidence score on every incident.

**How to verify it's working:** Open any incident → header shows a confidence ring gauge
(0–100%) with colour coding. Incident list supports filtering by confidence. Dashboard
shows a "High Confidence" widget. Clicking the gauge shows the full confidence breakdown
(which components contributed how much).

#### Confidence Weight Model

| Component | Weight | Source |
|---|---|---|
| Rule contribution | 30% | Existing `_incident_severity_score()` normalised 0–1 |
| Threat intelligence | 25% | Phase 1 TI verdict (MALICIOUS=1.0, SUSPICIOUS=0.6, CLEAN=0.0) |
| Historical similarity | 20% | Phase 6 `incident_patterns` table (0.0 until Phase 6, then fills) |
| Asset criticality | 10% | Existing `_asset_score()` normalised 0–1 |
| LLM reasoning | 15% | Top hypothesis `initial_probability` from Phase 2 |

> Note: Until Phase 6 is deployed, historical similarity weight is redistributed equally
> across the other four components (effective weights: 35/29/0/12/24). No zero scores.

#### Backend Files

| File | Change |
|---|---|
| `backend/cysiemstack/correlation_engine/risk_scorer.py` | Add `compute_investigation_confidence(incident, ti_result, top_hypothesis_prob, asset_tier, historical_similarity)` — returns `(score_0_to_1, breakdown_dict)`. Existing `calculate_entity_risk()` unchanged |
| `backend/cysiemstack/correlation_engine/hypothesis_engine.py` | Add `re_evaluate_hypotheses(incident, new_evidence)` — second LLM pass. Updates hypothesis probabilities in place. Called after evidence collection completes |
| `backend/cysiemstack/correlation_engine/correlator.py` | After evidence collection: call `re_evaluate_hypotheses()` → `compute_investigation_confidence()` → write `confidence_score` + `confidence_breakdown` |
| `backend/cysiemstack/correlation_engine/models.py` | Add `confidence_score NUMERIC(4,2)`, `confidence_breakdown JSONB`, `confidence_computed_at TIMESTAMPTZ` to `Incident` |
| `backend/siem_proxy.py` | Expose `confidence_score`, `confidence_breakdown`, `confidence_computed_at` in `/api/siem/incidents/<id>` and `/api/siem/incidents` list |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/siem/SiemIncidentsPage.jsx` | **Confidence ring gauge** on incident detail header: SVG ring 0–100%, colour: red <50%, amber 50–70%, yellow 70–85%, green >85%. Clicking ring opens breakdown popover showing 5 weighted components as horizontal bars |
| `portal/src/siem/SiemIncidentsPage.jsx` | **Confidence chip** on incident list cards: coloured percentage badge (e.g. `87% CONF`) next to severity badge |
| `portal/src/siem/SiemIncidentsPage.jsx` | Confidence filter on incident list: dropdown "All / Low (<50%) / Medium (50–70%) / High (>70%) / Critical (>85%)" |
| `portal/src/pages/dashboard/DashboardPage.jsx` | **"High Confidence Incidents" widget**: list of top 5 incidents with `confidence_score > 0.85`, showing title + score + severity. Links to incident detail |
| `portal/src/siem/SiemIncidentsPage.jsx` | "Confidence computed at" timestamp below gauge — shows freshness after re-evaluation |

#### UI Verification Checklist
- [ ] Incident detail header shows confidence ring gauge
- [ ] Ring colour matches thresholds (red/amber/yellow/green)
- [ ] Clicking ring shows breakdown popover with 5 component bars
- [ ] Each component bar shows its name, weight, and contribution
- [ ] Incident list cards show confidence chip
- [ ] Confidence filter dropdown works (filters list correctly)
- [ ] Dashboard "High Confidence Incidents" widget shows and links correctly
- [ ] Confidence updates after evidence collection (check timestamp change)
- [ ] Incidents with no hypotheses yet show confidence based on available components (no zero)

**RBAC:** GET confidence data → viewer+
**Agents to notify:** @g-cyra-siem (incident model change)

---

### Phase 5 — Structured Recommendation Engine & Confidence-Gated SOAR

**Goal:** Replace free-text remediation with structured Containment/Eradication/Recovery output.
Gate SOAR execution on confidence threshold. Analysts see clear, actionable response cards
rather than a wall of text.

**CySOAR integration principle:** CySOAR (Node-RED) is installed from the Extensions page
(`/extensions`). When it is running, Phase 5 auto-detects it and wires up SOAR dispatch
**with zero manual configuration**. Users do not need to enter webhook URLs anywhere.
If CySOAR is not installed, the Response tab shows an install prompt instead of SOAR controls.

**How to verify it's working:** Open a high-confidence incident → "Response" tab shows three
clearly labelled sections (Containment / Eradication / Recovery) with action cards, a
CySOAR status indicator showing "RUNNING · Auto-wired", and a confidence-gated action button.

#### How Auto-Wiring Works

When CySOAR is installed via Extensions, the Node-RED container runs on port 1880 and is
accessible locally at `http://127.0.0.1:1880`. The existing `cases/routes.py` already
defaults to this address. Phase 5 extends `_soar_webhook_url()` in `cysoar_connector.py`
with a third resolution path:

```
Resolution order (existing → new):
  1. settings.soar_webhook_url  (cysiemstack.env explicit override)
  2. ai_settings.json → soar.webhookUrl  (portal-managed explicit override)
  3. [NEW] Auto-detect: if /opt/cycentra/modules/state.json shows
     cysoar.status == "running" → use http://127.0.0.1:1880
```

This means: install CySOAR from Extensions → SOAR dispatch works automatically. No settings
page needed. The explicit override paths (1 and 2) remain for advanced/custom deployments.

#### Confidence Gate Thresholds

| Confidence | UI State | SOAR Action |
|---|---|---|
| < 70% | 🔴 "Needs Review" — no SOAR controls | No dispatch |
| 70–89% | 🟡 "Analyst Approval Required" — "Approve & Execute" button | Dispatch on approval |
| ≥ 90% | 🟢 "Auto-Executed" — actions sent to CySOAR automatically | Auto-dispatch |

#### Backend Files

| File | Change |
|---|---|
| `backend/cysiemstack/correlation_engine/cysoar_connector.py` | Extend `_soar_webhook_url()` with auto-detection (resolution path 3): read `/opt/cycentra/modules/state.json`, return `http://127.0.0.1:1880` if `cysoar.status == "running"`. No other changes to existing dispatch logic |
| `backend/cysiemstack/correlation_engine/cysoar_connector.py` | Add `dispatch_if_confident(incident, recommendation, confidence_score)`. Calls `_soar_webhook_url()` (auto-wired if installed). Applies confidence gate. Posts enriched payload including `recommendation` fields (containment/eradication/recovery) to Node-RED. Writes result to `soar_dispatched`, `soar_dispatched_at`, `soar_dispatch_log` |
| `backend/cysiemstack/correlation_engine/llm_enricher.py` | Add `generate_structured_recommendation(incident, confidence_score)`. Prompt returns `{containment: [], eradication: [], recovery: [], executive_summary: ""}`. Applied when `confidence_score >= 0.50`; existing free-text REMEDIATION_STEPS kept as fallback for < 50% |
| `backend/cysiemstack/correlation_engine/models.py` | Add `recommendation JSONB`, `soar_dispatched BOOLEAN DEFAULT FALSE`, `soar_dispatched_at TIMESTAMPTZ`, `soar_dispatch_log JSONB` to `Incident` |
| `backend/siem_proxy.py` | Expose `recommendation`, `soar_dispatched`, `soar_dispatched_at`, `soar_dispatch_log` in incident API. New POST `/api/siem/incidents/<id>/approve-soar` route (analyst+) for 70–89% manual approval gate |
| `backend/siem_proxy.py` | New GET `/api/siem/soar/status` — returns `{installed: bool, running: bool, url: str, source: "auto"|"config"|"env"}`. Used by frontend to show CySOAR connection state without exposing credentials |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/siem/SiemIncidentsPage.jsx` | **"Response" tab** in incident detail: executive summary at top, then three accordion sections (Containment / Eradication / Recovery), each with numbered action cards |
| `portal/src/siem/SiemIncidentsPage.jsx` | **CySOAR status bar** at top of Response tab: fetches `/api/siem/soar/status` on mount. Shows: `🟢 CySOAR RUNNING · Auto-wired` when installed, or `⚪ CySOAR not installed — [Install from Extensions ↗]` link when absent |
| `portal/src/siem/SiemIncidentsPage.jsx` | **Confidence gate banner** below CySOAR bar: red/amber/green showing gate state. "Approve & Execute" button appears only at 70–89%; auto-dispatched shows timestamp; < 70% shows "Analyst review required" |
| `portal/src/siem/SiemIncidentsPage.jsx` | **SOAR dispatch badge** on incident list card: `⚡ AUTO` (green), `⏳ PENDING` (amber), or `👤 REVIEW` (red) |
| `portal/src/siem/SiemIncidentsPage.jsx` | **Dispatch log accordion** at bottom of Response tab: collapsible list of dispatch events from `soar_dispatch_log` — timestamp, confidence at dispatch, Node-RED HTTP response code, actions sent count |
| `portal/src/pages/dashboard/DashboardPage.jsx` | **"SOAR Activity" widget**: last 24h counts — auto-dispatched / pending approval / manual review. CySOAR status dot (green=running, grey=not installed) |

#### UI Verification Checklist
- [ ] Response tab appears in incident detail when `recommendation` is populated
- [ ] Three accordion sections display (Containment / Eradication / Recovery)
- [ ] Executive summary at top
- [ ] CySOAR status bar shows correctly:
  - [ ] With CySOAR installed: `🟢 RUNNING · Auto-wired` with no URL field shown
  - [ ] Without CySOAR: `⚪ Not installed` with "Install from Extensions ↗" link
- [ ] < 70% confidence: red gate banner, no SOAR controls
- [ ] 70–89% confidence: amber banner + "Approve & Execute" button
- [ ] ≥ 90% confidence: green banner, "Auto-Executed at [timestamp]"
- [ ] "Approve & Execute" shows confirmation dialog before posting to Node-RED
- [ ] After dispatch: SOAR badge appears on incident list card
- [ ] Dispatch log shows HTTP response code from Node-RED
- [ ] Dashboard SOAR Activity widget shows correct counts
- [ ] Uninstalling CySOAR from Extensions → status bar changes to "Not installed" on next load

**RBAC:** GET recommendation/soar-status → viewer+; POST approve-soar → analyst+; auto-dispatch → system (engine process)
**New env vars:** None — `SOAR_WEBHOOK_URL` already exists as explicit override; auto-detect requires no new vars
**Archive after phase:** Plain `REMEDIATION_STEPS` string for incidents with `confidence >= 0.50` (kept as fallback for low-confidence only)

---

### Phase 6 — Incident Pattern Memory & Learning Loop

**Goal:** Store resolved incident patterns and feed them into Phase 4's historical similarity
component. Over time, the confidence engine becomes more accurate as it recognises known-good
and known-bad investigation patterns.

**How to verify it's working:** New "Similar Past Incidents" panel in incident detail shows
matched patterns with similarity score. Settings > System shows total patterns stored and
confidence accuracy trend over time.

#### Backend Files

| File | Change |
|---|---|
| `backend/cy_comp/models.py` | **New `incident_patterns` table:** `id, technique, kill_chain_stage, process_chain JSONB, payload_indicators JSONB, response_actions JSONB, outcome VARCHAR(50), confidence_at_resolution NUMERIC(4,2), similarity_vector JSONB, created_at TIMESTAMPTZ` |
| `backend/cysiemstack/correlation_engine/llm_enricher.py` | On incident transition to `closed` or `resolved`: call `_store_incident_pattern(incident)`. Extends (does not replace) existing `_store_to_cymind_memory()` |
| `backend/cysiemstack/correlation_engine/risk_scorer.py` | `historical_similarity` component: query `incident_patterns` for records matching technique + kill-chain stage. Return cosine similarity score 0–1 to fill the 20% weight slot in Phase 4 |
| `backend/siem_proxy.py` | New GET `/api/siem/incidents/<id>/similar` → returns top 3 matching patterns with similarity scores |
| `backend/blueprints/system/routes.py` | Add pattern stats to `/api/system/version` or new `/api/system/ai-stats` endpoint |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/siem/SiemIncidentsPage.jsx` | **"Similar Past Incidents" panel** in incident detail: up to 3 matched pattern cards showing technique, kill-chain stage, similarity %, outcome badge (RESOLVED/FALSE_POSITIVE), and confidence at resolution |
| `portal/src/siem/SiemIncidentsPage.jsx` | Historical similarity contribution visible in Phase 4 confidence breakdown popover — now shows real value instead of 0.0 |
| `portal/src/pages/settings/SystemSettingsPage.jsx` | **"AI Investigation Stats" card** in Updates tab: total patterns stored, avg confidence accuracy, phases active |

#### UI Verification Checklist
- [ ] Closed/resolved incidents generate a pattern (check via AI Stats card count incrementing)
- [ ] "Similar Past Incidents" panel appears on incident detail (only when similarity > 0.4)
- [ ] Each matched pattern card shows similarity % and outcome
- [ ] Confidence breakdown popover now shows non-zero historical similarity contribution
- [ ] AI Investigation Stats card shows growing pattern count over time
- [ ] Panel is absent (not empty) when no similar patterns found

**RBAC:** GET similar patterns → viewer+
**Archive after phase:** Nothing — Phase 4's `historical_similarity=0.0` placeholder now replaced by real values.

---

### Phase 7 — SIEM-Agnostic Adapter Layer (deferred — do last)

**Goal:** Decouple Wazuh-specific API calls from `siem_proxy.py` into a `SIEMAdapter`
protocol. Enables future SIEM additions (Elastic, Splunk) without touching the investigation
engine built in Phases 1–6.

**⚠ Risk note:** This phase touches `siem_proxy.py` extensively. Requires thorough regression
testing of the full Wazuh integration before deploying to production. All Phases 1–6 must
be stable first.

#### New Files

```
backend/
  siem_adapters/
    __init__.py          # get_active_adapter() → reads DB or env var fallback
    base.py              # SIEMAdapter Protocol
    wazuh.py             # WazuhAdapter — absorbs all inline Wazuh helpers
```

#### SIEMAdapter Protocol

```python
class SIEMAdapter(Protocol):
    def get_agents(self) -> list[dict]: ...
    def get_agent_sca(self, agent_id: str) -> dict: ...
    def get_agent_vulnerabilities(self, agent_id: str) -> dict: ...
    def get_agent_packages(self, agent_id: str) -> dict: ...
    def get_process_tree(self, agent_id: str, pid: str) -> dict: ...
    def get_dns_history(self, agent_id: str) -> dict: ...
    def get_auth_token(self) -> str | None: ...
    def test_connection(self) -> dict: ...
    def get_capabilities(self) -> list[str]: ...
```

#### DB Schema for SIEM Configs

```sql
CREATE TABLE siem_integrations (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(100) NOT NULL,
    siem_type     VARCHAR(50) NOT NULL,      -- "wazuh" | "elastic" | "splunk"
    base_url      TEXT NOT NULL,
    username      VARCHAR(255),
    password_enc  TEXT,                      -- encrypted via kv_secrets
    is_active     BOOLEAN DEFAULT FALSE,
    capabilities  JSONB DEFAULT '[]',
    last_tested   TIMESTAMPTZ,
    last_test_ok  BOOLEAN,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);
```

Existing env vars (`WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS`) remain valid as
fallback — zero breaking change for existing deployments.

#### Backend Files

| File | Change |
|---|---|
| `backend/siem_adapters/__init__.py` | New |
| `backend/siem_adapters/base.py` | New |
| `backend/siem_adapters/wazuh.py` | New — absorbs `_wazuh_auth_token()`, `_wz()`, `_WAZUH_ADMIN_BASIC`, `_WAZUH_RO_BASIC`, `_refresh_host_cache_sync()` Wazuh API calls |
| `backend/siem_proxy.py` | Refactor: replace all inline Wazuh API calls with `get_active_adapter()`. Identical external behavior |
| `backend/blueprints/siem_config/routes.py` | New Blueprint — CRUD for `siem_integrations` table + `/test-connection` endpoint |
| `backend/cy_comp/models.py` | Add `siem_integrations` table to `ensure_tables()` |
| `backend/app.py` | Register `siem_config_bp` |

#### Frontend Files

| File | Change |
|---|---|
| `portal/src/pages/settings/SystemSettingsPage.jsx` | Add "SIEM Integrations" tab (Tab 5) |
| `portal/src/pages/settings/SiemIntegrationsTab.jsx` | New — connection cards (URL, user, password, type, capabilities), test button, active toggle, last-tested status |

#### UI Verification Checklist
- [ ] Settings → SIEM Integrations tab shows Wazuh card populated from existing env vars
- [ ] "Test Connection" button returns green/red result
- [ ] Active toggle persists to DB
- [ ] All existing Wazuh-dependent features (host posture, incidents, UEBA) work identically
- [ ] Phase 1–6 evidence collectors still function via adapter

**RBAC:** GET SIEM config → analyst+; POST/PUT/DELETE → admin only
**Agents to notify:** @g-cyra-devops, @g-cyra-siem

#### Archive after Phase 7

| Code | Reason |
|---|---|
| `siem_proxy.py` inline `_wazuh_auth_token()`, `_wz()`, `_WAZUH_ADMIN_BASIC`, `_WAZUH_RO_BASIC` | Moved to `siem_adapters/wazuh.py` |
| Hardcoded `WAZUH_API_URL` reads in `_refresh_host_cache_sync()` | Replaced by `get_active_adapter()` |

---

## 6. Cumulative Archive / Obsolescence Plan

| After Phase | File / Code | Reason |
|---|---|---|
| 1 | `CYSIEM-Config/lists/sync_misp_cache.py` | Superseded by `ti_enricher.py` plugin architecture |
| 2 | One-shot `SYSTEM_PROMPT` in `llm_enricher.py` (as sole prompt) | Replaced by structured hypothesis prompt; becomes one of two prompts |
| 5 | Plain `REMEDIATION_STEPS` string for `confidence >= 0.50` incidents | Replaced by structured `{containment, eradication, recovery}` — kept as fallback for < 50% only |
| 7 | `siem_proxy.py` inline Wazuh helpers (`_wazuh_auth_token`, `_wz`, `_WAZUH_ADMIN_BASIC`) | Moved to `siem_adapters/wazuh.py` |

---

## 7. Pre-Implementation Checklist (per phase)

- [ ] Phase reviewed and approved
- [ ] AST check all new `.py` files before merge
- [ ] `npm run build` passes after any JSX changes
- [ ] All new routes have RBAC + OPTIONS handler
- [ ] `app.py` stays ≤ 70 lines
- [ ] `App.jsx` stays ≤ 120 lines
- [ ] RELEASE_NOTES.md entry drafted
- [ ] No secrets in code or logs
- [ ] All new DB columns use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (never `create_all()`)
- [ ] All new async operations are fire-and-forget with explicit timeout (30s max)
- [ ] UI verification checklist for the phase is fully ticked

---

## 8. Open Decisions (resolve before starting implementation)

1. **TI API keys (Phase 1):** Which services to enable first — VirusTotal, AbuseIPDB, and/or GreyNoise? All are pay-per-call; AbuseIPDB has a generous free tier. Start with AbuseIPDB + GreyNoise?
2. **SOAR auto-dispatch threshold (Phase 5):** Confirm 90% as the auto-execute threshold or adjust upward (95%) for more conservative first deployment.
3. **Confidence minimum for structured recommendation (Phase 5):** Currently 50% — lower than this shows free-text. Adjust?
4. **Patent filing:** Provisional filing recommended before Phase 5 ships publicly.
5. **Phase 7 scheduling:** Confirm Phase 7 is only after all 1–6 are stable in production (no earlier).
