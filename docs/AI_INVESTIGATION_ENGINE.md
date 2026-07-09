# AI Investigation Engine — CySIEM Correlation Engine

> **Settings → Updates & Version → AI Investigation Engine**

The AI Investigation Engine is a six-phase pipeline that enriches every security incident automatically — from raw alert normalisation through to machine-learning-backed structured recommendations and long-term pattern memory.

---

## Architecture Overview

```
Wazuh Alert → Redis → [Phase 1] Normalise/Group/Correlate/UEBA
                              ↓
                      [Phase 2] LLM Narrative + Hypotheses
                              ↓
                      [Phase 3] Gap Analysis + Evidence Collection
                              ↓
                      [Phase 4] Confidence Score (0–1)
                              ↓
                      [Phase 5] C/E/R Recommendations + CySOAR
                              ↓
                      [Phase 6] Pattern Memory (incident closed)
                              ↓
                      Next incident of same type → historical weight applied
```

---

## The Six Phases

### Phase 1 — Normalise · Group · Correlate · UEBA
**File:** `cysiemstack/correlation_engine/ingestor.py`  
**Always active.**

Every alert from Wazuh passes through:
1. **Normalise** (`normaliser.py`) — maps raw Wazuh JSON to a canonical alert schema (rule_id, src_ip, agent_id, MITRE fields, etc.)
2. **Group** (`grouper.py`) — matches the alert to an existing open incident (by technique + agent + time window) or creates a new one. Advisory DB lock prevents race conditions under concurrent ingestion.
3. **Correlate** (`correlator.py`) — runs all 55 correlation rules against the updated incident. Rules fire across alert sequences (e.g. CR-003 lateral movement: SSH auth failure → success → new process).
4. **UEBA** (`ueba.py`, `ueba_ml.py`) — 17 behavioral detectors per user + host (activity spike, after-hours access, impossible travel, etc.). ML-based anomaly detection layered on top.
5. **Risk scoring** — entity risk (user/host/cloud) recalculated. FP probability computed from: rule confidence × UEBA anomaly count × TI IOC hits × kill-chain stage × asset tier.

---

### Phase 2 — LLM Narrative + Hypotheses
**File:** `cysiemstack/correlation_engine/llm_enricher.py` → `hypothesis_engine.py`  
**Active when:** incident severity = critical/high AND alert_count ≥ 3 AND LLM not yet generated.

The configured AI provider (CyMind, Anthropic, Gemini, Ollama, DeepSeek — set in Settings → AI Config) generates:
- **Analyst summary** — plain-English incident narrative with context about affected assets and observed behavior.
- **Remediation steps** — prioritised free-text response guidance.
- **Structured hypotheses** — ranked MITRE ATT&CK attack path hypotheses, each with: kill-chain stage, initial probability (0–100), missing evidence list. Example:
  ```json
  { "kill_chain_stage": "privilege-escalation",
    "mitre_technique": "T1548.003",
    "initial_probability": 72,
    "missing_evidence": ["process_ancestry", "sudo_log_entry"] }
  ```
- The top hypothesis's `kill_chain_stage` is wired into the incident record for Phase 3.

---

### Phase 3 — Gap Analysis + Evidence Collection
**Files:** `gap_analyser.py`, `evidence_collector.py`  
**Active when:** Phase 2 produced hypotheses.

Runs as a background task (fire-and-forget, 30 s timeout):
1. **Gap analysis** — for each hypothesis, identifies which evidence items are required but not yet present in the alert set.
2. **Evidence collection** — queries available sources for the missing evidence: process trees, network connections (Wazuh syscollector), file events, authentication logs. Marks each item COLLECTED or MISSING.
3. **Coverage metric** — `evidence_coverage = collected / total_requested` stored on the incident (0–1).

---

### Phase 4 — Re-evaluate + Confidence Score
**File:** `risk_scorer.py` → `compute_investigation_confidence()`  
**Active when:** Phase 3 completes.

Hypotheses are re-evaluated with the collected evidence. Then a **5-component confidence score** is computed:

| Component | Weight | What it measures |
|-----------|--------|-----------------|
| Rule Contribution | 30% | Average confidence of fired correlation rules |
| Threat Intelligence | 25% | CyTIM verdict (malicious=1.0, suspicious=0.6, clean=0.0) |
| Historical Similarity | 20% | Match against `incident_patterns` table (Phase 6 data) |
| Asset Criticality | 10% | Asset tier (1=crown jewel → 0=unclassified) |
| LLM Reasoning | 15% | Top hypothesis initial probability / 100 |

> **When no patterns exist yet** (Phase 6 inactive), the 20% Historical weight is redistributed proportionally across the other four components so the achievable maximum remains 1.0.

The final score (0–1) drives all downstream decisions: Phase 5 fires only at ≥ 0.50; the confidence breakdown is shown in the incident detail panel.

---

### Phase 5 — Structured C/E/R Recommendations + CySOAR
**File:** `llm_enricher.py` → `generate_structured_recommendation()`  
**Active when:** confidence_score ≥ 0.50 (confirmed by Phase 4).

Generates a machine-readable **Contain / Eradicate / Recover** action plan:
```json
{
  "contain":    ["Isolate host CY360-DEV from network", "Reset credentials for user root"],
  "eradicate":  ["Remove persistence mechanism at /etc/cron.d/...", "Patch CVE-2024-..."],
  "recover":    ["Restore from snapshot taken 2026-07-08", "Re-validate audit trail"]
}
```
This `recommendation` field is stored on the incident and surfaced in the incident detail panel. If CySOAR is enabled and the playbook matches, the containment steps are dispatched automatically.

---

### Phase 6 — Pattern Memory (Historical Similarity)
**Files:** `llm_enricher.py` → `_store_incident_pattern()`, `risk_scorer.py` → `compute_historical_similarity()`  
**Active when:** at least one pattern exists in `incident_patterns` table.

When an incident is **closed or resolved** (by analyst or auto-close), the engine stores a pattern record:

```sql
-- incident_patterns table
id                        BIGINT PRIMARY KEY
source_incident_id        TEXT           -- e.g. "INC-46891"
technique                 TEXT           -- MITRE ID e.g. "T1078"
kill_chain_stage          TEXT           -- e.g. "privilege-escalation"
process_chain             JSONB          -- correlation rules that fired
payload_indicators        JSONB          -- { src_ips, users, agents, rule_ids }
response_actions          JSONB          -- structured C/E/R used
outcome                   TEXT           -- "closed" | "resolved" | "false_positive"
confidence_at_resolution  NUMERIC(4,2)   -- Phase 4 score, or fp_probability/100
similarity_vector         JSONB          -- { techniques, tactics, kill_chain, severity, alert_count_bucket }
created_at                TIMESTAMPTZ
```

**How confidence_at_resolution is populated:**
- For **analyst-closed** incidents: Phase 4 `confidence_score` (0–1).
- For **auto-closed FP** incidents: `fp_probability / 100` (how confident the engine was it was a false positive). Phase 4 never runs for auto-closed low-severity incidents.

**How patterns are consumed** (next time a similar incident arrives):
```python
# risk_scorer.compute_historical_similarity()
# Finds patterns with matching technique OR kill_chain_stage
# technique match = +0.60 score, kill_chain match = +0.40 score
# Returns best match score (0–1) → feeds into the 20% historical weight
```

---

## What Patterns Indicate and Predict

### FP Suppressor (outcome = `closed` or `false_positive`)
Stored when the engine auto-closed an incident due to high FP probability, or an analyst marked it false positive.

**Effect on future incidents:** The 20% historical similarity slot is *dampened* — a future incident with the same MITRE technique on the same agent class will score lower confidence. This reduces triage noise for repeat benign activity (e.g. a scheduled sudo task that fires rule 5400 every night).

**Trigger for upgrade:** If the underlying activity genuinely changes (e.g. a new malicious sudo command uses the same technique), CyTIM IOC hits or UEBA anomalies will override the dampening — the `_is_guarded()` function in `fp_pattern_store.py` blocks suppression when confirmed IOC hits or high-fidelity rules (CR-003/013/014/025/026) fire.

### TP Booster (outcome = `resolved`)
Stored when an analyst confirmed and resolved a real incident.

**Effect on future incidents:** The 20% historical similarity slot is *boosted* — a future incident matching the same technique gains higher confidence, making Phase 5 recommendations and CySOAR dispatch more likely to trigger.

---

## Viewing Patterns in the UI

**Settings → Updates & Version → AI Investigation Engine → VIEW PATTERNS**

The pattern table shows:
- **#** — pattern database ID
- **INCIDENT** — source incident (e.g. INC-46891)
- **TECHNIQUE** — MITRE ATT&CK technique ID + name (e.g. T1078 · Valid Accounts)
- **TACTIC** — ATT&CK tactic (e.g. Defense Evasion)
- **OUTCOME** — `closed` (orange) / `resolved` (green) / `false_positive` (red)
- **CONF** — confidence at resolution as percentage
- **AGENTS / USERS** — primary affected asset and user
- **STORED** — date pattern was written

Click any row to expand the **prediction panel**, which explains exactly what effect this pattern has on future similar incidents, and shows the FP score and reason for auto-closure.

---

## Stats Card

| Metric | Source |
|--------|--------|
| **PATTERNS STORED** | `COUNT(*) FROM incident_patterns` |
| **AVG CONFIDENCE** | `AVG(confidence_at_resolution)` — reflects engine certainty across all stored outcomes |
| **LAST PATTERN** | `MAX(created_at)` — should update continuously as incidents close |

---

## Known History

| Date | Event |
|------|-------|
| 2026-06-25 | First 3 patterns written via analyst `transition_incident` endpoint |
| 2026-06-25 – 2026-07-09 | Zero new patterns — ingestor Band 1 auto-close bypassed `transition_incident`, `_store_incident_pattern` never called |
| 2026-07-09 | Bug fixed: `_store_incident_pattern` added to both auto-close paths in `ingestor.py`. 16 patterns immediately written. |
| 2026-07-09 | `fp_auto_close_scheduler` fixed: `timedelta` import missing in `main.py:_fp_auto_close_scheduler()` |
| 2026-07-09 | `confidence_at_resolution` backfilled for all 16 existing patterns from `fp_probability / 100` |
| 2026-07-09 | AVG CONFIDENCE double ×100 bug fixed: backend was sending `avg_conf * 100`, frontend also multiplied by 100 |

---

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/system/ai-stats` | viewer+ | Aggregate stats: patterns_total, avg_confidence_accuracy (0–1), phases_active, last_pattern_at |
| `GET /api/system/ai-patterns?page=&limit=` | viewer+ | Paginated pattern list with prediction metadata |
