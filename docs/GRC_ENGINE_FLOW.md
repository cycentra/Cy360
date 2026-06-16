# CyCentra 360 — GRC Engine Processing Flow

**Version:** 1.2.x  
**Module:** cy-comp (Security Compliance)  
**Last Updated:** 2026-05-14

---

## Overview

The GRC (Governance, Risk & Compliance) engine in CyCentra 360 is a multi-layer pipeline that continuously ingests telemetry from across the platform, maps it against compliance controls, identifies gaps and risks, and surfaces them as assessments, findings, risk register entries, dashboards, and reports. It is designed to maintain a single authoritative record per compliance artefact — no duplication of alert or incident data into compliance-only tables.

---

## 1. Data Ingestion

### 1.1 Compliance Frameworks & Reference Documents

| Source | Location | Description |
|--------|----------|-------------|
| Framework standards (ISO 27001, NIS2, DORA, SOC 2, NIST CSF, PCI DSS) | `cy_comp_policy_docs` (doc_type='framework') | Admin-uploaded via **System Settings → Security Compliance → Framework Documents**. Each framework has a dedicated CyMind RAG collection (`framework-{id}`). Locked base docs cannot be deleted. |
| Questionnaire templates | `cy_comp_questionnaire_templates` | Seeded from code at startup (`questionnaire.py → seed_templates()`). 26–45 controls-level questions per framework covering all major control domains. Idempotent — safe to re-run. |
| Framework control mappings | `FRAMEWORK_CONTROL_COUNTS` in `compliance.py` | Canonical question/control count per framework used as the scoring denominator (`nis2=28, dora=28, iso27001=45, soc2=28, nist_csf=26, pci_dss=30, gdpr=30, eu_ai_act=30`). |

### 1.2 Customer Policy Documents

| Source | Location | Description |
|--------|----------|-------------|
| Organisational policy docs | `cy_comp_policy_docs` (doc_type='policy') | Uploaded via **GRC Posture → Getting Started → Upload Policy Docs**. Flat store — not organised by framework. CyMind RAG collection: `org-policies`. Supports PDF, DOCX, TXT, Markdown. |

### 1.3 Security Telemetry

| Source | Table | Compliance columns |
|--------|-------|--------------------|
| SIEM alerts (Wazuh / Correlation Engine) | `alerts` | `is_compliance_relevant`, `compliance_frameworks TEXT[]`, `compliance_controls JSONB`, `compliance_confidence NUMERIC(4,2)` |
| Incidents | `incidents` | `compliance_frameworks TEXT[]`, `compliance_controls JSONB`, `compliance_confidence NUMERIC(4,2)`, `compliance_breach BOOLEAN` |
| Vulnerabilities | ASM scan results in `scan_results` | Linked via MITRE technique → control mapping in `auto_findings.py` |
| Configuration state | `cy_comp_questionnaire_responses` | Analyst-answered questionnaire responses that capture control-level configuration evidence |
| SIEM connection metadata | `cy_comp_siem_connections` | External SIEM sources beyond the built-in Correlation Engine |

**Zero-duplication design:** Compliance enrichment lives as added columns on the canonical `alerts` and `incidents` tables. No alert or incident data is copied into cy-comp-specific tables.

---

## 2. Mapping, Tagging & Enrichment

### 2.1 Alert-to-Framework Mapping

**Trigger:** Background job (`APScheduler`) and on-demand via `POST /api/comp/findings/auto-generate`.

**Pipeline (`auto_findings.py → generate_findings_from_alerts`):**

1. Query `alerts` where `is_compliance_relevant IS NULL` (unprocessed) or on-demand for a specific framework.
2. For each alert: extract `mitre_technique`, `rule_level`, `compliance_confidence`.
3. Look up `REMEDIATION_GUIDANCE[mitre_technique]` to get which frameworks and controls are affected. Falls back to parent technique (e.g. T1110.001 → T1110), then to a DEFAULT_REMEDIATION entry.
4. For each framework affected: write or update a row in `cy_comp_findings` with:
   - `framework`, `control_id`, `control_ref` (MITRE technique ID)
   - `source_type = 'automated'`, `auto_generated = TRUE`
   - `alert_count` (aggregated across matching alerts)
   - `last_seen_at` (most recent alert timestamp)
   - `verdict` computed by `_verdict(rule_level, confidence)`
5. Update `alerts.is_compliance_relevant = TRUE`, `compliance_frameworks`, `compliance_controls`, `compliance_confidence`.
6. Deduplication key: `(framework, control_id, source_type='automated', auto_generated=TRUE)` — ON CONFLICT DO UPDATE.

### 2.2 Questionnaire-Based Evidence Collection

**Trigger:** Analyst opens **Assessments** page and answers framework questionnaire.

**Pipeline (`questionnaire.py`):**

1. Templates are displayed per framework in section-grouped order.
2. Analyst selects response (yes/no, 1–5 scale, multi-choice, or text).
3. `save_response()` upserts into `cy_comp_questionnaire_responses` with `question_id`, `response`, `notes`, `evidence_refs`, `auto_score`.
4. Auto-scoring rules: `yes_no`: YES→2pts, NO→0pts; `score_1_5`: ≥4→2pts, 3→1pt, ≤2→0pts; `text`/`multi_choice`→1pt (pending manual review).
5. `generate_gap_findings(framework)` creates `cy_comp_findings` entries for every NO-response question, flagged with `questionnaire_gap=TRUE`.

### 2.3 CyMind RAG Enrichment

**Used for:** compliance assessment contextualisation, gap narrative generation, report text generation.

**How it works:**
- Alert or finding description is sent to CyMind via `query_for_compliance(description)`.
- CyMind queries across all active framework RAG collections (`framework-iso27001`, `framework-nis2`, etc.) and the `org-policies` collection.
- Returns matching chunks with confidence score, used to:
  - Confirm or refine framework mapping for an alert.
  - Generate narrative evidence for gap findings.
  - Power the report generation pipeline.

---

## 3. Gap Identification & Risk Assessment

### 3.1 Verdict Engine

Each finding in `cy_comp_findings` carries a `verdict`:

| Verdict | Condition |
|---------|-----------|
| **BREACH** | `rule_level ≥ 12` AND `compliance_confidence ≥ 0.70` |
| **WARNING** | `rule_level ≥ 10` OR (`rule_level ≥ 7` AND `confidence ≥ 0.60`) |
| **COMPLIANT** | All other auto-generated findings |
| **OPEN** | Default for manually created or questionnaire-gap findings pending review |

### 3.2 Control Gap Identification

A control is considered a **gap** when:
- Questionnaire response is NO for a required control (`questionnaire_gap=TRUE`), OR
- No questionnaire response exists AND there are BREACH-verdict automated findings for that control.

A control is **partial** when:
- Score_1_5 response is 3 (mid-range), OR
- Questionnaire says YES but automated findings show WARNING-level alerts.

### 3.3 Controls View

`GET /api/comp/controls-view/<framework>` merges three data sources into one row per control:

| Column | Source |
|--------|--------|
| `control_ref` | Questionnaire template `control_ref` |
| `status` | Derived: `compliant` / `partial` / `gap` / `breach` / `not_assessed` |
| `sources` | `["questionnaire"]`, `["automated"]`, or both |
| `response` | Questionnaire answer |
| `alert_count` | Count of `is_compliance_relevant` alerts for this control |
| `finding` | Highest-severity automated finding detail |

### 3.4 Risk Register Auto-Population

`POST /api/comp/risks/auto-populate` runs `risk.py → auto_populate_from_findings()`:

1. Reads all BREACH and WARNING verdict findings where `auto_generated=TRUE`.
2. For each: creates a `cy_comp_risks` entry unless a similar title already exists (LIKE dedup).
3. Severity → likelihood × impact mapping: `critical`→5×5, `high`→4×4, `medium`→3×3.
4. Resulting risk score drives the heatmap in **Risk Management**.

---

## 4. Scoring

### 4.1 Per-Framework Score Calculation

Computed by `compliance.py → _compute_score_for_framework(cur, framework)`:

```
q_total   = question count from questionnaire templates
             (falls back to FRAMEWORK_CONTROL_COUNTS[framework] if no templates)

q_pass    = answered questions with auto_score = 2 (full pass)
q_partial = answered questions with auto_score = 1 (partial)
q_fail    = answered questions with auto_score = 0 (gap/fail)

alert_penalty = min(40, critical_alerts*8 + high_alerts*4 + medium_alerts*1)

if q_answered > 0:
    q_score = (q_pass + q_partial*0.5) / q_total * 100
    final_score = max(0, q_score - alert_penalty)
elif q_total > 0:      ← templates seeded but none answered
    final_score = 0.0
else:                  ← no templates seeded at all (framework not configured)
    final_score = max(0, 100 - alert_penalty)
```

**Key invariant:** `q_total` is always the questionnaire question count (26–45 per framework) — never the alert count. This ensures the score reflects control coverage, not alert volume.

### 4.2 Score History

`cy_comp_framework_scores` stores point-in-time score snapshots for trend charts. Written by the scheduler and on manual score saves.

### 4.3 Overall GRC Posture Score

Displayed on the **GRC Posture Dashboard** as a weighted average across all active frameworks using the per-framework blended scores.

---

## 5. Correlation into Outputs

### 5.1 Assessments (Questionnaire + Controls View)

- **Assessment page** (`/comp-assessment`): analyst-facing questionnaire per framework. Shows score strip (score, total controls, answered, gaps), section tabs, and per-question evidence entry.
- **Controls List tab**: merged view of all controls — questionnaire status, automated finding status, alert count, breach details. Filter by status.

### 5.2 Findings Registry

- **Findings page** (`/comp-findings`): unified list of all `cy_comp_findings` — automated (from alerts) and questionnaire-gap (from NO responses).
- Verdict badges: BREACH (red) / WARNING (orange) / COMPLIANT (green) / OPEN (grey).
- Remediation panel per finding: MITRE-mapped action steps, affected framework controls, evidence references.
- Filters: framework, severity, verdict, source (auto/survey/manual).

### 5.3 Risk Register

- **Risk Management page** (`/comp-risks`): `cy_comp_risks` table with likelihood × impact heatmap.
- Auto-populated from BREACH/WARNING findings via "Auto-Populate from Findings" button.
- Manual risk entries also supported.

### 5.4 GRC Posture Dashboard

- **GRC Posture page** (`/comp-dashboard`): consolidated cross-framework view.
  - Donut chart: overall GRC score.
  - Framework score bars with show/hide toggle (persisted to localStorage).
  - Findings pie chart: BREACH / WARNING / COMPLIANT distribution.
  - Verdict bar chart.
  - Alerts-by-day histogram (severity-coded).
  - Score trend line chart (all frameworks, 30-day history).
  - Breach incidents table.
  - Getting Started flow widget.

### 5.5 Reports

- **Reports page** (`/comp-reports`): on-demand PDF/HTML report generation per framework.
- Report jobs tracked in `cy_comp_report_jobs`.
- Report content draws from: framework score, controls view, gap findings list, risk register entries, questionnaire evidence, and CyMind RAG-generated narrative.

---

## 6. Evidence Linkage & Traceability

| Artefact | Traceability |
|----------|-------------|
| Automated finding | Links back to source alerts via `alert_count`, `last_seen_at`, MITRE technique |
| Questionnaire gap finding | Links back to `question_id`, `control_ref`, questionnaire response and `notes` |
| Risk register entry | Created from finding `id`; title includes finding title for correlation |
| Report | Embeds framework score, finding list with verdicts, risk register snapshot, questionnaire completion |
| Policy doc chunks | Traceable to `cymind_doc_id` in `cy_comp_policy_docs` and CyMind RAG source chunks |

---

## 7. Data Stores Summary

| Table | Purpose |
|-------|---------|
| `cy_comp_findings` | Central finding registry — auto-generated + manual + questionnaire gaps |
| `cy_comp_questionnaire_templates` | Per-framework control questions (seeded, framework-specific) |
| `cy_comp_questionnaire_responses` | Analyst answers with auto-score, notes, evidence refs |
| `cy_comp_risks` | Risk register entries with likelihood × impact scoring |
| `cy_comp_framework_scores` | Historical score snapshots per framework (trend data) |
| `cy_comp_controls` | Optional manual control override entries |
| `cy_comp_policy_docs` | Both org policy docs (doc_type='policy') and framework reference docs (doc_type='framework'). `locked=TRUE` prevents deletion of base framework docs. |
| `cy_comp_report_jobs` | Report generation job status tracking |
| `cy_comp_siem_connections` | External SIEM adapter configurations |
| `alerts` | Source of truth for security alerts — compliance columns added as enrichment |
| `incidents` | Source of truth for incidents — compliance breach columns added as enrichment |

---

## 8. Processing Sequence (End-to-End)

```
1. INGEST
   ├── Admin uploads framework reference docs → CyMind RAG (framework-{id} collection)
   ├── Analyst uploads org policy docs → CyMind RAG (org-policies collection)
   ├── Alerts stream in from Wazuh / Correlation Engine → alerts table
   └── Incidents created from correlated alerts → incidents table

2. ENRICH
   ├── Background job: tag alerts with is_compliance_relevant, frameworks, controls, confidence
   └── CyMind RAG query confirms / refines framework mapping

3. QUESTIONNAIRE
   ├── Analyst answers control questions per framework
   ├── Auto-score applied (yes_no, 1-5, text)
   └── NO-responses generate questionnaire_gap findings

4. FINDINGS GENERATION
   ├── auto_findings.py aggregates alerts by MITRE technique → cy_comp_findings (auto_generated=TRUE)
   ├── Verdict assigned per finding (BREACH / WARNING / COMPLIANT)
   └── Remediation guidance attached from MITRE mapping

5. SCORING
   ├── questionnaire score (primary) = pass + partial/2 / total_questions * 100
   ├── alert penalty = min(40, crit*8 + high*4 + med*1)
   └── framework_score = max(0, questionnaire_score - alert_penalty)

6. RISK CORRELATION
   ├── BREACH findings → auto-populate risk register (likelihood × impact)
   └── Risk appetite thresholds applied per category/framework

7. OUTPUT
   ├── GRC Posture Dashboard (charts, trends, breach incidents)
   ├── Assessments (questionnaire + controls view per framework)
   ├── Findings Registry (verdict badges, remediation panel)
   ├── Risk Register (heatmap)
   └── Reports (PDF/HTML with evidence traceability)
```

---

## 9. Configuration Points

| Setting | Location | Default |
|---------|----------|---------|
| Framework question count denominator | `compliance.py → FRAMEWORK_CONTROL_COUNTS` | Per-framework dict |
| Verdict thresholds | `auto_findings.py → _verdict()` | BREACH: level≥12 AND conf≥0.7 |
| Alert penalty cap | `compliance.py` | 40 points max |
| Alert severity weights | `compliance.py` | crit×8, high×4, med×1 |
| CyMind RAG URL | `ai_settings.json → cymind_integration.cymindUrl` | `http://127.0.0.1:8200` |
| Framework docs lock | `cy_comp_policy_docs.locked` | FALSE (admin toggles per doc) |
| Hidden frameworks | Browser `localStorage → grc_hidden_frameworks` | None hidden |
