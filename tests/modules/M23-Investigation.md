# M23 — AI Investigation Engine
**Files:** `backend/cysiemstack/correlation_engine/hypothesis_engine.py`, `ai_router.py`, `evidence_collector.py`, `llm_enricher.py`, `audit_reporter.py`
**Run Date:** 2026-06-29

---

## Module Scope

6-phase AI-driven investigation engine that takes SIEM incidents and autonomously generates structured investigation reports. Integrates with CyMind for LLM-backed analysis.

**Phases:**
1. **Hypothesis** — Generate attack hypotheses from incident data
2. **Evidence Collection** — Gather supporting/refuting evidence
3. **LLM Enrichment** — CyMind analysis of collected evidence
4. **Correlation** — Cross-incident campaign detection
5. **Reporting** — Structured investigation report generation
6. **Gap Analysis** — MITRE ATT&CK coverage gap identification

**Components:**
- `hypothesis_engine.py` — Phase 1: hypothesis generation
- `evidence_collector.py` — Phase 2: evidence gathering
- `llm_enricher.py` — Phase 3: LLM enrichment via CyMind
- `campaign_correlator.py` — Phase 4: campaign correlation
- `audit_reporter.py` — Phase 5: report generation
- `gap_analyser.py` — Phase 6: gap analysis
- `ai_router.py` — Routes to appropriate LLM (CyMind/Groq)

---

## AI-Executable Tests (132 tests — ALL PASS)

### A1 — Phase 1: Hypothesis Generation

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01-A1.22 | Hypothesis engine: input handling, output structure, edge cases | ✅ 22/22 PASS | |

### A2 — Phase 2: Evidence Collection

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01-A2.22 | Evidence collector: DB query mocking, schema validation, empty results | ✅ 22/22 PASS | |

### A3 — Phase 3: LLM Enrichment

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01-A3.22 | LLM enricher: CyMind mock, Groq fallback, error handling, response parsing | ✅ 22/22 PASS | |

### A4 — Phase 4: Campaign Correlation

| # | Test | Result | Detail |
|---|------|--------|--------|
| A4.01-A4.22 | Campaign correlator: multi-incident linking, timeline merge, confidence | ✅ 22/22 PASS | |

### A5 — Phase 5: Report Generation

| # | Test | Result | Detail |
|---|------|--------|--------|
| A5.01-A5.22 | Report output: structure, markdown format, section presence | ✅ 22/22 PASS | |

### A6 — Phase 6: Gap Analysis

| # | Test | Result | Detail |
|---|------|--------|--------|
| A6.01-A6.22 | Gap analysis: MITRE coverage map, missing technique IDs, priority scoring | ✅ 22/22 PASS | |

**Total: 132/132 PASSED** (confirmed in previous run 2026-06-22)

---

## Manual Test Suite

### M-INV-01: AI Investigation Trigger
**Steps:**
1. Open a high-severity SIEM incident
2. Click "Investigate with AI"
3. Verify all 6 phases execute (progress shown)
4. Verify investigation report generated

### M-INV-02: Investigation Report Quality
**Steps:**
1. Review generated investigation report
2. Verify structure: Executive Summary, Attack Hypothesis, Evidence, Correlation, Recommendations, MITRE Gaps
3. Verify hypothesis cites actual alert data
4. Verify MITRE ATT&CK technique IDs are valid

### M-INV-03: Groq Fallback
**Steps:**
1. Disable CyMind (stop container)
2. Trigger investigation
3. Verify AI router falls back to Groq
4. Verify report still generated (potentially lower quality)

### M-INV-04: Campaign Detection
**Steps:**
1. Generate 5 related incidents with common IOCs across 3 hosts
2. Trigger investigation on any one incident
3. Verify Phase 4 links all 5 incidents into a campaign
4. Verify campaign timeline shows unified attack progression

### M-INV-05: MITRE Gap Analysis
**Steps:**
1. Review gap analysis section of investigation report
2. Verify missing techniques identified (e.g., T1059 not covered)
3. Verify recommendations include rule creation for gap coverage
4. Navigate to SIEM → Rules — verify suggested new rules match gaps
