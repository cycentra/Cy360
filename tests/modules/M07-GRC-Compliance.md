# M07 — GRC / Compliance Engine
**Files:** `backend/cy_comp/`, `backend/blueprints/comp/routes.py`
**Run Date:** 2026-06-29

---

## Module Scope

Full GRC (Governance, Risk, Compliance) engine supporting 6 frameworks. Questionnaire-driven assessment with AI-powered gap analysis, auto-findings from MITRE mapping, risk register, policy document RAG, SOA generation, and compliance reports.

**Supported Frameworks:**
- ISO 27001 (19 controls)
- NIS2 (20 controls)
- DORA (19 controls)
- SOC 2 (16 controls)
- NIST CSF (17 controls)
- PCI DSS (17 controls)

**Components:**
- `models.py` — PostgreSQL tables: `cy_comp_assessments`, `cy_comp_responses`, `cy_comp_findings`, `cy_comp_risks`, `cy_comp_documents`
- `services/compliance.py` — Scoring engine, gap analysis, `FRAMEWORK_CONTROL_COUNTS`
- `services/questionnaire.py` — Questionnaire templates, `seed_templates()`
- `services/ai_analysis.py` — CyMind AI-backed posture analysis
- `services/auto_findings.py` — MITRE ATT&CK → framework control mapping
- `services/policy_rag.py` — RAG queries against policy docs
- `services/risk.py` — Risk register CRUD
- `services/report.py` — PDF/DOCX report generation
- `services/soa.py` — Statement of Applicability
- `services/siem_bridge.py` — Pull compliance-relevant alerts from SIEM
- `data/annex_a_controls.py` — ISO 27001 Annex A controls
- `data/questionnaires.py` — Questionnaire bank (all 6 frameworks)
- `data/question_correlations.py` — Cross-framework question mapping

---

## AI-Executable Tests (Automated)

### A1 — Static Analysis

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `comp_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | AST syntax all `cy_comp/*.py` | ✅ PASS | All files compile |
| A1.03 | `FRAMEWORK_CONTROL_COUNTS` correct | ✅ PASS | nis2=20, dora=19, iso27001=19, soc2=16, nist_csf=17, pci_dss=17 |
| A1.04 | `seed_templates()` is idempotent | ✅ PASS | Runs at startup without error; `force=True` updates text only |
| A1.05 | Auto-findings MITRE mapping non-empty | ✅ PASS | Technique→control map present |
| A1.06 | `get_cymind_api_key()` returns `chatApiKey` before `apiKey` | ✅ PASS | Correct key priority |
| A1.07 | No hardcoded API keys | ✅ PASS | Static scan clean |

### A2 — Compliance Scoring Logic

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | Score = implemented/total × 100 | ✅ PASS | Formula verified |
| A2.02 | Gap = total - implemented | ✅ PASS | |
| A2.03 | All 6 framework denominators correct | ✅ PASS | |
| A2.04 | Score 0-100 range enforced | ✅ PASS | No out-of-range scores |

### A3 — API Endpoints

| # | Test | Result | Detail |
|---|------|--------|--------|
| A3.01 | Unauthenticated → 401 on all `/api/comp/` | ✅ PASS | Auth guard active |
| A3.02 | Viewer can GET assessments | ✅ PASS | Read access allowed |
| A3.03 | Viewer cannot POST new assessment | ✅ PASS | Write blocked |
| A3.04 | Analyst can submit questionnaire responses | ✅ PASS | |

---

## Manual Test Suite

### M-GRC-01: New Assessment — ISO 27001
**Steps:**
1. Navigate to Compliance → New Assessment
2. Select ISO 27001 framework
3. Complete all 19 control questionnaire sections
4. Submit assessment
5. Verify score calculated (0-100%)
6. Verify gap analysis shows missing controls

### M-GRC-02: AI Gap Analysis
**Steps:**
1. Complete a partial assessment (50% controls)
2. Click "AI Analysis"
3. Verify CyMind returns gap analysis report
4. Verify recommendations align with answered questions

### M-GRC-03: Auto-Findings from SIEM Alerts
**Steps:**
1. Trigger a SIEM alert mapped to a MITRE technique
2. Verify auto-findings appear in Compliance → Findings
3. Verify finding links to the correct framework control
4. Verify finding status is "open"

### M-GRC-04: Risk Register
**Steps:**
1. Navigate to Compliance → Risk Register
2. Create new risk with: title, likelihood, impact, mitigation, owner
3. Verify risk appears in register with computed risk score
4. Update risk status to "mitigated"
5. Verify audit trail entry created

### M-GRC-05: Policy Document Upload
**Steps:**
1. Navigate to Compliance → Policy Documents
2. Upload a PDF/DOCX policy document
3. Verify document ingested into RAG collection (`org-policies`)
4. Ask CyMind: "Does our policy cover incident response?"
5. Verify CyMind cites the uploaded document

### M-GRC-06: Compliance Report Generation
**Steps:**
1. Complete an assessment for NIS2
2. Navigate to Compliance → Reports → Generate
3. Select NIS2 framework; generate PDF
4. Verify PDF downloads and contains: score, gap table, finding list, recommendations

### M-GRC-07: Cross-Framework Correlation
**Steps:**
1. Complete ISO 27001 and PCI DSS assessments
2. Navigate to Compliance → Cross-Framework View
3. Verify common controls are linked across frameworks
4. Verify improvements to ISO 27001 auto-propagate to PCI DSS score

### M-GRC-08: Statement of Applicability (SOA)
**Steps:**
1. Navigate to Compliance → SOA → Generate for ISO 27001
2. Verify SOA table includes all Annex A controls
3. Verify applicable/not-applicable status reflects questionnaire responses
4. Export SOA as DOCX

### M-GRC-09: Compliance Live Alerts
**Steps:**
1. Navigate to Compliance → Live Alerts
2. Verify alerts enriched with compliance metadata (framework, control ID)
3. Click an alert to see compliance context
4. Verify SIEM bridge is pulling from alerts/incidents tables (not duplicate tables)
