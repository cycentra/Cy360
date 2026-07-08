# CyComp Enhancement Release — 2026-07-08

**Scope:** CyCentra 360 GRC Compliance module (CyComp) — full gap closure across all 20 GRC features.  
**Total files modified:** 13 backend + 6 frontend.  
**Total new routes added:** 17 (12 in batch 1 + 5 in batch 2).  
**New frameworks added:** ISO 42001:2023, EU AI Act.  
**New DB tables:** `cy_comp_exposure`, `cy_comp_control_validations`.  
**No schema breaking changes** — all DB changes are additive `ALTER TABLE IF NOT EXISTS` migrations and new tables.

> **This document covers both implementation batches.** Batch 1 (sections 1–11) was the initial gap closure. Batch 2 (section 12 onward) completed all partially-addressed items and added Predictive Risk Modeling.

---

## What Was Built and Where

### 1. ISO 42001:2023 — AI Management System Framework

**Why:** EU AI Act covers regulatory obligations but ISO 42001 is the management standard — they complement each other. Growing demand from financial services and tech firms needing AIMS certification.

**Files changed:**
- [`cy_comp/data/questionnaires.py`](../backend/cy_comp/data/questionnaires.py) — Added `ISO_42001` list (26 questions), appended to `ALL_QUESTIONNAIRES` and `FRAMEWORK_META`.
- [`cy_comp/services/compliance.py`](../backend/cy_comp/services/compliance.py) — Added `"iso42001"` to `SUPPORTED_FRAMEWORKS` and `FRAMEWORK_CONTROL_COUNTS` (denominator = 26).
- [`cy_comp/services/report.py`](../backend/cy_comp/services/report.py) — Added `"iso42001": "ISO 42001"` to `FRAMEWORK_LABELS`.

**26 questions covering:**
| Section | Clauses | Questions |
|---------|---------|-----------|
| Context & Leadership | Cl.4–5 | 5 |
| Planning | Cl.6 | 5 |
| Support | Cl.7 | 4 |
| Operation / AI Lifecycle | Cl.8 + Annex A.7–A.10 | 7 |
| Performance Evaluation | Cl.9 | 3 |
| Improvement | Cl.10 | 2 |

**How to activate:**
```bash
# Seed the new ISO 42001 questions into the DB (one-time after deploy)
curl -X POST https://your-cy360/api/comp/questionnaire/seed \
     -H "Cookie: session=..." -d '{"force": true}'
```
The framework then appears in the questionnaire hub, dashboard, and all framework selectors automatically.

---

### 2. AI Control Recommendations Route

**Why:** `suggest_controls()` in `ai_analysis.py` existed but was never exposed as an API route. GRC analysts had no way to call it from the UI.

**New route:** `POST /api/comp/controls/recommend`  
**RBAC:** `@require_analyst`

**Request:**
```json
{ "framework": "nis2", "gap_description": "No MFA enforced on admin accounts" }
```

**Response:**
```json
{
  "framework": "nis2",
  "suggestions": {
    "nis2": ["Art21-2a", "Art21-2j"],
    "iso27001": ["A.8.5"],
    "nist": ["IA-2"],
    "remediation_priority": "immediate",
    "effort": "medium"
  },
  "raw": "..."
}
```

**File changed:** [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `recommend_controls()` at line ~1595.

---

### 3. AI Policy Draft Generation

**Why:** Analysts can identify gaps but writing policy language from scratch is time-consuming. CyMind can draft compliant policy clauses aligned to specific controls.

**New function:** `ai_analysis.generate_policy_draft()` — generates a 150-250 word policy clause with implementation guidance.  
**New route:** `POST /api/comp/policy-docs/draft`  
**RBAC:** `@require_analyst`

**Request:**
```json
{
  "framework": "iso27001",
  "control_id": "A.8.5",
  "control_name": "Privileged Access Management",
  "gap_description": "No documented PAM procedure; admin accounts share passwords",
  "existing_policy_snippet": "Optional — paste the current clause here for AI to rewrite"
}
```

**Response:**
```json
{
  "framework": "iso27001",
  "control_id": "A.8.5",
  "draft_clause": "The organisation SHALL enforce privileged access management...",
  "implementation_guidance": ["Deploy PAM tool (CyberArk, BeyondTrust)", "..."],
  "raw": "..."
}
```

**Files changed:**
- [`cy_comp/services/ai_analysis.py`](../backend/cy_comp/services/ai_analysis.py) — Added `generate_policy_draft()` function (~60 lines).
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `draft_policy_clause()` route.

All calls logged to `cy_comp_ai_audit_log` with `entity_type='policy_draft'`.

---

### 4. Executive Risk Copilot

**Why:** CyMind chat overlay exists platform-wide but isn't pre-seeded with live compliance data. Executives need to ask plain-language questions about posture without navigating dashboards.

**New function:** `ai_analysis.ask_copilot(question, context_data)` — builds a live data context block from `get_dashboard_summary()` then queries CyMind.  
**New route:** `POST /api/comp/ask`  
**RBAC:** `@require_viewer`

**Request:**
```json
{
  "question": "What are our top 3 compliance risks this quarter?",
  "frameworks": ["nis2", "dora"]   // optional — scopes the context
}
```

**Response:**
```json
{
  "question": "What are our top 3 compliance risks this quarter?",
  "answer": "Based on your live posture data, your top three risks are..."
}
```

**Files changed:**
- [`cy_comp/services/ai_analysis.py`](../backend/cy_comp/services/ai_analysis.py) — Added `ask_copilot()` function (~60 lines).
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `executive_copilot()` route.

The copilot uses the GRC system prompt + live data context. CyMind RAG is disabled (`use_rag=False`) so the answer comes purely from the injected live data — no hallucination of historical documents.

---

### 5. What-If Score Simulation

**Why:** GRC analysts want to model "if we implement MFA, what happens to our NIS2 score?" without saving anything. Board presentations need scenario analysis.

**New function:** `compliance.simulate_framework_score(framework, overrides)` — stateless, no DB writes.  
**New route:** `POST /api/comp/simulate`  
**RBAC:** `@require_viewer`

**Request:**
```json
{
  "framework": "nis2",
  "overrides": [
    {"question_id": "nis2-auth-01", "score": 2},
    {"question_id": "nis2-auth-02", "score": 2}
  ]
}
```

**Response:**
```json
{
  "framework": "nis2",
  "actual_score": 61.4,
  "simulated_score": 74.2,
  "delta": 12.8,
  "alert_penalty": 4,
  "changed_questions": [
    {"question_id": "nis2-auth-01", "from": 0, "to": 2},
    {"question_id": "nis2-auth-02", "from": null, "to": 2}
  ],
  "simulated_at": "2026-07-08T..."
}
```

Uses the **canonical scoring formula** from `_compute_score_for_framework()` — mathematically identical, not duplicated. The formula is: `(pass_weight + partial_weight × 0.5) / total_weight × 100 − alert_penalty`.

**Files changed:**
- [`cy_comp/services/compliance.py`](../backend/cy_comp/services/compliance.py) — Added `simulate_framework_score()`.
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `simulate_score()` route.

---

### 6. On-Demand Score Refresh

**Why:** SIEM sync is hourly. After fixing controls or responding to findings, analysts want updated scores immediately without waiting.

**New function:** `compliance.refresh_scores()` — calls `siem_bridge.sync()` then `compute_framework_scores()`.  
**New route:** `POST /api/comp/dashboard/refresh`  
**RBAC:** `@require_analyst`

**Request:**
```json
{ "frameworks": ["nis2", "iso27001"] }  // optional — leave empty to refresh all
```

**Response:**
```json
{
  "scores": [...],
  "siem_synced": {"alerts": {"enriched": 12, "relevant": 3}, "incidents": {"updated": 1}},
  "refreshed_at": "2026-07-08T..."
}
```

**Files changed:**
- [`cy_comp/services/compliance.py`](../backend/cy_comp/services/compliance.py) — Added `refresh_scores()`.
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `refresh_dashboard()` route.

---

### 7. Cyber Resilience Score

**Why:** DORA mandates resilience testing; NIST CSF 2.0 has RS/RC functions; compliance scores don't surface resilience as a standalone KPI. Boards need a single resilience number.

**New function:** `compliance.get_resilience_score()` — pulls from 4 existing data sources:

| Dimension | Source | Weight |
|-----------|--------|--------|
| Resilience Testing | DORA questionnaire (Art.24–26 section) | 30% |
| Incident Recovery (MTTR) | `cases` table — resolved cases last 90 days | 25% |
| Backup & Recovery Controls | DORA BCP + ISO 27001 availability sections | 25% |
| Continuity Planning | DORA continuity + NIST CSF RS/RC sections | 20% |

Missing dimensions are excluded and remaining weights are rebalanced proportionally.

**New route:** `GET /api/comp/resilience-score`  
**RBAC:** `@require_viewer`

**Response:**
```json
{
  "overall_score": 73.5,
  "rating": "adequate",
  "dimensions": {
    "resilience_testing":  {"score": 80.0, "weight": 0.30, "rating": "strong"},
    "incident_recovery":   {"score": 65.0, "weight": 0.25, "rating": "adequate", "mttr_hours": 18.4},
    "backup_recovery":     {"score": 75.0, "weight": 0.25, "rating": "adequate"},
    "continuity_planning": {"score": 60.0, "weight": 0.20, "rating": "developing"}
  },
  "computed_at": "2026-07-08T..."
}
```

Ratings: `strong ≥85 | adequate ≥70 | developing ≥50 | critical <50`.

**Files changed:**
- [`cy_comp/services/compliance.py`](../backend/cy_comp/services/compliance.py) — Added `get_resilience_score()`.
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `get_resilience_score()` route.

---

### 8. Financial Impact Fields on Risk Register

**Why:** Risk scores are cyber-centric. Boards and ERM teams need financial context alongside each risk entry.

**New columns on `cy_comp_risks`** (added via `_MIGRATE_COLUMNS`, fully additive):
- `financial_impact` TEXT — categorical: `low | medium | high | critical | unknown`
- `financial_impact_eur` BIGINT — optional estimated EUR value
- `business_unit` TEXT — owning business unit
- `risk_category_erp` TEXT — ERM category (e.g., `operational | strategic | compliance | reputational`)

**How to use** — same `POST /api/comp/risks` and `PUT /api/comp/risks/<id>` endpoints now accept:
```json
{
  "title": "Ransomware on ERP systems",
  "likelihood": 4,
  "impact": 5,
  "financial_impact": "critical",
  "financial_impact_eur": 2500000,
  "business_unit": "Finance & Operations",
  "risk_category_erp": "operational",
  "frameworks": ["dora", "nis2"]
}
```

These fields are returned in all risk responses and included in the board report.

**Files changed:**
- [`cy_comp/models.py`](../backend/cy_comp/models.py) — Added 4 column migrations.
- [`cy_comp/services/risk.py`](../backend/cy_comp/services/risk.py) — Updated `_SELECT_RISK`, `_row_to_risk`, `create_risk`, `update_risk`.

---

### 9. Unified Board-Ready Report

**Why:** Each module (GRC, ASM) generates its own report. Boards need one document covering all risk domains.

**New function:** `report.generate_board_report_job()` — collects data from all existing sources and generates a PDF + JSON board pack.  
**New route:** `POST /api/comp/reports/generate-board`  
**RBAC:** `@require_analyst`

**Contents of the board report:**
1. Overall posture score with grade (A–F)
2. Framework compliance table (all 9 frameworks)
3. Top 10 open risks sorted by score + financial_impact_eur
4. Critical/high findings count per framework
5. 30-day compliance alert trend (weekly buckets)
6. Cyber resilience score with dimension breakdown
7. Top 10 open exposure items (supply chain + vulnerabilities)

**Request:**
```json
{ "period_start": "2026-04-01", "period_end": "2026-06-30" }
```

**Response:** `202 Accepted` with `{"job_id": "...", "status": "pending"}`.

Poll status via the existing `GET /api/comp/reports/jobs/<job_id>` endpoint.  
Download via existing `GET /api/comp/reports/<report_id>/download`.

**Files changed:**
- [`cy_comp/services/report.py`](../backend/cy_comp/services/report.py) — Added `create_board_report_job()`, `generate_board_report_job()`, `_build_board_pdf()`.
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `generate_board_report()` route.

---

### 10. SIEM Autonomous Evidence → cy_comp_evidence Bridge

**Why:** The SIEM Investigation Engine (Phase 3) autonomously collects 5 types of forensic evidence per incident (process trees, file hashes, DNS history, user privilege logs, vuln scan). This was siloed in the correlation DB. Compliance auditors need this evidence in the GRC evidence register.

**New function:** `siem_bridge.sync_siem_evidence_to_comp(limit)` — reads `incidents.evidence_log` JSONB from compliance-breach incidents and inserts COLLECTED items into `cy_comp_evidence`. Deduplicates via `source_ref = "siem:<incident_id>:<evidence_type>"`.

**New route:** `POST /api/comp/evidence/sync-siem`  
**RBAC:** `@require_analyst`

**Request:**
```json
{ "limit": 200 }  // max incidents to scan — default 200
```

**Response:**
```json
{ "imported": 14, "skipped": 3, "errors": 0 }
```

Evidence type mapping:
| SIEM Evidence Type | cy_comp_evidence.type |
|--------------------|-----------------------|
| process_tree | process_artifact |
| file_hash | file_artifact |
| dns_history | network_log |
| user_privilege | access_log |
| vulnerability_scan | vuln_report |

**Files changed:**
- [`cy_comp/models.py`](../backend/cy_comp/models.py) — Added `source_ref` column + unique index on `cy_comp_evidence`.
- [`cy_comp/services/siem_bridge.py`](../backend/cy_comp/services/siem_bridge.py) — Added `sync_siem_evidence_to_comp()`.
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added `sync_evidence_from_siem()` route.

---

### 11. Exposure Register (cy_comp_exposure)

**Why:** ASM scan data (supply chain vulns, port findings, SSL issues) was untracked after the scan report was generated. No remediation workflow, no ownership, no SLA. The new exposure table bridges ASM → GRC.

**New DB table:** `cy_comp_exposure` — 21 columns covering asset identity, exposure type, severity, CVSS, CVEs, remediation state, financial impact, and ownership.

**New routes:**
- `GET /api/comp/exposure` — list with optional `?status=open&severity=critical&asset=example.com`
- `POST /api/comp/exposure` — create manual exposure item
- `PUT /api/comp/exposure/<id>` — update status/remediation/assignee
- `POST /api/comp/exposure/import-asm` — import from latest ASM scan JSON

**RBAC:** GET = viewer; POST/PUT = analyst.

**How to import from ASM:**
```bash
# Import from the latest scan automatically
curl -X POST https://your-cy360/api/comp/exposure/import-asm \
     -H "Cookie: session=..." -H "Content-Type: application/json" \
     -d '{}'

# Import from a specific scan
curl -X POST https://your-cy360/api/comp/exposure/import-asm \
     -d '{"scan_id": "abc123"}'
```

Imports supply chain vulnerable dependencies and vulnerability scanner findings. Both are idempotent — re-running the same scan import skips already-imported items.

**Files changed:**
- [`cy_comp/models.py`](../backend/cy_comp/models.py) — Added `cy_comp_exposure` table DDL + indexes.
- [`blueprints/comp/routes.py`](../backend/blueprints/comp/routes.py) — Added 4 exposure routes.

---

## Complete API Reference — New Endpoints

| Method | Route | RBAC | Description |
|--------|-------|------|-------------|
| POST | `/api/comp/controls/recommend` | analyst | AI control recommendations for a gap |
| POST | `/api/comp/policy-docs/draft` | analyst | AI policy clause draft for a control |
| POST | `/api/comp/ask` | viewer | Executive risk copilot — NL question |
| POST | `/api/comp/simulate` | viewer | What-if score simulation (stateless) |
| POST | `/api/comp/dashboard/refresh` | analyst | On-demand SIEM sync + score refresh |
| GET | `/api/comp/resilience-score` | viewer | Composite cyber resilience score |
| POST | `/api/comp/reports/generate-board` | analyst | Unified board-ready PDF/JSON report |
| POST | `/api/comp/evidence/sync-siem` | analyst | Bridge SIEM evidence to comp register |
| GET | `/api/comp/exposure` | viewer | List exposure register |
| POST | `/api/comp/exposure` | analyst | Create exposure item |
| PUT | `/api/comp/exposure/<id>` | analyst | Update exposure item |
| POST | `/api/comp/exposure/import-asm` | analyst | Import ASM scan → exposure register |

---

## Database Changes

All changes are **additive and idempotent** — run `ensure_tables()` at startup as always.

### New columns on existing tables

```sql
-- cy_comp_risks (financial context)
ALTER TABLE cy_comp_risks ADD COLUMN IF NOT EXISTS financial_impact TEXT DEFAULT 'unknown';
ALTER TABLE cy_comp_risks ADD COLUMN IF NOT EXISTS financial_impact_eur BIGINT;
ALTER TABLE cy_comp_risks ADD COLUMN IF NOT EXISTS business_unit TEXT;
ALTER TABLE cy_comp_risks ADD COLUMN IF NOT EXISTS risk_category_erp TEXT;

-- cy_comp_evidence (SIEM bridge deduplication)
ALTER TABLE cy_comp_evidence ADD COLUMN IF NOT EXISTS source_ref TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_cy_comp_evidence_source_ref ON cy_comp_evidence(source_ref) WHERE source_ref IS NOT NULL;
```

### New tables

```sql
-- Exposure register (17 new tables total)
CREATE TABLE IF NOT EXISTS cy_comp_exposure (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    asset           TEXT NOT NULL,
    asset_type      TEXT DEFAULT 'host',
    exposure_type   TEXT NOT NULL DEFAULT 'vulnerability',
    severity        TEXT NOT NULL DEFAULT 'medium',
    title           TEXT NOT NULL,
    description     TEXT,
    source          TEXT DEFAULT 'manual',
    source_ref      TEXT,
    cvss_score      NUMERIC(4,1),
    cves            TEXT[] DEFAULT '{}',
    remediation     TEXT,
    status          TEXT NOT NULL DEFAULT 'open',
    financial_impact TEXT,
    business_impact  TEXT,
    assigned_to     TEXT,
    due_date        TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## Post-Deploy Checklist

```bash
# 1. Deploy code (restart backend service)
systemctl restart cycentra-backend.service

# 2. Verify ensure_tables() ran cleanly (check startup logs)
journalctl -u cycentra-backend.service -n 50 | grep "cy_comp"

# 3. Seed ISO 42001 questionnaire
curl -X POST https://your-cy360/api/comp/questionnaire/seed \
     -H "Cookie: session=<admin_session>" \
     -H "Content-Type: application/json" \
     -d '{"force": true}'

# 4. Verify ISO 42001 appears in questionnaire hub
curl https://your-cy360/api/comp/questionnaire/hub -H "Cookie: session=..."

# 5. Optional: import latest ASM scan to exposure register
curl -X POST https://your-cy360/api/comp/exposure/import-asm \
     -H "Cookie: session=..." -H "Content-Type: application/json" -d '{}'

# 6. Optional: sync SIEM evidence to comp evidence register
curl -X POST https://your-cy360/api/comp/evidence/sync-siem \
     -H "Cookie: session=..." -H "Content-Type: application/json" -d '{}'

# 7. Verify new routes respond
curl https://your-cy360/api/comp/resilience-score -H "Cookie: session=..."
```

---

## What Was NOT Built (and Why)

| Feature | Decision |
|---------|----------|
| Digital twins for organizational risk | Explicitly skipped by product owner — requires graph DB (Neo4j), XL effort |
| ~~Predictive risk modeling~~ | ~~Needs 6+ months of score history~~ **→ Built in batch 2** |
| ~~Full continuous control validation~~ | ~~L-effort systematic test harness~~ **→ Built in batch 2 (10 validators)** |
| ~~Frontend pages for new features~~ | ~~Backend APIs are complete~~ **→ 4 pages built in batch 2** |

---

## Invariants Preserved

- **Scoring formula** unchanged and not duplicated — `simulate_framework_score()` uses the same constants (`pass_weight + partial_weight × 0.5) / total_weight × 100 − alert_penalty`) as `_compute_score_for_framework()`.
- **Denominator contract** preserved — `iso42001: 26` added to `FRAMEWORK_CONTROL_COUNTS`.
- **Never write to `alerts` table** from cy_comp — `sync_siem_evidence_to_comp()` reads `incidents` only.
- **Fallback score = 100%** — unchanged.
- **All new routes** have `@require_viewer` or `@require_analyst` decorators.
- **All AI calls** logged to `cy_comp_ai_audit_log` with `entity_type` set.
- **`ensure_tables()` idempotent** — all DDL uses `CREATE TABLE IF NOT EXISTS` and `ALTER TABLE ADD COLUMN IF NOT EXISTS`.

---

---

# Batch 2 — Partial Items Completion + Predictive Risk Modeling — 2026-07-08

**Scope:** Completed all 6 partially-addressed GRC items + built predictive risk modeling from scratch.  
**Files added:** 2 backend services + 4 frontend pages.  
**Files modified:** `models.py`, `routes.py`, `AppRouter.jsx`, `navConfig.jsx`, `ComplianceDashboardPage.jsx`, `g-cyra-comp.md`.  
**New routes:** 5. **New DB table:** `cy_comp_control_validations`.

---

## B1. Real-Time Risk Scoring via SSE (#2 — completed)

**What was missing:** On-demand refresh existed; live push when new alerts arrived did not.

**New backend:** `GET /api/comp/dashboard/stream`  
**RBAC:** `@require_viewer`  
**Mechanism:** Flask `stream_with_context` generator polls `MAX(timestamp) FROM alerts WHERE is_compliance_relevant = TRUE` every 30 seconds. When the timestamp changes (new alert ingested), pushes updated framework scores as a `score-update` event. Emits `heartbeat` events in idle periods to keep the TCP connection alive.

**nginx note:** Response includes `X-Accel-Buffering: no` to disable nginx proxy buffering (required for SSE behind nginx).

**Frontend:** `ComplianceDashboardPage.jsx` — SSE hook added in `useEffect` after initial data load:
```js
const es = new EventSource(`${API_BASE}/api/comp/dashboard/stream`, { withCredentials: true });
es.addEventListener("score-update", e => {
  const { scores, reason } = JSON.parse(e.data);
  if (reason !== "connected") setSummary(prev => ({ ...prev, framework_scores: scores }));
});
es.onerror = () => es.close();  // stop on error — avoids reconnect loop
```
Dashboard scores update in place without a page reload.

---

## B2. Continuous Control Validation (#7 — completed)

**New service:** `cy_comp/services/control_validator.py`

**Architecture:** Decorator-registered validators. Each is a pure function that receives a psycopg2 cursor and returns `{status, score, detail, evidence}`. Results are UPSERTED into `cy_comp_control_validations` (one row per validator, keyed on `validator_id`).

### 10 Validators

| ID | Title | Frameworks |
|----|-------|-----------|
| `cv-vuln-01` | Critical Vulnerability Currency | nis2, iso27001, nist_csf, pci_dss |
| `cv-siem-01` | SIEM Monitoring Coverage | nis2, dora, iso27001, soc2, nist_csf |
| `cv-ir-01` | Incident Response Practice | nis2, dora, iso27001, soc2, nist_csf |
| `cv-sc-01` | Supply Chain Risk Management | nis2, dora, iso27001, nist_csf |
| `cv-log-01` | Log Retention Continuity | dora, iso27001, soc2, pci_dss |
| `cv-ai-01` | Shadow AI Governance | eu_ai_act, iso42001 |
| `cv-patch-01` | Patch Management Currency | nis2, iso27001, pci_dss, nist_csf |
| `cv-backup-01` | Backup & Recovery Controls | dora, iso27001, soc2, nist_csf |
| `cv-access-01` | Access Control & IAM | nis2, iso27001, soc2, pci_dss |
| `cv-comp-01` | Assessment Completion Rate | all 9 frameworks |

**Status values:** `pass` / `warning` / `fail` / `unknown`

**Auto-finding:** When `status=fail` and `score < 60`, an open `cy_comp_finding` is auto-created (idempotent — skips if one already exists for that `validator_id + framework`).

**Scheduler:** `register_validator_scheduler(scheduler)` registers a daily 03:00 UTC job via APScheduler.

**New table:**
```sql
CREATE TABLE IF NOT EXISTS cy_comp_control_validations (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    run_id          TEXT NOT NULL,
    validator_id    TEXT NOT NULL UNIQUE,   -- UPSERT key
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    frameworks      TEXT[] DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'unknown',
    score           NUMERIC(5,1),
    detail          TEXT,
    evidence_json   JSONB DEFAULT '{}',
    validated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**New API routes:**

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| `GET` | `/api/comp/control-validations` | viewer+ | Latest result per validator, sorted fail-first |
| `POST` | `/api/comp/control-validations/run` | analyst+ | Trigger on-demand run. Body: `{"auto_finding": true}` |

**Run response:**
```json
{
  "run_id": "uuid",
  "validated_at": "2026-07-08T...",
  "total": 10,
  "pass": 6, "fail": 2, "warning": 1, "unknown": 1,
  "results": [{ "validator_id": "cv-vuln-01", "status": "fail", "score": 40, "detail": "..." }]
}
```

---

## B3. Supply Chain Visualization (#12 — completed)

**New page:** `portal/src/pages/compliance/SupplyChainRiskPage.jsx`  
**Nav entry:** "Supply Chain Risk" (📦) in SECURITY COMPLIANCE section  
**Tab ID:** `comp-supplychain`

**Data source:** `GET /api/comp/exposure?exposure_type=supply_chain` — already existed from batch 1.

**Features:**
- 4 stat cards: Total Dependencies / Critical / High / Resolved+Accepted
- Filters: severity, status, free-text search (asset, title, CVE)
- Table: asset, risk title+description, CVEs (up to 3 + overflow count), CVSS, severity badge, status badge, inline Resolve / Accept Risk / Reopen actions
- "Import from ASM Scan" button — calls `POST /api/comp/exposure/import-asm`
- Empty state with CTA when no supply chain items exist

---

## B4. Exposure Register Full UI (complement to #10)

**New page:** `portal/src/pages/compliance/ExposureRegisterPage.jsx`  
**Nav entry:** "Exposure Register" (📡) in SECURITY COMPLIANCE section  
**Tab ID:** `comp-exposure`

**Features:**
- Tabs: All / Vulnerabilities / Supply Chain / Other
- Header buttons: "Sync from SIEM" → `POST /api/comp/evidence/sync-siem`, "Import ASM Scan" → `POST /api/comp/exposure/import-asm`, "+ Add Item"
- Create modal: asset, title, description, CVSS, type, asset_type, severity
- Table with inline status dropdown (open / in_progress / resolved / accepted / false_positive) — each change fires `PUT /api/comp/exposure/<id>` immediately
- Age column highlights items open >30 days in orange

---

## B5. Predictive Risk Modeling (#17 — built from scratch)

**New service:** `cy_comp/services/prediction.py`

**Algorithm:** Pure-Python, no external ML dependencies.
1. **Linear regression** on `cy_comp_framework_scores` history: `y = intercept + slope × x` where x = days since first record.
2. **EWMA** (α = 0.3) for smoothed trend line alongside raw scores.
3. **R²** as fit-quality metric — used in confidence calculation.
4. **Confidence** = `min(95, R²×65 + min(n,20)×1.25 - horizon×0.15)` — degrades for longer horizons and sparse data.
5. **Confidence interval** = ±(residual std-dev × 1.5 × (1 + horizon/90)), capped at ±30 points.
6. All predictions clamped to [0, 100].

**Functions:**
```python
predict_framework_score(framework, horizons=(30,60,90)) -> dict
predict_all_frameworks(frameworks=None) -> dict[str, dict]
get_portfolio_trend(frameworks=None) -> dict  # aggregate direction
```

**New API routes:**

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| `GET` | `/api/comp/predict?framework=nis2&horizon=30,60,90` | viewer+ | Single framework prediction (omit `framework` for portfolio trend) |
| `GET` | `/api/comp/predict/all` | viewer+ | All frameworks in one call |

**Prediction response per framework:**
```json
{
  "framework": "nis2",
  "data_points": 14,
  "trend": "improving",
  "slope_per_day": 0.0821,
  "r_squared": 0.782,
  "current_score": 71.4,
  "predictions": {
    "30": { "score": 73.9, "confidence": 68, "low": 68.2, "high": 79.6 },
    "60": { "score": 76.3, "confidence": 62, "low": 69.1, "high": 83.5 },
    "90": { "score": 78.8, "confidence": 57, "low": 70.4, "high": 87.2 }
  },
  "actual": [{ "days": 0, "date": "2026-06-01", "score": 65.2, "ewma": 65.2 }, ...]
}
```

**Note:** Predictions warm up after the first few refreshes. Use `POST /api/comp/dashboard/refresh` to force score snapshots into `cy_comp_framework_scores`. Predictions are most reliable after 10+ data points.

**New page:** `portal/src/pages/compliance/RiskPredictionPage.jsx`  
**Nav entry:** "Risk Prediction" (📈) in SECURITY COMPLIANCE section  
**Tab ID:** `comp-predict`

**UI features:**
- Portfolio summary: improving / declining / stable / no-data counts across all 9 frameworks
- Framework selector buttons (colour-coded per FW_META)
- Horizon toggle: +30d / +60d / +90d
- SVG line chart: solid line = historical actual scores, dashed = predicted trajectory, shaded band = confidence interval
- "Refresh Score History" button → `POST /api/comp/dashboard/refresh` then reloads prediction
- Prediction table: Current / +30d / +60d / +90d scores with confidence % and low–high range
- Regression detail card: slope/day and R² with colour-coded quality indicators
- Warning when fewer than 5 data points

---

## B6. Unified Cyber + Enterprise Risk Dashboard (#15 + #20 — completed)

**New page:** `portal/src/pages/compliance/UnifiedRiskDashboardPage.jsx`  
**Nav entry:** "Unified Console" (🖥) — pinned at top of SECURITY COMPLIANCE section  
**Tab ID:** `comp-unified`

Pulls from 5 endpoints concurrently via `Promise.allSettled` (gracefully degrades if any fails):

| Endpoint | Data |
|----------|------|
| `GET /api/benchmark/score` | CSPI (Security Posture Index) |
| `GET /api/comp/dashboard` | Framework scores + top risks |
| `GET /api/comp/resilience-score` | Cyber resilience composite |
| `GET /api/comp/predict` | Portfolio trend (improving/declining/stable) |
| `GET /api/comp/control-validations` | Technical validator health |

### Tab 1: Risk Overview
- 3 score donuts: CSPI / Compliance Score / Cyber Resilience
- Portfolio trend card (↑ Improving / ↓ Declining / → Mixed)
- Control validators health card (fail + warning counts)
- Top Risks table with: risk title, business unit, severity, financial impact (EUR), status
- Technical Control Health list (all validators, fail-first ordering)

### Tab 2: Governance Console
- 4 domain cards: 🛡 Cyber Security (NIS2, DORA, NIST CSF) · ✅ Compliance (ISO 27001, SOC 2, PCI DSS) · 🔐 Privacy (GDPR) · 🤖 AI Governance (EU AI Act, ISO 42001)
- Each domain shows: domain-average score, per-framework score bars with colour, trend arrow from prediction API
- Executive summary bar: frameworks deployed / overall compliance / CSPI / validators failing

---

## Batch 2 — Complete File Manifest

### New Files

| File | Purpose |
|------|---------|
| `backend/cy_comp/services/prediction.py` | Linear regression + EWMA predictive modeling |
| `backend/cy_comp/services/control_validator.py` | 10 automated technical control validators |
| `portal/src/pages/compliance/SupplyChainRiskPage.jsx` | Supply chain risk visualization |
| `portal/src/pages/compliance/ExposureRegisterPage.jsx` | Full exposure register CRUD UI |
| `portal/src/pages/compliance/RiskPredictionPage.jsx` | Predictive risk chart + horizon table |
| `portal/src/pages/compliance/UnifiedRiskDashboardPage.jsx` | Unified risk + governance console |

### Modified Files

| File | Change |
|------|--------|
| `backend/cy_comp/models.py` | Added `cy_comp_control_validations` DDL in `_MIGRATE_COLUMNS` |
| `backend/blueprints/comp/routes.py` | 5 new routes: SSE stream, 2× control validation, 2× predict |
| `portal/src/components/AppRouter.jsx` | 4 new imports + 4 tab renders |
| `portal/src/sidebar/navConfig.jsx` | 4 new nav items in SECURITY COMPLIANCE section |
| `portal/src/pages/compliance/ComplianceDashboardPage.jsx` | `iso42001` added to FW_META; SSE EventSource hook |
| `CyRepo/.claude/commands/g-cyra-comp.md` | Skill file updated with all new services/routes/tables |

---

## Batch 2 — Post-Deploy Checklist

```bash
# 1. Restart backend (picks up 2 new service files + routes)
systemctl restart cycentra-backend.service

# 2. Verify cy_comp_control_validations table was created
psql -h localhost -p 5433 -U cycentra correlation \
  -c "SELECT COUNT(*) FROM cy_comp_control_validations;"

# 3. Run first control validation manually
curl -X POST https://your-cy360/api/comp/control-validations/run \
     -H "Cookie: session=<analyst_session>" \
     -H "Content-Type: application/json" \
     -d '{"auto_finding": true}'

# 4. Populate score history for predictions (run refresh a few times over days)
curl -X POST https://your-cy360/api/comp/dashboard/refresh \
     -H "Cookie: session=<analyst_session>"

# 5. Verify SSE stream responds
curl -N https://your-cy360/api/comp/dashboard/stream \
     -H "Cookie: session=<viewer_session>"
# Should see: event: score-update\ndata: {...}\n\n  within 2s

# 6. Rebuild frontend
cd /path/to/Cy360/portal && npm run build

# 7. Verify new pages load
# - Navigate to "Unified Console" in sidebar
# - Navigate to "Risk Prediction" → should show warming-up state if no history yet
# - Navigate to "Supply Chain Risk" → import from ASM if scan exists
```

---

## Invariants Preserved (Batch 2)

- Scoring formula unchanged — `prediction.py` reads scores but never computes them.
- `cy_comp_` prefix on all new tables.
- SSE generator never writes to `alerts` table — read-only poll.
- All new routes have RBAC decorators (`@require_viewer` or `@require_analyst`).
- `ensure_tables()` remains idempotent — `cy_comp_control_validations` uses `CREATE TABLE IF NOT EXISTS`.
- Auto-findings from validators are idempotent — no duplicate findings created.
