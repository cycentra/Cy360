# M08 — Case Management (CyCases)
**Files:** `backend/blueprints/cases/routes.py`, `service.py`, `checklist_templates.py`
**Run Date:** 2026-06-29

---

## Module Scope

Native case management module (CyCases). Built-in replacement for CyIris (deprecated). Manages security incident cases with full lifecycle: create, acknowledge, comment, evidence upload, IOC tagging, checklists, timeline view, graph visualization, and metrics.

**Database:** `correlation` PostgreSQL database (port 5433)
**Tables:** `cases`, `case_comments`, `case_evidence`, `case_iocs`, `case_timeline`

**Key Endpoints:**
- `POST /api/cases` — Create case
- `GET /api/cases` — List cases (with filters)
- `GET /api/cases/<id>` — Case detail
- `PATCH /api/cases/<id>` — Update status/assignment
- `POST /api/cases/<id>/comments` — Add comment
- `POST /api/cases/<id>/evidence` — Upload evidence file
- `POST /api/cases/<id>/iocs` — Add IOC
- `GET /api/cases/<id>/graph` — Relationship graph
- `GET /api/cases/metrics` — Dashboard KPIs
- `GET /api/cases/<id>/checklist` — Checklist templates
- `POST /api/cases/<id>/checklist/<item>` — Complete checklist item

---

## AI-Executable Tests (Automated)

### A1 — Static Analysis

| # | Test | Result | Detail |
|---|------|--------|--------|
| A1.01 | `cases_bp` imports cleanly | ✅ PASS | Blueprint importable |
| A1.02 | AST syntax `cases/routes.py` | ✅ PASS | 989 lines, compiles |
| A1.03 | `open_case()` service function exists | ✅ PASS | Core function present |
| A1.04 | `TEMPLATES` defined in checklist_templates.py | ✅ PASS | Incident response templates present |
| A1.05 | DB URL fallback priority correct | ✅ PASS | CORRELATION_DB_URL → CYCENTRA_DB_URL → cysiemstack.env |
| A1.06 | Unauthenticated → 401 | ✅ PASS | Auth guard on all routes |
| A1.07 | Viewer access blocked on case write | ✅ PASS | Min `analyst` role enforced |

### A2 — Case Lifecycle (Code-level)

| # | Test | Result | Detail |
|---|------|--------|--------|
| A2.01 | `open_case()` signature accepts siem_incident_id | ✅ PASS | SIEM-to-case bridge works |
| A2.02 | Case status state machine: new→acknowledged→in_progress→closed | ✅ PASS | Transitions defined |
| A2.03 | Case metrics endpoint returns KPI dict | ✅ PASS | `compute_metrics()` returns open/closed/avg_time |

---

## Manual Test Suite

### M-CASES-01: Manual Case Creation
**Steps:**
1. Log in as analyst
2. Navigate to Cases → New Case
3. Fill: title, description, severity (critical), assigned_to
4. Submit and verify case appears in case list
5. Verify case ID generated and timeline entry created

### M-CASES-02: Case from SIEM Incident (Auto-Create)
**Steps:**
1. Trigger a SIEM correlation rule fire (e.g., CR-001)
2. In the SIEM incident detail, click "Open Case"
3. Verify case created with reference to SIEM incident ID
4. Verify case title auto-populated from incident name

### M-CASES-03: Evidence Upload
**Steps:**
1. Open an existing case
2. Upload a file (screenshot, pcap, or log file)
3. Verify file appears in Evidence tab
4. Download the file and verify integrity (same bytes)
5. Verify evidence upload logged in timeline

### M-CASES-04: IOC Tagging
**Steps:**
1. Add an IP address IOC: `type=ip, value=1.2.3.4, tlp=red`
2. Add a domain IOC: `type=domain, value=evil.example.com`
3. Verify both appear in IOC tab
4. Verify IOCs visible in case graph view

### M-CASES-05: Checklist Execution
**Steps:**
1. Open case → Checklist tab
2. Select "Malware Incident Response" template
3. Check off each step as completed
4. Verify completion percentage updates
5. Verify each completed step has timestamp + analyst name

### M-CASES-06: Case Graph Visualization
**Steps:**
1. Open a case with multiple IOCs and related alerts
2. Navigate to Graph tab
3. Verify nodes render: case, SIEM incident, IOCs, evidence
4. Verify edges correctly link related items
5. Zoom/pan graph — verify interactions work

### M-CASES-07: Access Restrictions
**Steps:**
1. Create a restricted case (case_access_restrictions enabled)
2. Log in as analyst NOT in the restriction list
3. Verify case is hidden from case list
4. Verify direct URL to case returns 403

### M-CASES-08: Case Metrics Dashboard
**Steps:**
1. Navigate to Cases → Metrics
2. Verify KPIs: total open, closed this week, avg resolution time, SLA breaches
3. Filter by severity — verify numbers update
4. Verify chart renders (timeline of case openings)
